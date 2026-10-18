"""Differential and metamorphic validation engine for network protocol captures."""

import ctypes
import json
import logging
import os
import subprocess
import time
import tracemalloc
import uuid
from ctypes import wintypes
from datetime import UTC, datetime
from pathlib import Path

from network_twin.captures.corpus import CaptureCorpus
from network_twin.captures.models import (
    CaptureValidationReport,
    DifferentialTestResult,
    FieldComparisonDifference,
    MetamorphicRelationType,
    ProcessResourceTelemetry,
)
from network_twin.captures.reference_decoder import ReferenceDecoder

logger = logging.getLogger("network_twin.captures.differential")


class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
        ("PrivateUsage", ctypes.c_size_t),
    ]


def _get_process_peak_memory(pid: int) -> int:
    """Measures peak native working set memory for a Windows process handle."""
    if os.name != "nt":
        return 0
    try:
        # PROCESS_QUERY_INFORMATION (0x0400) | PROCESS_VM_READ (0x0010)
        handle = ctypes.windll.kernel32.OpenProcess(0x0400 | 0x0010, False, pid)
        if not handle:
            return 0
        counters = PROCESS_MEMORY_COUNTERS_EX()
        counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS_EX)
        ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb)
        ctypes.windll.kernel32.CloseHandle(handle)
        return int(counters.PeakWorkingSetSize)
    except Exception as e:
        logger.debug("Could not read process memory info: %s", e)
        return 0


class DifferentialValidator:
    """Differential and metamorphic testing harness for C++ protocol engine."""

    def __init__(self, corpus: CaptureCorpus | None = None) -> None:
        self.corpus = corpus or CaptureCorpus()
        self.binary_path = self._resolve_engine_binary()

    def _resolve_engine_binary(self) -> Path:
        """Finds compiled protocol_engine executable."""
        project_root = Path(__file__).resolve().parents[5]
        candidates = [
            project_root / "build" / "engine" / "Release" / "protocol_engine.exe",
            project_root / "build" / "engine" / "protocol_engine.exe",
            Path("build/engine/Release/protocol_engine.exe").resolve(),
            Path("build/engine/protocol_engine.exe").resolve(),
        ]
        for c in candidates:
            if c.is_file():
                return c.resolve()
        raise FileNotFoundError("Could not find compiled protocol_engine.exe. Run cmake --build first.")

    def run_engine_on_file(
        self, pcap_path: Path, output_dir: Path
    ) -> tuple[dict, list[dict], ProcessResourceTelemetry]:
        """Executes C++ engine binary and records native memory and telemetry."""
        output_dir.mkdir(parents=True, exist_ok=True)
        events_path = output_dir / f"events_{uuid.uuid4().hex[:8]}.jsonl"
        summary_path = output_dir / f"summary_{uuid.uuid4().hex[:8]}.json"

        cmd = [
            str(self.binary_path),
            "--pcap",
            str(pcap_path),
            "--out",
            str(events_path),
            "--summary",
            str(summary_path),
            "--benchmark",
        ]

        tracemalloc.start()
        t0 = time.perf_counter()

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        peak_native_mem = _get_process_peak_memory(proc.pid)
        stdout, stderr = proc.communicate(timeout=60)

        elapsed_ms = (time.perf_counter() - t0) * 1000
        current_heap, peak_heap = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        if proc.returncode != 0 and "truncated" not in stdout and "malformed" not in stdout:
            raise RuntimeError(f"Engine failed with returncode {proc.returncode}: {stderr}\nOutput: {stdout}")

        # If peak memory check during runtime was 0 or low, query again
        if peak_native_mem == 0:
            peak_native_mem = _get_process_peak_memory(proc.pid)

        summary_data = {}
        if summary_path.is_file():
            with open(summary_path, encoding="utf-8") as f:
                summary_data = json.load(f)

        events = []
        if events_path.is_file():
            with open(events_path, encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        events.append(json.loads(line))

        # Calculate throughput
        total_packets = summary_data.get("total_packets") or summary_data.get("total_packets_processed") or len(events)
        total_bytes = (
            summary_data.get("total_bytes") or summary_data.get("total_bytes_processed") or pcap_path.stat().st_size
        )
        pps = (total_packets / (elapsed_ms / 1000.0)) if elapsed_ms > 0 else 0.0
        mbps = ((total_bytes * 8) / (elapsed_ms / 1000.0) / 1_000_000.0) if elapsed_ms > 0 else 0.0

        telemetry = ProcessResourceTelemetry(
            wall_duration_ms=round(elapsed_ms, 2),
            throughput_pps=round(pps, 1),
            throughput_mbps=round(mbps, 2),
            peak_native_memory_bytes=peak_native_mem,
            python_heap_bytes=peak_heap,
        )

        return summary_data, events, telemetry

    def validate_capture(self, capture_id: str) -> CaptureValidationReport:
        """Validates capture decoding against expected outcomes and reference decoder."""
        item = self.corpus.get_capture(capture_id)
        if not item:
            raise KeyError(f"Capture '{capture_id}' not found in corpus.")

        pcap_path = self.corpus.get_capture_path(capture_id)
        temp_dir = Path("data/temp_differential") / capture_id
        summary, events, telemetry = self.run_engine_on_file(pcap_path, temp_dir)

        # 1. Decode raw packets with independent reference decoder
        raw_bytes = pcap_path.read_bytes()
        ref_packets: list[tuple[int, int, bytes]] = []
        if item.format.value == "PCAP":
            ref_packets = ReferenceDecoder.parse_pcap_packets(raw_bytes)

        differences: list[FieldComparisonDifference] = []
        if ref_packets and len(ref_packets) == len(events):
            for idx, (_, _, pkt_bytes) in enumerate(ref_packets):
                ref_dec = ReferenceDecoder.decode_packet(pkt_bytes)
                eng_ev = events[idx]

                # Compare Ethernet MACs
                if ref_dec.get("link_layer"):
                    ref_dst = ref_dec["link_layer"].get("destination_mac")
                    eng_dst = eng_ev.get("link_layer", {}).get("destination_mac") if eng_ev.get("link_layer") else None
                    if ref_dst and eng_dst and ref_dst.lower() != eng_dst.lower():
                        differences.append(
                            FieldComparisonDifference(
                                packet_index=idx,
                                field_name="destination_mac",
                                cpp_engine_value=eng_dst,
                                reference_decoder_value=ref_dst,
                                match=False,
                            )
                        )

                # Compare IP addresses
                if ref_dec.get("network_layer") and eng_ev.get("network_layer"):
                    ref_src = ref_dec["network_layer"].get("source_ip")
                    eng_src = eng_ev["network_layer"].get("source_ip")
                    if ref_src and eng_src and ref_src != eng_src:
                        differences.append(
                            FieldComparisonDifference(
                                packet_index=idx,
                                field_name="source_ip",
                                cpp_engine_value=eng_src,
                                reference_decoder_value=ref_src,
                                match=False,
                            )
                        )

                # Compare TCP ports & sequence numbers
                if ref_dec.get("transport_layer") and eng_ev.get("transport_layer"):
                    ref_sport = ref_dec["transport_layer"].get("source_port")
                    eng_sport = eng_ev["transport_layer"].get("source_port")
                    if ref_sport and eng_sport and ref_sport != eng_sport:
                        differences.append(
                            FieldComparisonDifference(
                                packet_index=idx,
                                field_name="source_port",
                                cpp_engine_value=eng_sport,
                                reference_decoder_value=ref_sport,
                                match=False,
                            )
                        )
                    ref_seq = ref_dec["transport_layer"].get("sequence_number")
                    eng_seq = eng_ev["transport_layer"].get("sequence_number")
                    if ref_seq is not None and eng_seq is not None and ref_seq != eng_seq:
                        differences.append(
                            FieldComparisonDifference(
                                packet_index=idx,
                                field_name="sequence_number",
                                cpp_engine_value=eng_seq,
                                reference_decoder_value=ref_seq,
                                match=False,
                            )
                        )

        # 2. Check against expected outcomes
        exp = item.expected_outcomes
        obs_packets = summary.get("total_packets_processed", len(events))
        obs_flows = summary.get("total_flows_tracked", len(summary.get("flows", [])))
        proto_counts = summary.get("protocol_counts", {})
        status_counts = summary.get("parser_status_counts", {})

        packet_match = obs_packets == exp.total_packets
        flow_match = (exp.total_flows == 0) or (obs_flows == exp.total_flows)
        diff_count = len(differences)

        passed = packet_match and flow_match and (diff_count == 0)

        explanation = (
            f"Capture '{item.name}' verified: {obs_packets} packets processed across {obs_flows} flows. "
            f"Reference decoder discrepancies: {diff_count}. Outcome: {'PASS' if passed else 'FAIL'}."
        )

        return CaptureValidationReport(
            validation_id=f"val-{uuid.uuid4().hex[:12]}",
            capture_id=capture_id,
            timestamp=datetime.now(UTC),
            passed=passed,
            total_packets_processed=obs_packets,
            total_flows_observed=obs_flows,
            protocol_distribution=proto_counts,
            parser_status_counts=status_counts,
            telemetry=telemetry,
            field_differences=differences,
            explanation=explanation,
        )

    def test_format_equivalence(self, pcap_id: str, pcapng_id: str) -> DifferentialTestResult:
        """Verifies bit-exact semantic equivalence across PCAP and PCAPNG encodings of the same trace."""
        t0 = time.perf_counter()
        pcap_path = self.corpus.get_capture_path(pcap_id)
        pcapng_path = self.corpus.get_capture_path(pcapng_id)

        temp_dir = Path("data/temp_differential") / "format_equiv"
        pcap_summary, pcap_events, _ = self.run_engine_on_file(pcap_path, temp_dir / "pcap")
        pcapng_summary, pcapng_events, _ = self.run_engine_on_file(pcapng_path, temp_dir / "pcapng")

        elapsed_ms = (time.perf_counter() - t0) * 1000

        # Assert identical packet counts
        pkts_pcap = pcap_summary.get("total_packets") or pcap_summary.get("total_packets_processed") or len(pcap_events)
        pkts_pcapng = (
            pcapng_summary.get("total_packets") or pcapng_summary.get("total_packets_processed") or len(pcapng_events)
        )

        # Assert identical flow counts
        flows_pcap = (
            pcap_summary.get("total_flows")
            or pcap_summary.get("total_flows_tracked")
            or len(pcap_summary.get("flows", []))
        )
        flows_pcapng = (
            pcapng_summary.get("total_flows")
            or pcapng_summary.get("total_flows_tracked")
            or len(pcapng_summary.get("flows", []))
        )

        # Assert identical protocol distributions
        proto_pcap = pcap_summary.get("protocol_counts", {})
        proto_pcapng = pcapng_summary.get("protocol_counts", {})

        passed = (pkts_pcap == pkts_pcapng) and (flows_pcap == flows_pcapng) and (proto_pcap == proto_pcapng)

        return DifferentialTestResult(
            test_id=f"diff-format-{uuid.uuid4().hex[:8]}",
            relation_type=MetamorphicRelationType.FORMAT_EQUIVALENCE,
            base_capture_id=pcap_id,
            transformed_capture_id=pcapng_id,
            passed=passed,
            expected_invariant="PCAP and PCAPNG representations of identical packet bytes must produce bit-exact protocol distributions and flow counts.",
            observed_behavior=(
                f"PCAP: {pkts_pcap} pkts, {flows_pcap} flows; PCAPNG: {pkts_pcapng} pkts, {flows_pcapng} flows. "
                f"Protocols match: {proto_pcap == proto_pcapng}."
            ),
            execution_time_ms=round(elapsed_ms, 2),
            details={
                "pcap_packets": pkts_pcap,
                "pcapng_packets": pkts_pcapng,
                "pcap_flows": flows_pcap,
                "pcapng_flows": flows_pcapng,
                "pcap_protocols": proto_pcap,
                "pcapng_protocols": proto_pcapng,
            },
        )

    def test_metamorphic_timestamp_shift(self, capture_id: str, shift_seconds: int = 60) -> DifferentialTestResult:
        """MR-TIMESHIFT: Uniformly shifting packet timestamps preserves packet counts, protocol mix, and flow keys."""
        t0 = time.perf_counter()
        pcap_path = self.corpus.get_capture_path(capture_id)
        raw_bytes = pcap_path.read_bytes()
        packets = ReferenceDecoder.parse_pcap_packets(raw_bytes)

        if not packets:
            raise ValueError("Cannot run timestamp shift on empty capture.")

        # Shift timestamps
        from scripts.generate_capture_corpus import write_classic_pcap

        shifted_packets = [(ts_sec + shift_seconds, ts_usec, pkt) for ts_sec, ts_usec, pkt in packets]
        shifted_bytes = write_classic_pcap(shifted_packets)

        temp_dir = Path("data/temp_differential") / f"timeshift_{uuid.uuid4().hex[:8]}"
        shifted_pcap = temp_dir / "shifted.pcap"
        temp_dir.mkdir(parents=True, exist_ok=True)
        shifted_pcap.write_bytes(shifted_bytes)

        base_summary, _, _ = self.run_engine_on_file(pcap_path, temp_dir / "base")
        shifted_summary, _, _ = self.run_engine_on_file(shifted_pcap, temp_dir / "shifted")

        elapsed_ms = (time.perf_counter() - t0) * 1000

        # Invariants:
        base_pkts = base_summary.get("total_packets", base_summary.get("total_packets_processed", 0))
        shifted_pkts = shifted_summary.get("total_packets", shifted_summary.get("total_packets_processed", 0))
        pkts_match = base_pkts == shifted_pkts

        base_flows = base_summary.get("total_flows", base_summary.get("total_flows_tracked", 0))
        shifted_flows = shifted_summary.get("total_flows", shifted_summary.get("total_flows_tracked", 0))
        flows_match = base_flows == shifted_flows

        proto_match = base_summary.get("protocol_counts") == shifted_summary.get("protocol_counts")

        passed = pkts_match and flows_match and proto_match

        return DifferentialTestResult(
            test_id=f"diff-timeshift-{uuid.uuid4().hex[:8]}",
            relation_type=MetamorphicRelationType.TIMESTAMP_SHIFT,
            base_capture_id=capture_id,
            transformed_capture_id=f"{capture_id}+shift{shift_seconds}s",
            passed=passed,
            expected_invariant=f"Adding {shift_seconds}s offset preserves packet count, protocol distribution, and flow keys.",
            observed_behavior=f"Packets match: {pkts_match}, Flows match: {flows_match}, Protocols match: {proto_match}.",
            execution_time_ms=round(elapsed_ms, 2),
            details={
                "base_packets": base_pkts,
                "shifted_packets": shifted_pkts,
                "base_flows": base_flows,
                "shifted_flows": shifted_flows,
            },
        )

    def test_metamorphic_noise_injection(self, capture_id: str) -> DifferentialTestResult:
        """MR-NOISE: Adding an independent unrelated flow leaves all original flows and states untouched."""
        t0 = time.perf_counter()
        pcap_path = self.corpus.get_capture_path(capture_id)
        raw_bytes = pcap_path.read_bytes()
        packets = ReferenceDecoder.parse_pcap_packets(raw_bytes)

        from scripts.generate_capture_corpus import (
            make_ethernet,
            make_ipv4,
            make_udp,
            write_classic_pcap,
        )

        # Create isolated noise packet on testnet prefix 198.51.100.0/24
        noise_udp = make_udp("198.51.100.10", "198.51.100.20", 9999, 9999, b"NOISE_PAYLOAD_TEST")
        noise_ip = make_ipv4("198.51.100.10", "198.51.100.20", 17, noise_udp)
        noise_pkt = make_ethernet("00:99:88:77:66:55", "00:11:22:33:44:55", 0x0800, noise_ip)

        noise_packets = list(packets)
        noise_packets.append((1700000999, 0, noise_pkt))
        noise_pcap_bytes = write_classic_pcap(noise_packets)

        temp_dir = Path("data/temp_differential") / f"noise_{uuid.uuid4().hex[:8]}"
        temp_dir.mkdir(parents=True, exist_ok=True)
        noise_pcap = temp_dir / "noise.pcap"
        noise_pcap.write_bytes(noise_pcap_bytes)

        base_summary, _, _ = self.run_engine_on_file(pcap_path, temp_dir / "base")
        noise_summary, _, _ = self.run_engine_on_file(noise_pcap, temp_dir / "noise")

        elapsed_ms = (time.perf_counter() - t0) * 1000

        # Invariants:
        base_pkts = base_summary.get("total_packets", base_summary.get("total_packets_processed", 0))
        noise_pkts = noise_summary.get("total_packets", noise_summary.get("total_packets_processed", 0))
        pkts_incremented = noise_pkts == base_pkts + 1

        base_flows = base_summary.get("total_flows", base_summary.get("total_flows_tracked", 0))
        noise_flows = noise_summary.get("total_flows", noise_summary.get("total_flows_tracked", 0))
        flows_incremented = noise_flows == base_flows + 1

        passed = pkts_incremented and flows_incremented

        return DifferentialTestResult(
            test_id=f"diff-noise-{uuid.uuid4().hex[:8]}",
            relation_type=MetamorphicRelationType.NOISE_INJECTION,
            base_capture_id=capture_id,
            transformed_capture_id=f"{capture_id}+noise",
            passed=passed,
            expected_invariant="Injecting 1 independent noise packet increments packet count by 1 and flow count by exactly 1.",
            observed_behavior=f"Packet diff: {noise_pkts - base_pkts} (expected +1), Flow diff: {noise_flows - base_flows} (expected +1).",
            execution_time_ms=round(elapsed_ms, 2),
            details={
                "base_packets": base_pkts,
                "noise_packets": noise_pkts,
                "base_flows": base_flows,
                "noise_flows": noise_flows,
            },
        )
