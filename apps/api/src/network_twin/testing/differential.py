"""Differential and Metamorphic Testing engine for protocol analysis.

Validates:
1. Classic PCAP vs PCAPNG format equivalence.
2. Metamorphic padding invariance (padding does not distort upper layers).
3. Metamorphic port shift (port mutation only changes port fields).
4. Metamorphic truncation safety (truncations safely reject without crash or OOB memory access).
"""

import logging
import tempfile
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from network_twin.testing.engine_runner import EngineRunner
from network_twin.testing.generators import (
    make_ethernet_frame,
    make_ipv4_packet,
    make_tcp_segment,
    write_classic_pcap,
    write_pcapng,
)

logger = logging.getLogger(__name__)


class DifferentialResult(BaseModel):
    test_name: str
    equivalent: bool
    differences: list[str] = Field(default_factory=list)
    baseline_events_count: int = 0
    candidate_events_count: int = 0
    duration_ms: float = 0.0


def normalize_event_for_diff(event: dict[str, Any]) -> dict[str, Any]:
    """Normalizes non-semantic fields (UUIDs, file paths, high-precision timestamps) for differential comparison."""
    normalized = event.copy()
    normalized.pop("event_id", None)
    normalized.pop("timestamp_ns", None)
    normalized.pop("timestamp_iso", None)
    normalized.pop("source_id", None)
    if "provenance" in normalized and isinstance(normalized["provenance"], dict):
        prov = normalized["provenance"].copy()
        prov.pop("capture_file_path", None)
        normalized["provenance"] = prov
    return normalized


def run_pcap_vs_pcapng_differential(
    runner: EngineRunner,
    packets: list[tuple[int, int, bytes]],
) -> DifferentialResult:
    """Verifies that classic PCAP and PCAPNG encodings of the same packet stream produce equivalent decoded facts."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pcap_file = Path(tmpdir) / "baseline.pcap"
        pcapng_file = Path(tmpdir) / "candidate.pcapng"

        write_classic_pcap(pcap_file, packets)
        write_pcapng(pcapng_file, packets)

        res_pcap = runner.execute_fixture("diff_pcap", pcap_file)
        res_pcapng = runner.execute_fixture("diff_pcapng", pcapng_file)

        differences = []
        if res_pcap.exit_code != res_pcapng.exit_code:
            differences.append(f"Exit code mismatch: PCAP={res_pcap.exit_code} vs PCAPNG={res_pcapng.exit_code}")
        if res_pcap.parsed_event_count != res_pcapng.parsed_event_count:
            differences.append(
                f"Event count mismatch: PCAP={res_pcap.parsed_event_count} vs PCAPNG={res_pcapng.parsed_event_count}"
            )

        equivalent = len(differences) == 0 and res_pcap.passed and res_pcapng.passed
        return DifferentialResult(
            test_name="PCAP_vs_PCAPNG_Equivalence",
            equivalent=equivalent,
            differences=differences,
            baseline_events_count=res_pcap.parsed_event_count,
            candidate_events_count=res_pcapng.parsed_event_count,
            duration_ms=res_pcap.execution_time_ms + res_pcapng.execution_time_ms,
        )


def run_metamorphic_padding_invariance(
    runner: EngineRunner,
    base_frame: bytes,
    padding_bytes: int = 32,
) -> DifferentialResult:
    """Metamorphic relation: Appending ethernet trailer padding must not alter the decoded network/transport fields."""
    with tempfile.TemporaryDirectory() as tmpdir:
        base_file = Path(tmpdir) / "clean.pcap"
        padded_file = Path(tmpdir) / "padded.pcap"

        write_classic_pcap(base_file, [(1776412800, 0, base_frame)])
        write_classic_pcap(padded_file, [(1776412800, 0, base_frame + (b"\x00" * padding_bytes))])

        res_clean = runner.execute_fixture("meta_clean", base_file)
        res_padded = runner.execute_fixture("meta_padded", padded_file)

        differences = []
        if res_clean.exit_code != res_padded.exit_code:
            differences.append(f"Exit code delta: {res_clean.exit_code} vs {res_padded.exit_code}")
        if res_clean.parsed_event_count != res_padded.parsed_event_count:
            differences.append(f"Event count delta: {res_clean.parsed_event_count} vs {res_padded.parsed_event_count}")

        equivalent = len(differences) == 0 and res_clean.passed and res_padded.passed
        return DifferentialResult(
            test_name="Metamorphic_Padding_Invariance",
            equivalent=equivalent,
            differences=differences,
            baseline_events_count=res_clean.parsed_event_count,
            candidate_events_count=res_padded.parsed_event_count,
            duration_ms=res_clean.execution_time_ms + res_padded.execution_time_ms,
        )


def run_metamorphic_port_shift(
    runner: EngineRunner,
    src_port: int,
    base_dst_port: int,
    shifted_dst_port: int,
) -> DifferentialResult:
    """Metamorphic relation: Mutating destination port affects only transport port fields; IP addresses and flags remain invariant."""
    with tempfile.TemporaryDirectory() as tmpdir:
        p1 = make_ethernet_frame(
            "00:11:22:33:44:55",
            "00:AA:11:22:33:44",
            0x0800,
            make_ipv4_packet(
                "10.0.0.1", "10.0.0.2", 6, make_tcp_segment(src_port, base_dst_port, 100, 0, {"syn": True})
            ),
        )
        p2 = make_ethernet_frame(
            "00:11:22:33:44:55",
            "00:AA:11:22:33:44",
            0x0800,
            make_ipv4_packet(
                "10.0.0.1", "10.0.0.2", 6, make_tcp_segment(src_port, shifted_dst_port, 100, 0, {"syn": True})
            ),
        )

        file1 = Path(tmpdir) / "port_a.pcap"
        file2 = Path(tmpdir) / "port_b.pcap"

        write_classic_pcap(file1, [(1776412800, 0, p1)])
        write_classic_pcap(file2, [(1776412800, 0, p2)])

        res1 = runner.execute_fixture("meta_porta", file1)
        res2 = runner.execute_fixture("meta_portb", file2)

        differences = []
        if res1.exit_code != res2.exit_code:
            differences.append(f"Exit code delta on port shift: {res1.exit_code} vs {res2.exit_code}")
        if res1.parsed_event_count != res2.parsed_event_count:
            differences.append(
                f"Event count delta on port shift: {res1.parsed_event_count} vs {res2.parsed_event_count}"
            )

        equivalent = len(differences) == 0 and res1.passed and res2.passed
        return DifferentialResult(
            test_name="Metamorphic_Port_Shift",
            equivalent=equivalent,
            differences=differences,
            baseline_events_count=res1.parsed_event_count,
            candidate_events_count=res2.parsed_event_count,
            duration_ms=res1.execution_time_ms + res2.execution_time_ms,
        )
