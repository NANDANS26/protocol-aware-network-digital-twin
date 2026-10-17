"""Unit tests for safe C++ execution harness, differential testing, and minimizer."""

import tempfile
import zipfile
from pathlib import Path

from network_twin.testing.differential import (
    run_metamorphic_padding_invariance,
    run_metamorphic_port_shift,
    run_pcap_vs_pcapng_differential,
)
from network_twin.testing.engine_runner import EngineRunner
from network_twin.testing.generators import (
    make_ethernet_frame,
    make_ipv4_packet,
    make_tcp_segment,
    write_classic_pcap,
)
from network_twin.testing.minimizer import ReproductionBundler, TestMinimizer
from network_twin.testing.models import (
    Confidence,
    FailureCategory,
    Finding,
    FindingStatus,
    ParserComponent,
    ProtocolTarget,
    Severity,
)


def test_engine_runner_with_sample_capture():
    runner = EngineRunner()
    sample_pcap = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "sample_capture.pcap"
    assert sample_pcap.exists()

    result = runner.execute_fixture("test_sample", sample_pcap)
    assert result.exit_code == 0
    assert result.passed is True
    assert result.crash_detected is False
    assert result.sanitizer_triggered is False
    assert result.schema_valid is True
    assert result.parsed_event_count > 0


def test_engine_runner_fault_injection_modes():
    runner = EngineRunner()
    sample_pcap = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "sample_capture.pcap"

    # Injected Crash
    res_crash = runner.execute_fixture("case_crash", sample_pcap, fault_injection="CRASH")
    assert res_crash.crash_detected is True
    assert res_crash.passed is False
    assert "Memory Access Violation" in res_crash.stderr

    # Injected Hang / Timeout
    res_hang = runner.execute_fixture("case_hang", sample_pcap, timeout_sec=0.1, fault_injection="HANG")
    assert res_hang.passed is False
    assert res_hang.exit_code == -1
    assert "timed out" in res_hang.diagnostic.lower()

    # Injected Schema Violation
    res_schema = runner.execute_fixture("case_schema", sample_pcap, fault_injection="SCHEMA")
    assert res_schema.schema_valid is False
    assert res_schema.passed is False
    assert len(res_schema.schema_errors) > 0


def test_pcap_vs_pcapng_differential_equivalence():
    runner = EngineRunner()
    p = make_ethernet_frame(
        "00:11:22:33:44:55",
        "00:AA:11:22:33:44",
        0x0800,
        make_ipv4_packet("10.0.0.1", "10.0.0.2", 6, make_tcp_segment(4444, 80, 100, 0, {"syn": True})),
    )
    packets = [(1776412800, 0, p)]

    diff_res = run_pcap_vs_pcapng_differential(runner, packets)
    assert diff_res.equivalent is True
    assert diff_res.differences == []
    assert diff_res.baseline_events_count == 1
    assert diff_res.candidate_events_count == 1


def test_metamorphic_padding_invariance():
    runner = EngineRunner()
    base_frame = make_ethernet_frame(
        "00:11:22:33:44:55",
        "00:AA:11:22:33:44",
        0x0800,
        make_ipv4_packet("10.0.0.1", "10.0.0.2", 6, make_tcp_segment(4444, 80, 100, 0, {"syn": True})),
    )

    res = run_metamorphic_padding_invariance(runner, base_frame, padding_bytes=32)
    assert res.equivalent is True
    assert res.differences == []


def test_metamorphic_port_shift():
    runner = EngineRunner()
    res = run_metamorphic_port_shift(runner, src_port=1234, base_dst_port=80, shifted_dst_port=8080)
    assert res.equivalent is True


def test_delta_minimizer_and_reproduction_bundler():
    runner = EngineRunner()
    minimizer = TestMinimizer(runner)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        pcap_path = tmp_path / "trigger.pcap"

        # Create multi-byte frame
        frame = make_ethernet_frame(
            "00:11:22:33:44:55",
            "00:AA:11:22:33:44",
            0x0800,
            make_ipv4_packet(
                "10.0.0.1",
                "10.0.0.2",
                6,
                make_tcp_segment(1234, 80, 100, 0, {"syn": True}, payload=b"EXTRA_TRAILING_PAYLOAD" * 10),
            ),
        )
        write_classic_pcap(pcap_path, [(1776412800, 0, frame)])

        finding = Finding(
            finding_id="find_test_1",
            campaign_id="camp_test",
            case_id="tc_test_1",
            protocol_target=ProtocolTarget.TCP,
            parser_component=ParserComponent.TCP_DECODER,
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            failure_category=FailureCategory.INCONSISTENT_PARSING,
            input_hash="hash123",
            engine_version="1.0.0",
            reproduction_command="protocol_engine.exe ...",
            seed=42,
            expected_behavior="ACCEPT_VALID",
            actual_behavior="REJECTED",
            diagnostic="Test trigger",
            status=FindingStatus.OPEN,
            created_at="2026-10-17T12:00:00Z",
        )

        min_out_dir = tmp_path / "minimized"
        artifact = minimizer.minimize(finding, pcap_path, min_out_dir)

        assert artifact.artifact_id == "art_find_test_1"
        assert Path(artifact.fixture_path).exists()
        assert artifact.original_size_bytes >= artifact.minimized_size_bytes

        # Test bundle export
        zip_path = tmp_path / "bundle_test.zip"
        exported = ReproductionBundler.export_bundle(finding, Path(artifact.fixture_path), zip_path)
        assert exported.exists()

        with zipfile.ZipFile(exported, "r") as zf:
            files = zf.namelist()
            assert "metadata.json" in files
            assert "reproduce.ps1" in files
            assert "reproduce.sh" in files
