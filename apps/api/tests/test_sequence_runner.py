"""
Integration tests for SequenceRunner executing against the real C++ protocol engine.
"""

import pytest

from network_twin.testing.sequence_differential import (
    run_sequence_metamorphic_noise_invariance,
    run_sequence_metamorphic_timestamp_shift,
    run_sequence_pcap_vs_pcapng_differential,
)
from network_twin.testing.sequence_generators import (
    generate_segmented_http_stream,
    generate_tcp_handshake_teardown,
    generate_tcp_retransmission_and_ooo,
    generate_tcp_rst_and_abort,
    generate_tcp_simultaneous_flows,
)
from network_twin.testing.sequence_runner import SequenceRunner


@pytest.fixture
def runner():
    return SequenceRunner(timeout_sec=5.0)


def test_execute_tcp_handshake_sequence_real_engine(runner):
    seq = generate_tcp_handshake_teardown(seed=42)
    res, findings = runner.execute(seq)

    assert res.exit_code == 0
    assert res.crash_detected is False
    assert res.hang_timeout is False
    assert res.schema_valid is True
    assert res.total_events_emitted == len(seq.steps)
    assert res.total_flows_detected == 1
    assert len(findings) == 0


def test_execute_tcp_retransmission_and_ooo_real_engine(runner):
    seq = generate_tcp_retransmission_and_ooo(seed=43)
    res, findings = runner.execute(seq)

    assert res.exit_code == 0
    assert res.crash_detected is False
    assert res.total_events_emitted == len(seq.steps)


def test_execute_tcp_rst_real_engine(runner):
    seq = generate_tcp_rst_and_abort(seed=44)
    res, findings = runner.execute(seq)

    assert res.exit_code == 0
    assert res.total_events_emitted == len(seq.steps)


def test_execute_simultaneous_flows_isolation_real_engine(runner):
    seq = generate_tcp_simultaneous_flows(seed=45)
    res, findings = runner.execute(seq)

    assert res.exit_code == 0
    assert res.flow_isolation_verified is True
    assert res.total_flows_detected == 2
    assert res.total_events_emitted == len(seq.steps)


def test_execute_segmented_http_real_engine(runner):
    seq = generate_segmented_http_stream(seed=47)
    res, findings = runner.execute(seq)

    assert res.exit_code == 0
    assert res.total_events_emitted == len(seq.steps)


def test_pcap_vs_pcapng_differential_check(runner):
    seq = generate_tcp_handshake_teardown(seed=88)
    diff = run_sequence_pcap_vs_pcapng_differential(seq, runner)

    assert diff.equivalent is True
    assert len(diff.differences) == 0
    assert diff.baseline_events_count == diff.candidate_events_count


def test_metamorphic_noise_invariance(runner):
    seq = generate_tcp_handshake_teardown(seed=89)
    diff = run_sequence_metamorphic_noise_invariance(seq, runner)

    assert diff.equivalent is True
    assert diff.candidate_events_count == diff.baseline_events_count + 1


def test_metamorphic_timestamp_shift(runner):
    seq = generate_tcp_handshake_teardown(seed=90)
    diff = run_sequence_metamorphic_timestamp_shift(seq, runner)

    assert diff.equivalent is True
    assert diff.baseline_events_count == diff.candidate_events_count


def test_controlled_fault_injection_crash_detection(runner):
    seq = generate_tcp_handshake_teardown(seed=91)
    res, findings = runner.execute(seq, fault_injection="SIMULATE_CRASH")

    assert res.crash_detected is True
    assert len(findings) == 1
    assert findings[0].category.value == "CRASH"
    assert "protocol_engine" in findings[0].reproduction_command
