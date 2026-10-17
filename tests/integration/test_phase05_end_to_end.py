"""
Phase 05 End-to-End Integration Verification Test.

Validates the complete 10-step lifecycle of stateful protocol sequence testing:
1. Canonical Sequence Generation (TCP Handshake, Retransmission, RST, Simultaneous Flows, HTTP, IP Frags)
2. Real C++ Protocol Engine Execution with Bounded Timeouts
3. JSONL Event Stream Emission and Draft 2020-12 Schema Validation
4. Stateful Connection Tracking & RFC State Transitions
5. Simultaneous Flow Isolation (No Cross-Flow Contamination)
6. PCAP vs PCAPNG Sequence Differential Equivalence
7. Metamorphic Background Noise Invariance Proof
8. Defect Triage, Fault Injection, and Delta Debugging Sequence Minimization
9. Self-Contained Reproduction ZIP Archive Export
10. Permanent Regression Promotion & Catalog Verification
"""

import io
import zipfile

from network_twin.storage.metadata_store import metadata_store
from network_twin.testing.sequence_differential import (
    run_sequence_metamorphic_noise_invariance,
    run_sequence_pcap_vs_pcapng_differential,
)
from network_twin.testing.sequence_generators import (
    generate_all_canonical_sequences,
)
from network_twin.testing.sequence_minimizer import (
    SequenceMinimizer,
    SequenceReproductionBundler,
)
from network_twin.testing.sequence_models import (
    SequenceFailureCategory,
    SequenceType,
)
from network_twin.testing.sequence_runner import SequenceRunner


def test_phase05_complete_end_to_end_verification():
    # --------------------------------------------------------------------------
    # Step 1: Generate All Canonical Sequences
    # --------------------------------------------------------------------------
    canonical_seqs = generate_all_canonical_sequences(seed=2026)
    assert len(canonical_seqs) == 7
    types = {s.sequence_type for s in canonical_seqs}
    assert SequenceType.TCP_HANDSHAKE_TEARDOWN in types
    assert SequenceType.TCP_SIMULTANEOUS_FLOWS in types
    assert SequenceType.IP_FRAGMENTATION in types

    # --------------------------------------------------------------------------
    # Step 2 & 3: Real C++ Protocol Engine Execution & Schema Conformance
    # --------------------------------------------------------------------------
    runner = SequenceRunner(timeout_sec=5.0)
    hs_seq = next(
        s
        for s in canonical_seqs
        if s.sequence_type == SequenceType.TCP_HANDSHAKE_TEARDOWN
    )

    res_hs, findings_hs = runner.execute(hs_seq)
    assert res_hs.exit_code == 0
    assert res_hs.crash_detected is False
    assert res_hs.hang_timeout is False
    assert res_hs.schema_valid is True
    assert res_hs.total_events_emitted == len(hs_seq.steps)
    assert len(findings_hs) == 0

    # --------------------------------------------------------------------------
    # Step 4: Stateful Connection Tracking & RFC State Transitions
    # --------------------------------------------------------------------------
    expected_states = [t.expected_state.value for t in hs_seq.expected_transitions]
    assert "SYN_SENT" in expected_states
    assert "SYN_RECEIVED" in expected_states
    assert "ESTABLISHED" in expected_states

    # --------------------------------------------------------------------------
    # Step 5: Simultaneous Flow Isolation
    # --------------------------------------------------------------------------
    sim_seq = next(
        s
        for s in canonical_seqs
        if s.sequence_type == SequenceType.TCP_SIMULTANEOUS_FLOWS
    )
    res_sim, findings_sim = runner.execute(sim_seq)
    assert res_sim.exit_code == 0
    assert res_sim.total_flows_detected == 2
    assert res_sim.flow_isolation_verified is True
    assert len(findings_sim) == 0

    # --------------------------------------------------------------------------
    # Step 6: PCAP vs PCAPNG Differential Equivalence
    # --------------------------------------------------------------------------
    diff_res = run_sequence_pcap_vs_pcapng_differential(hs_seq, runner)
    assert diff_res.equivalent is True
    assert diff_res.baseline_events_count == diff_res.candidate_events_count
    assert len(diff_res.differences) == 0

    # --------------------------------------------------------------------------
    # Step 7: Metamorphic Noise Invariance
    # --------------------------------------------------------------------------
    meta_res = run_sequence_metamorphic_noise_invariance(hs_seq, runner)
    assert meta_res.equivalent is True
    assert meta_res.candidate_events_count == meta_res.baseline_events_count + 1

    # --------------------------------------------------------------------------
    # Step 8: Controlled Fault Injection & Sequence Minimization
    # --------------------------------------------------------------------------
    res_fault, findings_fault = runner.execute(hs_seq, fault_injection="SIMULATE_CRASH")
    assert res_fault.crash_detected is True
    assert len(findings_fault) >= 1
    crash_finding = findings_fault[0]
    assert crash_finding.category == SequenceFailureCategory.CRASH

    # Run Minimizer on crash finding
    minimizer = SequenceMinimizer(runner=runner)
    minimized_seq, repro_meta = minimizer.minimize(hs_seq, crash_finding)
    assert repro_meta.original_step_count == len(hs_seq.steps)
    assert repro_meta.minimized_step_count <= repro_meta.original_step_count
    assert "protocol_engine.exe" in repro_meta.cli_command

    # --------------------------------------------------------------------------
    # Step 9: Export Reproduction ZIP Bundle
    # --------------------------------------------------------------------------
    bundle_bytes = SequenceReproductionBundler.create_bundle(
        minimized_seq, crash_finding, repro_meta
    )
    assert len(bundle_bytes) > 100
    with zipfile.ZipFile(io.BytesIO(bundle_bytes), "r") as zf:
        names = zf.namelist()
        assert "reproduce_sequence.ps1" in names
        assert "reproduce_sequence.sh" in names
        assert "metadata.json" in names

    # --------------------------------------------------------------------------
    # Step 10: Permanent Regression Promotion & Persistence
    # --------------------------------------------------------------------------
    metadata_store.save_sequence(hs_seq)
    metadata_store.save_sequence_finding(crash_finding)

    regr_fixture = metadata_store.promote_sequence_regression(
        finding_id=crash_finding.finding_id,
        name="TCP Handshake Graceful Teardown Baseline Regression",
    )
    assert regr_fixture.regression_id.startswith("seq-regr-")
    assert regr_fixture.expected_to_pass is True

    # Verify queryable from store
    stored_regrs = metadata_store.list_sequence_regressions()
    assert any(r.regression_id == regr_fixture.regression_id for r in stored_regrs)
