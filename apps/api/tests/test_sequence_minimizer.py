"""
Unit and integration tests for SequenceMinimizer and SequenceReproductionBundler.
"""

import io
import json
import zipfile

from network_twin.testing.sequence_generators import (
    apply_sequence_mutations,
    generate_tcp_handshake_teardown,
)
from network_twin.testing.sequence_minimizer import (
    SequenceMinimizer,
    SequenceReproductionBundler,
)
from network_twin.testing.sequence_models import (
    SequenceFailureCategory,
    SequenceFinding,
    SequenceMutation,
    SequenceMutationType,
    SequenceReproductionMetadata,
    SequenceSeverity,
)


def test_sequence_minimizer_reduces_noisy_sequence():
    base_seq = generate_tcp_handshake_teardown(seed=42)
    # Inject 2 noise packets
    mut = SequenceMutation(
        mutation_type=SequenceMutationType.INSERT_UNRELATED_NOISE,
        parameters={},
        description="Noise injection",
    )
    noisy_seq = apply_sequence_mutations(base_seq, [mut, mut], seed=43)
    assert len(noisy_seq.steps) == len(base_seq.steps) + 2

    # Mock runner that triggers crash whenever more than 5 steps exist
    class MockRunner:
        def execute(self, seq):
            crash = len(seq.steps) >= 5
            finding = SequenceFinding(
                finding_id=f"find-{seq.sequence_id}",
                sequence_id=seq.sequence_id,
                severity=SequenceSeverity.CRITICAL,
                category=SequenceFailureCategory.CRASH,
                title="Simulated Crash",
                description="Simulated crash on large sequence",
                root_cause_summary="Simulated test crash",
                reproduction_command="protocol_engine.exe test",
                fixture_path="test.pcap",
                fixture_hash="hash123",
                created_at_iso="2026-10-17T12:00:00Z",
            )

            class Res:
                crash_detected = crash

            return Res(), [finding] if crash else []

    target_finding = SequenceFinding(
        finding_id="find-initial",
        sequence_id=noisy_seq.sequence_id,
        severity=SequenceSeverity.CRITICAL,
        category=SequenceFailureCategory.CRASH,
        title="Initial Target Finding",
        description="Crash",
        root_cause_summary="Initial crash",
        reproduction_command="protocol_engine.exe test",
        fixture_path="test.pcap",
        fixture_hash="hash123",
        created_at_iso="2026-10-17T12:00:00Z",
    )

    minimizer = SequenceMinimizer(runner=MockRunner())
    minimized_seq, meta = minimizer.minimize(noisy_seq, target_finding)

    assert meta.minimized_step_count < meta.original_step_count
    assert meta.reduction_ratio > 0.0
    assert len(minimized_seq.steps) == meta.minimized_step_count
    assert "protocol_engine.exe" in meta.cli_command


def test_sequence_reproduction_bundler():
    seq = generate_tcp_handshake_teardown(seed=42)
    finding = SequenceFinding(
        finding_id="find-repro-01",
        sequence_id=seq.sequence_id,
        severity=SequenceSeverity.HIGH,
        category=SequenceFailureCategory.STATE_TRANSITION_MISMATCH,
        title="State Mismatch in Handshake",
        description="TCP state tracker missed SYN-ACK transition",
        root_cause_summary="Simulated root cause",
        reproduction_command="protocol_engine.exe --input test.pcap --format pcap",
        fixture_path="test.pcap",
        fixture_hash="abc123sha",
        created_at_iso="2026-10-17T12:00:00Z",
    )
    metadata = SequenceReproductionMetadata(
        finding_id=finding.finding_id,
        sequence_id=seq.sequence_id,
        original_step_count=9,
        minimized_step_count=5,
        reduction_ratio=0.44,
        removed_steps=[5, 6, 7, 8],
        cli_command=finding.reproduction_command,
        reproduction_script_ps1="& .\\protocol_engine.exe",
        reproduction_script_sh="./protocol_engine",
    )

    zip_bytes = SequenceReproductionBundler.create_bundle(seq, finding, metadata)
    assert len(zip_bytes) > 50

    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
        namelist = zf.namelist()
        assert f"{seq.sequence_id}.pcap" in namelist
        assert "reproduce_sequence.ps1" in namelist
        assert "reproduce_sequence.sh" in namelist
        assert "metadata.json" in namelist

        meta_json = json.loads(zf.read("metadata.json").decode("utf-8"))
        assert meta_json["finding_id"] == "find-repro-01"
        assert meta_json["original_steps"] == 9
        assert meta_json["minimized_steps"] == 5
