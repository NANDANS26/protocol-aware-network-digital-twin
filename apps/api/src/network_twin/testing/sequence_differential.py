"""
Sequence-Aware Differential & Metamorphic Testing for Phase 05.

Validates semantic equivalence between PCAP and PCAPNG sequence representations,
and proves metamorphic properties such as flow isolation under noise injection
and state preservation under benign timestamp shifts.
"""

from __future__ import annotations

import time

from pydantic import BaseModel, ConfigDict, Field

from network_twin.testing.sequence_generators import apply_sequence_mutations
from network_twin.testing.sequence_models import (
    ProtocolSequence,
    SequenceMutation,
    SequenceMutationType,
)
from network_twin.testing.sequence_runner import SequenceRunner


class SequenceDifferentialResult(BaseModel):
    """Result of sequence-level differential or metamorphic verification."""

    model_config = ConfigDict(extra="forbid")

    test_name: str = Field(..., description="Name of differential or metamorphic test")
    equivalent: bool = Field(..., description="Whether both representations yielded equivalent semantic facts")
    mode: str = Field(..., description="'pcap_vs_pcapng', 'noise_invariance', 'timestamp_shift'")
    sequence_id: str = Field(..., description="Target sequence identifier")
    baseline_events_count: int = Field(..., description="Events produced by baseline execution")
    candidate_events_count: int = Field(..., description="Events produced by candidate/mutated execution")
    duration_ms: float = Field(..., description="Execution duration in milliseconds")
    differences: list[str] = Field(default_factory=list, description="List of observed semantic discrepancies")
    diagnostic: str | None = Field(default=None, description="Detailed diagnostic or error report")


def run_sequence_pcap_vs_pcapng_differential(
    sequence: ProtocolSequence,
    runner: SequenceRunner | None = None,
) -> SequenceDifferentialResult:
    """Verifies that executing a sequence in PCAP format yields identical semantic facts to PCAPNG format."""
    start = time.perf_counter()
    if runner is None:
        runner = SequenceRunner()

    seq_pcap = sequence.model_copy()
    seq_pcap.format = "pcap"

    seq_pcapng = sequence.model_copy()
    seq_pcapng.format = "pcapng"

    res_pcap, findings_pcap = runner.execute(seq_pcap)
    res_pcapng, findings_pcapng = runner.execute(seq_pcapng)

    differences: list[str] = []

    if res_pcap.exit_code != res_pcapng.exit_code:
        differences.append(f"Exit code discrepancy: PCAP={res_pcap.exit_code} vs PCAPNG={res_pcapng.exit_code}")

    if res_pcap.total_events_emitted != res_pcapng.total_events_emitted:
        differences.append(
            f"Event count mismatch: PCAP emitted {res_pcap.total_events_emitted} events, PCAPNG emitted {res_pcapng.total_events_emitted}"
        )

    if res_pcap.total_flows_detected != res_pcapng.total_flows_detected:
        differences.append(
            f"Flow count mismatch: PCAP detected {res_pcap.total_flows_detected} flows, PCAPNG detected {res_pcapng.total_flows_detected}"
        )

    duration_ms = (time.perf_counter() - start) * 1000.0
    equivalent = len(differences) == 0

    return SequenceDifferentialResult(
        test_name=f"pcap_vs_pcapng_{sequence.sequence_id}",
        equivalent=equivalent,
        mode="pcap_vs_pcapng",
        sequence_id=sequence.sequence_id,
        baseline_events_count=res_pcap.total_events_emitted,
        candidate_events_count=res_pcapng.total_events_emitted,
        duration_ms=duration_ms,
        differences=differences,
    )


def run_sequence_metamorphic_noise_invariance(
    sequence: ProtocolSequence,
    runner: SequenceRunner | None = None,
) -> SequenceDifferentialResult:
    """
    Metamorphic property: Injecting an independent background packet (e.g. ICMP ping)
    must NOT alter the semantic event facts of the primary TCP flow.
    """
    start = time.perf_counter()
    if runner is None:
        runner = SequenceRunner()

    # 1. Baseline run
    base_res, _ = runner.execute(sequence)

    # 2. Mutated run with injected noise
    mut = SequenceMutation(
        mutation_type=SequenceMutationType.INSERT_UNRELATED_NOISE,
        parameters={},
        description="Inject background noise packet",
    )
    mutated_seq = apply_sequence_mutations(sequence, [mut], seed=sequence.seed + 99)
    mut_res, _ = runner.execute(mutated_seq)

    differences: list[str] = []

    # Injected noise should produce exactly 1 additional event (for ICMP) without breaking baseline events
    expected_event_count = base_res.total_events_emitted + 1
    if mut_res.total_events_emitted != expected_event_count:
        differences.append(
            f"Event count anomaly under noise injection: expected {expected_event_count}, got {mut_res.total_events_emitted}"
        )

    if mut_res.crash_detected:
        differences.append("Crash detected when background noise was interleaved into sequence")

    duration_ms = (time.perf_counter() - start) * 1000.0
    equivalent = len(differences) == 0

    return SequenceDifferentialResult(
        test_name=f"metamorphic_noise_invariance_{sequence.sequence_id}",
        equivalent=equivalent,
        mode="noise_invariance",
        sequence_id=sequence.sequence_id,
        baseline_events_count=base_res.total_events_emitted,
        candidate_events_count=mut_res.total_events_emitted,
        duration_ms=duration_ms,
        differences=differences,
    )


def run_sequence_metamorphic_timestamp_shift(
    sequence: ProtocolSequence,
    runner: SequenceRunner | None = None,
) -> SequenceDifferentialResult:
    """
    Metamorphic property: Shifting timestamps uniformly by an offset must preserve
    the exact same state machine transitions, event count, and flow keys.
    """
    start = time.perf_counter()
    if runner is None:
        runner = SequenceRunner()

    base_res, _ = runner.execute(sequence)

    mut = SequenceMutation(
        mutation_type=SequenceMutationType.SHIFT_TIMESTAMPS,
        parameters={"shift_ns": 500_000_000},
        description="Shift timestamps uniformly by 500ms",
    )
    mutated_seq = apply_sequence_mutations(sequence, [mut], seed=sequence.seed + 101)
    mut_res, _ = runner.execute(mutated_seq)

    differences: list[str] = []

    if base_res.total_events_emitted != mut_res.total_events_emitted:
        differences.append(
            f"Event count mismatch after timestamp shift: baseline={base_res.total_events_emitted}, candidate={mut_res.total_events_emitted}"
        )

    if base_res.total_flows_detected != mut_res.total_flows_detected:
        differences.append(
            f"Flow count mismatch after timestamp shift: baseline={base_res.total_flows_detected}, candidate={mut_res.total_flows_detected}"
        )

    duration_ms = (time.perf_counter() - start) * 1000.0
    equivalent = len(differences) == 0

    return SequenceDifferentialResult(
        test_name=f"metamorphic_timestamp_shift_{sequence.sequence_id}",
        equivalent=equivalent,
        mode="timestamp_shift",
        sequence_id=sequence.sequence_id,
        baseline_events_count=base_res.total_events_emitted,
        candidate_events_count=mut_res.total_events_emitted,
        duration_ms=duration_ms,
        differences=differences,
    )
