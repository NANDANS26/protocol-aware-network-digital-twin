"""
Stateful Protocol Sequence Models for Phase 05.

Defines typed contracts for multi-packet sequences, connection state tracking,
state transitions, sequence mutations, per-step engine observations,
sequence-level findings, and reproduction metadata.
"""

from __future__ import annotations

import enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ConnectionState(enum.StrEnum):
    """RFC 793/9293 TCP and abstract protocol connection states."""

    CLOSED = "CLOSED"
    SYN_SENT = "SYN_SENT"
    SYN_RECEIVED = "SYN_RECEIVED"
    ESTABLISHED = "ESTABLISHED"
    FIN_WAIT_1 = "FIN_WAIT_1"
    FIN_WAIT_2 = "FIN_WAIT_2"
    CLOSE_WAIT = "CLOSE_WAIT"
    CLOSING = "CLOSING"
    LAST_ACK = "LAST_ACK"
    TIME_WAIT = "TIME_WAIT"
    RESET = "RESET"
    MIDSTREAM = "MIDSTREAM"
    UNKNOWN = "UNKNOWN"


class SequenceType(enum.StrEnum):
    """Category of protocol sequence."""

    TCP_HANDSHAKE_TEARDOWN = "TCP_HANDSHAKE_TEARDOWN"
    TCP_RETRANSMISSION_OOO = "TCP_RETRANSMISSION_OOO"
    TCP_RST_AND_ABORT = "TCP_RST_AND_ABORT"
    TCP_SIMULTANEOUS_FLOWS = "TCP_SIMULTANEOUS_FLOWS"
    TCP_TUPLE_REUSE = "TCP_TUPLE_REUSE"
    IP_FRAGMENTATION = "IP_FRAGMENTATION"
    DNS_TRANSACTION_COLLISION = "DNS_TRANSACTION_COLLISION"
    HTTP_SEGMENTED_STREAM = "HTTP_SEGMENTED_STREAM"
    TLS_SEGMENTED_HANDSHAKE = "TLS_SEGMENTED_HANDSHAKE"
    METAMORPHIC_FLOW_ISOLATION = "METAMORPHIC_FLOW_ISOLATION"


class SequenceMutationType(enum.StrEnum):
    """Deterministic sequence-level mutation operators."""

    NONE = "NONE"
    REORDER_PACKETS = "REORDER_PACKETS"
    DUPLICATE_PACKET = "DUPLICATE_PACKET"
    DROP_PACKET = "DROP_PACKET"
    SHIFT_TIMESTAMPS = "SHIFT_TIMESTAMPS"
    SPLIT_SEGMENT = "SPLIT_SEGMENT"
    COALESCE_SEGMENTS = "COALESCE_SEGMENTS"
    INTERLEAVE_FLOWS = "INTERLEAVE_FLOWS"
    INSERT_UNRELATED_NOISE = "INSERT_UNRELATED_NOISE"
    REUSE_IDENTIFIERS = "REUSE_IDENTIFIERS"
    MUTATE_TEARDOWN_ORDER = "MUTATE_TEARDOWN_ORDER"
    TRUNCATE_SEQUENCE = "TRUNCATE_SEQUENCE"


class SequenceFailureCategory(enum.StrEnum):
    """Classification of sequence-level anomalies and defects."""

    CRASH = "CRASH"
    HANG_TIMEOUT = "HANG_TIMEOUT"
    SCHEMA_VIOLATION = "SCHEMA_VIOLATION"
    STATE_TRANSITION_MISMATCH = "STATE_TRANSITION_MISMATCH"
    FLOW_LEAKAGE = "FLOW_LEAKAGE"
    REASSEMBLY_MISMATCH = "REASSEMBLY_MISMATCH"
    COVERAGE_GAP_UNSUPPORTED = "COVERAGE_GAP_UNSUPPORTED"
    DIFFERENTIAL_MISMATCH = "DIFFERENTIAL_MISMATCH"


class SequenceSeverity(enum.StrEnum):
    """Defect severity for sequence-level findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class ExpectedStateTransition(BaseModel):
    """Formal assertion for a state transition at a specific step in the sequence."""

    model_config = ConfigDict(extra="forbid")

    step_index: int = Field(..., description="0-indexed step triggering the transition")
    flow_id: str = Field(..., description="Canonical flow identifier being asserted")
    expected_state: ConnectionState = Field(..., description="Expected connection state after step")
    rationale: str = Field(default="", description="RFC citation or state-machine justification")


class SequenceStep(BaseModel):
    """Single packet step within a multi-packet protocol sequence."""

    model_config = ConfigDict(extra="forbid")

    step_index: int = Field(..., description="0-indexed sequence step index")
    timestamp_offset_ns: int = Field(
        default=0, description="Relative timestamp offset in nanoseconds from sequence start"
    )
    source_ip: str = Field(default="192.168.1.100", description="IPv4 or IPv6 source address")
    destination_ip: str = Field(default="192.168.1.200", description="IPv4 or IPv6 destination address")
    source_port: int = Field(default=49152, description="Layer-4 source port")
    destination_port: int = Field(default=80, description="Layer-4 destination port")
    protocol: str = Field(default="TCP", description="L4 protocol: TCP, UDP, ICMP")
    tcp_seq: int = Field(default=0, description="TCP sequence number")
    tcp_ack: int = Field(default=0, description="TCP acknowledgment number")
    tcp_flags: dict[str, bool] = Field(
        default_factory=lambda: {"syn": False, "ack": False, "fin": False, "rst": False, "psh": False, "urg": False},
        description="TCP flag bitfield",
    )
    tcp_window: int = Field(default=64240, description="TCP advertised window size")
    ip_id: int = Field(default=1000, description="IPv4 Identification or IPv6 Fragment ID")
    ip_fragment_offset: int = Field(default=0, description="IP fragment offset in 8-byte units")
    ip_more_fragments: bool = Field(default=False, description="IP More Fragments (MF) flag")
    payload_hex: str = Field(default="", description="Raw application layer payload bytes in hex")
    label: str = Field(default="", description="Human-readable step description (e.g., 'SYN packet from client')")
    is_noise: bool = Field(default=False, description="Whether this step represents injected noise or background flow")


class SequenceMutation(BaseModel):
    """Record of a mutation applied to a base protocol sequence."""

    model_config = ConfigDict(extra="forbid")

    mutation_type: SequenceMutationType = Field(..., description="Type of sequence mutation operator applied")
    parameters: dict[str, Any] = Field(default_factory=dict, description="Operator-specific parameters")
    description: str = Field(default="", description="Summary of changes introduced by this mutation")


class ProtocolSequence(BaseModel):
    """Complete multi-packet protocol sequence specification."""

    __test__ = False  # Prevent pytest from treating this as a test class
    model_config = ConfigDict(extra="forbid")

    sequence_id: str = Field(..., description="Unique sequence identifier")
    name: str = Field(..., description="Human-readable sequence name")
    description: str = Field(default="", description="Detailed purpose and verification mission")
    sequence_type: SequenceType = Field(..., description="Category of protocol sequence")
    seed: int = Field(default=42, description="Deterministic random seed used to generate this sequence")
    generator_version: str = Field(default="1.0.0", description="Generator semantic version")
    steps: list[SequenceStep] = Field(default_factory=list, description="Ordered packet steps")
    expected_transitions: list[ExpectedStateTransition] = Field(
        default_factory=list, description="Expected state machine transitions"
    )
    expected_flow_count: int = Field(default=1, description="Expected number of unique flows identified by engine")
    expected_properties: dict[str, Any] = Field(default_factory=dict, description="High-level invariants to assert")
    mutations: list[SequenceMutation] = Field(default_factory=list, description="Mutations applied to this sequence")
    format: str = Field(default="pcap", description="Generated capture format: 'pcap' or 'pcapng'")
    fixture_path: str | None = Field(default=None, description="Path to generated PCAP/PCAPNG file")
    fixture_hash: str | None = Field(default=None, description="SHA-256 hash of fixture bytes")
    is_supported: bool = Field(
        default=True, description="Whether the C++ engine currently implements the protocol semantics"
    )
    coverage_gap_notes: str | None = Field(
        default=None, description="Documented explanation of coverage limitations if is_supported=False"
    )
    created_at_iso: str = Field(..., description="ISO 8601 creation timestamp")


class PerStepEngineObservation(BaseModel):
    """Engine observation recorded for a single step in a sequence."""

    model_config = ConfigDict(extra="forbid")

    step_index: int = Field(..., description="Sequence step index")
    event_id: str | None = Field(default=None, description="Emitted event ID if parsed successfully")
    flow_id: str | None = Field(default=None, description="Emitted flow ID")
    parser_status: str = Field(default="ok", description="Parser status: 'ok', 'truncated', 'checksum_error', etc.")
    observed_state: ConnectionState | None = Field(default=None, description="TCP state observed in flow table")
    anomalies: list[str] = Field(default_factory=list, description="Engine anomalies detected for this step")


class SequenceExecutionResult(BaseModel):
    """Result of executing a multi-packet sequence through the C++ engine."""

    __test__ = False
    model_config = ConfigDict(extra="forbid")

    execution_id: str = Field(..., description="Unique execution result ID")
    sequence_id: str = Field(..., description="Reference sequence ID")
    exit_code: int = Field(..., description="Process exit code")
    duration_ms: float = Field(..., description="Execution duration in milliseconds")
    total_events_emitted: int = Field(..., description="Number of canonical events written to JSONL")
    total_flows_detected: int = Field(..., description="Number of distinct flows detected")
    crash_detected: bool = Field(default=False, description="Whether abnormal termination or memory fault occurred")
    hang_timeout: bool = Field(default=False, description="Whether process exceeded wall-clock timeout")
    schema_valid: bool = Field(default=True, description="Whether all emitted events pass JSON Schema Draft 2020-12")
    state_transitions_verified: bool = Field(
        default=True, description="Whether all ExpectedStateTransitions were satisfied"
    )
    flow_isolation_verified: bool = Field(
        default=True, description="Whether independent flows remained completely isolated"
    )
    step_observations: list[PerStepEngineObservation] = Field(default_factory=list, description="Per-step telemetry")
    diagnostic: str | None = Field(default=None, description="Detailed diagnostic or error report")
    executed_at_iso: str = Field(..., description="ISO 8601 execution timestamp")


class SequenceFinding(BaseModel):
    """Finding or discrepancy detected during stateful sequence testing."""

    __test__ = False
    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(..., description="Unique finding identifier")
    sequence_id: str = Field(..., description="Associated sequence ID")
    severity: SequenceSeverity = Field(..., description="Defect severity")
    category: SequenceFailureCategory = Field(..., description="Failure category")
    title: str = Field(..., description="Concise finding headline")
    description: str = Field(..., description="Detailed explanation of state discrepancy or crash")
    root_cause_summary: str = Field(..., description="Technical root cause analysis")
    reproduction_command: str = Field(..., description="Self-contained CLI reproduction command")
    fixture_path: str = Field(..., description="Path to trigger fixture")
    fixture_hash: str = Field(..., description="SHA-256 fingerprint of trigger fixture")
    minimized: bool = Field(default=False, description="Whether sequence minimization has occurred")
    minimized_sequence_id: str | None = Field(default=None, description="ID of minimized sequence if available")
    is_regression: bool = Field(
        default=False, description="Whether this finding has been promoted to a regression test"
    )
    created_at_iso: str = Field(..., description="ISO 8601 creation timestamp")


class SequenceReproductionMetadata(BaseModel):
    """Metadata accompanying a sequence reproduction bundle."""

    __test__ = False
    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(..., description="Associated finding ID")
    sequence_id: str = Field(..., description="Sequence ID")
    original_step_count: int = Field(..., description="Number of steps in original sequence")
    minimized_step_count: int = Field(..., description="Number of steps in minimized sequence")
    reduction_ratio: float = Field(..., description="Fraction of steps removed (0.0 - 1.0)")
    removed_steps: list[int] = Field(default_factory=list, description="Indices of steps stripped during minimization")
    cli_command: str = Field(..., description="CLI execution command")
    reproduction_script_ps1: str = Field(..., description="PowerShell reproduction script")
    reproduction_script_sh: str = Field(..., description="POSIX shell reproduction script")


class SequenceRegressionFixture(BaseModel):
    """Permanent regression test entry stored in catalog."""

    __test__ = False
    model_config = ConfigDict(extra="forbid")

    regression_id: str = Field(..., description="Unique regression fixture ID")
    finding_id: str = Field(..., description="Originating finding ID")
    name: str = Field(..., description="Regression test name")
    sequence_type: SequenceType = Field(..., description="Sequence category")
    fixture_path: str = Field(..., description="Path to persistent regression PCAP")
    fixture_hash: str = Field(..., description="SHA-256 hash of regression fixture")
    expected_exit_code: int = Field(default=0, description="Expected engine exit code")
    expected_to_pass: bool = Field(default=True, description="Whether test is expected to cleanly pass")
    created_at_iso: str = Field(..., description="ISO 8601 creation timestamp")
    last_run_iso: str | None = Field(default=None, description="Last execution timestamp")
    last_run_passed: bool | None = Field(default=None, description="Outcome of last execution")
