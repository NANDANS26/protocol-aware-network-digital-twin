"""Data models for Phase 09 Real-Capture Validation, Differential Testing & Evidence."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CaptureProvenance(StrEnum):
    PUBLIC_CAPTURE = "PUBLIC_CAPTURE"
    AUTHORIZED_LOCAL = "AUTHORIZED_LOCAL"
    SYNTHETIC_FIXTURE = "SYNTHETIC_FIXTURE"


class CaptureFormat(StrEnum):
    PCAP = "PCAP"
    PCAPNG = "PCAPNG"


class CaptureExpectedOutcome(BaseModel):
    total_packets: int = Field(..., description="Expected total packet count")
    total_flows: int = Field(0, description="Expected total flow count")
    dns_queries: int = Field(0, description="Expected DNS queries count")
    dns_responses: int = Field(0, description="Expected DNS responses count")
    http_requests: int = Field(0, description="Expected HTTP requests count")
    http_responses: int = Field(0, description="Expected HTTP responses count")
    tls_handshakes: int = Field(0, description="Expected TLS handshakes count")
    extracted_sni: str | None = Field(None, description="Expected TLS SNI hostname")
    vlan_tags: list[int] = Field(default_factory=list, description="Expected 802.1Q VLAN IDs")
    has_fragments: bool = Field(False, description="Whether capture contains fragmented IP packets")
    has_retransmissions: bool = Field(False, description="Whether capture exercises TCP retransmissions")
    has_out_of_order: bool = Field(False, description="Whether capture exercises out-of-order segments")
    has_malformed: bool = Field(False, description="Whether capture contains truncated or malformed frames")
    parser_status: str = Field("ok", description="Expected overall parser status (ok, malformed, truncated)")


class CaptureManifestItem(BaseModel):
    capture_id: str = Field(..., description="Unique deterministic identifier for capture fixture")
    name: str = Field(..., description="Human-readable title of the capture")
    format: CaptureFormat = Field(..., description="Container format: PCAP or PCAPNG")
    provenance: CaptureProvenance = Field(..., description="Origin classification")
    source: str = Field(..., description="Verified origin, RFC, or generator attribution")
    license: str = Field(..., description="Software/Data license (e.g., GPL-2.0, CC0, Apache-2.0)")
    attribution: str = Field(..., description="Author or organization attribution")
    sha256: str = Field(..., description="Cryptographic SHA-256 fingerprint of the raw capture file")
    file_name: str = Field(..., description="File name inside data/captures directory")
    file_size_bytes: int = Field(..., description="Exact file size in bytes")
    packet_count: int = Field(..., description="Total packet count in capture")
    protocols: list[str] = Field(default_factory=list, description="List of represented protocols")
    scenarios: list[str] = Field(default_factory=list, description="Network scenarios exercised")
    expected_outcomes: CaptureExpectedOutcome = Field(..., description="Independently established expected outcomes")
    known_limitations: list[str] = Field(
        default_factory=list, description="Explicitly documented unsupported behavior or scope bounds"
    )


class ProcessResourceTelemetry(BaseModel):
    wall_duration_ms: float = Field(..., description="Total wall-clock duration in milliseconds")
    throughput_pps: float = Field(0.0, description="Packets per second throughput")
    throughput_mbps: float = Field(0.0, description="Megabits per second throughput")
    peak_native_memory_bytes: int = Field(
        0, description="Peak native process WorkingSet / RSS memory measured separately"
    )
    python_heap_bytes: int = Field(0, description="Python runtime heap allocation measured via tracemalloc")


class FieldComparisonDifference(BaseModel):
    packet_index: int = Field(..., description="0-indexed packet sequence number")
    field_name: str = Field(..., description="Name of the header field compared")
    cpp_engine_value: Any = Field(..., description="Value produced by C++ systems engine")
    reference_decoder_value: Any = Field(..., description="Independently calculated reference value")
    match: bool = Field(..., description="Whether fields matched exactly")


class CaptureValidationReport(BaseModel):
    validation_id: str = Field(..., description="Unique identifier for validation run")
    capture_id: str = Field(..., description="Target capture identifier")
    timestamp: datetime = Field(..., description="Timestamp of validation")
    passed: bool = Field(..., description="Overall verification outcome")
    total_packets_processed: int = Field(..., description="Observed packet count")
    total_flows_observed: int = Field(..., description="Observed flow count")
    protocol_distribution: dict[str, int] = Field(default_factory=dict, description="Counts of decoded protocols")
    parser_status_counts: dict[str, int] = Field(default_factory=dict, description="Counts of parser statuses")
    telemetry: ProcessResourceTelemetry = Field(..., description="Resource consumption telemetry")
    field_differences: list[FieldComparisonDifference] = Field(
        default_factory=list, description="Discrepancies against reference decoder"
    )
    explanation: str = Field(..., description="Summary explanation of validation verdict")


class MetamorphicRelationType(StrEnum):
    FORMAT_EQUIVALENCE = "FORMAT_EQUIVALENCE"
    TIMESTAMP_SHIFT = "TIMESTAMP_SHIFT"
    NOISE_INJECTION = "NOISE_INJECTION"
    PACKET_DUPLICATION = "PACKET_DUPLICATION"
    PACKET_REORDERING = "PACKET_REORDERING"


class DifferentialTestResult(BaseModel):
    test_id: str = Field(..., description="Unique identifier for differential test")
    relation_type: MetamorphicRelationType = Field(..., description="Metamorphic or differential relation tested")
    base_capture_id: str = Field(..., description="Baseline capture fixture")
    transformed_capture_id: str | None = Field(None, description="Transformed capture fixture if applicable")
    passed: bool = Field(..., description="Whether metamorphic invariant was satisfied")
    expected_invariant: str = Field(..., description="Hand-verifiable invariant assertion description")
    observed_behavior: str = Field(..., description="Actual observed behavior across both runs")
    execution_time_ms: float = Field(..., description="Total execution time in milliseconds")
    details: dict[str, Any] = Field(default_factory=dict, description="Structured metric comparison data")
