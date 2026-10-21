"""Typed contracts and data models for Phase 07 reproducible benchmarking."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, model_validator


class BenchmarkProvenance(StrEnum):
    """Origin of benchmark dataset or packet capture."""

    REAL_CAPTURE = "REAL_CAPTURE"
    PUBLIC_CAPTURE = "PUBLIC_CAPTURE"
    SYNTHETIC_FIXTURE = "SYNTHETIC_FIXTURE"


class BenchmarkCategory(StrEnum):
    """Taxonomy category of benchmark evaluation."""

    HAND_VERIFIABLE_CORE = "HAND_VERIFIABLE_CORE"
    STATEFUL_FLOWS = "STATEFUL_FLOWS"
    DNS_TOPOLOGY_CHANGES = "DNS_TOPOLOGY_CHANGES"
    SECURITY_VIOLATION = "SECURITY_VIOLATION"
    MALFORMED_EDGE_CASES = "MALFORMED_EDGE_CASES"
    SCALE_PROFILING = "SCALE_PROFILING"


class BaselineComparisonStatus(StrEnum):
    """Classification of learned model accuracy relative to deterministic baselines."""

    BEATS_BASELINE = "BEATS_BASELINE"
    LAGS_BASELINE = "LAGS_BASELINE"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


class ExpectedOutcome(BaseModel):
    """Independently derived expected behavior for a benchmark fixture."""

    min_packets: int = Field(default=0, description="Minimum expected packet count")
    expected_flows: int = Field(default=0, description="Expected stateful flow count")
    expected_lpm_next_hop: str | None = Field(default=None, description="Expected next hop IP for LPM route test")
    expected_forwarding_status: str | None = Field(
        default=None, description="Expected forwarding outcome: DELIVERED, DROPPED_BY_FIREWALL, FORWARDING_LOOP"
    )
    expected_invariant_status: str | None = Field(
        default=None, description="Expected security invariant status: HOLD, VIOLATED, INDETERMINATE"
    )
    ground_truth_rationale: str = Field(description="Deterministic justification derived independently of the engine")


class BenchmarkFixtureMeta(BaseModel):
    """Metadata describing a reproducible benchmark fixture."""

    fixture_id: str
    name: str
    category: BenchmarkCategory
    provenance: BenchmarkProvenance
    description: str
    packet_count: int
    byte_size: int
    content_sha256: str
    expected_properties: ExpectedOutcome
    byte_count: int | None = None
    expected_outcome: ExpectedOutcome | None = None
    provenance_details: str | None = None

    @model_validator(mode="before")
    @classmethod
    def sync_compat_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "byte_count" not in data or data["byte_count"] is None:
                data["byte_count"] = data.get("byte_size", 0)
            if "byte_size" not in data or data["byte_size"] is None:
                data["byte_size"] = data.get("byte_count", 0)
            if "expected_outcome" not in data or data["expected_outcome"] is None:
                data["expected_outcome"] = data.get("expected_properties")
            if "expected_properties" not in data or data["expected_properties"] is None:
                data["expected_properties"] = data.get("expected_outcome")
            if "provenance_details" not in data or data["provenance_details"] is None:
                data["provenance_details"] = data.get("description", "")
        return data


class DecodingStageMetrics(BaseModel):
    """Metrics recorded during packet decoding and event generation."""

    packets_decoded: int
    bytes_processed: int
    duration_ms: float
    throughput_pkts_per_sec: float
    errors_encountered: list[str] = Field(default_factory=list)
    packet_count: int | None = None
    byte_count: int | None = None
    throughput_pps: float | None = None

    @model_validator(mode="before")
    @classmethod
    def sync_compat_metrics(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "packet_count" not in data or data["packet_count"] is None:
                data["packet_count"] = data.get("packets_decoded", 0)
            if "byte_count" not in data or data["byte_count"] is None:
                data["byte_count"] = data.get("bytes_processed", 0)
            if "throughput_pps" not in data or data["throughput_pps"] is None:
                data["throughput_pps"] = data.get("throughput_pkts_per_sec", 0.0)
        return data


class DeterministicStageMetrics(BaseModel):
    """Metrics recorded during deterministic simulation and formal verification."""

    model_id: str | None = None
    forwarding_status: str
    forwarding_matches_expected: bool
    invariant_status: str
    invariant_matches_expected: bool
    witness_path_length: int = 0
    duration_ms: float
    topology_node_count: int | None = None
    topology_edge_count: int | None = None
    violation_count: int | None = None


class PredictiveStageMetrics(BaseModel):
    """Metrics comparing learned models to baseline models on held-out windows."""

    target: str
    sample_count: int
    train_count: int
    test_count: int
    baseline_algorithm: str
    baseline_mae: float | None = None
    baseline_rmse: float | None = None
    learned_algorithm: str
    learned_mae: float | None = None
    learned_rmse: float | None = None
    relative_improvement_pct: float | None = None
    comparison_status: BaselineComparisonStatus
    conformal_coverage_pct: float | None = None
    conformal_interval_mean_width: float | None = None
    ood_in_dist_score: float | None = None
    ood_shifted_score: float | None = None
    duration_ms: float


class ConsensusStageMetrics(BaseModel):
    """Metrics verifying ground truth supremacy in scenario consensus."""

    consensus_status: str
    ground_truth_held: bool
    explanation: str


class OperationalProfile(BaseModel):
    """Resource utilization and execution profile."""

    total_runtime_ms: float = 0.0
    peak_memory_mb: float = 0.0
    storage_bytes_delta: int = 0
    memory_growth_mb: float | None = None
    cpu_duration_ms: float | None = None
    wall_duration_ms: float | None = None

    @model_validator(mode="before")
    @classmethod
    def sync_profile_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            total = data.get("total_runtime_ms", 0.0)
            if "wall_duration_ms" not in data or data["wall_duration_ms"] is None:
                data["wall_duration_ms"] = total
            if "cpu_duration_ms" not in data or data["cpu_duration_ms"] is None:
                data["cpu_duration_ms"] = total
            if "memory_growth_mb" not in data or data["memory_growth_mb"] is None:
                data["memory_growth_mb"] = 0.0
        return data


class BenchmarkRunRecord(BaseModel):
    """Full persistent audit record for a single benchmark execution."""

    run_id: str
    fixture_id: str
    fixture_name: str
    provenance: BenchmarkProvenance
    category: BenchmarkCategory
    fixture_sha256: str
    git_commit: str = "ead9e00"
    software_version: str = "0.7.0"
    executed_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    status: str = "COMPLETED"
    decoding: DecodingStageMetrics
    deterministic: DeterministicStageMetrics
    predictive: PredictiveStageMetrics | None = None
    consensus: ConsensusStageMetrics | None = None
    operational: OperationalProfile
    profile: OperationalProfile | None = None
    timestamp_iso: str | None = None
    verification_passed: bool | None = None
    failure_reasons: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def sync_compat_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if ("profile" not in data or data["profile"] is None) and data.get("operational"):
                data["profile"] = data["operational"]
            if ("operational" not in data or data["operational"] is None) and data.get("profile"):
                data["operational"] = data["profile"]
            if ("timestamp_iso" not in data or data["timestamp_iso"] is None) and data.get("executed_at"):
                data["timestamp_iso"] = data["executed_at"]
            if ("executed_at" not in data or data["executed_at"] is None) and data.get("timestamp_iso"):
                data["executed_at"] = data["timestamp_iso"]
            if "verification_passed" not in data or data["verification_passed"] is None:
                data["verification_passed"] = data.get("status") == "COMPLETED"
            if "failure_reasons" not in data or data["failure_reasons"] is None:
                data["failure_reasons"] = data.get("limitations", [])
            if "limitations" not in data or data["limitations"] is None:
                data["limitations"] = data.get("failure_reasons", [])
        return data

    @model_validator(mode="after")
    def populate_post_validation_fields(self) -> "BenchmarkRunRecord":
        if not self.timestamp_iso:
            self.timestamp_iso = self.executed_at
        if not self.profile:
            self.profile = self.operational
        if self.verification_passed is None:
            self.verification_passed = self.status == "COMPLETED"
        if not self.failure_reasons:
            self.failure_reasons = list(self.limitations)
        return self


class BenchmarkRunRequest(BaseModel):
    """Request payload to trigger benchmark execution."""

    fixture_id: str = Field(default="all", description="Fixture ID or 'all' for full validation suite")
    random_seed: int = Field(default=42, description="Random seed for deterministic evaluation")


class BenchmarkSummaryResponse(BaseModel):
    """High-level summary of all benchmark runs and systemic validity."""

    total_runs: int
    verified_fixtures_count: int
    average_throughput_pkts_sec: float
    deterministic_accuracy_pct: float
    models_beating_baseline_pct: float
    runs: list[BenchmarkRunRecord]
