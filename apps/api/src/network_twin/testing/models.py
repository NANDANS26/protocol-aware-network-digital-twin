"""Strongly typed formal models for protocol security test generation, fuzzing, and differential verification."""

from enum import StrEnum

from pydantic import BaseModel, Field


class ProtocolTarget(StrEnum):
    ETHERNET = "ETHERNET"
    VLAN = "VLAN"
    IPV4 = "IPV4"
    IPV6 = "IPV6"
    TCP = "TCP"
    UDP = "UDP"
    DNS = "DNS"
    HTTP = "HTTP"
    TLS_CLIENT_HELLO = "TLS_CLIENT_HELLO"
    QUIC_CLASSIFIER = "QUIC_CLASSIFIER"


class ParserComponent(StrEnum):
    ETHERNET_DECODER = "ETHERNET_DECODER"
    IPV4_DECODER = "IPV4_DECODER"
    IPV6_DECODER = "IPV6_DECODER"
    TCP_DECODER = "TCP_DECODER"
    UDP_DECODER = "UDP_DECODER"
    DNS_PARSER = "DNS_PARSER"
    HTTP_PARSER = "HTTP_PARSER"
    TLS_PARSER = "TLS_PARSER"
    QUIC_CLASSIFIER = "QUIC_CLASSIFIER"
    CAPTURE_READER = "CAPTURE_READER"


class GenerationStrategy(StrEnum):
    BASELINE_CONFORMANCE = "BASELINE_CONFORMANCE"
    MUTATION_FUZZING = "MUTATION_FUZZING"
    BOUNDARY_EDGE_CASES = "BOUNDARY_EDGE_CASES"
    MALFORMED_INPUTS = "MALFORMED_INPUTS"
    DIFFERENTIAL_EQUIVALENCE = "DIFFERENTIAL_EQUIVALENCE"


class MutationOperator(StrEnum):
    NONE = "NONE"
    TRUNCATE_HEADER = "TRUNCATE_HEADER"
    TRUNCATE_PAYLOAD = "TRUNCATE_PAYLOAD"
    CORRUPT_CHECKSUM = "CORRUPT_CHECKSUM"
    INVALID_VERSION = "INVALID_VERSION"
    INVALID_LENGTH = "INVALID_LENGTH"
    EXTREME_BOUNDARIES = "EXTREME_BOUNDARIES"
    CONTRADICTORY_FLAGS = "CONTRADICTORY_FLAGS"
    MALFORMED_OPTIONS = "MALFORMED_OPTIONS"
    POINTER_LOOP = "POINTER_LOOP"
    POINTER_OUT_OF_BOUNDS = "POINTER_OUT_OF_BOUNDS"
    INJECT_PADDING = "INJECT_PADDING"
    PORT_SHIFT = "PORT_SHIFT"
    EXTENSION_CHAIN_LOOP = "EXTENSION_CHAIN_LOOP"
    BIT_FLIP = "BIT_FLIP"


class CampaignStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class CaseStatus(StrEnum):
    PENDING = "PENDING"
    EXECUTED = "EXECUTED"
    PASSED = "PASSED"
    FAILED = "FAILED"
    ERROR = "ERROR"


class ExpectedBehavior(StrEnum):
    ACCEPT_VALID = "ACCEPT_VALID"
    SAFE_REJECT = "SAFE_REJECT"
    EQUIVALENT_PARSING = "EQUIVALENT_PARSING"


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class Confidence(StrEnum):
    CONFIRMED = "CONFIRMED"
    SUSPECTED = "SUSPECTED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class FailureCategory(StrEnum):
    CRASH = "CRASH"
    HANG_TIMEOUT = "HANG_TIMEOUT"
    SANITIZER_VIOLATION = "SANITIZER_VIOLATION"
    SCHEMA_VIOLATION = "SCHEMA_VIOLATION"
    INCONSISTENT_PARSING = "INCONSISTENT_PARSING"
    UNEXPECTED_REJECTION = "UNEXPECTED_REJECTION"
    UNEXPECTED_ACCEPTANCE = "UNEXPECTED_ACCEPTANCE"
    DIFFERENTIAL_MISMATCH = "DIFFERENTIAL_MISMATCH"


class FindingStatus(StrEnum):
    OPEN = "OPEN"
    TRIAGED = "TRIAGED"
    MINIMIZED = "MINIMIZED"
    REGRESSION_PROMOTED = "REGRESSION_PROMOTED"
    CLOSED = "CLOSED"


class TestCase(BaseModel):
    __test__ = False

    case_id: str
    campaign_id: str
    test_index: int
    protocol_target: ProtocolTarget
    generation_strategy: GenerationStrategy
    mutation_sequence: list[MutationOperator] = Field(default_factory=list)
    seed: int
    generator_version: str = "1.0.0"
    fixture_format: str = "pcap"
    fixture_path: str
    fixture_hash: str
    expected_behavior: ExpectedBehavior
    status: CaseStatus = CaseStatus.PENDING
    created_at: str


class ExecutionResult(BaseModel):
    result_id: str
    case_id: str
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    execution_time_ms: float = 0.0
    parser_status: str = "ok"
    parsed_event_count: int = 0
    schema_valid: bool = True
    schema_errors: list[str] = Field(default_factory=list)
    anomalies_detected: list[str] = Field(default_factory=list)
    sanitizer_triggered: bool = False
    crash_detected: bool = False
    passed: bool = True
    diagnostic: str | None = None
    executed_at: str


class TestCampaign(BaseModel):
    __test__ = False

    campaign_id: str
    name: str
    description: str = ""
    protocol_targets: list[ProtocolTarget]
    strategies: list[GenerationStrategy]
    seed: int
    max_cases_per_target: int = 10
    total_cases: int = 0
    status: CampaignStatus = CampaignStatus.PENDING
    created_at: str
    completed_at: str | None = None
    cases_generated: int = 0
    cases_executed: int = 0
    passed_count: int = 0
    rejected_count: int = 0
    failed_count: int = 0
    findings_count: int = 0
    duration_ms: float = 0.0
    engine_version: str = "1.0.0"


class CampaignCreateRequest(BaseModel):
    name: str
    description: str = ""
    protocol_targets: list[ProtocolTarget] = Field(
        default_factory=lambda: [
            ProtocolTarget.ETHERNET,
            ProtocolTarget.VLAN,
            ProtocolTarget.IPV4,
            ProtocolTarget.IPV6,
            ProtocolTarget.TCP,
            ProtocolTarget.UDP,
            ProtocolTarget.DNS,
            ProtocolTarget.HTTP,
            ProtocolTarget.TLS_CLIENT_HELLO,
            ProtocolTarget.QUIC_CLASSIFIER,
        ]
    )
    strategies: list[GenerationStrategy] = Field(
        default_factory=lambda: [
            GenerationStrategy.BASELINE_CONFORMANCE,
            GenerationStrategy.MUTATION_FUZZING,
            GenerationStrategy.BOUNDARY_EDGE_CASES,
            GenerationStrategy.MALFORMED_INPUTS,
        ]
    )
    seed: int | None = None
    max_cases_per_target: int = Field(default=5, ge=1, le=100)
    run_immediately: bool = True


class Finding(BaseModel):
    finding_id: str
    campaign_id: str
    case_id: str
    protocol_target: ProtocolTarget
    parser_component: ParserComponent
    severity: Severity
    confidence: Confidence
    failure_category: FailureCategory
    input_hash: str
    engine_version: str
    reproduction_command: str
    seed: int
    mutation_sequence: list[str] = Field(default_factory=list)
    expected_behavior: str
    actual_behavior: str
    diagnostic: str
    status: FindingStatus = FindingStatus.OPEN
    regression_fixture_id: str | None = None
    created_at: str


class MinimizationStep(BaseModel):
    step_number: int
    action: str
    candidate_size_bytes: int
    still_reproduces: bool


class ReproductionArtifact(BaseModel):
    artifact_id: str
    finding_id: str
    fixture_path: str
    fixture_hash: str
    reproduction_command: str
    original_size_bytes: int
    minimized_size_bytes: int
    minimization_steps: list[MinimizationStep] = Field(default_factory=list)
    verified_reproducible: bool = True
    created_at: str


class RegressionFixture(BaseModel):
    fixture_id: str
    finding_id: str
    name: str
    protocol_target: ProtocolTarget
    failure_category: FailureCategory
    fixture_path: str
    fixture_hash: str
    engine_baseline_version: str
    expected_behavior: ExpectedBehavior
    created_at: str
    last_run_at: str | None = None
    last_run_passed: bool | None = None
    last_run_exit_code: int | None = None
    last_run_diagnostic: str | None = None


class RegressionRunResult(BaseModel):
    fixture_id: str
    passed: bool
    exit_code: int
    diagnostic: str | None = None
    duration_ms: float
    executed_at: str
