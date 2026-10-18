"""Data models for adversarial verification and hardening test suites."""

from enum import StrEnum

from pydantic import BaseModel, Field


class AdversarialCategory(StrEnum):
    ROUTING_FORWARDING = "ROUTING_FORWARDING"
    SECURITY_ISOLATION = "SECURITY_ISOLATION"
    CONFIG_CONSISTENCY = "CONFIG_CONSISTENCY"
    PARSER_RESILIENCE = "PARSER_RESILIENCE"
    PREDICTIVE_INTEGRITY = "PREDICTIVE_INTEGRITY"
    METAMORPHIC_INVARIANCE = "METAMORPHIC_INVARIANCE"


class AdversarialTestCase(BaseModel):
    test_id: str = Field(..., description="Unique deterministic identifier for the test case")
    name: str = Field(..., description="Human-readable title of the adversarial verification case")
    category: AdversarialCategory = Field(..., description="Target category under verification")
    description: str = Field(..., description="Detailed description of what edge case is tested")
    hand_verifiable_oracle: str = Field(
        ..., description="Independently established expected outcome and mathematical rationale"
    )
    expected_status: str = Field(
        ..., description="Expected status string (e.g., REACHABLE, BLOCKED, INDETERMINATE, PASS, FAIL)"
    )
    expected_reason_code: str = Field(..., description="Expected reason code string")


class AdversarialTestResult(BaseModel):
    test_id: str
    name: str
    category: AdversarialCategory
    hand_verifiable_oracle: str
    expected_status: str
    actual_status: str
    expected_reason_code: str
    actual_reason_code: str
    passed: bool = Field(..., description="True if actual engine outcome perfectly matches the hand-verified oracle")
    details: str = Field(default="")
    execution_time_ms: float = Field(default=0.0)


class AdversarialRunSummary(BaseModel):
    run_id: str
    timestamp_iso: str
    total_cases: int
    passed_cases: int
    failed_cases: int
    all_passed: bool
    category_breakdown: dict[str, dict[str, int]] = Field(default_factory=dict)
    results: list[AdversarialTestResult] = Field(default_factory=list)
