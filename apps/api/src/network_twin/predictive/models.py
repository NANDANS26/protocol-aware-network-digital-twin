"""
Strongly Typed Contracts for Phase 06: Predictive Network World Model & Validated Behavior Forecasting.
"""

from __future__ import annotations

import enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class PredictionTarget(enum.StrEnum):
    """Supported predictive modeling targets grounded in verifiable network telemetry."""

    FLOW_VOLUME_NEXT_WINDOW = "FLOW_VOLUME_NEXT_WINDOW"
    """Forecast arrival rate / count of new flows in the subsequent observation window."""

    RELATIONSHIP_PERSISTENCE = "RELATIONSHIP_PERSISTENCE"
    """Binary prediction of whether an observed endpoint communication pair will persist."""

    INVARIANT_RISK_SCORE = "INVARIANT_RISK_SCORE"
    """Predictive probability that a scenario mutation risks violating security invariants."""

    PROTOCOL_ACTIVITY_DRIFT = "PROTOCOL_ACTIVITY_DRIFT"
    """Forecast proportional drift in dominant application layer protocols (HTTP, DNS, TLS)."""


class ModelAlgorithm(enum.StrEnum):
    """Algorithms and baseline estimators supported in Phase 06."""

    PERSISTENCE_BASELINE = "PERSISTENCE_BASELINE"
    """Naive persistence baseline: y_{t+1} = y_t."""

    MOVING_AVERAGE_BASELINE = "MOVING_AVERAGE_BASELINE"
    """Exponential / rolling window mean baseline."""

    RIDGE_REGRESSION = "RIDGE_REGRESSION"
    """L2-regularized linear model for continuous flow forecasting."""

    LOGISTIC_REGRESSION = "LOGISTIC_REGRESSION"
    """Calibrated linear classifier for relationship persistence."""

    RANDOM_FOREST = "RANDOM_FOREST"
    """Non-linear ensemble trees for tabular network behavior prediction."""

    GRADIENT_BOOSTING = "GRADIENT_BOOSTING"
    """Iterative boosted decision trees for subtle feature interactions."""


class FeatureSchema(BaseModel):
    """Specification of features extracted for a dataset."""

    model_config = ConfigDict(extra="forbid")

    feature_names: list[str] = Field(..., description="Ordered list of feature column identifiers")
    feature_types: dict[str, str] = Field(..., description="Mapping of feature name to numeric type")
    target_column: str = Field(..., description="Target variable name strictly shifted to t+1 window")
    excluded_features: list[str] = Field(
        default_factory=lambda: ["raw_payload", "payload_hex", "authorization_headers"],
        description="Features explicitly excluded to maintain zero-trust privacy",
    )


class DatasetManifest(BaseModel):
    """Immutable manifest of an extracted versioned network behavior dataset."""

    model_config = ConfigDict(extra="forbid")

    dataset_id: str = Field(..., description="Unique dataset identifier")
    name: str = Field(..., description="Human-readable dataset name")
    description: str = Field(default="", description="Dataset summary and provenance notes")
    pipeline_version: str = Field(default="1.0.0", description="Feature extractor pipeline version")
    source_captures: list[str] = Field(default_factory=list, description="IDs of source capture files")
    source_artifacts: list[str] = Field(default_factory=list, description="Source artifact hashes")
    time_window_sec: float = Field(default=10.0, description="Time bucket interval in seconds")
    total_samples: int = Field(..., description="Total observation window samples")
    feature_count: int = Field(..., description="Number of numeric feature predictors")
    target_type: PredictionTarget = Field(..., description="Target category for this dataset")
    feature_schema: FeatureSchema = Field(..., description="Feature names, types, and target definition")
    data_quality_notes: list[str] = Field(
        default_factory=list, description="Data hygiene, missingness, and sampling notes"
    )
    dataset_samples: list[dict[str, Any]] = Field(
        default_factory=list, description="Extracted time-window tabular records"
    )
    hash_sha256: str = Field(..., description="Cryptographic fingerprint of feature records")
    created_at_iso: str = Field(..., description="ISO 8601 creation timestamp")


class EvaluationReport(BaseModel):
    """Comprehensive offline evaluation report with baseline comparisons and calibration."""

    model_config = ConfigDict(extra="forbid")

    algorithm: ModelAlgorithm = Field(..., description="Model algorithm evaluated")
    target: PredictionTarget = Field(..., description="Prediction target")
    split_type: str = Field(default="TIME_BASED_SPLIT", description="Temporal train/test partitioning")
    train_sample_count: int = Field(..., description="Training set window count")
    test_sample_count: int = Field(..., description="Out-of-time evaluation window count")
    metrics: dict[str, float] = Field(
        ..., description="Evaluation metrics (MAE, RMSE, R2 for regression; Precision, Recall, F1 for classification)"
    )
    baseline_metrics: dict[str, float] = Field(
        default_factory=dict, description="Metrics achieved by naive persistence baseline"
    )
    improvement_over_baseline: dict[str, float] = Field(
        default_factory=dict, description="Relative metric improvement compared to baseline"
    )
    calibration_assessment: str = Field(
        default="WELL_CALIBRATED", description="Empirical calibration or probability reliability"
    )
    feature_importances: dict[str, float] = Field(
        default_factory=dict, description="Top predictive feature importance coefficients"
    )
    out_of_distribution_threshold: float = Field(
        default=3.0, description="Mahalanobis / Euclidean distance threshold for OOD flagging"
    )


class ModelArtifact(BaseModel):
    """Metadata representing a persisted, versioned predictive model."""

    model_config = ConfigDict(extra="forbid")

    model_id: str = Field(..., description="Unique model identifier")
    name: str = Field(..., description="Model title")
    version: str = Field(default="1.0.0", description="Semantic model version")
    target: PredictionTarget = Field(..., description="Prediction target")
    algorithm: ModelAlgorithm = Field(..., description="Algorithm used")
    dataset_id: str = Field(..., description="Associated training dataset manifest ID")
    feature_names: list[str] = Field(..., description="Expected ordered feature inputs")
    artifact_path: str = Field(..., description="Filesystem location of serialized weights")
    artifact_hash_sha256: str = Field(..., description="SHA-256 integrity hash of model binary")
    evaluation: EvaluationReport = Field(..., description="Model evaluation and baseline comparison")
    limitations: list[str] = Field(
        default_factory=list, description="Documented operational boundaries and unsupported domains"
    )
    created_at_iso: str = Field(..., description="ISO 8601 timestamp")


class ModelTrainingRun(BaseModel):
    """Record of a model training session."""

    model_config = ConfigDict(extra="forbid")

    run_id: str = Field(..., description="Unique run identifier")
    model_id: str = Field(..., description="Produced model ID")
    dataset_id: str = Field(..., description="Source dataset ID")
    target: PredictionTarget = Field(..., description="Target modeled")
    algorithm: ModelAlgorithm = Field(..., description="Algorithm executed")
    status: str = Field(default="COMPLETED", description="Training status")
    duration_ms: float = Field(..., description="Wall-clock training duration in ms")
    evaluation: EvaluationReport = Field(..., description="Evaluation report")
    created_at_iso: str = Field(..., description="ISO 8601 execution timestamp")


class UncertaintyAssessment(BaseModel):
    """Conformal prediction intervals and out-of-distribution assessment."""

    model_config = ConfigDict(extra="forbid")

    uncertainty_method: str = Field(
        ..., description="Method used: EMPIRICAL_CONFORMAL_INTERVAL, ENSEMBLE_VARIANCE, or CALIBRATED_PROBABILITY"
    )
    lower_bound: float | None = Field(default=None, description="Lower prediction interval bound for regression")
    upper_bound: float | None = Field(default=None, description="Upper prediction interval bound for regression")
    confidence_level: float = Field(default=0.90, description="Nominal confidence coverage (e.g. 0.90 = 90% coverage)")
    is_out_of_distribution: bool = Field(
        default=False, description="Whether input features exceeded the training distribution envelope"
    )
    ood_distance_score: float = Field(default=0.0, description="Normalized distance from training feature centroid")
    reliability_tier: str = Field(
        default="HIGH", description="Reliability grade: HIGH, MODERATE, LOW, or UNRELIABLE_OOD"
    )
    rationale: str = Field(default="", description="Explanation of uncertainty and reliability")


class PredictionRequest(BaseModel):
    """Inference request payload."""

    model_config = ConfigDict(extra="forbid")

    model_id: str = Field(..., description="Target model ID to invoke")
    features: dict[str, Any] = Field(
        default_factory=dict, description="Feature values for inference (or empty if from current state)"
    )
    prediction_horizon_sec: float | None = Field(
        default=10.0, description="Forecast horizon in seconds beyond observation window"
    )


class PredictionResult(BaseModel):
    """Validated prediction outcome with uncertainty and input provenance."""

    model_config = ConfigDict(extra="forbid")

    prediction_id: str = Field(..., description="Unique prediction record identifier")
    model_id: str = Field(..., description="Model ID executed")
    target: PredictionTarget = Field(..., description="Target predicted")
    predicted_value: float = Field(..., description="Point prediction or probability")
    uncertainty: UncertaintyAssessment = Field(..., description="Interval, confidence, and OOD assessment")
    feature_provenance: dict[str, Any] = Field(
        default_factory=dict, description="Input features and provenance hashes used"
    )
    deterministic_comparison: dict[str, Any] | None = Field(
        default=None, description="Comparative deterministic evaluation if applicable"
    )
    disagreement_explanation: str | None = Field(
        default=None, description="Structured explanation if statistical and deterministic views diverge"
    )
    predicted_at_iso: str = Field(..., description="ISO 8601 prediction timestamp")


class ScenarioPredictionComparison(BaseModel):
    """Comparison between deterministic scenario verification and learned behavioral prediction."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: str = Field(..., description="Counterfactual scenario evaluated")
    base_model_id: str = Field(..., description="Base digital twin model ID")
    deterministic_reachable: bool = Field(..., description="Whether destination is reachable via LPM & ACL")
    deterministic_invariants_passed: bool = Field(..., description="Whether formal invariants hold")
    deterministic_violations: list[str] = Field(
        default_factory=list, description="Formal invariant violation descriptions"
    )
    predicted_flow_volume_ratio: float = Field(
        ..., description="Forecast flow volume ratio under hypothetical topology state"
    )
    predicted_relationship_persistence: float = Field(
        ..., description="Predicted probability that affected communication paths persist"
    )
    predicted_invariant_risk: float = Field(
        ..., description="Statistical risk score of invariant degradation (0.0 to 1.0)"
    )
    consensus_status: str = Field(
        ..., description="Consensus category: ALIGNED, COMPLEMENTARY, or DIVERGENT_INVESTIGATION_REQUIRED"
    )
    detailed_explanation: str = Field(
        ..., description="Technical explanation harmonizing deterministic ground truth with statistical estimates"
    )


class PredictiveLimitationsResponse(BaseModel):
    """Documented boundaries and unsupported targets to maintain engineering integrity."""

    model_config = ConfigDict(extra="forbid")

    supported_targets: list[str] = Field(..., description="Targets with reproducible validation")
    unsupported_targets: list[str] = Field(
        ..., description="Targets intentionally excluded due to lack of ground truth"
    )
    methodological_rules: list[str] = Field(
        ..., description="Inviolable principles (e.g. predictions never override deterministic proofs)"
    )
    data_quality_limitations: list[str] = Field(
        ..., description="Dataset sampling, resolution, and windowing constraints"
    )
