"""
FastAPI REST API Routes for Phase 06: Predictive Network World Model & Validated Behavior Forecasting.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from network_twin.predictive.feature_pipeline import (
    FeaturePipeline,
    generate_canonical_synthetic_dataset,
)
from network_twin.predictive.models import (
    DatasetManifest,
    ModelAlgorithm,
    ModelArtifact,
    ModelTrainingRun,
    PredictionRequest,
    PredictionResult,
    PredictionTarget,
    PredictiveLimitationsResponse,
    ScenarioPredictionComparison,
)
from network_twin.predictive.models_engine import ModelPredictor, ModelTrainer
from network_twin.predictive.scenario_evaluator import PredictiveScenarioEvaluator
from network_twin.simulation.models import ReachabilityQuery, TransportProtocolConstraint
from network_twin.simulation.scenario_engine import ScenarioEngine
from network_twin.storage.metadata_store import metadata_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/predictive", tags=["Predictive World Model"])


class DatasetExtractRequest(BaseModel):
    name: str = Field(default="network_behavior_dataset", description="Dataset identifier name")
    description: str = Field(default="Time-windowed network behavioral dataset", description="Dataset summary")
    time_window_sec: float = Field(default=10.0, description="Observation time window in seconds")
    target_type: PredictionTarget = Field(
        default=PredictionTarget.FLOW_VOLUME_NEXT_WINDOW, description="Target variable to predict"
    )
    source_captures: list[str] = Field(default_factory=list, description="Specific capture IDs or empty for all")
    use_synthetic_canonical: bool = Field(
        default=False, description="Generate canonical benchmark dataset for offline reproducible testing"
    )
    synthetic_sample_count: int = Field(default=120, description="Sample count if generating canonical dataset")


class ModelTrainRequest(BaseModel):
    dataset_id: str = Field(..., description="Target dataset manifest ID")
    target: PredictionTarget = Field(default=PredictionTarget.FLOW_VOLUME_NEXT_WINDOW, description="Prediction target")
    algorithm: ModelAlgorithm = Field(default=ModelAlgorithm.RIDGE_REGRESSION, description="Estimation algorithm")
    model_name: str | None = Field(default=None, description="Optional custom model name")


class ScenarioEvaluateRequest(BaseModel):
    model_id: str | None = Field(default=None, description="Optional predictive model ID to use for inference")
    test_probe_packet: dict[str, Any] | None = Field(
        default=None, description="Optional probe packet header (source_ip, destination_ip, port, protocol)"
    )


# --- Datasets Endpoints ---


@router.get("/datasets", response_model=list[DatasetManifest])
def list_datasets() -> list[DatasetManifest]:
    """Lists all versioned behavior datasets stored in the metadata catalog."""
    return metadata_store.list_dataset_manifests()


@router.post("/datasets/extract", response_model=DatasetManifest)
def extract_dataset(req: DatasetExtractRequest) -> DatasetManifest:
    """Extracts a versioned behavioral dataset from captures or canonical benchmarks."""
    pipeline = FeaturePipeline()

    if req.use_synthetic_canonical:
        manifest = generate_canonical_synthetic_dataset(
            target_type=req.target_type,
            sample_count=req.synthetic_sample_count,
            time_window_sec=req.time_window_sec,
        )
        manifest.name = req.name
        manifest.description = req.description
    else:
        # Extract from actual storage
        manifest = pipeline.extract_dataset(
            source_capture_ids=req.source_captures,
            time_window_sec=req.time_window_sec,
            target_type=req.target_type,
        )
        # If no samples could be extracted from storage, auto-fallback to canonical benchmark
        if manifest.total_samples < 10:
            manifest = generate_canonical_synthetic_dataset(
                target_type=req.target_type,
                sample_count=req.synthetic_sample_count,
                time_window_sec=req.time_window_sec,
            )
            manifest.name = req.name
            manifest.description = f"{req.description} (canonical benchmark fallback: no captures in store)"

    metadata_store.save_dataset_manifest(manifest)
    return manifest


@router.get("/datasets/{dataset_id}", response_model=DatasetManifest)
def get_dataset(dataset_id: str) -> DatasetManifest:
    """Retrieves a specific dataset manifest by ID."""
    manifest = metadata_store.get_dataset_manifest(dataset_id)
    if not manifest:
        raise HTTPException(status_code=404, detail=f"Dataset '{dataset_id}' not found.")
    return manifest


# --- Model Training Endpoints ---


@router.post("/train", response_model=ModelTrainingRun)
def train_model(req: ModelTrainRequest) -> ModelTrainingRun:
    """Trains a predictive model on a versioned dataset and evaluates against baseline."""
    manifest = metadata_store.get_dataset_manifest(req.dataset_id)
    if not manifest:
        raise HTTPException(status_code=404, detail=f"Dataset '{req.dataset_id}' not found.")

    trainer = ModelTrainer()
    try:
        run = trainer.train_model(
            manifest=manifest,
            algorithm=req.algorithm,
            target=req.target,
            model_name=req.model_name,
        )
    except Exception as e:
        logger.error("Model training failed: %s", e)
        raise HTTPException(status_code=400, detail=f"Model training failed: {e}") from e

    # Persist the artifact in metadata catalog
    artifact = trainer.get_model_artifact(run.model_id)
    if artifact:
        metadata_store.save_model_artifact(artifact)

    return run


@router.get("/models", response_model=list[ModelArtifact])
def list_models() -> list[ModelArtifact]:
    """Lists all trained predictive model artifacts."""
    return metadata_store.list_model_artifacts()


@router.get("/models/{model_id}", response_model=ModelArtifact)
def get_model(model_id: str) -> ModelArtifact:
    """Retrieves metadata and evaluation report for a specific model artifact."""
    artifact = metadata_store.get_model_artifact(model_id)
    if not artifact:
        raise HTTPException(status_code=404, detail=f"Model '{model_id}' not found.")
    return artifact


# --- Inference Endpoints ---


@router.post("/predict", response_model=PredictionResult)
def predict(req: PredictionRequest) -> PredictionResult:
    """Executes validated inference with uncertainty assessment and OOD gating."""
    artifact = metadata_store.get_model_artifact(req.model_id)
    if not artifact:
        raise HTTPException(status_code=404, detail=f"Model '{req.model_id}' not found.")

    predictor = ModelPredictor()
    result = predictor.predict(artifact, req.features, req.prediction_horizon_sec or 10.0)

    # Persist prediction record
    metadata_store.save_prediction_record(result)
    return result


@router.get("/predictions", response_model=list[PredictionResult])
def list_predictions(model_id: str | None = None) -> list[PredictionResult]:
    """Lists past prediction records, optionally filtered by model_id."""
    return metadata_store.list_prediction_records(model_id=model_id)


# --- Scenario Prediction & Verification Comparison ---


@router.post("/scenarios/{scenario_id}/evaluate", response_model=ScenarioPredictionComparison)
def evaluate_scenario(
    scenario_id: str,
    req: ScenarioEvaluateRequest | None = None,
) -> ScenarioPredictionComparison:
    """
    Evaluates a counterfactual scenario using both deterministic verification and predictive models.
    Enforces the rule: deterministic verification always supersedes learned predictions.
    """
    scenario = metadata_store.get_scenario(scenario_id)
    if not scenario:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found.")

    base_model = metadata_store.get_network_model(scenario.base_model_id)
    if not base_model:
        raise HTTPException(
            status_code=404,
            detail=f"Base model '{scenario.base_model_id}' for scenario not found.",
        )

    # Mutate base model according to scenario actions
    scenario_engine = ScenarioEngine()
    invariants = metadata_store.list_invariants()
    cf_model, cf_result = scenario_engine.run_scenario(base_model, scenario, invariants=invariants)

    # Resolve predictive model if requested or find latest matching target
    predictive_model = None
    if req and req.model_id:
        predictive_model = metadata_store.get_model_artifact(req.model_id)
    else:
        models = metadata_store.list_model_artifacts()
        if models:
            predictive_model = models[0]

    # Resolve probe packet
    probe_pkt = None
    if req and req.test_probe_packet:
        proto_str = req.test_probe_packet.get("transport_protocol", "TCP").upper()
        proto = (
            TransportProtocolConstraint.TCP
            if proto_str == "TCP"
            else (TransportProtocolConstraint.UDP if proto_str == "UDP" else TransportProtocolConstraint.ANY)
        )
        probe_pkt = ReachabilityQuery(
            source_ip=req.test_probe_packet.get("source_ip", "10.0.1.10"),
            destination_ip=req.test_probe_packet.get("destination_ip", "10.0.2.10"),
            protocol=proto,
            destination_port=int(req.test_probe_packet.get("destination_port", 443)),
            source_port=int(req.test_probe_packet.get("source_port", 50000)),
        )

    evaluator = PredictiveScenarioEvaluator()
    comparison = evaluator.evaluate_scenario(
        scenario_id=scenario_id,
        base_model=base_model,
        mutated_model=cf_model,
        applied_actions=[a.model_dump() for a in scenario.actions],
        predictive_model=predictive_model,
        test_probe_packet=probe_pkt,
        invariants=invariants,
    )

    return comparison


# --- Methodological Rules & Limitations ---


@router.get("/limitations", response_model=PredictiveLimitationsResponse)
def get_limitations() -> PredictiveLimitationsResponse:
    """Returns documented boundaries, unsupported targets, and inviolable methodological rules."""
    return PredictiveLimitationsResponse(
        supported_targets=[
            "FLOW_VOLUME_NEXT_WINDOW: Arrival rate forecasting for next observation window",
            "RELATIONSHIP_PERSISTENCE: Binary probability of endpoint communication persistence",
            "INVARIANT_RISK_SCORE: Statistical likelihood that a scenario degrades invariants",
            "PROTOCOL_ACTIVITY_DRIFT: Proportional shifts across transport and app protocols",
        ],
        unsupported_targets=[
            "Arbitrary Payload Classification: Deep packet payload contents are excluded for zero-trust privacy",
            "Zero-Day Vulnerability Attribution: Purely statistical models cannot invent unobserved exploit mechanics",
            "Indeterminate State Overriding: Statistical models cannot override deterministic security verification",
        ],
        methodological_rules=[
            "Ground Truth Supremacy: Deterministic verification and packet evidence always supersede statistical predictions.",
            "Strict Temporal Non-Leakage: Predictors for window t derive solely from events <= t; targets derive strictly from window t+1.",
            "Mandatory Uncertainty Calibration: All continuous forecasts include 90% conformal intervals; classifiers include calibration metrics.",
            "Out-of-Distribution Gating: Inference inputs exceeding training distribution distance are flagged UNRELIABLE_OOD.",
        ],
        data_quality_limitations=[
            "Requires minimum of 20 time windows for valid temporal train/test splitting and baseline calculation.",
            "Predictions reflect observed statistical regularities and cannot account for unobserved out-of-band topology reconfigurations.",
        ],
    )
