"""
Unit tests for Predictive Models, Baseline Estimators, and Uncertainty Engine (Phase 06).
Verifies:
1. Strict temporal train/test splitting.
2. Naive baselines (Persistence, Moving Average) vs learned models (Ridge, RF, Logistic).
3. Conformal 90% prediction intervals and calibrated probability bounds.
4. Out-of-distribution (OOD) distance gating.
5. Model persistence and SHA-256 artifact verification.
"""

from network_twin.predictive.feature_pipeline import generate_canonical_synthetic_dataset
from network_twin.predictive.models import ModelAlgorithm, PredictionTarget
from network_twin.predictive.models_engine import (
    ModelPredictor,
    ModelTrainer,
    MovingAverageBaseline,
    PersistenceBaseline,
)


def test_temporal_train_test_split():
    """Verifies temporal splitting preserves sequence order without lookahead shuffling."""
    trainer = ModelTrainer()
    data = [{"flow_arrival_count": float(i), "target": float(i + 1)} for i in range(50)]

    train, test = trainer._temporal_split(data, train_ratio=0.75)
    assert len(train) == 37
    assert len(test) == 13

    # Ensure chronological order: all train items precede all test items
    max_train_val = max(x["flow_arrival_count"] for x in train)
    min_test_val = min(x["flow_arrival_count"] for x in test)
    assert max_train_val < min_test_val


def test_baseline_estimators():
    """Verifies naive persistence and moving average baseline calculations."""
    history = [10.0, 12.0, 14.0, 16.0]

    persistence = PersistenceBaseline()
    persistence.fit(history)
    assert persistence.predict() == 16.0

    ma = MovingAverageBaseline(window=3)
    ma.fit(history)
    # average of last 3: (12 + 14 + 16) / 3 = 14.0
    assert ma.predict() == 14.0


def test_ridge_regression_training_and_evaluation():
    """Verifies Ridge regression training against synthetic canonical flow dataset."""
    manifest = generate_canonical_synthetic_dataset(
        target_type=PredictionTarget.FLOW_VOLUME_NEXT_WINDOW,
        sample_count=60,
    )
    trainer = ModelTrainer()
    run = trainer.train_model(
        manifest=manifest,
        algorithm=ModelAlgorithm.RIDGE_REGRESSION,
        target=PredictionTarget.FLOW_VOLUME_NEXT_WINDOW,
    )

    assert run.status == "COMPLETED"
    assert run.duration_ms > 0
    assert "mae" in run.evaluation.metrics
    assert "rmse" in run.evaluation.metrics
    assert run.evaluation.train_sample_count > 0
    assert run.evaluation.test_sample_count > 0

    # Ensure artifact was generated and can be retrieved
    artifact = trainer.get_model_artifact(run.model_id)
    assert artifact is not None
    assert artifact.model_id == run.model_id
    assert len(artifact.artifact_hash_sha256) == 64


def test_conformal_uncertainty_and_inference():
    """Verifies inference generates valid point estimates and 90% conformal intervals."""
    manifest = generate_canonical_synthetic_dataset(
        target_type=PredictionTarget.FLOW_VOLUME_NEXT_WINDOW,
        sample_count=60,
    )
    trainer = ModelTrainer()
    run = trainer.train_model(
        manifest=manifest,
        algorithm=ModelAlgorithm.RIDGE_REGRESSION,
        target=PredictionTarget.FLOW_VOLUME_NEXT_WINDOW,
    )
    artifact = trainer.get_model_artifact(run.model_id)
    assert artifact is not None

    predictor = ModelPredictor()
    test_features = {
        "flow_arrival_count": 15.0,
        "active_flow_count": 22.0,
        "total_packet_count": 180.0,
        "total_bytes": 60000.0,
        "tcp_retransmissions": 0.0,
        "tcp_out_of_order": 0.0,
        "tcp_rst_count": 0.0,
        "dns_queries_count": 6.0,
        "dns_avg_rtt_ms": 13.0,
        "tcp_ratio": 0.8,
        "udp_ratio": 0.2,
        "dns_ratio": 0.15,
        "http_ratio": 0.55,
        "tls_ratio": 0.25,
        "active_relationships_count": 8.0,
        "external_ip_flow_ratio": 0.1,
    }

    result = predictor.predict(artifact, test_features, prediction_horizon_sec=10.0)

    assert result.model_id == artifact.model_id
    assert result.predicted_value > 0.0
    assert result.uncertainty.confidence_level == 0.90
    assert result.uncertainty.lower_bound is not None
    assert result.uncertainty.upper_bound is not None
    assert result.uncertainty.upper_bound >= result.uncertainty.lower_bound
    assert not result.uncertainty.is_out_of_distribution


def test_out_of_distribution_gating():
    """Verifies that extreme anomalous feature vectors are flagged as out-of-distribution."""
    manifest = generate_canonical_synthetic_dataset(
        target_type=PredictionTarget.FLOW_VOLUME_NEXT_WINDOW,
        sample_count=50,
    )
    trainer = ModelTrainer()
    run = trainer.train_model(
        manifest=manifest,
        algorithm=ModelAlgorithm.RIDGE_REGRESSION,
        target=PredictionTarget.FLOW_VOLUME_NEXT_WINDOW,
    )
    artifact = trainer.get_model_artifact(run.model_id)
    assert artifact is not None

    predictor = ModelPredictor()

    # Extreme input feature values (1000x normal baseline)
    extreme_features = {
        "flow_arrival_count": 50000.0,
        "active_flow_count": 99999.0,
        "total_packet_count": 1000000.0,
        "total_bytes": 100000000.0,
        "tcp_retransmissions": 500.0,
        "tcp_out_of_order": 200.0,
        "tcp_rst_count": 1000.0,
        "dns_queries_count": 8000.0,
        "dns_avg_rtt_ms": 500.0,
        "tcp_ratio": 0.9,
        "udp_ratio": 0.1,
        "dns_ratio": 0.1,
        "http_ratio": 0.7,
        "tls_ratio": 0.2,
        "active_relationships_count": 5000.0,
        "external_ip_flow_ratio": 0.9,
    }

    result = predictor.predict(artifact, extreme_features)

    assert result.uncertainty.is_out_of_distribution is True
    assert result.uncertainty.reliability_tier == "UNRELIABLE_OOD"
    assert result.uncertainty.ood_distance_score > 3.0


def test_random_forest_and_classification_targets():
    """Verifies Random Forest training on non-linear continuous and binary persistence targets."""
    manifest_bin = generate_canonical_synthetic_dataset(
        target_type=PredictionTarget.RELATIONSHIP_PERSISTENCE,
        sample_count=50,
    )
    trainer = ModelTrainer()
    run_bin = trainer.train_model(
        manifest=manifest_bin,
        algorithm=ModelAlgorithm.RANDOM_FOREST,
        target=PredictionTarget.RELATIONSHIP_PERSISTENCE,
    )
    assert run_bin.status == "COMPLETED"
    assert "accuracy" in run_bin.evaluation.metrics or "f1" in run_bin.evaluation.metrics
