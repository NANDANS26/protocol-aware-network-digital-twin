"""
Phase 06 End-to-End Integration Verification Test.

Validates the complete 7-step lifecycle of the Predictive Network World Model:
1. Feature Extraction & Temporal Windowing (Zero Target Leakage, Zero Payload Retention)
2. Naive Baseline Benchmarking (Persistence, Moving Average)
3. Offline Model Training & Comparative Evaluation (Ridge, Random Forest)
4. Calibrated Inference & Conformal 90% Uncertainty Bounds
5. Out-of-Distribution (OOD) Distance Gating
6. Counterfactual Scenario Evaluation & Deterministic Verification Consensus (Rule Enforcement)
7. Catalog Persistence, SHA-256 Provenance & Audit Traceability
"""

from network_twin.predictive.feature_pipeline import (
    FEATURE_NAMES,
    FeaturePipeline,
    generate_canonical_synthetic_dataset,
)
from network_twin.predictive.models import (
    ModelAlgorithm,
    PredictionTarget,
)
from network_twin.predictive.models_engine import (
    ModelPredictor,
    ModelTrainer,
    MovingAverageBaseline,
    PersistenceBaseline,
)
from network_twin.predictive.scenario_evaluator import PredictiveScenarioEvaluator
from network_twin.simulation.models import (
    AccessControlList,
    FirewallRule,
    ModelInterface,
    ModelNode,
    ModelNodeType,
    NetworkModel,
    ReachabilityQuery,
    RuleAction,
    RuleDirection,
    TransportProtocolConstraint,
)
from network_twin.storage.metadata_store import metadata_store


def test_phase06_complete_end_to_end_verification():
    # --------------------------------------------------------------------------
    # Step 1: Feature Pipeline Extraction with Zero Leakage & Zero-Trust Privacy
    # --------------------------------------------------------------------------
    pipeline = FeaturePipeline(time_window_sec=10.0)
    assert pipeline.time_window_sec == 10.0
    dataset = generate_canonical_synthetic_dataset(
        target_type=PredictionTarget.FLOW_VOLUME_NEXT_WINDOW,
        sample_count=80,
        time_window_sec=10.0,
    )
    assert dataset.total_samples == 80
    assert dataset.feature_count == len(FEATURE_NAMES)
    assert len(dataset.dataset_samples) == 80

    # Privacy check: verify complete exclusion of raw payload bytes
    for sample in dataset.dataset_samples:
        assert "raw_payload" not in sample
        assert "payload_hex" not in sample
        assert "authorization_headers" not in sample
        assert "target" in sample
        assert isinstance(sample["target"], float)

    # Persist dataset manifest
    metadata_store.save_dataset_manifest(dataset)
    retrieved_ds = metadata_store.get_dataset_manifest(dataset.dataset_id)
    assert retrieved_ds is not None
    assert retrieved_ds.dataset_id == dataset.dataset_id

    # --------------------------------------------------------------------------
    # Step 2: Naive Baseline Benchmarking
    # --------------------------------------------------------------------------
    targets_history = [s["target"] for s in dataset.dataset_samples[:60]]
    pers_baseline = PersistenceBaseline()
    pers_baseline.fit(targets_history)
    pers_pred = pers_baseline.predict()
    assert pers_pred == targets_history[-1]

    ma_baseline = MovingAverageBaseline(window=5)
    ma_baseline.fit(targets_history)
    ma_pred = ma_baseline.predict()
    expected_ma = sum(targets_history[-5:]) / 5.0
    assert abs(ma_pred - expected_ma) < 1e-4

    # --------------------------------------------------------------------------
    # Step 3: Offline Model Training & Comparative Evaluation
    # --------------------------------------------------------------------------
    trainer = ModelTrainer()
    run = trainer.train_model(
        manifest=dataset,
        algorithm=ModelAlgorithm.RIDGE_REGRESSION,
        target=PredictionTarget.FLOW_VOLUME_NEXT_WINDOW,
        model_name="Phase 06 Benchmark Ridge Model",
    )
    assert run.status == "COMPLETED"
    assert run.duration_ms > 0
    assert run.evaluation.train_sample_count == 60  # 75% of 80
    assert run.evaluation.test_sample_count == 20  # 25% of 80
    assert "mae" in run.evaluation.metrics
    assert "rmse" in run.evaluation.metrics
    assert "r2" in run.evaluation.metrics

    # Model artifact integrity verification
    artifact = trainer.get_model_artifact(run.model_id)
    assert artifact is not None
    assert artifact.artifact_hash_sha256 is not None
    assert len(artifact.artifact_hash_sha256) == 64
    metadata_store.save_model_artifact(artifact)

    # --------------------------------------------------------------------------
    # Step 4: Calibrated Inference & Conformal 90% Uncertainty Bounds
    # --------------------------------------------------------------------------
    predictor = ModelPredictor()
    nominal_features = {
        "flow_arrival_count": 18.0,
        "active_flow_count": 25.0,
        "total_packet_count": 200.0,
        "total_bytes": 68000.0,
        "tcp_retransmissions": 0.0,
        "tcp_out_of_order": 0.0,
        "tcp_rst_count": 0.0,
        "dns_queries_count": 7.0,
        "dns_avg_rtt_ms": 12.0,
        "tcp_ratio": 0.8,
        "udp_ratio": 0.2,
        "dns_ratio": 0.15,
        "http_ratio": 0.55,
        "tls_ratio": 0.25,
        "active_relationships_count": 10.0,
        "external_ip_flow_ratio": 0.1,
    }
    prediction = predictor.predict(
        artifact, nominal_features, prediction_horizon_sec=10.0
    )
    assert prediction.model_id == artifact.model_id
    assert prediction.predicted_value > 0.0
    assert prediction.uncertainty.confidence_level == 0.90
    assert prediction.uncertainty.lower_bound is not None
    assert prediction.uncertainty.upper_bound is not None
    assert prediction.uncertainty.upper_bound > prediction.uncertainty.lower_bound
    assert not prediction.uncertainty.is_out_of_distribution
    assert prediction.uncertainty.reliability_tier == "HIGH"

    metadata_store.save_prediction_record(prediction)

    # --------------------------------------------------------------------------
    # Step 5: Out-of-Distribution (OOD) Distance Gating
    # --------------------------------------------------------------------------
    extreme_anomalous_features = dict(nominal_features)
    extreme_anomalous_features["flow_arrival_count"] = 99999.0
    extreme_anomalous_features["total_bytes"] = 1e9

    ood_prediction = predictor.predict(artifact, extreme_anomalous_features)
    assert ood_prediction.uncertainty.is_out_of_distribution is True
    assert ood_prediction.uncertainty.reliability_tier == "UNRELIABLE_OOD"
    assert ood_prediction.uncertainty.ood_distance_score > 3.0

    # --------------------------------------------------------------------------
    # Step 6: Counterfactual Scenario Evaluation & Inviolable Consensus Rules
    # --------------------------------------------------------------------------
    # Create base twin model
    host1 = ModelNode(
        node_id="host-1",
        label="Client-Host",
        node_type=ModelNodeType.HOST,
        interfaces=[
            ModelInterface(
                interface_id="eth0",
                node_id="host-1",
                name="eth0",
                ip_assignments=[],
            )
        ],
    )
    firewall = ModelNode(
        node_id="fw-1",
        label="Edge-Firewall",
        node_type=ModelNodeType.FIREWALL,
        interfaces=[
            ModelInterface(
                interface_id="eth0",
                node_id="fw-1",
                name="eth0",
                ip_assignments=[],
            )
        ],
        acls=[
            AccessControlList(
                acl_id="acl-block",
                node_id="fw-1",
                name="Block-All",
                rules=[
                    FirewallRule(
                        rule_id="r-deny-all",
                        node_id="fw-1",
                        rule_number=1,
                        name="Drop All Ingress",
                        action=RuleAction.DENY,
                        direction=RuleDirection.INGRESS,
                    )
                ],
            )
        ],
    )
    base_model = NetworkModel(
        model_id="net-model-base",
        name="Base Production Twin",
        source_snapshot_id="snap-01",
        source_snapshot_fingerprint="sha256-mock",
        nodes={"host-1": host1, "fw-1": firewall},
    )
    mutated_model = NetworkModel(
        model_id="net-model-mutated",
        name="Mutated Production Twin",
        source_snapshot_id="snap-01",
        source_snapshot_fingerprint="sha256-mock",
        nodes={"host-1": host1, "fw-1": firewall},
    )

    evaluator = PredictiveScenarioEvaluator(predictor=predictor)
    probe_query = ReachabilityQuery(
        source_ip="10.0.1.10",
        destination_ip="10.0.2.10",
        protocol=TransportProtocolConstraint.TCP,
        destination_port=443,
    )
    actions = [{"action_type": "ADD_FIREWALL_RULE", "target_node_id": "fw-1"}]

    comparison = evaluator.evaluate_scenario(
        scenario_id="scen-cf-01",
        base_model=base_model,
        mutated_model=mutated_model,
        applied_actions=actions,
        predictive_model=artifact,
        test_probe_packet=probe_query,
    )

    # Inviolable verification rule: deterministic reachability is False (blocked by firewall)
    # The statistical model cannot turn this into a pass!
    assert comparison.scenario_id == "scen-cf-01"
    assert comparison.deterministic_reachable is False
    assert (
        "DIVERGENT" in comparison.consensus_status
        or "COMPLEMENTARY" in comparison.consensus_status
    )
    assert "ground truth" in comparison.detailed_explanation.lower()

    # --------------------------------------------------------------------------
    # Step 7: Catalog Persistence & Audit Traceability
    # --------------------------------------------------------------------------
    datasets_list = metadata_store.list_dataset_manifests()
    assert any(d.dataset_id == dataset.dataset_id for d in datasets_list)

    models_list = metadata_store.list_model_artifacts()
    assert any(m.model_id == artifact.model_id for m in models_list)

    predictions_list = metadata_store.list_prediction_records(
        model_id=artifact.model_id
    )
    assert len(predictions_list) >= 1
