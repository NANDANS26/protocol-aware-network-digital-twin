"""
API Route integration tests for Phase 06 Predictive World Model endpoints.
"""

import pytest
from httpx import AsyncClient

from network_twin.predictive.models import ModelAlgorithm, PredictionTarget


@pytest.mark.anyio
async def test_get_limitations(client: AsyncClient):
    """Verifies retrieval of documented boundaries and methodological rules."""
    response = await client.get("/api/v1/predictive/limitations")
    assert response.status_code == 200
    data = response.json()

    assert "supported_targets" in data
    assert len(data["supported_targets"]) >= 4
    assert "unsupported_targets" in data
    assert "methodological_rules" in data

    # Verify inviolable rule
    rules_text = " ".join(data["methodological_rules"])
    assert "Ground Truth Supremacy" in rules_text or "supersede" in rules_text


@pytest.mark.anyio
async def test_predictive_lifecycle_routes(client: AsyncClient):
    """
    Verifies end-to-end API lifecycle:
    Extract dataset -> Train model -> List models -> Make prediction.
    """
    # 1. Extract canonical synthetic dataset
    extract_resp = await client.post(
        "/api/v1/predictive/datasets/extract",
        json={
            "name": "api_test_dataset",
            "description": "Dataset extracted via API test",
            "time_window_sec": 10.0,
            "target_type": PredictionTarget.FLOW_VOLUME_NEXT_WINDOW,
            "use_synthetic_canonical": True,
            "synthetic_sample_count": 50,
        },
    )
    assert extract_resp.status_code == 200
    dataset_data = extract_resp.json()
    dataset_id = dataset_data["dataset_id"]
    assert dataset_id is not None
    assert dataset_data["total_samples"] == 50

    # 2. Get dataset by ID
    get_ds_resp = await client.get(f"/api/v1/predictive/datasets/{dataset_id}")
    assert get_ds_resp.status_code == 200
    assert get_ds_resp.json()["dataset_id"] == dataset_id

    # 3. Train predictive model
    train_resp = await client.post(
        "/api/v1/predictive/train",
        json={
            "dataset_id": dataset_id,
            "target": PredictionTarget.FLOW_VOLUME_NEXT_WINDOW,
            "algorithm": ModelAlgorithm.RIDGE_REGRESSION,
            "model_name": "API Test Ridge Model",
        },
    )
    assert train_resp.status_code == 200
    train_data = train_resp.json()
    model_id = train_data["model_id"]
    assert model_id is not None
    assert train_data["status"] == "COMPLETED"

    # 4. List models and retrieve model details
    list_models_resp = await client.get("/api/v1/predictive/models")
    assert list_models_resp.status_code == 200
    models_list = list_models_resp.json()
    assert any(m["model_id"] == model_id for m in models_list)

    get_model_resp = await client.get(f"/api/v1/predictive/models/{model_id}")
    assert get_model_resp.status_code == 200
    assert get_model_resp.json()["model_id"] == model_id

    # 5. Execute inference request
    predict_resp = await client.post(
        "/api/v1/predictive/predict",
        json={
            "model_id": model_id,
            "features": {
                "flow_arrival_count": 20.0,
                "active_flow_count": 28.0,
                "total_packet_count": 220.0,
                "total_bytes": 75000.0,
                "tcp_retransmissions": 0.0,
                "tcp_out_of_order": 0.0,
                "tcp_rst_count": 0.0,
                "dns_queries_count": 8.0,
                "dns_avg_rtt_ms": 11.5,
                "tcp_ratio": 0.8,
                "udp_ratio": 0.2,
                "dns_ratio": 0.15,
                "http_ratio": 0.55,
                "tls_ratio": 0.25,
                "active_relationships_count": 12.0,
                "external_ip_flow_ratio": 0.1,
            },
            "prediction_horizon_sec": 10.0,
        },
    )
    assert predict_resp.status_code == 200
    pred_data = predict_resp.json()
    assert pred_data["model_id"] == model_id
    assert pred_data["predicted_value"] > 0
    assert "uncertainty" in pred_data
    assert pred_data["uncertainty"]["lower_bound"] is not None

    # 6. List past prediction records
    past_preds_resp = await client.get(f"/api/v1/predictive/predictions?model_id={model_id}")
    assert past_preds_resp.status_code == 200
    assert len(past_preds_resp.json()) >= 1
