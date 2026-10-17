"""Unit and integration tests for adversarial verification and hardening suite."""

import pytest
from fastapi.testclient import TestClient

from network_twin.hardening.cases import ALL_ADVERSARIAL_CASES, get_all_adversarial_cases
from network_twin.hardening.models import AdversarialCategory
from network_twin.hardening.runner import AdversarialRunner
from network_twin.main import app


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def test_adversarial_cases_metadata():
    cases = get_all_adversarial_cases()
    assert len(cases) == len(ALL_ADVERSARIAL_CASES)
    assert len(cases) >= 10

    for c in cases:
        assert c.test_id.startswith("ADV-")
        assert len(c.name) > 0
        assert len(c.hand_verifiable_oracle) > 10
        assert c.category in AdversarialCategory


def test_adversarial_runner_execution(tmp_path):
    runner = AdversarialRunner(storage_dir=tmp_path)
    summary = runner.run_all()

    assert summary.total_cases >= 10
    assert summary.failed_cases == 0
    assert summary.all_passed is True
    assert summary.passed_cases == summary.total_cases

    # Verify category breakdown
    assert AdversarialCategory.ROUTING_FORWARDING.value in summary.category_breakdown
    assert AdversarialCategory.CONFIG_CONSISTENCY.value in summary.category_breakdown
    assert AdversarialCategory.SECURITY_ISOLATION.value in summary.category_breakdown
    assert AdversarialCategory.PREDICTIVE_INTEGRITY.value in summary.category_breakdown
    assert AdversarialCategory.METAMORPHIC_INVARIANCE.value in summary.category_breakdown

    # Check persistence
    latest = runner.get_latest_summary()
    assert latest is not None
    assert latest.run_id == summary.run_id
    assert latest.all_passed is True

    fetched = runner.get_run_by_id(summary.run_id)
    assert fetched is not None
    assert fetched.run_id == summary.run_id


def test_adversarial_api_endpoints(client: TestClient):
    # 1. List cases
    resp = client.get("/api/v1/twin/hardening/cases")
    assert resp.status_code == 200
    cases_data = resp.json()
    assert len(cases_data) >= 10
    test_ids = [c["test_id"] for c in cases_data]
    assert "ADV-ROUTE-01" in test_ids
    assert "ADV-SEC-01" in test_ids
    assert "ADV-SEC-02" in test_ids

    # 2. Execute suite
    run_resp = client.post("/api/v1/twin/hardening/run")
    assert run_resp.status_code == 200
    run_data = run_resp.json()
    assert run_data["all_passed"] is True
    assert run_data["total_cases"] >= 10
    assert run_data["failed_cases"] == 0
    run_id = run_data["run_id"]

    # 3. Get latest
    latest_resp = client.get("/api/v1/twin/hardening/latest")
    assert latest_resp.status_code == 200
    latest_data = latest_resp.json()
    assert latest_data["run_id"] == run_id

    # 4. Get by run ID
    id_resp = client.get(f"/api/v1/twin/hardening/runs/{run_id}")
    assert id_resp.status_code == 200
    assert id_resp.json()["run_id"] == run_id

    # 5. Non-existent run ID
    notFound_resp = client.get("/api/v1/twin/hardening/runs/adv-run-nonexistent")
    assert notFound_resp.status_code == 404
