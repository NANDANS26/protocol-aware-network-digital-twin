"""Integration tests for security testing, fuzzing, and differential API endpoints."""

from fastapi.testclient import TestClient

from network_twin.main import app

client = TestClient(app)


def test_create_and_execute_campaign_api():
    payload = {
        "name": "Integration Test Campaign",
        "description": "API verification of campaign execution",
        "protocol_targets": ["ETHERNET", "IPV4", "TCP", "DNS"],
        "strategies": ["BASELINE_CONFORMANCE"],
        "seed": 1337,
        "max_cases_per_target": 2,
        "run_immediately": True,
    }

    res = client.post("/api/v1/testing/campaigns", json=payload)
    assert res.status_code == 201
    data = res.json()
    assert data["name"] == "Integration Test Campaign"
    assert data["status"] == "COMPLETED"
    assert data["cases_generated"] == 8  # 4 targets * 1 strategy * 2 cases
    assert data["cases_executed"] == 8
    assert data["passed_count"] == 8
    campaign_id = data["campaign_id"]

    # Retrieve campaign
    get_res = client.get(f"/api/v1/testing/campaigns/{campaign_id}")
    assert get_res.status_code == 200
    assert get_res.json()["campaign_id"] == campaign_id

    # List campaigns
    list_res = client.get("/api/v1/testing/campaigns")
    assert list_res.status_code == 200
    assert len(list_res.json()) >= 1

    # List test cases
    cases_res = client.get(f"/api/v1/testing/campaigns/{campaign_id}/cases")
    assert cases_res.status_code == 200
    cases = cases_res.json()
    assert len(cases) == 8
    first_case_id = cases[0]["case_id"]

    # Get single test case
    case_detail = client.get(f"/api/v1/testing/cases/{first_case_id}")
    assert case_detail.status_code == 200
    assert "test_case" in case_detail.json()
    assert "execution_result" in case_detail.json()

    # Rerun test case
    rerun_res = client.post(f"/api/v1/testing/cases/{first_case_id}/rerun")
    assert rerun_res.status_code == 200
    assert rerun_res.json()["case_id"] == first_case_id
    assert rerun_res.json()["passed"] is True


def test_malformed_campaign_and_finding_lifecycle():
    payload = {
        "name": "Malformed Truncation Campaign",
        "description": "Verifying safe rejection on malformed headers",
        "protocol_targets": ["ETHERNET", "IPV4", "UDP"],
        "strategies": ["MALFORMED_INPUTS"],
        "seed": 42,
        "max_cases_per_target": 2,
        "run_immediately": True,
    }

    res = client.post("/api/v1/testing/campaigns", json=payload)
    assert res.status_code == 201
    data = res.json()
    assert data["status"] == "COMPLETED"
    assert data["rejected_count"] >= 1  # Malformed inputs safely rejected without crash


def test_quick_differential_check_api():
    res = client.post("/api/v1/testing/differential/quick-check")
    assert res.status_code == 200
    data = res.json()
    assert data["equivalent"] is True
    assert data["test_name"] == "PCAP_vs_PCAPNG_Equivalence"
