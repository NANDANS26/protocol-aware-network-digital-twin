"""Tests for Protocol Analysis API routes and engine service integration."""

from pathlib import Path

from fastapi.testclient import TestClient

from network_twin.main import create_app
from network_twin.services.analysis_service import analysis_service


def test_analysis_service_finds_binary():
    assert analysis_service.is_engine_available() is True
    binary = analysis_service.find_engine_binary()
    assert binary is not None
    assert binary.is_file()


def test_analysis_service_validates_magic_bytes():
    assert analysis_service.validate_capture_bytes(b"\xa1\xb2\xc3\xd4\x00\x02") is True
    assert analysis_service.validate_capture_bytes(b"\x0a\x0d\x0d\x0a\x00\x00") is True
    assert analysis_service.validate_capture_bytes(b"INVALID_HEADER_BYTES") is False
    assert analysis_service.validate_capture_bytes(b"") is False


def test_health_reflects_operational_engine():
    app = create_app()
    client = TestClient(app)

    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()

    subsystems = data.get("subsystems", {})
    assert "protocol_analysis_engine" in subsystems
    assert subsystems["protocol_analysis_engine"]["status"] == "ok"
    assert subsystems["protocol_analysis_engine"]["operational_state"] == "operational"

    assert "flow_tracker" in subsystems
    assert subsystems["flow_tracker"]["status"] == "ok"
    assert subsystems["flow_tracker"]["operational_state"] == "operational"


def test_run_demo_analysis_pcap():
    app = create_app()
    client = TestClient(app)

    response = client.post("/api/v1/analysis/demo?format=pcap")
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "completed"
    job_id = data["job_id"]
    assert job_id is not None

    summary = data["summary"]
    assert summary is not None
    assert summary["total_packets"] == 15
    assert summary["total_flows"] == 4
    assert summary["dns_queries"] >= 1
    assert summary["http_requests"] >= 1
    assert summary["tls_handshakes"] >= 1

    # Verify flows endpoint
    flow_resp = client.get(f"/api/v1/analysis/jobs/{job_id}/flows")
    assert flow_resp.status_code == 200
    flows_data = flow_resp.json()
    assert flows_data["total_flows"] == 4
    assert len(flows_data["flows"]) == 4

    # Verify events endpoint
    events_resp = client.get(f"/api/v1/analysis/jobs/{job_id}/events")
    assert events_resp.status_code == 200
    events_data = events_resp.json()
    assert events_data["total_events"] == 15
    assert len(events_data["events"]) == 15
    assert events_data["events"][0]["schema_version"] == "1.0.0"


def test_run_demo_analysis_pcapng():
    app = create_app()
    client = TestClient(app)

    response = client.post("/api/v1/analysis/demo?format=pcapng")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["summary"]["total_packets"] == 15


def test_upload_invalid_magic_rejected():
    app = create_app()
    client = TestClient(app)

    response = client.post(
        "/api/v1/analysis/upload",
        files={"file": ("corrupt.txt", b"NOT_A_VALID_CAPTURE_FILE_HEADER", "application/octet-stream")},
    )
    assert response.status_code == 400
    res_data = response.json()
    err_msg = res_data.get("message") or res_data.get("detail", "")
    assert "Magic bytes do not match" in err_msg


def test_upload_valid_pcap():
    app = create_app()
    client = TestClient(app)

    project_root = Path(__file__).resolve().parent.parent.parent.parent
    pcap_path = project_root / "tests" / "fixtures" / "sample_capture.pcap"

    with open(pcap_path, "rb") as f:
        content = f.read()

    response = client.post(
        "/api/v1/analysis/upload",
        files={"file": ("sample_upload.pcap", content, "application/vnd.tcpdump.pcap")},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "completed"
    assert data["summary"]["total_packets"] == 15
