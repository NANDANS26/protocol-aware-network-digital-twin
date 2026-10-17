"""Integration smoke tests verifying end-to-end foundation health across C++ and Python."""

import subprocess
from pathlib import Path

import jsonschema
import pytest
from httpx import ASGITransport, AsyncClient
from network_twin.config import AppSettings
from network_twin.main import create_app

WORKSPACE_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.asyncio
async def test_full_system_smoke_and_contract_roundtrip():
    # 1. Initialize API in test configuration
    settings = AppSettings(environment="testing", debug=True)
    app = create_app(settings)
    transport = ASGITransport(app=app)

    async with AsyncClient(
        transport=transport, base_url="http://localhost:8000"
    ) as client:
        # 2. Check health endpoint
        health_resp = await client.get("/api/v1/health")
        assert health_resp.status_code == 200
        health_data = health_resp.json()
        assert health_data["status"] == "healthy"
        assert health_data["version"] == "0.1.0"
        assert health_data["schema_version"] == "1.0.0"

        # 3. Check readiness endpoint
        ready_resp = await client.get("/api/v1/ready")
        assert ready_resp.status_code == 200
        assert ready_resp.json()["status"] == "healthy"

        # 4. Check schema retrieval and validate with jsonschema validator
        schema_resp = await client.get("/api/v1/events/schema")
        assert schema_resp.status_code == 200
        schema_json = schema_resp.json()
        jsonschema.Draft202012Validator.check_schema(schema_json)

        # 5. Roundtrip event validation test
        sample_event = {
            "schema_version": "1.0.0",
            "event_id": "c7a8b9d0-1234-4567-89ab-cdef01234567",
            "timestamp_ns": 1729153800000000000,
            "timestamp_iso": "2026-10-17T08:30:00Z",
            "source_id": "integration-sensor-01",
            "link_layer": {
                "source_mac": "00:50:56:C0:00:01",
                "destination_mac": "00:50:56:C0:00:08",
                "ether_type": 2048,
            },
            "network_layer": {
                "version": "IPv4",
                "source_ip": "172.16.10.5",
                "destination_ip": "172.16.10.1",
                "ttl_or_hop_limit": 128,
            },
            "transport_layer": {
                "protocol": "UDP",
                "source_port": 5353,
                "destination_port": 5353,
            },
            "parser_status": {
                "status": "ok",
                "bytes_consumed": 42,
                "bytes_remaining": 0,
            },
            "provenance": {
                "packet_index": 100,
                "wire_length_bytes": 84,
                "capture_length_bytes": 84,
                "capture_interface": "eth0",
            },
        }

        val_resp = await client.post("/api/v1/events/validate", json=sample_event)
        assert val_resp.status_code == 200
        val_data = val_resp.json()
        assert val_data["valid"] is True
        assert val_data["event_id"] == sample_event["event_id"]


def test_cpp_engine_binary_smoke():
    # Verify the C++ engine executable was built and responds to --version
    engine_exe_win = (
        WORKSPACE_ROOT / "build" / "engine" / "Release" / "protocol_engine.exe"
    )
    engine_exe_unix = WORKSPACE_ROOT / "build" / "engine" / "protocol_engine"

    exe_path = engine_exe_win if engine_exe_win.exists() else engine_exe_unix
    assert exe_path.exists(), (
        f"C++ engine executable not found at {engine_exe_win} or {engine_exe_unix}"
    )

    result = subprocess.run(
        [str(exe_path), "--version"], capture_output=True, text=True, check=True
    )
    assert "Protocol-Aware Network Digital Twin Engine" in result.stdout
    assert "C++20" in result.stdout
