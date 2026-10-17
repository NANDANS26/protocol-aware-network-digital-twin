"""Tests for health, readiness, and version endpoints."""

import pytest
from httpx import ASGITransport, AsyncClient

from network_twin.config import AppSettings
from network_twin.main import create_app


@pytest.mark.asyncio
async def test_health_endpoint(client: AsyncClient):
    response = await client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "healthy"
    assert data["schema_version"] == "1.0.0"
    assert "subsystems" in data
    assert "api_service" in data["subsystems"]
    assert data["subsystems"]["api_service"]["status"] == "ok"
    assert data["subsystems"]["api_service"]["operational_state"] == "operational"

    # Verify honest reporting of operational engine and planned future subsystems
    assert data["subsystems"]["protocol_analysis_engine"]["status"] in ("ok", "planned")
    assert data["subsystems"]["network_digital_twin"]["status"] in ("ok", "planned")
    assert data["subsystems"]["network_digital_twin"]["operational_state"] in ("operational", "planned")


@pytest.mark.asyncio
async def test_readiness_endpoint_default(client: AsyncClient):
    response = await client.get("/api/v1/ready")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"


@pytest.mark.asyncio
async def test_readiness_fails_when_mandatory_dependency_missing():
    # Configure an instance requiring a database
    strict_settings = AppSettings(
        environment="testing",
        debug=True,
        require_database=True,
    )
    strict_app = create_app(strict_settings)
    transport = ASGITransport(app=strict_app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        response = await ac.get("/api/v1/ready")
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "not_ready"
        assert data["subsystems"]["database"]["operational_state"] == "unavailable"


@pytest.mark.asyncio
async def test_version_endpoint(client: AsyncClient):
    response = await client.get("/api/v1/version")
    assert response.status_code == 200
    data = response.json()
    assert "app_name" in data
    assert "app_version" in data
    assert "schema_version" in data
