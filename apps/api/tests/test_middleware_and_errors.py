"""Tests for middleware, request correlation, and centralized error handling."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_request_correlation_id_generated(client: AsyncClient):
    response = await client.get("/api/v1/health")
    assert response.status_code == 200
    assert "x-request-id" in response.headers
    assert len(response.headers["x-request-id"]) > 0


@pytest.mark.asyncio
async def test_request_correlation_id_preserved(client: AsyncClient):
    custom_id = "test-corr-id-98765"
    response = await client.get("/api/v1/health", headers={"X-Request-ID": custom_id})
    assert response.status_code == 200
    assert response.headers["x-request-id"] == custom_id


@pytest.mark.asyncio
async def test_not_found_handling(client: AsyncClient):
    response = await client.get("/api/v1/non_existent_route")
    assert response.status_code == 404
    data = response.json()
    assert "error" in data
    assert "request_id" in data


@pytest.mark.asyncio
async def test_validation_error_structure(client: AsyncClient):
    # Send malformed payload to /api/v1/events/validate
    response = await client.post("/api/v1/events/validate", json={"bad_field": 123})
    assert response.status_code == 422
    data = response.json()
    assert data["error"] == "ValidationError"
    assert "details" in data
    assert isinstance(data["details"], list)
    assert len(data["details"]) > 0
    assert "request_id" in data
