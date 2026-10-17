"""Pytest fixtures for backend tests."""

import pytest
from httpx import ASGITransport, AsyncClient

from network_twin.config import AppSettings
from network_twin.main import create_app


@pytest.fixture
def test_settings() -> AppSettings:
    return AppSettings(
        environment="testing",
        debug=True,
        require_database=False,
        require_engine=False,
    )


@pytest.fixture
def app(test_settings: AppSettings):
    return create_app(test_settings)


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac
