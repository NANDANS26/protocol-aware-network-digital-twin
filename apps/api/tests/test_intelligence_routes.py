"""Integration tests for Network Intelligence API endpoints."""

import json
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from network_twin.config import AppSettings
from network_twin.main import create_app
from network_twin.storage.metadata_store import MetadataStore


@pytest.fixture
def test_app_client(tmp_path: Path):
    cfg = AppSettings(
        environment="testing",
        data_dir=str(tmp_path),
    )
    # Ensure metadata store is initialized for the test instance
    store = MetadataStore(cfg)
    app = create_app(cfg)
    return app, store


@pytest.mark.asyncio
async def test_intelligence_api_flow(test_app_client):
    app, store = test_app_client
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Initially assets and snapshots are empty
        res = await client.get("/api/v1/assets")
        assert res.status_code == 200
        assert res.json() == []

        res = await client.get("/api/v1/topology")
        assert res.status_code == 200
        topo = res.json()
        assert topo["node_count"] == 0

        # 2. Test Configuration Import
        import_req = {
            "format": "routing_table",
            "source_name": "lab-gateway",
            "content": json.dumps([
                {"destination": "192.168.10.0/24", "next_hop": "192.168.1.1", "interface": "eth0", "metric": "10"}
            ]),
        }
        res = await client.post("/api/v1/imports", json=import_req)
        assert res.status_code == 200
        imp_data = res.json()
        assert imp_data["items_imported"] == 1
        assert imp_data["status"] == "completed"

        # Check evidence was stored
        res = await client.get("/api/v1/evidence")
        assert res.status_code == 200
        evs = res.json()
        assert len(evs) == 1

        # 3. Create a snapshot
        snap_req = {"name": "Initial Import Snapshot"}
        res = await client.post("/api/v1/snapshots", json=snap_req)
        assert res.status_code == 200
        snap = res.json()
        snap_id = snap["snapshot_id"]
        assert snap_id.startswith("snap-")

        # 4. List snapshots
        res = await client.get("/api/v1/snapshots")
        assert res.status_code == 200
        assert len(res.json()) >= 1

        # 5. Get snapshot graph
        res = await client.get(f"/api/v1/snapshots/{snap_id}/graph")
        assert res.status_code == 200
        snap_graph = res.json()
        assert snap_graph["graph_id"] == snap_id
