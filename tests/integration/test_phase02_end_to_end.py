"""Full end-to-end integration test traversing C++ engine -> Parquet -> SQLite -> Topology -> API."""

from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from network_twin.config import AppSettings
from network_twin.main import create_app
from network_twin.services.analysis_service import AnalysisService


@pytest.mark.asyncio
async def test_full_phase02_engine_to_twin_pipeline(tmp_path: Path):
    project_root = Path(__file__).resolve().parents[2]
    sample_pcap = project_root / "tests" / "fixtures" / "sample_capture.pcap"
    assert sample_pcap.is_file(), f"Fixture {sample_pcap} must exist."

    content = sample_pcap.read_bytes()

    cfg = AppSettings(
        environment="testing",
        data_dir=str(tmp_path),
    )

    app = create_app(cfg)
    service = AnalysisService(cfg)
    app.state.analysis_service = service
    app.state.metadata_store = service.metadata_store
    app.state.analytics_store = service.analytics_store

    # 1. Ensure engine binary is available
    binary = service.find_engine_binary()
    assert binary is not None, "protocol_engine.exe must be compiled."

    # 2. Run real C++ engine analysis and intelligence extraction
    job = service.analyze_capture("sample_capture.pcap", content)
    assert job.status == "completed"
    assert job.summary is not None
    assert job.summary.total_packets == 15
    assert job.summary.total_flows == 4

    # 3. Verify Parquet analytical file was created via DuckDB
    parquet_path = service.analytics_store.get_parquet_path(job.job_id)
    assert parquet_path.is_file(), "Parquet analytical file must exist."

    # 4. Verify intelligence assets were persisted in metadata store
    assets = service.metadata_store.list_assets()
    assert len(assets) >= 2, "Observed assets must be identified."
    primary_ips = {a.primary_ip for a in assets}
    assert "192.168.1.50" in primary_ips
    assert "192.168.1.100" in primary_ips

    # 5. Query through the real REST API
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # A. Query Captures
        res = await client.get("/api/v1/captures")
        assert res.status_code == 200
        caps = res.json()
        assert len(caps) >= 1
        assert caps[0]["filename"] == "sample_capture.pcap"

        # B. Query Assets
        res = await client.get("/api/v1/assets")
        assert res.status_code == 200
        asset_list = res.json()
        assert len(asset_list) >= 2

        # C. Query Reconstructed Topology
        res = await client.get("/api/v1/topology")
        assert res.status_code == 200
        topo = res.json()
        assert topo["node_count"] >= 3
        assert topo["edge_count"] >= 2

        # D. Query Snapshots
        res = await client.get("/api/v1/snapshots")
        assert res.status_code == 200
        snaps = res.json()
        assert len(snaps) >= 1

        # E. Query DuckDB Parquet Analytics (Top Talkers)
        res = await client.get(f"/api/v1/analytics/top-talkers?job_id={job.job_id}")
        assert res.status_code == 200
        talkers = res.json()
        assert len(talkers) >= 1
        assert talkers[0]["ip_address"] == "192.168.1.50"
