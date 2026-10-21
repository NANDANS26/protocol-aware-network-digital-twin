"""Tests for C++ Engine -> Rust Evidence Pipeline -> Relational Catalog integration."""

import json
from pathlib import Path

import pytest

from network_twin.config import AppSettings
from network_twin.services.analysis_service import AnalysisService
from network_twin.storage.metadata_store import MetadataStore


@pytest.fixture
def clean_env(tmp_path: Path) -> AppSettings:
    return AppSettings(
        data_dir=str(tmp_path / "data"),
        engine_binary_path=str(Path("build/engine/Release/protocol_engine.exe").resolve()),
    )


def test_analysis_service_invokes_rust_pipeline_on_real_pcap(clean_env: AppSettings):
    sample_pcap = Path("tests/fixtures/sample_capture.pcap").resolve()
    assert sample_pcap.is_file(), "sample_capture.pcap fixture must exist"

    service = AnalysisService(clean_env)
    rust_bin = service.find_rust_pipeline_binary()
    assert rust_bin is not None and rust_bin.is_file(), f"Rust evidence pipeline binary must exist at {rust_bin}"

    with open(sample_pcap, "rb") as f:
        content = f.read()

    job = service.analyze_capture("sample_capture.pcap", content)

    assert job.status == "completed"
    assert job.capture_id is not None
    assert job.job_id is not None

    store = MetadataStore(clean_env)
    cap = store.get_capture(job.capture_id)
    assert cap is not None
    assert cap["lifecycle_status"] == "COMPLETE"
    assert cap["packet_count"] == 15
    assert cap["accepted_count"] == 15
    assert cap["rejected_count"] == 0
    assert cap["active_analysis_run_id"] == job.job_id

    # Verify reconciliation record
    job_record = store.get_analysis_job(job.job_id)
    assert job_record is not None
    reconcil = json.loads(job_record["reconciliation_json"])
    assert reconcil["rust_pipeline_executed"] is True
    assert reconcil["accepted_count"] == 15
    assert reconcil["rejected_count"] == 0
    assert reconcil["status"] == "COMPLETED"

    # Verify canonical events file
    events_path = Path(job_record["events_path"])
    assert events_path.is_file()
    with open(events_path, encoding="utf-8") as f:
        first_line = json.loads(f.readline().strip())
        assert first_line["schema_version"] == "1.0.0"
        prov = first_line["provenance"]
        assert prov["capture_id"] == job.capture_id
        assert prov["analysis_run_id"] == job.job_id
        assert prov["pipeline_version"] == "1.0.0"

    # Verify snapshot lineage
    snapshots = store.list_snapshots(capture_id=job.capture_id)
    assert len(snapshots) >= 1
    snap = snapshots[0]
    assert job.capture_id in snap.source_captures
    assert snap.metadata.get("capture_id") == job.capture_id
    assert snap.metadata.get("analysis_job_id") == job.job_id


def test_independent_capture_uploads_have_unique_identities(clean_env: AppSettings):
    sample_pcap = Path("tests/fixtures/sample_capture.pcap").resolve()
    with open(sample_pcap, "rb") as f:
        content = f.read()

    service = AnalysisService(clean_env)
    job1 = service.analyze_capture("upload_1.pcap", content)
    job2 = service.analyze_capture("upload_2.pcap", content)

    assert job1.capture_id != job2.capture_id, "Each upload must retain its own unique capture identity"

    store = MetadataStore(clean_env)
    cap1 = store.get_capture(job1.capture_id)
    cap2 = store.get_capture(job2.capture_id)

    assert cap1 is not None and cap2 is not None
    assert cap1["filename"] == "upload_1.pcap"
    assert cap2["filename"] == "upload_2.pcap"
    assert cap1["content_sha256"] == cap2["content_sha256"], (
        "Content SHA remains identical while upload histories are independent"
    )


def test_scoped_snapshot_retrieval(clean_env: AppSettings):
    sample_pcap = Path("tests/fixtures/sample_capture.pcap").resolve()
    with open(sample_pcap, "rb") as f:
        content = f.read()

    service = AnalysisService(clean_env)
    job1 = service.analyze_capture("scope_1.pcap", content)
    job2 = service.analyze_capture("scope_2.pcap", content)

    store = MetadataStore(clean_env)
    snaps_1 = store.list_snapshots(capture_id=job1.capture_id)
    snaps_2 = store.list_snapshots(capture_id=job2.capture_id)

    assert len(snaps_1) == 1
    assert len(snaps_2) == 1
    assert snaps_1[0].snapshot_id != snaps_2[0].snapshot_id
    assert snaps_1[0].source_captures == [job1.capture_id]
    assert snaps_2[0].source_captures == [job2.capture_id]


def test_capture_runs_and_active_context_routes(clean_env: AppSettings):
    from fastapi.testclient import TestClient

    from network_twin.main import app

    # Point app state to clean_env
    app.state.config = clean_env
    app.state.analysis_service = AnalysisService(clean_env)

    sample_pcap = Path("tests/fixtures/sample_capture.pcap").resolve()
    with open(sample_pcap, "rb") as f:
        content = f.read()

    job = app.state.analysis_service.analyze_capture("route_test.pcap", content)

    client = TestClient(app)

    # 1. Active context
    resp = client.get(f"/api/v1/captures/{job.capture_id}/active-context")
    assert resp.status_code == 200
    ctx = resp.json()
    assert ctx["capture_id"] == job.capture_id
    assert ctx["filename"] == "route_test.pcap"
    assert ctx["lifecycle_status"] == "COMPLETE"
    assert ctx["active_analysis_run_id"] == job.job_id
    assert ctx["packet_count"] == 15
    assert ctx["accepted_count"] == 15

    # 2. Runs history
    resp_runs = client.get(f"/api/v1/captures/{job.capture_id}/runs")
    assert resp_runs.status_code == 200
    runs = resp_runs.json()
    assert len(runs) >= 1
    assert runs[0]["job_id"] == job.job_id

    # 3. Scoped snapshots
    resp_snaps = client.get(f"/api/v1/snapshots?capture_id={job.capture_id}")
    assert resp_snaps.status_code == 200
    snaps = resp_snaps.json()
    assert len(snaps) >= 1
    assert snaps[0]["source_captures"] == [job.capture_id]
