"""Tests for MetadataStore (SQLite) and AnalyticsStore (DuckDB + Parquet)."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from network_twin.config import AppSettings
from network_twin.models.intelligence import (
    Asset,
    IdentityStatus,
)
from network_twin.storage.analytics_store import AnalyticsStore
from network_twin.storage.metadata_store import MetadataStore


@pytest.fixture
def test_storage(tmp_path: Path):
    cfg = AppSettings(
        environment="testing",
        data_dir=str(tmp_path),
    )
    meta = MetadataStore(cfg)
    analytics = AnalyticsStore(cfg)
    return meta, analytics, tmp_path


def test_metadata_store_captures_and_jobs(test_storage):
    meta, _, _ = test_storage

    # Register capture
    cap = meta.register_capture(
        capture_id="cap-1",
        filename="test.pcap",
        content_sha256="abc123hash",
        file_size_bytes=1024,
        format_type="PCAP",
        storage_path="/path/test.pcap",
    )
    assert cap["capture_id"] == "cap-1"
    assert cap["content_sha256"] == "abc123hash"

    # Deduplication check
    retrieved = meta.get_capture_by_hash("abc123hash")
    assert retrieved is not None
    assert retrieved["capture_id"] == "cap-1"

    # Save and retrieve analysis job
    meta.save_analysis_job(
        job_id="job-1",
        capture_id="cap-1",
        filename="test.pcap",
        file_size_bytes=1024,
        status="completed",
        created_at=datetime.now(UTC).isoformat(),
        completed_at=datetime.now(UTC).isoformat(),
        summary_dict={"total_packets": 50},
    )

    job = meta.get_analysis_job("job-1")
    assert job is not None
    assert job["status"] == "completed"
    assert job["summary"]["total_packets"] == 50


def test_metadata_store_assets_and_conflicts(test_storage):
    meta, _, _ = test_storage
    now = datetime.now(UTC)

    asset = Asset(
        asset_id="asset-1",
        primary_ip="192.168.1.50",
        ip_addresses=["192.168.1.50"],
        mac_addresses=["00:11:22:33:44:55"],
        hostnames=["workstation.local"],
        observed_protocols=["TCP", "DNS"],
        observed_services=["HTTP"],
        first_seen=now,
        last_seen=now,
        identity_status=IdentityStatus.CONFIRMED,
        confidence=0.95,
        conflicts=[],
        observation_sources=["cap-1"],
    )

    meta.upsert_asset(asset)

    retrieved = meta.get_asset("asset-1")
    assert retrieved is not None
    assert retrieved.primary_ip == "192.168.1.50"
    assert retrieved.identity_status == IdentityStatus.CONFIRMED

    # Update with conflict
    asset.conflicts.append("Conflicting MAC observed: 66:77:88:99:aa:bb")
    asset.identity_status = IdentityStatus.CONFLICTING
    meta.upsert_asset(asset)

    updated = meta.get_asset("asset-1")
    assert updated is not None
    assert updated.identity_status == IdentityStatus.CONFLICTING
    assert len(updated.conflicts) == 1


def test_analytics_store_duckdb_parquet(test_storage):
    _, analytics, tmp_path = test_storage

    # Write a test JSONL event file
    jsonl_file = tmp_path / "test.events.jsonl"
    events = [
        {
            "event_id": "ev-1",
            "event_type": "network.flow",
            "timestamp_ns": 1000000000,
            "timestamp_iso": "2026-04-17T08:00:00.000Z",
            "src_ip": "192.168.1.50",
            "dst_ip": "192.168.1.1",
            "src_port": 54321,
            "dst_port": 53,
            "ip_proto": "UDP",
            "transport_protocol": "UDP",
            "payload_length_bytes": 60,
            "payload_hash_sha256": "hash1",
            "parser_status": {"status": "ok", "message": "Valid"},
            "capture_metadata": {"wire_length_bytes": 60, "captured_length_bytes": 60},
            "flow_state": {"flow_id": "flow-1", "tcp_state": None},
            "dns": {"transaction_id": 1234, "qname": "api.twin.internal"},
            "http": None,
            "tls": None,
        },
        {
            "event_id": "ev-2",
            "event_type": "network.flow",
            "timestamp_ns": 2000000000,
            "timestamp_iso": "2026-04-17T08:00:01.000Z",
            "src_ip": "192.168.1.50",
            "dst_ip": "10.0.0.1",
            "src_port": 49152,
            "dst_port": 80,
            "ip_proto": "TCP",
            "transport_protocol": "TCP",
            "payload_length_bytes": 250,
            "payload_hash_sha256": "hash2",
            "parser_status": {"status": "ok", "message": "Valid"},
            "capture_metadata": {"wire_length_bytes": 250, "captured_length_bytes": 250},
            "flow_state": {"flow_id": "flow-2", "tcp_state": "ESTABLISHED"},
            "dns": None,
            "http": {"method": "GET", "uri": "/v1/health", "status_code": 200},
            "tls": None,
        },
    ]

    with open(jsonl_file, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")

    # Convert to Parquet
    parquet_path = analytics.convert_jsonl_to_parquet("job-test", jsonl_file)
    assert parquet_path.is_file()

    # Query events
    queried = analytics.query_events("job-test")
    assert len(queried) == 2

    # Query top talkers
    talkers = analytics.query_top_talkers("job-test")
    assert len(talkers) == 1
    assert talkers[0]["ip_address"] == "192.168.1.50"
    assert talkers[0]["packet_count"] == 2
    assert talkers[0]["total_bytes"] == 310

    # Query protocol breakdown
    breakdown = analytics.query_protocol_breakdown("job-test")
    assert len(breakdown) == 2
    protos = {b["protocol"] for b in breakdown}
    assert "UDP" in protos
    assert "TCP" in protos
