"""Comprehensive PostgreSQL integration tests for DatabaseEngine and MetadataStore."""

import os
import uuid

import pytest

from network_twin.config import AppSettings
from network_twin.models.intelligence import (
    Asset,
    EvidenceRecord,
    NetworkService,
)
from network_twin.services.subsystem_service import SubsystemService
from network_twin.storage.db_engine import (
    DatabaseConnectionError,
    DatabaseEngine,
    DbRow,
    translate_placeholders,
)
from network_twin.storage.metadata_store import MetadataStore

PG_TEST_URL = os.environ.get("NTWIN_DATABASE_URL", "postgresql://postgres@127.0.0.1:54333/network_twin")


def _is_pg_reachable(url: str) -> bool:
    try:
        import psycopg

        conn = psycopg.connect(url, connect_timeout=3)
        conn.close()
        return True
    except Exception:
        return False


skip_if_no_pg = pytest.mark.skipif(
    not _is_pg_reachable(PG_TEST_URL),
    reason=f"PostgreSQL test instance is not reachable at {PG_TEST_URL}",
)


def test_translate_placeholders():
    """Verify placeholder translation preserves quotes and replaces ? with %s."""
    sql = "SELECT * FROM t WHERE a = ? AND b = 'what?' AND c = ?"
    translated = translate_placeholders(sql)
    assert translated == "SELECT * FROM t WHERE a = %s AND b = 'what?' AND c = %s"


def test_db_row():
    """Verify DbRow supports both column name and integer index access."""
    row = DbRow(["col_a", "col_b"], [123, "hello"])
    assert row["col_a"] == 123
    assert row["col_b"] == "hello"
    assert row[0] == 123
    assert row[1] == "hello"
    assert dict(row) == {"col_a": 123, "col_b": "hello"}
    assert row.get("col_a") == 123
    assert row.get("nonexistent", "def") == "def"


def test_refuse_silent_fallback_on_bad_postgres_url():
    """When PostgreSQL is configured but fails to connect, fail fast and do NOT fall back to SQLite."""
    bad_url = "postgresql://invalid_user:invalid_pass@127.0.0.1:59999/nonexistent_db"
    cfg = AppSettings(database_url=bad_url, require_database=False)
    engine = DatabaseEngine(cfg)

    assert engine.db_type == "postgresql"
    assert engine.is_connected is False
    assert engine.last_error is not None

    # Operations must raise DatabaseConnectionError, not fall back to SQLite
    with pytest.raises(DatabaseConnectionError) as exc_info:
        with engine.get_connection() as conn:
            conn.execute("SELECT 1;")
    assert "unavailable" in str(exc_info.value).lower()
    assert "silently fall back" in str(exc_info.value).lower()

    # Health check must honestly report failure
    health = engine.check_health()
    assert health["backend"] == "postgresql"
    assert health["connected"] is False
    assert health["error"] is not None


@skip_if_no_pg
def test_postgres_engine_health_and_pooling():
    """Verify PostgreSQL connection pool opens and health report includes pool stats."""
    cfg = AppSettings(database_url=PG_TEST_URL)
    MetadataStore(cfg)  # ensure schema is initialized
    engine = DatabaseEngine(cfg)
    try:
        assert engine.is_connected is True
        health = engine.check_health()
        assert health["backend"] == "postgresql"
        assert health["connected"] is True
        assert health["schema_version"] == 9
        assert health["pool_stats"] is not None
        assert health["pool_stats"]["min_size"] >= 1
    finally:
        engine.close()


@skip_if_no_pg
def test_postgres_metadata_store_crud():
    """Verify MetadataStore works seamlessly with PostgreSQL for captures, jobs, and entities."""
    cfg = AppSettings(database_url=PG_TEST_URL)
    store = MetadataStore(cfg)

    test_capture_id = f"test-cap-{uuid.uuid4().hex[:8]}"
    test_job_id = f"test-job-{uuid.uuid4().hex[:8]}"

    # 1. Register capture
    store.register_capture(
        capture_id=test_capture_id,
        filename="test_pcap.pcap",
        content_sha256="abcdef1234567890",
        file_size_bytes=1024,
        storage_path="/tmp/test_pcap.pcap",
        format_type="pcap",
    )

    cap = store.get_capture(test_capture_id)
    assert cap is not None
    assert cap["capture_id"] == test_capture_id
    assert cap["filename"] == "test_pcap.pcap"
    assert cap["lifecycle_status"] == "REGISTERED"

    # 2. Update capture lifecycle
    store.update_capture_lifecycle(
        capture_id=test_capture_id,
        lifecycle_status="ANALYZED",
        packet_count=100,
        event_count=95,
        accepted_count=90,
        rejected_count=5,
    )
    cap_updated = store.get_capture(test_capture_id)
    assert cap_updated["lifecycle_status"] == "ANALYZED"
    assert cap_updated["packet_count"] == 100

    # 3. Save analysis job
    store.save_analysis_job(
        job_id=test_job_id,
        capture_id=test_capture_id,
        filename="test_pcap.pcap",
        file_size_bytes=1024,
        status="completed",
        created_at="2026-10-21T00:00:00Z",
        summary_dict={
            "capture_file": "test_pcap.pcap",
            "total_packets": 100,
            "total_flows": 3,
        },
    )
    job = store.get_analysis_job(test_job_id)
    assert job is not None
    assert job["job_id"] == test_job_id
    assert job["capture_id"] == test_capture_id

    # 4. Upsert asset
    asset_id = f"asset-{uuid.uuid4().hex[:8]}"
    asset = Asset(
        asset_id=asset_id,
        primary_ip="10.0.0.50",
        ip_addresses=["10.0.0.50"],
        mac_addresses=["aa:bb:cc:dd:ee:01"],
        hostnames=["pg-test-host"],
        observed_protocols=["TCP", "TLS"],
        observed_services=["https"],
        first_seen="2026-10-21T00:00:00Z",
        last_seen="2026-10-21T01:00:00Z",
        identity_status="CONFIRMED",
        confidence=0.98,
        conflicts=[],
        observation_sources=["test"],
    )
    store.upsert_asset(asset)
    retrieved_asset = store.get_asset(asset_id)
    assert retrieved_asset is not None
    assert retrieved_asset.primary_ip == "10.0.0.50"
    assert "pg-test-host" in retrieved_asset.hostnames

    # 5. Upsert service
    service_id = f"svc-{uuid.uuid4().hex[:8]}"
    service = NetworkService(
        service_id=service_id,
        asset_id=asset_id,
        server_ip="10.0.0.50",
        transport_protocol="TCP",
        port=443,
        app_protocol="TLS",
        classification_confidence=0.95,
        first_seen="2026-10-21T00:00:00Z",
        last_seen="2026-10-21T01:00:00Z",
        observation_sources=["test"],
    )
    store.upsert_service(service)
    retrieved_services = store.list_services()
    assert any(s.service_id == service_id for s in retrieved_services)

    # 6. Save evidence records
    ev_id = f"ev-{uuid.uuid4().hex[:8]}"
    evidence = EvidenceRecord(
        evidence_id=ev_id,
        evidence_type="PACKET_OBSERVED",
        source_type="PCAP",
        source_artifact_id=test_capture_id,
        observation_timestamp="2026-10-21T00:00:00Z",
        ingestion_timestamp="2026-10-21T00:00:01Z",
        src_ref="10.0.0.50:443",
        dst_ref="10.0.0.1:50000",
        parser_status="SUCCESS",
        confidence=1.0,
        provenance=f"capture_id:{test_capture_id}",
        details={"protocol": "TLS"},
    )
    store.save_evidence_records([evidence])
    retrieved_ev = store.get_evidence(ev_id)
    assert retrieved_ev is not None
    assert retrieved_ev.evidence_id == ev_id
    assert retrieved_ev.source_artifact_id == test_capture_id


@skip_if_no_pg
def test_postgres_transaction_rollback():
    """Verify transactions rollback completely on PostgreSQL when an exception occurs."""
    cfg = AppSettings(database_url=PG_TEST_URL)
    store = MetadataStore(cfg)
    test_cap = f"rollback-cap-{uuid.uuid4().hex[:8]}"

    # Attempt to insert and raise an exception inside the transaction
    with pytest.raises(ValueError):
        with store._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO captures (
                    capture_id, filename, content_sha256, file_size_bytes, format,
                    storage_path, uploaded_at, lifecycle_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (test_cap, "rollback.pcap", "sha256", 100, "pcap", "/tmp/r.pcap", "2026-10-21T00:00:00Z", "COMPLETE"),
            )
            # Trigger failure before commit
            raise ValueError("Forced error to test rollback")

    # Record must NOT exist
    assert store.get_capture(test_cap) is None


@skip_if_no_pg
def test_subsystem_service_reports_postgres_health():
    """Verify SubsystemService accurately reports PostgreSQL status and details."""
    cfg = AppSettings(database_url=PG_TEST_URL)
    svc = SubsystemService(cfg)
    report = svc.get_subsystems_report()

    db_report = report.get("database")
    assert db_report is not None
    assert db_report.status.value == "ok"
    assert db_report.operational_state.value == "operational"
    assert "PostgreSQL" in str(db_report.details)
    assert "network_twin" in str(db_report.details)
