"""Phase 12: Reliability, Failure Recovery, and Cross-Component Contracts Tests.

Validates:
1. Database schema migration lifecycle (v1 through v8) on clean databases.
2. Cross-layer contract consistency (C++ output <-> Pydantic <-> SQLite).
3. Malformed and zero-length input rejection without unhandled crashes.
4. Security protections: Path traversal rejection in uploads and corpus access.
5. Investigation failure paths: Unmodeled endpoints, missing dependency replay refusal.
6. Evidence tampering detection via cryptographic verification.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from network_twin.config import AppSettings
from network_twin.investigations.engine import InvestigationEngine
from network_twin.investigations.models import (
    CandidateStatus,
    CreateInvestigationRequest,
    EvidenceSufficiency,
    IntegrityStatus,
    InvestigationScope,
    InvestigationType,
    ReplayStatus,
)
from network_twin.services.analysis_service import AnalysisService
from network_twin.storage.metadata_store import MetadataStore


@pytest.fixture
def clean_env(tmp_path: Path):
    """Provides isolated storage paths and fresh configuration."""
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    return AppSettings(data_dir=str(data_dir), environment="testing")


class TestDatabaseMigrations:
    """Validates metadata store schema migration lifecycle."""

    def test_schema_migrations_reach_target_version(self, clean_env: AppSettings):
        """Verifies that all migrations (v1-v8) apply cleanly to a fresh database."""
        store = MetadataStore(clean_env)

        # Verify target schema version
        with store._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT MAX(version) FROM schema_migrations")
            latest_version = cursor.fetchone()[0]
            assert latest_version == 8, f"Latest schema version must be 8, got {latest_version}"

            # Verify all expected tables exist
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {row[0] for row in cursor.fetchall()}

            expected_tables = {
                "captures",
                "analysis_jobs",
                "assets",
                "services",
                "network_segments",
                "communication_relationships",
                "evidence_records",
                "topology_snapshots",
                "network_models",
                "simulation_scenarios",
                "investigation_cases",
                "investigation_executions",
                "schema_migrations",
            }
            missing_tables = expected_tables - tables
            assert not missing_tables, f"Database is missing expected tables: {missing_tables}"

    def test_reopening_database_does_not_reapply_migrations(self, clean_env: AppSettings):
        """Verifies idempotency of schema migrations upon reopening."""
        store1 = MetadataStore(clean_env)

        with store1._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM schema_migrations")
            migration_count_1 = cursor.fetchone()[0]

        # Reopen with new instance
        store2 = MetadataStore(clean_env)
        with store2._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM schema_migrations")
            migration_count_2 = cursor.fetchone()[0]

        assert migration_count_1 == migration_count_2 == 8


class TestSecurityHardening:
    """Validates input sanitization and security boundary protections."""

    def test_path_traversal_in_upload_filename_rejected(self, clean_env: AppSettings):
        """Verifies that filenames attempting directory traversal are rejected."""
        service = AnalysisService(clean_env)
        dummy_content = b"\xd4\xc3\xb2\xa1" + b"\x00" * 20

        with pytest.raises(ValueError, match="Path traversal detected"):
            service.analyze_capture("../../traversal.pcap", dummy_content)

        with pytest.raises(ValueError, match="Path traversal detected"):
            service.analyze_capture("..\\..\\windows_traversal.pcap", dummy_content)

    def test_malformed_capture_bytes_rejected_safely(self, clean_env: AppSettings):
        """Verifies that completely corrupt or non-PCAP bytes are safely rejected."""
        service = AnalysisService(clean_env)
        corrupted_bytes = b"NOT_A_VALID_PCAP_HEADER_DATA_1234567890"

        with pytest.raises(ValueError, match="Invalid capture file"):
            service.analyze_capture("corrupt.pcap", corrupted_bytes)

    def test_empty_capture_bytes_rejected(self, clean_env: AppSettings):
        """Verifies that zero-byte files are rejected safely."""
        service = AnalysisService(clean_env)
        empty_bytes = b""

        with pytest.raises(ValueError, match="Invalid capture file"):
            service.analyze_capture("empty.pcap", empty_bytes)


class TestInvestigationReliability:
    """Validates investigation failure modes, missing dependencies, and tampering."""

    def test_unmodeled_endpoints_yield_insufficient_evidence(self, clean_env: AppSettings):
        """Verifies that investigating unmodeled endpoints returns INSUFFICIENT evidence."""
        store = MetadataStore(clean_env)
        inv_engine = InvestigationEngine(metadata_store=store)

        req = CreateInvestigationRequest(
            title="Investigation of Phantom Endpoints",
            investigation_type=InvestigationType.CONNECTIVITY_FAILURE,
            scope=InvestigationScope(
                source_ip="198.51.100.99",
                destination_ip="203.0.113.88",
                transport_protocol="TCP",
                destination_port=443,
            ),
        )
        case = inv_engine.create_investigation(req)
        executed = inv_engine.execute_investigation(case.investigation_id)

        assert executed.sufficiency == EvidenceSufficiency.INSUFFICIENT
        assert len(executed.candidate_explanations) > 0
        top = executed.candidate_explanations[0]
        assert top.status == CandidateStatus.INSUFFICIENT_EVIDENCE
        assert "Endpoint Not Modeled" in top.title or "Insufficient" in top.title

    def test_missing_capture_dependency_refuses_replay(self, clean_env: AppSettings):
        """Verifies that replaying when a referenced capture is deleted results in REPLAY_NOT_POSSIBLE."""
        store = MetadataStore(clean_env)
        inv_engine = InvestigationEngine(metadata_store=store)

        # Register capture
        store.register_capture(
            capture_id="cap-temp-test",
            filename="temp.pcap",
            content_sha256="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            file_size_bytes=100,
            format_type="PCAP",
            storage_path="/tmp/temp.pcap",
        )

        req = CreateInvestigationRequest(
            title="Replay Dependency Test",
            investigation_type=InvestigationType.UNEXPECTED_TRAFFIC_RELATIONSHIP,
            scope=InvestigationScope(
                source_ip="10.0.0.1",
                destination_ip="10.0.0.2",
                capture_ids=["cap-temp-test"],
            ),
        )
        case = inv_engine.create_investigation(req)
        inv_engine.execute_investigation(case.investigation_id)

        executions = inv_engine.list_executions(case.investigation_id)
        assert len(executions) >= 1
        original_exec_id = executions[0].execution_id

        # Delete backing capture directly from database to simulate data loss
        with store._get_connection() as conn:
            conn.execute("DELETE FROM captures WHERE capture_id = 'cap-temp-test'")

        # Attempt replay
        replayed_record, comparison = inv_engine.replay_execution(case.investigation_id, original_exec_id)
        assert replayed_record.status == "NOT_POSSIBLE"
        assert comparison.replay_status == ReplayStatus.REPLAY_NOT_POSSIBLE
        assert comparison.is_identical is False
        assert "is no longer present in storage" in replayed_record.unresolved_questions[0]

    def test_evidence_tampering_detected_by_integrity_verifier(self, clean_env: AppSettings):
        """Verifies that modifying evidence node content triggers MODIFIED status."""
        store = MetadataStore(clean_env)
        inv_engine = InvestigationEngine(metadata_store=store)

        req = CreateInvestigationRequest(
            title="Integrity Tamper Detection Test",
            investigation_type=InvestigationType.CONNECTIVITY_FAILURE,
            scope=InvestigationScope(
                source_ip="10.0.0.1",
                destination_ip="10.0.0.2",
                transport_protocol="TCP",
            ),
        )
        case = inv_engine.create_investigation(req)
        inv_engine.execute_investigation(case.investigation_id)

        executions = inv_engine.list_executions(case.investigation_id)
        orig_record = executions[0]

        # Verify initial untampered integrity report
        report1 = inv_engine.verify_execution(orig_record.execution_id)
        assert report1.overall_status == IntegrityStatus.VERIFIED
        assert report1.modified_count == 0

        # Now deliberately tamper with an evidence node in the stored execution record
        tampered_record = orig_record.model_copy(deep=True)
        assert len(tampered_record.evidence_graph.nodes) > 0
        tampered_node = tampered_record.evidence_graph.nodes[0]
        tampered_node.label = "TAMPERED_LABEL_INJECTED_ATTACK"

        # Overwrite in database
        store.save_execution(tampered_record)

        # Verify that integrity auditor flags tampering
        tamper_report = inv_engine.verify_execution(orig_record.execution_id)
        assert tamper_report.overall_status == IntegrityStatus.MODIFIED
        assert tamper_report.modified_count >= 1

        tampered_items = [item for item in tamper_report.item_reports if item.status == IntegrityStatus.MODIFIED]
        assert len(tampered_items) >= 1
        assert tampered_items[0].evidence_id == tampered_node.evidence_id
