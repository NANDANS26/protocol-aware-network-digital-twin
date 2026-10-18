"""Relational Metadata Catalog for captures, assets, evidence, and topology snapshots."""

import json
import logging
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from network_twin.benchmarking.models import (
    BenchmarkRunRecord,
    BenchmarkSummaryResponse,
)
from network_twin.config import AppSettings, settings
from network_twin.investigations.models import InvestigationCase
from network_twin.models.intelligence import (
    Asset,
    CommunicationRelationship,
    ConfigImportResult,
    EvidenceRecord,
    NetworkSegment,
    NetworkService,
    TopologyEdge,
    TopologyGraph,
    TopologyNode,
    TopologySnapshot,
)
from network_twin.predictive.models import (
    DatasetManifest,
    ModelArtifact,
    PredictionResult,
)
from network_twin.simulation.models import (
    CounterfactualResult,
    NetworkModel,
    SecurityInvariant,
    SimulationScenario,
    VerificationResult,
)
from network_twin.testing.models import (
    ExecutionResult,
    Finding,
    RegressionFixture,
    TestCampaign,
    TestCase,
)
from network_twin.testing.sequence_models import (
    ExpectedStateTransition,
    ProtocolSequence,
    SequenceFinding,
    SequenceMutation,
    SequenceRegressionFixture,
    SequenceStep,
    SequenceType,
)

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 7


class MetadataStore:
    """Persistent relational catalog with ACID transactions and schema versioning."""

    def __init__(self, config: AppSettings = settings):
        self.config = config
        self.db_path = Path(self.config.data_dir) / "metadata.db"
        self._ensure_initialized()

    def _get_connection(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def _ensure_initialized(self):
        """Initializes tables and executes migrations if needed."""
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL,
                    description TEXT NOT NULL
                );
                """
            )
            cur = conn.execute("SELECT MAX(version) FROM schema_migrations;")
            row = cur.fetchone()
            current_version = row[0] if row and row[0] is not None else 0

            if current_version < 1:
                self._migrate_to_v1(conn)
            if current_version < 2:
                self._migrate_to_v2(conn)
            if current_version < 3:
                self._migrate_to_v3(conn)
            if current_version < 4:
                self._migrate_to_v4(conn)
            if current_version < 5:
                self._migrate_to_v5(conn)
            if current_version < 6:
                self._migrate_to_v6(conn)
            if current_version < 7:
                self._migrate_to_v7(conn)

    def _migrate_to_v1(self, conn: sqlite3.Connection):
        """Initial Schema v1 creation."""
        logger.info("Applying Metadata Store Schema Migration v1...")

        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS captures (
                capture_id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                content_sha256 TEXT NOT NULL UNIQUE,
                file_size_bytes INTEGER NOT NULL,
                format TEXT NOT NULL,
                storage_path TEXT NOT NULL,
                uploaded_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS analysis_jobs (
                job_id TEXT PRIMARY KEY,
                capture_id TEXT REFERENCES captures(capture_id),
                filename TEXT NOT NULL,
                file_size_bytes INTEGER NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                completed_at TEXT,
                error_message TEXT,
                summary_json TEXT
            );

            CREATE TABLE IF NOT EXISTS assets (
                asset_id TEXT PRIMARY KEY,
                primary_ip TEXT NOT NULL,
                ip_addresses_json TEXT NOT NULL,
                mac_addresses_json TEXT NOT NULL,
                hostnames_json TEXT NOT NULL,
                observed_protocols_json TEXT NOT NULL,
                observed_services_json TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                identity_status TEXT NOT NULL,
                confidence REAL NOT NULL,
                conflicts_json TEXT NOT NULL,
                observation_sources_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_assets_primary_ip ON assets(primary_ip);

            CREATE TABLE IF NOT EXISTS network_segments (
                segment_id TEXT PRIMARY KEY,
                cidr_prefix TEXT NOT NULL UNIQUE,
                address_family TEXT NOT NULL,
                gateway_ip TEXT,
                observed_host_count INTEGER NOT NULL,
                configuration_source TEXT,
                confidence REAL NOT NULL,
                provenance TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS services (
                service_id TEXT PRIMARY KEY,
                asset_id TEXT NOT NULL REFERENCES assets(asset_id),
                server_ip TEXT NOT NULL,
                transport_protocol TEXT NOT NULL,
                port INTEGER NOT NULL,
                app_protocol TEXT NOT NULL,
                classification_confidence REAL NOT NULL,
                tls_sni TEXT,
                tls_alpn_json TEXT,
                http_server TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_services_server_port ON services(server_ip, port, transport_protocol);

            CREATE TABLE IF NOT EXISTS evidence_records (
                evidence_id TEXT PRIMARY KEY,
                evidence_type TEXT NOT NULL,
                source_type TEXT NOT NULL,
                source_artifact_id TEXT NOT NULL,
                observation_timestamp TEXT,
                ingestion_timestamp TEXT NOT NULL,
                src_ref TEXT,
                dst_ref TEXT,
                parser_status TEXT NOT NULL,
                confidence REAL NOT NULL,
                provenance TEXT NOT NULL,
                details_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_evidence_artifact ON evidence_records(source_artifact_id);

            CREATE TABLE IF NOT EXISTS communication_relationships (
                relationship_id TEXT PRIMARY KEY,
                src_asset_id TEXT NOT NULL REFERENCES assets(asset_id),
                dst_asset_id TEXT NOT NULL REFERENCES assets(asset_id),
                transport_protocol TEXT NOT NULL,
                src_port INTEGER,
                dst_port INTEGER,
                app_protocol TEXT NOT NULL,
                packet_count INTEGER NOT NULL,
                byte_count INTEGER NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                flow_ids_json TEXT NOT NULL,
                dns_transaction_ids_json TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                directionality TEXT NOT NULL,
                confidence REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_comm_src_dst ON communication_relationships(src_asset_id, dst_asset_id);

            CREATE TABLE IF NOT EXISTS topology_snapshots (
                snapshot_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                source_captures_json TEXT NOT NULL,
                source_configs_json TEXT NOT NULL,
                identity_policy_version TEXT NOT NULL,
                graph_algorithm_version TEXT NOT NULL,
                node_count INTEGER NOT NULL,
                edge_count INTEGER NOT NULL,
                unresolved_conflicts_json TEXT NOT NULL,
                schema_version TEXT NOT NULL,
                metadata_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS snapshot_nodes (
                snapshot_id TEXT NOT NULL REFERENCES topology_snapshots(snapshot_id) ON DELETE CASCADE,
                node_id TEXT NOT NULL,
                node_type TEXT NOT NULL,
                label TEXT NOT NULL,
                asset_id TEXT,
                segment_id TEXT,
                properties_json TEXT NOT NULL,
                PRIMARY KEY (snapshot_id, node_id)
            );

            CREATE TABLE IF NOT EXISTS snapshot_edges (
                snapshot_id TEXT NOT NULL REFERENCES topology_snapshots(snapshot_id) ON DELETE CASCADE,
                edge_id TEXT NOT NULL,
                source_node_id TEXT NOT NULL,
                target_node_id TEXT NOT NULL,
                edge_type TEXT NOT NULL,
                evidence_class TEXT NOT NULL,
                primary_protocol TEXT NOT NULL,
                packet_count INTEGER NOT NULL,
                byte_count INTEGER NOT NULL,
                confidence REAL NOT NULL,
                evidence_ids_json TEXT NOT NULL,
                properties_json TEXT NOT NULL,
                PRIMARY KEY (snapshot_id, edge_id)
            );

            CREATE TABLE IF NOT EXISTS imported_configurations (
                import_id TEXT PRIMARY KEY,
                format TEXT NOT NULL,
                source_name TEXT NOT NULL,
                status TEXT NOT NULL,
                items_imported INTEGER NOT NULL,
                errors_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                evidence_ids_json TEXT NOT NULL
            );

            INSERT INTO schema_migrations (version, applied_at, description)
            VALUES (1, datetime('now'), 'Initial schema for captures, assets, evidence, and topology');
            """
        )
        conn.commit()

    def _migrate_to_v2(self, conn: sqlite3.Connection):
        """Schema v2: Executable Network Models, Scenarios, Invariants, and Results."""
        logger.info("Applying Metadata Store Schema Migration v2...")

        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS network_models (
                model_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                source_snapshot_id TEXT NOT NULL REFERENCES topology_snapshots(snapshot_id) ON DELETE CASCADE,
                source_snapshot_fingerprint TEXT NOT NULL,
                schema_version TEXT NOT NULL,
                model_version INTEGER NOT NULL,
                fingerprint TEXT NOT NULL,
                created_at TEXT NOT NULL,
                is_counterfactual INTEGER NOT NULL DEFAULT 0,
                parent_model_id TEXT,
                model_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS simulation_scenarios (
                scenario_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                base_model_id TEXT NOT NULL REFERENCES network_models(model_id) ON DELETE CASCADE,
                created_at TEXT NOT NULL,
                scenario_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS counterfactual_results (
                run_id TEXT PRIMARY KEY,
                scenario_id TEXT NOT NULL,
                base_model_id TEXT NOT NULL,
                baseline_fingerprint TEXT NOT NULL,
                counterfactual_model_id TEXT NOT NULL,
                counterfactual_fingerprint TEXT NOT NULL,
                applied_actions_count INTEGER NOT NULL,
                newly_reachable_count INTEGER NOT NULL,
                newly_blocked_count INTEGER NOT NULL,
                invariant_regressions_count INTEGER NOT NULL,
                executed_at TEXT NOT NULL,
                result_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS security_invariants (
                invariant_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                invariant_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                scope TEXT NOT NULL,
                version TEXT NOT NULL,
                created_at TEXT NOT NULL,
                definition_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS verification_runs (
                run_id TEXT PRIMARY KEY,
                model_id TEXT NOT NULL,
                scenario_id TEXT,
                evaluated_at TEXT NOT NULL,
                pass_count INTEGER NOT NULL,
                fail_count INTEGER NOT NULL,
                indeterminate_count INTEGER NOT NULL,
                summary_json TEXT NOT NULL,
                results_json TEXT NOT NULL
            );

            INSERT INTO schema_migrations (version, applied_at, description)
            VALUES (2, datetime('now'), 'Phase 03: Executable Network Models, Scenarios, Invariants, and Results');
            """
        )
        conn.commit()

    def _migrate_to_v3(self, conn: sqlite3.Connection):
        """Schema v3: Protocol Security Testing Campaigns, Cases, Findings, and Regressions."""
        logger.info("Applying Metadata Store Schema Migration v3...")

        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS test_campaigns (
                campaign_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                protocol_targets_json TEXT NOT NULL,
                strategies_json TEXT NOT NULL,
                seed INTEGER NOT NULL,
                max_cases_per_target INTEGER NOT NULL,
                total_cases INTEGER NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                completed_at TEXT,
                cases_generated INTEGER NOT NULL DEFAULT 0,
                cases_executed INTEGER NOT NULL DEFAULT 0,
                passed_count INTEGER NOT NULL DEFAULT 0,
                rejected_count INTEGER NOT NULL DEFAULT 0,
                failed_count INTEGER NOT NULL DEFAULT 0,
                findings_count INTEGER NOT NULL DEFAULT 0,
                duration_ms REAL NOT NULL DEFAULT 0.0,
                engine_version TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS test_cases (
                case_id TEXT PRIMARY KEY,
                campaign_id TEXT NOT NULL REFERENCES test_campaigns(campaign_id) ON DELETE CASCADE,
                test_index INTEGER NOT NULL,
                protocol_target TEXT NOT NULL,
                generation_strategy TEXT NOT NULL,
                mutation_sequence_json TEXT NOT NULL,
                seed INTEGER NOT NULL,
                generator_version TEXT NOT NULL,
                fixture_format TEXT NOT NULL,
                fixture_path TEXT NOT NULL,
                fixture_hash TEXT NOT NULL,
                expected_behavior TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS execution_results (
                result_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL REFERENCES test_cases(case_id) ON DELETE CASCADE,
                exit_code INTEGER NOT NULL,
                stdout TEXT NOT NULL,
                stderr TEXT NOT NULL,
                execution_time_ms REAL NOT NULL,
                parser_status TEXT NOT NULL,
                parsed_event_count INTEGER NOT NULL,
                schema_valid INTEGER NOT NULL,
                schema_errors_json TEXT NOT NULL,
                anomalies_json TEXT NOT NULL,
                sanitizer_triggered INTEGER NOT NULL,
                crash_detected INTEGER NOT NULL,
                passed INTEGER NOT NULL,
                diagnostic TEXT,
                executed_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS test_findings (
                finding_id TEXT PRIMARY KEY,
                campaign_id TEXT NOT NULL REFERENCES test_campaigns(campaign_id) ON DELETE CASCADE,
                case_id TEXT NOT NULL REFERENCES test_cases(case_id) ON DELETE CASCADE,
                protocol_target TEXT NOT NULL,
                parser_component TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                failure_category TEXT NOT NULL,
                input_hash TEXT NOT NULL,
                engine_version TEXT NOT NULL,
                reproduction_command TEXT NOT NULL,
                seed INTEGER NOT NULL,
                mutation_sequence_json TEXT NOT NULL,
                expected_behavior TEXT NOT NULL,
                actual_behavior TEXT NOT NULL,
                diagnostic TEXT NOT NULL,
                status TEXT NOT NULL,
                regression_fixture_id TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS regression_fixtures (
                fixture_id TEXT PRIMARY KEY,
                finding_id TEXT NOT NULL,
                name TEXT NOT NULL,
                protocol_target TEXT NOT NULL,
                failure_category TEXT NOT NULL,
                fixture_path TEXT NOT NULL,
                fixture_hash TEXT NOT NULL,
                engine_baseline_version TEXT NOT NULL,
                expected_behavior TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_run_at TEXT,
                last_run_passed INTEGER,
                last_run_exit_code INTEGER,
                last_run_diagnostic TEXT
            );

            INSERT INTO schema_migrations (version, applied_at, description)
            VALUES (3, datetime('now'), 'Phase 04: Protocol Security Testing, Campaigns, Cases, Findings, and Regressions');
            """
        )
        conn.commit()

    def _migrate_to_v4(self, conn: sqlite3.Connection):
        """Schema v4: Stateful Protocol Sequences, Sequence Observations, Findings, and Regressions."""
        logger.info("Applying Metadata Store Schema Migration v4...")

        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS protocol_sequences (
                sequence_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                sequence_type TEXT NOT NULL,
                seed INTEGER NOT NULL,
                generator_version TEXT NOT NULL,
                steps_json TEXT NOT NULL,
                expected_transitions_json TEXT NOT NULL,
                expected_flow_count INTEGER NOT NULL,
                expected_properties_json TEXT NOT NULL,
                mutations_json TEXT NOT NULL,
                format TEXT NOT NULL,
                fixture_path TEXT,
                fixture_hash TEXT,
                is_supported INTEGER NOT NULL,
                coverage_gap_notes TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sequence_findings (
                finding_id TEXT PRIMARY KEY,
                sequence_id TEXT NOT NULL REFERENCES protocol_sequences(sequence_id) ON DELETE CASCADE,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                root_cause_summary TEXT NOT NULL,
                reproduction_command TEXT NOT NULL,
                fixture_path TEXT NOT NULL,
                fixture_hash TEXT NOT NULL,
                minimized INTEGER NOT NULL,
                minimized_sequence_id TEXT,
                is_regression INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sequence_regressions (
                regression_id TEXT PRIMARY KEY,
                finding_id TEXT NOT NULL,
                name TEXT NOT NULL,
                sequence_type TEXT NOT NULL,
                fixture_path TEXT NOT NULL,
                fixture_hash TEXT NOT NULL,
                expected_exit_code INTEGER NOT NULL,
                expected_to_pass INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                last_run_at TEXT,
                last_run_passed INTEGER
            );

            INSERT INTO schema_migrations (version, applied_at, description)
            VALUES (4, datetime('now'), 'Phase 05: Stateful Protocol Sequences, Findings, and Regressions');
            """
        )
        conn.commit()

    def _migrate_to_v5(self, conn: sqlite3.Connection):
        """Schema v5: Predictive Network World Model, Datasets, Model Artifacts, and Predictions."""
        logger.info("Applying Metadata Store Schema Migration v5...")

        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS predictive_datasets (
                dataset_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                pipeline_version TEXT NOT NULL,
                time_window_sec REAL NOT NULL,
                total_samples INTEGER NOT NULL,
                feature_count INTEGER NOT NULL,
                target_type TEXT NOT NULL,
                hash_sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL,
                manifest_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS model_artifacts (
                model_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                version TEXT NOT NULL,
                target TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                dataset_id TEXT NOT NULL REFERENCES predictive_datasets(dataset_id) ON DELETE CASCADE,
                artifact_path TEXT NOT NULL,
                artifact_hash_sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL,
                artifact_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS prediction_records (
                prediction_id TEXT PRIMARY KEY,
                model_id TEXT NOT NULL REFERENCES model_artifacts(model_id) ON DELETE CASCADE,
                target TEXT NOT NULL,
                predicted_value REAL NOT NULL,
                predicted_at TEXT NOT NULL,
                result_json TEXT NOT NULL
            );

            INSERT INTO schema_migrations (version, applied_at, description)
            VALUES (5, datetime('now'), 'Phase 06: Predictive Network World Model, Datasets, Model Artifacts, and Predictions');
            """
        )
        conn.commit()

    def _migrate_to_v6(self, conn: sqlite3.Connection):
        """Schema v6: Benchmarking and validation ledger."""
        logger.info("Applying Metadata Store Schema Migration v6...")

        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS benchmark_runs (
                run_id TEXT PRIMARY KEY,
                fixture_id TEXT NOT NULL,
                fixture_name TEXT NOT NULL,
                provenance TEXT NOT NULL,
                category TEXT NOT NULL,
                fixture_sha256 TEXT NOT NULL,
                git_commit TEXT NOT NULL,
                software_version TEXT NOT NULL,
                executed_at TEXT NOT NULL,
                status TEXT NOT NULL,
                decoding_metrics_json TEXT NOT NULL,
                deterministic_metrics_json TEXT NOT NULL,
                predictive_metrics_json TEXT,
                consensus_metrics_json TEXT,
                operational_profile_json TEXT NOT NULL,
                limitations_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS benchmark_metrics (
                metric_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL REFERENCES benchmark_runs(run_id) ON DELETE CASCADE,
                metric_name TEXT NOT NULL,
                metric_value REAL NOT NULL,
                sample_count INTEGER,
                created_at TEXT NOT NULL
            );

            INSERT INTO schema_migrations (version, applied_at, description)
            VALUES (6, datetime('now'), 'Phase 07: Real-World Validation and Reproducible Benchmark Catalog');
            """
        )
        conn.commit()

    def _migrate_to_v7(self, conn: sqlite3.Connection):
        """Schema v7: Incident Investigations, Evidence Graphs, and Ranked Explanations."""
        logger.info("Applying Metadata Store Schema Migration v7...")

        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS investigation_cases (
                investigation_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                investigation_type TEXT NOT NULL,
                scope_json TEXT NOT NULL,
                status TEXT NOT NULL,
                sufficiency TEXT NOT NULL,
                created_at_iso TEXT NOT NULL,
                updated_at_iso TEXT NOT NULL,
                evidence_graph_json TEXT NOT NULL,
                candidate_explanations_json TEXT NOT NULL,
                primary_root_cause_id TEXT,
                counterfactual_comparisons_json TEXT NOT NULL,
                unresolved_questions_json TEXT NOT NULL,
                explicit_limitations_json TEXT NOT NULL,
                reproduction_steps_json TEXT NOT NULL
            );

            INSERT INTO schema_migrations (version, applied_at, description)
            VALUES (7, datetime('now'), 'Phase 10: Evidence-Backed Network Incident Investigation and Root-Cause Analysis');
            """
        )
        conn.commit()

    # --- Captures & Jobs ---

    def register_capture(
        self,
        capture_id: str,
        filename: str,
        content_sha256: str,
        file_size_bytes: int,
        format_type: str,
        storage_path: str,
    ) -> dict[str, Any]:
        with self._get_connection() as conn:
            existing = self.get_capture_by_hash(content_sha256)
            if existing:
                actual_capture_id = existing["capture_id"]
                conn.execute(
                    "UPDATE captures SET filename = ?, storage_path = ? WHERE capture_id = ?;",
                    (filename, storage_path, actual_capture_id),
                )
                conn.commit()
                return self.get_capture(actual_capture_id) or {}

            now_iso = datetime.now(UTC).isoformat()
            conn.execute(
                """
                INSERT INTO captures (capture_id, filename, content_sha256, file_size_bytes, format, storage_path, uploaded_at)
                VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (capture_id, filename, content_sha256, file_size_bytes, format_type, storage_path, now_iso),
            )
            conn.commit()
            return self.get_capture(capture_id) or {}

    def get_capture(self, capture_id: str) -> dict[str, Any] | None:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM captures WHERE capture_id = ?;", (capture_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def get_capture_by_hash(self, content_sha256: str) -> dict[str, Any] | None:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM captures WHERE content_sha256 = ?;", (content_sha256,))
            row = cur.fetchone()
            return dict(row) if row else None

    def list_captures(self) -> list[dict[str, Any]]:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM captures ORDER BY uploaded_at DESC;")
            return [dict(r) for r in cur.fetchall()]

    def save_analysis_job(
        self,
        job_id: str,
        capture_id: str | None,
        filename: str,
        file_size_bytes: int,
        status: str,
        created_at: str,
        completed_at: str | None = None,
        error_message: str | None = None,
        summary_dict: dict[str, Any] | None = None,
    ):
        with self._get_connection() as conn:
            # Verify foreign key existence for capture_id if provided
            if capture_id:
                cur = conn.execute("SELECT 1 FROM captures WHERE capture_id = ?;", (capture_id,))
                if not cur.fetchone():
                    capture_id = None

            summary_json = json.dumps(summary_dict) if summary_dict else None
            conn.execute(
                """
                INSERT INTO analysis_jobs (job_id, capture_id, filename, file_size_bytes, status, created_at, completed_at, error_message, summary_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    status=excluded.status,
                    completed_at=excluded.completed_at,
                    error_message=excluded.error_message,
                    summary_json=excluded.summary_json;
                """,
                (
                    job_id,
                    capture_id,
                    filename,
                    file_size_bytes,
                    status,
                    created_at,
                    completed_at,
                    error_message,
                    summary_json,
                ),
            )
            conn.commit()

    def get_analysis_job(self, job_id: str) -> dict[str, Any] | None:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM analysis_jobs WHERE job_id = ?;", (job_id,))
            row = cur.fetchone()
            if not row:
                return None
            res = dict(row)
            if res.get("summary_json"):
                res["summary"] = json.loads(res["summary_json"])
            else:
                res["summary"] = None
            return res

    def list_analysis_jobs(self) -> list[dict[str, Any]]:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM analysis_jobs ORDER BY created_at DESC;")
            jobs = []
            for row in cur.fetchall():
                item = dict(row)
                if item.get("summary_json"):
                    item["summary"] = json.loads(item["summary_json"])
                else:
                    item["summary"] = None
                jobs.append(item)
            return jobs

    # --- Evidence Records ---

    def save_evidence_records(self, records: list[EvidenceRecord]):
        if not records:
            return
        with self._get_connection() as conn:
            conn.executemany(
                """
                INSERT INTO evidence_records (
                    evidence_id, evidence_type, source_type, source_artifact_id,
                    observation_timestamp, ingestion_timestamp, src_ref, dst_ref,
                    parser_status, confidence, provenance, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(evidence_id) DO UPDATE SET
                    confidence=excluded.confidence,
                    details_json=excluded.details_json;
                """,
                [
                    (
                        r.evidence_id,
                        r.evidence_type.value,
                        r.source_type,
                        r.source_artifact_id,
                        r.observation_timestamp.isoformat() if r.observation_timestamp else None,
                        r.ingestion_timestamp.isoformat(),
                        r.src_ref,
                        r.dst_ref,
                        r.parser_status,
                        r.confidence,
                        r.provenance,
                        json.dumps(r.details),
                    )
                    for r in records
                ],
            )
            conn.commit()

    def get_evidence(self, evidence_id: str) -> EvidenceRecord | None:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM evidence_records WHERE evidence_id = ?;", (evidence_id,))
            row = cur.fetchone()
            if not row:
                return None
            return self._row_to_evidence(row)

    def list_evidence(
        self,
        source_artifact_id: str | None = None,
        evidence_type: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[EvidenceRecord]:
        query = "SELECT * FROM evidence_records WHERE 1=1"
        params: list[Any] = []
        if source_artifact_id:
            query += " AND source_artifact_id = ?"
            params.append(source_artifact_id)
        if evidence_type:
            query += " AND evidence_type = ?"
            params.append(evidence_type)
        query += " ORDER BY ingestion_timestamp DESC LIMIT ? OFFSET ?;"
        params.extend([limit, offset])

        with self._get_connection() as conn:
            cur = conn.execute(query, params)
            return [self._row_to_evidence(r) for r in cur.fetchall()]

    def _row_to_evidence(self, row: sqlite3.Row) -> EvidenceRecord:
        return EvidenceRecord(
            evidence_id=row["evidence_id"],
            evidence_type=row["evidence_type"],
            source_type=row["source_type"],
            source_artifact_id=row["source_artifact_id"],
            observation_timestamp=datetime.fromisoformat(row["observation_timestamp"])
            if row["observation_timestamp"]
            else None,
            ingestion_timestamp=datetime.fromisoformat(row["ingestion_timestamp"]),
            src_ref=row["src_ref"],
            dst_ref=row["dst_ref"],
            parser_status=row["parser_status"],
            confidence=row["confidence"],
            provenance=row["provenance"],
            details=json.loads(row["details_json"]),
        )

    # --- Assets ---

    def upsert_asset(self, asset: Asset):
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO assets (
                    asset_id, primary_ip, ip_addresses_json, mac_addresses_json,
                    hostnames_json, observed_protocols_json, observed_services_json,
                    first_seen, last_seen, identity_status, confidence,
                    conflicts_json, observation_sources_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(asset_id) DO UPDATE SET
                    primary_ip=excluded.primary_ip,
                    ip_addresses_json=excluded.ip_addresses_json,
                    mac_addresses_json=excluded.mac_addresses_json,
                    hostnames_json=excluded.hostnames_json,
                    observed_protocols_json=excluded.observed_protocols_json,
                    observed_services_json=excluded.observed_services_json,
                    last_seen=excluded.last_seen,
                    identity_status=excluded.identity_status,
                    confidence=excluded.confidence,
                    conflicts_json=excluded.conflicts_json,
                    observation_sources_json=excluded.observation_sources_json;
                """,
                (
                    asset.asset_id,
                    asset.primary_ip,
                    json.dumps(asset.ip_addresses),
                    json.dumps(asset.mac_addresses),
                    json.dumps(asset.hostnames),
                    json.dumps(asset.observed_protocols),
                    json.dumps(asset.observed_services),
                    asset.first_seen.isoformat(),
                    asset.last_seen.isoformat(),
                    asset.identity_status.value,
                    asset.confidence,
                    json.dumps(asset.conflicts),
                    json.dumps(asset.observation_sources),
                ),
            )
            conn.commit()

    def get_asset(self, asset_id: str) -> Asset | None:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM assets WHERE asset_id = ?;", (asset_id,))
            row = cur.fetchone()
            return self._row_to_asset(row) if row else None

    def list_assets(
        self,
        ip_query: str | None = None,
        identity_status: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Asset]:
        query = "SELECT * FROM assets WHERE 1=1"
        params: list[Any] = []
        if ip_query:
            query += " AND (primary_ip LIKE ? OR ip_addresses_json LIKE ? OR hostnames_json LIKE ?)"
            pat = f"%{ip_query}%"
            params.extend([pat, pat, pat])
        if identity_status:
            query += " AND identity_status = ?"
            params.append(identity_status)
        query += " ORDER BY last_seen DESC LIMIT ? OFFSET ?;"
        params.extend([limit, offset])

        with self._get_connection() as conn:
            cur = conn.execute(query, params)
            return [self._row_to_asset(r) for r in cur.fetchall()]

    def find_asset_by_ip(self, ip: str) -> Asset | None:
        """Finds an asset whose primary_ip or ip_addresses matches the given IP."""
        assets = self.list_assets(ip_query=ip, limit=10)
        for asset in assets:
            if asset.primary_ip == ip or ip in asset.ip_addresses:
                return asset
        return None

    def _row_to_asset(self, row: sqlite3.Row) -> Asset:
        return Asset(
            asset_id=row["asset_id"],
            primary_ip=row["primary_ip"],
            ip_addresses=json.loads(row["ip_addresses_json"]),
            mac_addresses=json.loads(row["mac_addresses_json"]),
            hostnames=json.loads(row["hostnames_json"]),
            observed_protocols=json.loads(row["observed_protocols_json"]),
            observed_services=json.loads(row["observed_services_json"]),
            first_seen=datetime.fromisoformat(row["first_seen"]),
            last_seen=datetime.fromisoformat(row["last_seen"]),
            identity_status=row["identity_status"],
            confidence=row["confidence"],
            conflicts=json.loads(row["conflicts_json"]),
            observation_sources=json.loads(row["observation_sources_json"]),
        )

    # --- Segments & Services ---

    def upsert_segment(self, segment: NetworkSegment):
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO network_segments (
                    segment_id, cidr_prefix, address_family, gateway_ip,
                    observed_host_count, configuration_source, confidence,
                    provenance, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cidr_prefix) DO UPDATE SET
                    observed_host_count=excluded.observed_host_count,
                    gateway_ip=COALESCE(excluded.gateway_ip, network_segments.gateway_ip),
                    last_seen=excluded.last_seen;
                """,
                (
                    segment.segment_id,
                    segment.cidr_prefix,
                    segment.address_family,
                    segment.gateway_ip,
                    segment.observed_host_count,
                    segment.configuration_source,
                    segment.confidence,
                    segment.provenance,
                    segment.first_seen.isoformat(),
                    segment.last_seen.isoformat(),
                ),
            )
            conn.commit()

    def list_segments(self) -> list[NetworkSegment]:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM network_segments ORDER BY cidr_prefix ASC;")
            return [
                NetworkSegment(
                    segment_id=r["segment_id"],
                    cidr_prefix=r["cidr_prefix"],
                    address_family=r["address_family"],
                    gateway_ip=r["gateway_ip"],
                    observed_host_count=r["observed_host_count"],
                    configuration_source=r["configuration_source"],
                    confidence=r["confidence"],
                    provenance=r["provenance"],
                    first_seen=datetime.fromisoformat(r["first_seen"]),
                    last_seen=datetime.fromisoformat(r["last_seen"]),
                )
                for r in cur.fetchall()
            ]

    def upsert_service(self, service: NetworkService):
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO services (
                    service_id, asset_id, server_ip, transport_protocol, port,
                    app_protocol, classification_confidence, tls_sni, tls_alpn_json,
                    http_server, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(service_id) DO UPDATE SET
                    app_protocol=excluded.app_protocol,
                    classification_confidence=excluded.classification_confidence,
                    tls_sni=COALESCE(excluded.tls_sni, services.tls_sni),
                    tls_alpn_json=COALESCE(excluded.tls_alpn_json, services.tls_alpn_json),
                    http_server=COALESCE(excluded.http_server, services.http_server),
                    last_seen=excluded.last_seen;
                """,
                (
                    service.service_id,
                    service.asset_id,
                    service.server_ip,
                    service.transport_protocol,
                    service.port,
                    service.app_protocol,
                    service.classification_confidence,
                    service.tls_sni,
                    json.dumps(service.tls_alpn),
                    service.http_server,
                    service.first_seen.isoformat(),
                    service.last_seen.isoformat(),
                ),
            )
            conn.commit()

    def list_services(self, asset_id: str | None = None) -> list[NetworkService]:
        query = "SELECT * FROM services WHERE 1=1"
        params: list[Any] = []
        if asset_id:
            query += " AND asset_id = ?"
            params.append(asset_id)
        query += " ORDER BY server_ip, port ASC;"

        with self._get_connection() as conn:
            cur = conn.execute(query, params)
            return [
                NetworkService(
                    service_id=r["service_id"],
                    asset_id=r["asset_id"],
                    server_ip=r["server_ip"],
                    transport_protocol=r["transport_protocol"],
                    port=r["port"],
                    app_protocol=r["app_protocol"],
                    classification_confidence=r["classification_confidence"],
                    tls_sni=r["tls_sni"],
                    tls_alpn=json.loads(r["tls_alpn_json"] or "[]"),
                    http_server=r["http_server"],
                    first_seen=datetime.fromisoformat(r["first_seen"]),
                    last_seen=datetime.fromisoformat(r["last_seen"]),
                )
                for r in cur.fetchall()
            ]

    # --- Communication Relationships ---

    def upsert_relationship(self, rel: CommunicationRelationship):
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO communication_relationships (
                    relationship_id, src_asset_id, dst_asset_id, transport_protocol,
                    src_port, dst_port, app_protocol, packet_count, byte_count,
                    first_seen, last_seen, flow_ids_json, dns_transaction_ids_json,
                    evidence_type, directionality, confidence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(relationship_id) DO UPDATE SET
                    packet_count=communication_relationships.packet_count + excluded.packet_count,
                    byte_count=communication_relationships.byte_count + excluded.byte_count,
                    last_seen=excluded.last_seen,
                    flow_ids_json=excluded.flow_ids_json,
                    dns_transaction_ids_json=excluded.dns_transaction_ids_json;
                """,
                (
                    rel.relationship_id,
                    rel.src_asset_id,
                    rel.dst_asset_id,
                    rel.transport_protocol,
                    rel.src_port,
                    rel.dst_port,
                    rel.app_protocol,
                    rel.packet_count,
                    rel.byte_count,
                    rel.first_seen.isoformat(),
                    rel.last_seen.isoformat(),
                    json.dumps(rel.flow_ids),
                    json.dumps(rel.dns_transaction_ids),
                    rel.evidence_type.value,
                    rel.directionality,
                    rel.confidence,
                ),
            )
            conn.commit()

    def list_relationships(
        self,
        asset_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[CommunicationRelationship]:
        query = "SELECT * FROM communication_relationships WHERE 1=1"
        params: list[Any] = []
        if asset_id:
            query += " AND (src_asset_id = ? OR dst_asset_id = ?)"
            params.extend([asset_id, asset_id])
        query += " ORDER BY packet_count DESC LIMIT ? OFFSET ?;"
        params.extend([limit, offset])

        with self._get_connection() as conn:
            cur = conn.execute(query, params)
            return [
                CommunicationRelationship(
                    relationship_id=r["relationship_id"],
                    src_asset_id=r["src_asset_id"],
                    dst_asset_id=r["dst_asset_id"],
                    transport_protocol=r["transport_protocol"],
                    src_port=r["src_port"],
                    dst_port=r["dst_port"],
                    app_protocol=r["app_protocol"],
                    packet_count=r["packet_count"],
                    byte_count=r["byte_count"],
                    first_seen=datetime.fromisoformat(r["first_seen"]),
                    last_seen=datetime.fromisoformat(r["last_seen"]),
                    flow_ids=json.loads(r["flow_ids_json"]),
                    dns_transaction_ids=json.loads(r["dns_transaction_ids_json"]),
                    evidence_type=r["evidence_type"],
                    directionality=r["directionality"],
                    confidence=r["confidence"],
                )
                for r in cur.fetchall()
            ]

    # --- Snapshots ---

    def save_snapshot(self, snapshot: TopologySnapshot, graph: TopologyGraph):
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO topology_snapshots (
                    snapshot_id, name, created_at, source_captures_json, source_configs_json,
                    identity_policy_version, graph_algorithm_version, node_count, edge_count,
                    unresolved_conflicts_json, schema_version, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(snapshot_id) DO UPDATE SET
                    name=excluded.name,
                    node_count=excluded.node_count,
                    edge_count=excluded.edge_count;
                """,
                (
                    snapshot.snapshot_id,
                    snapshot.name,
                    snapshot.created_at.isoformat(),
                    json.dumps(snapshot.source_captures),
                    json.dumps(snapshot.source_configs),
                    snapshot.identity_policy_version,
                    snapshot.graph_algorithm_version,
                    snapshot.node_count,
                    snapshot.edge_count,
                    json.dumps(snapshot.unresolved_conflicts),
                    snapshot.schema_version,
                    json.dumps(snapshot.metadata),
                ),
            )

            # Insert nodes
            conn.executemany(
                """
                INSERT INTO snapshot_nodes (snapshot_id, node_id, node_type, label, asset_id, segment_id, properties_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(snapshot_id, node_id) DO UPDATE SET
                    label=excluded.label,
                    properties_json=excluded.properties_json;
                """,
                [
                    (
                        snapshot.snapshot_id,
                        n.node_id,
                        n.node_type.value,
                        n.label,
                        n.asset_id,
                        n.segment_id,
                        json.dumps(n.properties),
                    )
                    for n in graph.nodes
                ],
            )

            # Insert edges
            conn.executemany(
                """
                INSERT INTO snapshot_edges (
                    snapshot_id, edge_id, source_node_id, target_node_id,
                    edge_type, evidence_class, primary_protocol, packet_count,
                    byte_count, confidence, evidence_ids_json, properties_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(snapshot_id, edge_id) DO UPDATE SET
                    packet_count=excluded.packet_count,
                    byte_count=excluded.byte_count,
                    properties_json=excluded.properties_json;
                """,
                [
                    (
                        snapshot.snapshot_id,
                        e.edge_id,
                        e.source_node_id,
                        e.target_node_id,
                        e.edge_type.value,
                        e.evidence_class.value,
                        e.primary_protocol,
                        e.packet_count,
                        e.byte_count,
                        e.confidence,
                        json.dumps(e.evidence_ids),
                        json.dumps(e.properties),
                    )
                    for e in graph.edges
                ],
            )
            conn.commit()

    def get_snapshot(self, snapshot_id: str) -> TopologySnapshot | None:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM topology_snapshots WHERE snapshot_id = ?;", (snapshot_id,))
            row = cur.fetchone()
            if not row:
                return None
            return TopologySnapshot(
                snapshot_id=row["snapshot_id"],
                name=row["name"],
                created_at=datetime.fromisoformat(row["created_at"]),
                source_captures=json.loads(row["source_captures_json"]),
                source_configs=json.loads(row["source_configs_json"]),
                identity_policy_version=row["identity_policy_version"],
                graph_algorithm_version=row["graph_algorithm_version"],
                node_count=row["node_count"],
                edge_count=row["edge_count"],
                unresolved_conflicts=json.loads(row["unresolved_conflicts_json"]),
                schema_version=row["schema_version"],
                metadata=json.loads(row["metadata_json"]),
            )

    def list_snapshots(self) -> list[TopologySnapshot]:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM topology_snapshots ORDER BY created_at DESC;")
            return [
                TopologySnapshot(
                    snapshot_id=row["snapshot_id"],
                    name=row["name"],
                    created_at=datetime.fromisoformat(row["created_at"]),
                    source_captures=json.loads(row["source_captures_json"]),
                    source_configs=json.loads(row["source_configs_json"]),
                    identity_policy_version=row["identity_policy_version"],
                    graph_algorithm_version=row["graph_algorithm_version"],
                    node_count=row["node_count"],
                    edge_count=row["edge_count"],
                    unresolved_conflicts=json.loads(row["unresolved_conflicts_json"]),
                    schema_version=row["schema_version"],
                    metadata=json.loads(row["metadata_json"]),
                )
                for row in cur.fetchall()
            ]

    def get_snapshot_graph(self, snapshot_id: str) -> TopologyGraph | None:
        snapshot = self.get_snapshot(snapshot_id)
        if not snapshot:
            return None

        with self._get_connection() as conn:
            n_cur = conn.execute("SELECT * FROM snapshot_nodes WHERE snapshot_id = ?;", (snapshot_id,))
            nodes = [
                TopologyNode(
                    node_id=r["node_id"],
                    node_type=r["node_type"],
                    label=r["label"],
                    asset_id=r["asset_id"],
                    segment_id=r["segment_id"],
                    properties=json.loads(r["properties_json"]),
                )
                for r in n_cur.fetchall()
            ]

            e_cur = conn.execute("SELECT * FROM snapshot_edges WHERE snapshot_id = ?;", (snapshot_id,))
            edges = [
                TopologyEdge(
                    edge_id=r["edge_id"],
                    source_node_id=r["source_node_id"],
                    target_node_id=r["target_node_id"],
                    edge_type=r["edge_type"],
                    evidence_class=r["evidence_class"],
                    primary_protocol=r["primary_protocol"],
                    packet_count=r["packet_count"],
                    byte_count=r["byte_count"],
                    confidence=r["confidence"],
                    evidence_ids=json.loads(r["evidence_ids_json"]),
                    properties=json.loads(r["properties_json"]),
                )
                for r in e_cur.fetchall()
            ]

            return TopologyGraph(
                graph_id=snapshot_id,
                nodes=nodes,
                edges=edges,
                node_count=len(nodes),
                edge_count=len(edges),
                generated_at=snapshot.created_at,
                metadata=snapshot.metadata,
            )

    # --- Configuration Imports ---

    def save_config_import(self, result: ConfigImportResult):
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO imported_configurations (
                    import_id, format, source_name, status, items_imported,
                    errors_json, created_at, evidence_ids_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(import_id) DO UPDATE SET
                    status=excluded.status,
                    items_imported=excluded.items_imported,
                    errors_json=excluded.errors_json;
                """,
                (
                    result.import_id,
                    result.format,
                    result.source_name,
                    result.status,
                    result.items_imported,
                    json.dumps(result.errors),
                    result.created_at.isoformat(),
                    json.dumps(result.evidence_ids),
                ),
            )
            conn.commit()

    def list_config_imports(self) -> list[ConfigImportResult]:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM imported_configurations ORDER BY created_at DESC;")
            return [
                ConfigImportResult(
                    import_id=r["import_id"],
                    format=r["format"],
                    source_name=r["source_name"],
                    status=r["status"],
                    items_imported=r["items_imported"],
                    errors=json.loads(r["errors_json"]),
                    created_at=datetime.fromisoformat(r["created_at"]),
                    evidence_ids=json.loads(r["evidence_ids_json"]),
                )
                for r in cur.fetchall()
            ]

    # --- Phase 03: Executable Network Models & Simulation ---

    def save_network_model(self, model: NetworkModel) -> None:
        with self._get_connection() as conn:
            if model.source_snapshot_id:
                cur = conn.execute("SELECT 1 FROM topology_snapshots WHERE snapshot_id = ?;", (model.source_snapshot_id,))
                if not cur.fetchone():
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO topology_snapshots (
                            snapshot_id, name, created_at, source_captures_json, source_configs_json,
                            identity_policy_version, graph_algorithm_version, node_count, edge_count,
                            unresolved_conflicts_json, schema_version, metadata_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """,
                        (
                            model.source_snapshot_id,
                            f"Snapshot for {model.name}",
                            model.created_at_iso,
                            "[]",
                            "[]",
                            "1.0",
                            "1.0",
                            len(model.nodes),
                            0,
                            "[]",
                            "1.0",
                            "{}",
                        ),
                    )
            conn.execute(
                """
                INSERT INTO network_models (
                    model_id, name, source_snapshot_id, source_snapshot_fingerprint,
                    schema_version, model_version, fingerprint, created_at,
                    is_counterfactual, parent_model_id, model_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(model_id) DO UPDATE SET
                    name=excluded.name,
                    fingerprint=excluded.fingerprint,
                    model_json=excluded.model_json;
                """,
                (
                    model.model_id,
                    model.name,
                    model.source_snapshot_id,
                    model.source_snapshot_fingerprint,
                    model.schema_version,
                    model.model_version,
                    model.fingerprint,
                    model.created_at_iso,
                    1 if model.is_counterfactual else 0,
                    model.parent_model_id,
                    model.model_dump_json(),
                ),
            )
            conn.commit()

    def get_network_model(self, model_id: str) -> NetworkModel | None:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT model_json FROM network_models WHERE model_id = ?;", (model_id,))
            row = cur.fetchone()
            if not row:
                return None
            return NetworkModel.model_validate_json(row["model_json"])

    def list_network_models(self) -> list[NetworkModel]:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT model_json FROM network_models ORDER BY created_at DESC;")
            return [NetworkModel.model_validate_json(r["model_json"]) for r in cur.fetchall()]

    def save_scenario(self, scenario: SimulationScenario) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO simulation_scenarios (
                    scenario_id, name, description, base_model_id, created_at, scenario_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(scenario_id) DO UPDATE SET
                    name=excluded.name,
                    description=excluded.description,
                    scenario_json=excluded.scenario_json;
                """,
                (
                    scenario.scenario_id,
                    scenario.name,
                    scenario.description,
                    scenario.base_model_id,
                    scenario.created_at_iso,
                    scenario.model_dump_json(),
                ),
            )
            conn.commit()

    def get_scenario(self, scenario_id: str) -> SimulationScenario | None:
        with self._get_connection() as conn:
            cur = conn.execute(
                "SELECT scenario_json FROM simulation_scenarios WHERE scenario_id = ?;",
                (scenario_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return SimulationScenario.model_validate_json(row["scenario_json"])

    def list_scenarios(self, base_model_id: str | None = None) -> list[SimulationScenario]:
        with self._get_connection() as conn:
            if base_model_id:
                cur = conn.execute(
                    "SELECT scenario_json FROM simulation_scenarios WHERE base_model_id = ? ORDER BY created_at DESC;",
                    (base_model_id,),
                )
            else:
                cur = conn.execute("SELECT scenario_json FROM simulation_scenarios ORDER BY created_at DESC;")
            return [SimulationScenario.model_validate_json(r["scenario_json"]) for r in cur.fetchall()]

    def save_counterfactual_result(self, result: CounterfactualResult) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO counterfactual_results (
                    run_id, scenario_id, base_model_id, baseline_fingerprint,
                    counterfactual_model_id, counterfactual_fingerprint,
                    applied_actions_count, newly_reachable_count, newly_blocked_count,
                    invariant_regressions_count, executed_at, result_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    result_json=excluded.result_json;
                """,
                (
                    result.run_id,
                    result.scenario_id,
                    result.base_model_id,
                    result.baseline_fingerprint,
                    result.counterfactual_model_id,
                    result.counterfactual_fingerprint,
                    result.applied_actions_count,
                    result.newly_reachable_count,
                    result.newly_blocked_count,
                    result.invariant_regressions_count,
                    result.executed_at_iso,
                    result.model_dump_json(),
                ),
            )
            conn.commit()

    def get_counterfactual_result(self, run_id: str) -> CounterfactualResult | None:
        with self._get_connection() as conn:
            cur = conn.execute(
                "SELECT result_json FROM counterfactual_results WHERE run_id = ?;",
                (run_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return CounterfactualResult.model_validate_json(row["result_json"])

    def save_invariant(self, invariant: SecurityInvariant) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO security_invariants (
                    invariant_id, name, description, invariant_type,
                    severity, scope, version, created_at, definition_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(invariant_id) DO UPDATE SET
                    name=excluded.name,
                    description=excluded.description,
                    severity=excluded.severity,
                    scope=excluded.scope,
                    definition_json=excluded.definition_json;
                """,
                (
                    invariant.invariant_id,
                    invariant.name,
                    invariant.description,
                    invariant.invariant_type.value,
                    invariant.severity.value,
                    invariant.scope,
                    invariant.version,
                    invariant.created_at_iso,
                    invariant.model_dump_json(),
                ),
            )
            conn.commit()

    def get_invariant(self, invariant_id: str) -> SecurityInvariant | None:
        with self._get_connection() as conn:
            cur = conn.execute(
                "SELECT definition_json FROM security_invariants WHERE invariant_id = ?;",
                (invariant_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return SecurityInvariant.model_validate_json(row["definition_json"])

    def list_invariants(self) -> list[SecurityInvariant]:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT definition_json FROM security_invariants ORDER BY created_at ASC;")
            return [SecurityInvariant.model_validate_json(r["definition_json"]) for r in cur.fetchall()]

    def save_verification_run(
        self,
        run_id: str,
        model_id: str,
        scenario_id: str | None,
        results: list[VerificationResult],
    ) -> None:
        pass_count = sum(1 for r in results if r.status.value == "PASS")
        fail_count = sum(1 for r in results if r.status.value == "FAIL")
        indeterminate_count = sum(1 for r in results if r.status.value == "INDETERMINATE")

        summary = {
            "total": len(results),
            "pass": pass_count,
            "fail": fail_count,
            "indeterminate": indeterminate_count,
        }

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO verification_runs (
                    run_id, model_id, scenario_id, evaluated_at,
                    pass_count, fail_count, indeterminate_count,
                    summary_json, results_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    results_json=excluded.results_json;
                """,
                (
                    run_id,
                    model_id,
                    scenario_id,
                    datetime.now(UTC).isoformat(),
                    pass_count,
                    fail_count,
                    indeterminate_count,
                    json.dumps(summary),
                    json.dumps([r.model_dump() for r in results]),
                ),
            )
            conn.commit()

    def get_verification_run(self, run_id: str) -> list[VerificationResult] | None:
        with self._get_connection() as conn:
            cur = conn.execute(
                "SELECT results_json FROM verification_runs WHERE run_id = ?;",
                (run_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            data = json.loads(row["results_json"])
            return [VerificationResult.model_validate(item) for item in data]

    # --- Phase 04: Security Testing, Fuzzing & Regressions ---

    def save_campaign(self, campaign: TestCampaign) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO test_campaigns (
                    campaign_id, name, description, protocol_targets_json,
                    strategies_json, seed, max_cases_per_target, total_cases,
                    status, created_at, completed_at, cases_generated,
                    cases_executed, passed_count, rejected_count, failed_count,
                    findings_count, duration_ms, engine_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(campaign_id) DO UPDATE SET
                    status=excluded.status,
                    completed_at=excluded.completed_at,
                    cases_executed=excluded.cases_executed,
                    passed_count=excluded.passed_count,
                    rejected_count=excluded.rejected_count,
                    failed_count=excluded.failed_count,
                    findings_count=excluded.findings_count,
                    duration_ms=excluded.duration_ms;
                """,
                (
                    campaign.campaign_id,
                    campaign.name,
                    campaign.description,
                    json.dumps([t.value for t in campaign.protocol_targets]),
                    json.dumps([s.value for s in campaign.strategies]),
                    campaign.seed,
                    campaign.max_cases_per_target,
                    campaign.total_cases,
                    campaign.status.value,
                    campaign.created_at,
                    campaign.completed_at,
                    campaign.cases_generated,
                    campaign.cases_executed,
                    campaign.passed_count,
                    campaign.rejected_count,
                    campaign.failed_count,
                    campaign.findings_count,
                    campaign.duration_ms,
                    campaign.engine_version,
                ),
            )
            conn.commit()

    def get_campaign(self, campaign_id: str) -> TestCampaign | None:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM test_campaigns WHERE campaign_id = ?;", (campaign_id,))
            row = cur.fetchone()
            if not row:
                return None
            data = dict(row)
            data["protocol_targets"] = json.loads(data["protocol_targets_json"])
            data["strategies"] = json.loads(data["strategies_json"])
            return TestCampaign.model_validate(data)

    def list_campaigns(self) -> list[TestCampaign]:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM test_campaigns ORDER BY created_at DESC;")
            campaigns = []
            for row in cur.fetchall():
                data = dict(row)
                data["protocol_targets"] = json.loads(data["protocol_targets_json"])
                data["strategies"] = json.loads(data["strategies_json"])
                campaigns.append(TestCampaign.model_validate(data))
            return campaigns

    def update_campaign_status(self, campaign_id: str, status: str) -> None:
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE test_campaigns SET status = ? WHERE campaign_id = ?;",
                (status if isinstance(status, str) else status.value, campaign_id),
            )
            conn.commit()

    def update_campaign_summary(
        self,
        campaign_id: str,
        status: str,
        cases_executed: int,
        passed_count: int,
        rejected_count: int,
        failed_count: int,
        findings_count: int,
        duration_ms: float,
        completed_at: str,
    ) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                UPDATE test_campaigns SET
                    status = ?,
                    cases_executed = ?,
                    passed_count = ?,
                    rejected_count = ?,
                    failed_count = ?,
                    findings_count = ?,
                    duration_ms = ?,
                    completed_at = ?
                WHERE campaign_id = ?;
                """,
                (
                    status if isinstance(status, str) else status.value,
                    cases_executed,
                    passed_count,
                    rejected_count,
                    failed_count,
                    findings_count,
                    duration_ms,
                    completed_at,
                    campaign_id,
                ),
            )
            conn.commit()

    def save_test_cases(self, cases: list[TestCase]) -> None:
        with self._get_connection() as conn:
            for tc in cases:
                conn.execute(
                    """
                    INSERT INTO test_cases (
                        case_id, campaign_id, test_index, protocol_target,
                        generation_strategy, mutation_sequence_json, seed,
                        generator_version, fixture_format, fixture_path,
                        fixture_hash, expected_behavior, status, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(case_id) DO UPDATE SET
                        status=excluded.status,
                        fixture_path=excluded.fixture_path,
                        fixture_hash=excluded.fixture_hash;
                    """,
                    (
                        tc.case_id,
                        tc.campaign_id,
                        tc.test_index,
                        tc.protocol_target.value,
                        tc.generation_strategy.value,
                        json.dumps([m.value if hasattr(m, "value") else m for m in tc.mutation_sequence]),
                        tc.seed,
                        tc.generator_version,
                        tc.fixture_format,
                        tc.fixture_path,
                        tc.fixture_hash,
                        tc.expected_behavior.value,
                        tc.status.value,
                        tc.created_at,
                    ),
                )
            conn.commit()

    def get_test_case(self, case_id: str) -> TestCase | None:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM test_cases WHERE case_id = ?;", (case_id,))
            row = cur.fetchone()
            if not row:
                return None
            data = dict(row)
            data["mutation_sequence"] = json.loads(data["mutation_sequence_json"])
            return TestCase.model_validate(data)

    def list_test_cases(
        self,
        campaign_id: str | None = None,
        target: str | None = None,
        status: str | None = None,
    ) -> list[TestCase]:
        query = "SELECT * FROM test_cases WHERE 1=1"
        params: list[Any] = []
        if campaign_id:
            query += " AND campaign_id = ?"
            params.append(campaign_id)
        if target:
            query += " AND protocol_target = ?"
            params.append(target)
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY test_index ASC;"

        with self._get_connection() as conn:
            cur = conn.execute(query, tuple(params))
            cases = []
            for row in cur.fetchall():
                data = dict(row)
                data["mutation_sequence"] = json.loads(data["mutation_sequence_json"])
                cases.append(TestCase.model_validate(data))
            return cases

    def update_test_case_status(self, case_id: str, status: str) -> None:
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE test_cases SET status = ? WHERE case_id = ?;",
                (status if isinstance(status, str) else status.value, case_id),
            )
            conn.commit()

    def save_execution_result(self, result: ExecutionResult) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO execution_results (
                    result_id, case_id, exit_code, stdout, stderr,
                    execution_time_ms, parser_status, parsed_event_count,
                    schema_valid, schema_errors_json, anomalies_json,
                    sanitizer_triggered, crash_detected, passed, diagnostic,
                    executed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(result_id) DO UPDATE SET
                    passed=excluded.passed;
                """,
                (
                    result.result_id,
                    result.case_id,
                    result.exit_code,
                    result.stdout,
                    result.stderr,
                    result.execution_time_ms,
                    result.parser_status,
                    result.parsed_event_count,
                    1 if result.schema_valid else 0,
                    json.dumps(result.schema_errors),
                    json.dumps(result.anomalies_detected),
                    1 if result.sanitizer_triggered else 0,
                    1 if result.crash_detected else 0,
                    1 if result.passed else 0,
                    result.diagnostic,
                    result.executed_at,
                ),
            )
            conn.commit()

    def get_execution_result(self, case_id: str) -> ExecutionResult | None:
        with self._get_connection() as conn:
            cur = conn.execute(
                "SELECT * FROM execution_results WHERE case_id = ? ORDER BY executed_at DESC LIMIT 1;", (case_id,)
            )
            row = cur.fetchone()
            if not row:
                return None
            data = dict(row)
            data["schema_valid"] = bool(data["schema_valid"])
            data["schema_errors"] = json.loads(data["schema_errors_json"])
            data["anomalies_detected"] = json.loads(data["anomalies_json"])
            data["sanitizer_triggered"] = bool(data["sanitizer_triggered"])
            data["crash_detected"] = bool(data["crash_detected"])
            data["passed"] = bool(data["passed"])
            return ExecutionResult.model_validate(data)

    def save_finding(self, finding: Finding) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO test_findings (
                    finding_id, campaign_id, case_id, protocol_target,
                    parser_component, severity, confidence, failure_category,
                    input_hash, engine_version, reproduction_command, seed,
                    mutation_sequence_json, expected_behavior, actual_behavior,
                    diagnostic, status, regression_fixture_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(finding_id) DO UPDATE SET
                    status=excluded.status,
                    regression_fixture_id=excluded.regression_fixture_id;
                """,
                (
                    finding.finding_id,
                    finding.campaign_id,
                    finding.case_id,
                    finding.protocol_target.value,
                    finding.parser_component.value,
                    finding.severity.value,
                    finding.confidence.value,
                    finding.failure_category.value,
                    finding.input_hash,
                    finding.engine_version,
                    finding.reproduction_command,
                    finding.seed,
                    json.dumps(finding.mutation_sequence),
                    finding.expected_behavior,
                    finding.actual_behavior,
                    finding.diagnostic,
                    finding.status.value,
                    finding.regression_fixture_id,
                    finding.created_at,
                ),
            )
            conn.commit()

    def get_finding(self, finding_id: str) -> Finding | None:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM test_findings WHERE finding_id = ?;", (finding_id,))
            row = cur.fetchone()
            if not row:
                return None
            data = dict(row)
            data["mutation_sequence"] = json.loads(data["mutation_sequence_json"])
            return Finding.model_validate(data)

    def list_findings(
        self,
        campaign_id: str | None = None,
        severity: str | None = None,
        protocol: str | None = None,
        status: str | None = None,
    ) -> list[Finding]:
        query = "SELECT * FROM test_findings WHERE 1=1"
        params: list[Any] = []
        if campaign_id:
            query += " AND campaign_id = ?"
            params.append(campaign_id)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if protocol:
            query += " AND protocol_target = ?"
            params.append(protocol)
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC;"

        with self._get_connection() as conn:
            cur = conn.execute(query, tuple(params))
            findings = []
            for row in cur.fetchall():
                data = dict(row)
                data["mutation_sequence"] = json.loads(data["mutation_sequence_json"])
                findings.append(Finding.model_validate(data))
            return findings

    def update_finding_status(self, finding_id: str, status: str) -> None:
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE test_findings SET status = ? WHERE finding_id = ?;",
                (status if isinstance(status, str) else status.value, finding_id),
            )
            conn.commit()

    def update_finding_regression_id(self, finding_id: str, fixture_id: str) -> None:
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE test_findings SET regression_fixture_id = ? WHERE finding_id = ?;",
                (fixture_id, finding_id),
            )
            conn.commit()

    def save_regression_fixture(self, fixture: RegressionFixture) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO regression_fixtures (
                    fixture_id, finding_id, name, protocol_target,
                    failure_category, fixture_path, fixture_hash,
                    engine_baseline_version, expected_behavior, created_at,
                    last_run_at, last_run_passed, last_run_exit_code,
                    last_run_diagnostic
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(fixture_id) DO UPDATE SET
                    name=excluded.name,
                    last_run_at=excluded.last_run_at,
                    last_run_passed=excluded.last_run_passed,
                    last_run_exit_code=excluded.last_run_exit_code,
                    last_run_diagnostic=excluded.last_run_diagnostic;
                """,
                (
                    fixture.fixture_id,
                    fixture.finding_id,
                    fixture.name,
                    fixture.protocol_target.value,
                    fixture.failure_category.value,
                    fixture.fixture_path,
                    fixture.fixture_hash,
                    fixture.engine_baseline_version,
                    fixture.expected_behavior.value,
                    fixture.created_at,
                    fixture.last_run_at,
                    1 if fixture.last_run_passed else (0 if fixture.last_run_passed is False else None),
                    fixture.last_run_exit_code,
                    fixture.last_run_diagnostic,
                ),
            )
            conn.commit()

    def get_regression_fixture(self, fixture_id: str) -> RegressionFixture | None:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM regression_fixtures WHERE fixture_id = ?;", (fixture_id,))
            row = cur.fetchone()
            if not row:
                return None
            data = dict(row)
            if data["last_run_passed"] is not None:
                data["last_run_passed"] = bool(data["last_run_passed"])
            return RegressionFixture.model_validate(data)

    def list_regression_fixtures(self) -> list[RegressionFixture]:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM regression_fixtures ORDER BY created_at DESC;")
            fixtures = []
            for row in cur.fetchall():
                data = dict(row)
                if data["last_run_passed"] is not None:
                    data["last_run_passed"] = bool(data["last_run_passed"])
                fixtures.append(RegressionFixture.model_validate(data))
            return fixtures

    def update_regression_run_status(
        self,
        fixture_id: str,
        last_run_at: str,
        passed: bool,
        exit_code: int,
        diagnostic: str | None,
    ) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                UPDATE regression_fixtures SET
                    last_run_at = ?,
                    last_run_passed = ?,
                    last_run_exit_code = ?,
                    last_run_diagnostic = ?
                WHERE fixture_id = ?;
                """,
                (last_run_at, 1 if passed else 0, exit_code, diagnostic, fixture_id),
            )
            conn.commit()

    # --- Phase 05: Stateful Protocol Sequences & Regressions ---

    def save_sequence(self, sequence: ProtocolSequence) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO protocol_sequences (
                    sequence_id, name, description, sequence_type, seed, generator_version,
                    steps_json, expected_transitions_json, expected_flow_count,
                    expected_properties_json, mutations_json, format, fixture_path,
                    fixture_hash, is_supported, coverage_gap_notes, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(sequence_id) DO UPDATE SET
                    steps_json = excluded.steps_json,
                    fixture_path = excluded.fixture_path,
                    fixture_hash = excluded.fixture_hash;
                """,
                (
                    sequence.sequence_id,
                    sequence.name,
                    sequence.description,
                    sequence.sequence_type.value,
                    sequence.seed,
                    sequence.generator_version,
                    json.dumps([s.model_dump() for s in sequence.steps]),
                    json.dumps([t.model_dump() for t in sequence.expected_transitions]),
                    sequence.expected_flow_count,
                    json.dumps(sequence.expected_properties),
                    json.dumps([m.model_dump() for m in sequence.mutations]),
                    sequence.format,
                    sequence.fixture_path,
                    sequence.fixture_hash,
                    1 if sequence.is_supported else 0,
                    sequence.coverage_gap_notes,
                    sequence.created_at_iso,
                ),
            )
            conn.commit()

    def get_sequence(self, sequence_id: str) -> ProtocolSequence | None:
        with self._get_connection() as conn:
            cur = conn.execute(
                "SELECT * FROM protocol_sequences WHERE sequence_id = ?;",
                (sequence_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            data = dict(row)
            return ProtocolSequence(
                sequence_id=data["sequence_id"],
                name=data["name"],
                description=data["description"],
                sequence_type=SequenceType(data["sequence_type"]),
                seed=data["seed"],
                generator_version=data["generator_version"],
                steps=[SequenceStep.model_validate(s) for s in json.loads(data["steps_json"])],
                expected_transitions=[
                    ExpectedStateTransition.model_validate(t) for t in json.loads(data["expected_transitions_json"])
                ],
                expected_flow_count=data["expected_flow_count"],
                expected_properties=json.loads(data["expected_properties_json"]),
                mutations=[SequenceMutation.model_validate(m) for m in json.loads(data["mutations_json"])],
                format=data["format"],
                fixture_path=data["fixture_path"],
                fixture_hash=data["fixture_hash"],
                is_supported=bool(data["is_supported"]),
                coverage_gap_notes=data["coverage_gap_notes"],
                created_at_iso=data["created_at"],
            )

    def list_sequences(self, sequence_type: str | None = None) -> list[ProtocolSequence]:
        with self._get_connection() as conn:
            if sequence_type:
                cur = conn.execute(
                    "SELECT * FROM protocol_sequences WHERE sequence_type = ? ORDER BY created_at DESC;",
                    (sequence_type,),
                )
            else:
                cur = conn.execute("SELECT * FROM protocol_sequences ORDER BY created_at DESC;")

            sequences = []
            for row in cur.fetchall():
                data = dict(row)
                sequences.append(
                    ProtocolSequence(
                        sequence_id=data["sequence_id"],
                        name=data["name"],
                        description=data["description"],
                        sequence_type=SequenceType(data["sequence_type"]),
                        seed=data["seed"],
                        generator_version=data["generator_version"],
                        steps=[SequenceStep.model_validate(s) for s in json.loads(data["steps_json"])],
                        expected_transitions=[
                            ExpectedStateTransition.model_validate(t)
                            for t in json.loads(data["expected_transitions_json"])
                        ],
                        expected_flow_count=data["expected_flow_count"],
                        expected_properties=json.loads(data["expected_properties_json"]),
                        mutations=[SequenceMutation.model_validate(m) for m in json.loads(data["mutations_json"])],
                        format=data["format"],
                        fixture_path=data["fixture_path"],
                        fixture_hash=data["fixture_hash"],
                        is_supported=bool(data["is_supported"]),
                        coverage_gap_notes=data["coverage_gap_notes"],
                        created_at_iso=data["created_at"],
                    )
                )
            return sequences

    def save_sequence_finding(self, finding: SequenceFinding) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO sequence_findings (
                    finding_id, sequence_id, severity, category, title, description,
                    root_cause_summary, reproduction_command, fixture_path, fixture_hash,
                    minimized, minimized_sequence_id, is_regression, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(finding_id) DO UPDATE SET
                    minimized = excluded.minimized,
                    minimized_sequence_id = excluded.minimized_sequence_id,
                    is_regression = excluded.is_regression;
                """,
                (
                    finding.finding_id,
                    finding.sequence_id,
                    finding.severity.value,
                    finding.category.value,
                    finding.title,
                    finding.description,
                    finding.root_cause_summary,
                    finding.reproduction_command,
                    finding.fixture_path,
                    finding.fixture_hash,
                    1 if finding.minimized else 0,
                    finding.minimized_sequence_id,
                    1 if finding.is_regression else 0,
                    finding.created_at_iso,
                ),
            )
            conn.commit()

    def list_sequence_findings(self, sequence_id: str | None = None) -> list[SequenceFinding]:
        with self._get_connection() as conn:
            if sequence_id:
                cur = conn.execute(
                    "SELECT * FROM sequence_findings WHERE sequence_id = ? ORDER BY created_at DESC;",
                    (sequence_id,),
                )
            else:
                cur = conn.execute("SELECT * FROM sequence_findings ORDER BY created_at DESC;")

            findings = []
            for row in cur.fetchall():
                data = dict(row)
                data["minimized"] = bool(data["minimized"])
                data["is_regression"] = bool(data["is_regression"])
                data["created_at_iso"] = data.pop("created_at")
                findings.append(SequenceFinding.model_validate(data))
            return findings

    def promote_sequence_regression(self, finding_id: str, name: str) -> SequenceRegressionFixture:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM sequence_findings WHERE finding_id = ?;", (finding_id,))
            row = cur.fetchone()
            if not row:
                raise ValueError(f"Sequence finding not found: {finding_id}")

            finding_data = dict(row)
            seq_id = finding_data["sequence_id"]
            cur_seq = conn.execute("SELECT sequence_type FROM protocol_sequences WHERE sequence_id = ?;", (seq_id,))
            seq_row = cur_seq.fetchone()
            seq_type = seq_row[0] if seq_row else "TCP_HANDSHAKE_TEARDOWN"

            reg_id = f"seq-regr-{finding_id}"
            now_iso = datetime.now(UTC).isoformat()

            conn.execute(
                """
                INSERT INTO sequence_regressions (
                    regression_id, finding_id, name, sequence_type, fixture_path,
                    fixture_hash, expected_exit_code, expected_to_pass, created_at,
                    last_run_at, last_run_passed
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)
                ON CONFLICT(regression_id) DO UPDATE SET name = excluded.name;
                """,
                (
                    reg_id,
                    finding_id,
                    name,
                    seq_type,
                    finding_data["fixture_path"],
                    finding_data["fixture_hash"],
                    0,
                    1,
                    now_iso,
                ),
            )
            conn.execute("UPDATE sequence_findings SET is_regression = 1 WHERE finding_id = ?;", (finding_id,))
            conn.commit()

            return SequenceRegressionFixture(
                regression_id=reg_id,
                finding_id=finding_id,
                name=name,
                sequence_type=SequenceType(seq_type),
                fixture_path=finding_data["fixture_path"],
                fixture_hash=finding_data["fixture_hash"],
                expected_exit_code=0,
                expected_to_pass=True,
                created_at_iso=now_iso,
            )

    def list_sequence_regressions(self) -> list[SequenceRegressionFixture]:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM sequence_regressions ORDER BY created_at DESC;")
            regressions = []
            for row in cur.fetchall():
                data = dict(row)
                data["expected_to_pass"] = bool(data["expected_to_pass"])
                if data["last_run_passed"] is not None:
                    data["last_run_passed"] = bool(data["last_run_passed"])
                data["created_at_iso"] = data.pop("created_at")
                last_run_at = data.pop("last_run_at", None)
                if last_run_at:
                    data["last_run_iso"] = last_run_at
                regressions.append(SequenceRegressionFixture.model_validate(data))
            return regressions

    # --- Phase 06: Predictive World Model, Datasets, Artifacts, Predictions ---

    def save_dataset_manifest(self, manifest: DatasetManifest) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO predictive_datasets (
                    dataset_id, name, description, pipeline_version,
                    time_window_sec, total_samples, feature_count,
                    target_type, hash_sha256, created_at, manifest_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(dataset_id) DO UPDATE SET
                    name = excluded.name,
                    description = excluded.description,
                    total_samples = excluded.total_samples,
                    manifest_json = excluded.manifest_json;
                """,
                (
                    manifest.dataset_id,
                    manifest.name,
                    manifest.description,
                    manifest.pipeline_version,
                    manifest.time_window_sec,
                    manifest.total_samples,
                    manifest.feature_count,
                    str(manifest.target_type),
                    manifest.hash_sha256,
                    manifest.created_at_iso,
                    manifest.model_dump_json(),
                ),
            )
            conn.commit()

    def get_dataset_manifest(self, dataset_id: str) -> DatasetManifest | None:
        with self._get_connection() as conn:
            cur = conn.execute(
                "SELECT manifest_json FROM predictive_datasets WHERE dataset_id = ?;",
                (dataset_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return DatasetManifest.model_validate_json(row["manifest_json"])

    def list_dataset_manifests(self) -> list[DatasetManifest]:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT manifest_json FROM predictive_datasets ORDER BY created_at DESC;")
            manifests = []
            for row in cur.fetchall():
                manifests.append(DatasetManifest.model_validate_json(row["manifest_json"]))
            return manifests

    def save_model_artifact(self, artifact: ModelArtifact) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO model_artifacts (
                    model_id, name, version, target, algorithm,
                    dataset_id, artifact_path, artifact_hash_sha256,
                    created_at, artifact_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(model_id) DO UPDATE SET
                    name = excluded.name,
                    artifact_json = excluded.artifact_json;
                """,
                (
                    artifact.model_id,
                    artifact.name,
                    artifact.version,
                    str(artifact.target),
                    str(artifact.algorithm),
                    artifact.dataset_id,
                    artifact.artifact_path,
                    artifact.artifact_hash_sha256,
                    artifact.created_at_iso,
                    artifact.model_dump_json(),
                ),
            )
            conn.commit()

    def get_model_artifact(self, model_id: str) -> ModelArtifact | None:
        with self._get_connection() as conn:
            cur = conn.execute(
                "SELECT artifact_json FROM model_artifacts WHERE model_id = ?;",
                (model_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return ModelArtifact.model_validate_json(row["artifact_json"])

    def list_model_artifacts(self) -> list[ModelArtifact]:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT artifact_json FROM model_artifacts ORDER BY created_at DESC;")
            artifacts = []
            for row in cur.fetchall():
                artifacts.append(ModelArtifact.model_validate_json(row["artifact_json"]))
            return artifacts

    def save_prediction_record(self, prediction: PredictionResult) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO prediction_records (
                    prediction_id, model_id, target, predicted_value,
                    predicted_at, result_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(prediction_id) DO UPDATE SET
                    result_json = excluded.result_json;
                """,
                (
                    prediction.prediction_id,
                    prediction.model_id,
                    str(prediction.target),
                    prediction.predicted_value,
                    prediction.predicted_at_iso,
                    prediction.model_dump_json(),
                ),
            )
            conn.commit()

    def list_prediction_records(self, model_id: str | None = None) -> list[PredictionResult]:
        with self._get_connection() as conn:
            if model_id:
                cur = conn.execute(
                    "SELECT result_json FROM prediction_records WHERE model_id = ? ORDER BY predicted_at DESC;",
                    (model_id,),
                )
            else:
                cur = conn.execute("SELECT result_json FROM prediction_records ORDER BY predicted_at DESC;")
            records = []
            for row in cur.fetchall():
                records.append(PredictionResult.model_validate_json(row["result_json"]))
            return records

    # --- Benchmarking & Real-World Validation (Phase 07) ---

    def save_benchmark_run(self, run: BenchmarkRunRecord) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO benchmark_runs (
                    run_id, fixture_id, fixture_name, provenance, category,
                    fixture_sha256, git_commit, software_version, executed_at,
                    status, decoding_metrics_json, deterministic_metrics_json,
                    predictive_metrics_json, consensus_metrics_json,
                    operational_profile_json, limitations_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    status = excluded.status,
                    decoding_metrics_json = excluded.decoding_metrics_json,
                    deterministic_metrics_json = excluded.deterministic_metrics_json,
                    predictive_metrics_json = excluded.predictive_metrics_json,
                    consensus_metrics_json = excluded.consensus_metrics_json,
                    operational_profile_json = excluded.operational_profile_json,
                    limitations_json = excluded.limitations_json;
                """,
                (
                    run.run_id,
                    run.fixture_id,
                    run.fixture_name,
                    str(run.provenance.value if hasattr(run.provenance, "value") else run.provenance),
                    str(run.category.value if hasattr(run.category, "value") else run.category),
                    run.fixture_sha256,
                    run.git_commit,
                    run.software_version,
                    run.executed_at,
                    run.status,
                    run.decoding.model_dump_json(),
                    run.deterministic.model_dump_json(),
                    run.predictive.model_dump_json() if run.predictive else None,
                    run.consensus.model_dump_json() if run.consensus else None,
                    run.operational.model_dump_json(),
                    json.dumps(run.limitations),
                ),
            )
            conn.execute(
                """
                INSERT OR REPLACE INTO benchmark_metrics (metric_id, run_id, metric_name, metric_value, sample_count, created_at)
                VALUES (?, ?, ?, ?, ?, ?);
                """,
                (
                    f"{run.run_id}-throughput",
                    run.run_id,
                    "throughput_pkts_sec",
                    float(run.decoding.throughput_pkts_per_sec),
                    run.decoding.packets_decoded,
                    run.executed_at,
                ),
            )
            conn.commit()

    def get_benchmark_run(self, run_id: str) -> BenchmarkRunRecord | None:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM benchmark_runs WHERE run_id = ?;", (run_id,))
            row = cur.fetchone()
            if not row:
                return None
            return self._row_to_benchmark_run(row)

    def list_benchmark_runs(self, limit: int = 50) -> list[BenchmarkRunRecord]:
        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM benchmark_runs ORDER BY executed_at DESC LIMIT ?;", (limit,))
            return [self._row_to_benchmark_run(row) for row in cur.fetchall()]

    def _row_to_benchmark_run(self, row: sqlite3.Row) -> BenchmarkRunRecord:
        from network_twin.benchmarking.models import (
            BenchmarkCategory,
            BenchmarkProvenance,
            ConsensusStageMetrics,
            DecodingStageMetrics,
            DeterministicStageMetrics,
            OperationalProfile,
            PredictiveStageMetrics,
        )

        decoding = DecodingStageMetrics.model_validate_json(row["decoding_metrics_json"])
        deterministic = DeterministicStageMetrics.model_validate_json(row["deterministic_metrics_json"])
        predictive = (
            PredictiveStageMetrics.model_validate_json(row["predictive_metrics_json"])
            if row["predictive_metrics_json"]
            else None
        )
        consensus = (
            ConsensusStageMetrics.model_validate_json(row["consensus_metrics_json"])
            if row["consensus_metrics_json"]
            else None
        )
        operational = OperationalProfile.model_validate_json(row["operational_profile_json"])
        limitations = json.loads(row["limitations_json"]) if row["limitations_json"] else []

        return BenchmarkRunRecord(
            run_id=row["run_id"],
            fixture_id=row["fixture_id"],
            fixture_name=row["fixture_name"],
            provenance=BenchmarkProvenance(row["provenance"]),
            category=BenchmarkCategory(row["category"]),
            fixture_sha256=row["fixture_sha256"],
            git_commit=row["git_commit"],
            software_version=row["software_version"],
            executed_at=row["executed_at"],
            status=row["status"],
            decoding=decoding,
            deterministic=deterministic,
            predictive=predictive,
            consensus=consensus,
            operational=operational,
            limitations=limitations,
        )

    def get_benchmark_summary(self) -> BenchmarkSummaryResponse:
        runs = self.list_benchmark_runs(limit=100)
        total_runs = len(runs)
        if total_runs == 0:
            return BenchmarkSummaryResponse(
                total_runs=0,
                verified_fixtures_count=0,
                average_throughput_pkts_sec=0.0,
                deterministic_accuracy_pct=100.0,
                models_beating_baseline_pct=0.0,
                runs=[],
            )

        unique_fixtures = {r.fixture_id for r in runs}
        avg_throughput = sum(r.decoding.throughput_pkts_per_sec for r in runs) / total_runs
        deterministic_correct = sum(
            1 for r in runs if r.deterministic.forwarding_matches_expected and r.deterministic.invariant_matches_expected
        )
        accuracy_pct = (deterministic_correct / total_runs) * 100.0

        runs_with_predictive = [r for r in runs if r.predictive and r.predictive.comparison_status != "INSUFFICIENT_DATA"]
        if runs_with_predictive:
            beating = sum(1 for r in runs_with_predictive if r.predictive.comparison_status == "BEATS_BASELINE")
            beating_pct = (beating / len(runs_with_predictive)) * 100.0
        else:
            beating_pct = 0.0

        return BenchmarkSummaryResponse(
            total_runs=total_runs,
            verified_fixtures_count=len(unique_fixtures),
            average_throughput_pkts_sec=round(avg_throughput, 2),
            deterministic_accuracy_pct=round(accuracy_pct, 2),
            models_beating_baseline_pct=round(beating_pct, 2),
            runs=runs,
        )

    # --- Phase 10: Incident Investigations ---

    def save_investigation(self, case: InvestigationCase):
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO investigation_cases (
                    investigation_id, title, investigation_type, scope_json,
                    status, sufficiency, created_at_iso, updated_at_iso,
                    evidence_graph_json, candidate_explanations_json,
                    primary_root_cause_id, counterfactual_comparisons_json,
                    unresolved_questions_json, explicit_limitations_json,
                    reproduction_steps_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(investigation_id) DO UPDATE SET
                    title=excluded.title,
                    investigation_type=excluded.investigation_type,
                    scope_json=excluded.scope_json,
                    status=excluded.status,
                    sufficiency=excluded.sufficiency,
                    updated_at_iso=excluded.updated_at_iso,
                    evidence_graph_json=excluded.evidence_graph_json,
                    candidate_explanations_json=excluded.candidate_explanations_json,
                    primary_root_cause_id=excluded.primary_root_cause_id,
                    counterfactual_comparisons_json=excluded.counterfactual_comparisons_json,
                    unresolved_questions_json=excluded.unresolved_questions_json,
                    explicit_limitations_json=excluded.explicit_limitations_json,
                    reproduction_steps_json=excluded.reproduction_steps_json;
                """,
                (
                    case.investigation_id,
                    case.title,
                    case.investigation_type.value,
                    json.dumps(case.scope.model_dump()),
                    case.status,
                    case.sufficiency.value,
                    case.created_at_iso,
                    case.updated_at_iso,
                    json.dumps(case.evidence_graph.model_dump()),
                    json.dumps([c.model_dump() for c in case.candidate_explanations]),
                    case.primary_root_cause_id,
                    json.dumps([c.model_dump() for c in case.counterfactual_comparisons]),
                    json.dumps(case.unresolved_questions),
                    json.dumps(case.explicit_limitations),
                    json.dumps(case.reproduction_steps),
                ),
            )
            conn.commit()

    def get_investigation(self, investigation_id: str) -> InvestigationCase | None:
        with self._get_connection() as conn:
            cur = conn.execute(
                "SELECT * FROM investigation_cases WHERE investigation_id = ?;",
                (investigation_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return InvestigationCase(
                investigation_id=row["investigation_id"],
                title=row["title"],
                investigation_type=row["investigation_type"],
                scope=json.loads(row["scope_json"]),
                status=row["status"],
                sufficiency=row["sufficiency"],
                created_at_iso=row["created_at_iso"],
                updated_at_iso=row["updated_at_iso"],
                evidence_graph=json.loads(row["evidence_graph_json"]),
                candidate_explanations=json.loads(row["candidate_explanations_json"]),
                primary_root_cause_id=row["primary_root_cause_id"],
                counterfactual_comparisons=json.loads(row["counterfactual_comparisons_json"]),
                unresolved_questions=json.loads(row["unresolved_questions_json"]),
                explicit_limitations=json.loads(row["explicit_limitations_json"]),
                reproduction_steps=json.loads(row["reproduction_steps_json"]),
            )

    def list_investigations(self) -> list[InvestigationCase]:
        with self._get_connection() as conn:
            cur = conn.execute(
                "SELECT * FROM investigation_cases ORDER BY created_at_iso DESC;"
            )
            rows = cur.fetchall()
            return [
                InvestigationCase(
                    investigation_id=row["investigation_id"],
                    title=row["title"],
                    investigation_type=row["investigation_type"],
                    scope=json.loads(row["scope_json"]),
                    status=row["status"],
                    sufficiency=row["sufficiency"],
                    created_at_iso=row["created_at_iso"],
                    updated_at_iso=row["updated_at_iso"],
                    evidence_graph=json.loads(row["evidence_graph_json"]),
                    candidate_explanations=json.loads(row["candidate_explanations_json"]),
                    primary_root_cause_id=row["primary_root_cause_id"],
                    counterfactual_comparisons=json.loads(row["counterfactual_comparisons_json"]),
                    unresolved_questions=json.loads(row["unresolved_questions_json"]),
                    explicit_limitations=json.loads(row["explicit_limitations_json"]),
                    reproduction_steps=json.loads(row["reproduction_steps_json"]),
                )
                for row in rows
            ]

    def delete_investigation(self, investigation_id: str) -> bool:
        with self._get_connection() as conn:
            cur = conn.execute(
                "DELETE FROM investigation_cases WHERE investigation_id = ?;",
                (investigation_id,),
            )
            conn.commit()
            return cur.rowcount > 0


metadata_store = MetadataStore()
