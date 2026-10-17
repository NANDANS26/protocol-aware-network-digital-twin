"""Relational Metadata Catalog for captures, assets, evidence, and topology snapshots."""

import json
import logging
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from network_twin.config import AppSettings, settings
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

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1


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
                (job_id, capture_id, filename, file_size_bytes, status, created_at, completed_at, error_message, summary_json),
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
            observation_timestamp=datetime.fromisoformat(row["observation_timestamp"]) if row["observation_timestamp"] else None,
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


metadata_store = MetadataStore()
