"""Protocol Analysis Service orchestrating C++ engine execution and intelligence ingestion."""

import hashlib
import json
import logging
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from network_twin.config import AppSettings, settings
from network_twin.intelligence.dns_correlator import DnsCorrelator
from network_twin.intelligence.identity_resolver import IdentityResolver
from network_twin.intelligence.segment_inferrer import SegmentInferrer
from network_twin.models.analysis import (
    AnalysisJob,
    AnalysisSummaryModel,
    EventListResponse,
    FlowListResponse,
)
from network_twin.models.intelligence import (
    CommunicationRelationship,
    EvidenceRecord,
    EvidenceType,
    NetworkService,
)
from network_twin.storage.analytics_store import AnalyticsStore
from network_twin.storage.metadata_store import MetadataStore
from network_twin.topology.graph_builder import GraphBuilder
from network_twin.topology.snapshot_manager import SnapshotManager

logger = logging.getLogger(__name__)

VALID_PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4",  # Classic microsecond native
    b"\xd4\xc3\xb2\xa1",  # Classic microsecond swapped
    b"\xa1\xb2\x3c\x4d",  # Classic nanosecond native
    b"\x4d\x3c\xb2\xa1",  # Classic nanosecond swapped
    b"\x0a\x0d\x0d\x0a",  # PCAPNG Section Header Block
}


class AnalysisService:
    """Coordinates packet capture uploads, verification, C++ engine execution, and intelligence ingestion."""

    def __init__(self, config: AppSettings = settings):
        self.config = config
        self.metadata_store = MetadataStore(config)
        self.analytics_store = AnalyticsStore(config)
        self.identity_resolver = IdentityResolver()
        self.dns_correlator = DnsCorrelator()
        self.segment_inferrer = SegmentInferrer()
        self.snapshot_manager = SnapshotManager(self.metadata_store, GraphBuilder(self.metadata_store))
        self._ensure_directories()

    def _ensure_directories(self):
        data_path = Path(self.config.data_dir)
        (data_path / "uploads").mkdir(parents=True, exist_ok=True)
        (data_path / "results").mkdir(parents=True, exist_ok=True)
        (data_path / "analytics").mkdir(parents=True, exist_ok=True)

    def find_engine_binary(self) -> Path | None:
        """Finds the compiled C++ protocol_engine binary."""
        if self.config.engine_binary_path and Path(self.config.engine_binary_path).is_file():
            return Path(self.config.engine_binary_path)

        project_root = Path(__file__).resolve().parents[5]
        candidates = [
            project_root / "build" / "engine" / "Release" / "protocol_engine.exe",
            project_root / "build" / "engine" / "protocol_engine.exe",
            project_root / "build" / "engine" / "Release" / "protocol_engine",
            project_root / "build" / "engine" / "protocol_engine",
        ]
        for candidate in candidates:
            if candidate.is_file():
                return candidate
        return None

    def is_engine_available(self) -> bool:
        return self.find_engine_binary() is not None

    def validate_capture_bytes(self, content: bytes) -> bool:
        if len(content) < 4:
            return False
        magic = content[:4]
        return magic in VALID_PCAP_MAGICS

    def analyze_capture(self, filename: str, content: bytes) -> AnalysisJob:
        """Saves capture file, executes C++ engine, persists metadata & Parquet, and extracts intelligence."""
        if Path(filename).name != filename or ".." in filename:
            raise ValueError("Invalid filename: Path traversal detected.")

        if not self.validate_capture_bytes(content):
            raise ValueError("Invalid capture file: Magic bytes do not match valid PCAP or PCAPNG header.")

        binary_path = self.find_engine_binary()
        if not binary_path:
            raise RuntimeError(
                "C++ Protocol Analysis Engine binary not found. Please compile the engine before running analysis."
            )

        job_id = str(uuid.uuid4())
        created_at = datetime.now(UTC)
        content_sha256 = hashlib.sha256(content).hexdigest()
        is_pcapng = content[:4] == b"\x0a\x0d\x0d\x0a"
        fmt_name = "PCAPNG" if is_pcapng else "PCAP"

        safe_filename = Path(filename).name
        uploads_dir = (Path(self.config.data_dir) / "uploads").resolve()
        upload_path = (uploads_dir / f"{job_id}_{safe_filename}").resolve()
        if not upload_path.is_relative_to(uploads_dir):
            raise ValueError("Invalid filename: Path traversal detected.")
        events_path = Path(self.config.data_dir) / "results" / f"{job_id}.events.jsonl"
        summary_path = Path(self.config.data_dir) / "results" / f"{job_id}.summary.json"

        # Write uploaded bytes to disk
        with open(upload_path, "wb") as f:
            f.write(content)

        # Register capture in persistent metadata catalog
        cap = self.metadata_store.register_capture(
            capture_id=job_id,
            filename=filename,
            content_sha256=content_sha256,
            file_size_bytes=len(content),
            format_type=fmt_name,
            storage_path=str(upload_path),
        )
        actual_capture_id = cap.get("capture_id", job_id)

        # Register analysis job
        self.metadata_store.save_analysis_job(
            job_id=job_id,
            capture_id=actual_capture_id,
            filename=filename,
            file_size_bytes=len(content),
            status="processing",
            created_at=created_at.isoformat(),
        )

        job = AnalysisJob(
            job_id=job_id,
            filename=filename,
            file_size_bytes=len(content),
            status="processing",
            created_at=created_at,
        )

        # Execute C++ engine binary safely via subprocess (no shell=True)
        cmd = [
            str(binary_path),
            "--pcap",
            str(upload_path),
            "--out",
            str(events_path),
            "--summary",
            str(summary_path),
            "--benchmark",
        ]

        logger.info("Executing engine: %s", " ".join(cmd))
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                check=True,
            )
            logger.info("Engine completed successfully: %s", proc.stdout[-200:] if proc.stdout else "")

            # Load summary report
            if not summary_path.is_file():
                raise RuntimeError("Engine completed but no summary file was produced.")

            with open(summary_path, encoding="utf-8") as f:
                summary_data = json.load(f)

            summary = AnalysisSummaryModel.model_validate(summary_data)
            completed_at = datetime.now(UTC)

            # 1. Update job status in metadata store
            self.metadata_store.save_analysis_job(
                job_id=job_id,
                capture_id=actual_capture_id,
                filename=filename,
                file_size_bytes=len(content),
                status="completed",
                created_at=created_at.isoformat(),
                completed_at=completed_at.isoformat(),
                summary_dict=summary_data,
            )

            job.status = "completed"
            job.completed_at = completed_at
            job.summary = summary

            # 2. Ingest events into Parquet via DuckDB
            try:
                self.analytics_store.convert_jsonl_to_parquet(job_id, events_path)
            except Exception as e:
                logger.warning("Failed to convert events to Parquet for job %s: %s", job_id, e)

            # 3. Reconstruct network intelligence from flows and events
            self._correlate_intelligence(job_id, summary, events_path, created_at)

            # 4. Generate a versioned topology snapshot
            try:
                self.snapshot_manager.create_snapshot(
                    name=f"Capture Ingestion: {filename}",
                    source_captures=[actual_capture_id],
                )
            except Exception as e:
                logger.warning("Failed to create snapshot after capture analysis: %s", e)

            return job

        except subprocess.CalledProcessError as e:
            completed_at = datetime.now(UTC)
            job.status = "failed"
            job.completed_at = completed_at
            job.error_message = f"Engine process failed with code {e.returncode}: {e.stderr}"
            logger.error("Engine execution failed: %s", job.error_message)
            self.metadata_store.save_analysis_job(
                job_id=job_id,
                capture_id=actual_capture_id,
                filename=filename,
                file_size_bytes=len(content),
                status="failed",
                created_at=created_at.isoformat(),
                completed_at=completed_at.isoformat(),
                error_message=job.error_message,
            )
            raise RuntimeError(job.error_message) from e
        except subprocess.TimeoutExpired as e:
            completed_at = datetime.now(UTC)
            job.status = "failed"
            job.completed_at = completed_at
            job.error_message = "Engine execution timed out after 120 seconds."
            logger.error(job.error_message)
            self.metadata_store.save_analysis_job(
                job_id=job_id,
                capture_id=actual_capture_id,
                filename=filename,
                file_size_bytes=len(content),
                status="failed",
                created_at=created_at.isoformat(),
                completed_at=completed_at.isoformat(),
                error_message=job.error_message,
            )
            raise RuntimeError(job.error_message) from e

    def _correlate_intelligence(
        self,
        job_id: str,
        summary: AnalysisSummaryModel,
        events_path: Path,
        timestamp: datetime,
    ):
        """Extracts assets, segments, services, and relationships from engine output."""
        all_evidence: list[EvidenceRecord] = []

        # Process individual flows from summary
        for flow in summary.flows:
            # Resolve src and dst assets
            src_asset, src_evs = self.identity_resolver.resolve_asset_from_observation(
                ip_str=flow.src_ip,
                mac_str=None,
                observed_time=timestamp,
                source_id=job_id,
                protocol=flow.ip_proto,
                service=flow.app_protocol if flow.app_protocol != "UNKNOWN" else None,
            )
            dst_asset, dst_evs = self.identity_resolver.resolve_asset_from_observation(
                ip_str=flow.dst_ip,
                mac_str=None,
                observed_time=timestamp,
                source_id=job_id,
                protocol=flow.ip_proto,
                service=flow.app_protocol if flow.app_protocol != "UNKNOWN" else None,
            )
            all_evidence.extend(src_evs)
            all_evidence.extend(dst_evs)

            # Persist assets first to satisfy foreign key constraints
            self.metadata_store.upsert_asset(src_asset)
            self.metadata_store.upsert_asset(dst_asset)

            # Inferred segments
            src_seg = self.segment_inferrer.observe_ip(flow.src_ip, timestamp, job_id)
            dst_seg = self.segment_inferrer.observe_ip(flow.dst_ip, timestamp, job_id)
            self.metadata_store.upsert_segment(src_seg)
            self.metadata_store.upsert_segment(dst_seg)

            # Upsert services if server port detected
            if flow.dst_port:
                svc_id = f"svc-{flow.dst_ip}-{flow.dst_port}-{flow.ip_proto}"
                svc = NetworkService(
                    service_id=svc_id,
                    asset_id=dst_asset.asset_id,
                    server_ip=flow.dst_ip,
                    transport_protocol=flow.ip_proto,
                    port=flow.dst_port,
                    app_protocol=flow.app_protocol,
                    classification_confidence=0.9 if flow.app_protocol != "UNKNOWN" else 0.5,
                    tls_sni=None,
                    http_server=None,
                    first_seen=timestamp,
                    last_seen=timestamp,
                )
                self.metadata_store.upsert_service(svc)

            # Communication relationship
            rel_id = f"rel-{src_asset.asset_id}-{dst_asset.asset_id}-{flow.ip_proto}-{flow.dst_port or 0}"
            rel = CommunicationRelationship(
                relationship_id=rel_id,
                src_asset_id=src_asset.asset_id,
                dst_asset_id=dst_asset.asset_id,
                transport_protocol=flow.ip_proto,
                src_port=flow.src_port,
                dst_port=flow.dst_port,
                app_protocol=flow.app_protocol,
                packet_count=flow.packets_forward + flow.packets_reverse,
                byte_count=flow.bytes_forward + flow.bytes_reverse,
                first_seen=timestamp,
                last_seen=timestamp,
                flow_ids=[flow.flow_id],
                dns_transaction_ids=[],
                evidence_type=EvidenceType.PACKET_OBSERVED,
                directionality="bidirectional",
                confidence=1.0,
            )
            self.metadata_store.upsert_relationship(rel)

        # Deep scan events for ARP, DNS, HTTP, TLS
        if events_path.is_file():
            with open(events_path, encoding="utf-8") as f:
                for line in f:
                    line_str = line.strip()
                    if not line_str:
                        continue
                    try:
                        ev = json.loads(line_str)
                        ev_type = ev.get("event_type")

                        # ARP correlation
                        if ev_type == "network.arp" or "arp" in ev:
                            arp_info = ev.get("arp", {})
                            sender_ip = arp_info.get("sender_ip")
                            sender_mac = arp_info.get("sender_mac")
                            if sender_ip and sender_mac:
                                arp_asset, arp_ev = self.identity_resolver.correlate_arp_mapping(
                                    sender_ip, sender_mac, timestamp, job_id
                                )
                                if arp_asset:
                                    self.metadata_store.upsert_asset(arp_asset)
                                all_evidence.append(arp_ev)

                        # DNS correlation
                        if "dns" in ev:
                            dns_info = ev.get("dns", {})
                            qname = dns_info.get("qname")
                            tx_id = dns_info.get("transaction_id", 0)
                            answers = dns_info.get("answers", [])
                            if qname and answers:
                                dns_tx, dns_evs = self.dns_correlator.record_response(
                                    tx_id=tx_id,
                                    qname=qname,
                                    server_ip=ev.get("src_ip", "0.0.0.0"),
                                    answers=answers,
                                    timestamp=timestamp,
                                    source_id=job_id,
                                )
                                all_evidence.extend(dns_evs)
                                # Link hostname to destination asset
                                for ans_ip in answers:
                                    asset = self.metadata_store.get_asset(
                                        f"asset-{hashlib.sha256(f'ip:{ans_ip.lower()}'.encode()).hexdigest()[:16]}"
                                    )
                                    if asset and qname not in asset.hostnames:
                                        asset.hostnames.append(qname)
                                        self.metadata_store.upsert_asset(asset)

                        # TLS SNI correlation
                        if "tls" in ev:
                            tls_info = ev.get("tls", {})
                            sni = tls_info.get("sni")
                            dst_ip = ev.get("dst_ip")
                            if sni and dst_ip:
                                asset = self.metadata_store.get_asset(
                                    f"asset-{hashlib.sha256(f'ip:{dst_ip.lower()}'.encode()).hexdigest()[:16]}"
                                )
                                if asset and sni not in asset.hostnames:
                                    asset.hostnames.append(sni)
                                    self.metadata_store.upsert_asset(asset)

                    except json.JSONDecodeError:
                        continue

        if all_evidence:
            self.metadata_store.save_evidence_records(all_evidence)

    def get_job(self, job_id: str) -> AnalysisJob | None:
        row = self.metadata_store.get_analysis_job(job_id)
        if not row:
            return None
        return AnalysisJob(
            job_id=row["job_id"],
            filename=row["filename"],
            file_size_bytes=row["file_size_bytes"],
            status=row["status"],
            created_at=datetime.fromisoformat(row["created_at"]),
            completed_at=datetime.fromisoformat(row["completed_at"]) if row.get("completed_at") else None,
            error_message=row.get("error_message"),
            summary=AnalysisSummaryModel.model_validate(row["summary"]) if row.get("summary") else None,
        )

    def list_jobs(self) -> list[AnalysisJob]:
        rows = self.metadata_store.list_analysis_jobs()
        return [
            AnalysisJob(
                job_id=row["job_id"],
                filename=row["filename"],
                file_size_bytes=row["file_size_bytes"],
                status=row["status"],
                created_at=datetime.fromisoformat(row["created_at"]),
                completed_at=datetime.fromisoformat(row["completed_at"]) if row.get("completed_at") else None,
                error_message=row.get("error_message"),
                summary=AnalysisSummaryModel.model_validate(row["summary"]) if row.get("summary") else None,
            )
            for row in rows
        ]

    def get_job_flows(
        self,
        job_id: str,
        ip_proto: str | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> FlowListResponse:
        job = self.get_job(job_id)
        if not job or not job.summary:
            raise KeyError(f"Job {job_id} not found or has no analysis summary.")

        all_flows = job.summary.flows
        if ip_proto:
            all_flows = [f for f in all_flows if f.ip_proto.upper() == ip_proto.upper()]

        total = len(all_flows)
        sliced = all_flows[offset : offset + limit]

        return FlowListResponse(
            job_id=job_id,
            total_flows=total,
            offset=offset,
            limit=limit,
            flows=sliced,
        )

    def get_job_events(
        self,
        job_id: str,
        offset: int = 0,
        limit: int = 100,
        status: str | None = None,
    ) -> EventListResponse:
        events_path = Path(self.config.data_dir) / "results" / f"{job_id}.events.jsonl"
        if not events_path.is_file():
            raise KeyError(f"Events file for job {job_id} not found.")

        matched_events: list[dict[str, Any]] = []
        total_matched = 0

        with open(events_path, encoding="utf-8") as f:
            for line in f:
                line_str = line.strip()
                if not line_str:
                    continue
                try:
                    ev = json.loads(line_str)
                    if status and ev.get("parser_status", {}).get("status") != status:
                        continue
                    if total_matched >= offset and len(matched_events) < limit:
                        matched_events.append(ev)
                    total_matched += 1
                except json.JSONDecodeError:
                    continue

        return EventListResponse(
            job_id=job_id,
            total_events=total_matched,
            offset=offset,
            limit=limit,
            events=matched_events,
        )


analysis_service = AnalysisService()
