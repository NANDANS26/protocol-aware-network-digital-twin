"""Protocol Analysis Service orchestrating the C++20 engine binary."""

import json
import logging
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from network_twin.config import AppSettings, settings
from network_twin.models.analysis import (
    AnalysisJob,
    AnalysisSummaryModel,
    EventListResponse,
    FlowListResponse,
)

logger = logging.getLogger(__name__)

VALID_PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4",  # Classic microsecond native
    b"\xd4\xc3\xb2\xa1",  # Classic microsecond swapped
    b"\xa1\xb2\x3c\x4d",  # Classic nanosecond native
    b"\x4d\x3c\xb2\xa1",  # Classic nanosecond swapped
    b"\x0a\x0d\x0d\x0a",  # PCAPNG Section Header Block
}


class AnalysisService:
    """Coordinates packet capture uploads, verification, and C++ engine execution."""

    def __init__(self, config: AppSettings = settings):
        self.config = config
        self._jobs: dict[str, AnalysisJob] = {}
        self._ensure_directories()

    def _ensure_directories(self):
        data_path = Path(self.config.data_dir)
        (data_path / "uploads").mkdir(parents=True, exist_ok=True)
        (data_path / "results").mkdir(parents=True, exist_ok=True)

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
        """Validates that file content begins with a recognized PCAP or PCAPNG magic header."""
        if len(content) < 4:
            return False
        magic = content[:4]
        return magic in VALID_PCAP_MAGICS

    def analyze_capture(self, filename: str, content: bytes) -> AnalysisJob:
        """Saves capture file and executes the C++ protocol analysis engine."""
        if not self.validate_capture_bytes(content):
            raise ValueError(
                "Invalid capture file: Magic bytes do not match valid PCAP or PCAPNG header."
            )

        binary_path = self.find_engine_binary()
        if not binary_path:
            raise RuntimeError(
                "C++ Protocol Analysis Engine binary not found. Please compile the engine before running analysis."
            )

        job_id = str(uuid.uuid4())
        created_at = datetime.now(UTC)

        upload_path = Path(self.config.data_dir) / "uploads" / f"{job_id}_{filename}"
        events_path = Path(self.config.data_dir) / "results" / f"{job_id}.events.jsonl"
        summary_path = Path(self.config.data_dir) / "results" / f"{job_id}.summary.json"

        # Write uploaded bytes to disk
        with open(upload_path, "wb") as f:
            f.write(content)

        job = AnalysisJob(
            job_id=job_id,
            filename=filename,
            file_size_bytes=len(content),
            status="processing",
            created_at=created_at,
        )
        self._jobs[job_id] = job

        # Execute C++ engine binary safely via subprocess (no shell=True)
        cmd = [
            str(binary_path),
            "--pcap", str(upload_path),
            "--out", str(events_path),
            "--summary", str(summary_path),
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
            job.status = "completed"
            job.completed_at = datetime.now(UTC)
            job.summary = summary
            return job

        except subprocess.CalledProcessError as e:
            job.status = "failed"
            job.completed_at = datetime.now(UTC)
            job.error_message = f"Engine process failed with code {e.returncode}: {e.stderr}"
            logger.error("Engine execution failed: %s", job.error_message)
            raise RuntimeError(job.error_message) from e
        except subprocess.TimeoutExpired as e:
            job.status = "failed"
            job.completed_at = datetime.now(UTC)
            job.error_message = "Engine execution timed out after 120 seconds."
            logger.error(job.error_message)
            raise RuntimeError(job.error_message) from e

    def get_job(self, job_id: str) -> AnalysisJob | None:
        return self._jobs.get(job_id)

    def list_jobs(self) -> list[AnalysisJob]:
        return list(self._jobs.values())

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
