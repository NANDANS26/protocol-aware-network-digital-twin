"""Pydantic models for capture upload, analysis jobs, flows, and reports."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class FlowSummaryModel(BaseModel):
    flow_id: str
    ip_proto: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    vlan_id: int | None = None
    state: str
    packets_forward: int = 0
    packets_reverse: int = 0
    bytes_forward: int = 0
    bytes_reverse: int = 0
    duration_ms: float = 0.0
    app_protocol: str = "UNKNOWN"
    info: str = ""
    retransmissions: int = 0
    out_of_order: int = 0


class AnalysisSummaryModel(BaseModel):
    capture_file: str
    total_packets: int = 0
    total_bytes: int = 0
    wire_bytes: int = 0
    duration_ms: float = 0.0
    start_time_iso: str = ""
    end_time_iso: str = ""
    packets_per_sec: float = 0.0
    throughput_mbps: float = 0.0
    total_flows: int = 0
    dns_queries: int = 0
    dns_responses: int = 0
    http_requests: int = 0
    http_responses: int = 0
    tls_handshakes: int = 0
    quic_datagrams: int = 0
    ptp_messages: int = 0
    protocol_counts: dict[str, int] = Field(default_factory=dict)
    parser_status_counts: dict[str, int] = Field(default_factory=dict)
    tcp_state_counts: dict[str, int] = Field(default_factory=dict)
    anomalies: list[str] = Field(default_factory=list)
    flows: list[FlowSummaryModel] = Field(default_factory=list)


class AnalysisJob(BaseModel):
    job_id: str
    capture_id: str | None = None
    filename: str
    file_size_bytes: int
    status: str = "completed"  # pending, processing, completed, failed
    created_at: datetime
    completed_at: datetime | None = None
    error_message: str | None = None
    summary: AnalysisSummaryModel | None = None


class JobUploadResponse(BaseModel):
    job_id: str
    capture_id: str | None = None
    filename: str
    file_size_bytes: int
    status: str
    message: str
    summary: AnalysisSummaryModel | None = None


class FlowListResponse(BaseModel):
    job_id: str
    total_flows: int
    offset: int
    limit: int
    flows: list[FlowSummaryModel]


class EventListResponse(BaseModel):
    job_id: str
    total_events: int
    offset: int
    limit: int
    events: list[dict[str, Any]]
