"""Domain models for Network Intelligence, Evidence, and Topology Reconstruction."""

from datetime import datetime
from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, Field, model_validator


class IdentityStatus(StrEnum):
    """Classification of asset identity confidence and stability."""

    CONFIRMED = "CONFIRMED"  # Consistent IP + MAC or matching authoritative configuration
    PROBABLE = "PROBABLE"  # Consistent IP without local MAC observation (e.g. routed traffic)
    AMBIGUOUS = "AMBIGUOUS"  # Multiple candidate identities or overlapping ephemeral observations
    CONFLICTING = "CONFLICTING"  # Contradictory observations (e.g. conflicting MACs on same local IP)
    UNRESOLVED = "UNRESOLVED"  # Insufficient evidence to establish persistent identity


class EvidenceType(StrEnum):
    """Categorization of evidence supporting network intelligence assertions."""

    PACKET_OBSERVED = "PACKET_OBSERVED"
    DNS_OBSERVED = "DNS_OBSERVED"
    IMPORTED_CONFIGURATION = "IMPORTED_CONFIGURATION"
    IMPORTED_ROUTING = "IMPORTED_ROUTING"
    IMPORTED_NEIGHBOR = "IMPORTED_NEIGHBOR"
    DERIVED_RELATIONSHIP = "DERIVED_RELATIONSHIP"
    ADMINISTRATIVE_ANNOTATION = "ADMINISTRATIVE_ANNOTATION"


class TopologyNodeType(StrEnum):
    """Types of entities represented in the network topology graph."""

    ASSET = "ASSET"
    SUBNET = "SUBNET"
    SERVICE = "SERVICE"
    INTERFACE = "INTERFACE"
    ROUTER = "ROUTER"
    DNS_RESOLVER = "DNS_RESOLVER"


class TopologyEdgeType(StrEnum):
    """Types of relationships represented in the network topology graph."""

    OBSERVED_COMMUNICATION = "OBSERVED_COMMUNICATION"
    INTERFACE_MEMBERSHIP = "INTERFACE_MEMBERSHIP"
    SUBNET_ATTACHMENT = "SUBNET_ATTACHMENT"
    CONFIGURED_ROUTE = "CONFIGURED_ROUTE"
    DNS_ASSOCIATION = "DNS_ASSOCIATION"
    SERVICE_DEPENDENCY = "SERVICE_DEPENDENCY"
    INFERRED_RELATIONSHIP = "INFERRED_RELATIONSHIP"
    ADMINISTRATIVE_ANNOTATION = "ADMINISTRATIVE_ANNOTATION"


class EvidenceClassification(StrEnum):
    """High-level classification separating direct physical observations from inferences."""

    DIRECT_OBSERVATION = "DIRECT_OBSERVATION"
    CONFIGURED = "CONFIGURED"
    INFERRED = "INFERRED"
    ANNOTATED = "ANNOTATED"


# --- Evidence Record ---


class EvidenceRecord(BaseModel):
    """An immutable, auditable record supporting an observation or intelligence claim."""

    evidence_id: str = Field(description="Unique identifier for this evidence item")
    evidence_type: EvidenceType
    source_type: str = Field(description="Source kind: 'pcap', 'pcapng', 'config_import', etc.")
    source_artifact_id: str = Field(description="Identifier of capture file or configuration import")
    observation_timestamp: datetime | None = Field(default=None, description="Timestamp observed on wire/system")
    ingestion_timestamp: datetime = Field(description="Timestamp when record was ingested")
    src_ref: str | None = Field(default=None, description="Primary source reference (IP, MAC, or asset ID)")
    dst_ref: str | None = Field(default=None, description="Primary destination reference")
    parser_status: str = Field(default="ok", description="Parser or importer status")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Evidence confidence score")
    provenance: str = Field(description="Human-readable provenance trail or file:line reference")
    details: dict[str, Any] = Field(default_factory=dict, description="Structured attributes specific to evidence")


# --- Asset Model ---


class Asset(BaseModel):
    """An observed or configured network endpoint/device."""

    asset_id: str = Field(description="Stable internal asset identifier")
    primary_ip: str = Field(description="Canonical primary IP address")
    ip_addresses: list[str] = Field(default_factory=list, description="All observed IP addresses for this asset")
    mac_addresses: list[str] = Field(default_factory=list, description="Observed Layer-2 MAC addresses")
    hostnames: list[str] = Field(default_factory=list, description="Observed DNS/TLS/HTTP hostnames")
    observed_protocols: list[str] = Field(default_factory=list, description="L3/L4/L7 protocols observed")
    observed_services: list[str] = Field(default_factory=list, description="Application services identified")
    first_seen: datetime = Field(description="First observation timestamp")
    last_seen: datetime = Field(description="Most recent observation timestamp")
    identity_status: IdentityStatus = Field(default=IdentityStatus.PROBABLE)
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    conflicts: list[str] = Field(default_factory=list, description="Any detected identity conflicts")
    conflict_reasons: list[str] = Field(default_factory=list, description="Backward-compatible alias for conflicts")
    observation_sources: list[str] = Field(
        default_factory=list, description="Captures or imports contributing evidence"
    )

    @model_validator(mode="after")
    def sync_conflicts(self) -> Self:
        if self.conflicts and not self.conflict_reasons:
            self.conflict_reasons = list(self.conflicts)
        elif self.conflict_reasons and not self.conflicts:
            self.conflicts = list(self.conflict_reasons)
        return self


# --- Network Segment ---


class NetworkSegment(BaseModel):
    """An inferred or configured IP subnet / network segment."""

    segment_id: str = Field(description="Unique segment identifier")
    cidr_prefix: str = Field(description="Subnet prefix, e.g. '192.168.1.0/24' or 'fc00::/7'")
    address_family: str = Field(description="'IPv4' or 'IPv6'")
    gateway_ip: str | None = Field(default=None, description="Observed or configured gateway IP")
    observed_host_count: int = Field(default=0, ge=0)
    configuration_source: str | None = Field(default=None, description="Name of configuration source if imported")
    confidence: float = Field(default=0.9, ge=0.0, le=1.0)
    provenance: str = Field(description="Source of subnet definition ('inferred_from_traffic', 'imported_route')")
    first_seen: datetime
    last_seen: datetime


# --- Network Service ---


class NetworkService(BaseModel):
    """An observed network application service listening on an endpoint."""

    service_id: str = Field(description="Unique service identifier")
    asset_id: str = Field(description="Asset hosting this service")
    server_ip: str = Field(description="Listening IP address")
    transport_protocol: str = Field(description="'TCP' or 'UDP'")
    port: int = Field(ge=1, le=65535)
    app_protocol: str = Field(default="UNKNOWN", description="Identified protocol: HTTP, DNS, TLS, etc.")
    classification_confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    tls_sni: str | None = Field(default=None)
    tls_alpn: list[str] = Field(default_factory=list)
    http_server: str | None = Field(default=None)
    first_seen: datetime
    last_seen: datetime


# --- Communication Relationship ---


class CommunicationRelationship(BaseModel):
    """An observed or verified bidirectional/unidirectional communication between endpoints."""

    relationship_id: str = Field(description="Unique relationship identifier")
    src_asset_id: str = Field(description="Initiator asset ID")
    dst_asset_id: str = Field(description="Responder asset ID")
    transport_protocol: str = Field(description="'TCP', 'UDP', 'ICMP', etc.")
    src_port: int | None = Field(default=None)
    dst_port: int | None = Field(default=None)
    app_protocol: str = Field(default="UNKNOWN")
    packet_count: int = Field(default=0, ge=0)
    byte_count: int = Field(default=0, ge=0)
    first_seen: datetime
    last_seen: datetime
    flow_ids: list[str] = Field(default_factory=list)
    dns_transaction_ids: list[str] = Field(default_factory=list)
    evidence_type: EvidenceType = Field(default=EvidenceType.PACKET_OBSERVED)
    directionality: str = Field(default="bidirectional", description="'bidirectional' or 'unidirectional'")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)


# --- Topology Graph Elements ---


class TopologyNode(BaseModel):
    """A node in the reconstructed network graph."""

    node_id: str = Field(description="Stable identifier for graph node")
    id: str | None = Field(default=None, description="Backward-compatible alias for node_id")
    node_type: TopologyNodeType
    label: str = Field(description="Human-readable label (e.g. IP, Hostname, Subnet CIDR)")
    asset_id: str | None = None
    segment_id: str | None = None
    properties: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def sync_id(self) -> Self:
        if not self.id:
            self.id = self.node_id
        return self


class TopologyEdge(BaseModel):
    """A directed or bidirectional edge in the network topology graph."""

    edge_id: str = Field(description="Stable edge identifier")
    id: str | None = Field(default=None, description="Backward-compatible alias for edge_id")
    source_node_id: str
    target_node_id: str
    edge_type: TopologyEdgeType
    evidence_class: EvidenceClassification
    primary_protocol: str = Field(default="IP")
    packet_count: int = Field(default=0, ge=0)
    byte_count: int = Field(default=0, ge=0)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    evidence_ids: list[str] = Field(default_factory=list, description="IDs of backing evidence records")
    properties: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def sync_id(self) -> Self:
        if not self.id:
            self.id = self.edge_id
        return self


class TopologyGraph(BaseModel):
    """Complete network topology graph representation."""

    graph_id: str
    nodes: list[TopologyNode] = Field(default_factory=list)
    edges: list[TopologyEdge] = Field(default_factory=list)
    node_count: int = 0
    edge_count: int = 0
    generated_at: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)


# --- Versioned Snapshot ---


class TopologySnapshot(BaseModel):
    """An immutable, versioned snapshot of network topology at a point in time."""

    snapshot_id: str = Field(description="Unique snapshot fingerprint / identifier")
    name: str = Field(description="Descriptive snapshot title")
    created_at: datetime
    created_at_iso: str | None = Field(default=None, description="ISO 8601 formatted creation timestamp")
    source_captures: list[str] = Field(default_factory=list, description="IDs of contributing captures")
    source_configs: list[str] = Field(default_factory=list, description="IDs of contributing configuration imports")
    capture_id: str | None = Field(default=None, description="Primary source capture ID if derived from capture")
    analysis_job_id: str | None = Field(default=None, description="Originating analysis job ID if derived from capture")
    identity_policy_version: str = Field(default="1.0.0")
    graph_algorithm_version: str = Field(default="1.0.0")
    node_count: int
    edge_count: int
    unresolved_conflicts: list[str] = Field(default_factory=list)
    schema_version: str = Field(default="1.0.0")
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def sync_created_at_iso(self) -> Self:
        if not self.created_at_iso and self.created_at:
            self.created_at_iso = self.created_at.isoformat()
        if not self.capture_id and self.metadata:
            self.capture_id = self.metadata.get("capture_id")
        if not self.analysis_job_id and self.metadata:
            self.analysis_job_id = self.metadata.get("analysis_job_id")
        return self


class SnapshotComparisonDiff(BaseModel):
    """Differential analysis between two topology snapshots."""

    base_snapshot_id: str
    target_snapshot_id: str
    added_nodes: list[TopologyNode] = Field(default_factory=list)
    removed_nodes: list[TopologyNode] = Field(default_factory=list)
    modified_nodes: list[dict[str, Any]] = Field(default_factory=list)
    added_edges: list[TopologyEdge] = Field(default_factory=list)
    removed_edges: list[TopologyEdge] = Field(default_factory=list)
    modified_edges: list[dict[str, Any]] = Field(default_factory=list)
    evidence_explanations: list[dict[str, Any]] = Field(default_factory=list)


# --- Configuration Imports ---


class ConfigImportRequest(BaseModel):
    """Request model for importing network configurations."""

    format: str = Field(description="'routing_table', 'arp_table', 'interfaces', 'inventory'")
    source_name: str = Field(description="Origin system or operator label")
    content: str = Field(description="Raw configuration content (JSON or CSV)")


class ConfigImportResult(BaseModel):
    """Result of a configuration import operation."""

    import_id: str
    format: str
    source_name: str
    status: str = Field(description="'completed', 'partial', 'failed'")
    items_imported: int = 0
    errors: list[str] = Field(default_factory=list)
    created_at: datetime
    evidence_ids: list[str] = Field(default_factory=list)
