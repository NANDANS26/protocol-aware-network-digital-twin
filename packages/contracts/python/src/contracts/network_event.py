"""Python Pydantic models for NetworkEvent schema v1.0.0.

Guarantees type-safety, validation, and JSON serialization conforming strictly to
schemas/v1/network_event.schema.json.
"""

from __future__ import annotations

from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class ParserStatusEnum(str, Enum):
    OK = "ok"
    INCOMPLETE = "incomplete"
    MALFORMED = "malformed"
    UNSUPPORTED_PROTOCOL = "unsupported_protocol"
    CHECKSUM_ERROR = "checksum_error"
    TRUNCATED = "truncated"


class FlowDirection(str, Enum):
    FORWARD = "forward"
    REVERSE = "reverse"
    UNKNOWN = "unknown"


class TransportProtocol(str, Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    ICMPV6 = "ICMPv6"
    SCTP = "SCTP"
    OTHER = "OTHER"


class IpVersion(str, Enum):
    IPV4 = "IPv4"
    IPV6 = "IPv6"


class LinkLayer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_mac: str | None = Field(
        default=None, pattern=r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
    )
    destination_mac: str | None = Field(
        default=None, pattern=r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
    )
    ether_type: int | None = Field(default=None, ge=0, le=65535)
    vlan_id: int | None = Field(default=None, ge=0, le=4095)


class NetworkLayerFlags(BaseModel):
    model_config = ConfigDict(extra="forbid")

    df: bool | None = None
    mf: bool | None = None


class NetworkLayer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: IpVersion | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    ttl_or_hop_limit: int | None = Field(default=None, ge=0, le=255)
    identification: int | None = Field(default=None, ge=0, le=65535)
    flags: NetworkLayerFlags | None = None


class TcpFlags(BaseModel):
    model_config = ConfigDict(extra="forbid")

    syn: bool | None = None
    ack: bool | None = None
    fin: bool | None = None
    rst: bool | None = None
    psh: bool | None = None
    urg: bool | None = None
    ece: bool | None = None
    cwr: bool | None = None


class TransportLayer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    protocol: TransportProtocol | None = None
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    tcp_sequence_number: int | None = Field(default=None, ge=0, le=4294967295)
    tcp_acknowledgment_number: int | None = Field(default=None, ge=0, le=4294967295)
    tcp_flags: TcpFlags | None = None
    window_size: int | None = Field(default=None, ge=0, le=65535)


class ApplicationLayer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    protocol: str | None = None
    payload_length_bytes: int = Field(default=0, ge=0)
    protocol_metadata: dict[str, Any] = Field(default_factory=dict)
    payload_hash_sha256: str | None = Field(default=None, pattern=r"^[0-9a-fA-F]{64}$")
    sanitized_preview: str | None = Field(default=None, max_length=512)


class ParserStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: ParserStatusEnum
    diagnostic_code: str | None = None
    diagnostic_message: str | None = None
    bytes_consumed: int | None = Field(default=None, ge=0)
    bytes_remaining: int | None = Field(default=None, ge=0)


class Provenance(BaseModel):
    model_config = ConfigDict(extra="forbid")

    packet_index: int = Field(ge=0)
    wire_length_bytes: int = Field(ge=0)
    capture_length_bytes: int = Field(ge=0)
    capture_interface: str | None = None
    capture_file_path: str | None = None


class NetworkEvent(BaseModel):
    """Canonical Network Event conforming to schemas/v1/network_event.schema.json."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(default="1.0.0")
    event_id: UUID
    timestamp_ns: int = Field(ge=0)
    timestamp_iso: str
    source_id: str
    flow_id: str | None = None
    flow_direction: FlowDirection | None = None
    link_layer: LinkLayer | None = None
    network_layer: NetworkLayer | None = None
    transport_layer: TransportLayer | None = None
    application_layer: ApplicationLayer | None = None
    parser_status: ParserStatus
    provenance: Provenance
