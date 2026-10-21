"""Infers IP subnets and candidate gateways from observed network traffic."""

import ipaddress
import logging
from datetime import datetime

from network_twin.models.intelligence import NetworkSegment

logger = logging.getLogger(__name__)


def infer_cidr_prefix(ip_str: str) -> str | None:
    """Computes default subnet prefix for an IP based on address family and conventions.
    Returns None for multicast, loopback, broadcast, or unspecified addresses."""
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return None

    if ip_obj.is_multicast or ip_obj.is_loopback or ip_obj.is_unspecified or ip_obj.is_reserved:
        return None

    if ip_obj.version == 4:
        # Standard IPv4 local subnetting assumption (/24 default for LANs)
        network = ipaddress.IPv4Network(f"{ip_str}/24", strict=False)
        return str(network)
    else:
        # Standard IPv6 subnet prefix is /64
        network = ipaddress.IPv6Network(f"{ip_str}/64", strict=False)
        return str(network)


class SegmentInferrer:
    """Maintains and infers network segments from observed IP addresses."""

    def __init__(self):
        # Key: cidr_prefix -> dict of metadata
        self._segments: dict[str, dict] = {}

    def observe_ip(self, ip_str: str, timestamp: datetime, source_id: str) -> NetworkSegment | None:
        cidr = infer_cidr_prefix(ip_str)
        if not cidr:
            return None

        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
            version_str = f"IPv{ip_obj.version}"
        except ValueError:
            return None

        # Check candidate gateway (never for multicast or reserved)
        is_candidate_gw = False
        if version_str == "IPv4" and not ip_obj.is_multicast:
            octets = ip_str.strip().split(".")
            if len(octets) == 4 and octets[3] in ("1", "254"):
                is_candidate_gw = True

        seg = self._segments.get(cidr)
        if not seg:
            seg = {
                "segment_id": f"seg-{cidr.replace('/', '_').replace(':', '_')}",
                "cidr_prefix": cidr,
                "address_family": version_str,
                "gateway_ip": ip_str if is_candidate_gw else None,
                "hosts": set([ip_str]),
                "configuration_source": None,
                "confidence": 0.85,
                "provenance": f"Inferred from observed traffic in {source_id}",
                "first_seen": timestamp,
                "last_seen": timestamp,
            }
            self._segments[cidr] = seg
        else:
            seg["hosts"].add(ip_str)
            if is_candidate_gw and not seg["gateway_ip"]:
                seg["gateway_ip"] = ip_str
            if timestamp < seg["first_seen"]:
                seg["first_seen"] = timestamp
            if timestamp > seg["last_seen"]:
                seg["last_seen"] = timestamp

        return NetworkSegment(
            segment_id=seg["segment_id"],
            cidr_prefix=seg["cidr_prefix"],
            address_family=seg["address_family"],
            gateway_ip=seg["gateway_ip"],
            observed_host_count=len(seg["hosts"]),
            configuration_source=seg["configuration_source"],
            confidence=seg["confidence"],
            provenance=seg["provenance"],
            first_seen=seg["first_seen"],
            last_seen=seg["last_seen"],
        )

    def list_inferred_segments(self) -> list[NetworkSegment]:
        return [
            NetworkSegment(
                segment_id=s["segment_id"],
                cidr_prefix=s["cidr_prefix"],
                address_family=s["address_family"],
                gateway_ip=s["gateway_ip"],
                observed_host_count=len(s["hosts"]),
                configuration_source=s["configuration_source"],
                confidence=s["confidence"],
                provenance=s["provenance"],
                first_seen=s["first_seen"],
                last_seen=s["last_seen"],
            )
            for s in self._segments.values()
        ]


segment_inferrer = SegmentInferrer()
