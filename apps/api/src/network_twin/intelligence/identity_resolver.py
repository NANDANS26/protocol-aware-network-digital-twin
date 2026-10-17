"""Deterministic, evidence-aware network identity correlation and asset tracking."""

import hashlib
import ipaddress
import logging
from datetime import datetime

from network_twin.models.intelligence import Asset, EvidenceRecord, EvidenceType, IdentityStatus

logger = logging.getLogger(__name__)


def generate_stable_asset_id(primary_ip: str, mac: str | None = None) -> str:
    """Generates a deterministic asset ID using SHA-256 seed."""
    key = f"ip:{primary_ip.strip().lower()}"
    if mac:
        key += f"|mac:{mac.strip().lower()}"
    return f"asset-{hashlib.sha256(key.encode()).hexdigest()[:16]}"


class IdentityResolver:
    """Correlates IP, MAC, ARP, DNS, and TLS observations into verified assets."""

    def __init__(self):
        # Cache of known assets keyed by primary IP
        self._ip_to_asset: dict[str, Asset] = {}

    def resolve_asset_from_observation(
        self,
        ip_str: str,
        mac_str: str | None,
        observed_time: datetime,
        source_id: str,
        protocol: str | None = None,
        hostname: str | None = None,
        service: str | None = None,
    ) -> tuple[Asset, list[EvidenceRecord]]:
        """Resolves or updates an asset given an observed packet/flow endpoint."""
        clean_ip = ip_str.strip()
        evidence_list: list[EvidenceRecord] = []

        try:
            ip_obj = ipaddress.ip_address(clean_ip)
        except ValueError:
            clean_ip = "0.0.0.0"
            ip_obj = ipaddress.ip_address(clean_ip)

        # Check if asset already exists
        existing = self._ip_to_asset.get(clean_ip)
        if existing:
            # Update observation timestamps
            if observed_time < existing.first_seen:
                existing.first_seen = observed_time
            if observed_time > existing.last_seen:
                existing.last_seen = observed_time

            # Check MAC consistency
            if mac_str:
                clean_mac = mac_str.lower().strip()
                if clean_mac not in existing.mac_addresses:
                    if existing.mac_addresses and clean_mac != "00:00:00:00:00:00" and not ip_obj.is_multicast:
                        # Conflicting MAC on same IP!
                        conflict_msg = f"Multiple MAC addresses observed for {clean_ip}: {existing.mac_addresses} vs {clean_mac}"
                        if conflict_msg not in existing.conflicts:
                            existing.conflicts.append(conflict_msg)
                            existing.identity_status = IdentityStatus.CONFLICTING
                            existing.confidence = min(existing.confidence, 0.4)
                    existing.mac_addresses.append(clean_mac)
                    if existing.identity_status != IdentityStatus.CONFLICTING:
                        existing.identity_status = IdentityStatus.CONFIRMED

            # Append hostnames
            if hostname and hostname not in existing.hostnames:
                existing.hostnames.append(hostname)

            # Append protocols
            if protocol and protocol not in existing.observed_protocols:
                existing.observed_protocols.append(protocol)

            # Append services
            if service and service not in existing.observed_services:
                existing.observed_services.append(service)

            if source_id not in existing.observation_sources:
                existing.observation_sources.append(source_id)

            return existing, evidence_list

        # New asset creation
        macs = [mac_str.lower().strip()] if mac_str and mac_str != "00:00:00:00:00:00" else []
        hostnames = [hostname] if hostname else []
        protocols = [protocol] if protocol else []
        services = [service] if service else []

        # Determine status
        if ip_obj.is_multicast or ip_obj.is_unspecified:
            status = IdentityStatus.UNRESOLVED
            confidence = 0.3
        elif macs:
            status = IdentityStatus.CONFIRMED
            confidence = 0.95
        else:
            status = IdentityStatus.PROBABLE
            confidence = 0.80

        asset_id = generate_stable_asset_id(clean_ip, macs[0] if macs else None)

        asset = Asset(
            asset_id=asset_id,
            primary_ip=clean_ip,
            ip_addresses=[clean_ip],
            mac_addresses=macs,
            hostnames=hostnames,
            observed_protocols=protocols,
            observed_services=services,
            first_seen=observed_time,
            last_seen=observed_time,
            identity_status=status,
            confidence=confidence,
            conflicts=[],
            observation_sources=[source_id],
        )

        self._ip_to_asset[clean_ip] = asset

        # Generate evidence record for this asset creation
        ev_id = f"ev-asset-{asset_id}"
        evidence = EvidenceRecord(
            evidence_id=ev_id,
            evidence_type=EvidenceType.PACKET_OBSERVED,
            source_type="packet_analysis",
            source_artifact_id=source_id,
            observation_timestamp=observed_time,
            ingestion_timestamp=datetime.now(datetime.UTC if hasattr(datetime, "UTC") else None),
            src_ref=clean_ip,
            dst_ref=None,
            parser_status="ok",
            confidence=confidence,
            provenance=f"Observed on wire from source {source_id}",
            details={"ip": clean_ip, "mac": macs, "status": status.value},
        )
        evidence_list.append(evidence)

        return asset, evidence_list

    def correlate_arp_mapping(
        self,
        ip_str: str,
        mac_str: str,
        observed_time: datetime,
        source_id: str,
    ) -> tuple[Asset | None, EvidenceRecord]:
        """Correlates an ARP mapping into the asset registry."""
        asset, _ = self.resolve_asset_from_observation(
            ip_str=ip_str,
            mac_str=mac_str,
            observed_time=observed_time,
            source_id=source_id,
            protocol="ARP",
        )

        ev = EvidenceRecord(
            evidence_id=f"ev-arp-{hashlib.sha256(f'{ip_str}:{mac_str}:{source_id}'.encode()).hexdigest()[:12]}",
            evidence_type=EvidenceType.PACKET_OBSERVED,
            source_type="arp_resolution",
            source_artifact_id=source_id,
            observation_timestamp=observed_time,
            ingestion_timestamp=datetime.now(datetime.UTC if hasattr(datetime, "UTC") else None),
            src_ref=ip_str,
            dst_ref=mac_str,
            parser_status="ok",
            confidence=0.98,
            provenance=f"ARP broadcast/response mapping in capture {source_id}",
            details={"ip": ip_str, "mac": mac_str},
        )
        return asset, ev


identity_resolver = IdentityResolver()
