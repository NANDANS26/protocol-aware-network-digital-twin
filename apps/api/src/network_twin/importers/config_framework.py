"""Safe, extensible import framework for authorized network configuration and routing tables."""

import csv
import io
import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from network_twin.models.intelligence import (
    ConfigImportResult,
    EvidenceClassification,
    EvidenceRecord,
    EvidenceType,
    TopologyEdge,
    TopologyEdgeType,
    TopologyNode,
    TopologyNodeType,
)

logger = logging.getLogger(__name__)

MAX_IMPORT_BYTES = 10 * 1024 * 1024  # 10 MB maximum configuration input size


class ConfigurationImportError(Exception):
    """Raised when an imported configuration is invalid or malformed."""
    pass


class BaseImporter:
    """Base class for all configuration parsers."""

    def __init__(self, source_name: str):
        self.source_name = source_name
        self.import_id = f"import-{uuid.uuid4().hex[:12]}"

    def parse(self, raw_content: str) -> tuple[ConfigImportResult, list[EvidenceRecord], list[TopologyNode], list[TopologyEdge]]:
        raise NotImplementedError


class RoutingTableImporter(BaseImporter):
    """Parses IPv4/IPv6 routing table exports in JSON or CSV format."""

    def parse(self, raw_content: str) -> tuple[ConfigImportResult, list[EvidenceRecord], list[TopologyNode], list[TopologyEdge]]:
        if len(raw_content.encode("utf-8")) > MAX_IMPORT_BYTES:
            raise ConfigurationImportError("Configuration file exceeds 10 MB limit.")

        errors: list[str] = []
        evidence_list: list[EvidenceRecord] = []
        nodes: list[TopologyNode] = []
        edges: list[TopologyEdge] = []

        now = datetime.now(UTC)
        rows = self._read_records(raw_content, errors)

        valid_count = 0
        for i, row in enumerate(rows):
            dest = row.get("destination") or row.get("prefix") or row.get("network")
            next_hop = row.get("next_hop") or row.get("gateway")
            interface = row.get("interface") or row.get("dev")
            metric = row.get("metric", "1")

            if not dest:
                errors.append(f"Row {i+1}: Missing required 'destination' or 'prefix'")
                continue

            valid_count += 1
            ev_id = f"ev-route-{self.import_id}-{i+1}"
            ev = EvidenceRecord(
                evidence_id=ev_id,
                evidence_type=EvidenceType.IMPORTED_ROUTING,
                source_type="routing_table",
                source_artifact_id=self.import_id,
                observation_timestamp=now,
                ingestion_timestamp=now,
                src_ref=dest,
                dst_ref=next_hop,
                parser_status="ok",
                confidence=1.0,
                provenance=f"Routing table import '{self.source_name}' (row {i+1})",
                details={
                    "destination": dest,
                    "next_hop": next_hop,
                    "interface": interface,
                    "metric": metric,
                },
            )
            evidence_list.append(ev)

            # Node for route destination
            dest_node_id = f"route-dest-{dest.replace('/', '_').replace(':', '_')}"
            dest_node = TopologyNode(
                node_id=dest_node_id,
                node_type=TopologyNodeType.SUBNET,
                label=f"Route: {dest}",
                properties={"destination": dest, "metric": metric},
            )
            nodes.append(dest_node)

            # If next_hop exists, create edge
            if next_hop and next_hop != "0.0.0.0":
                gw_node_id = f"asset-ip-{next_hop.replace(':', '_')}"
                gw_node = TopologyNode(
                    node_id=gw_node_id,
                    node_type=TopologyNodeType.ROUTER,
                    label=f"Gateway: {next_hop}",
                    properties={"ip": next_hop},
                )
                nodes.append(gw_node)

                edge = TopologyEdge(
                    edge_id=f"edge-route-{self.import_id}-{i+1}",
                    source_node_id=gw_node_id,
                    target_node_id=dest_node_id,
                    edge_type=TopologyEdgeType.CONFIGURED_ROUTE,
                    evidence_class=EvidenceClassification.CONFIGURED,
                    primary_protocol="IP",
                    confidence=1.0,
                    evidence_ids=[ev_id],
                    properties={"interface": interface, "metric": metric},
                )
                edges.append(edge)

        status = "completed" if not errors else ("partial" if valid_count > 0 else "failed")
        result = ConfigImportResult(
            import_id=self.import_id,
            format="routing_table",
            source_name=self.source_name,
            status=status,
            items_imported=valid_count,
            errors=errors,
            created_at=now,
            evidence_ids=[e.evidence_id for e in evidence_list],
        )
        return result, evidence_list, nodes, edges

    def _read_records(self, content: str, errors: list[str]) -> list[dict[str, Any]]:
        trimmed = content.strip()
        if trimmed.startswith("[") or trimmed.startswith("{"):
            try:
                data = json.loads(trimmed)
                return data if isinstance(data, list) else [data]
            except json.JSONDecodeError as e:
                errors.append(f"JSON parsing error: {e}")
                return []
        else:
            # CSV parsing
            try:
                reader = csv.DictReader(io.StringIO(trimmed))
                return [dict(r) for r in reader]
            except Exception as e:
                errors.append(f"CSV parsing error: {e}")
                return []


class NeighborTableImporter(BaseImporter):
    """Parses ARP / NDP neighbor tables in JSON or CSV format."""

    def parse(self, raw_content: str) -> tuple[ConfigImportResult, list[EvidenceRecord], list[TopologyNode], list[TopologyEdge]]:
        if len(raw_content.encode("utf-8")) > MAX_IMPORT_BYTES:
            raise ConfigurationImportError("Configuration file exceeds 10 MB limit.")

        errors: list[str] = []
        evidence_list: list[EvidenceRecord] = []
        nodes: list[TopologyNode] = []
        edges: list[TopologyEdge] = []

        now = datetime.now(UTC)
        rows = self._read_records(raw_content, errors)

        valid_count = 0
        for i, row in enumerate(rows):
            ip_str = row.get("ip") or row.get("ip_address") or row.get("address")
            mac_str = row.get("mac") or row.get("mac_address") or row.get("lladdr")
            interface = row.get("interface") or row.get("dev")

            if not ip_str or not mac_str:
                errors.append(f"Row {i+1}: Missing required 'ip' or 'mac'")
                continue

            valid_count += 1
            ev_id = f"ev-neighbor-{self.import_id}-{i+1}"
            ev = EvidenceRecord(
                evidence_id=ev_id,
                evidence_type=EvidenceType.IMPORTED_NEIGHBOR,
                source_type="neighbor_table",
                source_artifact_id=self.import_id,
                observation_timestamp=now,
                ingestion_timestamp=now,
                src_ref=ip_str,
                dst_ref=mac_str,
                parser_status="ok",
                confidence=1.0,
                provenance=f"ARP/Neighbor import '{self.source_name}' (row {i+1})",
                details={"ip": ip_str, "mac": mac_str, "interface": interface},
            )
            evidence_list.append(ev)

            node_id = f"asset-ip-{ip_str.replace(':', '_')}"
            node = TopologyNode(
                node_id=node_id,
                node_type=TopologyNodeType.ASSET,
                label=f"{ip_str} ({mac_str})",
                properties={"ip": ip_str, "mac": mac_str, "interface": interface},
            )
            nodes.append(node)

        status = "completed" if not errors else ("partial" if valid_count > 0 else "failed")
        result = ConfigImportResult(
            import_id=self.import_id,
            format="neighbor_table",
            source_name=self.source_name,
            status=status,
            items_imported=valid_count,
            errors=errors,
            created_at=now,
            evidence_ids=[e.evidence_id for e in evidence_list],
        )
        return result, evidence_list, nodes, edges

    def _read_records(self, content: str, errors: list[str]) -> list[dict[str, Any]]:
        trimmed = content.strip()
        if trimmed.startswith("[") or trimmed.startswith("{"):
            try:
                data = json.loads(trimmed)
                return data if isinstance(data, list) else [data]
            except json.JSONDecodeError as e:
                errors.append(f"JSON parsing error: {e}")
                return []
        else:
            try:
                reader = csv.DictReader(io.StringIO(trimmed))
                return [dict(r) for r in reader]
            except Exception as e:
                errors.append(f"CSV parsing error: {e}")
                return []


class DeviceInventoryImporter(BaseImporter):
    """Parses device and asset inventories (hostname, IPs, MACs, role) in JSON/CSV."""

    def parse(self, raw_content: str) -> tuple[ConfigImportResult, list[EvidenceRecord], list[TopologyNode], list[TopologyEdge]]:
        if len(raw_content.encode("utf-8")) > MAX_IMPORT_BYTES:
            raise ConfigurationImportError("Configuration file exceeds 10 MB limit.")

        errors: list[str] = []
        evidence_list: list[EvidenceRecord] = []
        nodes: list[TopologyNode] = []
        edges: list[TopologyEdge] = []

        now = datetime.now(UTC)
        rows = self._read_records(raw_content, errors)

        valid_count = 0
        for i, row in enumerate(rows):
            hostname = row.get("hostname") or row.get("name")
            ip_str = row.get("ip") or row.get("primary_ip") or row.get("ip_address")
            mac_str = row.get("mac") or row.get("mac_address")
            role = row.get("role", "server")

            if not ip_str and not hostname:
                errors.append(f"Row {i+1}: Missing both 'ip' and 'hostname'")
                continue

            primary_ip = ip_str or "0.0.0.0"
            valid_count += 1
            ev_id = f"ev-inventory-{self.import_id}-{i+1}"
            ev = EvidenceRecord(
                evidence_id=ev_id,
                evidence_type=EvidenceType.IMPORTED_CONFIGURATION,
                source_type="device_inventory",
                source_artifact_id=self.import_id,
                observation_timestamp=now,
                ingestion_timestamp=now,
                src_ref=primary_ip,
                dst_ref=hostname,
                parser_status="ok",
                confidence=1.0,
                provenance=f"Inventory import '{self.source_name}' (row {i+1})",
                details={"hostname": hostname, "ip": primary_ip, "mac": mac_str, "role": role},
            )
            evidence_list.append(ev)

            node_id = f"asset-inv-{self.import_id}-{i+1}"
            node_type = TopologyNodeType.ROUTER if role.lower() in ("router", "gateway", "firewall", "switch") else TopologyNodeType.ASSET
            node = TopologyNode(
                node_id=node_id,
                node_type=node_type,
                label=hostname or primary_ip,
                properties={"primary_ip": primary_ip, "hostname": hostname, "mac": mac_str, "role": role},
            )
            nodes.append(node)

        status = "completed" if not errors else ("partial" if valid_count > 0 else "failed")
        result = ConfigImportResult(
            import_id=self.import_id,
            format="inventory",
            source_name=self.source_name,
            status=status,
            items_imported=valid_count,
            errors=errors,
            created_at=now,
            evidence_ids=[e.evidence_id for e in evidence_list],
        )
        return result, evidence_list, nodes, edges

    def _read_records(self, content: str, errors: list[str]) -> list[dict[str, Any]]:
        trimmed = content.strip()
        if trimmed.startswith("[") or trimmed.startswith("{"):
            try:
                data = json.loads(trimmed)
                return data if isinstance(data, list) else [data]
            except json.JSONDecodeError as e:
                errors.append(f"JSON parsing error: {e}")
                return []
        else:
            try:
                reader = csv.DictReader(io.StringIO(trimmed))
                return [dict(r) for r in reader]
            except Exception as e:
                errors.append(f"CSV parsing error: {e}")
                return []


def get_importer(format_name: str, source_name: str) -> BaseImporter:
    fmt = format_name.lower().strip()
    if fmt in ("routing", "routing_table", "routes"):
        return RoutingTableImporter(source_name)
    elif fmt in ("neighbor", "neighbor_table", "arp", "arp_table"):
        return NeighborTableImporter(source_name)
    elif fmt in ("inventory", "devices", "assets"):
        return DeviceInventoryImporter(source_name)
    else:
        raise ConfigurationImportError(
            f"Unsupported configuration format '{format_name}'. Supported formats: 'routing_table', 'neighbor_table', 'inventory'."
        )
