"""Reconstructs typed, evidence-backed network topology graphs from stored intelligence."""

import ipaddress
import logging
from datetime import UTC, datetime

from network_twin.models.intelligence import (
    EvidenceClassification,
    TopologyEdge,
    TopologyEdgeType,
    TopologyGraph,
    TopologyNode,
    TopologyNodeType,
)
from network_twin.storage.metadata_store import MetadataStore, metadata_store

logger = logging.getLogger(__name__)


class GraphBuilder:
    """Constructs verifiable topology graphs strictly from persisted evidence and configuration."""

    def __init__(self, store: MetadataStore = metadata_store):
        self.store = store

    def build_current_graph(self) -> TopologyGraph:
        """Assembles the current topology graph from all persisted intelligence assets."""
        now = datetime.now(UTC)
        nodes: dict[str, TopologyNode] = {}
        edges: dict[str, TopologyEdge] = {}

        # 1. Load Segments
        segments = self.store.list_segments()
        for seg in segments:
            node_id = f"subnet-{seg.segment_id}"
            nodes[node_id] = TopologyNode(
                node_id=node_id,
                node_type=TopologyNodeType.SUBNET,
                label=f"Subnet {seg.cidr_prefix}",
                segment_id=seg.segment_id,
                properties={
                    "cidr_prefix": seg.cidr_prefix,
                    "address_family": seg.address_family,
                    "gateway_ip": seg.gateway_ip,
                    "host_count": seg.observed_host_count,
                    "confidence": seg.confidence,
                    "provenance": seg.provenance,
                },
            )

        # 2. Load Assets
        assets = self.store.list_assets(limit=1000)
        for asset in assets:
            asset_node_id = f"node-{asset.asset_id}"
            is_router = False

            # Check if asset acts as gateway for any segment
            for seg in segments:
                if seg.gateway_ip and seg.gateway_ip in asset.ip_addresses:
                    is_router = True
                    break

            node_type = TopologyNodeType.ROUTER if is_router else TopologyNodeType.ASSET
            label = asset.hostnames[0] if asset.hostnames else asset.primary_ip
            if is_router:
                label = f"Router: {label}"

            nodes[asset_node_id] = TopologyNode(
                node_id=asset_node_id,
                node_type=node_type,
                label=label,
                asset_id=asset.asset_id,
                properties={
                    "primary_ip": asset.primary_ip,
                    "ip_addresses": asset.ip_addresses,
                    "mac_addresses": asset.mac_addresses,
                    "hostnames": asset.hostnames,
                    "protocols": asset.observed_protocols,
                    "services": asset.observed_services,
                    "identity_status": asset.identity_status.value,
                    "confidence": asset.confidence,
                    "conflicts": asset.conflicts,
                },
            )

            # Inferred Edge: Subnet Attachment
            for seg in segments:
                try:
                    network = ipaddress.ip_network(seg.cidr_prefix, strict=False)
                    for ip_str in asset.ip_addresses:
                        ip_obj = ipaddress.ip_address(ip_str)
                        if ip_obj in network:
                            subnet_node_id = f"subnet-{seg.segment_id}"
                            edge_id = f"edge-attach-{asset.asset_id}-{seg.segment_id}"
                            edges[edge_id] = TopologyEdge(
                                edge_id=edge_id,
                                source_node_id=asset_node_id,
                                target_node_id=subnet_node_id,
                                edge_type=TopologyEdgeType.SUBNET_ATTACHMENT,
                                evidence_class=EvidenceClassification.INFERRED,
                                primary_protocol="IP",
                                confidence=seg.confidence,
                                evidence_ids=[],
                                properties={"cidr": seg.cidr_prefix},
                            )
                            break
                except ValueError:
                    continue

        # 3. Load Services
        services = self.store.list_services()
        for svc in services:
            svc_node_id = f"svc-{svc.service_id}"
            svc_label = f"{svc.app_protocol}:{svc.port}"
            if svc.tls_sni:
                svc_label += f" ({svc.tls_sni})"

            nodes[svc_node_id] = TopologyNode(
                node_id=svc_node_id,
                node_type=TopologyNodeType.SERVICE,
                label=svc_label,
                asset_id=svc.asset_id,
                properties={
                    "server_ip": svc.server_ip,
                    "transport_protocol": svc.transport_protocol,
                    "port": svc.port,
                    "app_protocol": svc.app_protocol,
                    "tls_sni": svc.tls_sni,
                    "http_server": svc.http_server,
                    "confidence": svc.classification_confidence,
                },
            )

            # Edge: Asset Hosts Service
            host_asset_node_id = f"node-{svc.asset_id}"
            if host_asset_node_id in nodes:
                edge_id = f"edge-hosts-{svc.service_id}"
                edges[edge_id] = TopologyEdge(
                    edge_id=edge_id,
                    source_node_id=host_asset_node_id,
                    target_node_id=svc_node_id,
                    edge_type=TopologyEdgeType.SERVICE_DEPENDENCY,
                    evidence_class=EvidenceClassification.DIRECT_OBSERVATION,
                    primary_protocol=svc.transport_protocol,
                    confidence=svc.classification_confidence,
                    evidence_ids=[],
                    properties={"port": svc.port, "app_protocol": svc.app_protocol},
                )

        # 4. Load Communication Relationships
        relationships = self.store.list_relationships(limit=2000)
        for rel in relationships:
            src_node_id = f"node-{rel.src_asset_id}"
            dst_node_id = f"node-{rel.dst_asset_id}"

            if src_node_id in nodes and dst_node_id in nodes:
                edge_id = f"edge-comm-{rel.relationship_id}"
                edges[edge_id] = TopologyEdge(
                    edge_id=edge_id,
                    source_node_id=src_node_id,
                    target_node_id=dst_node_id,
                    edge_type=TopologyEdgeType.OBSERVED_COMMUNICATION,
                    evidence_class=EvidenceClassification.DIRECT_OBSERVATION,
                    primary_protocol=rel.transport_protocol,
                    packet_count=rel.packet_count,
                    byte_count=rel.byte_count,
                    confidence=rel.confidence,
                    evidence_ids=rel.flow_ids,
                    properties={
                        "src_port": rel.src_port,
                        "dst_port": rel.dst_port,
                        "app_protocol": rel.app_protocol,
                        "directionality": rel.directionality,
                        "flows": rel.flow_ids,
                    },
                )

        node_list = list(nodes.values())
        edge_list = list(edges.values())

        return TopologyGraph(
            graph_id=f"graph-{now.strftime('%Y%m%d%H%M%S')}",
            nodes=node_list,
            edges=edge_list,
            node_count=len(node_list),
            edge_count=len(edge_list),
            generated_at=now,
            metadata={"source": "metadata_store", "asset_count": len(assets)},
        )


graph_builder = GraphBuilder()
