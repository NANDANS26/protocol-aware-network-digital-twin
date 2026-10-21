"""Reconstructs typed, evidence-backed network topology graphs from stored intelligence."""

import ipaddress
import logging
from datetime import UTC, datetime
from typing import Any

from network_twin.models.intelligence import (
    Asset,
    CommunicationRelationship,
    EvidenceClassification,
    NetworkSegment,
    NetworkService,
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

    def build_graph_for_entities(
        self,
        assets: list[Asset],
        segments: list[NetworkSegment],
        services: list[NetworkService],
        relationships: list[CommunicationRelationship],
        metadata: dict[str, Any] | None = None,
    ) -> TopologyGraph:
        """Assembles a verifiable topology graph strictly from provided entity subsets."""
        now = datetime.now(UTC)
        nodes: dict[str, TopologyNode] = {}
        edges: dict[str, TopologyEdge] = {}

        # 1. Segments (Only valid unicast subnets, never multicast)
        for seg in segments:
            # Check if segment prefix is multicast or invalid
            try:
                net_obj = ipaddress.ip_network(seg.cidr_prefix, strict=False)
                if net_obj.is_multicast or net_obj.is_loopback:
                    continue
            except ValueError:
                continue

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
                    "source_type": "inferred" if "Inferred" in seg.provenance else "configured",
                },
            )

        # 2. Assets (Distinguish unicast hosts, Layer-2 endpoints, and multicast clock groups)
        for asset in assets:
            asset_node_id = f"node-{asset.asset_id}"

            is_multicast = False
            if asset.primary_ip:
                try:
                    ip_obj = ipaddress.ip_address(asset.primary_ip)
                    is_multicast = ip_obj.is_multicast
                except ValueError:
                    is_multicast = False

            is_l2_only = not asset.primary_ip and bool(asset.mac_addresses)

            # Routers: MUST NOT be multicast or L2-only, and must match gateway of a known segment
            is_router = False
            if not is_multicast and not is_l2_only:
                for seg in segments:
                    if seg.gateway_ip and seg.gateway_ip in asset.ip_addresses:
                        # Only consider router if it has multiple interfaces or confirmed routing role
                        if len(asset.ip_addresses) > 1 or "ROUTER" in [s.upper() for s in asset.observed_services]:
                            is_router = True
                            break

            node_type = TopologyNodeType.ROUTER if is_router else TopologyNodeType.ASSET

            # Clean and accurate labels
            if is_multicast:
                label = asset.hostnames[0] if asset.hostnames else f"Multicast: {asset.primary_ip}"
            elif is_l2_only:
                label = asset.hostnames[0] if asset.hostnames else f"MAC: {asset.mac_addresses[0]}"
            else:
                label = asset.hostnames[0] if asset.hostnames else (asset.primary_ip or asset.asset_id)
                if is_router:
                    label = f"Router: {label}"

            entity_type = "multicast_group" if is_multicast else ("l2_device" if is_l2_only else "host")

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
                    "entity_type": entity_type,
                    "is_multicast": is_multicast,
                    "is_l2_only": is_l2_only,
                    "source_type": "observed",
                },
            )

            # Subnet Attachment: Strictly for unicast host assets with IP within subnet
            if not is_multicast and not is_l2_only:
                for seg in segments:
                    try:
                        network = ipaddress.ip_network(seg.cidr_prefix, strict=False)
                        if network.is_multicast:
                            continue
                        for ip_str in asset.ip_addresses:
                            ip_o = ipaddress.ip_address(ip_str)
                            if ip_o.is_multicast:
                                continue
                            if ip_o in network:
                                subnet_node_id = f"subnet-{seg.segment_id}"
                                if subnet_node_id in nodes:
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
                                        properties={"cidr": seg.cidr_prefix, "derivation_method": "CIDR prefix match"},
                                    )
                                    break
                    except ValueError:
                        continue

        # 3. Services
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
                    "source_type": "observed",
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

        # 4. Communication Relationships
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
                        "source_type": "observed",
                    },
                )

        node_list = list(nodes.values())
        edge_list = list(edges.values())

        graph_meta = {
            "source": "metadata_store",
            "asset_count": len(assets),
            "segment_count": len(segments),
            "service_count": len(services),
            "relationship_count": len(relationships),
        }
        if metadata:
            graph_meta.update(metadata)

        return TopologyGraph(
            graph_id=f"graph-{now.strftime('%Y%m%d%H%M%S')}",
            nodes=node_list,
            edges=edge_list,
            node_count=len(node_list),
            edge_count=len(edge_list),
            generated_at=now,
            metadata=graph_meta,
        )

    def build_current_graph(self) -> TopologyGraph:
        """Assembles the aggregate topology graph from all persisted intelligence assets."""
        segments = self.store.list_segments()
        assets = self.store.list_assets(limit=1000)
        services = self.store.list_services()
        relationships = self.store.list_relationships(limit=2000)
        return self.build_graph_for_entities(
            assets=assets,
            segments=segments,
            services=services,
            relationships=relationships,
            metadata={"source_type": "AGGREGATE_ACTIVE_MODEL", "model_scope": "all_historical"},
        )

    def build_graph_for_capture(
        self, capture_id: str | list[str] | None = None, job_id: str | None = None
    ) -> TopologyGraph:
        """Constructs an isolated topology graph containing ONLY entities derived from specific capture(s) or job."""
        c_ids = [capture_id] if isinstance(capture_id, str) and capture_id else (capture_id or [])

        # 1. Fetch assets for this capture/job
        assets: list[Asset] = []
        if job_id:
            assets.extend(self.store.list_assets(source_id=job_id, limit=500))
        for cid in c_ids:
            if cid:
                assets.extend(self.store.list_assets(source_id=cid, limit=500))

        # Fallback to evidence lookup if needed
        lookup_ids = [job_id] if job_id else []
        lookup_ids.extend([cid for cid in c_ids if cid])
        if not assets and lookup_ids:
            for lid in lookup_ids:
                evs = self.store.list_evidence(source_artifact_id=lid, limit=500)
                seen_ips = set()
                for ev in evs:
                    if ev.src_ref:
                        seen_ips.add(ev.src_ref)
                    if ev.dst_ref:
                        seen_ips.add(ev.dst_ref)
                for ip in seen_ips:
                    asset = self.store.find_asset_by_ip(ip)
                    if asset and asset not in assets:
                        assets.append(asset)

        # Dedup assets
        seen_asset_ids = set()
        dedup_assets: list[Asset] = []
        for a in assets:
            if a.asset_id not in seen_asset_ids:
                seen_asset_ids.add(a.asset_id)
                dedup_assets.append(a)
        assets = dedup_assets
        asset_ids = {a.asset_id for a in assets}

        # 2. Segments observed in this capture
        all_segments = self.store.list_segments()
        segments = [
            s
            for s in all_segments
            if (job_id and job_id in s.provenance) or any(cid and cid in s.provenance for cid in c_ids)
        ]
        # If segments not strictly tagged with provenance, match against this capture's unicast host IPs
        if not segments and assets:
            for seg in all_segments:
                try:
                    net = ipaddress.ip_network(seg.cidr_prefix, strict=False)
                    if net.is_multicast:
                        continue
                    for a in assets:
                        for ip_str in a.ip_addresses:
                            ip_o = ipaddress.ip_address(ip_str)
                            if not ip_o.is_multicast and ip_o in net:
                                if seg not in segments:
                                    segments.append(seg)
                                break
                except ValueError:
                    continue

        # 3. Services on this capture's assets
        all_services = self.store.list_services()
        services = [s for s in all_services if s.asset_id in asset_ids]

        # 4. Relationships between this capture's assets
        all_relationships = self.store.list_relationships(limit=2000)
        relationships = [r for r in all_relationships if r.src_asset_id in asset_ids and r.dst_asset_id in asset_ids]

        primary_cid = c_ids[0] if c_ids else None
        cap = self.store.get_capture(primary_cid) if primary_cid else None
        filename = cap.get("filename") if cap else (primary_cid or "unknown")

        return self.build_graph_for_entities(
            assets=assets,
            segments=segments,
            services=services,
            relationships=relationships,
            metadata={
                "capture_id": primary_cid,
                "capture_ids": c_ids,
                "analysis_job_id": job_id,
                "capture_filename": filename,
                "source_type": "DIRECT_OBSERVATION",
                "derivation_method": "PCAP flow & packet correlation",
                "model_scope": "isolated_capture",
            },
        )


graph_builder = GraphBuilder()
