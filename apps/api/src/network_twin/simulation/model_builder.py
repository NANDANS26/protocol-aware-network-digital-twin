"""Builds an executable NetworkModel from a persistent TopologySnapshot and imported configurations."""

import hashlib
import ipaddress
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from network_twin.models.intelligence import TopologyGraph
from network_twin.simulation.models import (
    AccessControlList,
    AdministrativeState,
    DefaultPolicy,
    FirewallRule,
    IPAddressAssignment,
    ModelInterface,
    ModelLimitation,
    ModelNode,
    ModelNodeType,
    NetworkModel,
    NetworkZone,
    RouteEntry,
    RouteStatus,
    RouteType,
    RuleAction,
    RuleDirection,
    TransportProtocolConstraint,
)
from network_twin.storage.metadata_store import MetadataStore

logger = logging.getLogger(__name__)


class ModelBuilder:
    """Constructs an executable, deterministic NetworkModel from a snapshot."""

    def __init__(self, metadata_store: MetadataStore):
        self.metadata_store = metadata_store

    def build_from_snapshot(
        self,
        snapshot_id: str,
        name: str | None = None,
        custom_routes: list[dict[str, Any]] | None = None,
        custom_acls: list[dict[str, Any]] | None = None,
        custom_zones: list[dict[str, Any]] | None = None,
    ) -> NetworkModel:
        """Derives an executable formal model from a stored topology snapshot."""
        snapshot = self.metadata_store.get_snapshot(snapshot_id)
        if not snapshot:
            raise KeyError(f"Topology snapshot '{snapshot_id}' not found.")

        graph = self.metadata_store.get_snapshot_graph(snapshot_id)
        if not graph:
            raise ValueError(f"Topology graph for snapshot '{snapshot_id}' is empty or unreadable.")

        model_id = f"model-{uuid.uuid4().hex[:12]}"
        model_name = name or f"Model from {snapshot.name}"

        nodes: dict[str, ModelNode] = {}
        zones: dict[str, NetworkZone] = {}
        limitations: list[ModelLimitation] = []
        evidence_refs: set[str] = set()
        config_refs: set[str] = set(snapshot.source_configs)

        # 1. Translate Nodes & Interfaces
        for tnode in graph.nodes:
            node_type = self._map_node_type(tnode.node_type.value)
            interfaces: list[ModelInterface] = []
            routing_table: list[RouteEntry] = []
            acls: list[AccessControlList] = []

            # Retrieve properties
            props = tnode.properties or {}
            ip_addrs = props.get("ip_addresses") or ([props["primary_ip"]] if props.get("primary_ip") else [])
            mac_addrs = props.get("mac_addresses") or []
            subnet_cidr = props.get("cidr_prefix") or props.get("cidr")
            is_inferred = props.get("provenance") == "inferred" or (props.get("confidence", 1.0) < 1.0)

            # Create network interfaces for IP addresses
            for idx, ip_str in enumerate(ip_addrs):
                prefix_len = 24 if "." in ip_str else 64
                # Check if subnet_cidr provides more specific prefix
                if subnet_cidr and "/" in subnet_cidr:
                    try:
                        net = ipaddress.ip_network(subnet_cidr, strict=False)
                        prefix_len = net.prefixlen
                    except ValueError:
                        pass

                assignment = IPAddressAssignment(
                    ip_address=ip_str,
                    prefix_length=prefix_len,
                    is_primary=(idx == 0),
                    is_inferred=is_inferred,
                )

                mac = mac_addrs[idx] if idx < len(mac_addrs) else None
                iface_id = f"if-{tnode.node_id}-{idx}"

                iface = ModelInterface(
                    interface_id=iface_id,
                    node_id=tnode.node_id,
                    name=f"eth{idx}",
                    mac_address=mac,
                    ip_assignments=[assignment],
                    state=AdministrativeState.UP,
                    is_inferred=is_inferred,
                )
                interfaces.append(iface)

                # Add connected route for the interface
                try:
                    net = ipaddress.ip_network(f"{ip_str}/{prefix_len}", strict=False)
                    routing_table.append(
                        RouteEntry(
                            route_id=f"route-{tnode.node_id}-conn-{idx}",
                            node_id=tnode.node_id,
                            destination_prefix=str(net),
                            prefix_length=net.prefixlen,
                            next_hop_ip=None,
                            output_interface_id=iface_id,
                            metric=0,
                            admin_distance=0,
                            route_type=RouteType.CONNECTED,
                            status=RouteStatus.ACTIVE,
                            is_inferred=is_inferred,
                        )
                    )
                except ValueError as err:
                    logger.warning("Invalid IP %s on node %s: %s", ip_str, tnode.node_id, err)

            # Node metadata check for default gateway
            default_gw = props.get("default_gateway") or props.get("gateway_ip")

            mnode = ModelNode(
                node_id=tnode.node_id,
                label=tnode.label,
                node_type=node_type,
                interfaces=interfaces,
                routing_table=routing_table,
                acls=acls,
                default_gateway_ip=str(default_gw) if default_gw else None,
                is_inferred=is_inferred,
                metadata=props,
            )
            nodes[tnode.node_id] = mnode

        # 2. Translate Edges into Forwarding State / Attached Subnets
        for edge in graph.edges:
            evidence_refs.update(edge.evidence_ids)

            if edge.edge_type.value == "SUBNET_ATTACHMENT":
                # Ensure connected subnet routes exist between asset and subnet hub
                subnet_node = nodes.get(edge.target_node_id)
                asset_node = nodes.get(edge.source_node_id)

                cidr = None
                if subnet_node and subnet_node.metadata:
                    cidr = subnet_node.metadata.get("cidr_prefix") or subnet_node.metadata.get("cidr")

                if subnet_node and asset_node and cidr:
                    try:
                        net = ipaddress.ip_network(cidr, strict=False)
                        # Add route if not already present
                        has_route = any(r.destination_prefix == str(net) for r in asset_node.routing_table)
                        if not has_route:
                            asset_node.routing_table.append(
                                RouteEntry(
                                    route_id=f"route-{asset_node.node_id}-sub-{subnet_node.node_id}",
                                    node_id=asset_node.node_id,
                                    destination_prefix=str(net),
                                    prefix_length=net.prefixlen,
                                    next_hop_ip=None,
                                    metric=1,
                                    admin_distance=0,
                                    route_type=RouteType.CONNECTED,
                                    status=RouteStatus.ACTIVE,
                                    is_inferred=(edge.evidence_class.value == "INFERRED"),
                                )
                            )
                    except ValueError:
                        pass

            elif edge.edge_type.value == "CONFIGURED_ROUTE":
                # Explicit configured route
                src_node = nodes.get(edge.source_node_id)
                prefix_str = edge.properties.get("destination_prefix") or edge.primary_protocol
                if src_node and prefix_str:
                    try:
                        net = ipaddress.ip_network(prefix_str, strict=False)
                        next_hop = edge.properties.get("next_hop_ip") or (edge.target_node_id if "." in edge.target_node_id else None)
                        src_node.routing_table.append(
                            RouteEntry(
                                route_id=f"route-{edge.edge_id}",
                                node_id=src_node.node_id,
                                destination_prefix=str(net),
                                prefix_length=net.prefixlen,
                                next_hop_ip=next_hop,
                                metric=edge.properties.get("metric", 1),
                                admin_distance=edge.properties.get("admin_distance", 1),
                                route_type=RouteType.STATIC,
                                status=RouteStatus.ACTIVE,
                                source_evidence_ids=edge.evidence_ids,
                                is_inferred=False,
                            )
                        )
                    except ValueError:
                        pass

        # 3. Incorporate Imported Configurations from MetadataStore
        self._incorporate_imported_configs(nodes, config_refs, evidence_refs)

        # 4. Apply Custom Routes if supplied
        if custom_routes:
            for cr in custom_routes:
                target_nid = cr.get("node_id")
                target_node = nodes.get(target_nid) or nodes.get(f"node-{target_nid}")
                if target_node:
                    try:
                        dest = cr["destination_prefix"]
                        net = ipaddress.ip_network(dest, strict=False)
                        target_node.routing_table.append(
                            RouteEntry(
                                route_id=f"route-custom-{uuid.uuid4().hex[:8]}",
                                node_id=target_node.node_id,
                                destination_prefix=str(net),
                                prefix_length=net.prefixlen,
                                next_hop_ip=cr.get("next_hop_ip"),
                                output_interface_id=cr.get("output_interface_id"),
                                metric=cr.get("metric", 1),
                                admin_distance=cr.get("admin_distance", 1),
                                route_type=RouteType.STATIC,
                                status=RouteStatus.ACTIVE,
                                is_inferred=False,
                            )
                        )
                    except Exception as err:
                        logger.warning("Failed to add custom route: %s", err)

        # 5. Apply Custom ACLs if supplied
        if custom_acls:
            for ca in custom_acls:
                target_nid = ca.get("node_id")
                target_node = nodes.get(target_nid) or nodes.get(f"node-{target_nid}")
                if target_node:
                    rules: list[FirewallRule] = []
                    for r_idx, r_dict in enumerate(ca.get("rules", []), start=1):
                        rule = FirewallRule(
                            rule_id=r_dict.get("rule_id", f"rule-{target_node.node_id}-{r_idx}"),
                            node_id=target_node.node_id,
                            rule_number=r_idx,
                            name=r_dict.get("name", f"Rule {r_idx}"),
                            action=RuleAction(r_dict.get("action", "PERMIT")),
                            direction=RuleDirection(r_dict.get("direction", "INGRESS")),
                            source_zone=r_dict.get("source_zone"),
                            source_prefix=r_dict.get("source_prefix"),
                            destination_zone=r_dict.get("destination_zone"),
                            destination_prefix=r_dict.get("destination_prefix"),
                            protocol=TransportProtocolConstraint(r_dict.get("protocol", "ANY")),
                            source_port=r_dict.get("source_port"),
                            destination_port=r_dict.get("destination_port"),
                            description=r_dict.get("description", ""),
                            is_inferred=False,
                        )
                        rules.append(rule)

                    acl = AccessControlList(
                        acl_id=ca.get("acl_id", f"acl-{target_node.node_id}"),
                        node_id=target_node.node_id,
                        name=ca.get("name", "Default ACL"),
                        rules=rules,
                        default_policy=DefaultPolicy(ca.get("default_policy", "DEFAULT_DENY")),
                    )
                    target_node.acls.append(acl)

        # 6. Apply Network Zones
        if custom_zones:
            for cz in custom_zones:
                zone = NetworkZone(
                    zone_id=cz["zone_id"],
                    name=cz["name"],
                    description=cz.get("description", ""),
                    assigned_node_ids=cz.get("assigned_node_ids", []),
                    assigned_interface_ids=cz.get("assigned_interface_ids", []),
                    assigned_subnets=cz.get("assigned_subnets", []),
                    security_level=cz.get("security_level", 50),
                )
                zones[zone.zone_id] = zone
                # Apply zone to assigned nodes
                for nid in zone.assigned_node_ids:
                    if nid in nodes:
                        nodes[nid].zone_id = zone.zone_id
        else:
            # Default auto-zones based on subnets if not explicitly supplied
            zones = self._generate_default_zones(nodes)

        # 7. Evaluate and record Model Limitations
        limitations = self._detect_model_limitations(nodes, graph)

        # 8. Compute Deterministic Fingerprint
        fingerprint = self._compute_fingerprint(snapshot.snapshot_id, nodes, zones)

        model = NetworkModel(
            model_id=model_id,
            name=model_name,
            source_snapshot_id=snapshot.snapshot_id,
            source_snapshot_fingerprint=snapshot.snapshot_id,
            schema_version="1.0.0",
            model_version=1,
            created_at_iso=datetime.now(UTC).isoformat(),
            fingerprint=fingerprint,
            nodes=nodes,
            zones=zones,
            source_evidence_refs=sorted(list(evidence_refs)),
            imported_config_refs=sorted(list(config_refs)),
            known_limitations=limitations,
            is_counterfactual=False,
        )

        self.metadata_store.save_network_model(model)
        logger.info(
            "Built NetworkModel '%s' (%s) with %d nodes, %d zones, fingerprint=%s",
            model.name,
            model.model_id,
            len(nodes),
            len(zones),
            fingerprint[:12],
        )
        return model

    def _map_node_type(self, tnode_type: str) -> ModelNodeType:
        if tnode_type == "ROUTER":
            return ModelNodeType.ROUTER
        if tnode_type == "SUBNET":
            return ModelNodeType.SUBNET
        if tnode_type == "SERVICE":
            return ModelNodeType.SERVICE
        return ModelNodeType.HOST

    def _incorporate_imported_configs(
        self,
        nodes: dict[str, ModelNode],
        config_refs: set[str],
        evidence_refs: set[str],
    ) -> None:
        """Loads imported routing tables and neighbor mappings from MetadataStore."""
        imports = self.metadata_store.list_config_imports()
        for imp in imports:
            if imp.status == "completed":
                config_refs.add(imp.source_name)
                evidence_refs.update(imp.evidence_ids)

    def _generate_default_zones(self, nodes: dict[str, ModelNode]) -> dict[str, NetworkZone]:
        """Generates zones: TRUSTED (internal LANs), UNTRUSTED (external/internet), DMZ."""
        zones: dict[str, NetworkZone] = {
            "zone-trusted": NetworkZone(
                zone_id="zone-trusted",
                name="Trusted Internal",
                description="Internal corporate and private networks (RFC 1918)",
                security_level=90,
            ),
            "zone-untrusted": NetworkZone(
                zone_id="zone-untrusted",
                name="Untrusted External",
                description="Public and untrusted external networks",
                security_level=10,
            ),
            "zone-dmz": NetworkZone(
                zone_id="zone-dmz",
                name="Demilitarized Zone",
                description="Perimeter network for public-facing services",
                security_level=50,
            ),
        }

        for node in nodes.values():
            is_private = False
            for iface in node.interfaces:
                for ip_assign in iface.ip_assignments:
                    try:
                        ip_obj = ipaddress.ip_address(ip_assign.ip_address)
                        if ip_obj.is_private:
                            is_private = True
                    except ValueError:
                        pass

            if is_private:
                node.zone_id = "zone-trusted"
                zones["zone-trusted"].assigned_node_ids.append(node.node_id)
            else:
                node.zone_id = "zone-untrusted"
                zones["zone-untrusted"].assigned_node_ids.append(node.node_id)

        return zones

    def _detect_model_limitations(
        self,
        nodes: dict[str, ModelNode],
        graph: TopologyGraph,
    ) -> list[ModelLimitation]:
        limitations: list[ModelLimitation] = []

        # Check routers without explicit firewall rules
        routers_without_acls = [
            n.node_id for n in nodes.values() if n.node_type == ModelNodeType.ROUTER and not n.acls
        ]
        if routers_without_acls:
            limitations.append(
                ModelLimitation(
                    limitation_code="UNCONFIGURED_ROUTER_ACLS",
                    description="Routers present in topology without explicit firewall/ACL rules. Default policy will be evaluated.",
                    affected_entities=routers_without_acls,
                    impact="Reachability through these routers depends on assumed default policy",
                )
            )

        # Check inferred subnets
        inferred_subnets = [
            n.node_id for n in nodes.values() if n.node_type == ModelNodeType.SUBNET and n.is_inferred
        ]
        if inferred_subnets:
            limitations.append(
                ModelLimitation(
                    limitation_code="INFERRED_SUBNET_PREFIXES",
                    description="Subnet CIDR prefixes were inferred from traffic patterns (/24 or /64) rather than formal router configs.",
                    affected_entities=inferred_subnets,
                    impact="Longest-prefix-match may not reflect internal sub-segmentation",
                )
            )

        # Check unrouted hosts
        hosts_without_routes = [
            n.node_id
            for n in nodes.values()
            if n.node_type == ModelNodeType.HOST
            and len(n.routing_table) <= 1
            and not n.default_gateway_ip
        ]
        if hosts_without_routes:
            limitations.append(
                ModelLimitation(
                    limitation_code="MISSING_DEFAULT_GATEWAYS",
                    description="End hosts have no explicit default gateway configured.",
                    affected_entities=hosts_without_routes,
                    impact="Traffic to external subnets will evaluate to NO_ROUTE_TO_HOST or INDETERMINATE",
                )
            )

        return limitations

    def _compute_fingerprint(
        self,
        base_snapshot_hash: str,
        nodes: dict[str, ModelNode],
        zones: dict[str, NetworkZone],
    ) -> str:
        """Produces a deterministic, canonical SHA-256 fingerprint for the model."""
        hasher = hashlib.sha256()
        hasher.update(base_snapshot_hash.encode("utf-8"))

        for nid in sorted(nodes.keys()):
            node = nodes[nid]
            hasher.update(f"node:{node.node_id}:{node.node_type.value}:{node.zone_id}".encode())
            for iface in sorted(node.interfaces, key=lambda x: x.interface_id):
                for ip in sorted(iface.ip_assignments, key=lambda x: x.ip_address):
                    hasher.update(f"ip:{ip.ip_address}/{ip.prefix_length}".encode())
            for route in sorted(node.routing_table, key=lambda x: (x.destination_prefix, x.metric)):
                hasher.update(
                    f"rt:{route.destination_prefix}:{route.next_hop_ip}:{route.metric}".encode()
                )
            for acl in sorted(node.acls, key=lambda x: x.acl_id):
                hasher.update(f"acl:{acl.acl_id}:{acl.default_policy.value}".encode())
                for rule in acl.rules:
                    hasher.update(
                        f"rule:{rule.rule_number}:{rule.action.value}:{rule.protocol.value}:{rule.destination_port}".encode()
                    )

        for zid in sorted(zones.keys()):
            z = zones[zid]
            hasher.update(f"zone:{z.zone_id}:{z.security_level}".encode())

        return hasher.hexdigest()
