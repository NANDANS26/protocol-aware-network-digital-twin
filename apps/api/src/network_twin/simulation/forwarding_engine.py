"""Deterministic Packet-Forwarding and Reachability Engine.

Implements IPv4/IPv6 longest-prefix-match (LPM) routing, next-hop resolution,
ordered ACL rule evaluation, loop detection, and explainable path trace generation.
"""

import ipaddress
import logging
import uuid
from typing import Any

from network_twin.simulation.models import (
    BlockingRule,
    DefaultPolicy,
    ModelNode,
    ModelNodeType,
    NetworkModel,
    PathHop,
    ReachabilityQuery,
    ReachabilityResult,
    ReachabilityStatus,
    ReasonCode,
    RouteEntry,
    RuleAction,
    RuleDirection,
    TransportProtocolConstraint,
)

logger = logging.getLogger(__name__)


class ForwardingEngine:
    """Deterministic, formal packet forwarding simulator."""

    def __init__(self, max_hops: int = 32):
        self.max_hops = max_hops

    def evaluate_reachability(
        self,
        model: NetworkModel,
        query: ReachabilityQuery,
    ) -> ReachabilityResult:
        """Evaluates whether traffic can traverse from source_ip to destination_ip."""
        query_id = f"reach-{uuid.uuid4().hex[:12]}"

        # 1. Validate IP syntax
        try:
            src_addr = ipaddress.ip_address(query.source_ip)
            dst_addr = ipaddress.ip_address(query.destination_ip)
        except ValueError as e:
            return ReachabilityResult(
                query_id=query_id,
                model_id=model.model_id,
                model_fingerprint=model.fingerprint,
                source_ip=query.source_ip,
                destination_ip=query.destination_ip,
                protocol=query.protocol,
                destination_port=query.destination_port,
                status=ReachabilityStatus.BLOCKED,
                reason_code=ReasonCode.INSUFFICIENT_FORWARDING_STATE,
                explanation=f"Malformed IP address in reachability query: {e}",
            )

        # 2. Locate Source Node
        source_node = self._find_node_by_ip(model, src_addr)
        if not source_node:
            # Check if source is on a modeled subnet
            source_subnet_node = self._find_subnet_for_ip(model, src_addr)
            if not source_subnet_node:
                return ReachabilityResult(
                    query_id=query_id,
                    model_id=model.model_id,
                    model_fingerprint=model.fingerprint,
                    source_ip=query.source_ip,
                    destination_ip=query.destination_ip,
                    protocol=query.protocol,
                    destination_port=query.destination_port,
                    status=ReachabilityStatus.INDETERMINATE,
                    reason_code=ReasonCode.SOURCE_UNKNOWN,
                    explanation=(
                        f"Source IP {query.source_ip} does not belong to any modeled interface or subnet."
                    ),
                    limitations=["Source host not mapped in digital twin model"],
                )
            source_node = source_subnet_node

        # 3. Locate Destination Node (optional at start, used for termination check)
        dest_node = self._find_node_by_ip(model, dst_addr)

        # 4. Hop-by-hop forwarding simulation
        current_node = source_node
        visited_nodes: list[str] = []
        path: list[PathHop] = []
        hop_index = 0
        policy_eval_count = 0
        route_decision_count = 0
        evidence_ids: set[str] = set()

        while hop_index < self.max_hops:
            # Check if reached destination
            if current_node == dest_node or self._node_owns_ip(current_node, dst_addr):
                # Final ingress ACL check on destination node
                acl_result, matched_rule, reason = self._evaluate_acls(
                    current_node,
                    query,
                    src_addr,
                    dst_addr,
                    direction=RuleDirection.INGRESS,
                )
                policy_eval_count += 1
                if acl_result == RuleAction.DENY:
                    blocking = BlockingRule(
                        node_id=current_node.node_id,
                        node_label=current_node.label,
                        rule_id=matched_rule.rule_id if matched_rule else None,
                        rule_number=matched_rule.rule_number if matched_rule else None,
                        rule_action=RuleAction.DENY,
                        direction=RuleDirection.INGRESS,
                        reason_code=reason,
                        explanation=f"Traffic blocked at destination {current_node.label} by ingress policy",
                    )
                    return ReachabilityResult(
                        query_id=query_id,
                        model_id=model.model_id,
                        model_fingerprint=model.fingerprint,
                        source_ip=query.source_ip,
                        destination_ip=query.destination_ip,
                        protocol=query.protocol,
                        destination_port=query.destination_port,
                        status=ReachabilityStatus.BLOCKED,
                        reason_code=reason,
                        path=path,
                        blocking_rule=blocking,
                        evaluated_policy_count=policy_eval_count,
                        route_decisions_count=route_decision_count,
                        explanation=(
                            f"Packet reached destination node '{current_node.label}' but was dropped by ingress firewall rule."
                        ),
                        evidence_ids=sorted(list(evidence_ids)),
                    )

                path.append(
                    PathHop(
                        hop_index=hop_index,
                        node_id=current_node.node_id,
                        node_label=current_node.label,
                        notes="Packet delivered to destination host interface",
                    )
                )

                return ReachabilityResult(
                    query_id=query_id,
                    model_id=model.model_id,
                    model_fingerprint=model.fingerprint,
                    source_ip=query.source_ip,
                    destination_ip=query.destination_ip,
                    protocol=query.protocol,
                    destination_port=query.destination_port,
                    status=ReachabilityStatus.REACHABLE,
                    reason_code=ReasonCode.REACHABLE,
                    path=path,
                    evaluated_policy_count=policy_eval_count,
                    route_decisions_count=route_decision_count,
                    explanation=(
                        f"End-to-end path verified successfully from {query.source_ip} to {query.destination_ip} via {len(path)} hops."
                    ),
                    evidence_ids=sorted(list(evidence_ids)),
                )

            # Loop detection
            if current_node.node_id in visited_nodes:
                return ReachabilityResult(
                    query_id=query_id,
                    model_id=model.model_id,
                    model_fingerprint=model.fingerprint,
                    source_ip=query.source_ip,
                    destination_ip=query.destination_ip,
                    protocol=query.protocol,
                    destination_port=query.destination_port,
                    status=ReachabilityStatus.BLOCKED,
                    reason_code=ReasonCode.FORWARDING_LOOP_DETECTED,
                    path=path,
                    evaluated_policy_count=policy_eval_count,
                    route_decisions_count=route_decision_count,
                    explanation=(
                        f"Forwarding loop detected: Node '{current_node.label}' ({current_node.node_id}) already visited."
                    ),
                    evidence_ids=sorted(list(evidence_ids)),
                )

            visited_nodes.append(current_node.node_id)

            # If arriving at an intermediate hop, evaluate Ingress ACL on current node
            if hop_index > 0:
                acl_result, matched_rule, reason = self._evaluate_acls(
                    current_node,
                    query,
                    src_addr,
                    dst_addr,
                    direction=RuleDirection.INGRESS,
                )
                policy_eval_count += 1
                if acl_result == RuleAction.DENY:
                    blocking = BlockingRule(
                        node_id=current_node.node_id,
                        node_label=current_node.label,
                        rule_id=matched_rule.rule_id if matched_rule else None,
                        rule_number=matched_rule.rule_number if matched_rule else None,
                        rule_action=RuleAction.DENY,
                        direction=RuleDirection.INGRESS,
                        reason_code=reason,
                        explanation=f"Traffic blocked at {current_node.label} by ingress policy",
                    )
                    return ReachabilityResult(
                        query_id=query_id,
                        model_id=model.model_id,
                        model_fingerprint=model.fingerprint,
                        source_ip=query.source_ip,
                        destination_ip=query.destination_ip,
                        protocol=query.protocol,
                        destination_port=query.destination_port,
                        status=ReachabilityStatus.BLOCKED,
                        reason_code=reason,
                        path=path,
                        blocking_rule=blocking,
                        evaluated_policy_count=policy_eval_count,
                        route_decisions_count=route_decision_count,
                        explanation=f"Packet dropped at hop {hop_index} ({current_node.label}) by ingress firewall rule.",
                        evidence_ids=sorted(list(evidence_ids)),
                    )

            # Evaluate Egress ACL on current node
            acl_result, matched_rule, reason = self._evaluate_acls(
                current_node,
                query,
                src_addr,
                dst_addr,
                direction=RuleDirection.EGRESS,
            )
            policy_eval_count += 1
            if acl_result == RuleAction.DENY:
                blocking = BlockingRule(
                    node_id=current_node.node_id,
                    node_label=current_node.label,
                    rule_id=matched_rule.rule_id if matched_rule else None,
                    rule_number=matched_rule.rule_number if matched_rule else None,
                    rule_action=RuleAction.DENY,
                    direction=RuleDirection.EGRESS,
                    reason_code=reason,
                    explanation=f"Traffic blocked at {current_node.label} by egress policy",
                )
                return ReachabilityResult(
                    query_id=query_id,
                    model_id=model.model_id,
                    model_fingerprint=model.fingerprint,
                    source_ip=query.source_ip,
                    destination_ip=query.destination_ip,
                    protocol=query.protocol,
                    destination_port=query.destination_port,
                    status=ReachabilityStatus.BLOCKED,
                    reason_code=reason,
                    path=path,
                    blocking_rule=blocking,
                    evaluated_policy_count=policy_eval_count,
                    route_decisions_count=route_decision_count,
                    explanation=f"Packet dropped at hop {hop_index} ({current_node.label}) by egress firewall rule.",
                    evidence_ids=sorted(list(evidence_ids)),
                )

            # Longest-Prefix-Match Routing Decision
            selected_route = self._lookup_route(current_node, dst_addr)
            route_decision_count += 1

            if not selected_route:
                # If no route, check default gateway
                if current_node.default_gateway_ip:
                    gw_ip = ipaddress.ip_address(current_node.default_gateway_ip)
                    next_node = self._find_node_by_ip(model, gw_ip)
                    if next_node:
                        path.append(
                            PathHop(
                                hop_index=hop_index,
                                node_id=current_node.node_id,
                                node_label=current_node.label,
                                routed_destination_prefix="0.0.0.0/0 (Default Gateway)",
                                next_hop_ip=current_node.default_gateway_ip,
                                notes="Forwarded via default gateway",
                            )
                        )
                        current_node = next_node
                        hop_index += 1
                        continue

                return ReachabilityResult(
                    query_id=query_id,
                    model_id=model.model_id,
                    model_fingerprint=model.fingerprint,
                    source_ip=query.source_ip,
                    destination_ip=query.destination_ip,
                    protocol=query.protocol,
                    destination_port=query.destination_port,
                    status=ReachabilityStatus.BLOCKED,
                    reason_code=ReasonCode.NO_ROUTE_TO_HOST,
                    path=path,
                    evaluated_policy_count=policy_eval_count,
                    route_decisions_count=route_decision_count,
                    explanation=(
                        f"No route to destination {query.destination_ip} on node '{current_node.label}'."
                    ),
                    evidence_ids=sorted(list(evidence_ids)),
                )

            evidence_ids.update(selected_route.source_evidence_ids)

            # Route resolution: Connected link vs Next-Hop
            if selected_route.route_type.value == "CONNECTED" or not selected_route.next_hop_ip:
                # Destination is on local link of current node
                if dest_node:
                    path.append(
                        PathHop(
                            hop_index=hop_index,
                            node_id=current_node.node_id,
                            node_label=current_node.label,
                            routed_destination_prefix=selected_route.destination_prefix,
                            notes=f"Directly connected to destination network {selected_route.destination_prefix}",
                        )
                    )
                    current_node = dest_node
                    hop_index += 1
                    continue
                else:
                    # Destination node itself isn't a modeled host, but prefix is connected
                    path.append(
                        PathHop(
                            hop_index=hop_index,
                            node_id=current_node.node_id,
                            node_label=current_node.label,
                            routed_destination_prefix=selected_route.destination_prefix,
                            notes="Destination IP matches connected subnet; target host unmodeled",
                        )
                    )
                    return ReachabilityResult(
                        query_id=query_id,
                        model_id=model.model_id,
                        model_fingerprint=model.fingerprint,
                        source_ip=query.source_ip,
                        destination_ip=query.destination_ip,
                        protocol=query.protocol,
                        destination_port=query.destination_port,
                        status=ReachabilityStatus.REACHABLE,
                        reason_code=ReasonCode.REACHABLE,
                        path=path,
                        evaluated_policy_count=policy_eval_count,
                        route_decisions_count=route_decision_count,
                        explanation=(
                            f"Packet successfully routed to connected network {selected_route.destination_prefix}."
                        ),
                        evidence_ids=sorted(list(evidence_ids)),
                    )

            # Next-Hop recursion
            try:
                next_hop_addr = ipaddress.ip_address(selected_route.next_hop_ip)
            except ValueError:
                return ReachabilityResult(
                    query_id=query_id,
                    model_id=model.model_id,
                    model_fingerprint=model.fingerprint,
                    source_ip=query.source_ip,
                    destination_ip=query.destination_ip,
                    protocol=query.protocol,
                    destination_port=query.destination_port,
                    status=ReachabilityStatus.BLOCKED,
                    reason_code=ReasonCode.UNRESOLVED_NEXT_HOP,
                    path=path,
                    explanation=(
                        f"Invalid next-hop IP '{selected_route.next_hop_ip}' in route on node '{current_node.label}'."
                    ),
                )

            next_node = self._find_node_by_ip(model, next_hop_addr)
            if not next_node:
                return ReachabilityResult(
                    query_id=query_id,
                    model_id=model.model_id,
                    model_fingerprint=model.fingerprint,
                    source_ip=query.source_ip,
                    destination_ip=query.destination_ip,
                    protocol=query.protocol,
                    destination_port=query.destination_port,
                    status=ReachabilityStatus.BLOCKED,
                    reason_code=ReasonCode.UNRESOLVED_NEXT_HOP,
                    path=path,
                    explanation=(
                        f"Unresolved next hop {selected_route.next_hop_ip} on node '{current_node.label}'."
                    ),
                    evidence_ids=sorted(list(evidence_ids)),
                )

            path.append(
                PathHop(
                    hop_index=hop_index,
                    node_id=current_node.node_id,
                    node_label=current_node.label,
                    routed_destination_prefix=selected_route.destination_prefix,
                    next_hop_ip=selected_route.next_hop_ip,
                    notes=f"LPM route match: {selected_route.destination_prefix} via {selected_route.next_hop_ip}",
                )
            )

            current_node = next_node
            hop_index += 1

        # Hop limit exceeded
        return ReachabilityResult(
            query_id=query_id,
            model_id=model.model_id,
            model_fingerprint=model.fingerprint,
            source_ip=query.source_ip,
            destination_ip=query.destination_ip,
            protocol=query.protocol,
            destination_port=query.destination_port,
            status=ReachabilityStatus.BLOCKED,
            reason_code=ReasonCode.HOP_LIMIT_EXCEEDED,
            path=path,
            evaluated_policy_count=policy_eval_count,
            route_decisions_count=route_decision_count,
            explanation=f"Forwarding hop limit ({self.max_hops}) exceeded without reaching destination.",
            evidence_ids=sorted(list(evidence_ids)),
        )

    def _lookup_route(self, node: ModelNode, dst_addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> RouteEntry | None:
        """Finds longest-prefix-match route on node."""
        matching_routes: list[RouteEntry] = []

        for route in node.routing_table:
            if route.status.value != "ACTIVE":
                continue
            try:
                net = ipaddress.ip_network(route.destination_prefix, strict=False)
                if dst_addr in net:
                    matching_routes.append(route)
            except ValueError:
                continue

        if not matching_routes:
            return None

        # Sort:
        # 1. Prefix length descending (Longest Prefix Match)
        # 2. Administrative distance ascending
        # 3. Metric ascending
        # 4. Route ID ascending (deterministic tie-breaker)
        matching_routes.sort(
            key=lambda r: (-r.prefix_length, r.admin_distance, r.metric, r.route_id)
        )
        return matching_routes[0]

    def _evaluate_acls(
        self,
        node: ModelNode,
        query: ReachabilityQuery,
        src_addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
        dst_addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
        direction: RuleDirection,
    ) -> tuple[RuleAction, Any, ReasonCode]:
        """Evaluates ordered firewall rules for a given direction. Returns (Action, MatchedRule, ReasonCode)."""
        if not node.acls:
            # No ACLs defined -> implicit allow
            return RuleAction.PERMIT, None, ReasonCode.REACHABLE

        for acl in node.acls:
            # If the ACL defines rules, it only filters directions it specifies
            if acl.rules:
                directional_rules = [
                    r for r in acl.rules if r.direction in (direction, RuleDirection.BOTH)
                ]
                if not directional_rules:
                    continue
            else:
                directional_rules = []

            for rule in directional_rules:
                # Match protocol
                if rule.protocol != TransportProtocolConstraint.ANY and rule.protocol != query.protocol:
                    continue

                # Match destination port
                if rule.destination_port is not None and query.destination_port is not None:
                    if rule.destination_port != query.destination_port:
                        continue

                # Match source port
                if rule.source_port is not None and query.source_port is not None:
                    if rule.source_port != query.source_port:
                        continue

                # Match source prefix
                if rule.source_prefix:
                    try:
                        src_net = ipaddress.ip_network(rule.source_prefix, strict=False)
                        if src_addr not in src_net:
                            continue
                    except ValueError:
                        continue

                # Match destination prefix
                if rule.destination_prefix:
                    try:
                        dst_net = ipaddress.ip_network(rule.destination_prefix, strict=False)
                        if dst_addr not in dst_net:
                            continue
                    except ValueError:
                        continue

                # First match
                if rule.action == RuleAction.PERMIT:
                    return RuleAction.PERMIT, rule, ReasonCode.REACHABLE
                else:
                    return RuleAction.DENY, rule, ReasonCode.DROPPED_BY_FIREWALL

            # Default policy if no rule matched in this directional ACL
            if acl.default_policy == DefaultPolicy.DEFAULT_DENY:
                return RuleAction.DENY, None, ReasonCode.DROPPED_BY_DEFAULT_POLICY
            else:
                return RuleAction.PERMIT, None, ReasonCode.REACHABLE

        return RuleAction.PERMIT, None, ReasonCode.REACHABLE

    def _find_node_by_ip(
        self,
        model: NetworkModel,
        ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    ) -> ModelNode | None:
        """Finds the node owning the specified IP address."""
        for node in model.nodes.values():
            if self._node_owns_ip(node, ip):
                return node
        return None

    def _node_owns_ip(
        self,
        node: ModelNode,
        ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    ) -> bool:
        for iface in node.interfaces:
            if iface.state.value != "UP":
                continue
            for assign in iface.ip_assignments:
                try:
                    if ipaddress.ip_address(assign.ip_address) == ip:
                        return True
                except ValueError:
                    continue
        return False

    def _find_subnet_for_ip(
        self,
        model: NetworkModel,
        ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    ) -> ModelNode | None:
        """Finds a SUBNET node enclosing the given IP."""
        for node in model.nodes.values():
            if node.node_type == ModelNodeType.SUBNET:
                cidr = node.metadata.get("cidr")
                if cidr:
                    try:
                        net = ipaddress.ip_network(cidr, strict=False)
                        if ip in net:
                            return node
                    except ValueError:
                        continue
        return None
