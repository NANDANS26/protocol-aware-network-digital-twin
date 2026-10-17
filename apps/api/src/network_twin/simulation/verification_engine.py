"""Deterministic Security Invariant Verification Engine.

Evaluates formal policy invariants against a NetworkModel using the ForwardingEngine:
1. Isolation
2. Required Reachability
3. Port Restriction
4. Management-Plane Isolation
5. Path Constraints
6. Forbidden Exposure
7. Configuration Consistency
"""

import ipaddress
import logging
import uuid

from network_twin.simulation.forwarding_engine import ForwardingEngine
from network_twin.simulation.models import (
    InvariantStatus,
    InvariantType,
    NetworkModel,
    ReachabilityQuery,
    ReachabilityStatus,
    SecurityInvariant,
    TransportProtocolConstraint,
    VerificationResult,
)

logger = logging.getLogger(__name__)


class VerificationEngine:
    """Evaluates security invariants against a formal NetworkModel."""

    def __init__(self, forwarding_engine: ForwardingEngine | None = None):
        self.forwarding = forwarding_engine or ForwardingEngine()

    def verify_all(
        self,
        model: NetworkModel,
        invariants: list[SecurityInvariant],
    ) -> list[VerificationResult]:
        """Runs the complete invariant verification suite."""
        results: list[VerificationResult] = []
        for inv in invariants:
            res = self.verify_invariant(model, inv)
            results.append(res)
        return results

    def verify_invariant(
        self,
        model: NetworkModel,
        invariant: SecurityInvariant,
    ) -> VerificationResult:
        """Dispatches invariant evaluation based on type."""
        try:
            if invariant.invariant_type == InvariantType.ISOLATION:
                return self._verify_isolation(model, invariant)
            elif invariant.invariant_type == InvariantType.REQUIRED_REACHABILITY:
                return self._verify_required_reachability(model, invariant)
            elif invariant.invariant_type == InvariantType.PORT_RESTRICTION:
                return self._verify_port_restriction(model, invariant)
            elif invariant.invariant_type == InvariantType.MANAGEMENT_PLANE_ISOLATION:
                return self._verify_management_plane(model, invariant)
            elif invariant.invariant_type == InvariantType.PATH_CONSTRAINTS:
                return self._verify_path_constraints(model, invariant)
            elif invariant.invariant_type == InvariantType.FORBIDDEN_EXPOSURE:
                return self._verify_forbidden_exposure(model, invariant)
            elif invariant.invariant_type == InvariantType.CONFIGURATION_CONSISTENCY:
                return self._verify_configuration_consistency(model, invariant)
            else:
                return VerificationResult(
                    result_id=f"ver-{uuid.uuid4().hex[:12]}",
                    invariant_id=invariant.invariant_id,
                    invariant_name=invariant.name,
                    invariant_type=invariant.invariant_type,
                    severity=invariant.severity,
                    status=InvariantStatus.NOT_APPLICABLE,
                    reason_code="UNSUPPORTED_INVARIANT_TYPE",
                    explanation=f"Invariant type '{invariant.invariant_type.value}' is not supported.",
                    model_id=model.model_id,
                    model_fingerprint=model.fingerprint,
                )
        except Exception as e:
            logger.error("Error evaluating invariant %s: %s", invariant.invariant_id, e)
            return VerificationResult(
                result_id=f"ver-{uuid.uuid4().hex[:12]}",
                invariant_id=invariant.invariant_id,
                invariant_name=invariant.name,
                invariant_type=invariant.invariant_type,
                severity=invariant.severity,
                status=InvariantStatus.INDETERMINATE,
                reason_code="EVALUATION_ERROR",
                explanation=f"Unexpected error evaluating invariant: {e}",
                model_id=model.model_id,
                model_fingerprint=model.fingerprint,
            )

    def _verify_isolation(
        self,
        model: NetworkModel,
        invariant: SecurityInvariant,
    ) -> VerificationResult:
        """Verifies that source zone/prefix cannot reach protected destination zone/prefix."""
        defn = invariant.definition
        src_ips = self._resolve_target_ips(model, defn.source_zone_or_cidr)
        dst_ips = self._resolve_target_ips(model, defn.destination_zone_or_cidr or defn.protected_zone)

        if not src_ips or not dst_ips:
            return VerificationResult(
                result_id=f"ver-{uuid.uuid4().hex[:12]}",
                invariant_id=invariant.invariant_id,
                invariant_name=invariant.name,
                invariant_type=invariant.invariant_type,
                severity=invariant.severity,
                status=InvariantStatus.INDETERMINATE,
                reason_code="UNRESOLVED_TARGETS",
                explanation="Could not resolve source or destination endpoints for isolation check.",
                model_id=model.model_id,
                model_fingerprint=model.fingerprint,
                limitations=["Target zone or subnet has no active IP addresses in model"],
            )

        for src_ip in src_ips:
            for dst_ip in dst_ips:
                query = ReachabilityQuery(
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    protocol=TransportProtocolConstraint.TCP,
                    destination_port=80,
                )
                reach = self.forwarding.evaluate_reachability(model, query)
                if reach.status == ReachabilityStatus.REACHABLE:
                    return VerificationResult(
                        result_id=f"ver-{uuid.uuid4().hex[:12]}",
                        invariant_id=invariant.invariant_id,
                        invariant_name=invariant.name,
                        invariant_type=invariant.invariant_type,
                        severity=invariant.severity,
                        status=InvariantStatus.FAIL,
                        reason_code="ISOLATION_VIOLATION",
                        explanation=f"Isolation violation: Path established from {src_ip} to protected destination {dst_ip}.",
                        witness_path=reach.path,
                        model_id=model.model_id,
                        model_fingerprint=model.fingerprint,
                        evidence_ids=reach.evidence_ids,
                    )
                elif reach.status == ReachabilityStatus.INDETERMINATE:
                    return VerificationResult(
                        result_id=f"ver-{uuid.uuid4().hex[:12]}",
                        invariant_id=invariant.invariant_id,
                        invariant_name=invariant.name,
                        invariant_type=invariant.invariant_type,
                        severity=invariant.severity,
                        status=InvariantStatus.INDETERMINATE,
                        reason_code="ROUTING_INDETERMINATE",
                        explanation=f"Could not conclusively verify isolation: {reach.explanation}",
                        model_id=model.model_id,
                        model_fingerprint=model.fingerprint,
                        limitations=reach.limitations,
                    )

        return VerificationResult(
            result_id=f"ver-{uuid.uuid4().hex[:12]}",
            invariant_id=invariant.invariant_id,
            invariant_name=invariant.name,
            invariant_type=invariant.invariant_type,
            severity=invariant.severity,
            status=InvariantStatus.PASS,
            reason_code="ISOLATION_ENFORCED",
            explanation=f"Isolation successfully verified across {len(src_ips)} sources and {len(dst_ips)} destinations.",
            model_id=model.model_id,
            model_fingerprint=model.fingerprint,
        )

    def _verify_required_reachability(
        self,
        model: NetworkModel,
        invariant: SecurityInvariant,
    ) -> VerificationResult:
        """Verifies that an approved source can reach a designated service."""
        defn = invariant.definition
        src_ips = self._resolve_target_ips(model, defn.source_zone_or_cidr)
        service_ip = defn.service_ip
        service_port = defn.service_port or 443

        if not src_ips or not service_ip:
            return VerificationResult(
                result_id=f"ver-{uuid.uuid4().hex[:12]}",
                invariant_id=invariant.invariant_id,
                invariant_name=invariant.name,
                invariant_type=invariant.invariant_type,
                severity=invariant.severity,
                status=InvariantStatus.INDETERMINATE,
                reason_code="UNRESOLVED_SERVICE_OR_SOURCE",
                explanation="Required reachability check could not resolve source IPs or service IP.",
                model_id=model.model_id,
                model_fingerprint=model.fingerprint,
            )

        for src_ip in src_ips:
            query = ReachabilityQuery(
                source_ip=src_ip,
                destination_ip=service_ip,
                protocol=TransportProtocolConstraint.TCP,
                destination_port=service_port,
            )
            reach = self.forwarding.evaluate_reachability(model, query)
            if reach.status != ReachabilityStatus.REACHABLE:
                return VerificationResult(
                    result_id=f"ver-{uuid.uuid4().hex[:12]}",
                    invariant_id=invariant.invariant_id,
                    invariant_name=invariant.name,
                    invariant_type=invariant.invariant_type,
                    severity=invariant.severity,
                    status=InvariantStatus.FAIL,
                    reason_code="REQUIRED_SERVICE_UNREACHABLE",
                    explanation=f"Required service at {service_ip}:{service_port} is unreachable from {src_ip}: {reach.explanation}",
                    blocking_rule=reach.blocking_rule,
                    model_id=model.model_id,
                    model_fingerprint=model.fingerprint,
                    evidence_ids=reach.evidence_ids,
                )

        return VerificationResult(
            result_id=f"ver-{uuid.uuid4().hex[:12]}",
            invariant_id=invariant.invariant_id,
            invariant_name=invariant.name,
            invariant_type=invariant.invariant_type,
            severity=invariant.severity,
            status=InvariantStatus.PASS,
            reason_code="REACHABILITY_VERIFIED",
            explanation=f"All {len(src_ips)} approved sources can successfully reach {service_ip}:{service_port}.",
            model_id=model.model_id,
            model_fingerprint=model.fingerprint,
        )

    def _verify_port_restriction(
        self,
        model: NetworkModel,
        invariant: SecurityInvariant,
    ) -> VerificationResult:
        """Verifies that a service is ONLY reachable on approved ports."""
        defn = invariant.definition
        service_ip = defn.service_ip
        allowed_ports = defn.allowed_ports or [443]

        if not service_ip:
            return VerificationResult(
                result_id=f"ver-{uuid.uuid4().hex[:12]}",
                invariant_id=invariant.invariant_id,
                invariant_name=invariant.name,
                invariant_type=invariant.invariant_type,
                severity=invariant.severity,
                status=InvariantStatus.INDETERMINATE,
                reason_code="MISSING_SERVICE_IP",
                explanation="No service IP specified for port restriction verification.",
                model_id=model.model_id,
                model_fingerprint=model.fingerprint,
            )

        # Probe representative unapproved ports
        probe_ports = [21, 22, 23, 80, 8080, 3389]
        unapproved_probes = [p for p in probe_ports if p not in allowed_ports]

        # Select probe source IP
        src_ip = None
        if defn.source_zone_or_cidr:
            candidates = self._resolve_target_ips(model, defn.source_zone_or_cidr)
            if candidates:
                src_ip = candidates[0]

        if not src_ip:
            try:
                svc_addr = ipaddress.ip_address(service_ip)
                candidates_list: list[tuple[int, str]] = []
                for node in model.nodes.values():
                    is_untrusted = 1 if (node.zone_id and "untrusted" in node.zone_id.lower()) else 0
                    for iface in node.interfaces:
                        for ip_assign in iface.ip_assignments:
                            try:
                                ip_obj = ipaddress.ip_address(ip_assign.ip_address)
                                if ip_obj != svc_addr:
                                    net = ipaddress.ip_network(
                                        f"{ip_assign.ip_address}/{ip_assign.prefix_length}", strict=False
                                    )
                                    is_diff_subnet = 1 if svc_addr not in net else 0
                                    score = (is_untrusted * 2) + is_diff_subnet
                                    candidates_list.append((score, ip_assign.ip_address))
                            except ValueError:
                                continue
                if candidates_list:
                    candidates_list.sort(key=lambda c: -c[0])
                    src_ip = candidates_list[0][1]
            except ValueError:
                pass

        if not src_ip:
            src_ip = "192.168.1.254"

        for port in unapproved_probes:
            query = ReachabilityQuery(
                source_ip=src_ip,
                destination_ip=service_ip,
                protocol=TransportProtocolConstraint.TCP,
                destination_port=port,
            )
            reach = self.forwarding.evaluate_reachability(model, query)
            if reach.status == ReachabilityStatus.REACHABLE:
                return VerificationResult(
                    result_id=f"ver-{uuid.uuid4().hex[:12]}",
                    invariant_id=invariant.invariant_id,
                    invariant_name=invariant.name,
                    invariant_type=invariant.invariant_type,
                    severity=invariant.severity,
                    status=InvariantStatus.FAIL,
                    reason_code="UNAUTHORIZED_PORT_EXPOSURE",
                    explanation=f"Unintended port exposure: Service at {service_ip} accepts traffic on unapproved port {port}.",
                    witness_path=reach.path,
                    model_id=model.model_id,
                    model_fingerprint=model.fingerprint,
                )

        return VerificationResult(
            result_id=f"ver-{uuid.uuid4().hex[:12]}",
            invariant_id=invariant.invariant_id,
            invariant_name=invariant.name,
            invariant_type=invariant.invariant_type,
            severity=invariant.severity,
            status=InvariantStatus.PASS,
            reason_code="PORT_RESTRICTIONS_ENFORCED",
            explanation=f"Port restriction verified: Non-approved ports ({unapproved_probes}) are safely blocked.",
            model_id=model.model_id,
            model_fingerprint=model.fingerprint,
        )

    def _verify_management_plane(
        self,
        model: NetworkModel,
        invariant: SecurityInvariant,
    ) -> VerificationResult:
        """Verifies that management plane interfaces are only accessible from authorized sources."""
        defn = invariant.definition
        authorized_cidrs = defn.authorized_source_cidrs or ["10.0.0.0/8"]
        mgmt_node_id = defn.management_interface_id

        mgmt_node = model.nodes.get(mgmt_node_id) if mgmt_node_id else None
        if not mgmt_node:
            # Check for any node with label 'router' or 'firewall'
            for n in model.nodes.values():
                if n.node_type.value in ("ROUTER", "FIREWALL"):
                    mgmt_node = n
                    break

        if not mgmt_node or not mgmt_node.interfaces:
            return VerificationResult(
                result_id=f"ver-{uuid.uuid4().hex[:12]}",
                invariant_id=invariant.invariant_id,
                invariant_name=invariant.name,
                invariant_type=invariant.invariant_type,
                severity=invariant.severity,
                status=InvariantStatus.NOT_APPLICABLE,
                reason_code="NO_MANAGEMENT_INTERFACE",
                explanation="No management interface found to verify management plane isolation.",
                model_id=model.model_id,
                model_fingerprint=model.fingerprint,
            )

        mgmt_ip = mgmt_node.interfaces[0].ip_assignments[0].ip_address

        # Probe from an unauthorized IP (not in authorized_cidrs)
        unauth_ip = "192.168.99.99"
        for candidate in ["192.168.99.99", "172.16.99.99", "203.0.113.99"]:
            cand_obj = ipaddress.ip_address(candidate)
            if not any(cand_obj in ipaddress.ip_network(c, strict=False) for c in authorized_cidrs):
                unauth_ip = candidate
                break
        query = ReachabilityQuery(
            source_ip=unauth_ip,
            destination_ip=mgmt_ip,
            protocol=TransportProtocolConstraint.TCP,
            destination_port=22,
        )
        reach = self.forwarding.evaluate_reachability(model, query)
        if reach.status == ReachabilityStatus.REACHABLE:
            return VerificationResult(
                result_id=f"ver-{uuid.uuid4().hex[:12]}",
                invariant_id=invariant.invariant_id,
                invariant_name=invariant.name,
                invariant_type=invariant.invariant_type,
                severity=invariant.severity,
                status=InvariantStatus.FAIL,
                reason_code="MANAGEMENT_PLANE_EXPOSED",
                explanation=f"Management interface {mgmt_ip}:22 is reachable from unauthorized source {unauth_ip}.",
                witness_path=reach.path,
                model_id=model.model_id,
                model_fingerprint=model.fingerprint,
            )

        return VerificationResult(
            result_id=f"ver-{uuid.uuid4().hex[:12]}",
            invariant_id=invariant.invariant_id,
            invariant_name=invariant.name,
            invariant_type=invariant.invariant_type,
            severity=invariant.severity,
            status=InvariantStatus.PASS,
            reason_code="MANAGEMENT_PLANE_ISOLATED",
            explanation=f"Management plane on {mgmt_ip} successfully protected against unauthorized probes.",
            model_id=model.model_id,
            model_fingerprint=model.fingerprint,
        )

    def _verify_path_constraints(
        self,
        model: NetworkModel,
        invariant: SecurityInvariant,
    ) -> VerificationResult:
        """Verifies that traffic traverses required nodes and avoids prohibited nodes."""
        defn = invariant.definition
        src_ips = self._resolve_target_ips(model, defn.source_zone_or_cidr)
        dst_ips = self._resolve_target_ips(model, defn.destination_zone_or_cidr)
        req_nodes = set(defn.required_intermediate_nodes)
        prohib_nodes = set(defn.prohibited_intermediate_nodes)

        if not src_ips or not dst_ips:
            return VerificationResult(
                result_id=f"ver-{uuid.uuid4().hex[:12]}",
                invariant_id=invariant.invariant_id,
                invariant_name=invariant.name,
                invariant_type=invariant.invariant_type,
                severity=invariant.severity,
                status=InvariantStatus.INDETERMINATE,
                reason_code="UNRESOLVED_ENDPOINTS",
                explanation="Path constraint endpoints could not be resolved.",
                model_id=model.model_id,
                model_fingerprint=model.fingerprint,
            )

        query = ReachabilityQuery(
            source_ip=src_ips[0],
            destination_ip=dst_ips[0],
            protocol=TransportProtocolConstraint.TCP,
            destination_port=443,
        )
        reach = self.forwarding.evaluate_reachability(model, query)

        if reach.status != ReachabilityStatus.REACHABLE:
            return VerificationResult(
                result_id=f"ver-{uuid.uuid4().hex[:12]}",
                invariant_id=invariant.invariant_id,
                invariant_name=invariant.name,
                invariant_type=invariant.invariant_type,
                severity=invariant.severity,
                status=InvariantStatus.FAIL,
                reason_code="PATH_UNREACHABLE",
                explanation=f"Cannot evaluate path constraints because path is unreachable: {reach.explanation}",
                model_id=model.model_id,
                model_fingerprint=model.fingerprint,
            )

        traversed_nodes = {h.node_id for h in reach.path}

        # Check required nodes
        missing_req = req_nodes - traversed_nodes
        if missing_req:
            return VerificationResult(
                result_id=f"ver-{uuid.uuid4().hex[:12]}",
                invariant_id=invariant.invariant_id,
                invariant_name=invariant.name,
                invariant_type=invariant.invariant_type,
                severity=invariant.severity,
                status=InvariantStatus.FAIL,
                reason_code="MISSING_REQUIRED_HOP",
                explanation=f"Path failed to traverse required nodes: {missing_req}",
                witness_path=reach.path,
                model_id=model.model_id,
                model_fingerprint=model.fingerprint,
            )

        # Check prohibited nodes
        violated_prohib = prohib_nodes.intersection(traversed_nodes)
        if violated_prohib:
            return VerificationResult(
                result_id=f"ver-{uuid.uuid4().hex[:12]}",
                invariant_id=invariant.invariant_id,
                invariant_name=invariant.name,
                invariant_type=invariant.invariant_type,
                severity=invariant.severity,
                status=InvariantStatus.FAIL,
                reason_code="PROHIBITED_HOP_TRAVERSED",
                explanation=f"Path traversed prohibited nodes: {violated_prohib}",
                witness_path=reach.path,
                model_id=model.model_id,
                model_fingerprint=model.fingerprint,
            )

        return VerificationResult(
            result_id=f"ver-{uuid.uuid4().hex[:12]}",
            invariant_id=invariant.invariant_id,
            invariant_name=invariant.name,
            invariant_type=invariant.invariant_type,
            severity=invariant.severity,
            status=InvariantStatus.PASS,
            reason_code="PATH_CONSTRAINTS_SATISFIED",
            explanation="Path successfully satisfied all intermediate node traversal constraints.",
            witness_path=reach.path,
            model_id=model.model_id,
            model_fingerprint=model.fingerprint,
        )

    def _verify_forbidden_exposure(
        self,
        model: NetworkModel,
        invariant: SecurityInvariant,
    ) -> VerificationResult:
        """Verifies that an internal service/IP cannot be reached from an untrusted zone."""
        defn = invariant.definition
        internal_ip = defn.service_ip or defn.destination_zone_or_cidr
        untrusted_zone_id = defn.untrusted_zone or "zone-untrusted"

        untrusted_ips: list[str] = []
        if untrusted_zone_id in model.zones:
            zone = model.zones[untrusted_zone_id]
            for nid in zone.assigned_node_ids:
                if nid in model.nodes:
                    for iface in model.nodes[nid].interfaces:
                        untrusted_ips.extend(ip.ip_address for ip in iface.ip_assignments)

        if not untrusted_ips:
            # Synthetic public IP test
            untrusted_ips = ["198.51.100.1"]

        for u_ip in untrusted_ips:
            query = ReachabilityQuery(
                source_ip=u_ip,
                destination_ip=str(internal_ip),
                protocol=TransportProtocolConstraint.TCP,
                destination_port=defn.service_port or 80,
            )
            reach = self.forwarding.evaluate_reachability(model, query)
            if reach.status == ReachabilityStatus.REACHABLE:
                return VerificationResult(
                    result_id=f"ver-{uuid.uuid4().hex[:12]}",
                    invariant_id=invariant.invariant_id,
                    invariant_name=invariant.name,
                    invariant_type=invariant.invariant_type,
                    severity=invariant.severity,
                    status=InvariantStatus.FAIL,
                    reason_code="FORBIDDEN_EXPOSURE_DETECTED",
                    explanation=f"Internal target {internal_ip} is directly reachable from untrusted IP {u_ip}.",
                    witness_path=reach.path,
                    model_id=model.model_id,
                    model_fingerprint=model.fingerprint,
                )

        return VerificationResult(
            result_id=f"ver-{uuid.uuid4().hex[:12]}",
            invariant_id=invariant.invariant_id,
            invariant_name=invariant.name,
            invariant_type=invariant.invariant_type,
            severity=invariant.severity,
            status=InvariantStatus.PASS,
            reason_code="EXPOSURE_PREVENTED",
            explanation=f"Target {internal_ip} is safely blocked from untrusted network access.",
            model_id=model.model_id,
            model_fingerprint=model.fingerprint,
        )

    def _verify_configuration_consistency(
        self,
        model: NetworkModel,
        invariant: SecurityInvariant,
    ) -> VerificationResult:
        """Detects contradictory routes, duplicate prefixes, unresolved next-hops, and invalid configs."""
        anomalies: list[str] = []

        for node in model.nodes.values():
            # Check duplicate identical prefixes with equal metric pointing to different next-hops
            seen_prefixes: dict[str, str | None] = {}
            for r in node.routing_table:
                if r.status.value != "ACTIVE":
                    continue
                key = f"{r.destination_prefix}-{r.metric}"
                if key in seen_prefixes:
                    if seen_prefixes[key] != r.next_hop_ip:
                        anomalies.append(
                            f"Node '{node.label}': Contradictory routing entry for {r.destination_prefix} with next-hops {seen_prefixes[key]} vs {r.next_hop_ip}."
                        )
                else:
                    seen_prefixes[key] = r.next_hop_ip

                # Check if next hop is valid IP
                if r.next_hop_ip:
                    try:
                        ipaddress.ip_address(r.next_hop_ip)
                    except ValueError:
                        anomalies.append(
                            f"Node '{node.label}': Invalid next-hop IP syntax '{r.next_hop_ip}' in route {r.route_id}."
                        )

            # Check ACL rule overlap / contradictions
            for acl in node.acls:
                seen_rules: set[str] = set()
                for rule in acl.rules:
                    rule_key = f"{rule.direction.value}-{rule.protocol.value}-{rule.source_prefix}-{rule.destination_prefix}-{rule.destination_port}"
                    if rule_key in seen_rules:
                        anomalies.append(
                            f"Node '{node.label}', ACL '{acl.name}': Redundant or shadowed rule {rule.rule_id} for {rule_key}."
                        )
                    seen_rules.add(rule_key)

        if anomalies:
            return VerificationResult(
                result_id=f"ver-{uuid.uuid4().hex[:12]}",
                invariant_id=invariant.invariant_id,
                invariant_name=invariant.name,
                invariant_type=invariant.invariant_type,
                severity=invariant.severity,
                status=InvariantStatus.FAIL,
                reason_code="CONFIGURATION_INCONSISTENCY",
                explanation=f"Configuration inconsistencies detected: {'; '.join(anomalies[:3])}",
                model_id=model.model_id,
                model_fingerprint=model.fingerprint,
                limitations=anomalies,
            )

        return VerificationResult(
            result_id=f"ver-{uuid.uuid4().hex[:12]}",
            invariant_id=invariant.invariant_id,
            invariant_name=invariant.name,
            invariant_type=invariant.invariant_type,
            severity=invariant.severity,
            status=InvariantStatus.PASS,
            reason_code="CONFIGURATIONS_CONSISTENT",
            explanation="No contradictory routes, invalid next-hops, or shadowed firewall rules detected.",
            model_id=model.model_id,
            model_fingerprint=model.fingerprint,
        )

    def _resolve_target_ips(self, model: NetworkModel, target: str | None) -> list[str]:
        """Resolves target string which could be a zone_id, a CIDR prefix, or an explicit IP."""
        if not target:
            return []

        # Check if zone ID
        if target in model.zones:
            zone = model.zones[target]
            ips: list[str] = []
            for nid in zone.assigned_node_ids:
                if nid in model.nodes:
                    for iface in model.nodes[nid].interfaces:
                        ips.extend(assign.ip_address for assign in iface.ip_assignments)
            return ips

        # Check if CIDR
        if "/" in target:
            try:
                net = ipaddress.ip_network(target, strict=False)
                matched: list[str] = []
                for n in model.nodes.values():
                    for iface in n.interfaces:
                        for assign in iface.ip_assignments:
                            try:
                                if ipaddress.ip_address(assign.ip_address) in net:
                                    matched.append(assign.ip_address)
                            except ValueError:
                                pass
                if matched:
                    return matched
                # If no hosts in model on this subnet, return first usable IP
                return [str(list(net.hosts())[0])]
            except ValueError:
                pass

        # Check if single IP
        try:
            ipaddress.ip_address(target)
            return [target]
        except ValueError:
            pass

        # Check node label or ID
        if target in model.nodes:
            n = model.nodes[target]
            return [assign.ip_address for iface in n.interfaces for assign in iface.ip_assignments]

        return []
