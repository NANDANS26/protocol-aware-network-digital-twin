"""Counterfactual Simulation Engine.

Applies isolated hypothetical changes to a NetworkModel and compares reachability
and security invariant outcomes between baseline and counterfactual states.
"""

import copy
import hashlib
import ipaddress
import logging
import re
import uuid
from datetime import UTC, datetime

from network_twin.simulation.forwarding_engine import ForwardingEngine
from network_twin.simulation.models import (
    AccessControlList,
    AdministrativeState,
    CounterfactualResult,
    DefaultPolicy,
    FilterStatefulness,
    FirewallRule,
    InvariantDifference,
    IPAddressAssignment,
    NetworkModel,
    PathDifference,
    ReachabilityQuery,
    ReachabilityStatus,
    RouteEntry,
    RouteStatus,
    RouteType,
    RuleAction,
    RuleDirection,
    SecurityInvariant,
    SimulationAction,
    SimulationActionType,
    SimulationScenario,
    TransportProtocolConstraint,
)
from network_twin.simulation.verification_engine import VerificationEngine

logger = logging.getLogger(__name__)


class ScenarioEngine:
    """Executes counterfactual simulation scenarios against a base NetworkModel."""

    def __init__(
        self,
        forwarding_engine: ForwardingEngine | None = None,
        verification_engine: VerificationEngine | None = None,
    ):
        self.forwarding = forwarding_engine or ForwardingEngine()
        self.verification = verification_engine or VerificationEngine(self.forwarding)

    def run_scenario(
        self,
        base_model: NetworkModel,
        scenario: SimulationScenario,
        invariants: list[SecurityInvariant] | None = None,
        test_queries: list[ReachabilityQuery] | None = None,
    ) -> tuple[NetworkModel, CounterfactualResult]:
        """Runs hypothetical scenario in isolation, returning (counterfactual_model, result)."""
        validation_errors = self.validate_scenario(base_model, scenario)
        if validation_errors:
            raise ValueError("; ".join(validation_errors))

        run_id = f"run-{uuid.uuid4().hex[:12]}"

        # 1. Deep clone base model for total isolation
        cf_model = copy.deepcopy(base_model)
        cf_model.model_id = f"model-cf-{uuid.uuid4().hex[:10]}"
        clean_base_name = re.sub(r"(\s*\[Counterfactual:[^\]]*\])+", "", base_model.name).strip()
        cf_model.name = f"{clean_base_name} [Counterfactual: {scenario.name}]"
        cf_model.is_counterfactual = True
        cf_model.parent_model_id = base_model.model_id
        cf_model.created_at_iso = datetime.now(UTC).isoformat()

        # 2. Apply scenario actions
        for idx, action in enumerate(scenario.actions, start=1):
            self._apply_action(cf_model, action, idx)

        # 3. Recompute counterfactual model fingerprint
        cf_model.fingerprint = self._compute_fingerprint(cf_model)

        # 4. Generate or use test reachability queries across model nodes
        queries_to_test = test_queries or self._generate_representative_queries(base_model)

        reachability_diffs: list[PathDifference] = []
        newly_reachable = 0
        newly_blocked = 0

        for q in queries_to_test:
            res_base = self.forwarding.evaluate_reachability(base_model, q)
            res_cf = self.forwarding.evaluate_reachability(cf_model, q)

            if res_base.status != res_cf.status:
                if res_base.status != ReachabilityStatus.REACHABLE and res_cf.status == ReachabilityStatus.REACHABLE:
                    change_type = "NEWLY_REACHABLE"
                    newly_reachable += 1
                    explanation = f"Traffic from {q.source_ip} to {q.destination_ip}:{q.destination_port} became REACHABLE (previously {res_base.reason_code.value})."
                elif res_base.status == ReachabilityStatus.REACHABLE and res_cf.status != ReachabilityStatus.REACHABLE:
                    change_type = "NEWLY_BLOCKED"
                    newly_blocked += 1
                    explanation = f"Traffic from {q.source_ip} to {q.destination_ip}:{q.destination_port} became BLOCKED ({res_cf.reason_code.value})."
                else:
                    change_type = "PATH_CHANGED"
                    explanation = (
                        f"Reachability status transitioned from {res_base.status.value} to {res_cf.status.value}."
                    )

                reachability_diffs.append(
                    PathDifference(
                        source_ip=q.source_ip,
                        destination_ip=q.destination_ip,
                        protocol=q.protocol,
                        destination_port=q.destination_port,
                        baseline_status=res_base.status,
                        counterfactual_status=res_cf.status,
                        change_type=change_type,
                        explanation=explanation,
                        baseline_reason=res_base.reason_code.value
                        if hasattr(res_base, "reason_code") and res_base.reason_code
                        else None,
                        counterfactual_reason=res_cf.reason_code.value
                        if hasattr(res_cf, "reason_code") and res_cf.reason_code
                        else None,
                    )
                )

        # 5. Evaluate Invariants on baseline vs counterfactual
        invariant_diffs: list[InvariantDifference] = []
        regressions = 0

        if invariants:
            base_inv_results = {r.invariant_id: r for r in self.verification.verify_all(base_model, invariants)}
            cf_inv_results = {r.invariant_id: r for r in self.verification.verify_all(cf_model, invariants)}

            for inv in invariants:
                b_res = base_inv_results.get(inv.invariant_id)
                c_res = cf_inv_results.get(inv.invariant_id)
                if b_res and c_res and b_res.status != c_res.status:
                    if b_res.status.value == "PASS" and c_res.status.value == "FAIL":
                        regressions += 1
                        exp = f"REGRESSION: Security invariant '{inv.name}' changed from PASS to FAIL."
                    elif b_res.status.value == "FAIL" and c_res.status.value == "PASS":
                        exp = f"IMPROVEMENT: Security invariant '{inv.name}' changed from FAIL to PASS."
                    else:
                        exp = (
                            f"Invariant '{inv.name}' status shifted from {b_res.status.value} to {c_res.status.value}."
                        )

                    invariant_diffs.append(
                        InvariantDifference(
                            invariant_id=inv.invariant_id,
                            invariant_name=inv.name,
                            severity=inv.severity,
                            baseline_status=b_res.status,
                            counterfactual_status=c_res.status,
                            explanation=exp,
                        )
                    )

        summary = (
            f"Scenario '{scenario.name}' applied {len(scenario.actions)} action(s). "
            f"Result: {newly_reachable} newly reachable path(s), {newly_blocked} newly blocked path(s), "
            f"{regressions} invariant regression(s)."
        )

        result = CounterfactualResult(
            run_id=run_id,
            scenario_id=scenario.scenario_id,
            scenario_name=scenario.name,
            base_model_id=base_model.model_id,
            baseline_fingerprint=base_model.fingerprint,
            counterfactual_model_id=cf_model.model_id,
            counterfactual_fingerprint=cf_model.fingerprint,
            applied_actions_count=len(scenario.actions),
            reachability_diffs=reachability_diffs,
            invariant_diffs=invariant_diffs,
            newly_reachable_count=newly_reachable,
            newly_blocked_count=newly_blocked,
            invariant_regressions_count=regressions,
            summary_explanation=summary,
            executed_at_iso=datetime.now(UTC).isoformat(),
        )

        logger.info("Scenario execution complete: %s", summary)
        return cf_model, result

    @classmethod
    def resolve_target_node(
        cls,
        model: NetworkModel,
        target_node_id: str,
        action_type: SimulationActionType | None = None,
    ):
        """Deterministically resolves a target node ID, alias, or role to a concrete ModelNode."""
        if not target_node_id or not str(target_node_id).strip():
            raise KeyError("Target node ID cannot be empty.")

        tid = str(target_node_id).strip()

        # 1. Exact match
        if tid in model.nodes:
            return model.nodes[tid]

        # 2. Prefixed or stripped "node-" match
        if f"node-{tid}" in model.nodes:
            return model.nodes[f"node-{tid}"]
        if tid.startswith("node-") and tid[5:] in model.nodes:
            return model.nodes[tid[5:]]

        # 3. Case-insensitive node_id or label match
        tid_lower = tid.lower()
        for node in model.nodes.values():
            if node.node_id.lower() == tid_lower or (node.label and node.label.lower() == tid_lower):
                return node

        # 4. Partial / Substring label match (e.g. "Router: 192.168.1.1" matching "router")
        for node in model.nodes.values():
            if (node.label and tid_lower in node.label.lower()) or tid_lower in node.node_id.lower():
                return node

        # 5. Semantic Policy/Routing Role Alias Resolution (e.g. firewall-1, router-1, perimeter)
        is_firewall_query = any(k in tid_lower for k in ("firewall", "fw", "perimeter", "filter"))
        is_router_query = any(k in tid_lower for k in ("router", "gateway", "gw", "core"))

        firewall_nodes = [n for n in model.nodes.values() if n.node_type.value == "FIREWALL"]
        if is_firewall_query and firewall_nodes:
            logger.info(
                "Resolved target alias '%s' to FIREWALL node '%s' (%s)",
                tid,
                firewall_nodes[0].node_id,
                firewall_nodes[0].label,
            )
            return firewall_nodes[0]

        router_nodes = [n for n in model.nodes.values() if n.node_type.value == "ROUTER"]
        if router_nodes:
            is_firewall_action = (
                action_type
                in (
                    SimulationActionType.ADD_FIREWALL_RULE,
                    SimulationActionType.REMOVE_FIREWALL_RULE,
                    SimulationActionType.MODIFY_FIREWALL_RULE,
                    SimulationActionType.REORDER_FIREWALL_RULES,
                )
                if action_type
                else False
            )

            if is_firewall_query or is_router_query or is_firewall_action:
                preferred = next((r for r in router_nodes if r.acls), router_nodes[0])
                logger.info(
                    "Resolved target alias '%s' to policy enforcement ROUTER node '%s' (%s)",
                    tid,
                    preferred.node_id,
                    preferred.label,
                )
                return preferred

        if firewall_nodes:
            return firewall_nodes[0]

        available = [f"{n.node_id} ({n.label}, {n.node_type.value})" for n in list(model.nodes.values())[:8]]
        raise KeyError(
            f"Target node '{target_node_id}' not found in model '{model.model_id}'. "
            f"Available candidate nodes ({len(model.nodes)} total): {', '.join(available)}"
        )

    @classmethod
    def validate_scenario(
        cls,
        model: NetworkModel,
        scenario: SimulationScenario,
    ) -> list[str]:
        """Performs static pre-execution validation of scenario actions against a target model."""
        errors: list[str] = []
        if not scenario.actions:
            errors.append("Scenario must specify at least one action.")

        for idx, action in enumerate(scenario.actions, start=1):
            try:
                cls.resolve_target_node(model, action.target_node_id, action.action_type)
            except KeyError as e:
                errors.append(f"Action #{idx} ({action.action_type.value}): {e.args[0]}")
                continue

            params = action.parameters or {}
            if action.action_type == SimulationActionType.ADD_ROUTE:
                dest = params.get("destination_prefix")
                if not dest:
                    errors.append(f"Action #{idx} (ADD_ROUTE): 'destination_prefix' parameter is required.")
                else:
                    try:
                        ipaddress.ip_network(dest, strict=False)
                    except ValueError as ve:
                        errors.append(f"Action #{idx} (ADD_ROUTE): Invalid CIDR prefix '{dest}': {ve}")
            elif action.action_type == SimulationActionType.ADD_FIREWALL_RULE:
                action_val = params.get("action", "DENY")
                if action_val not in ("PERMIT", "DENY"):
                    errors.append(
                        f"Action #{idx} (ADD_FIREWALL_RULE): Invalid action '{action_val}'. Must be PERMIT or DENY."
                    )
                dir_val = params.get("direction", "INGRESS")
                if dir_val not in ("INGRESS", "EGRESS"):
                    errors.append(
                        f"Action #{idx} (ADD_FIREWALL_RULE): Invalid direction '{dir_val}'. Must be INGRESS or EGRESS."
                    )
                port = params.get("destination_port")
                if port is not None and not (isinstance(port, int) and 1 <= port <= 65535):
                    errors.append(f"Action #{idx} (ADD_FIREWALL_RULE): Port must be an integer between 1 and 65535.")

        return errors

    def _apply_action(
        self,
        model: NetworkModel,
        action: SimulationAction,
        action_index: int,
    ) -> None:
        """Applies a single simulation action deterministically with rigorous validation."""
        target_node = self.resolve_target_node(model, action.target_node_id, action.action_type)

        params = action.parameters

        if action.action_type == SimulationActionType.ADD_ROUTE:
            dest = params.get("destination_prefix")
            if not dest:
                raise ValueError(f"Action #{action_index}: 'destination_prefix' is required for ADD_ROUTE.")
            net = ipaddress.ip_network(dest, strict=False)

            route = RouteEntry(
                route_id=f"route-cf-{uuid.uuid4().hex[:8]}",
                node_id=target_node.node_id,
                destination_prefix=str(net),
                prefix_length=net.prefixlen,
                next_hop_ip=params.get("next_hop_ip"),
                output_interface_id=params.get("output_interface_id"),
                metric=params.get("metric", 1),
                admin_distance=params.get("admin_distance", 1),
                route_type=RouteType.STATIC,
                status=RouteStatus.ACTIVE,
                is_inferred=False,
            )
            target_node.routing_table.append(route)

        elif action.action_type == SimulationActionType.REMOVE_ROUTE:
            route_id = params.get("route_id")
            dest = params.get("destination_prefix")
            if not route_id and not dest:
                raise ValueError(f"Action #{action_index}: Either 'route_id' or 'destination_prefix' is required.")

            def _should_keep_route(r: RouteEntry) -> bool:
                if route_id and r.route_id == route_id:
                    return False
                if dest and r.destination_prefix == dest:
                    return False
                return True

            target_node.routing_table = [r for r in target_node.routing_table if _should_keep_route(r)]

        elif action.action_type == SimulationActionType.MODIFY_ROUTE:
            route_id = params.get("route_id")
            for r in target_node.routing_table:
                if r.route_id == route_id:
                    if "metric" in params:
                        r.metric = int(params["metric"])
                    if "next_hop_ip" in params:
                        r.next_hop_ip = str(params["next_hop_ip"])
                    if "status" in params:
                        r.status = RouteStatus(params["status"])

        elif action.action_type == SimulationActionType.ADD_FIREWALL_RULE:
            if not target_node.acls:
                target_node.acls.append(
                    AccessControlList(
                        acl_id=f"acl-{target_node.node_id}",
                        node_id=target_node.node_id,
                        name="Default ACL",
                        rules=[],
                        default_policy=DefaultPolicy.DEFAULT_ALLOW,
                    )
                )

            acl = target_node.acls[0]
            new_rule = FirewallRule(
                rule_id=params.get("rule_id", f"rule-cf-{uuid.uuid4().hex[:8]}"),
                node_id=target_node.node_id,
                rule_number=len(acl.rules) + 1,
                name=params.get("name", "Counterfactual Rule"),
                action=RuleAction(params.get("action", "DENY")),
                direction=RuleDirection(params.get("direction", "INGRESS")),
                source_prefix=params.get("source_prefix"),
                destination_prefix=params.get("destination_prefix"),
                protocol=TransportProtocolConstraint(params.get("protocol", "ANY")),
                destination_port=params.get("destination_port"),
                source_port=params.get("source_port"),
                statefulness=FilterStatefulness(params.get("statefulness", "STATELESS")),
                description=params.get("description", action.comment),
            )

            position = params.get("position")
            if position is not None and 0 <= position <= len(acl.rules):
                acl.rules.insert(position, new_rule)
                # Re-index rule numbers
                for idx, r in enumerate(acl.rules, start=1):
                    r.rule_number = idx
            else:
                acl.rules.append(new_rule)

        elif action.action_type == SimulationActionType.REMOVE_FIREWALL_RULE:
            rule_id = params.get("rule_id")
            for acl in target_node.acls:
                acl.rules = [r for r in acl.rules if r.rule_id != rule_id]

        elif action.action_type == SimulationActionType.MODIFY_FIREWALL_RULE:
            rule_id = params.get("rule_id")
            for acl in target_node.acls:
                for r in acl.rules:
                    if r.rule_id == rule_id:
                        if "action" in params:
                            r.action = RuleAction(params["action"])
                        if "destination_port" in params:
                            r.destination_port = params["destination_port"]
                        if "protocol" in params:
                            r.protocol = TransportProtocolConstraint(params["protocol"])

        elif action.action_type == SimulationActionType.REORDER_FIREWALL_RULES:
            order_ids = params.get("rule_order", [])
            for acl in target_node.acls:
                rule_map = {r.rule_id: r for r in acl.rules}
                new_rules = [rule_map[rid] for rid in order_ids if rid in rule_map]
                # append any remaining rules
                for r in acl.rules:
                    if r not in new_rules:
                        new_rules.append(r)
                for idx, r in enumerate(new_rules, start=1):
                    r.rule_number = idx
                acl.rules = new_rules

        elif action.action_type == SimulationActionType.MODIFY_INTERFACE_IP:
            iface_id = params.get("interface_id")
            new_ip = params.get("new_ip")
            new_prefix = params.get("new_prefix_length", 24)
            if not new_ip:
                raise ValueError("new_ip is required for MODIFY_INTERFACE_IP")

            for iface in target_node.interfaces:
                if iface.interface_id == iface_id or not iface_id:
                    if iface.ip_assignments:
                        iface.ip_assignments[0].ip_address = new_ip
                        iface.ip_assignments[0].prefix_length = new_prefix
                    else:
                        iface.ip_assignments.append(
                            IPAddressAssignment(
                                ip_address=new_ip,
                                prefix_length=new_prefix,
                            )
                        )
                    break

        elif action.action_type == SimulationActionType.SET_INTERFACE_STATE:
            iface_id = params.get("interface_id")
            new_state = AdministrativeState(params.get("state", "UP"))
            for iface in target_node.interfaces:
                if iface.interface_id == iface_id or not iface_id:
                    iface.state = new_state

        elif action.action_type == SimulationActionType.SET_ZONE_ASSIGNMENT:
            new_zone = params.get("zone_id")
            target_node.zone_id = new_zone
            if new_zone and new_zone in model.zones:
                if target_node.node_id not in model.zones[new_zone].assigned_node_ids:
                    model.zones[new_zone].assigned_node_ids.append(target_node.node_id)

    def _generate_representative_queries(self, model: NetworkModel) -> list[ReachabilityQuery]:
        """Generates representative reachability queries across model nodes."""
        all_ips: list[str] = []
        for node in model.nodes.values():
            for iface in node.interfaces:
                for ip in iface.ip_assignments:
                    all_ips.append(ip.ip_address)

        queries: list[ReachabilityQuery] = []
        # Pair nodes
        for i in range(len(all_ips)):
            for j in range(len(all_ips)):
                if i != j:
                    queries.append(
                        ReachabilityQuery(
                            source_ip=all_ips[i],
                            destination_ip=all_ips[j],
                            protocol=TransportProtocolConstraint.TCP,
                            destination_port=443,
                        )
                    )
                    queries.append(
                        ReachabilityQuery(
                            source_ip=all_ips[i],
                            destination_ip=all_ips[j],
                            protocol=TransportProtocolConstraint.TCP,
                            destination_port=80,
                        )
                    )
        return queries[:20]

    def _compute_fingerprint(self, model: NetworkModel) -> str:
        """Deterministic fingerprint of model state."""
        hasher = hashlib.sha256()
        hasher.update(model.source_snapshot_fingerprint.encode("utf-8"))

        for nid in sorted(model.nodes.keys()):
            node = model.nodes[nid]
            hasher.update(f"node:{node.node_id}:{node.node_type.value}:{node.zone_id}".encode())
            for iface in sorted(node.interfaces, key=lambda x: x.interface_id):
                hasher.update(f"iface:{iface.interface_id}:{iface.state.value}".encode())
                for ip in sorted(iface.ip_assignments, key=lambda x: x.ip_address):
                    hasher.update(f"ip:{ip.ip_address}/{ip.prefix_length}".encode())
            for route in sorted(node.routing_table, key=lambda x: (x.destination_prefix, x.metric)):
                hasher.update(
                    f"rt:{route.destination_prefix}:{route.next_hop_ip}:{route.metric}:{route.status.value}".encode()
                )
            for acl in sorted(node.acls, key=lambda x: x.acl_id):
                hasher.update(f"acl:{acl.acl_id}:{acl.default_policy.value}".encode())
                for rule in acl.rules:
                    hasher.update(
                        f"rule:{rule.rule_number}:{rule.action.value}:{rule.protocol.value}:{rule.destination_port}:{rule.direction.value}".encode()
                    )

        return hasher.hexdigest()
