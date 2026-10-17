"""Unit tests for ScenarioEngine counterfactual simulation."""

import pytest

from network_twin.simulation.models import (
    AccessControlList,
    DefaultPolicy,
    FirewallRule,
    IPAddressAssignment,
    ModelInterface,
    ModelNode,
    ModelNodeType,
    NetworkModel,
    ReachabilityQuery,
    ReachabilityStatus,
    RouteEntry,
    RouteType,
    RuleAction,
    RuleDirection,
    SimulationAction,
    SimulationActionType,
    SimulationScenario,
    TransportProtocolConstraint,
)
from network_twin.simulation.scenario_engine import ScenarioEngine


@pytest.fixture
def scenario_test_model() -> NetworkModel:
    """Creates a 2-node model where Host A and Host B are connected via a router."""
    node_a = ModelNode(
        node_id="host-a",
        label="Host A",
        node_type=ModelNodeType.HOST,
        interfaces=[
            ModelInterface(
                interface_id="if-a",
                node_id="host-a",
                name="eth0",
                ip_assignments=[IPAddressAssignment(ip_address="10.0.1.10", prefix_length=24)],
            )
        ],
        routing_table=[
            RouteEntry(
                route_id="r-a-conn",
                node_id="host-a",
                destination_prefix="10.0.1.0/24",
                prefix_length=24,
                route_type=RouteType.CONNECTED,
            ),
            RouteEntry(
                route_id="r-a-def",
                node_id="host-a",
                destination_prefix="0.0.0.0/0",
                prefix_length=0,
                next_hop_ip="10.0.1.1",
            ),
        ],
    )

    node_r = ModelNode(
        node_id="router-1",
        label="Router 1",
        node_type=ModelNodeType.ROUTER,
        interfaces=[
            ModelInterface(
                interface_id="if-r0",
                node_id="router-1",
                name="eth0",
                ip_assignments=[IPAddressAssignment(ip_address="10.0.1.1", prefix_length=24)],
            ),
            ModelInterface(
                interface_id="if-r1",
                node_id="router-1",
                name="eth1",
                ip_assignments=[IPAddressAssignment(ip_address="10.0.2.1", prefix_length=24)],
            ),
        ],
        routing_table=[
            RouteEntry(
                route_id="r-r-conn1",
                node_id="router-1",
                destination_prefix="10.0.1.0/24",
                prefix_length=24,
                route_type=RouteType.CONNECTED,
            ),
            RouteEntry(
                route_id="r-r-conn2",
                node_id="router-1",
                destination_prefix="10.0.2.0/24",
                prefix_length=24,
                route_type=RouteType.CONNECTED,
            ),
        ],
        acls=[
            AccessControlList(
                acl_id="acl-r",
                node_id="router-1",
                name="Filter",
                rules=[
                    FirewallRule(
                        rule_id="rule-allow-all",
                        node_id="router-1",
                        rule_number=1,
                        action=RuleAction.PERMIT,
                        direction=RuleDirection.INGRESS,
                    )
                ],
                default_policy=DefaultPolicy.DEFAULT_ALLOW,
            )
        ],
    )

    node_b = ModelNode(
        node_id="host-b",
        label="Host B",
        node_type=ModelNodeType.HOST,
        interfaces=[
            ModelInterface(
                interface_id="if-b",
                node_id="host-b",
                name="eth0",
                ip_assignments=[IPAddressAssignment(ip_address="10.0.2.20", prefix_length=24)],
            )
        ],
        routing_table=[
            RouteEntry(
                route_id="r-b-conn",
                node_id="host-b",
                destination_prefix="10.0.2.0/24",
                prefix_length=24,
                route_type=RouteType.CONNECTED,
            ),
            RouteEntry(
                route_id="r-b-def",
                node_id="host-b",
                destination_prefix="0.0.0.0/0",
                prefix_length=0,
                next_hop_ip="10.0.2.1",
            ),
        ],
    )

    return NetworkModel(
        model_id="scen-base-model",
        name="Scenario Test Network",
        source_snapshot_id="snap-scen-01",
        source_snapshot_fingerprint="scen-fp",
        nodes={"host-a": node_a, "router-1": node_r, "host-b": node_b},
        fingerprint="initial-model-fingerprint",
    )


def test_scenario_blocks_previously_reachable_path(scenario_test_model: NetworkModel):
    engine = ScenarioEngine()
    initial_fp = scenario_test_model.fingerprint

    # Scenario: Add DENY rule on Router 1 for port 443
    scenario = SimulationScenario(
        scenario_id="scen-block-https",
        name="Block HTTPS",
        description="Hypothetically block TCP 443 on Router 1",
        base_model_id=scenario_test_model.model_id,
        actions=[
            SimulationAction(
                action_type=SimulationActionType.ADD_FIREWALL_RULE,
                target_node_id="router-1",
                parameters={
                    "rule_id": "rule-deny-443",
                    "action": "DENY",
                    "direction": "INGRESS",
                    "protocol": "TCP",
                    "destination_port": 443,
                    "position": 0,  # Insert at top of ACL!
                },
            )
        ],
    )

    test_query = ReachabilityQuery(
        source_ip="10.0.1.10",
        destination_ip="10.0.2.20",
        protocol=TransportProtocolConstraint.TCP,
        destination_port=443,
    )

    cf_model, result = engine.run_scenario(
        scenario_test_model,
        scenario,
        test_queries=[test_query],
    )

    # 1. Base model must remain untouched
    assert scenario_test_model.fingerprint == initial_fp
    assert scenario_test_model.nodes["router-1"].acls[0].rules[0].rule_id == "rule-allow-all"

    # 2. Counterfactual model has the new rule and a new fingerprint
    assert cf_model.fingerprint != initial_fp
    assert cf_model.nodes["router-1"].acls[0].rules[0].rule_id == "rule-deny-443"

    # 3. Reachability difference must show newly blocked path
    assert result.newly_blocked_count == 1
    assert len(result.reachability_diffs) == 1
    diff = result.reachability_diffs[0]
    assert diff.baseline_status == ReachabilityStatus.REACHABLE
    assert diff.counterfactual_status == ReachabilityStatus.BLOCKED
    assert diff.change_type == "NEWLY_BLOCKED"


def test_scenario_adds_route_making_destination_reachable(scenario_test_model: NetworkModel):
    engine = ScenarioEngine()
    # Remove route to 10.0.2.0/24 on Router 1 so traffic to 10.0.2.20 is blocked
    scenario_test_model.nodes["router-1"].routing_table = [
        r for r in scenario_test_model.nodes["router-1"].routing_table if r.destination_prefix != "10.0.2.0/24"
    ]

    test_query = ReachabilityQuery(
        source_ip="10.0.1.10",
        destination_ip="10.0.2.20",
        protocol=TransportProtocolConstraint.TCP,
        destination_port=80,
    )

    # Counterfactual Scenario: Add static route to 10.0.2.0/24
    scenario = SimulationScenario(
        scenario_id="scen-add-route",
        name="Restore Subnet Route",
        description="Add missing route entry",
        base_model_id=scenario_test_model.model_id,
        actions=[
            SimulationAction(
                action_type=SimulationActionType.ADD_ROUTE,
                target_node_id="router-1",
                parameters={
                    "destination_prefix": "10.0.2.0/24",
                    "metric": 1,
                },
            )
        ],
    )

    cf_model, result = engine.run_scenario(
        scenario_test_model,
        scenario,
        test_queries=[test_query],
    )

    assert result.newly_reachable_count == 1
    diff = result.reachability_diffs[0]
    assert diff.baseline_status == ReachabilityStatus.BLOCKED
    assert diff.counterfactual_status == ReachabilityStatus.REACHABLE
    assert diff.change_type == "NEWLY_REACHABLE"
