"""Unit tests for ScenarioEngine counterfactual simulation."""

import pytest

from network_twin.simulation.models import (
    AccessControlList,
    CounterfactualResult,
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


def test_scenario_resolves_firewall_alias_to_router(scenario_test_model: NetworkModel):
    """Verifies that an action targeting 'firewall-1' gracefully resolves to router-1."""
    engine = ScenarioEngine()
    scenario = SimulationScenario(
        scenario_id="scen-alias-test",
        name="Emergency Lockdown",
        description="Targeting firewall-1 which resolves to router-1",
        base_model_id=scenario_test_model.model_id,
        actions=[
            SimulationAction(
                action_type=SimulationActionType.ADD_FIREWALL_RULE,
                target_node_id="firewall-1",
                parameters={
                    "rule_id": "rule-deny-https",
                    "action": "DENY",
                    "direction": "INGRESS",
                    "protocol": "TCP",
                    "destination_port": 443,
                    "position": 0,
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

    assert result.applied_actions_count == 1
    assert result.newly_blocked_count == 1
    assert result.result_id == result.run_id
    assert len(result.path_differences) == 1
    assert result.path_differences[0].change_type == "NEWLY_BLOCKED"


def test_scenario_validation_catches_invalid_target_and_params(scenario_test_model: NetworkModel):
    """Verifies pre-execution validation catches non-existent nodes and invalid parameters."""
    engine = ScenarioEngine()
    # 1. Non-existent host target
    bad_scenario = SimulationScenario(
        scenario_id="scen-bad-target",
        name="Bad Target",
        base_model_id=scenario_test_model.model_id,
        actions=[
            SimulationAction(
                action_type=SimulationActionType.ADD_ROUTE,
                target_node_id="non-existent-device-xyz",
                parameters={"destination_prefix": "10.99.0.0/24"},
            )
        ],
    )
    errors = engine.validate_scenario(scenario_test_model, bad_scenario)
    assert len(errors) == 1
    assert "not found in model" in errors[0]

    # 2. Invalid CIDR parameter
    bad_param_scenario = SimulationScenario(
        scenario_id="scen-bad-cidr",
        name="Bad CIDR",
        base_model_id=scenario_test_model.model_id,
        actions=[
            SimulationAction(
                action_type=SimulationActionType.ADD_ROUTE,
                target_node_id="router-1",
                parameters={"destination_prefix": "999.999.999.999/99"},
            )
        ],
    )
    errors = engine.validate_scenario(scenario_test_model, bad_param_scenario)
    assert len(errors) == 1
    assert "Invalid CIDR prefix" in errors[0]


def test_counterfactual_result_contract_compatibility():
    """Verifies CounterfactualResult synchronizes dual frontend and backend fields."""
    res = CounterfactualResult(
        run_id="run-12345",
        scenario_id="scen-123",
        scenario_name="Test Scenario",
        base_model_id="model-base",
        baseline_fingerprint="fp-base",
        counterfactual_model_id="model-cf",
        counterfactual_fingerprint="fp-cf",
        applied_actions_count=1,
        newly_reachable_count=2,
        newly_blocked_count=3,
        invariant_regressions_count=1,
        summary_explanation="Test summary",
    )
    assert res.result_id == "run-12345"
    assert res.newly_reachable_paths_count == 2
    assert res.newly_blocked_paths_count == 3
    assert res.security_regressions_count == 1
    assert res.created_at_iso == res.executed_at_iso


def test_scenario_name_compounding_prevention(scenario_test_model: NetworkModel):
    """Verifies that running scenarios sequentially against cloned models does not compound tags."""
    engine = ScenarioEngine()
    scenario = SimulationScenario(
        scenario_id="scen-test-name",
        name="Emergency External Lockdown",
        base_model_id=scenario_test_model.model_id,
        actions=[
            SimulationAction(
                action_type=SimulationActionType.ADD_ROUTE,
                target_node_id="router-1",
                parameters={"destination_prefix": "10.99.0.0/24"},
            )
        ],
    )
    # First run
    cf1, _ = engine.run_scenario(scenario_test_model, scenario)
    assert cf1.name == "Scenario Test Network [Counterfactual: Emergency External Lockdown]"

    # Second run using cf1 as base model
    cf2, _ = engine.run_scenario(cf1, scenario)
    assert cf2.name == "Scenario Test Network [Counterfactual: Emergency External Lockdown]"
    assert "[Counterfactual: Emergency External Lockdown] [Counterfactual:" not in cf2.name


def test_metadata_store_counterfactual_model_filtering(tmp_path):
    """Verifies MetadataStore filters models by is_counterfactual flag."""
    from network_twin.config import AppSettings
    from network_twin.storage.metadata_store import MetadataStore

    test_settings = AppSettings(data_dir=str(tmp_path))
    store = MetadataStore(test_settings)

    base = NetworkModel(
        model_id="model-base-1",
        name="Base Network Model",
        source_snapshot_id="snap-1",
        source_snapshot_fingerprint="fp-snap-1",
        fingerprint="fp-base-1",
        is_counterfactual=False,
    )
    cf = NetworkModel(
        model_id="model-cf-1",
        name="Counterfactual Model",
        source_snapshot_id="snap-1",
        source_snapshot_fingerprint="fp-snap-1",
        fingerprint="fp-cf-1",
        is_counterfactual=True,
        parent_model_id="model-base-1",
    )

    store.save_network_model(base)
    store.save_network_model(cf)

    all_models = store.list_network_models()
    assert len(all_models) == 2

    baselines_only = store.list_network_models(is_counterfactual=False)
    assert len(baselines_only) == 1
    assert baselines_only[0].model_id == "model-base-1"

    counterfactuals_only = store.list_network_models(is_counterfactual=True)
    assert len(counterfactuals_only) == 1
    assert counterfactuals_only[0].model_id == "model-cf-1"
