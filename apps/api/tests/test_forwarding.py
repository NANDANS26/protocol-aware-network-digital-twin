"""Unit tests for deterministic packet-forwarding and reachability engine."""

import pytest

from network_twin.simulation.forwarding_engine import ForwardingEngine
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
    ReasonCode,
    RouteEntry,
    RouteType,
    RuleAction,
    RuleDirection,
    TransportProtocolConstraint,
)


@pytest.fixture
def base_network() -> NetworkModel:
    """Builds a deterministic 3-node network: HostA -> Router1 -> HostB."""
    # Host A (10.0.1.10/24)
    iface_a = ModelInterface(
        interface_id="if-a0",
        node_id="host-a",
        name="eth0",
        ip_assignments=[IPAddressAssignment(ip_address="10.0.1.10", prefix_length=24)],
    )
    route_a_conn = RouteEntry(
        route_id="r-a-conn",
        node_id="host-a",
        destination_prefix="10.0.1.0/24",
        prefix_length=24,
        route_type=RouteType.CONNECTED,
    )
    route_a_def = RouteEntry(
        route_id="r-a-def",
        node_id="host-a",
        destination_prefix="0.0.0.0/0",
        prefix_length=0,
        next_hop_ip="10.0.1.1",
        route_type=RouteType.STATIC,
    )
    node_a = ModelNode(
        node_id="host-a",
        label="Host A",
        node_type=ModelNodeType.HOST,
        interfaces=[iface_a],
        routing_table=[route_a_conn, route_a_def],
    )

    # Router 1 (eth0: 10.0.1.1/24, eth1: 10.0.2.1/24)
    iface_r0 = ModelInterface(
        interface_id="if-r0",
        node_id="router-1",
        name="eth0",
        ip_assignments=[IPAddressAssignment(ip_address="10.0.1.1", prefix_length=24)],
    )
    iface_r1 = ModelInterface(
        interface_id="if-r1",
        node_id="router-1",
        name="eth1",
        ip_assignments=[IPAddressAssignment(ip_address="10.0.2.1", prefix_length=24)],
    )
    route_r_conn1 = RouteEntry(
        route_id="r-r-conn1",
        node_id="router-1",
        destination_prefix="10.0.1.0/24",
        prefix_length=24,
        route_type=RouteType.CONNECTED,
    )
    route_r_conn2 = RouteEntry(
        route_id="r-r-conn2",
        node_id="router-1",
        destination_prefix="10.0.2.0/24",
        prefix_length=24,
        route_type=RouteType.CONNECTED,
    )
    node_r = ModelNode(
        node_id="router-1",
        label="Router 1",
        node_type=ModelNodeType.ROUTER,
        interfaces=[iface_r0, iface_r1],
        routing_table=[route_r_conn1, route_r_conn2],
    )

    # Host B (10.0.2.20/24)
    iface_b = ModelInterface(
        interface_id="if-b0",
        node_id="host-b",
        name="eth0",
        ip_assignments=[IPAddressAssignment(ip_address="10.0.2.20", prefix_length=24)],
    )
    route_b_conn = RouteEntry(
        route_id="r-b-conn",
        node_id="host-b",
        destination_prefix="10.0.2.0/24",
        prefix_length=24,
        route_type=RouteType.CONNECTED,
    )
    route_b_def = RouteEntry(
        route_id="r-b-def",
        node_id="host-b",
        destination_prefix="0.0.0.0/0",
        prefix_length=0,
        next_hop_ip="10.0.2.1",
        route_type=RouteType.STATIC,
    )
    node_b = ModelNode(
        node_id="host-b",
        label="Host B",
        node_type=ModelNodeType.HOST,
        interfaces=[iface_b],
        routing_table=[route_b_conn, route_b_def],
    )

    return NetworkModel(
        model_id="test-model-01",
        name="Test 3-Node Network",
        source_snapshot_id="snap-test-01",
        source_snapshot_fingerprint="test-fingerprint-01",
        nodes={"host-a": node_a, "router-1": node_r, "host-b": node_b},
        fingerprint="test-fingerprint-model",
    )


def test_reachability_basic_flow(base_network: NetworkModel):
    engine = ForwardingEngine()
    query = ReachabilityQuery(
        source_ip="10.0.1.10",
        destination_ip="10.0.2.20",
        protocol=TransportProtocolConstraint.TCP,
        destination_port=443,
    )
    result = engine.evaluate_reachability(base_network, query)

    assert result.status == ReachabilityStatus.REACHABLE
    assert result.reason_code == ReasonCode.REACHABLE
    assert len(result.path) >= 2
    assert result.path[0].node_id == "host-a"
    assert result.path[-1].node_id == "host-b"


def test_longest_prefix_match(base_network: NetworkModel):
    engine = ForwardingEngine()
    router = base_network.nodes["router-1"]

    # Add general /16 route and specific /28 route
    router.routing_table.append(
        RouteEntry(
            route_id="r-gen",
            node_id="router-1",
            destination_prefix="192.168.0.0/16",
            prefix_length=16,
            next_hop_ip="10.0.2.100",
            metric=10,
        )
    )
    router.routing_table.append(
        RouteEntry(
            route_id="r-spec",
            node_id="router-1",
            destination_prefix="192.168.1.0/28",
            prefix_length=28,
            next_hop_ip="10.0.2.20",
            metric=50,  # higher metric, but more specific prefix!
        )
    )

    query = ReachabilityQuery(
        source_ip="10.0.1.10",
        destination_ip="192.168.1.5",
        protocol=TransportProtocolConstraint.TCP,
        destination_port=80,
    )
    result = engine.evaluate_reachability(base_network, query)

    # Route hop at router-1 must select r-spec (/28) over r-gen (/16)
    router_hop = next((h for h in result.path if h.node_id == "router-1"), None)
    assert router_hop is not None
    assert router_hop.routed_destination_prefix == "192.168.1.0/28"
    assert router_hop.next_hop_ip == "10.0.2.20"


def test_no_route_to_host(base_network: NetworkModel):
    engine = ForwardingEngine()
    # Remove default route on host-a
    base_network.nodes["host-a"].routing_table = [
        r for r in base_network.nodes["host-a"].routing_table if r.destination_prefix != "0.0.0.0/0"
    ]

    query = ReachabilityQuery(
        source_ip="10.0.1.10",
        destination_ip="172.16.0.1",
        protocol=TransportProtocolConstraint.TCP,
        destination_port=443,
    )
    result = engine.evaluate_reachability(base_network, query)

    assert result.status == ReachabilityStatus.BLOCKED
    assert result.reason_code == ReasonCode.NO_ROUTE_TO_HOST
    assert "No route" in result.explanation


def test_unresolved_next_hop(base_network: NetworkModel):
    engine = ForwardingEngine()
    base_network.nodes["router-1"].routing_table.append(
        RouteEntry(
            route_id="r-blackhole",
            node_id="router-1",
            destination_prefix="172.16.0.0/16",
            prefix_length=16,
            next_hop_ip="10.99.99.99",  # unmodeled, unresolved IP
        )
    )

    query = ReachabilityQuery(
        source_ip="10.0.1.10",
        destination_ip="172.16.5.5",
        protocol=TransportProtocolConstraint.TCP,
        destination_port=443,
    )
    result = engine.evaluate_reachability(base_network, query)

    assert result.status == ReachabilityStatus.BLOCKED
    assert result.reason_code == ReasonCode.UNRESOLVED_NEXT_HOP


def test_ordered_firewall_evaluation(base_network: NetworkModel):
    engine = ForwardingEngine()
    router = base_network.nodes["router-1"]

    # Rule 1: PERMIT TCP 443
    rule_permit = FirewallRule(
        rule_id="r-permit-https",
        node_id="router-1",
        rule_number=1,
        action=RuleAction.PERMIT,
        direction=RuleDirection.INGRESS,
        protocol=TransportProtocolConstraint.TCP,
        destination_port=443,
    )
    # Rule 2: DENY TCP ANY
    rule_deny = FirewallRule(
        rule_id="r-deny-all",
        node_id="router-1",
        rule_number=2,
        action=RuleAction.DENY,
        direction=RuleDirection.INGRESS,
        protocol=TransportProtocolConstraint.TCP,
    )

    router.acls.append(
        AccessControlList(
            acl_id="acl-router",
            node_id="router-1",
            name="Ingress Filter",
            rules=[rule_permit, rule_deny],
            default_policy=DefaultPolicy.DEFAULT_DENY,
        )
    )

    # Test Port 443 -> should PERMIT
    q_443 = ReachabilityQuery(
        source_ip="10.0.1.10",
        destination_ip="10.0.2.20",
        protocol=TransportProtocolConstraint.TCP,
        destination_port=443,
    )
    res_443 = engine.evaluate_reachability(base_network, q_443)
    assert res_443.status == ReachabilityStatus.REACHABLE

    # Test Port 80 -> should DENY by rule 2
    q_80 = ReachabilityQuery(
        source_ip="10.0.1.10",
        destination_ip="10.0.2.20",
        protocol=TransportProtocolConstraint.TCP,
        destination_port=80,
    )
    res_80 = engine.evaluate_reachability(base_network, q_80)
    assert res_80.status == ReachabilityStatus.BLOCKED
    assert res_80.reason_code == ReasonCode.DROPPED_BY_FIREWALL
    assert res_80.blocking_rule is not None
    assert res_80.blocking_rule.rule_id == "r-deny-all"


def test_forwarding_loop_detection(base_network: NetworkModel):
    engine = ForwardingEngine()
    # Create static routing loop: Router 1 points 10.0.2.0/24 to Host A, Host A points to Router 1
    router = base_network.nodes["router-1"]
    router.routing_table = [
        RouteEntry(
            route_id="r-loop",
            node_id="router-1",
            destination_prefix="10.0.2.0/24",
            prefix_length=24,
            next_hop_ip="10.0.1.10",  # points back to host-a!
        )
    ]

    query = ReachabilityQuery(
        source_ip="10.0.1.10",
        destination_ip="10.0.2.20",
        protocol=TransportProtocolConstraint.TCP,
        destination_port=80,
    )
    result = engine.evaluate_reachability(base_network, query)

    assert result.status == ReachabilityStatus.BLOCKED
    assert result.reason_code == ReasonCode.FORWARDING_LOOP_DETECTED


def test_ipv6_reachability():
    engine = ForwardingEngine()
    # Create IPv6 network: fd00:1::10 -> fd00:1::1 / fd00:2::1 -> fd00:2::20
    iface_a = ModelInterface(
        interface_id="if-a6",
        node_id="host-a6",
        name="eth0",
        ip_assignments=[IPAddressAssignment(ip_address="fd00:1::10", prefix_length=64)],
    )
    node_a = ModelNode(
        node_id="host-a6",
        label="Host A IPv6",
        node_type=ModelNodeType.HOST,
        interfaces=[iface_a],
        routing_table=[
            RouteEntry(
                route_id="r6-a-conn",
                node_id="host-a6",
                destination_prefix="fd00:1::/64",
                prefix_length=64,
                route_type=RouteType.CONNECTED,
            ),
            RouteEntry(
                route_id="r6-a-def",
                node_id="host-a6",
                destination_prefix="::/0",
                prefix_length=0,
                next_hop_ip="fd00:1::1",
            ),
        ],
    )

    iface_r0 = ModelInterface(
        interface_id="if-r6-0",
        node_id="router-6",
        name="eth0",
        ip_assignments=[IPAddressAssignment(ip_address="fd00:1::1", prefix_length=64)],
    )
    iface_r1 = ModelInterface(
        interface_id="if-r6-1",
        node_id="router-6",
        name="eth1",
        ip_assignments=[IPAddressAssignment(ip_address="fd00:2::1", prefix_length=64)],
    )
    node_r = ModelNode(
        node_id="router-6",
        label="Router IPv6",
        node_type=ModelNodeType.ROUTER,
        interfaces=[iface_r0, iface_r1],
        routing_table=[
            RouteEntry(
                route_id="r6-r-conn1",
                node_id="router-6",
                destination_prefix="fd00:1::/64",
                prefix_length=64,
                route_type=RouteType.CONNECTED,
            ),
            RouteEntry(
                route_id="r6-r-conn2",
                node_id="router-6",
                destination_prefix="fd00:2::/64",
                prefix_length=64,
                route_type=RouteType.CONNECTED,
            ),
        ],
    )

    iface_b = ModelInterface(
        interface_id="if-b6",
        node_id="host-b6",
        name="eth0",
        ip_assignments=[IPAddressAssignment(ip_address="fd00:2::20", prefix_length=64)],
    )
    node_b = ModelNode(
        node_id="host-b6",
        label="Host B IPv6",
        node_type=ModelNodeType.HOST,
        interfaces=[iface_b],
        routing_table=[
            RouteEntry(
                route_id="r6-b-conn",
                node_id="host-b6",
                destination_prefix="fd00:2::/64",
                prefix_length=64,
                route_type=RouteType.CONNECTED,
            )
        ],
    )

    model = NetworkModel(
        model_id="test-model-ipv6",
        name="IPv6 Network",
        source_snapshot_id="snap-6",
        source_snapshot_fingerprint="fp-6",
        nodes={"host-a6": node_a, "router-6": node_r, "host-b6": node_b},
        fingerprint="fp-model-6",
    )

    query = ReachabilityQuery(
        source_ip="fd00:1::10",
        destination_ip="fd00:2::20",
        protocol=TransportProtocolConstraint.TCP,
        destination_port=443,
    )
    result = engine.evaluate_reachability(model, query)

    assert result.status == ReachabilityStatus.REACHABLE
    assert len(result.path) >= 2
