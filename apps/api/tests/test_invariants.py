"""Unit tests for Security Invariant Verification Engine."""

import pytest

from network_twin.simulation.models import (
    AccessControlList,
    DefaultPolicy,
    FirewallRule,
    InvariantDefinition,
    InvariantSeverity,
    InvariantStatus,
    InvariantType,
    IPAddressAssignment,
    ModelInterface,
    ModelNode,
    ModelNodeType,
    NetworkModel,
    NetworkZone,
    RouteEntry,
    RouteType,
    RuleAction,
    RuleDirection,
    SecurityInvariant,
    TransportProtocolConstraint,
)
from network_twin.simulation.verification_engine import VerificationEngine


@pytest.fixture
def enterprise_model() -> NetworkModel:
    """Builds a segmented model with DMZ and Internal Trusted zones."""
    # Internal Host (10.0.1.50) in zone-trusted
    iface_int = ModelInterface(
        interface_id="if-int",
        node_id="host-internal",
        name="eth0",
        ip_assignments=[IPAddressAssignment(ip_address="10.0.1.50", prefix_length=24)],
    )
    node_int = ModelNode(
        node_id="host-internal",
        label="Internal DB Server",
        node_type=ModelNodeType.HOST,
        zone_id="zone-trusted",
        interfaces=[iface_int],
        routing_table=[
            RouteEntry(
                route_id="r-int-conn",
                node_id="host-internal",
                destination_prefix="10.0.1.0/24",
                prefix_length=24,
                route_type=RouteType.CONNECTED,
            ),
            RouteEntry(
                route_id="r-int-def",
                node_id="host-internal",
                destination_prefix="0.0.0.0/0",
                prefix_length=0,
                next_hop_ip="10.0.1.1",
            ),
        ],
    )

    # Perimeter Firewall (eth0: 198.51.100.1 [untrusted], eth1: 10.0.1.1 [trusted])
    iface_fw_ext = ModelInterface(
        interface_id="if-fw-ext",
        node_id="firewall-1",
        name="eth0",
        ip_assignments=[IPAddressAssignment(ip_address="198.51.100.1", prefix_length=24)],
    )
    iface_fw_int = ModelInterface(
        interface_id="if-fw-int",
        node_id="firewall-1",
        name="eth1",
        ip_assignments=[IPAddressAssignment(ip_address="10.0.1.1", prefix_length=24)],
    )

    # Ingress rule: Drop untrusted to 10.0.1.50:5432 (database)
    rule_drop_db = FirewallRule(
        rule_id="fw-drop-db",
        node_id="firewall-1",
        rule_number=1,
        action=RuleAction.DENY,
        direction=RuleDirection.INGRESS,
        destination_prefix="10.0.1.50/32",
        protocol=TransportProtocolConstraint.TCP,
        destination_port=5432,
    )
    # Ingress rule: Permit HTTPS to DMZ Web (10.0.1.80:443)
    rule_permit_web = FirewallRule(
        rule_id="fw-permit-web",
        node_id="firewall-1",
        rule_number=2,
        action=RuleAction.PERMIT,
        direction=RuleDirection.INGRESS,
        destination_prefix="10.0.1.80/32",
        protocol=TransportProtocolConstraint.TCP,
        destination_port=443,
    )

    node_fw = ModelNode(
        node_id="firewall-1",
        label="Perimeter Firewall",
        node_type=ModelNodeType.FIREWALL,
        interfaces=[iface_fw_ext, iface_fw_int],
        routing_table=[
            RouteEntry(
                route_id="r-fw-ext",
                node_id="firewall-1",
                destination_prefix="198.51.100.0/24",
                prefix_length=24,
                route_type=RouteType.CONNECTED,
            ),
            RouteEntry(
                route_id="r-fw-int",
                node_id="firewall-1",
                destination_prefix="10.0.1.0/24",
                prefix_length=24,
                route_type=RouteType.CONNECTED,
            ),
        ],
        acls=[
            AccessControlList(
                acl_id="acl-fw",
                node_id="firewall-1",
                name="Perimeter Ingress",
                rules=[rule_drop_db, rule_permit_web],
                default_policy=DefaultPolicy.DEFAULT_DENY,
            )
        ],
    )

    # Web Server in DMZ (10.0.1.80)
    iface_web = ModelInterface(
        interface_id="if-web",
        node_id="host-web",
        name="eth0",
        ip_assignments=[IPAddressAssignment(ip_address="10.0.1.80", prefix_length=24)],
    )
    node_web = ModelNode(
        node_id="host-web",
        label="Public Web Server",
        node_type=ModelNodeType.HOST,
        zone_id="zone-dmz",
        interfaces=[iface_web],
        routing_table=[
            RouteEntry(
                route_id="r-web-conn",
                node_id="host-web",
                destination_prefix="10.0.1.0/24",
                prefix_length=24,
                route_type=RouteType.CONNECTED,
            ),
            RouteEntry(
                route_id="r-web-def",
                node_id="host-web",
                destination_prefix="0.0.0.0/0",
                prefix_length=0,
                next_hop_ip="10.0.1.1",
            ),
        ],
    )

    # External Client (198.51.100.50) in zone-untrusted
    iface_ext = ModelInterface(
        interface_id="if-ext",
        node_id="host-external",
        name="eth0",
        ip_assignments=[IPAddressAssignment(ip_address="198.51.100.50", prefix_length=24)],
    )
    node_ext = ModelNode(
        node_id="host-external",
        label="External Internet Host",
        node_type=ModelNodeType.HOST,
        zone_id="zone-untrusted",
        interfaces=[iface_ext],
        routing_table=[
            RouteEntry(
                route_id="r-ext-conn",
                node_id="host-external",
                destination_prefix="198.51.100.0/24",
                prefix_length=24,
                route_type=RouteType.CONNECTED,
            ),
            RouteEntry(
                route_id="r-ext-def",
                node_id="host-external",
                destination_prefix="0.0.0.0/0",
                prefix_length=0,
                next_hop_ip="198.51.100.1",
            ),
        ],
    )

    zones = {
        "zone-trusted": NetworkZone(
            zone_id="zone-trusted",
            name="Trusted",
            assigned_node_ids=["host-internal"],
        ),
        "zone-untrusted": NetworkZone(
            zone_id="zone-untrusted",
            name="Untrusted",
            assigned_node_ids=["host-external"],
        ),
        "zone-dmz": NetworkZone(
            zone_id="zone-dmz",
            name="DMZ",
            assigned_node_ids=["host-web"],
        ),
    }

    return NetworkModel(
        model_id="model-enterprise-01",
        name="Enterprise Perimeter Model",
        source_snapshot_id="snap-ent-01",
        source_snapshot_fingerprint="ent-fp",
        nodes={
            "host-internal": node_int,
            "firewall-1": node_fw,
            "host-web": node_web,
            "host-external": node_ext,
        },
        zones=zones,
        fingerprint="ent-model-fingerprint",
    )


def test_isolation_invariant_pass(enterprise_model: NetworkModel):
    engine = VerificationEngine()
    inv = SecurityInvariant(
        invariant_id="inv-db-isolation",
        name="Database Isolation",
        description="External untrusted hosts must not reach database",
        invariant_type=InvariantType.ISOLATION,
        severity=InvariantSeverity.CRITICAL,
        definition=InvariantDefinition(
            source_zone_or_cidr="zone-untrusted",
            destination_zone_or_cidr="10.0.1.50/32",
        ),
    )
    res = engine.verify_invariant(enterprise_model, inv)

    assert res.status == InvariantStatus.PASS
    assert res.reason_code == "ISOLATION_ENFORCED"


def test_isolation_invariant_fail_with_witness_path(enterprise_model: NetworkModel):
    engine = VerificationEngine()
    # Permit everything on firewall to trigger violation
    enterprise_model.nodes["firewall-1"].acls[0].rules = [
        FirewallRule(
            rule_id="fw-permit-any",
            node_id="firewall-1",
            rule_number=1,
            action=RuleAction.PERMIT,
            direction=RuleDirection.INGRESS,
        )
    ]

    inv = SecurityInvariant(
        invariant_id="inv-db-isolation",
        name="Database Isolation",
        description="External untrusted hosts must not reach database",
        invariant_type=InvariantType.ISOLATION,
        severity=InvariantSeverity.CRITICAL,
        definition=InvariantDefinition(
            source_zone_or_cidr="zone-untrusted",
            destination_zone_or_cidr="10.0.1.50/32",
        ),
    )
    res = engine.verify_invariant(enterprise_model, inv)

    assert res.status == InvariantStatus.FAIL
    assert res.reason_code == "ISOLATION_VIOLATION"
    assert res.witness_path is not None
    assert len(res.witness_path) >= 2


def test_required_reachability(enterprise_model: NetworkModel):
    engine = VerificationEngine()
    # Web service on 10.0.1.80:443 should be reachable from untrusted
    inv = SecurityInvariant(
        invariant_id="inv-web-reachability",
        name="Public Web Reachability",
        description="Web service must be reachable from external zone",
        invariant_type=InvariantType.REQUIRED_REACHABILITY,
        severity=InvariantSeverity.HIGH,
        definition=InvariantDefinition(
            source_zone_or_cidr="zone-untrusted",
            service_ip="10.0.1.80",
            service_port=443,
        ),
    )
    res = engine.verify_invariant(enterprise_model, inv)

    assert res.status == InvariantStatus.PASS
    assert res.reason_code == "REACHABILITY_VERIFIED"


def test_port_restriction(enterprise_model: NetworkModel):
    engine = VerificationEngine()
    # Only port 443 permitted on 10.0.1.80; other ports (e.g. 21, 22, 80) blocked by default deny
    inv = SecurityInvariant(
        invariant_id="inv-port-restriction",
        name="Web Port Restriction",
        description="Only port 443 permitted",
        invariant_type=InvariantType.PORT_RESTRICTION,
        severity=InvariantSeverity.HIGH,
        definition=InvariantDefinition(
            service_ip="10.0.1.80",
            allowed_ports=[443],
        ),
    )
    res = engine.verify_invariant(enterprise_model, inv)

    assert res.status == InvariantStatus.PASS
    assert res.reason_code == "PORT_RESTRICTIONS_ENFORCED"


def test_configuration_consistency(enterprise_model: NetworkModel):
    engine = VerificationEngine()
    # Add conflicting contradictory route
    enterprise_model.nodes["firewall-1"].routing_table.append(
        RouteEntry(
            route_id="r-fw-conflict",
            node_id="firewall-1",
            destination_prefix="10.0.1.0/24",
            prefix_length=24,
            next_hop_ip="198.51.100.99",  # Different next-hop with same metric!
            metric=1,
        )
    )

    inv = SecurityInvariant(
        invariant_id="inv-consistency",
        name="Routing Consistency",
        description="Detect conflicting routes",
        invariant_type=InvariantType.CONFIGURATION_CONSISTENCY,
        severity=InvariantSeverity.MEDIUM,
        definition=InvariantDefinition(),
    )
    res = engine.verify_invariant(enterprise_model, inv)

    assert res.status == InvariantStatus.FAIL
    assert res.reason_code == "CONFIGURATION_INCONSISTENCY"
