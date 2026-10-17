"""Adversarial verification and hardening test cases with hand-verifiable oracles."""

import copy
import time
from collections.abc import Callable
from datetime import UTC, datetime

from network_twin.hardening.models import (
    AdversarialCategory,
    AdversarialTestCase,
    AdversarialTestResult,
)
from network_twin.predictive.models import (
    DatasetManifest,
    FeatureSchema,
    PredictionTarget,
)
from network_twin.predictive.models_engine import ModelTrainer
from network_twin.simulation.forwarding_engine import ForwardingEngine
from network_twin.simulation.models import (
    AccessControlList,
    AdministrativeState,
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
    ReachabilityQuery,
    ReachabilityStatus,
    ReasonCode,
    RouteEntry,
    RouteStatus,
    RuleAction,
    RuleDirection,
    SecurityInvariant,
    SimulationAction,
    SimulationActionType,
    SimulationScenario,
    TransportProtocolConstraint,
)
from network_twin.simulation.scenario_engine import ScenarioEngine
from network_twin.simulation.verification_engine import VerificationEngine


def _make_test_model(model_id: str, name: str, nodes: dict[str, ModelNode]) -> NetworkModel:
    return NetworkModel(
        model_id=model_id,
        name=name,
        source_snapshot_id=f"snap-{model_id}",
        source_snapshot_fingerprint=f"fp-{model_id}",
        nodes=nodes,
    )


def _build_lpm_test_model() -> tuple[NetworkModel, ReachabilityQuery]:
    """Builds a deterministic 2-node topology with overlapping /8, /16, and /24 routes."""
    router = ModelNode(
        node_id="r1",
        label="CoreRouter",
        node_type=ModelNodeType.ROUTER,
        interfaces=[
            ModelInterface(
                interface_id="eth0",
                node_id="r1",
                name="eth0",
                mac_address="00:11:22:33:44:01",
                state=AdministrativeState.UP,
                ip_assignments=[IPAddressAssignment(ip_address="10.0.0.1", prefix_length=8)],
            ),
            ModelInterface(
                interface_id="eth1",
                node_id="r1",
                name="eth1",
                mac_address="00:11:22:33:44:02",
                state=AdministrativeState.UP,
                ip_assignments=[IPAddressAssignment(ip_address="172.16.1.1", prefix_length=24)],
            ),
            ModelInterface(
                interface_id="eth2",
                node_id="r1",
                name="eth2",
                mac_address="00:11:22:33:44:03",
                state=AdministrativeState.UP,
                ip_assignments=[IPAddressAssignment(ip_address="192.168.1.1", prefix_length=24)],
            ),
        ],
        routing_table=[
            RouteEntry(
                route_id="r-default",
                node_id="r1",
                destination_prefix="0.0.0.0/0",
                prefix_length=0,
                output_interface_id="eth0",
                metric=100,
                status=RouteStatus.ACTIVE,
            ),
            RouteEntry(
                route_id="r-slash8",
                node_id="r1",
                destination_prefix="10.0.0.0/8",
                prefix_length=8,
                output_interface_id="eth0",
                metric=10,
                status=RouteStatus.ACTIVE,
            ),
            RouteEntry(
                route_id="r-slash16",
                node_id="r1",
                destination_prefix="10.1.0.0/16",
                prefix_length=16,
                output_interface_id="eth1",
                metric=10,
                status=RouteStatus.ACTIVE,
            ),
            RouteEntry(
                route_id="r-slash24",
                node_id="r1",
                destination_prefix="10.1.2.0/24",
                prefix_length=24,
                output_interface_id="eth2",
                metric=10,
                status=RouteStatus.ACTIVE,
            ),
        ],
    )
    dest_host = ModelNode(
        node_id="h1",
        label="TargetHost",
        node_type=ModelNodeType.HOST,
        interfaces=[
            ModelInterface(
                interface_id="eth0",
                node_id="h1",
                name="eth0",
                mac_address="00:11:22:33:44:99",
                state=AdministrativeState.UP,
                ip_assignments=[IPAddressAssignment(ip_address="10.1.2.45", prefix_length=24)],
            )
        ],
    )
    model = _make_test_model("adv-lpm-model", "LPM Test Model", {"r1": router, "h1": dest_host})
    query = ReachabilityQuery(
        source_ip="10.0.0.1",
        destination_ip="10.1.2.45",
        protocol=TransportProtocolConstraint.TCP,
        destination_port=80,
    )
    return model, query


def _case_lpm_preference() -> AdversarialTestResult:
    t0 = time.perf_counter()
    model, query = _build_lpm_test_model()
    engine = ForwardingEngine()
    reach = engine.evaluate_reachability(model, query)
    elapsed = (time.perf_counter() - t0) * 1000

    # Hand-verified oracle: Destination 10.1.2.45 matches 0.0.0.0/0, 10.0.0.0/8, 10.1.0.0/16, and 10.1.2.0/24.
    # Longest prefix is /24, which egresses via eth2.
    passed = reach.status == ReachabilityStatus.REACHABLE and len(reach.path) > 0 and reach.path[0].egress_interface == "eth2"
    return AdversarialTestResult(
        test_id="ADV-ROUTE-01",
        name="Longest Prefix Match (LPM) Strict Preference",
        category=AdversarialCategory.ROUTING_FORWARDING,
        hand_verifiable_oracle="10.1.2.45 matches /0, /8, /16, and /24; LPM dictates forwarding via /24 route egressing eth2.",
        expected_status="REACHABLE",
        actual_status=reach.status.value,
        expected_reason_code="DELIVERED_LOCAL",
        actual_reason_code=reach.reason_code.value,
        passed=passed,
        details=f"Egress interface used: {reach.path[0].egress_interface if reach.path else 'None'}. Full path: {reach.explanation}",
        execution_time_ms=round(elapsed, 2),
    )


def _case_metric_tie_breaking() -> AdversarialTestResult:
    t0 = time.perf_counter()
    router = ModelNode(
        node_id="r1",
        label="BorderRouter",
        node_type=ModelNodeType.ROUTER,
        interfaces=[
            ModelInterface(
                interface_id="eth-low",
                node_id="r1",
                name="eth-low",
                mac_address="00:aa:bb:cc:dd:01",
                state=AdministrativeState.UP,
                ip_assignments=[IPAddressAssignment(ip_address="192.168.10.1", prefix_length=24)],
            ),
            ModelInterface(
                interface_id="eth-high",
                node_id="r1",
                name="eth-high",
                mac_address="00:aa:bb:cc:dd:02",
                state=AdministrativeState.UP,
                ip_assignments=[IPAddressAssignment(ip_address="192.168.20.1", prefix_length=24)],
            ),
        ],
        routing_table=[
            RouteEntry(
                route_id="r-high-metric",
                node_id="r1",
                destination_prefix="172.20.0.0/16",
                prefix_length=16,
                output_interface_id="eth-high",
                metric=50,
                status=RouteStatus.ACTIVE,
            ),
            RouteEntry(
                route_id="r-low-metric",
                node_id="r1",
                destination_prefix="172.20.0.0/16",
                prefix_length=16,
                output_interface_id="eth-low",
                metric=10,
                status=RouteStatus.ACTIVE,
            ),
        ],
    )
    dest_host = ModelNode(
        node_id="h1",
        label="Host",
        node_type=ModelNodeType.HOST,
        interfaces=[
            ModelInterface(
                interface_id="eth0",
                node_id="h1",
                name="eth0",
                mac_address="00:aa:bb:cc:dd:99",
                state=AdministrativeState.UP,
                ip_assignments=[IPAddressAssignment(ip_address="172.20.1.10", prefix_length=16)],
            )
        ],
    )
    model = _make_test_model("adv-metric-model", "Metric Tie-Break Model", {"r1": router, "h1": dest_host})
    query = ReachabilityQuery(
        source_ip="192.168.10.1",
        destination_ip="172.20.1.10",
        protocol=TransportProtocolConstraint.TCP,
        destination_port=443,
    )
    engine = ForwardingEngine()
    reach = engine.evaluate_reachability(model, query)
    elapsed = (time.perf_counter() - t0) * 1000

    passed = reach.status == ReachabilityStatus.REACHABLE and len(reach.path) > 0 and reach.path[0].egress_interface == "eth-low"
    return AdversarialTestResult(
        test_id="ADV-ROUTE-02",
        name="Lowest Metric Tie-Breaking on Equal Prefixes",
        category=AdversarialCategory.ROUTING_FORWARDING,
        hand_verifiable_oracle="Two identical 172.20.0.0/16 routes (metric 10 vs 50); metric 10 via eth-low must be selected.",
        expected_status="REACHABLE",
        actual_status=reach.status.value,
        expected_reason_code="DELIVERED_LOCAL",
        actual_reason_code=reach.reason_code.value,
        passed=passed,
        details=f"Selected egress interface: {reach.path[0].egress_interface if reach.path else 'None'}.",
        execution_time_ms=round(elapsed, 2),
    )


def _case_interface_down() -> AdversarialTestResult:
    t0 = time.perf_counter()
    router = ModelNode(
        node_id="r1",
        label="EdgeRouter",
        node_type=ModelNodeType.ROUTER,
        interfaces=[
            ModelInterface(
                interface_id="eth_in",
                node_id="r1",
                name="eth_in",
                mac_address="00:11:11:11:11:01",
                state=AdministrativeState.UP,
                ip_assignments=[IPAddressAssignment(ip_address="192.168.1.1", prefix_length=24)],
            ),
            ModelInterface(
                interface_id="eth_out",
                node_id="r1",
                name="eth_out",
                mac_address="00:11:11:11:11:02",
                state=AdministrativeState.DOWN,
                ip_assignments=[IPAddressAssignment(ip_address="10.200.0.1", prefix_length=16)],
            ),
        ],
        routing_table=[
            RouteEntry(
                route_id="r-down",
                node_id="r1",
                destination_prefix="10.200.0.0/16",
                prefix_length=16,
                output_interface_id="eth_out",
                metric=1,
                status=RouteStatus.ACTIVE,
            )
        ],
    )
    model = _make_test_model("adv-down-model", "Down Model", {"r1": router})
    query = ReachabilityQuery(
        source_ip="192.168.1.1",
        destination_ip="10.200.1.1",
        protocol=TransportProtocolConstraint.TCP,
        destination_port=80,
    )
    engine = ForwardingEngine()
    reach = engine.evaluate_reachability(model, query)
    elapsed = (time.perf_counter() - t0) * 1000

    passed = reach.status == ReachabilityStatus.BLOCKED and reach.reason_code == ReasonCode.INTERFACE_DOWN
    return AdversarialTestResult(
        test_id="ADV-ROUTE-03",
        name="Interface Administrative DOWN Enforcement",
        category=AdversarialCategory.ROUTING_FORWARDING,
        hand_verifiable_oracle="Egress interface eth_out is administratively DOWN; packet cannot be transmitted onto wire and must be BLOCKED.",
        expected_status="BLOCKED",
        actual_status=reach.status.value,
        expected_reason_code="INTERFACE_DOWN",
        actual_reason_code=reach.reason_code.value,
        passed=passed,
        details=reach.explanation,
        execution_time_ms=round(elapsed, 2),
    )


def _case_self_referencing_loop() -> AdversarialTestResult:
    t0 = time.perf_counter()
    router = ModelNode(
        node_id="r1",
        label="LoopRouter",
        node_type=ModelNodeType.ROUTER,
        interfaces=[
            ModelInterface(
                interface_id="eth0",
                node_id="r1",
                name="eth0",
                mac_address="00:22:22:22:22:01",
                state=AdministrativeState.UP,
                ip_assignments=[IPAddressAssignment(ip_address="10.50.0.1", prefix_length=24)],
            )
        ],
        routing_table=[
            RouteEntry(
                route_id="r-self-loop",
                node_id="r1",
                destination_prefix="192.168.100.0/24",
                prefix_length=24,
                next_hop_ip="10.50.0.1",  # Local interface address
                output_interface_id="eth0",
                metric=1,
                status=RouteStatus.ACTIVE,
            )
        ],
    )
    model = _make_test_model("adv-self-loop-model", "Self Loop Model", {"r1": router})
    query = ReachabilityQuery(
        source_ip="10.50.0.1",
        destination_ip="192.168.100.5",
        protocol=TransportProtocolConstraint.TCP,
        destination_port=80,
    )
    engine = ForwardingEngine()
    reach = engine.evaluate_reachability(model, query)
    elapsed = (time.perf_counter() - t0) * 1000

    passed = reach.status == ReachabilityStatus.BLOCKED and reach.reason_code == ReasonCode.FORWARDING_LOOP_DETECTED
    return AdversarialTestResult(
        test_id="ADV-ROUTE-04",
        name="Self-Referencing Next-Hop Loop Detection",
        category=AdversarialCategory.ROUTING_FORWARDING,
        hand_verifiable_oracle="Next-hop IP 10.50.0.1 belongs to the evaluating router itself; immediate self-loop must be rejected.",
        expected_status="BLOCKED",
        actual_status=reach.status.value,
        expected_reason_code="FORWARDING_LOOP_DETECTED",
        actual_reason_code=reach.reason_code.value,
        passed=passed,
        details=reach.explanation,
        execution_time_ms=round(elapsed, 2),
    )


def _case_dual_stack_mismatch() -> AdversarialTestResult:
    t0 = time.perf_counter()
    router = ModelNode(
        node_id="r6",
        label="IPv6OnlyRouter",
        node_type=ModelNodeType.ROUTER,
        interfaces=[
            ModelInterface(
                interface_id="eth0",
                node_id="r6",
                name="eth0",
                mac_address="00:66:66:66:66:01",
                state=AdministrativeState.UP,
                ip_assignments=[IPAddressAssignment(ip_address="2001:db8::1", prefix_length=64)],
            )
        ],
        routing_table=[
            RouteEntry(
                route_id="r-v6-default",
                node_id="r6",
                destination_prefix="2001:db8::/32",
                prefix_length=32,
                output_interface_id="eth0",
                metric=1,
                status=RouteStatus.ACTIVE,
            )
        ],
    )
    model = _make_test_model("adv-v6-model", "IPv6 Model", {"r6": router})
    # Query IPv4 destination against IPv6 router
    query = ReachabilityQuery(
        source_ip="2001:db8::1",
        destination_ip="192.0.2.1",
        protocol=TransportProtocolConstraint.TCP,
        destination_port=80,
    )
    engine = ForwardingEngine()
    reach = engine.evaluate_reachability(model, query)
    elapsed = (time.perf_counter() - t0) * 1000

    passed = reach.status == ReachabilityStatus.BLOCKED and reach.reason_code == ReasonCode.NO_ROUTE_TO_HOST
    return AdversarialTestResult(
        test_id="ADV-ROUTE-05",
        name="Dual-Stack Version Mismatch Graceful Handling",
        category=AdversarialCategory.ROUTING_FORWARDING,
        hand_verifiable_oracle="Querying an IPv4 address against IPv6-only routing tables must cleanly return NO_ROUTE_TO_HOST without unhandled exceptions.",
        expected_status="BLOCKED",
        actual_status=reach.status.value,
        expected_reason_code="NO_ROUTE_TO_HOST",
        actual_reason_code=reach.reason_code.value,
        passed=passed,
        details=reach.explanation,
        execution_time_ms=round(elapsed, 2),
    )


def _case_unresolved_evidence_indeterminate() -> AdversarialTestResult:
    t0 = time.perf_counter()
    # Topology with internal host, but verification attempts to test forbidden exposure from an unmodeled source IP
    router = ModelNode(
        node_id="r1",
        label="IsolatedRouter",
        node_type=ModelNodeType.ROUTER,
        interfaces=[
            ModelInterface(
                interface_id="eth0",
                node_id="r1",
                name="eth0",
                mac_address="00:33:33:33:33:01",
                state=AdministrativeState.UP,
                ip_assignments=[IPAddressAssignment(ip_address="10.0.1.1", prefix_length=24)],
            )
        ],
        routing_table=[],
    )
    model = _make_test_model("adv-indeterminate-model", "Indeterminate Model", {"r1": router})

    # Forbidden exposure invariant against unmodeled/unresolvable external source IP
    invariant = SecurityInvariant(
        invariant_id="inv-forbid-indet",
        name="Forbidden External SSH Exposure",
        description="Verify database at 10.0.1.1 is not exposed to untrusted external source",
        invariant_type=InvariantType.FORBIDDEN_EXPOSURE,
        severity=InvariantSeverity.CRITICAL,
        definition=InvariantDefinition(
            source_zone_or_cidr="198.51.100.99/32",  # External IP not in any modeled interface/subnet
            service_ip="10.0.1.1",
            forbidden_ports=[22],
        ),
    )
    verifier = VerificationEngine()
    result = verifier.verify_invariant(model, invariant)
    elapsed = (time.perf_counter() - t0) * 1000

    # Hand-verified oracle: Because source IP 198.51.100.99 is not modeled, reachability evaluates to
    # INDETERMINATE (SOURCE_UNKNOWN). In our hardened engine, indeterminate reachability MUST NEVER
    # report false PASS; it must strictly return INDETERMINATE with ROUTING_INDETERMINATE.
    passed = result.status == InvariantStatus.INDETERMINATE and result.reason_code == "ROUTING_INDETERMINATE"
    return AdversarialTestResult(
        test_id="ADV-SEC-01",
        name="Strict Verification: Unresolved Evidence Never Yields False PASS",
        category=AdversarialCategory.SECURITY_ISOLATION,
        hand_verifiable_oracle="Unresolved source IP yields INDETERMINATE reachability; verification must strictly return INDETERMINATE, never false PASS.",
        expected_status="INDETERMINATE",
        actual_status=result.status.value,
        expected_reason_code="ROUTING_INDETERMINATE",
        actual_reason_code=result.reason_code,
        passed=passed,
        details=result.explanation,
        execution_time_ms=round(elapsed, 2),
    )


def _case_acl_subnet_shadowing() -> AdversarialTestResult:
    t0 = time.perf_counter()
    router = ModelNode(
        node_id="fw1",
        label="EdgeFirewall",
        node_type=ModelNodeType.FIREWALL,
        interfaces=[
            ModelInterface(
                interface_id="eth0",
                node_id="fw1",
                name="eth0",
                mac_address="00:44:44:44:44:01",
                state=AdministrativeState.UP,
                ip_assignments=[IPAddressAssignment(ip_address="10.10.0.1", prefix_length=16)],
            )
        ],
        acls=[
            AccessControlList(
                acl_id="acl-edge",
                node_id="fw1",
                name="Edge Ingress Filter",
                default_policy=DefaultPolicy.DEFAULT_ALLOW,
                rules=[
                    FirewallRule(
                        rule_id="rule-broad-deny",
                        node_id="fw1",
                        rule_number=1,
                        name="BlockEntireSubnet",
                        action=RuleAction.DENY,
                        direction=RuleDirection.INGRESS,
                        source_prefix="10.0.0.0/16",
                        destination_prefix="0.0.0.0/0",
                        protocol=TransportProtocolConstraint.ANY,
                    ),
                    FirewallRule(
                        rule_id="rule-shadowed-allow",
                        node_id="fw1",
                        rule_number=2,
                        name="AllowSubsetHost",
                        action=RuleAction.PERMIT,
                        direction=RuleDirection.INGRESS,
                        source_prefix="10.0.5.0/24",  # Contained inside 10.0.0.0/16!
                        destination_prefix="0.0.0.0/0",
                        protocol=TransportProtocolConstraint.TCP,
                        destination_port=443,
                    ),
                ],
            )
        ],
    )
    model = _make_test_model("adv-acl-shadow-model", "ACL Shadow Model", {"fw1": router})
    invariant = SecurityInvariant(
        invariant_id="inv-cfg-cons",
        name="Configuration Consistency Audit",
        description="Audit routing and ACLs for contradictions and shadowing",
        invariant_type=InvariantType.CONFIGURATION_CONSISTENCY,
        severity=InvariantSeverity.MEDIUM,
        definition=InvariantDefinition(),
    )
    verifier = VerificationEngine()
    result = verifier.verify_invariant(model, invariant)
    elapsed = (time.perf_counter() - t0) * 1000

    passed = result.status == InvariantStatus.FAIL and "shadowed" in result.explanation.lower()
    return AdversarialTestResult(
        test_id="ADV-SEC-02",
        name="True ACL Subnet and Port Shadowing Detection",
        category=AdversarialCategory.CONFIG_CONSISTENCY,
        hand_verifiable_oracle="Rule 1 blocks 10.0.0.0/16; Rule 2 allows subset 10.0.5.0/24; Rule 2 is completely shadowed and never reached.",
        expected_status="FAIL",
        actual_status=result.status.value,
        expected_reason_code="CONFIGURATION_INCONSISTENCY",
        actual_reason_code=result.reason_code,
        passed=passed,
        details=result.explanation,
        execution_time_ms=round(elapsed, 2),
    )


def _case_scenario_deep_clone_integrity() -> AdversarialTestResult:
    t0 = time.perf_counter()
    model, _ = _build_lpm_test_model()
    original_fp = model.fingerprint
    original_routes_count = len(model.nodes["r1"].routing_table)

    scenario = SimulationScenario(
        scenario_id="sc-test-isolation",
        name="Isolate and Mutate Scenario",
        description="Verify baseline isolation against counterfactual mutation",
        base_model_id=model.model_id,
        actions=[
            SimulationAction(
                action_type=SimulationActionType.REMOVE_ROUTE,
                target_node_id="r1",
                parameters={"route_id": "r-slash24"},
            ),
            SimulationAction(
                action_type=SimulationActionType.ADD_FIREWALL_RULE,
                target_node_id="r1",
                parameters={"action": "DENY", "source_prefix": "10.1.2.0/24"},
            ),
        ],
    )
    engine = ScenarioEngine()
    cf_model, result = engine.run_scenario(model, scenario)
    elapsed = (time.perf_counter() - t0) * 1000

    # Hand-verified oracle:
    # 1. Baseline model must remain completely untouched: same fingerprint, same route count.
    # 2. Counterfactual model must have 1 less route and 1 more firewall rule.
    baseline_untouched = (
        model.fingerprint == original_fp
        and len(model.nodes["r1"].routing_table) == original_routes_count
    )
    cf_mutated = (
        len(cf_model.nodes["r1"].routing_table) == original_routes_count - 1
        and len(cf_model.nodes["r1"].acls) > 0
    )
    passed = baseline_untouched and cf_mutated
    return AdversarialTestResult(
        test_id="ADV-SCENARIO-01",
        name="Scenario Deep-Clone Immutability and State Isolation",
        category=AdversarialCategory.SECURITY_ISOLATION,
        hand_verifiable_oracle="Mutating counterfactual state MUST NOT alter baseline model snapshot; original fingerprint must be preserved.",
        expected_status="PASS",
        actual_status="PASS" if passed else "FAIL",
        expected_reason_code="IMMUTABILITY_PRESERVED",
        actual_reason_code="IMMUTABILITY_PRESERVED" if passed else "LEAKED_MUTATION",
        passed=passed,
        details=f"Baseline routes: {len(model.nodes['r1'].routing_table)} (FP: {model.fingerprint[:12]}); CF routes: {len(cf_model.nodes['r1'].routing_table)} (FP: {cf_model.fingerprint[:12]}).",
        execution_time_ms=round(elapsed, 2),
    )


def _case_predictive_validation_hardening() -> AdversarialTestResult:
    t0 = time.perf_counter()
    schema = FeatureSchema(
        feature_names=["active_flows", "byte_rate"],
        feature_types={"active_flows": "float64", "byte_rate": "float64"},
        target_column="target",
    )
    # Insufficient samples (< 4)
    invalid_samples = [
        {"active_flows": 1.0, "byte_rate": 100.0, "target": 5.0},
        {"active_flows": 2.0, "byte_rate": 200.0, "target": 6.0},
    ]
    invalid_manifest = DatasetManifest(
        dataset_id="test-ds-invalid",
        name="Invalid Sample Dataset",
        total_samples=len(invalid_samples),
        feature_count=2,
        target_type=PredictionTarget.FLOW_VOLUME_NEXT_WINDOW,
        feature_schema=schema,
        dataset_samples=invalid_samples,
        hash_sha256="sha-invalid-test",
        created_at_iso=datetime.now(UTC).isoformat(),
    )
    trainer = ModelTrainer()

    # Test 1: Expect ValueError for < 4 samples
    threw_insufficient = False
    try:
        trainer.train_model(invalid_manifest)
    except ValueError as e:
        if "Insufficient samples" in str(e):
            threw_insufficient = True

    # Test 2: Expect ValueError for invalid test_ratio
    valid_samples = [
        {"active_flows": float(i), "byte_rate": float(i * 100), "target": float(i + 1)}
        for i in range(10)
    ]
    valid_manifest = DatasetManifest(
        dataset_id="test-ds-ratio",
        name="Valid Sample Dataset",
        total_samples=len(valid_samples),
        feature_count=2,
        target_type=PredictionTarget.FLOW_VOLUME_NEXT_WINDOW,
        feature_schema=schema,
        dataset_samples=valid_samples,
        hash_sha256="sha-ratio-test",
        created_at_iso=datetime.now(UTC).isoformat(),
    )
    threw_ratio = False
    try:
        trainer.train_model(valid_manifest, test_ratio=0.8)  # > 0.5 must be rejected
    except ValueError as e:
        if "Invalid test_ratio" in str(e):
            threw_ratio = True

    elapsed = (time.perf_counter() - t0) * 1000
    passed = threw_insufficient and threw_ratio
    return AdversarialTestResult(
        test_id="ADV-ML-01",
        name="Predictive Training Boundary and Split Hardening",
        category=AdversarialCategory.PREDICTIVE_INTEGRITY,
        hand_verifiable_oracle="Model training with N < 4 or test_ratio > 0.5 must strictly reject input with actionable ValueError.",
        expected_status="PASS",
        actual_status="PASS" if passed else "FAIL",
        expected_reason_code="VALIDATION_REJECTED",
        actual_reason_code="VALIDATION_REJECTED" if passed else "SILENT_FAILURE",
        passed=passed,
        details=f"Insufficient check passed: {threw_insufficient}; Ratio check passed: {threw_ratio}.",
        execution_time_ms=round(elapsed, 2),
    )


def _case_metamorphic_coordinate_invariance() -> AdversarialTestResult:
    t0 = time.perf_counter()
    model_a, query_a = _build_lpm_test_model()

    # Create model_b which is identical in routing and interfaces but has permuted node dictionary keys
    # and different benign metadata
    model_b = _make_test_model(
        "adv-lpm-model-permuted",
        "LPM Permuted Model",
        {
            "h1": copy.deepcopy(model_a.nodes["h1"]),
            "r1": copy.deepcopy(model_a.nodes["r1"]),
        },
    )
    model_b.nodes["r1"].metadata["gui_position_x"] = 999.0
    model_b.nodes["r1"].metadata["gui_position_y"] = -450.0

    engine = ForwardingEngine()
    reach_a = engine.evaluate_reachability(model_a, query_a)
    reach_b = engine.evaluate_reachability(model_b, query_a)
    elapsed = (time.perf_counter() - t0) * 1000

    # Hand-verified oracle: Layout coordinate shift or map iteration ordering MUST NOT alter
    # reachability status, reason code, or traversed path sequence.
    same_status = reach_a.status == reach_b.status
    same_reason = reach_a.reason_code == reach_b.reason_code
    same_path_length = len(reach_a.path) == len(reach_b.path)
    same_hops = [h.node_id for h in reach_a.path] == [h.node_id for h in reach_b.path]

    passed = same_status and same_reason and same_path_length and same_hops
    return AdversarialTestResult(
        test_id="ADV-META-01",
        name="Metamorphic Invariance: Benign Metadata Permutation",
        category=AdversarialCategory.METAMORPHIC_INVARIANCE,
        hand_verifiable_oracle="Permutation of GUI coordinates and node dictionary ordering must produce mathematically identical forwarding decisions.",
        expected_status="PASS",
        actual_status="PASS" if passed else "FAIL",
        expected_reason_code="METAMORPHIC_EQUIVALENT",
        actual_reason_code="METAMORPHIC_EQUIVALENT" if passed else "DIVERGENCE_DETECTED",
        passed=passed,
        details=f"Path A hops: {[h.node_id for h in reach_a.path]}; Path B hops: {[h.node_id for h in reach_b.path]}.",
        execution_time_ms=round(elapsed, 2),
    )


ALL_ADVERSARIAL_CASES: list[Callable[[], AdversarialTestResult]] = [
    _case_lpm_preference,
    _case_metric_tie_breaking,
    _case_interface_down,
    _case_self_referencing_loop,
    _case_dual_stack_mismatch,
    _case_unresolved_evidence_indeterminate,
    _case_acl_subnet_shadowing,
    _case_scenario_deep_clone_integrity,
    _case_predictive_validation_hardening,
    _case_metamorphic_coordinate_invariance,
]


def get_all_adversarial_cases() -> list[AdversarialTestCase]:
    """Returns static metadata for all registered adversarial test cases."""
    results = [fn() for fn in ALL_ADVERSARIAL_CASES]
    return [
        AdversarialTestCase(
            test_id=r.test_id,
            name=r.name,
            category=r.category,
            description=r.hand_verifiable_oracle,
            hand_verifiable_oracle=r.hand_verifiable_oracle,
            expected_status=r.expected_status,
            expected_reason_code=r.expected_reason_code,
        )
        for r in results
    ]
