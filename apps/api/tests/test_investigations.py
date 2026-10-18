"""
Tests for Phase 10: Evidence-Backed Incident Investigation & Root-Cause Analysis.
"""

from fastapi.testclient import TestClient

from network_twin.investigations.engine import InvestigationEngine
from network_twin.investigations.models import (
    CandidateStatus,
    CreateInvestigationRequest,
    EvidenceClass,
    EvidenceSufficiency,
    InvestigationScope,
    InvestigationType,
)
from network_twin.main import app
from network_twin.simulation.models import (
    AccessControlList,
    AdministrativeState,
    DefaultPolicy,
    FilterStatefulness,
    FirewallRule,
    IPAddressAssignment,
    ModelInterface,
    ModelNode,
    ModelNodeType,
    NetworkModel,
    RouteEntry,
    RouteStatus,
    RouteType,
    RuleAction,
    RuleDirection,
    SimulationActionType,
    TransportProtocolConstraint,
)
from network_twin.storage.metadata_store import MetadataStore


def build_test_network_model(
    model_id: str = "test-model-inv-01", if_state: AdministrativeState = AdministrativeState.DOWN
) -> NetworkModel:
    """Constructs a deterministic 2-node router network model for investigation tests."""
    r1 = ModelNode(
        node_id="router-1",
        label="Border Router 1",
        node_type=ModelNodeType.ROUTER,
        interfaces=[
            ModelInterface(
                interface_id="eth0",
                node_id="router-1",
                name="eth0",
                ip_assignments=[IPAddressAssignment(ip_address="192.168.10.1", prefix_length=24)],
                state=AdministrativeState.UP,
            ),
            ModelInterface(
                interface_id="eth1",
                node_id="router-1",
                name="eth1",
                ip_assignments=[IPAddressAssignment(ip_address="10.200.0.1", prefix_length=24)],
                state=if_state,  # Parametric: can test DOWN vs UP
            ),
        ],
        routing_table=[
            RouteEntry(
                route_id="r-lan-1",
                node_id="router-1",
                destination_prefix="192.168.10.0/24",
                prefix_length=24,
                next_hop_ip=None,
                output_interface_id="eth0",
                route_type=RouteType.CONNECTED,
                status=RouteStatus.ACTIVE,
                metric=0,
            ),
            RouteEntry(
                route_id="r-wan-1",
                node_id="router-1",
                destination_prefix="10.200.0.0/24",
                prefix_length=24,
                next_hop_ip=None,
                output_interface_id="eth1",
                route_type=RouteType.CONNECTED,
                status=RouteStatus.ACTIVE,
                metric=10,
            ),
        ],
        acls=[
            AccessControlList(
                acl_id="acl-wan-in",
                node_id="router-1",
                name="WAN Ingress Filter",
                default_policy=DefaultPolicy.DEFAULT_ALLOW,
                rules=[
                    FirewallRule(
                        rule_id="rule-deny-ssh",
                        node_id="router-1",
                        rule_number=1,
                        action=RuleAction.DENY,
                        direction=RuleDirection.INGRESS,
                        source_prefix="0.0.0.0/0",
                        destination_prefix="10.200.0.0/24",
                        protocol=TransportProtocolConstraint.TCP,
                        destination_port=22,
                        statefulness=FilterStatefulness.STATELESS,
                        description="Block inbound SSH to WAN subnet",
                    )
                ],
            )
        ],
    )

    h1 = ModelNode(
        node_id="host-1",
        label="Host 1",
        node_type=ModelNodeType.HOST,
        interfaces=[
            ModelInterface(
                interface_id="h1-eth0",
                node_id="host-1",
                name="eth0",
                ip_assignments=[IPAddressAssignment(ip_address="192.168.10.50", prefix_length=24)],
                state=AdministrativeState.UP,
            )
        ],
        routing_table=[
            RouteEntry(
                route_id="r-h1-conn",
                node_id="host-1",
                destination_prefix="192.168.10.0/24",
                prefix_length=24,
                route_type=RouteType.CONNECTED,
                status=RouteStatus.ACTIVE,
            ),
            RouteEntry(
                route_id="r-h1-def",
                node_id="host-1",
                destination_prefix="0.0.0.0/0",
                prefix_length=0,
                next_hop_ip="192.168.10.1",
                route_type=RouteType.STATIC,
                status=RouteStatus.ACTIVE,
            ),
        ],
    )

    return NetworkModel(
        model_id=model_id,
        name="Investigation Test Model",
        source_snapshot_id="snap-test",
        source_snapshot_fingerprint="fp-test",
        nodes={"router-1": r1, "host-1": h1},
        fingerprint="fp-test-model",
    )


def test_investigation_lifecycle_and_persistence():
    store = MetadataStore()
    engine = InvestigationEngine(metadata_store=store)

    req = CreateInvestigationRequest(
        title="Investigation Case: Office-to-DC Outage",
        investigation_type=InvestigationType.CONNECTIVITY_FAILURE,
        scope=InvestigationScope(
            source_ip="192.168.10.50",
            destination_ip="10.200.0.99",
            transport_protocol="TCP",
            destination_port=443,
        ),
    )

    case = engine.create_investigation(req)
    assert case.investigation_id.startswith("inv-")
    assert case.status == "OPEN"
    assert case.sufficiency == EvidenceSufficiency.INSUFFICIENT

    # Verify retrieval from persistence
    retrieved = store.get_investigation(case.investigation_id)
    assert retrieved is not None
    assert retrieved.title == req.title
    assert retrieved.scope.source_ip == "192.168.10.50"


def test_investigate_connectivity_failure_interface_down():
    store = MetadataStore()
    model = build_test_network_model(model_id="model-if-down-test", if_state=AdministrativeState.DOWN)
    store.save_network_model(model)

    engine = InvestigationEngine(metadata_store=store)
    req = CreateInvestigationRequest(
        title="Outage: Interface DOWN Investigation",
        investigation_type=InvestigationType.CONNECTIVITY_FAILURE,
        scope=InvestigationScope(
            source_ip="192.168.10.50",
            destination_ip="10.200.0.99",
            transport_protocol="TCP",
            destination_port=80,
            model_id=model.model_id,
        ),
    )
    case = engine.create_investigation(req)
    analyzed = engine.execute_investigation(case.investigation_id)

    assert analyzed.status == "ANALYZED"
    assert analyzed.sufficiency == EvidenceSufficiency.SUFFICIENT
    assert len(analyzed.candidate_explanations) > 0

    top_candidate = analyzed.candidate_explanations[0]
    assert top_candidate.status == CandidateStatus.CONFIRMED_WITHIN_MODEL_SCOPE
    assert "DOWN" in top_candidate.title
    assert analyzed.primary_root_cause_id == top_candidate.candidate_id

    # Evidence graph checks
    assert analyzed.evidence_graph.node_count > 0
    # Must have SIMULATED evidence for forwarding
    sim_nodes = [n for n in analyzed.evidence_graph.nodes if n.evidence_class == EvidenceClass.SIMULATED]
    assert len(sim_nodes) >= 1


def test_investigate_connectivity_failure_acl_deny():
    store = MetadataStore()
    # Interface is UP, but port 22 (SSH) is blocked by explicit ACL rule
    model = build_test_network_model(model_id="model-acl-deny-test", if_state=AdministrativeState.UP)
    store.save_network_model(model)

    engine = InvestigationEngine(metadata_store=store)
    req = CreateInvestigationRequest(
        title="SSH Traffic Dropped Investigation",
        investigation_type=InvestigationType.CONNECTIVITY_FAILURE,
        scope=InvestigationScope(
            source_ip="192.168.10.50",
            destination_ip="10.200.0.99",
            transport_protocol="TCP",
            destination_port=22,  # Port 22 matched by rule-deny-ssh
            model_id=model.model_id,
        ),
    )
    case = engine.create_investigation(req)
    analyzed = engine.execute_investigation(case.investigation_id)

    assert analyzed.status == "ANALYZED"
    assert analyzed.sufficiency == EvidenceSufficiency.SUFFICIENT
    top_candidate = analyzed.candidate_explanations[0]
    assert top_candidate.status == CandidateStatus.CONFIRMED_WITHIN_MODEL_SCOPE
    assert "rule-deny-ssh" in top_candidate.title or "Security Policy" in top_candidate.title
    assert "rule-deny-ssh" in top_candidate.rationale


def test_investigate_unmodeled_endpoint_never_claims_confirmed():
    """Crucial requirement: When evidence is missing, NEVER invent or confirm root cause."""
    store = MetadataStore()
    model = build_test_network_model(model_id="model-unmodeled-test", if_state=AdministrativeState.UP)
    store.save_network_model(model)

    engine = InvestigationEngine(metadata_store=store)
    req = CreateInvestigationRequest(
        title="Unmodeled Source IP Investigation",
        investigation_type=InvestigationType.CONNECTIVITY_FAILURE,
        scope=InvestigationScope(
            source_ip="172.31.250.99",  # Completely unmodeled IP
            destination_ip="10.200.0.99",
            transport_protocol="TCP",
            destination_port=80,
            model_id=model.model_id,
        ),
    )
    case = engine.create_investigation(req)
    analyzed = engine.execute_investigation(case.investigation_id)

    # Must be INSUFFICIENT or INDETERMINATE, never CONFIRMED
    assert analyzed.sufficiency == EvidenceSufficiency.INSUFFICIENT
    top_candidate = analyzed.candidate_explanations[0]
    assert top_candidate.status == CandidateStatus.INSUFFICIENT_EVIDENCE
    assert len(top_candidate.missing_evidence) > 0


def test_investigate_dns_resolution_failure():
    store = MetadataStore()
    engine = InvestigationEngine(metadata_store=store)

    # Test Case 1: Zero DNS traffic captured -> INSUFFICIENT_EVIDENCE
    req_empty = CreateInvestigationRequest(
        title="Missing DNS Exchange",
        investigation_type=InvestigationType.DNS_RESOLUTION_FAILURE,
        scope=InvestigationScope(
            hostname="unseen-api.internal.corp",
        ),
    )
    case1 = engine.create_investigation(req_empty)
    analyzed1 = engine.execute_investigation(case1.investigation_id)
    assert analyzed1.sufficiency == EvidenceSufficiency.INSUFFICIENT
    assert analyzed1.candidate_explanations[0].status == CandidateStatus.INSUFFICIENT_EVIDENCE


def test_investigate_counterfactual_remediation():
    """Verify side-by-side counterfactual simulation alters modeled reachability from BLOCKED to REACHABLE."""
    store = MetadataStore()
    model = build_test_network_model(model_id="model-cf-test", if_state=AdministrativeState.DOWN)
    store.save_network_model(model)

    engine = InvestigationEngine(metadata_store=store)
    req = CreateInvestigationRequest(
        title="Counterfactual Remediation Test",
        investigation_type=InvestigationType.CONNECTIVITY_FAILURE,
        scope=InvestigationScope(
            source_ip="192.168.10.50",
            destination_ip="10.200.0.99",
            transport_protocol="TCP",
            destination_port=80,
            model_id=model.model_id,
        ),
    )
    case = engine.create_investigation(req)
    _ = engine.execute_investigation(case.investigation_id)

    # Run counterfactual: bring interface eth1 to state UP
    remediated_case = engine.run_counterfactual(
        investigation_id=case.investigation_id,
        scenario_name="Remediation: Bring eth1 UP",
        action_type=SimulationActionType.SET_INTERFACE_STATE,
        action_parameters={
            "node_id": "router-1",
            "interface_id": "eth1",
            "state": "UP",
        },
    )

    assert len(remediated_case.counterfactual_comparisons) == 1
    cf = remediated_case.counterfactual_comparisons[0]
    assert cf.baseline_status == "BLOCKED"
    assert cf.counterfactual_status == "REACHABLE"
    assert "REMEDIAL_ACTION_CONFIRMED" in cf.outcome_difference
    assert cf.is_counterfactual_verified is True


def test_investigation_rest_api_endpoints():
    client = TestClient(app)

    # 1. Create investigation
    create_payload = {
        "title": "API Test Investigation Case",
        "investigation_type": "CONNECTIVITY_FAILURE",
        "scope": {
            "source_ip": "192.168.1.10",
            "destination_ip": "10.0.0.5",
            "transport_protocol": "TCP",
            "destination_port": 80,
            "capture_ids": [],
            "snapshot_ids": [],
        },
    }
    res = client.post("/api/v1/twin/investigations", json=create_payload)
    assert res.status_code == 200
    data = res.json()
    inv_id = data["investigation_id"]
    assert data["title"] == create_payload["title"]

    # 2. List investigations
    res_list = client.get("/api/v1/twin/investigations")
    assert res_list.status_code == 200
    all_cases = res_list.json()
    assert any(c["investigation_id"] == inv_id for c in all_cases)

    # 3. Get specific case
    res_get = client.get(f"/api/v1/twin/investigations/{inv_id}")
    assert res_get.status_code == 200
    assert res_get.json()["investigation_id"] == inv_id

    # 4. Execute investigation
    res_exec = client.post(f"/api/v1/twin/investigations/{inv_id}/execute")
    assert res_exec.status_code == 200
    exec_data = res_exec.json()
    assert exec_data["status"] == "ANALYZED"
    assert "candidate_explanations" in exec_data

    # 5. Export artifact
    res_export = client.get(f"/api/v1/twin/investigations/{inv_id}/export")
    assert res_export.status_code == 200
    export_json = res_export.json()
    assert export_json["investigation_id"] == inv_id

    # 6. Delete
    res_del = client.delete(f"/api/v1/twin/investigations/{inv_id}")
    assert res_del.status_code == 200
    assert res_del.json()["deleted"] is True

    # 7. Confirm 404
    res_after = client.get(f"/api/v1/twin/investigations/{inv_id}")
    assert res_after.status_code == 404
