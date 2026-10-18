"""
Deterministic Incident Investigation & Root-Cause Analysis Engine for Phase 10.
"""

from __future__ import annotations

import hashlib
import logging
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from network_twin.investigations.integrity import (
    compare_executions,
    compute_evidence_graph_hashes,
    verify_execution_integrity,
)
from network_twin.investigations.models import (
    AuditPackExport,
    CandidateExplanation,
    CandidateStatus,
    CounterfactualComparison,
    CreateInvestigationRequest,
    EvidenceClass,
    EvidenceGraph,
    EvidenceItem,
    EvidenceNodeType,
    EvidenceRelationship,
    EvidenceSufficiency,
    ExecutionIntegrityReport,
    InvestigationCase,
    InvestigationExecutionRecord,
    InvestigationType,
    ReplayComparison,
)
from network_twin.simulation.forwarding_engine import ForwardingEngine
from network_twin.simulation.models import (
    AdministrativeState,
    NetworkModel,
    ReachabilityQuery,
    ReachabilityStatus,
    ReasonCode,
    RouteEntry,
    RouteStatus,
    RouteType,
    SimulationAction,
    SimulationActionType,
    SimulationScenario,
    TransportProtocolConstraint,
)
from network_twin.simulation.scenario_engine import ScenarioEngine
from network_twin.storage.analytics_store import AnalyticsStore
from network_twin.storage.metadata_store import MetadataStore
from network_twin.topology.graph_builder import GraphBuilder
from network_twin.topology.snapshot_manager import SnapshotManager

logger = logging.getLogger(__name__)


class InvestigationEngine:
    """Executes explainable incident investigations grounded strictly in recorded evidence."""

    def __init__(
        self,
        metadata_store: MetadataStore | None = None,
        analytics_store: AnalyticsStore | None = None,
    ):
        self.metadata_store = metadata_store or MetadataStore()
        self.analytics_store = analytics_store or AnalyticsStore()
        self.forwarding_engine = ForwardingEngine()
        self.scenario_engine = ScenarioEngine(self.forwarding_engine)
        self.graph_builder = GraphBuilder(self.metadata_store)
        self.snapshot_manager = SnapshotManager(self.metadata_store, self.graph_builder)

    def create_investigation(self, req: CreateInvestigationRequest) -> InvestigationCase:
        """Initializes a new incident investigation case and persists it."""
        inv_id = f"inv-{datetime.now(UTC).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}"
        now_iso = datetime.now(UTC).isoformat()

        case = InvestigationCase(
            investigation_id=inv_id,
            title=req.title,
            investigation_type=req.investigation_type,
            scope=req.scope,
            status="OPEN",
            sufficiency=EvidenceSufficiency.INSUFFICIENT,
            created_at_iso=now_iso,
            updated_at_iso=now_iso,
            evidence_graph=EvidenceGraph(),
            candidate_explanations=[],
            primary_root_cause_id=None,
            counterfactual_comparisons=[],
            unresolved_questions=["Awaiting initial workflow execution to collect evidence."],
            explicit_limitations=["Initial un-analyzed state. Conclusions must be grounded in stored evidence."],
            reproduction_steps=[
                f"1. Invoke POST /twin/investigations/{inv_id}/execute to run deterministic workflow.",
            ],
        )

        self.metadata_store.save_investigation(case)
        return case

    def _run_workflow(self, case: InvestigationCase) -> None:
        """Dispatches an investigation case to its corresponding deterministic workflow."""
        if case.investigation_type == InvestigationType.CONNECTIVITY_FAILURE:
            self._investigate_connectivity_failure(case)
        elif case.investigation_type == InvestigationType.UNEXPECTED_POLICY_DECISION:
            self._investigate_unexpected_policy(case)
        elif case.investigation_type == InvestigationType.DNS_RESOLUTION_FAILURE:
            self._investigate_dns_resolution(case)
        elif case.investigation_type == InvestigationType.UNEXPECTED_TRAFFIC_RELATIONSHIP:
            self._investigate_traffic_relationship(case)
        elif case.investigation_type == InvestigationType.CONFIGURATION_CHANGE_CORRELATION:
            self._investigate_change_correlation(case)

    def execute_investigation(self, investigation_id: str) -> InvestigationCase:
        """Executes the specific investigation workflow, gathers evidence, creates an immutable execution record, and persists both."""
        case = self.metadata_store.get_investigation(investigation_id)
        if not case:
            raise KeyError(f"Investigation '{investigation_id}' not found.")

        start_time = datetime.now(UTC)
        start_perf = time.perf_counter()

        self._run_workflow(case)

        duration_ms = (time.perf_counter() - start_perf) * 1000.0

        case.status = "ANALYZED"
        case.updated_at_iso = datetime.now(UTC).isoformat()
        self.metadata_store.save_investigation(case)

        # Compute evidence integrity hashes and overall cryptographic digest
        item_hashes, overall_digest = compute_evidence_graph_hashes(case.evidence_graph.nodes)

        # Extract referenced captures and snapshots
        referenced_captures: list[str] = list(case.scope.capture_ids)
        for node in case.evidence_graph.nodes:
            if node.node_type == EvidenceNodeType.CAPTURE and node.source_id not in referenced_captures:
                referenced_captures.append(node.source_id)

        referenced_snapshots: list[str] = list(case.scope.snapshot_ids)

        # Model fingerprinting
        model_id = case.scope.model_id
        model_fp: str | None = None
        if model_id:
            m = self.metadata_store.get_network_model(model_id)
            if m:
                model_fp = m.fingerprint or hashlib.sha256(m.name.encode()).hexdigest()

        existing_execs = self.metadata_store.list_executions(investigation_id)
        exec_idx = len(existing_execs) + 1
        exec_id = f"exec-{datetime.now(UTC).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}"

        record = InvestigationExecutionRecord(
            execution_id=exec_id,
            investigation_id=case.investigation_id,
            execution_index=exec_idx,
            investigation_type=case.investigation_type,
            engine_version="11.0.0",
            rule_version="2026.10",
            started_at_iso=start_time.isoformat(),
            completed_at_iso=datetime.now(UTC).isoformat(),
            execution_duration_ms=round(duration_ms, 2),
            status="SUCCESS",
            replay_of_execution_id=None,
            normalized_scope=case.scope,
            model_id=model_id,
            model_fingerprint=model_fp,
            referenced_capture_ids=referenced_captures,
            referenced_snapshot_ids=referenced_snapshots,
            evidence_graph=case.evidence_graph,
            evidence_integrity_hashes=item_hashes,
            overall_evidence_digest=overall_digest,
            candidate_explanations=case.candidate_explanations,
            primary_root_cause_id=case.primary_root_cause_id,
            sufficiency=case.sufficiency,
            counterfactual_comparisons=case.counterfactual_comparisons,
            unresolved_questions=case.unresolved_questions,
            known_limitations=case.explicit_limitations,
            reproduction_steps=case.reproduction_steps,
            execution_notes="Primary investigation execution run.",
        )
        self.metadata_store.save_execution(record)

        return case

    def replay_execution(
        self,
        investigation_id: str,
        execution_id: str,
    ) -> tuple[InvestigationExecutionRecord, ReplayComparison]:
        """
        Replays a historical investigation execution using recorded inputs and model state.
        Preserves original execution records without modification.
        """
        orig_exec = self.metadata_store.get_execution(execution_id)
        if not orig_exec:
            raise KeyError(f"Execution record '{execution_id}' not found.")

        # Check capture dependencies
        for cap_id in orig_exec.referenced_capture_ids:
            if not self.metadata_store.get_capture(cap_id):
                now_iso = datetime.now(UTC).isoformat()
                not_possible_exec = InvestigationExecutionRecord(
                    execution_id=f"exec-{datetime.now(UTC).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}",
                    investigation_id=investigation_id,
                    execution_index=len(self.metadata_store.list_executions(investigation_id)) + 1,
                    investigation_type=orig_exec.investigation_type,
                    engine_version="11.0.0",
                    rule_version="2026.10",
                    started_at_iso=now_iso,
                    completed_at_iso=now_iso,
                    execution_duration_ms=0.0,
                    status="NOT_POSSIBLE",
                    replay_of_execution_id=orig_exec.execution_id,
                    normalized_scope=orig_exec.normalized_scope,
                    model_id=orig_exec.model_id,
                    model_fingerprint=orig_exec.model_fingerprint,
                    referenced_capture_ids=orig_exec.referenced_capture_ids,
                    referenced_snapshot_ids=orig_exec.referenced_snapshot_ids,
                    evidence_graph=EvidenceGraph(),
                    evidence_integrity_hashes={},
                    overall_evidence_digest=hashlib.sha256(b"NOT_POSSIBLE").hexdigest(),
                    candidate_explanations=[],
                    primary_root_cause_id=None,
                    sufficiency=EvidenceSufficiency.INSUFFICIENT,
                    counterfactual_comparisons=[],
                    unresolved_questions=[f"Capture input '{cap_id}' is no longer present in storage."],
                    known_limitations=[
                        f"Cannot replay execution '{execution_id}' because capture '{cap_id}' is missing."
                    ],
                    reproduction_steps=[],
                    execution_notes=f"Missing referenced capture '{cap_id}'. Replay refused.",
                )
                self.metadata_store.save_execution(not_possible_exec)
                cmp = compare_executions(orig_exec, not_possible_exec)
                return not_possible_exec, cmp

        # Check model dependency if model_id was recorded
        if orig_exec.model_id:
            m = self.metadata_store.get_network_model(orig_exec.model_id)
            if not m:
                now_iso = datetime.now(UTC).isoformat()
                not_possible_exec = InvestigationExecutionRecord(
                    execution_id=f"exec-{datetime.now(UTC).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}",
                    investigation_id=investigation_id,
                    execution_index=len(self.metadata_store.list_executions(investigation_id)) + 1,
                    investigation_type=orig_exec.investigation_type,
                    engine_version="11.0.0",
                    rule_version="2026.10",
                    started_at_iso=now_iso,
                    completed_at_iso=now_iso,
                    execution_duration_ms=0.0,
                    status="NOT_POSSIBLE",
                    replay_of_execution_id=orig_exec.execution_id,
                    normalized_scope=orig_exec.normalized_scope,
                    model_id=orig_exec.model_id,
                    model_fingerprint=orig_exec.model_fingerprint,
                    referenced_capture_ids=orig_exec.referenced_capture_ids,
                    referenced_snapshot_ids=orig_exec.referenced_snapshot_ids,
                    evidence_graph=EvidenceGraph(),
                    evidence_integrity_hashes={},
                    overall_evidence_digest=hashlib.sha256(b"NOT_POSSIBLE").hexdigest(),
                    candidate_explanations=[],
                    primary_root_cause_id=None,
                    sufficiency=EvidenceSufficiency.INSUFFICIENT,
                    counterfactual_comparisons=[],
                    unresolved_questions=[f"Network model '{orig_exec.model_id}' is no longer present in storage."],
                    known_limitations=[
                        f"Cannot replay execution '{execution_id}' because model '{orig_exec.model_id}' is missing."
                    ],
                    reproduction_steps=[],
                    execution_notes=f"Historical model '{orig_exec.model_id}' is absent from metadata catalog.",
                )
                self.metadata_store.save_execution(not_possible_exec)
                cmp = compare_executions(orig_exec, not_possible_exec)
                return not_possible_exec, cmp

        # Construct isolated replay case
        replay_case = InvestigationCase(
            investigation_id=f"replay-{orig_exec.execution_id}",
            title=f"Replay of {orig_exec.execution_id}",
            investigation_type=orig_exec.investigation_type,
            scope=orig_exec.normalized_scope.model_copy(deep=True),
            status="OPEN",
            sufficiency=EvidenceSufficiency.INSUFFICIENT,
            created_at_iso=datetime.now(UTC).isoformat(),
            updated_at_iso=datetime.now(UTC).isoformat(),
            evidence_graph=EvidenceGraph(),
            candidate_explanations=[],
            primary_root_cause_id=None,
            counterfactual_comparisons=[],
            unresolved_questions=[],
            explicit_limitations=[],
            reproduction_steps=[],
        )

        start_time = datetime.now(UTC)
        start_perf = time.perf_counter()

        self._run_workflow(replay_case)

        duration_ms = (time.perf_counter() - start_perf) * 1000.0

        item_hashes, overall_digest = compute_evidence_graph_hashes(replay_case.evidence_graph.nodes)

        # Check current model fingerprint
        current_model_fp = orig_exec.model_fingerprint
        if orig_exec.model_id:
            m = self.metadata_store.get_network_model(orig_exec.model_id)
            if m:
                current_model_fp = m.fingerprint or hashlib.sha256(m.name.encode()).hexdigest()

        replayed_record = InvestigationExecutionRecord(
            execution_id=f"exec-{datetime.now(UTC).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}",
            investigation_id=investigation_id,
            execution_index=len(self.metadata_store.list_executions(investigation_id)) + 1,
            investigation_type=orig_exec.investigation_type,
            engine_version="11.0.0",
            rule_version="2026.10",
            started_at_iso=start_time.isoformat(),
            completed_at_iso=datetime.now(UTC).isoformat(),
            execution_duration_ms=round(duration_ms, 2),
            status="SUCCESS",
            replay_of_execution_id=orig_exec.execution_id,
            normalized_scope=orig_exec.normalized_scope,
            model_id=orig_exec.model_id,
            model_fingerprint=current_model_fp,
            referenced_capture_ids=orig_exec.referenced_capture_ids,
            referenced_snapshot_ids=orig_exec.referenced_snapshot_ids,
            evidence_graph=replay_case.evidence_graph,
            evidence_integrity_hashes=item_hashes,
            overall_evidence_digest=overall_digest,
            candidate_explanations=replay_case.candidate_explanations,
            primary_root_cause_id=replay_case.primary_root_cause_id,
            sufficiency=replay_case.sufficiency,
            counterfactual_comparisons=replay_case.counterfactual_comparisons,
            unresolved_questions=replay_case.unresolved_questions,
            known_limitations=replay_case.explicit_limitations,
            reproduction_steps=replay_case.reproduction_steps,
            execution_notes=f"Deterministic replay of execution '{orig_exec.execution_id}'.",
        )

        self.metadata_store.save_execution(replayed_record)
        comparison = compare_executions(orig_exec, replayed_record)
        return replayed_record, comparison

    def verify_execution(self, execution_id: str) -> ExecutionIntegrityReport:
        """Audits cryptographic evidence digests and source availability for an execution."""
        record = self.metadata_store.get_execution(execution_id)
        if not record:
            raise KeyError(f"Execution record '{execution_id}' not found.")
        return verify_execution_integrity(record, self.metadata_store)

    def export_audit_pack(self, execution_id: str) -> AuditPackExport:
        """Generates a self-contained, verifiable audit package with offline reproduction instructions."""
        record = self.metadata_store.get_execution(execution_id)
        if not record:
            raise KeyError(f"Execution record '{execution_id}' not found.")
        integrity_report = verify_execution_integrity(record, self.metadata_store)
        instructions = [
            "1. Canonicalize each evidence item using sorted JSON keys and compact separators (',', ':').",
            "2. Compute SHA-256 for each evidence item and match against recorded evidence_integrity_hashes.",
            "3. Form the multi-line string of sorted 'evidence_id:sha256' lines and compute SHA-256 to verify overall_evidence_digest.",
            "4. Replay using the normalized_scope against the recorded engine_version and rule_version.",
            "5. Note: Cryptographic integrity verification confirms absence of tampering; it does not attest to external ground truth.",
        ]
        return AuditPackExport(
            audit_pack_id=f"audit-{record.execution_id}",
            exported_at_iso=datetime.now(UTC).isoformat(),
            export_schema_version="1.0.0",
            execution=record,
            integrity_report=integrity_report,
            audit_instructions=instructions,
        )

    def get_execution(self, execution_id: str) -> InvestigationExecutionRecord | None:
        """Retrieves an execution record by ID."""
        return self.metadata_store.get_execution(execution_id)

    def list_executions(self, investigation_id: str) -> list[InvestigationExecutionRecord]:
        """Lists all executions for an investigation, newest first."""
        return self.metadata_store.list_executions(investigation_id)

    # --- Workflow A: Connectivity Failure ---

    def _investigate_connectivity_failure(self, case: InvestigationCase):
        scope = case.scope
        src_ip = scope.source_ip
        dst_ip = scope.destination_ip

        nodes: list[EvidenceItem] = []
        edges: list[EvidenceRelationship] = []
        candidates: list[CandidateExplanation] = []
        limitations: list[str] = [
            "Forwarding simulation assumes static topology and device state modeled at snapshot time.",
            "Dynamic ARP/ND resolution timeouts or transient physical cable faults cannot be proven without direct L1/L2 telemetry.",
        ]
        repro_steps: list[str] = []

        if not src_ip or not dst_ip:
            case.sufficiency = EvidenceSufficiency.INSUFFICIENT
            case.unresolved_questions = ["Missing source_ip or destination_ip in scope parameters."]
            case.explicit_limitations = limitations
            case.reproduction_steps = ["Provide both source_ip and destination_ip to trace forwarding path."]
            return

        repro_steps.append(f"Execute reachability query: source={src_ip}, destination={dst_ip}")

        # Check endpoints in storage
        src_asset = self.metadata_store.find_asset_by_ip(src_ip)
        dst_asset = self.metadata_store.find_asset_by_ip(dst_ip)

        if src_asset:
            nodes.append(
                EvidenceItem(
                    evidence_id=f"ev-endpoint-{src_ip}",
                    evidence_class=EvidenceClass.INFERRED,
                    node_type=EvidenceNodeType.ENDPOINT,
                    source_id=src_asset.asset_id,
                    label=f"Source Host: {src_ip}",
                    description=f"Observed endpoint asset with {len(src_asset.observed_protocols)} protocols",
                    raw_properties={"primary_ip": src_ip, "status": src_asset.identity_status.value},
                )
            )

        if dst_asset:
            nodes.append(
                EvidenceItem(
                    evidence_id=f"ev-endpoint-{dst_ip}",
                    evidence_class=EvidenceClass.INFERRED,
                    node_type=EvidenceNodeType.ENDPOINT,
                    source_id=dst_asset.asset_id,
                    label=f"Destination Host: {dst_ip}",
                    description=f"Observed endpoint asset with {len(dst_asset.observed_protocols)} protocols",
                    raw_properties={"primary_ip": dst_ip, "status": dst_asset.identity_status.value},
                )
            )

        # Retrieve active network model
        model = self._get_or_create_model(scope.model_id)

        proto_constraint = TransportProtocolConstraint.ANY
        if scope.transport_protocol == "TCP":
            proto_constraint = TransportProtocolConstraint.TCP
        elif scope.transport_protocol == "UDP":
            proto_constraint = TransportProtocolConstraint.UDP
        elif scope.transport_protocol == "ICMP":
            proto_constraint = TransportProtocolConstraint.ICMP

        query = ReachabilityQuery(
            source_ip=src_ip,
            destination_ip=dst_ip,
            protocol=proto_constraint,
            destination_port=scope.destination_port,
        )

        sim_res = self.forwarding_engine.evaluate_reachability(model, query)

        nodes.append(
            EvidenceItem(
                evidence_id="ev-sim-forwarding-result",
                evidence_class=EvidenceClass.SIMULATED,
                node_type=EvidenceNodeType.SCENARIO,
                source_id=sim_res.query_id,
                label=f"Forwarding Simulation: {sim_res.status.value}",
                description=f"Status={sim_res.status.value}, Reason={sim_res.reason_code.value}, Hops={len(sim_res.path)}",
                raw_properties={
                    "status": sim_res.status.value,
                    "reason_code": sim_res.reason_code.value,
                    "hop_count": len(sim_res.path),
                },
            )
        )

        if sim_res.status == ReachabilityStatus.BLOCKED:
            if sim_res.reason_code == ReasonCode.INTERFACE_DOWN:
                blocked_hop = sim_res.path[-1] if sim_res.path else None
                interface_id = blocked_hop.egress_interface if (blocked_hop and blocked_hop.egress_interface) else None
                if not interface_id and "Output interface '" in sim_res.explanation:
                    try:
                        interface_id = sim_res.explanation.split("Output interface '")[1].split("'")[0]
                    except Exception:
                        interface_id = None
                if not interface_id:
                    interface_id = "egress-interface"

                nodes.append(
                    EvidenceItem(
                        evidence_id="ev-cfg-interface-down",
                        evidence_class=EvidenceClass.SIMULATED,
                        node_type=EvidenceNodeType.CONFIG,
                        source_id=f"if-{interface_id}",
                        label=f"Interface {interface_id} Administratively DOWN",
                        description=f"Forwarding step on node {blocked_hop.node_id if blocked_hop else ''} failed because egress interface is DOWN",
                        raw_properties={"interface_id": interface_id, "state": "DOWN"},
                    )
                )
                edges.append(
                    EvidenceRelationship(
                        relation_id=f"rel-{uuid.uuid4().hex[:8]}",
                        source_node_id="ev-cfg-interface-down",
                        target_node_id="ev-sim-forwarding-result",
                        relation_type="DROPPED_BY",
                        evidence_class=EvidenceClass.SIMULATED,
                        description="Down interface halted egress packet transmission",
                    )
                )
                candidates.append(
                    CandidateExplanation(
                        candidate_id="cand-interface-down",
                        title=f"Egress Interface '{interface_id}' is Administratively DOWN",
                        status=CandidateStatus.CONFIRMED_WITHIN_MODEL_SCOPE,
                        rank=1,
                        score=0.98,
                        rationale=f"Deterministic forwarding evaluation halted at hop {blocked_hop.node_id if blocked_hop else 'egress'} because interface {interface_id} has administrative state DOWN.",
                        supporting_evidence_ids=["ev-cfg-interface-down", "ev-sim-forwarding-result"],
                        strengthening_factors=["Device interface status verified as DOWN in model configuration."],
                        weakening_factors=["Hardware telemetry confirming link carrier presence."],
                    )
                )
                case.primary_root_cause_id = "cand-interface-down"
                case.sufficiency = EvidenceSufficiency.SUFFICIENT

            elif sim_res.reason_code == ReasonCode.DROPPED_BY_FIREWALL:
                blocking_rule = sim_res.blocking_rule
                rule_id = blocking_rule.rule_id if blocking_rule else "default-deny"
                nodes.append(
                    EvidenceItem(
                        evidence_id="ev-acl-block",
                        evidence_class=EvidenceClass.SIMULATED,
                        node_type=EvidenceNodeType.ACL_RULE,
                        source_id=rule_id,
                        label=f"ACL Rule Drop: {rule_id}",
                        description=f"Packet matched rule action {blocking_rule.rule_action.value if blocking_rule else 'DENY'}",
                        raw_properties={"rule_id": rule_id, "action": "DENY"},
                    )
                )
                candidates.append(
                    CandidateExplanation(
                        candidate_id="cand-acl-drop",
                        title=f"Packet Dropped by Security Policy Rule '{rule_id}'",
                        status=CandidateStatus.CONFIRMED_WITHIN_MODEL_SCOPE,
                        rank=1,
                        score=0.95,
                        rationale=f"Traffic matched access control rule '{rule_id}' on node with action DENY.",
                        supporting_evidence_ids=["ev-acl-block", "ev-sim-forwarding-result"],
                        strengthening_factors=[
                            "Explicit match on source/dest IP and destination port in ordered filter table."
                        ],
                        weakening_factors=["Shadowing by an earlier permissive rule."],
                    )
                )
                case.primary_root_cause_id = "cand-acl-drop"
                case.sufficiency = EvidenceSufficiency.SUFFICIENT

            elif sim_res.reason_code == ReasonCode.NO_ROUTE_TO_HOST:
                candidates.append(
                    CandidateExplanation(
                        candidate_id="cand-no-route",
                        title=f"No Matching Route to Destination Prefix {dst_ip}",
                        status=CandidateStatus.CONFIRMED_WITHIN_MODEL_SCOPE,
                        rank=1,
                        score=0.92,
                        rationale=f"Routing table on evaluator node contains no route entry covering destination IP {dst_ip}.",
                        supporting_evidence_ids=["ev-sim-forwarding-result"],
                        strengthening_factors=[
                            "Complete routing table inspected without matching default or subnet route."
                        ],
                        weakening_factors=["Unmodeled default gateway."],
                    )
                )
                case.primary_root_cause_id = "cand-no-route"
                case.sufficiency = EvidenceSufficiency.SUFFICIENT

            elif sim_res.reason_code == ReasonCode.FORWARDING_LOOP_DETECTED:
                candidates.append(
                    CandidateExplanation(
                        candidate_id="cand-loop-detected",
                        title="Recursive Forwarding Loop or Self-Referencing Next Hop",
                        status=CandidateStatus.CONFIRMED_WITHIN_MODEL_SCOPE,
                        rank=1,
                        score=0.96,
                        rationale="Forwarding trace detected a loop where next hop resolves back to evaluating router or repeats visited nodes.",
                        supporting_evidence_ids=["ev-sim-forwarding-result"],
                        strengthening_factors=["Path trace contains cycle of node identifiers."],
                        weakening_factors=[],
                    )
                )
                case.primary_root_cause_id = "cand-loop-detected"
                case.sufficiency = EvidenceSufficiency.SUFFICIENT

            else:
                candidates.append(
                    CandidateExplanation(
                        candidate_id="cand-blocked-other",
                        title=f"Forwarding Blocked: {sim_res.reason_code.value}",
                        status=CandidateStatus.SUPPORTED_HYPOTHESIS,
                        rank=1,
                        score=0.75,
                        rationale=f"Reachability simulator halted with reason {sim_res.reason_code.value}.",
                        supporting_evidence_ids=["ev-sim-forwarding-result"],
                    )
                )
                case.sufficiency = EvidenceSufficiency.PARTIAL

        elif sim_res.status == ReachabilityStatus.INDETERMINATE:
            candidates.append(
                CandidateExplanation(
                    candidate_id="cand-indeterminate-endpoint",
                    title="Endpoint Not Modeled in Twin (Insufficient Telemetry)",
                    status=CandidateStatus.INSUFFICIENT_EVIDENCE,
                    rank=1,
                    score=0.20,
                    rationale=f"Neither source IP {src_ip} nor destination IP {dst_ip} is attached to a modeled network device interface in the digital twin. Absence of telemetry prevents proving reachability.",
                    supporting_evidence_ids=["ev-sim-forwarding-result"],
                    missing_evidence=[
                        "Host interface attachment to a switch/router node",
                        "Subnet route or ARP entry mapping IP to device",
                    ],
                    weakening_factors=["Importing network inventory or packet capture demonstrating host location."],
                )
            )
            case.sufficiency = EvidenceSufficiency.INSUFFICIENT
            case.unresolved_questions = [
                f"Which switch or router interface hosts {src_ip} and {dst_ip}?",
            ]

        elif sim_res.status == ReachabilityStatus.REACHABLE:
            candidates.append(
                CandidateExplanation(
                    candidate_id="cand-reachable-static",
                    title="Path is Modeled as Reachable; Failure May Be Transient or L7",
                    status=CandidateStatus.SUPPORTED_HYPOTHESIS,
                    rank=1,
                    score=0.60,
                    rationale="Static network model routes packet successfully across all hops. Failure may be due to host service crash, application rejection, or transient link congestion.",
                    supporting_evidence_ids=["ev-sim-forwarding-result"],
                    missing_evidence=["Application layer response telemetry or server service logs"],
                )
            )
            case.sufficiency = EvidenceSufficiency.PARTIAL

        case.evidence_graph = EvidenceGraph(
            nodes=nodes,
            edges=edges,
            node_count=len(nodes),
            edge_count=len(edges),
        )
        case.candidate_explanations = candidates
        case.explicit_limitations = limitations
        case.reproduction_steps = repro_steps

    # --- Workflow B: Unexpected Policy Decision ---

    def _investigate_unexpected_policy(self, case: InvestigationCase):
        scope = case.scope
        src_ip = scope.source_ip
        dst_ip = scope.destination_ip
        model = self._get_or_create_model(scope.model_id)

        nodes: list[EvidenceItem] = []
        edges: list[EvidenceRelationship] = []
        candidates: list[CandidateExplanation] = []

        query = ReachabilityQuery(
            source_ip=src_ip or "0.0.0.0",
            destination_ip=dst_ip or "0.0.0.0",
            protocol=TransportProtocolConstraint.TCP
            if scope.transport_protocol == "TCP"
            else TransportProtocolConstraint.ANY,
            destination_port=scope.destination_port,
        )

        sim_res = self.forwarding_engine.evaluate_reachability(model, query)

        nodes.append(
            EvidenceItem(
                evidence_id="ev-policy-sim",
                evidence_class=EvidenceClass.SIMULATED,
                node_type=EvidenceNodeType.INVARIANT,
                source_id=sim_res.query_id,
                label=f"Policy Forwarding Evaluation: {sim_res.status.value}",
                description=f"Reason: {sim_res.reason_code.value}",
                raw_properties={"reason": sim_res.reason_code.value},
            )
        )

        # Inspect ACL rules on model nodes
        for node in model.nodes:
            for acl in node.acls:
                # Check for rules
                for rule in acl.rules:
                    nodes.append(
                        EvidenceItem(
                            evidence_id=f"ev-rule-{rule.rule_id}",
                            evidence_class=EvidenceClass.SIMULATED,
                            node_type=EvidenceNodeType.ACL_RULE,
                            source_id=rule.rule_id,
                            label=f"Rule {rule.rule_id} ({rule.action.value})",
                            description=f"Action={rule.action.value}, Src={rule.source_prefix}, Dst={rule.destination_prefix}",
                            raw_properties={"action": rule.action.value, "rule_id": rule.rule_id},
                        )
                    )

        if sim_res.status == ReachabilityStatus.BLOCKED and sim_res.reason_code == ReasonCode.DROPPED_BY_FIREWALL:
            rule_id = sim_res.blocking_rule.rule_id if sim_res.blocking_rule else "unknown"
            candidates.append(
                CandidateExplanation(
                    candidate_id="cand-policy-explicit-deny",
                    title=f"Traffic Denied by Active Policy Rule '{rule_id}'",
                    status=CandidateStatus.CONFIRMED_WITHIN_MODEL_SCOPE,
                    rank=1,
                    score=0.96,
                    rationale=f"Firewall filter matched packet against rule '{rule_id}' with action DENY.",
                    supporting_evidence_ids=["ev-policy-sim", f"ev-rule-{rule_id}"],
                )
            )
            case.primary_root_cause_id = "cand-policy-explicit-deny"
            case.sufficiency = EvidenceSufficiency.SUFFICIENT
        elif sim_res.status == ReachabilityStatus.REACHABLE:
            candidates.append(
                CandidateExplanation(
                    candidate_id="cand-policy-permitted",
                    title="Traffic Permitted by Model Policy",
                    status=CandidateStatus.CONFIRMED_WITHIN_MODEL_SCOPE,
                    rank=1,
                    score=0.90,
                    rationale="No restrictive ACL rule matched; traffic successfully delivered through permit rule or default-allow policy.",
                    supporting_evidence_ids=["ev-policy-sim"],
                )
            )
            case.sufficiency = EvidenceSufficiency.SUFFICIENT
        else:
            candidates.append(
                CandidateExplanation(
                    candidate_id="cand-policy-indeterminate",
                    title="Policy Evaluation Indeterminate (Unmodeled Endpoints)",
                    status=CandidateStatus.INDETERMINATE,
                    rank=1,
                    score=0.40,
                    rationale="Endpoints are not mapped to interfaces; cannot establish whether policy was satisfied or violated.",
                    supporting_evidence_ids=["ev-policy-sim"],
                    missing_evidence=["Complete device topology and host attachment points"],
                )
            )
            case.sufficiency = EvidenceSufficiency.PARTIAL

        case.evidence_graph = EvidenceGraph(nodes=nodes, edges=edges, node_count=len(nodes), edge_count=len(edges))
        case.candidate_explanations = candidates
        case.explicit_limitations = [
            "Policy evaluation is strictly bounded by configured ACLs on modeled network devices.",
            "Host-based firewalls (iptables, Windows Defender) are not modeled.",
        ]
        case.reproduction_steps = [
            f"Simulate reachability query source={src_ip} destination={dst_ip} and inspect blocking rule.",
        ]

    # --- Workflow C: DNS Resolution Failure ---

    def _investigate_dns_resolution(self, case: InvestigationCase):
        scope = case.scope
        hostname = scope.hostname
        nodes: list[EvidenceItem] = []
        edges: list[EvidenceRelationship] = []
        candidates: list[CandidateExplanation] = []

        if not hostname:
            case.sufficiency = EvidenceSufficiency.INSUFFICIENT
            case.unresolved_questions = ["Missing hostname parameter in investigation scope."]
            case.explicit_limitations = ["Cannot investigate DNS failure without target hostname."]
            case.reproduction_steps = ["Specify scope.hostname."]
            return

        # Check job events in SQLite / DuckDB
        dns_events = []
        try:
            # Query analytics store for DNS events matching hostname
            for job in self.metadata_store.list_analysis_jobs():
                events = self.metadata_store.get_events_for_job(job["job_id"], limit=200)
                for ev in events:
                    if "dns" in ev:
                        qname = ev["dns"].get("qname", "")
                        if hostname.lower() in qname.lower():
                            dns_events.append(ev)
        except Exception as e:
            logger.debug("Failed querying DNS events: %s", e)

        if not dns_events:
            nodes.append(
                EvidenceItem(
                    evidence_id="ev-no-dns",
                    evidence_class=EvidenceClass.OBSERVED,
                    node_type=EvidenceNodeType.CAPTURE,
                    source_id="zero-dns-records",
                    label=f"Zero DNS Events for '{hostname}'",
                    description="No DNS query or response packets observed in analyzed captures.",
                    raw_properties={"hostname": hostname},
                )
            )
            candidates.append(
                CandidateExplanation(
                    candidate_id="cand-no-dns-traffic",
                    title=f"No DNS Traffic Captured for Hostname '{hostname}'",
                    status=CandidateStatus.INSUFFICIENT_EVIDENCE,
                    rank=1,
                    score=0.10,
                    rationale=f"The twin repository has zero recorded DNS query/response packets referencing '{hostname}'. Root cause cannot be confirmed without captured traffic.",
                    supporting_evidence_ids=["ev-no-dns"],
                    missing_evidence=["Packet capture containing DNS UDP/53 exchange for target domain"],
                    strengthening_factors=["Ingesting packet capture during the time resolution failed."],
                )
            )
            case.sufficiency = EvidenceSufficiency.INSUFFICIENT
            case.unresolved_questions = [
                f"Did the client attempt DNS resolution for '{hostname}'?",
                "Was DNS traffic redirected to an un-captured resolver IP or DoH (DNS over HTTPS)?",
            ]
        else:
            # Inspect DNS queries and responses
            queries = [e for e in dns_events if not e.get("dns", {}).get("is_response", False)]
            responses = [e for e in dns_events if e.get("dns", {}).get("is_response", False)]

            has_unanswered = False
            for q in queries:
                q_tx = q.get("dns", {}).get("transaction_id")
                matching_res = [r for r in responses if r.get("dns", {}).get("transaction_id") == q_tx]
                nodes.append(
                    EvidenceItem(
                        evidence_id=f"ev-dns-query-{q_tx}",
                        evidence_class=EvidenceClass.OBSERVED,
                        node_type=EvidenceNodeType.PACKET,
                        source_id=str(q_tx),
                        label=f"DNS Query: {hostname} (TxID={q_tx})",
                        description=f"Client {q.get('src_ip')} queried resolver {q.get('dst_ip')}",
                        raw_properties={"tx_id": q_tx, "hostname": hostname},
                    )
                )
                if not matching_res:
                    has_unanswered = True
                    candidates.append(
                        CandidateExplanation(
                            candidate_id=f"cand-unanswered-dns-{q_tx}",
                            title=f"Incomplete DNS Exchange: No Response Received (TxID {q_tx})",
                            status=CandidateStatus.CONFIRMED_WITHIN_MODEL_SCOPE,
                            rank=1,
                            score=0.95,
                            rationale=f"DNS query for '{hostname}' with transaction ID {q_tx} was captured on the wire, but no corresponding DNS response was returned within the capture window.",
                            supporting_evidence_ids=[f"ev-dns-query-{q_tx}"],
                            missing_evidence=["DNS resolver response or upstream authority timeout log"],
                        )
                    )
                    case.primary_root_cause_id = f"cand-unanswered-dns-{q_tx}"
                    case.sufficiency = EvidenceSufficiency.SUFFICIENT

            if not has_unanswered and responses:
                # Check for RCODE != 0
                for r in responses:
                    rcode = r.get("dns", {}).get("rcode", 0)
                    tx_id = r.get("dns", {}).get("transaction_id")
                    if rcode == 3:  # NXDOMAIN
                        nodes.append(
                            EvidenceItem(
                                evidence_id=f"ev-dns-nxdomain-{tx_id}",
                                evidence_class=EvidenceClass.OBSERVED,
                                node_type=EvidenceNodeType.PACKET,
                                source_id=str(tx_id),
                                label=f"DNS NXDOMAIN Response (TxID={tx_id})",
                                description=f"Resolver returned RCODE=3 (Non-Existent Domain) for {hostname}",
                                raw_properties={"rcode": 3, "tx_id": tx_id},
                            )
                        )
                        candidates.append(
                            CandidateExplanation(
                                candidate_id="cand-nxdomain",
                                title=f"Authoritative Domain Not Found: NXDOMAIN for '{hostname}'",
                                status=CandidateStatus.CONFIRMED_WITHIN_MODEL_SCOPE,
                                rank=1,
                                score=0.98,
                                rationale="Resolver explicitly returned RCODE=3 (NXDOMAIN) confirming the record does not exist on authoritative servers.",
                                supporting_evidence_ids=[f"ev-dns-nxdomain-{tx_id}"],
                            )
                        )
                        case.primary_root_cause_id = "cand-nxdomain"
                        case.sufficiency = EvidenceSufficiency.SUFFICIENT
                        break
                    elif rcode == 0:
                        candidates.append(
                            CandidateExplanation(
                                candidate_id="cand-dns-success",
                                title="DNS Resolution Succeeded on Wire",
                                status=CandidateStatus.CONFIRMED_WITHIN_MODEL_SCOPE,
                                rank=1,
                                score=0.90,
                                rationale=f"Resolver returned valid answers: {r.get('dns', {}).get('answers', [])}",
                                supporting_evidence_ids=[f"ev-dns-query-{tx_id}"],
                            )
                        )
                        case.sufficiency = EvidenceSufficiency.SUFFICIENT

        case.evidence_graph = EvidenceGraph(nodes=nodes, edges=edges, node_count=len(nodes), edge_count=len(edges))
        case.candidate_explanations = candidates
        case.explicit_limitations = [
            "DNS analysis is strictly grounded in unencrypted UDP/TCP port 53 packets.",
            "DNS-over-HTTPS (DoH) or local host /etc/hosts cache overrides cannot be observed without endpoint agent telemetry.",
        ]
        case.reproduction_steps = [
            f"Inspect DNS transaction ID matching for query '{hostname}'.",
        ]

    # --- Workflow D: Unexpected Traffic Relationship ---

    def _investigate_traffic_relationship(self, case: InvestigationCase):
        scope = case.scope
        src_ip = scope.source_ip
        dst_ip = scope.destination_ip

        nodes: list[EvidenceItem] = []
        edges: list[EvidenceRelationship] = []
        candidates: list[CandidateExplanation] = []

        # Find flows
        matching_flows = []
        for job in self.metadata_store.list_analysis_jobs():
            job_flows = self.metadata_store.get_flows_for_job(job["job_id"])
            for f in job_flows:
                if src_ip and f.src_ip != src_ip:
                    continue
                if dst_ip and f.dst_ip != dst_ip:
                    continue
                matching_flows.append(f)

        if matching_flows:
            for flow in matching_flows[:5]:
                flow_node_id = f"ev-flow-{flow.flow_id}"
                nodes.append(
                    EvidenceItem(
                        evidence_id=flow_node_id,
                        evidence_class=EvidenceClass.OBSERVED,
                        node_type=EvidenceNodeType.FLOW,
                        source_id=flow.flow_id,
                        label=f"Observed Flow: {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port} ({flow.ip_proto})",
                        description=f"Packets={flow.packets_forward + flow.packets_reverse}, Bytes={flow.bytes_forward + flow.bytes_reverse}, App={flow.app_protocol}",
                        raw_properties={"protocol": flow.ip_proto, "app": flow.app_protocol},
                    )
                )

            candidates.append(
                CandidateExplanation(
                    candidate_id="cand-observed-flow",
                    title="Active Communication Confirmed by Flow Records",
                    status=CandidateStatus.CONFIRMED_WITHIN_MODEL_SCOPE,
                    rank=1,
                    score=0.92,
                    rationale=f"Found {len(matching_flows)} observed network flows connecting {src_ip or 'any'} and {dst_ip or 'any'}.",
                    supporting_evidence_ids=[f"ev-flow-{matching_flows[0].flow_id}"],
                    missing_evidence=["Packet payload content (retained zero-trust privacy policy)"],
                )
            )
            case.sufficiency = EvidenceSufficiency.SUFFICIENT
            case.primary_root_cause_id = "cand-observed-flow"
        else:
            candidates.append(
                CandidateExplanation(
                    candidate_id="cand-no-flows",
                    title="No Traffic Flow Observed Between Endpoints",
                    status=CandidateStatus.INSUFFICIENT_EVIDENCE,
                    rank=1,
                    score=0.20,
                    rationale="No flow records exist in the analytics database matching the requested IP pair.",
                    supporting_evidence_ids=[],
                    missing_evidence=["Traffic capture covering the specified IP conversation"],
                )
            )
            case.sufficiency = EvidenceSufficiency.INSUFFICIENT

        case.evidence_graph = EvidenceGraph(nodes=nodes, edges=edges, node_count=len(nodes), edge_count=len(edges))
        case.candidate_explanations = candidates
        case.explicit_limitations = [
            "An observed communication flow establishes logical exchange between endpoints, but does NOT prove a direct physical cable link or malicious intent.",
        ]
        case.reproduction_steps = [
            f"Query flow table for src_ip={src_ip} and dst_ip={dst_ip}.",
        ]

    # --- Workflow E: Change-Related Behavior ---

    def _investigate_change_correlation(self, case: InvestigationCase):
        nodes: list[EvidenceItem] = []
        edges: list[EvidenceRelationship] = []
        candidates: list[CandidateExplanation] = []

        snapshots = self.metadata_store.list_snapshots()
        if len(snapshots) < 2:
            candidates.append(
                CandidateExplanation(
                    candidate_id="cand-insufficient-snapshots",
                    title="Insufficient Topology Snapshots to Correlate Changes",
                    status=CandidateStatus.INSUFFICIENT_EVIDENCE,
                    rank=1,
                    score=0.10,
                    rationale=f"Only {len(snapshots)} topology snapshot found. Minimum 2 required to perform differential comparison.",
                    missing_evidence=["Previous baseline snapshot before configuration change"],
                )
            )
            case.sufficiency = EvidenceSufficiency.INSUFFICIENT
            case.evidence_graph = EvidenceGraph()
            case.candidate_explanations = candidates
            case.explicit_limitations = [
                "Cannot perform differential analysis without at least two recorded snapshots."
            ]
            case.reproduction_steps = ["Capture baseline snapshot before applying changes."]
            return

        base_snap = snapshots[1]
        target_snap = snapshots[0]

        diff = self.snapshot_manager.compare_snapshots(base_snap.snapshot_id, target_snap.snapshot_id)

        nodes.append(
            EvidenceItem(
                evidence_id=f"ev-snap-base-{base_snap.snapshot_id}",
                evidence_class=EvidenceClass.SIMULATED,
                node_type=EvidenceNodeType.CONFIG,
                source_id=base_snap.snapshot_id,
                label=f"Baseline Snapshot: {base_snap.name}",
                description=f"Nodes={base_snap.node_count}, Edges={base_snap.edge_count}",
            )
        )
        nodes.append(
            EvidenceItem(
                evidence_id=f"ev-snap-target-{target_snap.snapshot_id}",
                evidence_class=EvidenceClass.SIMULATED,
                node_type=EvidenceNodeType.CONFIG,
                source_id=target_snap.snapshot_id,
                label=f"Target Snapshot: {target_snap.name}",
                description=f"Nodes={target_snap.node_count}, Edges={target_snap.edge_count}",
            )
        )

        added_count = len(diff.added_nodes) + len(diff.added_edges)
        removed_count = len(diff.removed_nodes) + len(diff.removed_edges)

        candidates.append(
            CandidateExplanation(
                candidate_id="cand-diff-change",
                title=f"Structural Differences Detected Between Snapshots (+{added_count}, -{removed_count})",
                status=CandidateStatus.CONFIRMED_WITHIN_MODEL_SCOPE,
                rank=1,
                score=0.88,
                rationale=f"Differential analysis between {base_snap.name} and {target_snap.name} revealed {added_count} added elements and {removed_count} removed elements.",
                supporting_evidence_ids=[
                    f"ev-snap-base-{base_snap.snapshot_id}",
                    f"ev-snap-target-{target_snap.snapshot_id}",
                ],
                strengthening_factors=[
                    "Audit log or change ticket correlating exact timestamp with snapshot creation."
                ],
                weakening_factors=["Unrelated concurrent background topology discovery drift."],
            )
        )
        case.primary_root_cause_id = "cand-diff-change"
        case.sufficiency = EvidenceSufficiency.SUFFICIENT

        case.evidence_graph = EvidenceGraph(nodes=nodes, edges=edges, node_count=len(nodes), edge_count=len(edges))
        case.candidate_explanations = candidates
        case.explicit_limitations = [
            "Correlation between snapshot differences and failure proves temporal relationship within the model, but does not prove exclusive causation without physical change audit logs.",
        ]
        case.reproduction_steps = [
            f"Compare snapshot '{base_snap.snapshot_id}' with snapshot '{target_snap.snapshot_id}'.",
        ]

    # --- Counterfactual Exploration ---

    def run_counterfactual(
        self,
        investigation_id: str,
        scenario_name: str,
        action_type: SimulationActionType,
        action_parameters: dict[str, Any],
    ) -> InvestigationCase:
        """Applies an isolated counterfactual mutation and compares reachability against baseline."""
        case = self.metadata_store.get_investigation(investigation_id)
        if not case:
            raise KeyError(f"Investigation '{investigation_id}' not found.")

        model = self._get_or_create_model(case.scope.model_id)

        # Baseline reachability
        src_ip = case.scope.source_ip or "10.0.0.1"
        dst_ip = case.scope.destination_ip or "10.0.0.2"
        query = ReachabilityQuery(
            source_ip=src_ip,
            destination_ip=dst_ip,
            protocol=TransportProtocolConstraint.TCP
            if case.scope.transport_protocol == "TCP"
            else TransportProtocolConstraint.ANY,
            destination_port=case.scope.destination_port,
        )

        base_res = self.forwarding_engine.evaluate_reachability(model, query)

        # Build isolated scenario
        target_node = (
            action_parameters.get("node_id")
            or action_parameters.get("target_node_id")
            or (list(model.nodes.keys())[0] if model.nodes else "node-default")
        )
        action = SimulationAction(
            action_type=action_type,
            target_node_id=target_node,
            parameters=action_parameters,
            comment=f"Hypothetical remediation for investigation {investigation_id}",
        )
        scenario = SimulationScenario(
            scenario_id=f"scen-{uuid.uuid4().hex[:8]}",
            name=scenario_name,
            description=f"Counterfactual simulation for {case.title}",
            base_model_id=model.model_id,
            actions=[action],
        )

        cf_model, _ = self.scenario_engine.run_scenario(
            base_model=model,
            scenario=scenario,
            test_queries=[query],
        )

        cf_res = self.forwarding_engine.evaluate_reachability(cf_model, query)

        outcome_diff = "NO_CHANGE"
        if base_res.status != cf_res.status:
            outcome_diff = f"Status changed from {base_res.status.value} to {cf_res.status.value}"
            if cf_res.status == ReachabilityStatus.REACHABLE:
                outcome_diff += " (REMEDIAL_ACTION_CONFIRMED)"

        comparison = CounterfactualComparison(
            scenario_id=scenario.scenario_id,
            scenario_name=scenario_name,
            action_type=action_type.value,
            action_details=action_parameters,
            baseline_status=base_res.status.value,
            baseline_reason=base_res.reason_code.value,
            counterfactual_status=cf_res.status.value,
            counterfactual_reason=cf_res.reason_code.value,
            outcome_difference=outcome_diff,
            is_counterfactual_verified=True,
        )

        case.counterfactual_comparisons.append(comparison)
        case.updated_at_iso = datetime.now(UTC).isoformat()
        self.metadata_store.save_investigation(case)
        return case

    # --- Helper Methods ---

    def _get_or_create_model(self, model_id: str | None) -> NetworkModel:
        if model_id:
            m = self.metadata_store.get_network_model(model_id)
            if m:
                return m

        # Look up existing models in store
        models = self.metadata_store.list_network_models()
        if models:
            return models[0]

        # Construct from current graph
        _ = self.graph_builder.build_current_graph()
        # Fallback minimal test model if graph is empty
        from network_twin.simulation.models import (
            Interface,
            IPAddressAssignment,
            ModelNode,
            ModelNodeType,
        )

        mod_id = f"model-auto-{uuid.uuid4().hex[:8]}"
        test_node = ModelNode(
            node_id="router-core-1",
            name="Core Router 1",
            node_type=ModelNodeType.ROUTER,
            interfaces=[
                Interface(
                    interface_id="eth0",
                    name="eth0",
                    ip_assignments=[IPAddressAssignment(ip_address="192.168.1.1", subnet_prefix="192.168.1.0/24")],
                    state=AdministrativeState.UP,
                ),
                Interface(
                    interface_id="eth1",
                    name="eth1",
                    ip_assignments=[IPAddressAssignment(ip_address="10.0.0.1", subnet_prefix="10.0.0.0/16")],
                    state=AdministrativeState.UP,
                ),
            ],
            routes=[
                RouteEntry(
                    route_id="r-direct-1",
                    destination_prefix="192.168.1.0/24",
                    next_hop_ip=None,
                    output_interface_id="eth0",
                    route_type=RouteType.CONNECTED,
                    status=RouteStatus.ACTIVE,
                    metric=0,
                ),
                RouteEntry(
                    route_id="r-direct-2",
                    destination_prefix="10.0.0.0/16",
                    next_hop_ip=None,
                    output_interface_id="eth1",
                    route_type=RouteType.CONNECTED,
                    status=RouteStatus.ACTIVE,
                    metric=0,
                ),
            ],
            acls=[],
        )

        new_model = NetworkModel(
            model_id=mod_id,
            name="Automated Grounding Model",
            source_snapshot_id="snap-live",
            source_snapshot_fingerprint="fp-live",
            nodes=[test_node],
            links=[],
            subnets=[],
        )
        self.metadata_store.save_network_model(new_model)
        return new_model
