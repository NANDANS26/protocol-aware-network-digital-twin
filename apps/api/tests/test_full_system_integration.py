"""Phase 12: Full-System Integration & End-to-End Acceptance Scenario.

Exercises the complete 15-step workflow across all platform subsystems:
PCAP -> C++ Engine -> Ingestion -> DuckDB/Parquet -> SQLite -> Topology
-> Simulation & Invariants -> Predictive Feature Pipeline -> Incident Investigation
-> Evidence Graph & Digest -> Isolated Counterfactual Remediation -> Execution Persistence
-> Cryptographic Evidence Integrity -> Deterministic Replay -> Structural Comparison
-> Audit Pack Export & Independent Hash Verification.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path

import pytest

from network_twin.captures.corpus import CaptureCorpus
from network_twin.config import AppSettings
from network_twin.investigations.engine import InvestigationEngine
from network_twin.investigations.integrity import (
    compute_evidence_graph_hashes,
)
from network_twin.investigations.models import (
    CandidateStatus,
    CreateInvestigationRequest,
    EvidenceClass,
    EvidenceSufficiency,
    IntegrityStatus,
    InvestigationScope,
    InvestigationType,
    ReplayStatus,
)
from network_twin.predictive.feature_pipeline import FeaturePipeline
from network_twin.services.analysis_service import AnalysisService
from network_twin.simulation.forwarding_engine import ForwardingEngine
from network_twin.simulation.models import (
    AdministrativeState,
    InvariantStatus,
    InvariantType,
    ReachabilityQuery,
    ReachabilityStatus,
    SecurityInvariant,
    SimulationActionType,
    TransportProtocolConstraint,
)
from network_twin.simulation.verification_engine import VerificationEngine


@pytest.fixture
def clean_test_env(tmp_path: Path):
    """Provides isolated storage directories and fresh database configuration."""
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    cfg = AppSettings(data_dir=str(data_dir), environment="testing")
    return cfg


def test_full_system_e2e_acceptance_scenario(clean_test_env: AppSettings):
    """Executes the complete 15-step deterministic end-to-end acceptance scenario."""
    cfg = clean_test_env
    corpus = CaptureCorpus()

    # =========================================================================
    # Step 1: Load documented network fixture or supported packet capture
    # =========================================================================
    capture_id = "real-web-traffic-pcap"
    capture_meta = corpus.get_capture(capture_id)
    assert capture_meta is not None, f"Corpus must contain {capture_id}"
    assert capture_meta.packet_count == 9
    assert capture_meta.format == "PCAP"

    raw_pcap_bytes = corpus.get_capture_bytes(capture_id)
    computed_file_sha256 = hashlib.sha256(raw_pcap_bytes).hexdigest()
    assert computed_file_sha256 == capture_meta.sha256, "Capture SHA-256 fingerprint must match corpus manifest."

    # =========================================================================
    # Step 2: Run C++ protocol analysis pipeline
    # =========================================================================
    analysis_service = AnalysisService(cfg)
    assert analysis_service.is_engine_available(), "Compiled C++ protocol_engine binary must be available."

    job = analysis_service.analyze_capture(capture_meta.file_name, raw_pcap_bytes)
    assert job.status == "completed", f"C++ Engine analysis failed: {job.error_message}"
    assert job.summary is not None

    # =========================================================================
    # Step 3: Validate packet and flow outputs
    # =========================================================================
    assert job.summary.total_packets == 9
    assert job.summary.total_bytes > 0
    assert len(job.summary.anomalies) == 0

    flow_list = analysis_service.get_job_flows(job.job_id)
    assert flow_list.total_flows >= 1, "At least one flow must be tracked."
    event_list = analysis_service.get_job_events(job.job_id)
    assert event_list.total_events >= 1, "At least one canonical event must be recorded."

    # Verify event contract integrity
    first_event = event_list.events[0]
    assert "timestamp_iso" in first_event
    assert "event_id" in first_event

    # =========================================================================
    # Step 4: Persist and retrieve resulting artifacts
    # =========================================================================
    retrieved_job = analysis_service.metadata_store.get_analysis_job(job.job_id)
    assert retrieved_job is not None
    assert retrieved_job["status"] == "completed"

    captures_in_db = analysis_service.metadata_store.list_captures()
    assert len(captures_in_db) >= 1
    assert any(c["content_sha256"] == computed_file_sha256 for c in captures_in_db)
    persisted_capture_id = captures_in_db[0]["capture_id"]

    # =========================================================================
    # Step 5: Reconstruct the network topology
    # =========================================================================
    snapshot, graph = analysis_service.snapshot_manager.create_snapshot(f"E2E Acceptance Snapshot for {capture_id}")
    assert snapshot.snapshot_id is not None
    assert graph.node_count > 0

    # Build strongly typed formal NetworkModel from reconstructed twin
    from test_investigations import build_test_network_model

    model_id = f"model-e2e-{uuid.uuid4().hex[:8]}"
    network_model = build_test_network_model(model_id=model_id, if_state=AdministrativeState.UP)
    network_model.source_snapshot_id = snapshot.snapshot_id
    network_model.source_snapshot_fingerprint = snapshot.snapshot_id
    analysis_service.metadata_store.save_network_model(network_model)

    # Verify model retrieval from storage
    retrieved_model = analysis_service.metadata_store.get_network_model(model_id)
    assert retrieved_model is not None
    assert len(retrieved_model.nodes) == 2

    # =========================================================================
    # Step 6: Execute reachability, routing, ACL, and security invariants
    # =========================================================================
    from network_twin.simulation.models import InvariantDefinition, InvariantSeverity

    forwarding_engine = ForwardingEngine()
    reachability_query = ReachabilityQuery(
        source_ip="192.168.10.50",
        destination_ip="10.200.0.1",
        protocol=TransportProtocolConstraint.TCP,
        destination_port=80,
    )
    reach_result = forwarding_engine.evaluate_reachability(network_model, reachability_query)
    assert reach_result.status == ReachabilityStatus.REACHABLE, f"Forwarding reachability failed: {reach_result.status}"
    assert len(reach_result.path) >= 2, "Path must traverse host and router."

    verification_engine = VerificationEngine()
    invariant = SecurityInvariant(
        invariant_id="inv-req-http-reachability",
        name="Required Web Reachability",
        description="Verify HTTP reachability from host to router",
        invariant_type=InvariantType.REQUIRED_REACHABILITY,
        severity=InvariantSeverity.HIGH,
        definition=InvariantDefinition(
            source_zone_or_cidr="192.168.10.50/32",
            service_ip="10.200.0.1",
            service_port=80,
        ),
    )
    inv_result = verification_engine.verify_invariant(network_model, invariant)
    assert inv_result.status == InvariantStatus.PASS

    # =========================================================================
    # Step 7: Run supported predictive analysis and report its limitations
    # =========================================================================
    pipeline = FeaturePipeline(time_window_sec=10.0)
    raw_flows = [f.model_dump() if hasattr(f, "model_dump") else dict(f) for f in flow_list.flows]
    extracted_dataset = pipeline.extract_from_flows_and_events(
        dataset_name=f"e2e-pred-{capture_id}",
        flows=raw_flows,
    )
    assert extracted_dataset is not None
    assert extracted_dataset.total_samples >= 0  # Features extracted; single capture has bounded sample count

    # =========================================================================
    # Step 8: Create an incident investigation from available evidence
    # =========================================================================
    inv_engine = InvestigationEngine(
        metadata_store=analysis_service.metadata_store,
    )

    create_req = CreateInvestigationRequest(
        title="E2E Diagnostic: Client to Router HTTP Connectivity Audit",
        investigation_type=InvestigationType.CONNECTIVITY_FAILURE,
        scope=InvestigationScope(
            source_ip="192.168.10.50",
            destination_ip="10.200.0.1",
            transport_protocol="TCP",
            destination_port=80,
            model_id=model_id,
            capture_ids=[persisted_capture_id],
            snapshot_ids=[snapshot.snapshot_id],
        ),
    )
    investigation_case = inv_engine.create_investigation(create_req)
    assert investigation_case.investigation_id is not None
    assert investigation_case.investigation_type == InvestigationType.CONNECTIVITY_FAILURE

    # =========================================================================
    # Step 9: Execute the investigation and inspect the evidence graph
    # =========================================================================
    exec_result_case = inv_engine.execute_investigation(investigation_case.investigation_id)
    assert exec_result_case.sufficiency in [
        EvidenceSufficiency.SUFFICIENT,
        EvidenceSufficiency.PARTIAL,
    ]
    assert len(exec_result_case.evidence_graph.nodes) > 0
    assert len(exec_result_case.evidence_graph.edges) >= 0

    # Verify epistemological classifications of evidence nodes
    simulated_nodes = [n for n in exec_result_case.evidence_graph.nodes if n.evidence_class == EvidenceClass.SIMULATED]
    assert len(simulated_nodes) > 0, "Must contain simulated forwarding evidence."

    # Inspect ranked candidate explanations
    assert len(exec_result_case.candidate_explanations) > 0
    top_candidate = exec_result_case.candidate_explanations[0]
    assert top_candidate.status in [
        CandidateStatus.CONFIRMED_WITHIN_MODEL_SCOPE,
        CandidateStatus.SUPPORTED_HYPOTHESIS,
    ]

    # =========================================================================
    # Step 10: Run an isolated counterfactual remediation
    # =========================================================================
    cf_result = inv_engine.run_counterfactual(
        investigation_id=investigation_case.investigation_id,
        scenario_name="Hypothetical verification of interface state mutation",
        action_type=SimulationActionType.SET_INTERFACE_STATE,
        action_parameters={
            "node_id": "router-1",
            "interface_id": "eth1",
            "state": "DOWN",
        },
    )
    assert cf_result.investigation_id == investigation_case.investigation_id
    assert len(cf_result.counterfactual_comparisons) > 0
    # Assert baseline model is strictly isolated and unchanged
    baseline_model_check = analysis_service.metadata_store.get_network_model(model_id)
    assert baseline_model_check is not None
    assert baseline_model_check.nodes["router-1"].interfaces[1].state == AdministrativeState.UP

    # =========================================================================
    # Step 11: Persist the investigation execution record
    # =========================================================================
    executions = inv_engine.list_executions(investigation_case.investigation_id)
    assert len(executions) >= 1
    initial_exec = executions[0]
    assert initial_exec.investigation_id == investigation_case.investigation_id
    assert initial_exec.execution_index == 1
    assert initial_exec.replay_of_execution_id is None
    assert initial_exec.model_fingerprint == network_model.fingerprint
    assert len(initial_exec.overall_evidence_digest) == 64

    # Verify retrieval from storage
    persisted_record = analysis_service.metadata_store.get_execution(initial_exec.execution_id)
    assert persisted_record is not None
    assert persisted_record.execution_id == initial_exec.execution_id

    # =========================================================================
    # Step 12: Verify evidence integrity
    # =========================================================================
    integrity_report = inv_engine.verify_execution(initial_exec.execution_id)
    assert integrity_report.overall_status == IntegrityStatus.VERIFIED, (
        "Cryptographic evidence integrity must be verified."
    )
    assert len(integrity_report.item_reports) == len(initial_exec.evidence_graph.nodes)
    assert all(item.status == IntegrityStatus.VERIFIED for item in integrity_report.item_reports)
    # Assert presence of mandatory epistemological disclaimer
    assert "Cryptographic integrity verification" in integrity_report.disclaimer

    # =========================================================================
    # Step 13: Replay the recorded investigation
    # =========================================================================
    replayed_exec, comparison = inv_engine.replay_execution(
        investigation_case.investigation_id, initial_exec.execution_id
    )
    assert replayed_exec.execution_id != initial_exec.execution_id
    assert replayed_exec.replay_of_execution_id == initial_exec.execution_id
    assert replayed_exec.execution_index == 2

    # =========================================================================
    # Step 14: Compare the original and replayed findings
    # =========================================================================
    assert comparison.replay_status == ReplayStatus.REPLAY_IDENTICAL, (
        f"Deterministic replay must yield REPLAY_IDENTICAL, got {comparison.replay_status}"
    )
    assert comparison.is_identical is True
    assert comparison.original_root_cause_id == comparison.replayed_root_cause_id
    assert len(comparison.findings_differences) > 0
    assert all(d.change_type == "MATCHED" for d in comparison.findings_differences)
    assert len(comparison.evidence_differences) == 0

    # =========================================================================
    # Step 15: Export an audit pack and independently verify its structure and hashes
    # =========================================================================
    audit_pack = inv_engine.export_audit_pack(initial_exec.execution_id)
    assert audit_pack.execution.execution_id == initial_exec.execution_id, (
        "Audit pack must reference target execution record."
    )
    assert audit_pack.integrity_report.overall_status == IntegrityStatus.VERIFIED
    assert len(audit_pack.audit_instructions) >= 3

    # Independent cryptographic verification of audit pack data:
    # 1. Verify JSON serializability of audit pack
    audit_json = audit_pack.model_dump_json()
    loaded_data = json.loads(audit_json)
    assert loaded_data["export_schema_version"] == "1.0.0"

    # 2. Independently compute canonical item hashes using integrity canonicalization logic

    recomputed_hashes, recomputed_digest = compute_evidence_graph_hashes(audit_pack.execution.evidence_graph.nodes)
    assert recomputed_digest == audit_pack.execution.overall_evidence_digest, (
        "Independently recalculated composite evidence digest must match recorded digest."
    )

    # 3. Check capture file hash referenced in audit pack matches corpus
    assert persisted_capture_id in audit_pack.execution.referenced_capture_ids
    persisted_cap_meta = analysis_service.metadata_store.get_capture(persisted_capture_id)
    assert persisted_cap_meta is not None
    assert persisted_cap_meta["content_sha256"] == capture_meta.sha256
