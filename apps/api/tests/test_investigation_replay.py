"""
Phase 11: Comprehensive Test Suite for Reproducible Investigation Replay & Evidence Integrity.
Validates immutable execution ledger, cryptographic verification, deterministic replay,
handling of missing/altered models and captures, and REST API contracts.
"""

import copy
import hashlib
from datetime import UTC, datetime

from fastapi.testclient import TestClient
from test_investigations import build_test_network_model

from network_twin.investigations.engine import InvestigationEngine
from network_twin.investigations.integrity import (
    canonicalize_evidence_item,
    compute_evidence_graph_hashes,
    compute_evidence_item_hash,
)
from network_twin.investigations.models import (
    CreateInvestigationRequest,
    EvidenceClass,
    EvidenceGraph,
    EvidenceItem,
    EvidenceNodeType,
    EvidenceSufficiency,
    IntegrityStatus,
    InvestigationExecutionRecord,
    InvestigationScope,
    InvestigationType,
    ReplayStatus,
)
from network_twin.main import app
from network_twin.simulation.models import AdministrativeState
from network_twin.storage.metadata_store import MetadataStore


def _setup_test_model(store: MetadataStore, model_id: str = "model-replay-01") -> str:
    """Saves a deterministic 2-node router model with eth1 DOWN."""
    model = build_test_network_model(model_id=model_id, if_state=AdministrativeState.DOWN)
    store.save_network_model(model)
    return model_id


def test_canonical_evidence_serialization_and_hashing():
    """Verifies deterministic canonical JSON serialization and SHA-256 sensitivity to property changes."""
    item1 = EvidenceItem(
        evidence_id="ev-endpoint-192.168.10.50",
        evidence_class=EvidenceClass.OBSERVED,
        node_type=EvidenceNodeType.ENDPOINT,
        source_id="asset-192.168.10.50",
        label="Observed Host 192.168.10.50",
        description="Observed active host communicating via TCP",
        raw_properties={"primary_ip": "192.168.10.50", "ttl": 64},
    )

    # Identical properties, created independently with different dict key insertion order
    item2 = EvidenceItem(
        evidence_id="ev-endpoint-192.168.10.50",
        evidence_class=EvidenceClass.OBSERVED,
        node_type=EvidenceNodeType.ENDPOINT,
        source_id="asset-192.168.10.50",
        label="Observed Host 192.168.10.50",
        description="Observed active host communicating via TCP",
        raw_properties={"ttl": 64, "primary_ip": "192.168.10.50"},
    )

    # Serializations and hashes must be bit-exact identical
    bytes1 = canonicalize_evidence_item(item1)
    bytes2 = canonicalize_evidence_item(item2)
    assert bytes1 == bytes2

    h1 = compute_evidence_item_hash(item1)
    h2 = compute_evidence_item_hash(item2)
    assert h1 == h2

    # Modifying a property changes the digest
    item3 = item1.model_copy(update={"description": "Tampered description"})
    h3 = compute_evidence_item_hash(item3)
    assert h1 != h3


def test_investigation_execution_record_creation_and_persistence():
    """Verifies that executing an investigation generates and persists an immutable InvestigationExecutionRecord."""
    store = MetadataStore()
    model_id = _setup_test_model(store, "model-persist-test-1")
    engine = InvestigationEngine(metadata_store=store)

    req = CreateInvestigationRequest(
        title="Connectivity Outage to Branch Office",
        investigation_type=InvestigationType.CONNECTIVITY_FAILURE,
        scope=InvestigationScope(
            source_ip="192.168.10.50",
            destination_ip="10.200.0.99",
            transport_protocol="TCP",
            destination_port=80,
            model_id=model_id,
        ),
    )
    case = engine.create_investigation(req)
    executed_case = engine.execute_investigation(case.investigation_id)
    assert executed_case.status == "ANALYZED"

    # Verify execution record persistence
    executions = store.list_executions(case.investigation_id)
    assert len(executions) >= 1
    exec_record = executions[0]

    assert exec_record.investigation_id == case.investigation_id
    assert exec_record.execution_index == 1
    assert exec_record.status == "SUCCESS"
    assert exec_record.model_id == model_id
    assert exec_record.execution_duration_ms >= 0.0
    assert len(exec_record.overall_evidence_digest) == 64
    assert len(exec_record.evidence_integrity_hashes) == len(exec_record.evidence_graph.nodes)

    # Verify retrieval by execution_id
    retrieved = store.get_execution(exec_record.execution_id)
    assert retrieved is not None
    assert retrieved.execution_id == exec_record.execution_id
    assert retrieved.overall_evidence_digest == exec_record.overall_evidence_digest


def test_verify_execution_integrity_success():
    """Verifies that untampered execution records pass cryptographic verification."""
    store = MetadataStore()
    model_id = _setup_test_model(store, "model-verify-test-1")
    engine = InvestigationEngine(metadata_store=store)

    req = CreateInvestigationRequest(
        title="Integrity Verification Test Case",
        investigation_type=InvestigationType.CONNECTIVITY_FAILURE,
        scope=InvestigationScope(
            source_ip="192.168.10.50",
            destination_ip="10.200.0.99",
            transport_protocol="TCP",
            destination_port=80,
            model_id=model_id,
        ),
    )
    case = engine.create_investigation(req)
    engine.execute_investigation(case.investigation_id)

    exec_record = store.get_latest_execution(case.investigation_id)
    assert exec_record is not None

    report = engine.verify_execution(exec_record.execution_id)
    assert report.overall_status == IntegrityStatus.VERIFIED
    assert report.total_evidence_items > 0
    assert report.verified_count == report.total_evidence_items
    assert report.modified_count == 0
    assert report.missing_count == 0
    assert "Cryptographic integrity verification proves" in report.disclaimer


def test_verify_execution_integrity_detects_tampering():
    """Verifies that cryptographic verification flags any modified evidence payload."""
    store = MetadataStore()
    model_id = _setup_test_model(store, "model-tamper-test-1")
    engine = InvestigationEngine(metadata_store=store)

    req = CreateInvestigationRequest(
        title="Tamper Detection Test Case",
        investigation_type=InvestigationType.CONNECTIVITY_FAILURE,
        scope=InvestigationScope(
            source_ip="192.168.10.50",
            destination_ip="10.200.0.99",
            transport_protocol="TCP",
            destination_port=80,
            model_id=model_id,
        ),
    )
    case = engine.create_investigation(req)
    engine.execute_investigation(case.investigation_id)

    orig_record = store.get_latest_execution(case.investigation_id)
    assert orig_record is not None

    # Simulate unauthorized modification of evidence in storage
    tampered_nodes = copy.deepcopy(orig_record.evidence_graph.nodes)
    assert len(tampered_nodes) > 0
    tampered_nodes[0].description = "TAMPERED: Unauthorized mutation of evidence text"

    tampered_graph = orig_record.evidence_graph.model_copy(update={"nodes": tampered_nodes})
    tampered_record = orig_record.model_copy(update={"evidence_graph": tampered_graph})

    # Save tampered record
    store.save_execution(tampered_record)

    # Verification must catch the discrepancy
    report = engine.verify_execution(orig_record.execution_id)
    assert report.overall_status == IntegrityStatus.MODIFIED
    assert report.modified_count >= 1
    flagged = [item for item in report.item_reports if item.status == IntegrityStatus.MODIFIED]
    assert len(flagged) >= 1
    assert "does not match recorded digest" in flagged[0].discrepancy_details


def test_verify_execution_integrity_missing_source():
    """Verifies that verification flags missing backing capture fixtures."""
    store = MetadataStore()
    engine = InvestigationEngine(metadata_store=store)

    node = EvidenceItem(
        evidence_id="ev-cap-missing",
        evidence_class=EvidenceClass.OBSERVED,
        node_type=EvidenceNodeType.CAPTURE,
        source_id="cap-phantom-9999",
        label="Missing Capture Fixture",
        description="Phantom capture",
    )
    hashes, digest = compute_evidence_graph_hashes([node])
    now_iso = datetime.now(UTC).isoformat()

    dummy_exec = InvestigationExecutionRecord(
        execution_id="exec-missing-src-test",
        investigation_id="inv-missing-src-test",
        execution_index=1,
        investigation_type=InvestigationType.CONNECTIVITY_FAILURE,
        engine_version="11.0.0",
        rule_version="2026.10",
        started_at_iso=now_iso,
        completed_at_iso=now_iso,
        execution_duration_ms=10.0,
        status="SUCCESS",
        normalized_scope=InvestigationScope(),
        referenced_capture_ids=["cap-phantom-9999"],
        evidence_graph=EvidenceGraph(nodes=[node]),
        evidence_integrity_hashes=hashes,
        overall_evidence_digest=digest,
        sufficiency=EvidenceSufficiency.INSUFFICIENT,
    )
    store.save_execution(dummy_exec)

    report = engine.verify_execution("exec-missing-src-test")
    assert report.overall_status == IntegrityStatus.MISSING_SOURCE
    assert report.missing_count >= 1


def test_deterministic_replay_produces_identical_outcome():
    """Verifies that replaying an investigation deterministically yields REPLAY_IDENTICAL."""
    store = MetadataStore()
    model_id = _setup_test_model(store, "model-replay-identical-1")
    engine = InvestigationEngine(metadata_store=store)

    req = CreateInvestigationRequest(
        title="Deterministic Replay Test Case",
        investigation_type=InvestigationType.CONNECTIVITY_FAILURE,
        scope=InvestigationScope(
            source_ip="192.168.10.50",
            destination_ip="10.200.0.99",
            transport_protocol="TCP",
            destination_port=80,
            model_id=model_id,
        ),
    )
    case = engine.create_investigation(req)
    engine.execute_investigation(case.investigation_id)

    orig_exec = store.get_latest_execution(case.investigation_id)
    assert orig_exec is not None

    # Replay execution
    replay_exec, comparison = engine.replay_execution(case.investigation_id, orig_exec.execution_id)

    # Outcome must be strictly REPLAY_IDENTICAL
    assert comparison.replay_status == ReplayStatus.REPLAY_IDENTICAL
    assert comparison.is_identical is True
    assert comparison.original_root_cause_id == orig_exec.primary_root_cause_id
    assert comparison.replayed_root_cause_id == orig_exec.primary_root_cause_id
    assert len(comparison.evidence_differences) == 0

    for diff in comparison.findings_differences:
        assert diff.change_type == "MATCHED"

    # Replay execution lineage
    assert replay_exec.replay_of_execution_id == orig_exec.execution_id
    assert replay_exec.execution_id != orig_exec.execution_id

    # Original execution remains completely immutable
    reloaded_orig = store.get_execution(orig_exec.execution_id)
    assert reloaded_orig.model_dump_json() == orig_exec.model_dump_json()


def test_replay_with_altered_model_produces_replay_different():
    """Verifies that modifying the underlying model leads to REPLAY_DIFFERENT with explicit difference items."""
    store = MetadataStore()
    model_id = _setup_test_model(store, "model-drift-test-1")
    engine = InvestigationEngine(metadata_store=store)

    req = CreateInvestigationRequest(
        title="Model Drift Replay Test",
        investigation_type=InvestigationType.CONNECTIVITY_FAILURE,
        scope=InvestigationScope(
            source_ip="192.168.10.50",
            destination_ip="10.200.0.99",
            transport_protocol="TCP",
            destination_port=80,
            model_id=model_id,
        ),
    )
    case = engine.create_investigation(req)
    engine.execute_investigation(case.investigation_id)

    orig_exec = store.get_latest_execution(case.investigation_id)
    assert orig_exec is not None
    assert orig_exec.primary_root_cause_id == "cand-interface-down"

    # Now modify model in store: Bring eth1 UP (resolving blockage)
    model = store.get_network_model(model_id)
    assert model is not None
    r1 = model.nodes["router-1"]
    for iface in r1.interfaces:
        if iface.interface_id == "eth1":
            iface.state = AdministrativeState.UP

    model.fingerprint = hashlib.sha256(b"fingerprint-modified-eth1-up").hexdigest()
    store.save_network_model(model)

    # Replay execution against updated model
    replay_exec, comparison = engine.replay_execution(case.investigation_id, orig_exec.execution_id)

    # Must produce REPLAY_DIFFERENT because blockage reason no longer holds
    assert comparison.replay_status == ReplayStatus.REPLAY_DIFFERENT
    assert comparison.is_identical is False
    assert len(comparison.findings_differences) > 0


def test_replay_refused_when_historical_model_missing():
    """Verifies that replay refuses to guess when a required network model is absent."""
    store = MetadataStore()
    engine = InvestigationEngine(metadata_store=store)

    now_iso = datetime.now(UTC).isoformat()
    dummy_exec = InvestigationExecutionRecord(
        execution_id="exec-missing-model-test",
        investigation_id="inv-missing-model-test",
        execution_index=1,
        investigation_type=InvestigationType.CONNECTIVITY_FAILURE,
        engine_version="11.0.0",
        rule_version="2026.10",
        started_at_iso=now_iso,
        completed_at_iso=now_iso,
        execution_duration_ms=10.0,
        status="SUCCESS",
        normalized_scope=InvestigationScope(model_id="model-ghost-9999"),
        model_id="model-ghost-9999",
        model_fingerprint="fp-ghost",
        evidence_graph=EvidenceGraph(),
        overall_evidence_digest=hashlib.sha256(b"DUMMY").hexdigest(),
        sufficiency=EvidenceSufficiency.INSUFFICIENT,
    )
    store.save_execution(dummy_exec)

    replay_exec, comparison = engine.replay_execution("inv-missing-model-test", "exec-missing-model-test")
    assert comparison.replay_status == ReplayStatus.REPLAY_NOT_POSSIBLE
    assert comparison.is_identical is False
    assert "model-ghost-9999" in comparison.summary
    assert replay_exec.status == "NOT_POSSIBLE"


def test_export_audit_pack():
    """Verifies export of self-contained audit package with offline reproduction instructions."""
    store = MetadataStore()
    model_id = _setup_test_model(store, "model-audit-test-1")
    engine = InvestigationEngine(metadata_store=store)

    req = CreateInvestigationRequest(
        title="Audit Pack Test",
        investigation_type=InvestigationType.CONNECTIVITY_FAILURE,
        scope=InvestigationScope(
            source_ip="192.168.10.50",
            destination_ip="10.200.0.99",
            transport_protocol="TCP",
            destination_port=80,
            model_id=model_id,
        ),
    )
    case = engine.create_investigation(req)
    engine.execute_investigation(case.investigation_id)

    exec_record = store.get_latest_execution(case.investigation_id)
    assert exec_record is not None

    audit_pack = engine.export_audit_pack(exec_record.execution_id)
    assert audit_pack.audit_pack_id == f"audit-{exec_record.execution_id}"
    assert audit_pack.execution.execution_id == exec_record.execution_id
    assert audit_pack.integrity_report.overall_status == IntegrityStatus.VERIFIED
    assert len(audit_pack.audit_instructions) >= 4
    assert any("Canonicalize each evidence item" in inst for inst in audit_pack.audit_instructions)


def test_investigation_replay_rest_api_endpoints():
    """Verifies all Phase 11 REST API endpoints via FastAPI TestClient."""
    client = TestClient(app)

    # 1. Create and execute investigation
    create_payload = {
        "title": "API Replay & Integrity Test Case",
        "investigation_type": "CONNECTIVITY_FAILURE",
        "scope": {
            "source_ip": "192.168.10.50",
            "destination_ip": "10.200.0.99",
            "transport_protocol": "TCP",
            "destination_port": 80,
            "capture_ids": [],
            "snapshot_ids": [],
        },
    }
    res = client.post("/api/v1/twin/investigations", json=create_payload)
    assert res.status_code == 200
    inv_id = res.json()["investigation_id"]

    res_exec = client.post(f"/api/v1/twin/investigations/{inv_id}/execute")
    assert res_exec.status_code == 200

    # 2. List executions
    res_list = client.get(f"/api/v1/twin/investigations/{inv_id}/executions")
    assert res_list.status_code == 200
    execs = res_list.json()
    assert len(execs) >= 1
    exec_id = execs[0]["execution_id"]

    # 3. Get single execution
    res_get = client.get(f"/api/v1/twin/investigations/{inv_id}/executions/{exec_id}")
    assert res_get.status_code == 200
    assert res_get.json()["execution_id"] == exec_id

    # 4. Verify integrity
    res_verify = client.post(f"/api/v1/twin/investigations/{inv_id}/executions/{exec_id}/verify-integrity")
    assert res_verify.status_code == 200
    verify_data = res_verify.json()
    assert verify_data["overall_status"] in ["VERIFIED", "MISSING_SOURCE"]
    assert "disclaimer" in verify_data

    # 5. Replay execution
    res_replay = client.post(f"/api/v1/twin/investigations/{inv_id}/executions/{exec_id}/replay")
    assert res_replay.status_code == 200
    replay_data = res_replay.json()
    assert "replayed_execution" in replay_data
    assert "comparison" in replay_data
    replayed_id = replay_data["replayed_execution"]["execution_id"]
    assert replay_data["comparison"]["replay_status"] in ["REPLAY_IDENTICAL", "REPLAY_DIFFERENT", "REPLAY_NOT_POSSIBLE"]

    # 6. Compare two executions
    res_cmp = client.get(f"/api/v1/twin/investigations/{inv_id}/executions/{exec_id}/compare/{replayed_id}")
    assert res_cmp.status_code == 200
    cmp_data = res_cmp.json()
    assert cmp_data["original_execution_id"] == exec_id
    assert cmp_data["replayed_execution_id"] == replayed_id

    # 7. Export audit pack
    res_audit = client.get(f"/api/v1/twin/investigations/{inv_id}/executions/{exec_id}/audit-pack")
    assert res_audit.status_code == 200
    pack_data = res_audit.json()
    assert pack_data["audit_pack_id"] == f"audit-{exec_id}"
    assert "audit_instructions" in pack_data
