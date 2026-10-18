"""
Integration tests for Sequence REST API routes (/api/v1/sequences).
"""

import pytest
from fastapi.testclient import TestClient

from network_twin.main import app
from network_twin.storage.metadata_store import metadata_store
from network_twin.testing.sequence_models import (
    SequenceFailureCategory,
    SequenceFinding,
    SequenceSeverity,
)


@pytest.fixture
def client():
    return TestClient(app)


def test_coverage_gaps_endpoint(client):
    res = client.get("/api/v1/sequences/coverage-gaps")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "documented"
    assert len(data["supported_stateful_semantics"]) >= 5
    assert len(data["coverage_gaps_and_limitations"]) >= 3

    # Confirm explicit mention of IP fragmentation reassembly limitation
    frag_gap = next(
        (g for g in data["coverage_gaps_and_limitations"] if "fragmentation" in g["subsystem"].lower()), None
    )
    assert frag_gap is not None
    assert "DECODE_ONLY" in frag_gap["status"]


def test_generate_and_list_sequences_api(client):
    # 1. Generate canonical sequences
    gen_res = client.post(
        "/api/v1/sequences/generate",
        json={"sequence_type": "TCP_HANDSHAKE_TEARDOWN", "seed": 42, "execute_immediately": True},
    )
    assert gen_res.status_code == 200
    seqs = gen_res.json()
    assert len(seqs) == 1
    seq_id = seqs[0]["sequence_id"]

    # 2. List sequences
    list_res = client.get("/api/v1/sequences")
    assert list_res.status_code == 200
    all_seqs = list_res.json()
    assert any(s["sequence_id"] == seq_id for s in all_seqs)

    # 3. Get sequence details
    detail_res = client.get(f"/api/v1/sequences/{seq_id}")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert len(detail["steps"]) == 9
    assert detail["sequence_type"] == "TCP_HANDSHAKE_TEARDOWN"


def test_run_sequence_endpoint(client):
    # Generate sequence first
    gen_res = client.post(
        "/api/v1/sequences/generate",
        json={"sequence_type": "TCP_RST_AND_ABORT", "seed": 77, "execute_immediately": False},
    )
    assert gen_res.status_code == 200
    seq_id = gen_res.json()[0]["sequence_id"]

    # Run sequence
    run_res = client.post(f"/api/v1/sequences/{seq_id}/run", json={})
    assert run_res.status_code == 200
    exec_data = run_res.json()
    assert exec_data["exit_code"] == 0
    assert exec_data["total_events_emitted"] == 4


def test_sequence_differential_endpoint(client):
    gen_res = client.post(
        "/api/v1/sequences/generate",
        json={"sequence_type": "TCP_SIMULTANEOUS_FLOWS", "seed": 88, "execute_immediately": False},
    )
    seq_id = gen_res.json()[0]["sequence_id"]

    diff_res = client.post(
        "/api/v1/sequences/differential",
        json={"sequence_id": seq_id, "mode": "pcap_vs_pcapng"},
    )
    assert diff_res.status_code == 200
    diff_data = diff_res.json()
    assert diff_data["equivalent"] is True
    assert diff_data["baseline_events_count"] == 7


def test_sequence_finding_promotion_and_regressions_api(client):
    # Setup test sequence and finding
    gen_res = client.post(
        "/api/v1/sequences/generate",
        json={"sequence_type": "TCP_HANDSHAKE_TEARDOWN", "seed": 99, "execute_immediately": False},
    )
    seq = gen_res.json()[0]
    seq_id = seq["sequence_id"]

    finding = SequenceFinding(
        finding_id=f"find-test-{seq_id}",
        sequence_id=seq_id,
        severity=SequenceSeverity.HIGH,
        category=SequenceFailureCategory.STATE_TRANSITION_MISMATCH,
        title="Test Handshake Finding",
        description="Simulated transition failure",
        root_cause_summary="Simulated root cause",
        reproduction_command="protocol_engine.exe test",
        fixture_path="test.pcap",
        fixture_hash="hash123",
        created_at_iso="2026-10-17T12:00:00Z",
    )
    metadata_store.save_sequence_finding(finding)

    # List findings
    find_res = client.get(f"/api/v1/sequences/findings?sequence_id={seq_id}")
    assert find_res.status_code == 200
    findings = find_res.json()
    assert len(findings) >= 1

    # Promote to regression
    prom_res = client.post(
        f"/api/v1/sequences/findings/{finding.finding_id}/promote",
        json={"name": "TCP Handshake Transition Regression"},
    )
    assert prom_res.status_code == 200
    regr = prom_res.json()
    assert regr["name"] == "TCP Handshake Transition Regression"
    assert regr["expected_to_pass"] is True

    # List regressions
    list_regr = client.get("/api/v1/sequences/regressions")
    assert list_regr.status_code == 200
    all_regrs = list_regr.json()
    assert any(r["regression_id"] == regr["regression_id"] for r in all_regrs)


def test_generate_suite_and_run_without_body(client):
    # 1. Generate suite via /generate-suite with empty body
    gen_res = client.post("/api/v1/sequences/generate-suite", json={})
    assert gen_res.status_code == 200
    seqs = gen_res.json()
    assert len(seqs) >= 1
    seq_id = seqs[0]["sequence_id"]

    # 2. Run sequence without body (reproduces UI call)
    run_res = client.post(f"/api/v1/sequences/{seq_id}/run")
    assert run_res.status_code == 200
    data = run_res.json()
    # Satisfies both SequenceExecutionResult and { execution, findings }
    assert "execution" in data
    assert "findings" in data
    assert data["exit_code"] == 0


def test_finding_minimization_bundle_and_promote_aliases(client):
    # Generate canonical sequence
    gen_res = client.post("/api/v1/sequences/generate", json={"seed": 42})
    assert gen_res.status_code == 200
    seq = gen_res.json()[0]
    seq_id = seq["sequence_id"]

    # Save a finding for this sequence
    finding = SequenceFinding(
        finding_id=f"find-workflow-{seq_id}",
        sequence_id=seq_id,
        severity=SequenceSeverity.MEDIUM,
        category=SequenceFailureCategory.STATE_TRANSITION_MISMATCH,
        title="Workflow Finding",
        description="Finding for minimization and bundle test",
        root_cause_summary="Simulated cause",
        reproduction_command=f"protocol_engine.exe test --seq {seq_id}",
        fixture_path="test.pcap",
        fixture_hash="hash456",
        created_at_iso="2026-10-18T12:00:00Z",
    )
    metadata_store.save_sequence_finding(finding)

    # 1. Minimize finding via POST /findings/{finding_id}/minimize
    min_res = client.post(f"/api/v1/sequences/findings/{finding.finding_id}/minimize")
    assert min_res.status_code == 200
    min_data = min_res.json()
    assert "reduction_ratio" in min_data
    assert min_data["finding_id"] == finding.finding_id

    # 2. Export reproduction ZIP bundle via GET /findings/{finding_id}/bundle
    bundle_res = client.get(f"/api/v1/sequences/findings/{finding.finding_id}/bundle")
    assert bundle_res.status_code == 200
    assert bundle_res.headers["content-type"] == "application/zip"
    assert len(bundle_res.content) > 0

    # 3. Promote via POST /findings/{finding_id}/promote-regression
    prom_res = client.post(
        f"/api/v1/sequences/findings/{finding.finding_id}/promote-regression",
        json={"name": "Promoted Regression Fixture"},
    )
    assert prom_res.status_code == 200
    fixture = prom_res.json()
    assert fixture["name"] == "Promoted Regression Fixture"
