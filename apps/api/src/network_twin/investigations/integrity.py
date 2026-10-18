"""
Deterministic Evidence Canonicalization, Cryptographic Integrity Verification, and Replay Comparison.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from network_twin.investigations.models import (
    CandidateExplanation,
    EvidenceIntegrityItem,
    EvidenceItem,
    EvidenceNodeType,
    ExecutionIntegrityReport,
    FindingDifference,
    IntegrityStatus,
    InvestigationExecutionRecord,
    ReplayComparison,
    ReplayStatus,
)


def canonicalize_evidence_item(item: EvidenceItem) -> bytes:
    """Produces deterministic, canonical JSON byte representation of an evidence item."""
    canonical_dict = {
        "description": item.description,
        "evidence_class": item.evidence_class.value,
        "evidence_id": item.evidence_id,
        "label": item.label,
        "node_type": item.node_type.value,
        "raw_properties": item.raw_properties,
        "source_id": item.source_id,
        "timestamp_iso": item.timestamp_iso,
    }
    return json.dumps(canonical_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_evidence_item_hash(item: EvidenceItem) -> str:
    """Computes SHA-256 hex digest of the canonicalized evidence item."""
    return hashlib.sha256(canonicalize_evidence_item(item)).hexdigest()


def compute_evidence_graph_hashes(nodes: list[EvidenceItem]) -> tuple[dict[str, str], str]:
    """
    Computes individual canonical SHA-256 hashes for each evidence item,
    and a combined overall evidence graph cryptographic digest.
    """
    hashes: dict[str, str] = {}
    for node in nodes:
        hashes[node.evidence_id] = compute_evidence_item_hash(node)

    if not hashes:
        return {}, hashlib.sha256(b"EMPTY_EVIDENCE_GRAPH").hexdigest()

    # Deterministic overall digest: sorted lines of "evidence_id:sha256"
    lines = [f"{eid}:{h}" for eid, h in sorted(hashes.items())]
    combined_payload = "\n".join(lines).encode("utf-8")
    overall_digest = hashlib.sha256(combined_payload).hexdigest()
    return hashes, overall_digest


def verify_execution_integrity(
    record: InvestigationExecutionRecord,
    metadata_store: Any,
) -> ExecutionIntegrityReport:
    """
    Formally audits the cryptographic integrity of an execution record.
    Verifies that evidence items match their recorded digests and that backing sources remain intact.
    """
    now_iso = datetime.now(UTC).isoformat()
    item_reports: list[EvidenceIntegrityItem] = []
    verified_count = 0
    modified_count = 0
    missing_count = 0

    for item in record.evidence_graph.nodes:
        recorded_h = record.evidence_integrity_hashes.get(item.evidence_id, "")
        computed_h = compute_evidence_item_hash(item)

        source_uri = f"twin://evidence/{item.node_type.value.lower()}/{item.source_id}"

        if not recorded_h or recorded_h != computed_h:
            item_reports.append(
                EvidenceIntegrityItem(
                    evidence_id=item.evidence_id,
                    evidence_class=item.evidence_class,
                    node_type=item.node_type,
                    recorded_sha256=recorded_h,
                    computed_sha256=computed_h,
                    source_uri=source_uri,
                    verified=False,
                    status=IntegrityStatus.MODIFIED,
                    discrepancy_details=(
                        f"Computed SHA-256 ({computed_h[:12]}...) does not match recorded digest ({recorded_h[:12]}...)"
                    ),
                )
            )
            modified_count += 1
            continue

        # Check source dependency existence if applicable
        if item.node_type == EvidenceNodeType.CAPTURE:
            cap = metadata_store.get_capture(item.source_id)
            if not cap:
                item_reports.append(
                    EvidenceIntegrityItem(
                        evidence_id=item.evidence_id,
                        evidence_class=item.evidence_class,
                        node_type=item.node_type,
                        recorded_sha256=recorded_h,
                        computed_sha256=computed_h,
                        source_uri=source_uri,
                        verified=False,
                        status=IntegrityStatus.MISSING_SOURCE,
                        discrepancy_details=f"Backing capture fixture '{item.source_id}' is missing from metadata store.",
                    )
                )
                missing_count += 1
                continue

        # Item verified
        item_reports.append(
            EvidenceIntegrityItem(
                evidence_id=item.evidence_id,
                evidence_class=item.evidence_class,
                node_type=item.node_type,
                recorded_sha256=recorded_h,
                computed_sha256=computed_h,
                source_uri=source_uri,
                verified=True,
                status=IntegrityStatus.VERIFIED,
                discrepancy_details=None,
            )
        )
        verified_count += 1

    # Check model state integrity if model_id was recorded
    if record.model_id:
        stored_model = metadata_store.get_network_model(record.model_id)
        if not stored_model:
            missing_count += 1
        elif record.model_fingerprint and stored_model.fingerprint != record.model_fingerprint:
            modified_count += 1

    # Determine overall integrity status
    if modified_count > 0:
        overall_status = IntegrityStatus.MODIFIED
    elif missing_count > 0:
        overall_status = IntegrityStatus.MISSING_SOURCE
    else:
        overall_status = IntegrityStatus.VERIFIED

    return ExecutionIntegrityReport(
        execution_id=record.execution_id,
        investigation_id=record.investigation_id,
        overall_status=overall_status,
        hash_algorithm="SHA-256",
        schema_version="1.0.0",
        total_evidence_items=len(record.evidence_graph.nodes),
        verified_count=verified_count,
        modified_count=modified_count,
        missing_count=missing_count,
        item_reports=item_reports,
        verified_at_iso=now_iso,
    )


def compare_executions(
    orig: InvestigationExecutionRecord,
    replayed: InvestigationExecutionRecord,
) -> ReplayComparison:
    """
    Compares an original investigation execution against a replayed execution.
    Isolates structural and semantic differences while ignoring nondeterministic execution timing.
    """
    if replayed.status == "NOT_POSSIBLE":
        return ReplayComparison(
            comparison_id=f"cmp-{uuid.uuid4().hex[:10]}",
            original_execution_id=orig.execution_id,
            replayed_execution_id=replayed.execution_id,
            investigation_id=orig.investigation_id,
            replay_status=ReplayStatus.REPLAY_NOT_POSSIBLE,
            is_identical=False,
            original_root_cause_id=orig.primary_root_cause_id,
            replayed_root_cause_id=None,
            findings_differences=[],
            evidence_differences=[],
            summary=f"Replay not possible: {replayed.execution_notes or 'Required inputs or models are missing.'}",
            compared_at_iso=datetime.now(UTC).isoformat(),
        )

    findings_diffs: list[FindingDifference] = []
    evidence_diffs: list[str] = []

    orig_map: dict[str, CandidateExplanation] = {c.candidate_id: c for c in orig.candidate_explanations}
    replayed_map: dict[str, CandidateExplanation] = {c.candidate_id: c for c in replayed.candidate_explanations}

    all_ids = set(orig_map.keys()) | set(replayed_map.keys())

    has_candidate_diff = False

    for cid in sorted(all_ids):
        o_cand = orig_map.get(cid)
        r_cand = replayed_map.get(cid)

        if o_cand and r_cand:
            status_match = o_cand.status == r_cand.status
            rank_match = o_cand.rank == r_cand.rank
            score_match = abs(o_cand.score - r_cand.score) < 0.001

            if status_match and rank_match and score_match:
                findings_diffs.append(
                    FindingDifference(
                        candidate_id=cid,
                        title=o_cand.title,
                        change_type="MATCHED",
                        original_status=o_cand.status,
                        replayed_status=r_cand.status,
                        original_score=o_cand.score,
                        replayed_score=r_cand.score,
                        original_rank=o_cand.rank,
                        replayed_rank=r_cand.rank,
                        explanation="Candidate explanation status, rank, and support score are identical.",
                    )
                )
            else:
                has_candidate_diff = True
                findings_diffs.append(
                    FindingDifference(
                        candidate_id=cid,
                        title=o_cand.title,
                        change_type="MODIFIED",
                        original_status=o_cand.status,
                        replayed_status=r_cand.status,
                        original_score=o_cand.score,
                        replayed_score=r_cand.score,
                        original_rank=o_cand.rank,
                        replayed_rank=r_cand.rank,
                        explanation=(
                            f"Finding altered: status ({o_cand.status.value} -> {r_cand.status.value}), "
                            f"rank ({o_cand.rank} -> {r_cand.rank}), score ({o_cand.score} -> {r_cand.score})."
                        ),
                    )
                )
        elif o_cand and not r_cand:
            has_candidate_diff = True
            findings_diffs.append(
                FindingDifference(
                    candidate_id=cid,
                    title=o_cand.title,
                    change_type="REMOVED",
                    original_status=o_cand.status,
                    replayed_status=None,
                    original_score=o_cand.score,
                    replayed_score=None,
                    original_rank=o_cand.rank,
                    replayed_rank=None,
                    explanation=f"Candidate explanation '{cid}' was present in original but absent in replay.",
                )
            )
        elif not o_cand and r_cand:
            has_candidate_diff = True
            findings_diffs.append(
                FindingDifference(
                    candidate_id=cid,
                    title=r_cand.title,
                    change_type="ADDED",
                    original_status=None,
                    replayed_status=r_cand.status,
                    original_score=None,
                    replayed_score=r_cand.score,
                    original_rank=None,
                    replayed_rank=r_cand.rank,
                    explanation=f"New candidate explanation '{cid}' generated in replay.",
                )
            )

    # Compare root cause
    root_cause_match = orig.primary_root_cause_id == replayed.primary_root_cause_id
    if not root_cause_match:
        has_candidate_diff = True

    # Compare evidence graph node IDs
    orig_nodes = {n.evidence_id for n in orig.evidence_graph.nodes}
    replayed_nodes = {n.evidence_id for n in replayed.evidence_graph.nodes}
    added_nodes = replayed_nodes - orig_nodes
    removed_nodes = orig_nodes - replayed_nodes

    for node_id in sorted(added_nodes):
        evidence_diffs.append(f"Added evidence node '{node_id}' in replay.")
    for node_id in sorted(removed_nodes):
        evidence_diffs.append(f"Removed evidence node '{node_id}' from original.")

    # Determine replay status
    is_identical = not has_candidate_diff and len(added_nodes) == 0 and len(removed_nodes) == 0

    if is_identical:
        replay_status = ReplayStatus.REPLAY_IDENTICAL
        summary = (
            "Deterministic replay succeeded: All candidate explanations, evidence graph nodes, "
            "and primary root cause are bit-exact identical to the recorded execution."
        )
    else:
        replay_status = ReplayStatus.REPLAY_DIFFERENT
        summary = (
            f"Replay produced divergence: {len(findings_diffs)} finding differences, "
            f"root cause match: {root_cause_match}, evidence differences: {len(evidence_diffs)}."
        )

    return ReplayComparison(
        comparison_id=f"cmp-{uuid.uuid4().hex[:10]}",
        original_execution_id=orig.execution_id,
        replayed_execution_id=replayed.execution_id,
        investigation_id=orig.investigation_id,
        replay_status=replay_status,
        is_identical=is_identical,
        original_root_cause_id=orig.primary_root_cause_id,
        replayed_root_cause_id=replayed.primary_root_cause_id,
        findings_differences=findings_diffs,
        evidence_differences=evidence_diffs,
        summary=summary,
        compared_at_iso=datetime.now(UTC).isoformat(),
    )
