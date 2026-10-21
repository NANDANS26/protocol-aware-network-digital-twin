"""
FastAPI Route Handlers for Stateful Protocol Sequences & Regressions (Phase 05).
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Response
from pydantic import BaseModel, Field

from network_twin.storage.metadata_store import metadata_store
from network_twin.testing.sequence_differential import (
    SequenceDifferentialResult,
    run_sequence_metamorphic_noise_invariance,
    run_sequence_metamorphic_timestamp_shift,
    run_sequence_pcap_vs_pcapng_differential,
)
from network_twin.testing.sequence_generators import (
    generate_all_canonical_sequences,
    generate_ip_fragmentation,
    generate_segmented_http_stream,
    generate_tcp_handshake_teardown,
    generate_tcp_retransmission_and_ooo,
    generate_tcp_rst_and_abort,
    generate_tcp_simultaneous_flows,
)
from network_twin.testing.sequence_minimizer import (
    SequenceMinimizer,
    SequenceReproductionBundler,
)
from network_twin.testing.sequence_models import (
    ProtocolSequence,
    SequenceFinding,
    SequenceRegressionFixture,
    SequenceReproductionMetadata,
    SequenceType,
)
from network_twin.testing.sequence_runner import SequenceRunner

router = APIRouter(prefix="/sequences", tags=["Stateful Protocol Sequences"])


class SequenceGenerateRequest(BaseModel):
    sequence_type: SequenceType | None = Field(default=None, description="Sequence type to generate, or null for all")
    seed: int = Field(default=42, description="Deterministic seed")
    execute_immediately: bool = Field(default=True, description="Whether to execute immediately after generation")


class SequenceRunRequest(BaseModel):
    fault_injection: str | None = Field(
        default=None, description="Inject SIMULATE_CRASH or SIMULATE_TIMEOUT for test harness verification"
    )


class SequenceDifferentialRequest(BaseModel):
    sequence_id: str = Field(..., description="Target sequence ID")
    mode: str = Field(default="pcap_vs_pcapng", description="'pcap_vs_pcapng', 'noise_invariance', 'timestamp_shift'")


class SequencePromoteRequest(BaseModel):
    name: str = Field(default="Stateful Protocol Regression", description="Human-readable regression name")


@router.get("", response_model=list[ProtocolSequence])
async def list_sequences(
    sequence_type: str | None = Query(default=None, description="Filter by sequence type"),
) -> list[ProtocolSequence]:
    """Lists stored protocol sequences."""
    return metadata_store.list_sequences(sequence_type=sequence_type)


@router.post("/generate-suite", response_model=list[ProtocolSequence])
@router.post("/generate", response_model=list[ProtocolSequence])
async def generate_sequences(req: SequenceGenerateRequest | None = None) -> list[ProtocolSequence]:
    """Generates canonical protocol sequences and optionally executes them."""
    r = req or SequenceGenerateRequest()
    if r.sequence_type == SequenceType.TCP_HANDSHAKE_TEARDOWN:
        seqs = [generate_tcp_handshake_teardown(seed=r.seed)]
    elif r.sequence_type == SequenceType.TCP_RETRANSMISSION_OOO:
        seqs = [generate_tcp_retransmission_and_ooo(seed=r.seed)]
    elif r.sequence_type == SequenceType.TCP_RST_AND_ABORT:
        seqs = [generate_tcp_rst_and_abort(seed=r.seed)]
    elif r.sequence_type == SequenceType.TCP_SIMULTANEOUS_FLOWS:
        seqs = [generate_tcp_simultaneous_flows(seed=r.seed)]
    elif r.sequence_type == SequenceType.IP_FRAGMENTATION:
        seqs = [generate_ip_fragmentation(seed=r.seed)]
    elif r.sequence_type == SequenceType.HTTP_SEGMENTED_STREAM:
        seqs = [generate_segmented_http_stream(seed=r.seed)]
    else:
        seqs = generate_all_canonical_sequences(seed=r.seed)

    runner = SequenceRunner() if r.execute_immediately else None

    for s in seqs:
        metadata_store.save_sequence(s)
        if runner:
            _, findings = runner.execute(s)
            for f in findings:
                metadata_store.save_sequence_finding(f)

    return seqs


@router.get("/coverage-gaps")
async def get_coverage_gaps():
    """Returns explicitly documented protocol coverage gaps and unsupported semantics."""
    supported = [
        "RFC 793/9293 TCP 3-Way Handshake & 4-Way Teardown",
        "TCP Retransmission & Out-of-Order Gap Detection",
        "Bidirectional Flow Table State Isolation",
        "Midstream Connection State Recovery",
        "TCP Stream Segment Reassembly (DirectionReassembler)",
        "DNS Query/Response Transaction Matching",
        "HTTP/1.1 Request/Response Method & Host Header Parsing",
        "TLS ClientHello SNI & ALPN Protocol Extraction",
    ]
    gaps_raw = [
        {
            "subsystem": "IP Fragmentation Reassembly",
            "status": "DECODE_ONLY_NO_REASSEMBLY_CACHE",
            "details": "IPv4 and IPv6 fragment headers, identification, and fragment offsets are decoded per-packet. The engine currently lacks an IP reassembly buffer to merge fragmented L4 payloads prior to transport decoding.",
        },
        {
            "subsystem": "TLS Handshake Decryption",
            "status": "METADATA_EXTRACTION_ONLY",
            "details": "Extracts unencrypted ClientHello and ServerHello parameters (SNI, ALPN, cipher suites). Record layer decryption and TLS session state tracking are out-of-scope.",
        },
        {
            "subsystem": "HTTP/2 Multiplexing & HPACK",
            "status": "UNSUPPORTED",
            "details": "HTTP parsing supports RFC 9112 HTTP/1.1 cleartext. Binary frame multiplexing and HPACK decompression are not implemented.",
        },
        {
            "subsystem": "QUIC Crypto State",
            "status": "CLASSIFICATION_ONLY",
            "details": "QUIC Initial and Handshake packets are heuristically classified without full variable-length integer parsing or crypto state derivation.",
        },
    ]
    # Enriched dual-contract items
    enriched_gaps = [
        {
            **g,
            "feature": g["subsystem"],
            "limitation_status": g["status"],
            "description": g["details"],
            "behavior": g["details"],
        }
        for g in gaps_raw
    ]

    return {
        "status": "documented",
        "engine_version": "v1.2.0-native-cpp",
        "supported_stateful_semantics": supported,
        "supported_capabilities": supported,
        "coverage_gaps_and_limitations": enriched_gaps,
        "documented_coverage_gaps": enriched_gaps,
    }


@router.get("/findings", response_model=list[SequenceFinding])
async def list_sequence_findings(
    sequence_id: str | None = Query(default=None, description="Filter by sequence ID"),
) -> list[SequenceFinding]:
    """Lists detected sequence-level findings."""
    return metadata_store.list_sequence_findings(sequence_id=sequence_id)


@router.get("/regressions", response_model=list[SequenceRegressionFixture])
async def list_sequence_regressions() -> list[SequenceRegressionFixture]:
    """Lists permanent stateful regression fixtures."""
    return metadata_store.list_sequence_regressions()


@router.get("/{sequence_id}", response_model=ProtocolSequence)
async def get_sequence(sequence_id: str) -> ProtocolSequence:
    """Retrieves full details for a specific protocol sequence."""
    seq = metadata_store.get_sequence(sequence_id)
    if not seq:
        raise HTTPException(status_code=404, detail=f"Sequence not found: {sequence_id}")
    return seq


@router.post("/{sequence_id}/run")
async def run_sequence(sequence_id: str, req: SequenceRunRequest | None = None):
    """Executes a stored sequence through the C++ protocol engine."""
    seq = metadata_store.get_sequence(sequence_id)
    if not seq:
        raise HTTPException(status_code=404, detail=f"Sequence not found: {sequence_id}")

    runner = SequenceRunner()
    fault = req.fault_injection if req else None
    res, findings = runner.execute(seq, fault_injection=fault)

    for f in findings:
        metadata_store.save_sequence_finding(f)

    res_dict = res.model_dump()
    res_dict["execution"] = res.model_dump()
    res_dict["findings"] = [f.model_dump() for f in findings]
    return res_dict


@router.post("/findings/{finding_id}/minimize", response_model=SequenceReproductionMetadata)
async def minimize_finding(finding_id: str) -> SequenceReproductionMetadata:
    """Runs delta debugging sequence minimizer directly on a finding."""
    findings = metadata_store.list_sequence_findings()
    target_finding = next((f for f in findings if f.finding_id == finding_id), None)
    if not target_finding:
        raise HTTPException(status_code=404, detail=f"Finding not found: {finding_id}")

    seq = metadata_store.get_sequence(target_finding.sequence_id)
    if not seq:
        raise HTTPException(status_code=404, detail="Underlying sequence not found.")

    minimizer = SequenceMinimizer()
    minimized_seq, meta = minimizer.minimize(seq, target_finding)

    metadata_store.save_sequence(minimized_seq)
    target_finding.minimized = True
    target_finding.minimized_sequence_id = minimized_seq.sequence_id
    metadata_store.save_sequence_finding(target_finding)

    return meta


@router.post("/{sequence_id}/minimize")
async def minimize_sequence(sequence_id: str):
    """Runs delta debugging sequence minimizer on a sequence finding."""
    seq = metadata_store.get_sequence(sequence_id)
    if not seq:
        raise HTTPException(status_code=404, detail=f"Sequence not found: {sequence_id}")

    findings = metadata_store.list_sequence_findings(sequence_id=sequence_id)
    if not findings:
        raise HTTPException(status_code=400, detail="Cannot minimize sequence without an active finding.")

    target_finding = findings[0]
    minimizer = SequenceMinimizer()
    minimized_seq, meta = minimizer.minimize(seq, target_finding)

    metadata_store.save_sequence(minimized_seq)
    target_finding.minimized = True
    target_finding.minimized_sequence_id = minimized_seq.sequence_id
    metadata_store.save_sequence_finding(target_finding)

    return {
        "message": "Minimization complete",
        "original_step_count": meta.original_step_count,
        "minimized_step_count": meta.minimized_step_count,
        "reduction_ratio": meta.reduction_ratio,
        "removed_steps": meta.removed_steps,
        "minimized_sequence_id": minimized_seq.sequence_id,
    }


@router.get("/findings/{finding_id}/bundle")
@router.get("/findings/{finding_id}/export")
async def export_finding_bundle(finding_id: str):
    """Exports a self-contained reproduction ZIP bundle for a finding."""
    findings = metadata_store.list_sequence_findings()
    finding = next((f for f in findings if f.finding_id == finding_id), None)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding not found: {finding_id}")

    seq = metadata_store.get_sequence(finding.sequence_id)
    if not seq:
        raise HTTPException(status_code=404, detail="Underlying sequence not found.")

    meta = SequenceReproductionMetadata(
        finding_id=finding.finding_id,
        sequence_id=seq.sequence_id,
        original_step_count=len(seq.steps),
        minimized_step_count=len(seq.steps),
        reduction_ratio=0.0,
        removed_steps=[],
        cli_command=finding.reproduction_command,
        reproduction_script_ps1=f"# Sequence Repro\n{finding.reproduction_command}\n",
        reproduction_script_sh=f"#!/bin/bash\n{finding.reproduction_command}\n",
    )

    zip_bytes = SequenceReproductionBundler.create_bundle(seq, finding, meta)
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename=sequence_repro_{finding_id}.zip"},
    )


@router.post("/findings/{finding_id}/promote-regression", response_model=SequenceRegressionFixture)
@router.post("/findings/{finding_id}/promote", response_model=SequenceRegressionFixture)
async def promote_sequence_finding(
    finding_id: str, req: SequencePromoteRequest | None = None
) -> SequenceRegressionFixture:
    """Promotes a triaged finding to a permanent regression fixture."""
    r = req or SequencePromoteRequest()
    try:
        return metadata_store.promote_sequence_regression(finding_id=finding_id, name=r.name)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e


@router.post("/differential", response_model=SequenceDifferentialResult)
async def run_sequence_differential(req: SequenceDifferentialRequest) -> SequenceDifferentialResult:
    """Executes a differential (PCAP vs PCAPNG) or metamorphic invariance verification."""
    seq = metadata_store.get_sequence(req.sequence_id)
    if not seq:
        raise HTTPException(status_code=404, detail=f"Sequence not found: {req.sequence_id}")

    runner = SequenceRunner()
    if req.mode == "noise_invariance":
        return run_sequence_metamorphic_noise_invariance(seq, runner)
    elif req.mode == "timestamp_shift":
        return run_sequence_metamorphic_timestamp_shift(seq, runner)
    else:
        return run_sequence_pcap_vs_pcapng_differential(seq, runner)
