"""
Strongly typed models for Phase 10: Evidence-Backed Network Incident Investigation & Root-Cause Analysis.
"""

from __future__ import annotations

import enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class InvestigationType(enum.StrEnum):
    """Supported investigation workflows grounded in existing engine capabilities."""
    CONNECTIVITY_FAILURE = "CONNECTIVITY_FAILURE"
    UNEXPECTED_POLICY_DECISION = "UNEXPECTED_POLICY_DECISION"
    DNS_RESOLUTION_FAILURE = "DNS_RESOLUTION_FAILURE"
    UNEXPECTED_TRAFFIC_RELATIONSHIP = "UNEXPECTED_TRAFFIC_RELATIONSHIP"
    CONFIGURATION_CHANGE_CORRELATION = "CONFIGURATION_CHANGE_CORRELATION"


class EvidenceClass(enum.StrEnum):
    """Explicit epistemological classification of evidence."""
    OBSERVED = "OBSERVED"      # Real packet decoding, flow record, or raw wire event
    INFERRED = "INFERRED"      # Derived endpoint, resolved asset, DNS correlation, or subnet
    SIMULATED = "SIMULATED"    # Deterministic forwarding trace, invariant result, or counterfactual
    PREDICTED = "PREDICTED"    # Statistical forecast (strictly labeled as predicted, never observed)


class EvidenceNodeType(enum.StrEnum):
    """Categorical types of nodes represented in the investigation evidence graph."""
    CAPTURE = "CAPTURE"
    PACKET = "PACKET"
    FLOW = "FLOW"
    ENDPOINT = "ENDPOINT"
    SERVICE = "SERVICE"
    CONFIG = "CONFIG"
    ROUTE = "ROUTE"
    ACL_RULE = "ACL_RULE"
    INVARIANT = "INVARIANT"
    SCENARIO = "SCENARIO"
    PREDICTION = "PREDICTION"


class CandidateStatus(enum.StrEnum):
    """Truthful explanation confidence status."""
    CONFIRMED_WITHIN_MODEL_SCOPE = "CONFIRMED_WITHIN_MODEL_SCOPE"
    SUPPORTED_HYPOTHESIS = "SUPPORTED_HYPOTHESIS"
    INDETERMINATE = "INDETERMINATE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class EvidenceSufficiency(enum.StrEnum):
    """Assessment of whether available evidence is sufficient for definitive root cause."""
    SUFFICIENT = "SUFFICIENT"
    PARTIAL = "PARTIAL"
    INSUFFICIENT = "INSUFFICIENT"


class EvidenceItem(BaseModel):
    """An individual piece of grounded evidence with provenance and epistemological class."""
    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(..., description="Unique evidence identifier")
    evidence_class: EvidenceClass = Field(..., description="Epistemological classification (OBSERVED, INFERRED, etc.)")
    node_type: EvidenceNodeType = Field(..., description="Domain type of evidence node")
    source_id: str = Field(..., description="ID of source asset, job, capture, or rule")
    label: str = Field(..., description="Human-readable evidence title")
    description: str = Field(default="", description="Detailed factual explanation")
    timestamp_iso: str | None = Field(default=None, description="ISO timestamp if time-bound")
    raw_properties: dict[str, Any] = Field(default_factory=dict, description="Verifiable telemetry attributes")


class EvidenceRelationship(BaseModel):
    """A directed edge linking evidence nodes with explicit provenance."""
    model_config = ConfigDict(extra="forbid")

    relation_id: str = Field(..., description="Unique relationship identifier")
    source_node_id: str = Field(..., description="Originating evidence node ID")
    target_node_id: str = Field(..., description="Target evidence node ID")
    relation_type: str = Field(..., description="Semantic edge type (e.g. GENERATED_FROM, DROPPED_BY)")
    evidence_class: EvidenceClass = Field(..., description="Epistemological status of this link")
    description: str = Field(default="", description="Factual explanation of the relationship")


class EvidenceGraph(BaseModel):
    """Complete bipartite/multi-relational evidence graph supporting an investigation."""
    model_config = ConfigDict(extra="forbid")

    nodes: list[EvidenceItem] = Field(default_factory=list)
    edges: list[EvidenceRelationship] = Field(default_factory=list)
    node_count: int = Field(default=0)
    edge_count: int = Field(default=0)


class CandidateExplanation(BaseModel):
    """A candidate root-cause explanation ranked without fabricated certainty."""
    model_config = ConfigDict(extra="forbid")

    candidate_id: str = Field(..., description="Unique candidate identifier")
    title: str = Field(..., description="Short explanation of candidate root cause")
    status: CandidateStatus = Field(..., description="Confidence and verification status")
    rank: int = Field(..., ge=1, description="Deterministic ranking position (1 = highest supported)")
    score: float = Field(..., ge=0.0, le=1.0, description="Calculated support score based on evidence rules")
    rationale: str = Field(..., description="Factual reasoning grounding why this candidate holds this rank")
    supporting_evidence_ids: list[str] = Field(default_factory=list, description="IDs of corroborating evidence")
    contradicting_evidence_ids: list[str] = Field(default_factory=list, description="IDs of conflicting evidence")
    missing_evidence: list[str] = Field(default_factory=list, description="Explicit data gaps needed to prove/refute")
    strengthening_factors: list[str] = Field(default_factory=list, description="Observations that would raise confidence")
    weakening_factors: list[str] = Field(default_factory=list, description="Observations that would refute this cause")


class InvestigationScope(BaseModel):
    """Explicit bounded scope parameters for an incident investigation."""
    model_config = ConfigDict(extra="forbid")

    source_ip: str | None = Field(default=None, description="Source IP address under investigation")
    destination_ip: str | None = Field(default=None, description="Destination IP address under investigation")
    transport_protocol: str | None = Field(default="ANY", description="Protocol constraint: TCP, UDP, ICMP, ANY")
    destination_port: int | None = Field(default=None, ge=1, le=65535, description="Target port under investigation")
    hostname: str | None = Field(default=None, description="DNS name or HTTP/TLS hostname under investigation")
    capture_ids: list[str] = Field(default_factory=list, description="Relevant source capture file IDs")
    snapshot_ids: list[str] = Field(default_factory=list, description="Relevant topology snapshot IDs")
    model_id: str | None = Field(default=None, description="Network model ID used for simulation")
    time_window_start: str | None = Field(default=None, description="Investigation start time window ISO")
    time_window_end: str | None = Field(default=None, description="Investigation end time window ISO")


class CounterfactualComparison(BaseModel):
    """Side-by-side comparison of baseline vs counterfactual simulation."""
    model_config = ConfigDict(extra="forbid")

    scenario_id: str = Field(..., description="Counterfactual scenario identifier")
    scenario_name: str = Field(..., description="Scenario title")
    action_type: str = Field(..., description="Type of change simulated (e.g. SET_INTERFACE_STATE, ADD_ROUTE)")
    action_details: dict[str, Any] = Field(default_factory=dict, description="Parameters of the change")
    baseline_status: str = Field(..., description="Baseline reachability status (REACHABLE, BLOCKED, etc.)")
    baseline_reason: str = Field(..., description="Baseline reason code")
    counterfactual_status: str = Field(..., description="Counterfactual reachability status")
    counterfactual_reason: str = Field(..., description="Counterfactual reason code")
    outcome_difference: str = Field(..., description="Description of whether the change resolved the failure")
    is_counterfactual_verified: bool = Field(default=True, description="Always True; labels result as simulated")


class InvestigationCase(BaseModel):
    """Comprehensive, versioned incident case with full evidence lineage and reproduction steps."""
    model_config = ConfigDict(extra="forbid")

    investigation_id: str = Field(..., description="Unique investigation case ID")
    title: str = Field(..., description="Concise investigation title")
    investigation_type: InvestigationType = Field(..., description="Investigation workflow type")
    scope: InvestigationScope = Field(..., description="Bounded scope parameters")
    status: str = Field(default="ANALYZED", description="Investigation status: OPEN, ANALYZED, CLOSED")
    sufficiency: EvidenceSufficiency = Field(..., description="Evidence sufficiency assessment")
    created_at_iso: str = Field(..., description="ISO 8601 creation timestamp")
    updated_at_iso: str = Field(..., description="ISO 8601 last updated timestamp")
    evidence_graph: EvidenceGraph = Field(default_factory=EvidenceGraph, description="Full multi-relational evidence graph")
    candidate_explanations: list[CandidateExplanation] = Field(default_factory=list, description="Ranked candidate root causes")
    primary_root_cause_id: str | None = Field(default=None, description="ID of primary confirmed root cause")
    counterfactual_comparisons: list[CounterfactualComparison] = Field(default_factory=list, description="Side-by-side comparisons")
    unresolved_questions: list[str] = Field(default_factory=list, description="Open questions that available data cannot answer")
    explicit_limitations: list[str] = Field(default_factory=list, description="Boundaries of what the model can and cannot claim")
    reproduction_steps: list[str] = Field(default_factory=list, description="Step-by-step instructions to reproduce findings")


class CreateInvestigationRequest(BaseModel):
    """Request payload to initiate a new incident investigation."""
    model_config = ConfigDict(extra="forbid")

    title: str = Field(..., min_length=3, max_length=150, description="Investigation title")
    investigation_type: InvestigationType = Field(..., description="Workflow type")
    scope: InvestigationScope = Field(..., description="Scope parameters")
