/**
 * Strongly Typed Contracts for Phase 10: Evidence-Backed Network Incident Investigation & Root-Cause Analysis.
 */

export type InvestigationType =
  | 'CONNECTIVITY_FAILURE'
  | 'UNEXPECTED_POLICY_DECISION'
  | 'DNS_RESOLUTION_FAILURE'
  | 'UNEXPECTED_TRAFFIC_RELATIONSHIP'
  | 'CHANGE_RELATED_BEHAVIOR';

export type EvidenceClass = 'OBSERVED' | 'INFERRED' | 'SIMULATED' | 'PREDICTED';

export type EvidenceNodeType =
  | 'PACKET'
  | 'FLOW'
  | 'ASSET'
  | 'TOPOLOGY_NODE'
  | 'TOPOLOGY_EDGE'
  | 'ROUTE'
  | 'ACL_RULE'
  | 'INVARIANT'
  | 'METRIC'
  | 'SCENARIO'
  | 'CONFIG';

export type CandidateStatus =
  | 'CONFIRMED_WITHIN_MODEL_SCOPE'
  | 'SUPPORTED_HYPOTHESIS'
  | 'INDETERMINATE'
  | 'INSUFFICIENT_EVIDENCE';

export type EvidenceSufficiency = 'SUFFICIENT' | 'PARTIAL' | 'INSUFFICIENT';

export interface EvidenceItem {
  evidence_id: string;
  evidence_class: EvidenceClass;
  node_type: EvidenceNodeType;
  source_id: string;
  label: string;
  description: string;
  provenance_uri?: string;
  capture_id?: string;
  packet_index?: number;
  timestamp_iso?: string;
  raw_properties: Record<string, any>;
}

export interface EvidenceRelationship {
  relation_id: string;
  source_node_id: string;
  target_node_id: string;
  relation_type: string;
  evidence_class: EvidenceClass;
  description: string;
}

export interface EvidenceGraph {
  nodes: EvidenceItem[];
  edges: EvidenceRelationship[];
  node_count: number;
  edge_count: number;
}

export interface CandidateExplanation {
  candidate_id: string;
  title: string;
  status: CandidateStatus;
  rank: number;
  score: number;
  rationale: string;
  supporting_evidence_ids: string[];
  contradicting_evidence_ids: string[];
  missing_evidence: string[];
  strengthening_factors: string[];
  weakening_factors: string[];
}

export interface InvestigationScope {
  source_ip?: string;
  destination_ip?: string;
  transport_protocol?: string;
  destination_port?: number;
  hostname?: string;
  time_window_start?: string;
  time_window_end?: string;
  capture_ids: string[];
  snapshot_ids: string[];
  model_id?: string;
  baseline_snapshot_id?: string;
  target_snapshot_id?: string;
}

export interface CounterfactualComparison {
  scenario_id: string;
  scenario_name: string;
  action_type: string;
  action_details: Record<string, any>;
  baseline_status: string;
  baseline_reason: string;
  counterfactual_status: string;
  counterfactual_reason: string;
  outcome_difference: string;
  is_counterfactual_verified: boolean;
}

export interface InvestigationCase {
  investigation_id: string;
  title: string;
  created_at_iso: string;
  updated_at_iso: string;
  investigation_type: InvestigationType;
  scope: InvestigationScope;
  status: string;
  sufficiency: EvidenceSufficiency;
  evidence_graph: EvidenceGraph;
  candidate_explanations: CandidateExplanation[];
  primary_root_cause_id?: string;
  counterfactual_comparisons: CounterfactualComparison[];
  known_limitations: string[];
  reproduction_steps: string[];
  author?: string;
}

export interface CreateInvestigationRequest {
  title: string;
  investigation_type: InvestigationType;
  scope: InvestigationScope;
}

export interface RunCounterfactualRequest {
  scenario_name: string;
  action_type: string;
  action_parameters: Record<string, any>;
}
