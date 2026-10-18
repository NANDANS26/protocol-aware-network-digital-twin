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

// --- Phase 11: Reproducible Replay & Evidence Integrity Types ---

export type ReplayStatus =
  | 'REPLAY_IDENTICAL'
  | 'REPLAY_DIFFERENT'
  | 'REPLAY_INCOMPLETE'
  | 'REPLAY_NOT_POSSIBLE';

export type IntegrityStatus =
  | 'VERIFIED'
  | 'MODIFIED'
  | 'MISSING_SOURCE'
  | 'UNSUPPORTED_SCHEMA';

export interface EvidenceIntegrityItem {
  evidence_id: string;
  evidence_class: EvidenceClass;
  node_type: EvidenceNodeType;
  recorded_sha256: string;
  computed_sha256: string;
  source_uri: string;
  verified: boolean;
  status: IntegrityStatus;
  discrepancy_details?: string | null;
}

export interface ExecutionIntegrityReport {
  execution_id: string;
  investigation_id: string;
  overall_status: IntegrityStatus;
  hash_algorithm: string;
  schema_version: string;
  total_evidence_items: number;
  verified_count: number;
  modified_count: number;
  missing_count: number;
  item_reports: EvidenceIntegrityItem[];
  verified_at_iso: string;
  disclaimer: string;
}

export interface FindingDifference {
  candidate_id: string;
  title: string;
  change_type: 'MATCHED' | 'MODIFIED' | 'ADDED' | 'REMOVED';
  original_status?: CandidateStatus | null;
  replayed_status?: CandidateStatus | null;
  original_score?: number | null;
  replayed_score?: number | null;
  original_rank?: number | null;
  replayed_rank?: number | null;
  explanation: string;
}

export interface ReplayComparison {
  comparison_id: string;
  original_execution_id: string;
  replayed_execution_id: string;
  investigation_id: string;
  replay_status: ReplayStatus;
  is_identical: boolean;
  original_root_cause_id?: string | null;
  replayed_root_cause_id?: string | null;
  findings_differences: FindingDifference[];
  evidence_differences: string[];
  summary: string;
  compared_at_iso: string;
}

export interface InvestigationExecutionRecord {
  execution_id: string;
  investigation_id: string;
  execution_index: number;
  investigation_type: InvestigationType;
  engine_version: string;
  rule_version: string;
  started_at_iso: string;
  completed_at_iso: string;
  execution_duration_ms: number;
  status: string;
  replay_of_execution_id?: string | null;
  normalized_scope: InvestigationScope;
  model_id?: string | null;
  model_fingerprint?: string | null;
  referenced_capture_ids: string[];
  referenced_snapshot_ids: string[];
  evidence_graph: EvidenceGraph;
  evidence_integrity_hashes: Record<string, string>;
  overall_evidence_digest: string;
  candidate_explanations: CandidateExplanation[];
  primary_root_cause_id?: string | null;
  sufficiency: EvidenceSufficiency;
  counterfactual_comparisons: CounterfactualComparison[];
  unresolved_questions: string[];
  known_limitations: string[];
  reproduction_steps: string[];
  execution_notes: string;
}

export interface ReplayExecutionResponse {
  replayed_execution: InvestigationExecutionRecord;
  comparison: ReplayComparison;
}

export interface AuditPackExport {
  audit_pack_id: string;
  exported_at_iso: string;
  export_schema_version: string;
  execution: InvestigationExecutionRecord;
  integrity_report: ExecutionIntegrityReport;
  audit_instructions: string[];
}

