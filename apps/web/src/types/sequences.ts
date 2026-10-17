/**
 * TypeScript contract definitions for Stateful Protocol Sequences, State Machine Fuzzing,
 * Minimization, and Regression Verification (Phase 05).
 */

export type ConnectionState =
  | 'CLOSED'
  | 'SYN_SENT'
  | 'SYN_RECEIVED'
  | 'ESTABLISHED'
  | 'FIN_WAIT_1'
  | 'FIN_WAIT_2'
  | 'CLOSE_WAIT'
  | 'CLOSING'
  | 'LAST_ACK'
  | 'TIME_WAIT'
  | 'RESET'
  | 'MIDSTREAM'
  | 'UNKNOWN';

export type SequenceType =
  | 'TCP_HANDSHAKE_TEARDOWN'
  | 'TCP_RETRANSMISSION_OOO'
  | 'TCP_RST_AND_ABORT'
  | 'TCP_SIMULTANEOUS_FLOWS'
  | 'TCP_TUPLE_REUSE'
  | 'IP_FRAGMENTATION'
  | 'DNS_TRANSACTION_COLLISION'
  | 'HTTP_SEGMENTED_STREAM'
  | 'TLS_SEGMENTED_HANDSHAKE'
  | 'METAMORPHIC_FLOW_ISOLATION';

export type SequenceMutationType =
  | 'NONE'
  | 'REORDER_PACKETS'
  | 'DUPLICATE_PACKET'
  | 'DROP_PACKET'
  | 'SHIFT_TIMESTAMPS'
  | 'SPLIT_SEGMENT'
  | 'COALESCE_SEGMENTS'
  | 'INTERLEAVE_FLOWS'
  | 'INSERT_UNRELATED_NOISE'
  | 'REUSE_IDENTIFIERS'
  | 'MUTATE_TEARDOWN_ORDER'
  | 'TRUNCATE_SEQUENCE';

export type SequenceFailureCategory =
  | 'CRASH'
  | 'HANG_TIMEOUT'
  | 'SCHEMA_VIOLATION'
  | 'STATE_TRANSITION_MISMATCH'
  | 'FLOW_LEAKAGE'
  | 'REASSEMBLY_MISMATCH'
  | 'COVERAGE_GAP_UNSUPPORTED'
  | 'DIFFERENTIAL_MISMATCH';

export type SequenceSeverity =
  | 'CRITICAL'
  | 'HIGH'
  | 'MEDIUM'
  | 'LOW'
  | 'INFORMATIONAL';

export interface ExpectedStateTransition {
  step_index: number;
  flow_id: string;
  expected_state: ConnectionState;
  rationale: string;
}

export interface SequenceStep {
  step_index: number;
  timestamp_offset_ns: number;
  source_ip: string;
  destination_ip: string;
  protocol: string;
  source_port?: number;
  destination_port?: number;
  tcp_seq?: number;
  tcp_ack?: number;
  tcp_flags?: Record<string, boolean>;
  tcp_window?: number;
  ip_id?: number;
  ip_fragment_offset?: number;
  ip_more_fragments?: boolean;
  payload_hex?: string;
  label?: string;
  is_noise?: boolean;
}

export interface SequenceMutation {
  mutation_type: SequenceMutationType;
  parameters: Record<string, unknown>;
  description: string;
}

export interface ProtocolSequence {
  sequence_id: string;
  name: string;
  description: string;
  sequence_type: SequenceType;
  seed: number;
  generator_version: string;
  steps: SequenceStep[];
  expected_transitions: ExpectedStateTransition[];
  expected_flow_count: number;
  expected_properties: Record<string, unknown>;
  mutations: SequenceMutation[];
  format: string;
  fixture_path?: string | null;
  fixture_hash?: string | null;
  is_supported: boolean;
  coverage_gap_notes?: string | null;
  created_at_iso: string;
}

export interface PerStepEngineObservation {
  step_index: number;
  event_id?: string | null;
  flow_id?: string | null;
  parser_status: string;
  observed_state?: ConnectionState | null;
  anomalies: string[];
}

export interface SequenceExecutionResult {
  execution_id: string;
  sequence_id: string;
  exit_code: number;
  duration_ms: number;
  total_events_emitted: number;
  total_flows_detected: number;
  crash_detected: boolean;
  hang_timeout: boolean;
  schema_valid: boolean;
  state_transitions_verified: boolean;
  flow_isolation_verified: boolean;
  step_observations: PerStepEngineObservation[];
  diagnostic?: string | null;
  executed_at_iso: string;
}

export interface SequenceFinding {
  finding_id: string;
  sequence_id: string;
  severity: SequenceSeverity;
  category: SequenceFailureCategory;
  title: string;
  description: string;
  root_cause_summary: string;
  reproduction_command: string;
  fixture_path: string;
  fixture_hash: string;
  minimized: boolean;
  minimized_sequence_id?: string | null;
  is_regression: boolean;
  created_at_iso: string;
}

export interface SequenceReproductionMetadata {
  finding_id: string;
  sequence_id: string;
  original_step_count: number;
  minimized_step_count: number;
  reduction_ratio: number;
  removed_steps: number[];
  cli_command: string;
  reproduction_script_ps1: string;
  reproduction_script_sh: string;
}

export interface SequenceRegressionFixture {
  regression_id: string;
  finding_id: string;
  name: string;
  sequence_type: SequenceType;
  fixture_path: string;
  fixture_hash: string;
  expected_exit_code: number;
  expected_to_pass: boolean;
  created_at_iso: string;
  last_run_iso?: string | null;
  last_run_passed?: boolean | null;
}

export interface SequenceDifferentialResult {
  sequence_id: string;
  mode: string;
  baseline_name: string;
  candidate_name: string;
  equivalent: boolean;
  differences: string[];
  baseline_event_count: number;
  candidate_event_count: number;
  duration_ms: number;
}

export interface CoverageGapsResponse {
  engine_version: string;
  supported_capabilities: string[];
  documented_coverage_gaps: {
    feature: string;
    description: string;
    behavior: string;
    limitation_status: string;
  }[];
}
