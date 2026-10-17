/**
 * Type definitions for Protocol Security Test Generation, Fuzzing & Differential Verification.
 */

export type ProtocolTarget =
  | 'ETHERNET'
  | 'VLAN'
  | 'IPV4'
  | 'IPV6'
  | 'TCP'
  | 'UDP'
  | 'DNS'
  | 'HTTP'
  | 'TLS_CLIENT_HELLO'
  | 'QUIC_CLASSIFIER';

export type ParserComponent =
  | 'ETHERNET_DECODER'
  | 'IPV4_DECODER'
  | 'IPV6_DECODER'
  | 'TCP_DECODER'
  | 'UDP_DECODER'
  | 'DNS_PARSER'
  | 'HTTP_PARSER'
  | 'TLS_PARSER'
  | 'QUIC_CLASSIFIER'
  | 'CAPTURE_READER';

export type GenerationStrategy =
  | 'BASELINE_CONFORMANCE'
  | 'MUTATION_FUZZING'
  | 'BOUNDARY_EDGE_CASES'
  | 'MALFORMED_INPUTS'
  | 'DIFFERENTIAL_EQUIVALENCE';

export type MutationOperator =
  | 'NONE'
  | 'TRUNCATE_HEADER'
  | 'TRUNCATE_PAYLOAD'
  | 'CORRUPT_CHECKSUM'
  | 'INVALID_VERSION'
  | 'INVALID_LENGTH'
  | 'EXTREME_BOUNDARIES'
  | 'CONTRADICTORY_FLAGS'
  | 'MALFORMED_OPTIONS'
  | 'POINTER_LOOP'
  | 'POINTER_OUT_OF_BOUNDS'
  | 'INJECT_PADDING'
  | 'PORT_SHIFT'
  | 'EXTENSION_CHAIN_LOOP'
  | 'BIT_FLIP';

export type CampaignStatus = 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';
export type CaseStatus = 'PENDING' | 'EXECUTED' | 'PASSED' | 'FAILED' | 'ERROR';
export type ExpectedBehavior = 'ACCEPT_VALID' | 'SAFE_REJECT' | 'EQUIVALENT_PARSING';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
export type Confidence = 'CONFIRMED' | 'SUSPECTED' | 'FALSE_POSITIVE';

export type FailureCategory =
  | 'CRASH'
  | 'HANG_TIMEOUT'
  | 'SANITIZER_VIOLATION'
  | 'SCHEMA_VIOLATION'
  | 'INCONSISTENT_PARSING'
  | 'UNEXPECTED_REJECTION'
  | 'UNEXPECTED_ACCEPTANCE'
  | 'DIFFERENTIAL_MISMATCH';

export type FindingStatus = 'OPEN' | 'TRIAGED' | 'MINIMIZED' | 'REGRESSION_PROMOTED' | 'CLOSED';

export interface TestCase {
  case_id: string;
  campaign_id: string;
  test_index: number;
  protocol_target: ProtocolTarget;
  generation_strategy: GenerationStrategy;
  mutation_sequence: string[];
  seed: number;
  generator_version: string;
  fixture_format: string;
  fixture_path: string;
  fixture_hash: string;
  expected_behavior: ExpectedBehavior;
  status: CaseStatus;
  created_at: string;
}

export interface ExecutionResult {
  result_id: string;
  case_id: string;
  exit_code: number;
  stdout: string;
  stderr: string;
  execution_time_ms: number;
  parser_status: string;
  parsed_event_count: number;
  schema_valid: boolean;
  schema_errors: string[];
  anomalies_detected: string[];
  sanitizer_triggered: boolean;
  crash_detected: boolean;
  passed: boolean;
  diagnostic: string | null;
  executed_at: string;
}

export interface TestCampaign {
  campaign_id: string;
  name: string;
  description: string;
  protocol_targets: ProtocolTarget[];
  strategies: GenerationStrategy[];
  seed: number;
  max_cases_per_target: number;
  total_cases: number;
  status: CampaignStatus;
  created_at: string;
  completed_at: string | null;
  cases_generated: number;
  cases_executed: number;
  passed_count: number;
  rejected_count: number;
  failed_count: number;
  findings_count: number;
  duration_ms: number;
  engine_version: string;
}

export interface CampaignCreateRequest {
  name: string;
  description?: string;
  protocol_targets?: ProtocolTarget[];
  strategies?: GenerationStrategy[];
  seed?: number;
  max_cases_per_target?: number;
  run_immediately?: boolean;
}

export interface Finding {
  finding_id: string;
  campaign_id: string;
  case_id: string;
  protocol_target: ProtocolTarget;
  parser_component: ParserComponent;
  severity: Severity;
  confidence: Confidence;
  failure_category: FailureCategory;
  input_hash: string;
  engine_version: string;
  reproduction_command: string;
  seed: number;
  mutation_sequence: string[];
  expected_behavior: string;
  actual_behavior: string;
  diagnostic: string;
  status: FindingStatus;
  regression_fixture_id: string | null;
  created_at: string;
}

export interface MinimizationStep {
  step_number: number;
  action: string;
  candidate_size_bytes: number;
  still_reproduces: boolean;
}

export interface ReproductionArtifact {
  artifact_id: string;
  finding_id: string;
  fixture_path: string;
  fixture_hash: string;
  reproduction_command: string;
  original_size_bytes: number;
  minimized_size_bytes: number;
  minimization_steps: MinimizationStep[];
  verified_reproducible: boolean;
  created_at: string;
}

export interface RegressionFixture {
  fixture_id: string;
  finding_id: string;
  name: string;
  protocol_target: ProtocolTarget;
  failure_category: FailureCategory;
  fixture_path: string;
  fixture_hash: string;
  engine_baseline_version: string;
  expected_behavior: ExpectedBehavior;
  created_at: string;
  last_run_at: string | null;
  last_run_passed: boolean | null;
  last_run_exit_code: number | null;
  last_run_diagnostic: string | null;
}

export interface RegressionRunResult {
  fixture_id: string;
  passed: boolean;
  exit_code: number;
  diagnostic: string | null;
  duration_ms: number;
  executed_at: string;
}

export interface DifferentialResult {
  test_name: string;
  equivalent: boolean;
  differences: string[];
  baseline_events_count: number;
  candidate_events_count: number;
  duration_ms: number;
}
