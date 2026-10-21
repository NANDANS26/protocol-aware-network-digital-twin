/**
 * Strongly Typed Contracts for Phase 07: Real-World Validation, Reproducible Benchmarking & End-to-End Network Twin Audit.
 */

export type BenchmarkProvenance = 'REAL_CAPTURE' | 'PUBLIC_CAPTURE' | 'SYNTHETIC_FIXTURE';

export type BenchmarkCategory =
  | 'CORE'
  | 'PUBLIC'
  | 'TOPOLOGY_DRIFT'
  | 'SECURITY'
  | 'EDGE_MALFORMED'
  | 'SCALE_PROFILE';

export type BaselineComparisonStatus =
  | 'BEATS_BASELINE'
  | 'MATCHES_BASELINE'
  | 'LAGS_BASELINE'
  | 'INSUFFICIENT_DATA';

export interface ExpectedOutcome {
  forwarding_status: string;
  invariant_status: string;
  should_drop: boolean;
  error_expected: boolean;
}

export interface BenchmarkFixtureMeta {
  fixture_id: string;
  name: string;
  category: BenchmarkCategory;
  provenance: BenchmarkProvenance;
  provenance_details?: string;
  description?: string;
  capture_path?: string;
  packet_count: number;
  byte_count?: number;
  byte_size?: number;
  expected_outcome?: ExpectedOutcome;
  expected_properties?: ExpectedOutcome;
  tags?: string[];
  content_sha256?: string;
}

export interface DecodingStageMetrics {
  packet_count?: number;
  packets_decoded?: number;
  byte_count?: number;
  bytes_processed?: number;
  flow_count?: number;
  event_count?: number;
  duration_ms: number;
  throughput_pps?: number;
  throughput_pkts_per_sec?: number;
  throughput_mbps?: number;
  errors_encountered?: string[];
}

export interface DeterministicStageMetrics {
  topology_node_count?: number;
  topology_edge_count?: number;
  forwarding_status: string;
  invariant_status: string;
  violation_count?: number;
  witness_path_length?: number;
  forwarding_matches_expected?: boolean;
  invariant_matches_expected?: boolean;
  duration_ms: number;
}

export interface PredictiveStageMetrics {
  target: string;
  sample_count: number;
  train_count: number;
  test_count: number;
  baseline_algorithm: string;
  baseline_mae: number | null;
  baseline_rmse: number | null;
  learned_algorithm: string;
  learned_mae: number | null;
  learned_rmse: number | null;
  relative_improvement_pct: number | null;
  comparison_status: BaselineComparisonStatus;
  conformal_coverage_pct?: number | null;
  conformal_interval_mean_width: number | null;
  ood_in_dist_score: number | null;
  ood_shifted_score: number | null;
  duration_ms: number;
}

export interface ConsensusStageMetrics {
  consensus_status: string;
  ground_truth_held: boolean;
  explanation: string;
}

export interface OperationalProfile {
  peak_memory_mb: number;
  memory_growth_mb?: number;
  cpu_duration_ms?: number;
  wall_duration_ms?: number;
  total_runtime_ms?: number;
  storage_bytes_delta?: number;
}

export interface BenchmarkRunRecord {
  run_id: string;
  fixture_id: string;
  fixture_name?: string;
  timestamp_iso?: string;
  executed_at?: string;
  provenance: BenchmarkProvenance;
  category: BenchmarkCategory;
  status?: string;
  decoding: DecodingStageMetrics;
  deterministic: DeterministicStageMetrics;
  predictive: PredictiveStageMetrics | null;
  consensus: ConsensusStageMetrics;
  profile?: OperationalProfile;
  operational?: OperationalProfile;
  verification_passed?: boolean;
  failure_reasons?: string[];
  limitations?: string[];
}

export interface BenchmarkSummaryResponse {
  total_runs: number;
  verified_fixtures: number;
  average_throughput_pps: number;
  average_pipeline_latency_ms: number;
  peak_memory_mb: number;
  deterministic_accuracy_pct: number;
  models_beating_baseline_pct: number;
  recent_runs: BenchmarkRunRecord[];
}
