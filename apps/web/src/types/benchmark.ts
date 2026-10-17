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
  provenance_details: string;
  capture_path: string;
  packet_count: number;
  byte_count: number;
  expected_outcome: ExpectedOutcome;
  tags: string[];
}

export interface DecodingStageMetrics {
  packet_count: number;
  byte_count: number;
  flow_count: number;
  event_count: number;
  duration_ms: number;
  throughput_pps: number;
  throughput_mbps: number;
}

export interface DeterministicStageMetrics {
  topology_node_count: number;
  topology_edge_count: number;
  forwarding_status: string;
  invariant_status: string;
  violation_count: number;
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
  relative_improvement_pct: number;
  comparison_status: BaselineComparisonStatus;
  conformal_coverage_pct: number;
  conformal_interval_mean_width: number;
  ood_in_dist_score: number;
  ood_shifted_score: number;
  duration_ms: number;
}

export interface ConsensusStageMetrics {
  consensus_status: string;
  ground_truth_held: boolean;
  explanation: string;
}

export interface OperationalProfile {
  peak_memory_mb: number;
  memory_growth_mb: number;
  cpu_duration_ms: number;
  wall_duration_ms: number;
}

export interface BenchmarkRunRecord {
  run_id: string;
  fixture_id: string;
  timestamp_iso: string;
  provenance: BenchmarkProvenance;
  category: BenchmarkCategory;
  decoding: DecodingStageMetrics;
  deterministic: DeterministicStageMetrics;
  predictive: PredictiveStageMetrics | null;
  consensus: ConsensusStageMetrics;
  profile: OperationalProfile;
  verification_passed: boolean;
  failure_reasons: string[];
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
