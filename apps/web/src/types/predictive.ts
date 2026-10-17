/**
 * Strongly Typed Contracts for Phase 06: Predictive Network World Model & Validated Behavior Forecasting.
 */

export type PredictionTarget =
  | 'FLOW_VOLUME_NEXT_WINDOW'
  | 'RELATIONSHIP_PERSISTENCE'
  | 'INVARIANT_RISK_SCORE'
  | 'PROTOCOL_ACTIVITY_DRIFT';

export type ModelAlgorithm =
  | 'PERSISTENCE_BASELINE'
  | 'MOVING_AVERAGE_BASELINE'
  | 'RIDGE_REGRESSION'
  | 'LOGISTIC_REGRESSION'
  | 'RANDOM_FOREST'
  | 'GRADIENT_BOOSTING';

export interface FeatureSchema {
  feature_names: string[];
  feature_types: Record<string, string>;
  target_column: string;
  excluded_features: string[];
}

export interface DatasetManifest {
  dataset_id: string;
  name: string;
  description: string;
  pipeline_version: string;
  source_captures: string[];
  source_artifacts: string[];
  time_window_sec: number;
  total_samples: number;
  feature_count: number;
  target_type: PredictionTarget;
  feature_schema: FeatureSchema;
  data_quality_notes: string[];
  dataset_samples: Record<string, unknown>[];
  hash_sha256: string;
  created_at_iso: string;
}

export interface EvaluationReport {
  algorithm: ModelAlgorithm;
  target: PredictionTarget;
  split_type: string;
  train_sample_count: number;
  test_sample_count: number;
  metrics: Record<string, number>;
  baseline_metrics: Record<string, number>;
  improvement_over_baseline: Record<string, number>;
  calibration_assessment: string;
  feature_importances: Record<string, number>;
  out_of_distribution_threshold: number;
}

export interface ModelArtifact {
  model_id: string;
  name: string;
  version: string;
  target: PredictionTarget;
  algorithm: ModelAlgorithm;
  dataset_id: string;
  feature_names: string[];
  artifact_path: string;
  artifact_hash_sha256: string;
  evaluation: EvaluationReport;
  limitations: string[];
  created_at_iso: string;
}

export interface ModelTrainingRun {
  run_id: string;
  model_id: string;
  dataset_id: string;
  target: PredictionTarget;
  algorithm: ModelAlgorithm;
  status: string;
  duration_ms: number;
  evaluation: EvaluationReport;
  created_at_iso: string;
}

export interface UncertaintyAssessment {
  uncertainty_method: string;
  lower_bound: number | null;
  upper_bound: number | null;
  confidence_level: number;
  is_out_of_distribution: boolean;
  ood_distance_score: number;
  reliability_tier: 'HIGH' | 'MODERATE' | 'LOW' | 'UNRELIABLE_OOD';
  rationale: string;
}

export interface PredictionRequest {
  model_id: string;
  features: Record<string, unknown>;
  prediction_horizon_sec?: number;
}

export interface PredictionResult {
  prediction_id: string;
  model_id: string;
  target: PredictionTarget;
  predicted_value: number;
  uncertainty: UncertaintyAssessment;
  feature_provenance: Record<string, unknown>;
  deterministic_comparison?: Record<string, unknown> | null;
  disagreement_explanation?: string | null;
  predicted_at_iso: string;
}

export interface ScenarioPredictionComparison {
  scenario_id: string;
  base_model_id: string;
  deterministic_reachable: boolean;
  deterministic_invariants_passed: boolean;
  deterministic_violations: string[];
  predicted_flow_volume_ratio: number;
  predicted_relationship_persistence: number;
  predicted_invariant_risk: number;
  consensus_status: string;
  detailed_explanation: string;
}

export interface PredictiveLimitationsResponse {
  supported_targets: string[];
  unsupported_targets: string[];
  methodological_rules: string[];
  data_quality_limitations: string[];
}

export interface DatasetExtractRequest {
  name?: string;
  description?: string;
  time_window_sec?: number;
  target_type?: PredictionTarget;
  source_captures?: string[];
  use_synthetic_canonical?: boolean;
  synthetic_sample_count?: number;
}

export interface ModelTrainRequest {
  dataset_id: string;
  target?: PredictionTarget;
  algorithm?: ModelAlgorithm;
  model_name?: string;
}
