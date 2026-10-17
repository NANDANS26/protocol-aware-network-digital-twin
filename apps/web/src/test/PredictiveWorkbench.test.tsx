import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { PredictiveWorkbench } from '../views/twin/PredictiveWorkbench';
import { apiClient } from '../api/client';
import type {
  DatasetManifest,
  ModelArtifact,
  PredictionResult,
  ScenarioPredictionComparison,
  PredictiveLimitationsResponse,
} from '../types/predictive';

vi.mock('../api/client', () => {
  return {
    apiClient: {
      listPredictiveDatasets: vi.fn(),
      extractPredictiveDataset: vi.fn(),
      getPredictiveDataset: vi.fn(),
      trainPredictiveModel: vi.fn(),
      listPredictiveModels: vi.fn(),
      getPredictiveModel: vi.fn(),
      predictBehavior: vi.fn(),
      listPredictiveRecords: vi.fn(),
      evaluateScenarioConsensus: vi.fn(),
      getPredictiveLimitations: vi.fn(),
    },
  };
});

describe('PredictiveWorkbench Component', () => {
  const mockDataset: DatasetManifest = {
    dataset_id: 'ds-canonical-flow-01',
    name: 'Canonical Diurnal Flow Volume',
    description: 'Time-windowed arrival sequence',
    pipeline_version: '1.0.0',
    source_captures: ['capture-01'],
    source_artifacts: [],
    time_window_sec: 10.0,
    total_samples: 80,
    feature_count: 16,
    target_type: 'FLOW_VOLUME_NEXT_WINDOW',
    feature_schema: {
      feature_names: ['flow_arrival_count', 'active_flow_count'],
      feature_types: { flow_arrival_count: 'float', active_flow_count: 'float' },
      target_column: 'target',
      excluded_features: ['raw_payload', 'payload_hex'],
    },
    data_quality_notes: ['Zero target leakage guaranteed.'],
    dataset_samples: [],
    hash_sha256: 'a1b2c3d4e5f67890123456789012345678901234567890123456789012345678',
    created_at_iso: '2026-10-17T20:00:00Z',
  };

  const mockModel: ModelArtifact = {
    model_id: 'model-ridge-01',
    name: 'Ridge Regression Benchmark',
    version: '1.0.0',
    target: 'FLOW_VOLUME_NEXT_WINDOW',
    algorithm: 'RIDGE_REGRESSION',
    dataset_id: 'ds-canonical-flow-01',
    feature_names: ['flow_arrival_count', 'active_flow_count'],
    artifact_path: 'data/models/model-ridge-01.joblib',
    artifact_hash_sha256: 'fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321',
    evaluation: {
      algorithm: 'RIDGE_REGRESSION',
      target: 'FLOW_VOLUME_NEXT_WINDOW',
      split_type: 'TIME_BASED_SPLIT',
      train_sample_count: 60,
      test_sample_count: 20,
      metrics: { mae: 1.45, rmse: 1.92, r2: 0.88 },
      baseline_metrics: { mae: 2.10, rmse: 2.85 },
      improvement_over_baseline: { mae: 30.9, rmse: 32.6 },
      calibration_assessment: 'Conformal 90% interval radius: ±2.40 units.',
      feature_importances: { flow_arrival_count: 0.65, active_flow_count: 0.35 },
      out_of_distribution_threshold: 3.0,
    },
    limitations: ['Predictions never override deterministic reachability proofs.'],
    created_at_iso: '2026-10-17T20:05:00Z',
  };

  const mockPrediction: PredictionResult = {
    prediction_id: 'pred-test-01',
    model_id: 'model-ridge-01',
    target: 'FLOW_VOLUME_NEXT_WINDOW',
    predicted_value: 19.45,
    uncertainty: {
      uncertainty_method: 'EMPIRICAL_CONFORMAL_INTERVAL',
      lower_bound: 17.05,
      upper_bound: 21.85,
      confidence_level: 0.90,
      is_out_of_distribution: false,
      ood_distance_score: 0.42,
      reliability_tier: 'HIGH',
      rationale: 'Conformal 90% prediction interval: [17.05, 21.85].',
    },
    feature_provenance: { features_used: {} },
    deterministic_comparison: null,
    disagreement_explanation: null,
    predicted_at_iso: '2026-10-17T20:10:00Z',
  };

  const mockLimitations: PredictiveLimitationsResponse = {
    supported_targets: ['FLOW_VOLUME_NEXT_WINDOW: Arrival rate forecasting'],
    unsupported_targets: ['Arbitrary Payload Classification: Excluded for zero-trust privacy'],
    methodological_rules: ['Ground Truth Supremacy: Deterministic proofs always prevail.'],
    data_quality_limitations: ['Requires minimum 20 observation windows.'],
  };

  const mockComparison: ScenarioPredictionComparison = {
    scenario_id: 'scen-cf-01',
    base_model_id: 'net-model-base',
    deterministic_reachable: false,
    deterministic_invariants_passed: true,
    deterministic_violations: [],
    predicted_flow_volume_ratio: 0.15,
    predicted_relationship_persistence: 0.08,
    predicted_invariant_risk: 0.05,
    consensus_status: 'ALIGNED',
    detailed_explanation: 'Deterministic forwarding engine proved destination is unreachable (Blocked by Firewall).',
  };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(apiClient.listPredictiveDatasets).mockResolvedValue([mockDataset]);
    vi.mocked(apiClient.listPredictiveModels).mockResolvedValue([mockModel]);
    vi.mocked(apiClient.listPredictiveRecords).mockResolvedValue([mockPrediction]);
    vi.mocked(apiClient.getPredictiveLimitations).mockResolvedValue(mockLimitations);
    vi.mocked(apiClient.predictBehavior).mockResolvedValue(mockPrediction);
    vi.mocked(apiClient.evaluateScenarioConsensus).mockResolvedValue(mockComparison);
  });

  it('renders header, operational badge, and metric cards', async () => {
    render(<PredictiveWorkbench />);

    expect(screen.getByText('Predictive Network World Model')).toBeInTheDocument();
    expect(screen.getByText('Phase 06 Operational')).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText('Canonical Diurnal Flow Volume')).toBeInTheDocument();
    });

    expect(screen.getByText('Versioned Datasets')).toBeInTheDocument();
    expect(screen.getByText('Uncertainty Coverage')).toBeInTheDocument();
  });

  it('switches to Model Evaluation tab and displays baseline comparison', async () => {
    render(<PredictiveWorkbench />);

    await waitFor(() => {
      expect(screen.getByText('Canonical Diurnal Flow Volume')).toBeInTheDocument();
    });

    const modelTabBtn = screen.getByRole('button', { name: /Model Evaluation & Baselines/i });
    fireEvent.click(modelTabBtn);

    await waitFor(() => {
      expect(screen.getByText('Ridge Regression Benchmark')).toBeInTheDocument();
      expect(screen.getByText(/Comparative Evaluation vs Naive Baseline/i)).toBeInTheDocument();
      expect(screen.getByText(/Candidate Model MAE:/i)).toBeInTheDocument();
    });
  });

  it('switches to Inference tab and executes calibrated prediction with uncertainty bounds', async () => {
    render(<PredictiveWorkbench />);

    const inferenceTabBtn = screen.getByRole('button', { name: /Inference & Uncertainty/i });
    fireEvent.click(inferenceTabBtn);

    await waitFor(() => {
      expect(screen.getByText(/Live Inference Feature Vector/i)).toBeInTheDocument();
    });

    const executeBtn = screen.getByRole('button', { name: /Execute Calibrated Inference/i });
    fireEvent.click(executeBtn);

    await waitFor(() => {
      expect(apiClient.predictBehavior).toHaveBeenCalledTimes(1);
      expect(screen.getAllByText('19.45').length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText(/90% Empirical Conformal Interval:/i)).toBeInTheDocument();
      expect(screen.getAllByText(/High Reliability \(In-Distribution\)/i).length).toBeGreaterThanOrEqual(1);
    });
  });

  it('switches to Scenario Consensus tab and displays ground truth supremacy', async () => {
    render(<PredictiveWorkbench />);

    const scenariosTabBtn = screen.getByRole('button', { name: /Scenario Consensus Harmonizer/i });
    fireEvent.click(scenariosTabBtn);

    await waitFor(() => {
      expect(screen.getByText(/Scenario Consensus & Ground Truth Harmonization/i)).toBeInTheDocument();
    });

    const evaluateBtn = screen.getByRole('button', { name: /Evaluate Scenario Consensus/i });
    fireEvent.click(evaluateBtn);

    await waitFor(() => {
      expect(apiClient.evaluateScenarioConsensus).toHaveBeenCalledTimes(1);
      expect(screen.getByText(/Deterministic Verification \(Ground Truth\)/i)).toBeInTheDocument();
      expect(screen.getByText('BLOCKED / DROPPED')).toBeInTheDocument();
    });
  });

  it('switches to Limitations tab and displays methodological rules', async () => {
    render(<PredictiveWorkbench />);

    const rulesTabBtn = screen.getByRole('button', { name: /Limitations & Rules/i });
    fireEvent.click(rulesTabBtn);

    await waitFor(() => {
      expect(screen.getByText(/Documented Boundaries & Inviolable Engineering Rules/i)).toBeInTheDocument();
      expect(screen.getByText(/Ground Truth Supremacy: Deterministic proofs always prevail./i)).toBeInTheDocument();
    });
  });
});
