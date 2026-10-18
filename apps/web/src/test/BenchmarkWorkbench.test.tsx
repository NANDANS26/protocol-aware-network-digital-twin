import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { BenchmarkWorkbench } from '../views/twin/BenchmarkWorkbench';
import { apiClient } from '../api/client';
import type {
  BenchmarkFixtureMeta,
  BenchmarkRunRecord,
  BenchmarkSummaryResponse,
} from '../types/benchmark';

vi.mock('../api/client', () => {
  return {
    apiClient: {
      listBenchmarkFixtures: vi.fn(),
      runBenchmark: vi.fn(),
      listBenchmarkRuns: vi.fn(),
      getBenchmarkRun: vi.fn(),
      getBenchmarkSummary: vi.fn(),
    },
  };
});

describe('BenchmarkWorkbench Component', () => {
  const mockFixtures: BenchmarkFixtureMeta[] = [
    {
      fixture_id: 'handshake-core',
      name: 'TCP Handshake Core Baseline',
      category: 'CORE',
      provenance: 'SYNTHETIC_FIXTURE',
      provenance_details: 'Deterministic synthetic 3-way handshake',
      capture_path: 'tests/fixtures/handshake_core.pcap',
      packet_count: 3,
      byte_count: 178,
      expected_outcome: {
        forwarding_status: 'DELIVERED',
        invariant_status: 'HOLD',
        should_drop: false,
        error_expected: false,
      },
      tags: ['tcp', 'handshake'],
    },
    {
      fixture_id: 'security-ssh-violation',
      name: 'Adversarial Unauthorized SSH Connection',
      category: 'SECURITY',
      provenance: 'SYNTHETIC_FIXTURE',
      provenance_details: 'Adversarial probe packet hitting ACL deny rule',
      capture_path: 'tests/fixtures/ssh_violation.pcap',
      packet_count: 1,
      byte_count: 74,
      expected_outcome: {
        forwarding_status: 'DROPPED_BY_FIREWALL',
        invariant_status: 'VIOLATED',
        should_drop: true,
        error_expected: false,
      },
      tags: ['security', 'acl', 'firewall'],
    },
  ];

  const mockRuns: BenchmarkRunRecord[] = [
    {
      run_id: 'run-test-01',
      fixture_id: 'handshake-core',
      timestamp_iso: '2026-10-17T21:00:00Z',
      provenance: 'SYNTHETIC_FIXTURE',
      category: 'CORE',
      decoding: {
        packet_count: 3,
        byte_count: 178,
        flow_count: 1,
        event_count: 3,
        duration_ms: 1.2,
        throughput_pps: 2500,
        throughput_mbps: 1.18,
      },
      deterministic: {
        topology_node_count: 4,
        topology_edge_count: 4,
        forwarding_status: 'DELIVERED',
        invariant_status: 'HOLD',
        violation_count: 0,
        duration_ms: 0.8,
      },
      predictive: {
        target: 'flow_volume_next_window',
        sample_count: 20,
        train_count: 14,
        test_count: 6,
        baseline_algorithm: 'PERSISTENCE',
        baseline_mae: 2.5,
        baseline_rmse: 3.1,
        learned_algorithm: 'RIDGE',
        learned_mae: 1.8,
        learned_rmse: 2.2,
        relative_improvement_pct: 28.0,
        comparison_status: 'BEATS_BASELINE',
        conformal_coverage_pct: 90.0,
        conformal_interval_mean_width: 3.4,
        ood_in_dist_score: 1.2,
        ood_shifted_score: 4.5,
        duration_ms: 0.0,
      },
      consensus: {
        consensus_status: 'COMPLEMENTARY',
        ground_truth_held: true,
        explanation: 'Deterministic forwarding matches route policies; predictive forecast complements telemetry.',
      },
      profile: {
        peak_memory_mb: 42.5,
        memory_growth_mb: 1.2,
        cpu_duration_ms: 2.1,
        wall_duration_ms: 3.5,
      },
      verification_passed: true,
      failure_reasons: [],
    },
  ];

  const mockSummary: BenchmarkSummaryResponse = {
    total_runs: 12,
    verified_fixtures: 6,
    average_throughput_pps: 18450,
    average_pipeline_latency_ms: 45.2,
    peak_memory_mb: 58.4,
    deterministic_accuracy_pct: 100.0,
    models_beating_baseline_pct: 100.0,
    recent_runs: mockRuns,
  };

  beforeEach(() => {
    vi.clearAllMocks();
    (apiClient.listBenchmarkFixtures as any).mockResolvedValue(mockFixtures);
    (apiClient.listBenchmarkRuns as any).mockResolvedValue(mockRuns);
    (apiClient.getBenchmarkSummary as any).mockResolvedValue(mockSummary);
    (apiClient.runBenchmark as any).mockResolvedValue(mockRuns);
  });

  it('renders benchmark workbench title, status badge, and integrity banner', async () => {
    render(<BenchmarkWorkbench />);

    await waitFor(() => {
      expect(screen.getByText('Reproducible Validation & Benchmarking')).toBeInTheDocument();
      expect(screen.getByText('Benchmark Suite Active')).toBeInTheDocument();
      expect(screen.getByText('Truthfulness & Methodological Integrity Standards')).toBeInTheDocument();
    });
  });

  it('renders metrics strip with throughput, latency, and accuracy', async () => {
    render(<BenchmarkWorkbench />);

    await waitFor(() => {
      expect(screen.getByText('Total Runs')).toBeInTheDocument();
      expect(screen.getByText('18,450 pps')).toBeInTheDocument();
      expect(screen.getByText('45.2 ms')).toBeInTheDocument();
      expect(screen.getByText('100% Pass rate')).toBeInTheDocument();
    });
  });

  it('renders registered fixtures catalog with provenance and expected outcomes', async () => {
    render(<BenchmarkWorkbench />);

    await waitFor(() => {
      expect(screen.getByText('handshake-core')).toBeInTheDocument();
      expect(screen.getByText('security-ssh-violation')).toBeInTheDocument();
      expect(screen.getByText('DROPPED_BY_FIREWALL')).toBeInTheDocument();
      expect(screen.getByText('VIOLATED')).toBeInTheDocument();
    });
  });

  it('switches to Audit Runs History tab and displays multi-stage details', async () => {
    render(<BenchmarkWorkbench />);

    await waitFor(() => {
      expect(screen.getByText('Audit Runs History')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Audit Runs History'));

    await waitFor(() => {
      expect(screen.getByText('Stage 1: Offline C++ Engine Decoding')).toBeInTheDocument();
      expect(screen.getByText('Stage 2: Deterministic Security Verification')).toBeInTheDocument();
      expect(screen.getByText(/Stage 3: Predictive ML Target/)).toBeInTheDocument();
      expect(screen.getByText('Stage 4: Ground-Truth Supremacy Consensus')).toBeInTheDocument();
      expect(screen.getByText(/✓ Beats Baseline/)).toBeInTheDocument();
      expect(screen.getByText('+28%')).toBeInTheDocument();
      expect(screen.getByText('GROUND TRUTH SUPREME: UPHELD')).toBeInTheDocument();
    });
  });

  it('triggers Run Validation Suite on button click', async () => {
    render(<BenchmarkWorkbench />);

    await waitFor(() => {
      expect(screen.getByText('Run Validation Suite')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Run Validation Suite'));

    await waitFor(() => {
      expect(apiClient.runBenchmark).toHaveBeenCalledWith({});
    });
  });

  it('switches to Ground-Truth Supremacy tab and explains adversarial drop supremacy', async () => {
    render(<BenchmarkWorkbench />);

    await waitFor(() => {
      expect(screen.getByText('Ground-Truth Supremacy')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Ground-Truth Supremacy'));

    await waitFor(() => {
      expect(screen.getByText('Independent Security Engine Validation')).toBeInTheDocument();
      expect(screen.getByText(/Deterministic Firewall ACL drops ALWAYS supersede statistical forecasts/)).toBeInTheDocument();
    });
  });
});
