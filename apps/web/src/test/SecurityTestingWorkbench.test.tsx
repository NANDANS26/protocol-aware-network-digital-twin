import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { SecurityTestingWorkbench } from '../views/twin/SecurityTestingWorkbench';
import { apiClient } from '../api/client';
import type { TestCampaign, TestCase, Finding, RegressionFixture, ReproductionArtifact, DifferentialResult } from '../types/testing';

vi.mock('../api/client', () => {
  return {
    apiClient: {
      listTestingCampaigns: vi.fn(),
      createTestingCampaign: vi.fn(),
      getTestingCampaign: vi.fn(),
      listTestingCases: vi.fn(),
      listTestingFindings: vi.fn(),
      minimizeFinding: vi.fn(),
      promoteFinding: vi.fn(),
      listRegressionFixtures: vi.fn(),
      runRegressionFixture: vi.fn(),
      runQuickDifferential: vi.fn(),
      exportFindingBundle: vi.fn(),
    },
  };
});

describe('SecurityTestingWorkbench Component', () => {
  const mockCampaign: TestCampaign = {
    campaign_id: 'camp-test-001',
    name: 'DNS Query Malformation Campaign',
    description: 'Deterministic grammar fuzzing for DNS',
    protocol_targets: ['DNS'],
    strategies: ['MALFORMED_INPUTS'],
    seed: 42,
    max_cases_per_target: 10,
    total_cases: 10,
    status: 'COMPLETED',
    created_at: '2026-10-17T12:00:00Z',
    completed_at: '2026-10-17T12:00:05Z',
    cases_generated: 10,
    cases_executed: 10,
    passed_count: 9,
    rejected_count: 1,
    failed_count: 0,
    findings_count: 1,
    duration_ms: 250,
    engine_version: '0.1.0',
  };

  const mockTestCase: TestCase = {
    case_id: 'case-test-001',
    campaign_id: 'camp-test-001',
    test_index: 0,
    protocol_target: 'DNS',
    generation_strategy: 'MALFORMED_INPUTS',
    mutation_sequence: ['POINTER_LOOP'],
    seed: 42,
    generator_version: '1.0.0',
    fixture_format: 'pcap',
    fixture_path: 'temp/fixtures/dns_001.pcap',
    fixture_hash: 'abc123sha256',
    expected_behavior: 'SAFE_REJECT',
    status: 'PASSED',
    created_at: '2026-10-17T12:00:01Z',
  };

  const mockFinding: Finding = {
    finding_id: 'find-test-001',
    campaign_id: 'camp-test-001',
    case_id: 'case-test-001',
    protocol_target: 'DNS',
    parser_component: 'DNS_PARSER',
    severity: 'MEDIUM',
    confidence: 'CONFIRMED',
    failure_category: 'INCONSISTENT_PARSING',
    input_hash: 'abc123sha256',
    engine_version: '0.1.0',
    reproduction_command: 'protocol_engine.exe --input temp/fixtures/dns_001.pcap --format pcap --jsonl out.jsonl',
    seed: 42,
    mutation_sequence: ['POINTER_LOOP'],
    expected_behavior: 'Safe rejection of cyclic compression pointer',
    actual_behavior: 'Parser returned incomplete record state',
    diagnostic: 'Target DNS parser looped on self-referential offset 0x0C',
    status: 'TRIAGED',
    regression_fixture_id: null,
    created_at: '2026-10-17T12:00:05Z',
  };

  const mockRegression: RegressionFixture = {
    fixture_id: 'regr-test-001',
    finding_id: 'find-test-001',
    name: 'DNS Cyclic Pointer Regression',
    protocol_target: 'DNS',
    failure_category: 'INCONSISTENT_PARSING',
    fixture_path: 'regressions/dns_cyclic.pcap',
    fixture_hash: 'abc123sha256',
    engine_baseline_version: '0.1.0',
    expected_behavior: 'SAFE_REJECT',
    created_at: '2026-10-17T12:05:00Z',
    last_run_at: '2026-10-17T12:05:01Z',
    last_run_passed: true,
    last_run_exit_code: 0,
    last_run_diagnostic: null,
  };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(apiClient.listTestingCampaigns).mockResolvedValue([mockCampaign]);
    vi.mocked(apiClient.listTestingCases).mockResolvedValue([mockTestCase]);
    vi.mocked(apiClient.listTestingFindings).mockResolvedValue([mockFinding]);
    vi.mocked(apiClient.listRegressionFixtures).mockResolvedValue([mockRegression]);
  });

  it('renders workbench title, operational status badge, and initial telemetry', async () => {
    render(<SecurityTestingWorkbench />);

    expect(screen.getByText(/Protocol Security Testing & Differential Fuzzing/i)).toBeInTheDocument();
    expect(screen.getByText(/Phase 04 Operational/i)).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getAllByText(/DNS Query Malformation Campaign/i).length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText(/Total Cases Executed/i)).toBeInTheDocument();
    });
  });

  it('allows launching a new fuzzing campaign via modal form', async () => {
    vi.mocked(apiClient.createTestingCampaign).mockResolvedValue({
      ...mockCampaign,
      campaign_id: 'camp-test-new',
    });

    render(<SecurityTestingWorkbench />);

    const openLauncherBtn = screen.getByRole('button', { name: /Configure & Launch Campaign/i });
    expect(openLauncherBtn).toBeInTheDocument();
    fireEvent.click(openLauncherBtn);

    const submitBtn = screen.getByRole('button', { name: /Execute Campaign/i });
    expect(submitBtn).toBeInTheDocument();
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(apiClient.createTestingCampaign).toHaveBeenCalledTimes(1);
    });
  });

  it('displays findings and allows minimization and regression promotion', async () => {
    const mockArtifact: ReproductionArtifact = {
      artifact_id: 'art-001',
      finding_id: 'find-test-001',
      fixture_path: 'temp/fixtures/dns_001_min.pcap',
      fixture_hash: 'minhash123',
      reproduction_command: 'protocol_engine.exe --input min.pcap',
      original_size_bytes: 72,
      minimized_size_bytes: 28,
      minimization_steps: [],
      verified_reproducible: true,
      created_at: '2026-10-17T12:06:00Z',
    };
    vi.mocked(apiClient.minimizeFinding).mockResolvedValue(mockArtifact);
    vi.mocked(apiClient.promoteFinding).mockResolvedValue(mockRegression);
    window.alert = vi.fn();
    window.prompt = vi.fn().mockReturnValue('DNS Boundary Test');

    render(<SecurityTestingWorkbench />);

    // Switch to Findings subtab
    const findingsTabBtn = screen.getByRole('button', { name: /Findings & Defect Triage/i });
    fireEvent.click(findingsTabBtn);

    await waitFor(() => {
      expect(screen.getByText(/Parser returned incomplete record state/i)).toBeInTheDocument();
    });

    // Select finding row
    const row = screen.getByText(/Parser returned incomplete record state/i);
    fireEvent.click(row);

    // Inspector should show diagnostic and reproduction command
    await waitFor(() => {
      expect(screen.getByText(/Target DNS parser looped on self-referential offset/i)).toBeInTheDocument();
      expect(screen.getByText(/protocol_engine\.exe/i)).toBeInTheDocument();
    });

    // Click Minimize finding
    const minimizeBtn = screen.getByRole('button', { name: /Run Delta Debugging Minimizer/i });
    fireEvent.click(minimizeBtn);

    await waitFor(() => {
      expect(apiClient.minimizeFinding).toHaveBeenCalledWith('find-test-001');
    });

    // Click Promote to Regression
    const promoteBtn = screen.getByRole('button', { name: /Promote to Regression Fixture/i });
    fireEvent.click(promoteBtn);

    await waitFor(() => {
      expect(apiClient.promoteFinding).toHaveBeenCalledWith('find-test-001', 'DNS Boundary Test');
    });
  });

  it('runs differential check between PCAP and PCAPNG', async () => {
    const mockDiff: DifferentialResult = {
      test_name: 'pcap_vs_pcapng_differential',
      equivalent: true,
      differences: [],
      baseline_events_count: 5,
      candidate_events_count: 5,
      duration_ms: 12.4,
    };
    vi.mocked(apiClient.runQuickDifferential).mockResolvedValue(mockDiff);

    render(<SecurityTestingWorkbench />);

    const diffCheckBtn = screen.getByRole('button', { name: /Run Differential Check/i });
    fireEvent.click(diffCheckBtn);

    await waitFor(() => {
      expect(apiClient.runQuickDifferential).toHaveBeenCalledTimes(1);
      expect(screen.getByText(/Differential Equivalence Verification: PASSED/i)).toBeInTheDocument();
    });
  });
});
