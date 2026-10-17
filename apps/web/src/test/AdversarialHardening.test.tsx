import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { AdversarialHardeningWorkbench } from '../views/twin/AdversarialHardeningWorkbench';
import { apiClient } from '../api/client';
import type {
  AdversarialTestCase,
  AdversarialRunSummary,
} from '../types/hardening';

vi.mock('../api/client', () => {
  return {
    apiClient: {
      getHardeningCases: vi.fn(),
      runHardeningSuite: vi.fn(),
      getLatestHardeningRun: vi.fn(),
      getHardeningRun: vi.fn(),
    },
  };
});

describe('AdversarialHardeningWorkbench Component', () => {
  const mockCases: AdversarialTestCase[] = [
    {
      test_id: 'ADV-ROUTE-01',
      name: 'Longest Prefix Match (LPM) Strict Preference',
      category: 'ROUTING_FORWARDING',
      description: 'Host route vs subnet vs default route preference',
      hand_verifiable_oracle: '10.1.2.45 matches /0, /8, /16, and /24; LPM dictates forwarding via /24 route egressing eth2.',
      expected_status: 'REACHABLE',
      expected_reason_code: 'REACHABLE',
    },
    {
      test_id: 'ADV-SEC-01',
      name: 'Strict Verification: Unresolved Evidence Never Yields False PASS',
      category: 'SECURITY_ISOLATION',
      description: 'Incomplete or unmodeled endpoint evidence returns INDETERMINATE, never PASS',
      hand_verifiable_oracle: 'Unresolved source IP yields INDETERMINATE reachability; verification must strictly return INDETERMINATE, never false PASS.',
      expected_status: 'INDETERMINATE',
      expected_reason_code: 'ROUTING_INDETERMINATE',
    },
    {
      test_id: 'ADV-SEC-02',
      name: 'True ACL Subnet and Port Shadowing Detection',
      category: 'CONFIG_CONSISTENCY',
      description: 'Superset deny rule shadows subsequent subset permit rule',
      hand_verifiable_oracle: 'Rule 1 blocks 10.0.0.0/16; Rule 2 allows subset 10.0.5.0/24; Rule 2 is completely shadowed and never reached.',
      expected_status: 'FAIL',
      expected_reason_code: 'CONFIGURATION_INCONSISTENCY',
    },
  ];

  const mockRunSummary: AdversarialRunSummary = {
    run_id: 'adv-run-test12345',
    timestamp: '2026-10-17T20:00:00Z',
    total_cases: 3,
    passed_cases: 3,
    failed_cases: 0,
    all_passed: true,
    duration_ms: 12.5,
    results: [
      {
        test_id: 'ADV-ROUTE-01',
        name: 'Longest Prefix Match (LPM) Strict Preference',
        category: 'ROUTING_FORWARDING',
        hand_verifiable_oracle: '10.1.2.45 matches /0, /8, /16, and /24; LPM dictates forwarding via /24 route egressing eth2.',
        expected_status: 'REACHABLE',
        actual_status: 'REACHABLE',
        expected_reason_code: 'REACHABLE',
        actual_reason_code: 'REACHABLE',
        passed: true,
        details: 'Egress interface used: eth2. Full path: Packet successfully routed to connected network 10.1.2.0/24.',
        execution_time_ms: 2.1,
      },
      {
        test_id: 'ADV-SEC-01',
        name: 'Strict Verification: Unresolved Evidence Never Yields False PASS',
        category: 'SECURITY_ISOLATION',
        hand_verifiable_oracle: 'Unresolved source IP yields INDETERMINATE reachability; verification must strictly return INDETERMINATE, never false PASS.',
        expected_status: 'INDETERMINATE',
        actual_status: 'INDETERMINATE',
        expected_reason_code: 'ROUTING_INDETERMINATE',
        actual_reason_code: 'ROUTING_INDETERMINATE',
        passed: true,
        details: 'Could not conclusively verify reachability for forbidden exposure query: SOURCE_UNKNOWN',
        execution_time_ms: 1.5,
      },
      {
        test_id: 'ADV-SEC-02',
        name: 'True ACL Subnet and Port Shadowing Detection',
        category: 'CONFIG_CONSISTENCY',
        hand_verifiable_oracle: 'Rule 1 blocks 10.0.0.0/16; Rule 2 allows subset 10.0.5.0/24; Rule 2 is completely shadowed and never reached.',
        expected_status: 'FAIL',
        actual_status: 'FAIL',
        expected_reason_code: 'CONFIGURATION_INCONSISTENCY',
        actual_reason_code: 'CONFIGURATION_INCONSISTENCY',
        passed: true,
        details: 'Shadowed ACL Rule: Rule 2 on node EdgeFirewall is completely shadowed by earlier Rule 1.',
        execution_time_ms: 1.2,
      },
    ],
  };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(apiClient.getHardeningCases).mockResolvedValue(mockCases);
    vi.mocked(apiClient.getLatestHardeningRun).mockResolvedValue(mockRunSummary);
    vi.mocked(apiClient.runHardeningSuite).mockResolvedValue(mockRunSummary);
  });

  it('renders workbench title, summary cards, and test cases', async () => {
    render(<AdversarialHardeningWorkbench />);

    await waitFor(() => {
      expect(screen.getByText('Adversarial Verification & Hardening Suite')).toBeInTheDocument();
    });

    expect(screen.getByText('ADV-ROUTE-01')).toBeInTheDocument();
    expect(screen.getByText('ADV-SEC-01')).toBeInTheDocument();
    expect(screen.getByText('ADV-SEC-02')).toBeInTheDocument();
    expect(screen.getByText('12.5 ms')).toBeInTheDocument();
  });

  it('triggers suite run when Run Hardening Suite is clicked', async () => {
    render(<AdversarialHardeningWorkbench />);

    await waitFor(() => {
      expect(screen.getByText('Run Hardening Suite')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Run Hardening Suite'));

    await waitFor(() => {
      expect(apiClient.runHardeningSuite).toHaveBeenCalledTimes(1);
    });
  });

  it('filters test cases by search query and category', async () => {
    render(<AdversarialHardeningWorkbench />);

    await waitFor(() => {
      expect(screen.getByText('ADV-ROUTE-01')).toBeInTheDocument();
    });

    const searchInput = screen.getByPlaceholderText('Search test oracles...');
    fireEvent.change(searchInput, { target: { value: 'Shadowing' } });

    expect(screen.queryByText('ADV-ROUTE-01')).not.toBeInTheDocument();
    expect(screen.getByText('ADV-SEC-02')).toBeInTheDocument();
  });

  it('expands test card to display hand-verifiable oracle and expected vs actual outcomes', async () => {
    render(<AdversarialHardeningWorkbench />);

    await waitFor(() => {
      expect(screen.getByText('ADV-ROUTE-01')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('ADV-ROUTE-01'));

    await waitFor(() => {
      expect(screen.getByText(/Hand-Verifiable Oracle & Mathematical Rationale/i)).toBeInTheDocument();
      expect(screen.getByText(/10.1.2.45 matches \/0, \/8, \/16, and \/24/i)).toBeInTheDocument();
      expect(screen.getByText(/Egress interface used: eth2/i)).toBeInTheDocument();
    });
  });
});
