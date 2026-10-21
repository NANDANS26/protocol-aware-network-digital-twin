import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { ScenarioLaboratoryView } from '../views/ScenarioLaboratoryView';
import { apiClient } from '../api/client';
import type {
  NetworkModel,
  SimulationScenario,
  CounterfactualResult,
} from '../types/simulation';

vi.mock('../api/client', () => {
  return {
    apiClient: {
      listModels: vi.fn(),
      listScenarios: vi.fn(),
      listInvariants: vi.fn(),
      getCounterfactualResult: vi.fn(),
      runScenario: vi.fn(),
      createScenario: vi.fn(),
      runVerification: vi.fn(),
      createInvariant: vi.fn(),
      evaluateReachability: vi.fn(),
    },
  };
});

describe('ScenarioLaboratoryView & Counterfactual Workstation Redesign', () => {
  const mockModels: NetworkModel[] = [
    {
      model_id: 'model-e6442de6c31f',
      name: 'Operational Twin Model',
      source_snapshot_id: 'snap-e6442de6c31f',
      source_snapshot_fingerprint: 'fp-snap-ops',
      schema_version: '1.0.0',
      model_version: 1,
      fingerprint: 'fp-ops-baseline',
      created_at_iso: '2026-10-18T12:00:00Z',
      is_counterfactual: false,
      nodes: {
        'router-1': {
          node_id: 'router-1',
          label: 'Border Router 1',
          node_type: 'ROUTER',
          interfaces: [
            {
              interface_id: 'if-r1',
              node_id: 'router-1',
              name: 'eth0',
              ip_assignments: [{ ip_address: '192.168.1.1', prefix_length: 24 }],
              state: 'UP',
            },
          ],
          routing_table: [],
          acls: [],
        },
        'host-1': {
          node_id: 'host-1',
          label: 'Host 100',
          node_type: 'HOST',
          interfaces: [
            {
              interface_id: 'if-h1',
              node_id: 'host-1',
              name: 'eth0',
              ip_assignments: [{ ip_address: '192.168.1.100', prefix_length: 24 }],
              state: 'UP',
            },
          ],
          routing_table: [],
          acls: [],
        },
      },
      zones: {},
      source_evidence_refs: [],
      imported_config_refs: [],
      known_limitations: [
        {
          limitation_code: 'UNMODELED_EXTERNAL_ENDPOINTS',
          description: 'IP addresses outside local subnets evaluate to INDETERMINATE with NO_EGRESS_INTERFACE.',
          affected_entities: ['10.0.1.100'],
          impact: 'INDETERMINATE',
        },
      ],
    },
    {
      model_id: 'model-cf-a895ae0f7c',
      name: 'Operational Twin Model [Counterfactual: Emergency Lockdown]',
      source_snapshot_id: 'snap-e6442de6c31f',
      source_snapshot_fingerprint: 'fp-snap-ops',
      schema_version: '1.0.0',
      model_version: 1,
      fingerprint: 'fp-ops-cf',
      created_at_iso: '2026-10-18T13:00:00Z',
      is_counterfactual: true,
      parent_model_id: 'model-e6442de6c31f',
      nodes: {},
      zones: {},
      source_evidence_refs: [],
      imported_config_refs: [],
      known_limitations: [],
    },
  ];

  const mockScenarios: SimulationScenario[] = [
    {
      scenario_id: 'scen-1792337194534',
      name: 'Emergency External Lockdown',
      description: 'Block all incoming external traffic to port 443',
      base_model_id: 'model-e6442de6c31f',
      actions: [
        {
          action_type: 'ADD_FIREWALL_RULE',
          target_node_id: 'router-1',
          parameters: {
            rule_id: 'rule-deny-443',
            action: 'DENY',
            direction: 'INGRESS',
            protocol: 'TCP',
            destination_port: 443,
          },
          comment: 'Block ingress external HTTPS during security incident',
        },
      ],
    },
  ];

  const mockResult: CounterfactualResult = {
    result_id: 'run-af57d7658b2f',
    run_id: 'run-af57d7658b2f',
    scenario_id: 'scen-1792337194534',
    scenario_name: 'Emergency External Lockdown',
    base_model_id: 'model-e6442de6c31f',
    baseline_fingerprint: 'fp-ops-baseline',
    counterfactual_model_id: 'model-cf-a895ae0f7c',
    counterfactual_fingerprint: 'fp-ops-cf',
    applied_actions_count: 1,
    newly_reachable_paths_count: 0,
    newly_blocked_paths_count: 2,
    security_regressions_count: 0,
    path_differences: [
      {
        source_ip: '192.168.1.1',
        destination_ip: '192.168.1.100',
        protocol: 'TCP',
        destination_port: 443,
        baseline_status: 'REACHABLE',
        counterfactual_status: 'BLOCKED',
        change_type: 'NEWLY_BLOCKED',
        explanation: 'Traffic from 192.168.1.1 to 192.168.1.100:443 became BLOCKED (FIREWALL_DENY).',
      },
    ],
    invariant_differences: [],
    summary_explanation: 'Scenario applied 1 action. Result: 2 newly blocked paths, 0 regressions.',
    created_at_iso: '2026-10-18T13:00:00Z',
    executed_at_iso: '2026-10-18T13:00:00Z',
  };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(apiClient.listModels).mockResolvedValue(mockModels);
    vi.mocked(apiClient.listScenarios).mockResolvedValue(mockScenarios);
    vi.mocked(apiClient.listInvariants).mockResolvedValue([]);
    vi.mocked(apiClient.getCounterfactualResult).mockResolvedValue(mockResult);
  });

  it('renders redesigned workstation with Section A, B, C, and D', async () => {
    render(<ScenarioLaboratoryView />);

    await waitFor(() => {
      expect(screen.getByTestId('scenario-laboratory')).toBeInTheDocument();
    });

    expect(screen.getByText(/Section A/i)).toBeInTheDocument();
    expect(screen.getByText(/Counterfactual Simulation & What-If Matrix Studio/i)).toBeInTheDocument();
    expect(screen.getByText(/Section B/i)).toBeInTheDocument();
    expect(screen.getByText(/Proposed Hypothetical Changes: Emergency External Lockdown/i)).toBeInTheDocument();
    expect(screen.getByText(/Section C/i)).toBeInTheDocument();
    expect(screen.getByText(/Deterministic Execution Results & Reachability Shifts/i)).toBeInTheDocument();
    expect(screen.getByText(/Section D/i)).toBeInTheDocument();
    expect(screen.getByText(/Evidence Grounding, Known Limitations/i)).toBeInTheDocument();
  });

  it('filters out derived counterfactual models from the baseline selector by default', async () => {
    render(<ScenarioLaboratoryView />);

    await waitFor(() => {
      expect(screen.getByLabelText(/Authoritative Baseline Model/i)).toBeInTheDocument();
    });

    const select = screen.getByLabelText(/Authoritative Baseline Model/i) as HTMLSelectElement;
    const optionTexts = Array.from(select.options).map((o) => o.text);

    // Baseline model should be included
    expect(optionTexts.some((t) => t.includes('Operational Twin Model') && t.includes('[Baseline]'))).toBe(true);
    // Derived counterfactual model should NOT be included in default baseline list
    expect(optionTexts.some((t) => t.includes('[Derived]'))).toBe(false);

    // Checking the derived models toggle
    const checkbox = screen.getByLabelText(/Show 1 derived model\(s\)/i);
    expect(checkbox).toBeInTheDocument();

    fireEvent.click(checkbox);
    const updatedOptionTexts = Array.from(select.options).map((o) => o.text);
    expect(updatedOptionTexts.some((t) => t.includes('[Derived]'))).toBe(true);
  });

  it('renders structured action cards with parameters and node label mapping', async () => {
    render(<ScenarioLaboratoryView />);

    await waitFor(() => {
      expect(screen.getByText(/ADD_FIREWALL_RULE/i)).toBeInTheDocument();
    });

    expect(screen.getByText(/Target:/i)).toBeInTheDocument();
    expect(screen.getByText('router-1')).toBeInTheDocument();
    expect(screen.getByText('(Border Router 1)')).toBeInTheDocument();
    expect(screen.getByText(/Policy: DENY/i)).toBeInTheDocument();
    expect(screen.getByText(/Port: 443/i)).toBeInTheDocument();
    expect(screen.getByText(/Direction: INGRESS/i)).toBeInTheDocument();
  });

  it('renders KPI matrix with expected policy effect vs regressions analysis', async () => {
    render(<ScenarioLaboratoryView />);

    await waitFor(() => {
      expect(screen.getByText(/\+2/)).toBeInTheDocument();
    });

    expect(screen.getByText(/Newly Blocked Paths/i)).toBeInTheDocument();
    expect(screen.getByText(/Zero policy violations/i)).toBeInTheDocument();
    expect(screen.getByText(/Executive Simulation Analysis/i)).toBeInTheDocument();
    expect(screen.getByText(/\[Expected Policy Impact\] Ingress Restriction/i)).toBeInTheDocument();
    expect(screen.getByText(/\[VERIFIED SAFE\] Zero Security Regressions/i)).toBeInTheDocument();
  });

  it('displays plain language explanations and unmodeled boundary warning for INDETERMINATE', async () => {
    render(<ScenarioLaboratoryView />);

    await waitFor(() => {
      expect(screen.getByText('INDETERMINATE')).toBeInTheDocument();
    });

    expect(
      screen.getByText(/INDETERMINATE does NOT mean secure or blocked; it reflects an unmodeled boundary/i)
    ).toBeInTheDocument();
    expect(screen.getByText('UNMODELED_EXTERNAL_ENDPOINTS')).toBeInTheDocument();
  });

  it('displays warning when stored result belongs to a different baseline model', async () => {
    // Return a result from a different model
    vi.mocked(apiClient.getCounterfactualResult).mockResolvedValueOnce({
      ...mockResult,
      base_model_id: 'model-other-123',
    });

    render(<ScenarioLaboratoryView />);

    await waitFor(() => {
      expect(
        screen.getByText(/Displaying Stored Results from a Different Baseline or Scenario/i)
      ).toBeInTheDocument();
    });
  });

  it('labels cached stored results as HISTORICAL RECORD and marks live run as LIVE', async () => {
    vi.mocked(apiClient.getCounterfactualResult).mockResolvedValueOnce(mockResult);

    render(<ScenarioLaboratoryView />);

    await waitFor(() => {
      expect(screen.getByText(/HISTORICAL RECORD/i)).toBeInTheDocument();
    });

    // Mock live execution
    vi.mocked(apiClient.runScenario).mockResolvedValueOnce({
      ...mockResult,
      run_id: 'run-live-999',
    });

    const runBtn = screen.getByRole('button', { name: /Run Simulation/i });
    fireEvent.click(runBtn);

    await waitFor(() => {
      expect(screen.getByText(/LATEST SIMULATION RESULT \(LIVE\)/i)).toBeInTheDocument();
    });
  });

  it('allows clicking a path difference row to open the inspectable drawer with deep provenance', async () => {
    vi.mocked(apiClient.getCounterfactualResult).mockResolvedValueOnce(mockResult);

    render(<ScenarioLaboratoryView />);

    await waitFor(() => {
      expect(screen.getByText(/192.168.1.1 → 192.168.1.100:443/i)).toBeInTheDocument();
    });

    // Drawer should not be open initially
    expect(screen.queryByText(/Path Forwarding & Policy Trace Inspection/i)).not.toBeInTheDocument();

    // Click "Inspect" button
    const inspectBtn = screen.getByRole('button', { name: /Inspect/i });
    fireEvent.click(inspectBtn);

    // Deep inspect drawer opens
    expect(screen.getByText(/Path Forwarding & Policy Trace Inspection/i)).toBeInTheDocument();
    expect(screen.getByText(/1. Traffic Endpoints/i)).toBeInTheDocument();
    expect(screen.getByText(/2. Deterministic State Transition/i)).toBeInTheDocument();
    expect(screen.getByText(/3. Reason Code & Provenance/i)).toBeInTheDocument();
    expect(screen.getAllByText(/FIREWALL_DENY/i).length).toBeGreaterThan(0);
  });

  it('displays discrete empty state when no simulation result has been generated', async () => {
    vi.mocked(apiClient.getCounterfactualResult).mockRejectedValueOnce(new Error('No result'));

    render(<ScenarioLaboratoryView />);

    await waitFor(() => {
      expect(screen.getByTestId('section-c-empty')).toBeInTheDocument();
      expect(screen.getByText(/No Simulation Results Available/i)).toBeInTheDocument();
    });
  });

  it('displays discrete execution error state when scenario execution fails', async () => {
    vi.mocked(apiClient.getCounterfactualResult).mockRejectedValueOnce(new Error('No result'));
    vi.mocked(apiClient.runScenario).mockRejectedValueOnce(
      new Error("Action #1 (ADD_FIREWALL_RULE): Target node 'firewall-1' not found in model.")
    );

    render(<ScenarioLaboratoryView />);

    await waitFor(() => {
      expect(screen.getByText(/No Simulation Results Available/i)).toBeInTheDocument();
    });

    const runBtn = screen.getByRole('button', { name: /Run Simulation/i });
    fireEvent.click(runBtn);

    await waitFor(() => {
      expect(screen.getByTestId('section-c-error')).toBeInTheDocument();
      expect(screen.getByText(/Scenario Simulation Execution Failed/i)).toBeInTheDocument();
      expect(screen.getByText(/Target node 'firewall-1' not found in model/i)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /Retry Simulation/i })).toBeInTheDocument();
    });
  });
});
