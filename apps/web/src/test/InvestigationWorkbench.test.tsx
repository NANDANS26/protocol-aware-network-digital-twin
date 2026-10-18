import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { InvestigationWorkbench } from '../views/twin/InvestigationWorkbench';
import { apiClient } from '../api/client';
import type { InvestigationCase } from '../types/investigations';

vi.mock('../api/client', () => {
  return {
    apiClient: {
      listInvestigations: vi.fn(),
      getInvestigation: vi.fn(),
      createInvestigation: vi.fn(),
      executeInvestigation: vi.fn(),
      runInvestigationCounterfactual: vi.fn(),
      exportInvestigation: vi.fn(),
      deleteInvestigation: vi.fn(),
    },
  };
});

describe('InvestigationWorkbench Component', () => {
  const mockCases: InvestigationCase[] = [
    {
      investigation_id: 'inv-test-case-01',
      title: 'Outage: Interface DOWN at Core Gateway',
      created_at_iso: '2026-10-18T00:00:00Z',
      updated_at_iso: '2026-10-18T00:00:00Z',
      investigation_type: 'CONNECTIVITY_FAILURE',
      scope: {
        source_ip: '192.168.10.50',
        destination_ip: '10.200.0.99',
        transport_protocol: 'TCP',
        destination_port: 80,
        capture_ids: [],
        snapshot_ids: [],
        model_id: 'model-core-gw',
      },
      status: 'ANALYZED',
      sufficiency: 'SUFFICIENT',
      evidence_graph: {
        nodes: [
          {
            evidence_id: 'ev-sim-forwarding',
            evidence_class: 'SIMULATED',
            node_type: 'SCENARIO',
            source_id: 'reach-001',
            label: 'Forwarding Simulation: BLOCKED',
            description: 'Status=BLOCKED, Reason=INTERFACE_DOWN, Hops=1',
            raw_properties: {},
          },
          {
            evidence_id: 'ev-cfg-interface-down',
            evidence_class: 'SIMULATED',
            node_type: 'CONFIG',
            source_id: 'if-eth1',
            label: 'Interface eth1 Administratively DOWN',
            description: 'Forwarding step failed because egress interface is DOWN',
            raw_properties: { state: 'DOWN' },
          },
        ],
        edges: [
          {
            relation_id: 'rel-1',
            source_node_id: 'ev-cfg-interface-down',
            target_node_id: 'ev-sim-forwarding',
            relation_type: 'DROPPED_BY',
            evidence_class: 'SIMULATED',
            description: 'Down interface halted egress packet transmission',
          },
        ],
        node_count: 2,
        edge_count: 1,
      },
      candidate_explanations: [
        {
          candidate_id: 'cand-interface-down',
          title: "Egress Interface 'eth1' is Administratively DOWN",
          status: 'CONFIRMED_WITHIN_MODEL_SCOPE',
          rank: 1,
          score: 0.98,
          rationale: 'Deterministic forwarding evaluation halted because interface eth1 has administrative state DOWN.',
          supporting_evidence_ids: ['ev-cfg-interface-down', 'ev-sim-forwarding'],
          contradicting_evidence_ids: [],
          missing_evidence: [],
          strengthening_factors: ['Device interface status verified as DOWN.'],
          weakening_factors: [],
        },
      ],
      primary_root_cause_id: 'cand-interface-down',
      counterfactual_comparisons: [
        {
          scenario_id: 'scen-cf-01',
          scenario_name: 'Remediation: Bring eth1 UP',
          action_type: 'SET_INTERFACE_STATE',
          action_details: { node_id: 'router-1', interface_id: 'eth1', state: 'UP' },
          baseline_status: 'BLOCKED',
          baseline_reason: 'INTERFACE_DOWN',
          counterfactual_status: 'REACHABLE',
          counterfactual_reason: 'REACHABLE',
          outcome_difference: 'Status changed from BLOCKED to REACHABLE (REMEDIAL_ACTION_CONFIRMED)',
          is_counterfactual_verified: true,
        },
      ],
      known_limitations: ['Physical layer carrier status unobservable from PCAP'],
      reproduction_steps: ['Run reachability query from 192.168.10.50 to 10.200.0.99:80'],
    },
  ];

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(apiClient.listInvestigations).mockResolvedValue(mockCases);
    vi.mocked(apiClient.getInvestigation).mockResolvedValue(mockCases[0] as InvestigationCase);
  });

  it('renders investigation list and loads case details', async () => {
    render(<InvestigationWorkbench />);

    await waitFor(() => {
      expect(screen.getByText(/CONFIRMED WITHIN MODEL SCOPE/i)).toBeInTheDocument();
    });

    expect(screen.getByText(/Evidence-Backed Network Incident Investigation/i)).toBeInTheDocument();
    expect(screen.getAllByText('Outage: Interface DOWN at Core Gateway').length).toBeGreaterThan(0);
    expect(screen.getAllByText('SUFFICIENT').length).toBeGreaterThan(0);
  });

  it('displays evidence graph nodes and counterfactual comparison side-by-side', async () => {
    render(<InvestigationWorkbench />);

    await waitFor(() => {
      expect(screen.getByText(/Forwarding Simulation: BLOCKED/i)).toBeInTheDocument();
    });

    expect(screen.getByText(/Interface eth1 Administratively DOWN/i)).toBeInTheDocument();
    expect(screen.getByText(/Remediation: Bring eth1 UP/i)).toBeInTheDocument();
    expect(screen.getByText(/REMEDIAL_ACTION_CONFIRMED/i)).toBeInTheDocument();
    expect(screen.getByText('REACHABLE')).toBeInTheDocument();
  });

  it('triggers investigation execution when Run button is clicked', async () => {
    const updatedCase: InvestigationCase = {
      ...(mockCases[0] as InvestigationCase),
      status: 'RE_ANALYZED',
    };
    vi.mocked(apiClient.executeInvestigation).mockResolvedValue(updatedCase);

    render(<InvestigationWorkbench />);

    await waitFor(() => {
      expect(screen.getByText('Run Investigation')).toBeInTheDocument();
    });

    const runBtn = screen.getByText('Run Investigation');
    fireEvent.click(runBtn);

    await waitFor(() => {
      expect(apiClient.executeInvestigation).toHaveBeenCalledWith('inv-test-case-01');
    });
  });

  it('opens New Incident Case modal and creates case', async () => {
    const newCase: InvestigationCase = {
      ...(mockCases[0] as InvestigationCase),
      investigation_id: 'inv-new-02',
      title: 'New DNS Incident Case',
      investigation_type: 'DNS_RESOLUTION_FAILURE',
    };
    vi.mocked(apiClient.createInvestigation).mockResolvedValue(newCase);

    render(<InvestigationWorkbench />);

    await waitFor(() => {
      expect(screen.getByText('New Incident Case')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('New Incident Case'));
    expect(screen.getByText('Create New Incident Investigation')).toBeInTheDocument();

    const titleInput = screen.getByPlaceholderText(/Core Gateway to WAN/i);
    fireEvent.change(titleInput, { target: { value: 'New DNS Incident Case' } });

    const createBtn = screen.getByRole('button', { name: /^Create Investigation$/i });
    fireEvent.click(createBtn);

    await waitFor(() => {
      expect(apiClient.createInvestigation).toHaveBeenCalled();
    });
  });
});
