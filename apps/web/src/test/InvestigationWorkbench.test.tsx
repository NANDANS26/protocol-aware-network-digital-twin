import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { InvestigationWorkbench } from '../views/twin/InvestigationWorkbench';
import { apiClient } from '../api/client';
import type {
  InvestigationCase,
  InvestigationExecutionRecord,
  ExecutionIntegrityReport,
  ReplayExecutionResponse,
  AuditPackExport,
} from '../types/investigations';

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
      listInvestigationExecutions: vi.fn(),
      getInvestigationExecution: vi.fn(),
      verifyExecutionIntegrity: vi.fn(),
      replayInvestigationExecution: vi.fn(),
      compareInvestigationExecutions: vi.fn(),
      exportExecutionAuditPack: vi.fn(),
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

  const mockExecutions: InvestigationExecutionRecord[] = [
    {
      execution_id: 'exec-test-01',
      investigation_id: 'inv-test-case-01',
      execution_index: 1,
      investigation_type: 'CONNECTIVITY_FAILURE',
      engine_version: '11.0.0',
      rule_version: '2026.10',
      started_at_iso: '2026-10-18T00:01:00Z',
      completed_at_iso: '2026-10-18T00:01:01Z',
      execution_duration_ms: 12.5,
      status: 'SUCCESS',
      replay_of_execution_id: null,
      normalized_scope: {
        source_ip: '192.168.10.50',
        destination_ip: '10.200.0.99',
        transport_protocol: 'TCP',
        destination_port: 80,
        capture_ids: [],
        snapshot_ids: [],
      },
      model_id: 'model-core-gw',
      model_fingerprint: 'fp-test',
      referenced_capture_ids: [],
      referenced_snapshot_ids: [],
      evidence_graph: { nodes: [], edges: [], node_count: 0, edge_count: 0 },
      evidence_integrity_hashes: { 'ev-sim-forwarding': 'a1b2c3d4e5f6' },
      overall_evidence_digest: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
      candidate_explanations: [],
      primary_root_cause_id: 'cand-interface-down',
      sufficiency: 'SUFFICIENT',
      counterfactual_comparisons: [],
      unresolved_questions: [],
      known_limitations: [],
      reproduction_steps: [],
      execution_notes: 'Initial run',
    },
  ];

  const mockIntegrityReport: ExecutionIntegrityReport = {
    execution_id: 'exec-test-01',
    investigation_id: 'inv-test-case-01',
    overall_status: 'VERIFIED',
    hash_algorithm: 'SHA-256',
    schema_version: '1.0.0',
    total_evidence_items: 2,
    verified_count: 2,
    modified_count: 0,
    missing_count: 0,
    item_reports: [
      {
        evidence_id: 'ev-sim-forwarding',
        evidence_class: 'SIMULATED',
        node_type: 'SCENARIO',
        recorded_sha256: 'a1b2c3d4e5f6',
        computed_sha256: 'a1b2c3d4e5f6',
        source_uri: 'twin://evidence/scenario/reach-001',
        verified: true,
        status: 'VERIFIED',
      },
    ],
    verified_at_iso: '2026-10-18T00:02:00Z',
    disclaimer:
      'Cryptographic integrity verification proves that recorded evidence has not been modified since recording; it does NOT attest to external real-world ground-truth or source authenticity.',
  };

  const mockReplayResponse: ReplayExecutionResponse = {
    replayed_execution: {
      ...mockExecutions[0]!,
      execution_id: 'exec-replay-02',
      execution_index: 2,
      replay_of_execution_id: 'exec-test-01',
    },
    comparison: {
      comparison_id: 'cmp-test-123',
      original_execution_id: 'exec-test-01',
      replayed_execution_id: 'exec-replay-02',
      investigation_id: 'inv-test-case-01',
      replay_status: 'REPLAY_IDENTICAL',
      is_identical: true,
      original_root_cause_id: 'cand-interface-down',
      replayed_root_cause_id: 'cand-interface-down',
      findings_differences: [
        {
          candidate_id: 'cand-interface-down',
          title: "Egress Interface 'eth1' is Administratively DOWN",
          change_type: 'MATCHED',
          original_status: 'CONFIRMED_WITHIN_MODEL_SCOPE',
          replayed_status: 'CONFIRMED_WITHIN_MODEL_SCOPE',
          original_score: 0.98,
          replayed_score: 0.98,
          original_rank: 1,
          replayed_rank: 1,
          explanation: 'Candidate explanation status, rank, and score are identical.',
        },
      ],
      evidence_differences: [],
      summary: 'Deterministic replay succeeded: All candidate explanations match bit-exact.',
      compared_at_iso: '2026-10-18T00:03:00Z',
    },
  };

  const mockAuditPack: AuditPackExport = {
    audit_pack_id: 'audit-exec-test-01',
    exported_at_iso: '2026-10-18T00:04:00Z',
    export_schema_version: '1.0.0',
    execution: mockExecutions[0]!,
    integrity_report: mockIntegrityReport,
    audit_instructions: [
      '1. Canonicalize each evidence item using sorted JSON keys and compact separators.',
      '2. Compute SHA-256 for each evidence item and match against recorded evidence_integrity_hashes.',
    ],
  };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(apiClient.listInvestigations).mockResolvedValue(mockCases);
    vi.mocked(apiClient.getInvestigation).mockResolvedValue(mockCases[0] as InvestigationCase);
    vi.mocked(apiClient.listInvestigationExecutions).mockResolvedValue(mockExecutions);
    vi.mocked(apiClient.verifyExecutionIntegrity).mockResolvedValue(mockIntegrityReport);
    vi.mocked(apiClient.replayInvestigationExecution).mockResolvedValue(mockReplayResponse);
    vi.mocked(apiClient.exportExecutionAuditPack).mockResolvedValue(mockAuditPack);
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

  it('renders execution history and executes cryptographic integrity audit', async () => {
    render(<InvestigationWorkbench />);

    await waitFor(() => {
      expect(screen.getByText(/Execution History & Replay Audit Ledger/i)).toBeInTheDocument();
      expect(screen.getByText(/#1 exec-test-01/i)).toBeInTheDocument();
    });

    const verifyBtn = screen.getByRole('button', { name: /Verify Integrity/i });
    fireEvent.click(verifyBtn);

    await waitFor(() => {
      expect(apiClient.verifyExecutionIntegrity).toHaveBeenCalledWith('inv-test-case-01', 'exec-test-01');
      expect(screen.getByText(/Cryptographic Evidence Integrity Audit/i)).toBeInTheDocument();
      expect(screen.getByText(/Cryptographic integrity verification proves that recorded evidence/i)).toBeInTheDocument();
    });
  });

  it('triggers deterministic replay and renders replay comparison cockpit', async () => {
    render(<InvestigationWorkbench />);

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Replay Run/i })).toBeInTheDocument();
    });

    const replayBtn = screen.getByRole('button', { name: /Replay Run/i });
    fireEvent.click(replayBtn);

    await waitFor(() => {
      expect(apiClient.replayInvestigationExecution).toHaveBeenCalledWith('inv-test-case-01', 'exec-test-01');
      expect(screen.getByText(/Deterministic Investigation Replay Cockpit/i)).toBeInTheDocument();
      expect(screen.getByText(/REPLAY IDENTICAL/i)).toBeInTheDocument();
      expect(screen.getByText(/All candidate explanations match bit-exact/i)).toBeInTheDocument();
    });
  });

  it('triggers export of verifiable audit pack', async () => {
    render(<InvestigationWorkbench />);

    await waitFor(() => {
      expect(screen.getByTitle(/Export Self-Contained Audit Pack JSON/i)).toBeInTheDocument();
    });

    const exportBtn = screen.getByTitle(/Export Self-Contained Audit Pack JSON/i);
    fireEvent.click(exportBtn);

    await waitFor(() => {
      expect(apiClient.exportExecutionAuditPack).toHaveBeenCalledWith('inv-test-case-01', 'exec-test-01');
      expect(screen.getByText(/Self-Contained Verifiable Audit Pack/i)).toBeInTheDocument();
      expect(screen.getByText(/Offline Audit Instructions/i)).toBeInTheDocument();
    });
  });
});
