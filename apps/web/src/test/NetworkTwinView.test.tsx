import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { NetworkTwinView } from '../views/NetworkTwinView';
import { apiClient } from '../api/client';
import type {
  Asset,
  NetworkSegment,
  NetworkService,
  CommunicationRelationship,
  EvidenceRecord,
  TopologyGraph,
  TopologySnapshot,
  SnapshotComparisonDiff,
  CaptureMetadata,
  ConfigImportResult,
} from '../types/intelligence';
import type {
  NetworkModel,
  ReachabilityResult,
  SecurityInvariant,
  VerificationResult,
  SimulationScenario,
  CounterfactualResult,
} from '../types/simulation';

vi.mock('../api/client', () => {
  return {
    apiClient: {
      listAssets: vi.fn(),
      listSegments: vi.fn(),
      listServices: vi.fn(),
      listRelationships: vi.fn(),
      listEvidence: vi.fn(),
      getTopology: vi.fn(),
      listSnapshots: vi.fn(),
      listCaptures: vi.fn(),
      listImports: vi.fn(),
      createSnapshot: vi.fn(),
      compareSnapshots: vi.fn(),
      importConfiguration: vi.fn(),
      listModels: vi.fn(),
      getModel: vi.fn(),
      buildNetworkModel: vi.fn(),
      getModelLimitations: vi.fn(),
      evaluateReachability: vi.fn(),
      listInvariants: vi.fn(),
      createInvariant: vi.fn(),
      runVerification: vi.fn(),
      getVerificationResults: vi.fn(),
      listScenarios: vi.fn(),
      getScenario: vi.fn(),
      createScenario: vi.fn(),
      runScenario: vi.fn(),
      getCounterfactualResult: vi.fn(),
    },
  };
});

describe('NetworkTwinView Workstation', () => {
  const mockAssets: Asset[] = [
    {
      asset_id: 'asset-192-168-1-100',
      ip_addresses: ['192.168.1.100'],
      mac_addresses: ['00:11:22:33:44:55'],
      hostnames: ['app-server.corp.local'],
      device_class: 'server',
      identity_status: 'CONFIRMED',
      conflict_reasons: [],
      confidence: 1.0,
      first_seen_iso: '2026-10-17T10:00:00Z',
      last_seen_iso: '2026-10-17T10:05:00Z',
      evidence_ids: ['ev-001'],
      metadata: {},
    },
    {
      asset_id: 'asset-192-168-1-200',
      ip_addresses: ['192.168.1.200'],
      mac_addresses: ['66:77:88:99:aa:bb'],
      hostnames: ['db-primary.corp.local'],
      device_class: 'database',
      identity_status: 'PROBABLE',
      conflict_reasons: [],
      confidence: 0.85,
      first_seen_iso: '2026-10-17T10:00:00Z',
      last_seen_iso: '2026-10-17T10:05:00Z',
      evidence_ids: ['ev-002'],
      metadata: {},
    },
  ];

  const mockSegments: NetworkSegment[] = [
    {
      segment_id: 'seg-192-168-1-0-24',
      cidr: '192.168.1.0/24',
      ip_version: 4,
      gateway_candidates: ['192.168.1.1'],
      assigned_asset_ids: ['asset-192-168-1-100', 'asset-192-168-1-200'],
      evidence_ids: ['ev-003'],
      inferred: true,
    },
  ];

  const mockServices: NetworkService[] = [
    {
      service_id: 'srv-443-tcp',
      asset_id: 'asset-192-168-1-100',
      ip_address: '192.168.1.100',
      port: 443,
      transport_protocol: 'TCP',
      application_protocol: 'TLS/HTTPS',
      banner_or_alpn: 'h2,http/1.1',
      first_seen_iso: '2026-10-17T10:00:00Z',
      last_seen_iso: '2026-10-17T10:05:00Z',
      evidence_ids: ['ev-004'],
    },
  ];

  const mockRelationships: CommunicationRelationship[] = [
    {
      relationship_id: 'rel-001',
      source_asset_id: 'asset-192-168-1-100',
      destination_asset_id: 'asset-192-168-1-200',
      source_ip: '192.168.1.100',
      destination_ip: '192.168.1.200',
      transport_protocol: 'TCP',
      destination_port: 5432,
      evidence_class: 'DIRECTLY_OBSERVED',
      packet_count: 42,
      byte_count: 5120,
      first_seen_iso: '2026-10-17T10:00:00Z',
      last_seen_iso: '2026-10-17T10:05:00Z',
      evidence_ids: ['ev-005'],
    },
  ];

  const mockEvidence: EvidenceRecord[] = [
    {
      evidence_id: 'ev-001',
      source_type: 'PCAP_OBSERVATION',
      source_artifact_id: 'capture-001.pcap',
      packet_number_or_offset: 1,
      flow_key: '192.168.1.100:443-192.168.1.200:5432-TCP',
      timestamp_iso: '2026-10-17T10:00:00Z',
      confidence: 1.0,
      extracted_attributes: { src_mac: '00:11:22:33:44:55', src_ip: '192.168.1.100' },
      notes: 'Direct ethernet and IP packet header',
    },
  ];

  const mockTopology: TopologyGraph = {
    nodes: [
      {
        id: 'node-subnet-192-168-1-0-24',
        label: '192.168.1.0/24',
        node_type: 'SUBNET',
        ip_addresses: [],
        mac_addresses: [],
        subnet_cidr: '192.168.1.0/24',
        evidence_class: 'INFERRED',
        metadata: {},
      },
      {
        id: 'node-asset-192-168-1-100',
        label: '192.168.1.100',
        node_type: 'ASSET',
        ip_addresses: ['192.168.1.100'],
        mac_addresses: ['00:11:22:33:44:55'],
        evidence_class: 'DIRECTLY_OBSERVED',
        metadata: {},
      },
    ],
    edges: [
      {
        id: 'edge-sub-001',
        source_node_id: 'node-asset-192-168-1-100',
        target_node_id: 'node-subnet-192-168-1-0-24',
        edge_type: 'SUBNET_ATTACHMENT',
        evidence_class: 'INFERRED',
        packet_count: 42,
        byte_count: 5120,
        evidence_ids: ['ev-003'],
        is_bidirectional: true,
      },
    ],
    generated_at_iso: '2026-10-17T10:05:00Z',
    node_count: 2,
    edge_count: 1,
    subnets_count: 1,
    services_count: 1,
  };

  const mockSnapshots: TopologySnapshot[] = [
    {
      snapshot_id: 'snap-001',
      name: 'Baseline 1',
      created_at_iso: '2026-10-17T10:00:00Z',
      hash_fingerprint: 'abcdef0123456789',
      node_count: 2,
      edge_count: 1,
      source_captures: ['capture-001.pcap'],
      source_configs: [],
      graph_summary: {},
    },
    {
      snapshot_id: 'snap-002',
      name: 'Baseline 2',
      created_at_iso: '2026-10-17T10:05:00Z',
      hash_fingerprint: '9876543210fedcba',
      node_count: 3,
      edge_count: 2,
      source_captures: ['capture-002.pcap'],
      source_configs: [],
      graph_summary: {},
    },
  ];

  const mockCaptures: CaptureMetadata[] = [
    {
      capture_id: 'cap-001',
      file_name: 'test_capture.pcap',
      file_size_bytes: 1024,
      sha256_hash: '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
      packet_count: 8,
      link_type: 1,
      ingested_at_iso: '2026-10-17T10:00:00Z',
      format: 'pcap',
    },
  ];

  const mockImports: ConfigImportResult[] = [
    {
      import_id: 'imp-001',
      source_name: 'core-routes.json',
      source_type: 'ROUTING_TABLE',
      imported_at_iso: '2026-10-17T10:00:00Z',
      items_imported: 5,
      status: 'completed',
      errors: [],
    },
  ];

  const mockModel: NetworkModel = {
    model_id: 'model-001',
    name: 'Operational Twin Model',
    source_snapshot_id: 'snap-001',
    source_snapshot_fingerprint: 'abcdef0123456789',
    schema_version: '1.0.0',
    model_version: 1,
    created_at_iso: '2026-10-17T10:00:00Z',
    fingerprint: '3b92f7c0a8761234',
    nodes: {
      'node-asset-192-168-1-100': {
        node_id: 'node-asset-192-168-1-100',
        label: 'app-server',
        node_type: 'HOST',
        zone_id: 'INTERNAL',
        interfaces: [
          {
            interface_id: 'if0',
            node_id: 'node-asset-192-168-1-100',
            name: 'eth0',
            ip_assignments: [{ ip_address: '192.168.1.100', prefix_length: 24, is_primary: true }],
            state: 'UP',
          },
        ],
        routing_table: [],
        acls: [],
      },
    },
    zones: {
      'INTERNAL': {
        zone_id: 'INTERNAL',
        name: 'Internal Network',
        assigned_node_ids: ['node-asset-192-168-1-100'],
        assigned_interface_ids: [],
        assigned_subnets: ['192.168.1.0/24'],
        security_level: 50,
      },
    },
    source_evidence_refs: [],
    imported_config_refs: [],
    known_limitations: [],
    is_counterfactual: false,
  };

  const mockInvariant: SecurityInvariant = {
    invariant_id: 'inv-isolation-01',
    name: 'PCI-DSS Isolation',
    invariant_type: 'ISOLATION',
    severity: 'CRITICAL',
    definition: {
      source_zone_or_cidr: 'DMZ',
      destination_zone_or_cidr: 'PCI',
    },
  };

  const mockVerificationResult: VerificationResult = {
    result_id: 'ver-res-01',
    invariant_id: 'inv-isolation-01',
    invariant_name: 'PCI-DSS Isolation',
    invariant_type: 'ISOLATION',
    severity: 'CRITICAL',
    status: 'PASS',
    reason_code: 'VERIFIED_ISOLATION',
    explanation: 'Isolation strictly enforced between DMZ and PCI zones.',
    model_id: 'model-001',
    model_fingerprint: '3b92f7c0a8761234',
    evaluated_at_iso: '2026-10-17T10:05:00Z',
  };

  const mockScenario: SimulationScenario = {
    scenario_id: 'scen-01',
    base_model_id: 'model-001',
    name: 'Emergency Port Block',
    actions: [
      {
        action_type: 'ADD_FIREWALL_RULE',
        target_node_id: 'node-asset-192-168-1-100',
        parameters: { port: 22, protocol: 'TCP' },
      },
    ],
    created_at_iso: '2026-10-17T10:00:00Z',
  };

  const mockCounterfactualResult: CounterfactualResult = {
    result_id: 'cf-res-01',
    scenario_id: 'scen-01',
    scenario_name: 'Emergency Port Block',
    base_model_id: 'model-001',
    baseline_fingerprint: '3b92f7c0a8761234',
    counterfactual_model_id: 'model-001-sim',
    counterfactual_fingerprint: '9f8e7d6c5b4a3210',
    applied_actions_count: 1,
    path_differences: [
      {
        source_ip: '10.0.1.50',
        destination_ip: '192.168.1.100',
        protocol: 'TCP',
        destination_port: 22,
        baseline_status: 'REACHABLE',
        counterfactual_status: 'BLOCKED',
        change_type: 'NEWLY_BLOCKED',
        explanation: 'Path blocked by counterfactual firewall rule',
      },
    ],
    invariant_differences: [],
    newly_reachable_paths_count: 0,
    newly_blocked_paths_count: 1,
    security_regressions_count: 0,
    summary_explanation: 'Simulation resulted in 1 path change and 0 invariant deviations.',
    created_at_iso: '2026-10-17T10:10:00Z',
  };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(apiClient.listAssets).mockResolvedValue(mockAssets);
    vi.mocked(apiClient.listSegments).mockResolvedValue(mockSegments);
    vi.mocked(apiClient.listServices).mockResolvedValue(mockServices);
    vi.mocked(apiClient.listRelationships).mockResolvedValue(mockRelationships);
    vi.mocked(apiClient.listEvidence).mockResolvedValue(mockEvidence);
    vi.mocked(apiClient.getTopology).mockResolvedValue(mockTopology);
    vi.mocked(apiClient.listSnapshots).mockResolvedValue(mockSnapshots);
    vi.mocked(apiClient.listCaptures).mockResolvedValue(mockCaptures);
    vi.mocked(apiClient.listImports).mockResolvedValue(mockImports);
    vi.mocked(apiClient.listModels).mockResolvedValue([mockModel]);
    vi.mocked(apiClient.listInvariants).mockResolvedValue([mockInvariant]);
    vi.mocked(apiClient.listScenarios).mockResolvedValue([mockScenario]);
  });

  it('renders header, operational badges, and metrics summary strip', async () => {
    render(<NetworkTwinView />);

    await waitFor(() => {
      expect(screen.getByRole('heading', { level: 1, name: /Network Digital Twin/i })).toBeInTheDocument();
      expect(screen.getByText(/Phase 0[23] Operational/i)).toBeInTheDocument();
      expect(screen.getByText('app-server.corp.local')).toBeInTheDocument();
    });

    // Check metrics counts
    expect(screen.getAllByText('2').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('192.168.1.100')).toBeInTheDocument();
  });

  it('allows switching to Topology Graph and renders nodes', async () => {
    render(<NetworkTwinView />);

    await waitFor(() => {
      expect(screen.getByText('Asset Explorer')).toBeInTheDocument();
    });

    const topoTabBtn = screen.getByRole('button', { name: /Topology Graph/i });
    fireEvent.click(topoTabBtn);

    await waitFor(() => {
      expect(screen.getByText(/Subnet Hub/i)).toBeInTheDocument();
      expect(screen.getByText(/Asset Node/i)).toBeInTheDocument();
    });
  });

  it('allows switching to Evidence Inspector and inspecting evidence record', async () => {
    render(<NetworkTwinView />);

    await waitFor(() => {
      expect(screen.getByText('Evidence Inspector')).toBeInTheDocument();
    });

    const evTabBtn = screen.getByRole('button', { name: /Evidence Inspector/i });
    fireEvent.click(evTabBtn);

    await waitFor(() => {
      expect(screen.getByText(/PCAP_OBSERVATION/i)).toBeInTheDocument();
      expect(screen.getByText(/capture-001\.pcap/i)).toBeInTheDocument();
    });
  });

  it('supports differential snapshot comparison', async () => {
    const mockDiff: SnapshotComparisonDiff = {
      base_snapshot_id: 'snap-001',
      target_snapshot_id: 'snap-002',
      compared_at_iso: '2026-10-17T10:10:00Z',
      added_nodes: [
        {
          id: 'node-asset-192-168-1-200',
          label: '192.168.1.200',
          node_type: 'ASSET',
          ip_addresses: ['192.168.1.200'],
          mac_addresses: [],
          evidence_class: 'DIRECTLY_OBSERVED',
          metadata: {},
        },
      ],
      removed_nodes: [],
      changed_nodes: [],
      added_edges: [],
      removed_edges: [],
      changed_edges: [],
      evidence_explanations: [
        'Added node 192.168.1.200 (ASSET) due to new packet observation in capture-002.pcap.',
      ],
    };

    vi.mocked(apiClient.compareSnapshots).mockResolvedValue(mockDiff);

    render(<NetworkTwinView />);

    await waitFor(() => {
      expect(screen.getByText('Snapshot Comparison')).toBeInTheDocument();
    });

    const compTabBtn = screen.getByRole('button', { name: /Snapshot Comparison/i });
    fireEvent.click(compTabBtn);

    await waitFor(() => {
      expect(screen.getByText(/Differential Topology Comparison/i)).toBeInTheDocument();
    });

    const runDiffBtn = screen.getByRole('button', { name: /Run Diff/i });
    fireEvent.click(runDiffBtn);

    await waitFor(() => {
      expect(screen.getByText(/Evidence-Grounded Explanations/i)).toBeInTheDocument();
      expect(screen.getByText(/Added node 192.168.1.200/i)).toBeInTheDocument();
    });
  });

  it('allows switching to Reachability Workbench and evaluating reachability', async () => {
    const mockReachabilityResult: ReachabilityResult = {
      query_id: 'q-001',
      model_id: 'model-001',
      model_fingerprint: '3b92f7c0a8761234',
      source_ip: '10.0.1.100',
      destination_ip: '10.0.2.200',
      protocol: 'TCP',
      destination_port: 443,
      status: 'REACHABLE',
      reason_code: 'FORWARDING_CONFIRMED',
      explanation: 'Path traverses all hops successfully',
      evaluated_policy_count: 2,
      route_decisions_count: 1,
      path: [
        {
          hop_index: 0,
          node_id: 'node-asset-192-168-1-100',
          node_label: 'app-server',
          ingress_interface: 'if0',
          egress_interface: 'if0',
          routed_destination_prefix: '10.0.2.0/24',
        },
      ],
      blocking_rule: null,
      evidence_ids: ['ev-001'],
    };

    vi.mocked(apiClient.evaluateReachability).mockResolvedValue(mockReachabilityResult);

    render(<NetworkTwinView />);

    await waitFor(() => {
      expect(screen.getByText('Reachability')).toBeInTheDocument();
    });

    const reachTabBtn = screen.getByRole('button', { name: /Reachability/i });
    fireEvent.click(reachTabBtn);

    await waitFor(() => {
      expect(screen.getByText(/Deterministic Reachability & Packet Forwarding Workbench/i)).toBeInTheDocument();
      expect(screen.getByText(/Evaluate Forwarding Path/i)).toBeInTheDocument();
    });

    const evalBtn = screen.getByRole('button', { name: /Evaluate Forwarding Path/i });
    fireEvent.click(evalBtn);

    await waitFor(() => {
      expect(screen.getByText('REACHABLE')).toBeInTheDocument();
      expect(screen.getByText(/Forwarding Path Hop Sequence/i)).toBeInTheDocument();
      expect(screen.getByText('app-server')).toBeInTheDocument();
    });
  });

  it('allows switching to Security Invariants and viewing verification results', async () => {
    vi.mocked(apiClient.runVerification).mockResolvedValue([mockVerificationResult]);

    render(<NetworkTwinView />);

    await waitFor(() => {
      expect(screen.getByText('Security Invariants')).toBeInTheDocument();
    });

    const secTabBtn = screen.getByRole('button', { name: /Security Invariants/i });
    fireEvent.click(secTabBtn);

    await waitFor(() => {
      expect(screen.getByText(/Security Invariant Verification Engine/i)).toBeInTheDocument();
      expect(screen.getByText('PCI-DSS Isolation')).toBeInTheDocument();
    });

    const runVerifyBtn = screen.getByRole('button', { name: /Run Verification/i });
    fireEvent.click(runVerifyBtn);

    await waitFor(() => {
      expect(screen.getByText(/1 Pass/i)).toBeInTheDocument();
    });
  });

  it('allows switching to What-If Scenarios and running counterfactual simulation', async () => {
    vi.mocked(apiClient.runScenario).mockResolvedValue(mockCounterfactualResult);

    render(<NetworkTwinView />);

    await waitFor(() => {
      expect(screen.getByText('What-If Scenarios')).toBeInTheDocument();
    });

    const scenTabBtn = screen.getByRole('button', { name: /What-If Scenarios/i });
    fireEvent.click(scenTabBtn);

    await waitFor(() => {
      expect(screen.getByText(/Counterfactual Simulation & What-If Matrix/i)).toBeInTheDocument();
      expect(screen.getAllByText('Emergency Port Block').length).toBeGreaterThanOrEqual(1);
    });

    const runSimBtn = screen.getByRole('button', { name: /Run Simulation/i });
    fireEvent.click(runSimBtn);

    await waitFor(() => {
      expect(screen.getByText(/Path Reachability Status Shifts/i)).toBeInTheDocument();
      expect(screen.getByText(/9f8e7d6c5b4a3210/)).toBeInTheDocument();
    });
  });

  it('allows switching to Model Inspector and displays model fingerprint', async () => {
    render(<NetworkTwinView />);

    await waitFor(() => {
      expect(screen.getByText('Model Inspector')).toBeInTheDocument();
    });

    const modelTabBtn = screen.getByRole('button', { name: /Model Inspector/i });
    fireEvent.click(modelTabBtn);

    await waitFor(() => {
      expect(screen.getByText(/Executable Formal Model Inspector/i)).toBeInTheDocument();
      expect(screen.getByText(/3b92f7c0a8761234/)).toBeInTheDocument();
      expect(screen.getByText('model-001')).toBeInTheDocument();
    });
  });
});
