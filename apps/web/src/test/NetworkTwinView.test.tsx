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
      deleteConfigImport: vi.fn(),
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
      expect(screen.getByText(/Twin Operational/i)).toBeInTheDocument();
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
      expect(screen.getByText('app-server.corp.local')).toBeInTheDocument();
    });

    const evTabBtn = screen.getByRole('button', { name: /Evidence Inspector/i });
    fireEvent.click(evTabBtn);

    await waitFor(() => {
      expect(screen.getByText(/PCAP_OBSERVATION/i)).toBeInTheDocument();
      expect(screen.getAllByText(/capture-001\.pcap/i).length).toBeGreaterThanOrEqual(1);
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

  it('executes model reconstruction with selected evidence inputs and renders consumption audit', async () => {
    const reconstructedSnap: TopologySnapshot = {
      snapshot_id: 'snap-reconstructed-999',
      name: 'Enterprise Core Twin - Baseline Reconstructed',
      node_count: 4,
      edge_count: 3,
      source_captures: ['cap-001'],
      source_configs: ['imp-001'],
      created_at_iso: '2026-10-21T08:00:00Z',
      metadata: {
        consumption_audit: {
          consumed_assets_count: 2,
          consumed_subnets_count: 1,
          consumed_services_count: 1,
          consumed_edges_count: 3,
          consumed_subnets: ['192.168.1.0/24'],
          source_captures: ['cap-001'],
          source_configs: ['imp-001'],
          skipped_or_rejected: [
            {
              item_id: 'seg-mcast-01',
              item_type: 'SUBNET',
              action: 'SKIPPED',
              reason: 'Multicast/loopback prefix 224.0.1.129 excluded from unicast forwarding tree',
            },
          ],
        },
        evidence_coverage: {
          directly_observed_pct: 75.0,
          inferred_pct: 25.0,
          configured_pct: 0.0,
          total_elements: 7,
        },
        limitations: [
          'PCAP traffic analysis is temporally bounded to the packet capture observation window.',
        ],
      },
    };

    vi.mocked(apiClient.createSnapshot).mockResolvedValue(reconstructedSnap);

    render(<NetworkTwinView />);

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /^Reconstruct Model$/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /^Reconstruct Model$/i }));

    await waitFor(() => {
      expect(screen.getByText(/Build & Reconstruct Network Digital Twin/i)).toBeInTheDocument();
      expect(screen.getByText(/Model Source Inputs/i)).toBeInTheDocument();
    });

    const executeBtn = screen.getByRole('button', { name: /Execute Reconstruction/i });
    fireEvent.click(executeBtn);

    await waitFor(() => {
      expect(apiClient.createSnapshot).toHaveBeenCalled();
      expect(screen.getByText(/Model Reconstructed & Persisted/i)).toBeInTheDocument();
      expect(screen.getByText(/75% Directly Observed/i)).toBeInTheDocument();
      expect(screen.getByText(/Source Records Filtered \/ Skipped/i)).toBeInTheDocument();
      expect(screen.getByText(/Multicast\/loopback prefix 224.0.1.129 excluded/i)).toBeInTheDocument();
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

  it('handles structured object diffs with node and edge change objects without crashing React', async () => {
    const complexDiff: SnapshotComparisonDiff = {
      base_snapshot_id: 'snap-alpha',
      target_snapshot_id: 'snap-beta',
      compared_at_iso: '2026-10-18T12:00:00Z',
      added_nodes: [
        {
          id: 'node-printer-01',
          node_id: 'node-printer-01',
          label: 'office-printer.local',
          node_type: 'ASSET',
        },
      ],
      removed_nodes: [],
      modified_nodes: [
        {
          node_id: 'node-db-01',
          changes: {
            label: { from: 'db-dev', to: 'db-prod' },
          },
        },
      ],
      added_edges: [
        {
          id: 'edge-01',
          edge_id: 'edge-01',
          source_node_id: 'node-app-01',
          target_node_id: 'node-db-01',
          edge_type: 'OBSERVED_COMMUNICATION',
          primary_protocol: 'TCP',
          packet_count: 50,
          byte_count: 5000,
          evidence_class: 'DIRECT_OBSERVATION',
        },
      ],
      removed_edges: [],
      modified_edges: [
        {
          edge_id: 'edge-02',
          changes: {
            packet_count: { from: 10, to: 90 },
          },
        },
      ],
      evidence_explanations: [
        {
          type: 'added_relationship',
          edge_id: 'edge-01',
          evidence_class: 'DIRECT_OBSERVATION',
          explanation: 'Newly observed communication (TCP) between node-app-01 and node-db-01 (50 packets)',
          evidence_ids: ['ev-capture-100', 'ev-capture-101'],
        },
        {
          type: 'added_entity',
          node_id: 'node-printer-01',
          explanation: 'Newly discovered ASSET: office-printer.local',
        },
        {
          type: 'unknown_anomaly_marker',
          custom_code: 'ERR_ROUTING_MISCONFIG',
          explanation: 'Asymmetric routing condition identified between subnets',
        },
      ],
    };

    vi.mocked(apiClient.compareSnapshots).mockResolvedValue(complexDiff);

    render(<NetworkTwinView />);

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Snapshot Comparison/i })).toBeInTheDocument();
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
      expect(screen.getByText(/Newly observed communication \(TCP\) between node-app-01/i)).toBeInTheDocument();
      expect(screen.getByText(/Newly discovered ASSET: office-printer\.local/i)).toBeInTheDocument();
      expect(screen.getByText(/Asymmetric routing condition identified/i)).toBeInTheDocument();
    });

    // Expand evidence drawer
    const evidenceDrawerBtn = screen.getByRole('button', { name: /Evidence Records \(2\)/i });
    fireEvent.click(evidenceDrawerBtn);

    expect(screen.getByText('ev-capture-100')).toBeInTheDocument();
    expect(screen.getByText('ev-capture-101')).toBeInTheDocument();

    // Verify modified nodes & edges rendered
    expect(screen.getAllByText('node-db-01').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('db-dev')).toBeInTheDocument();
    expect(screen.getByText('db-prod')).toBeInTheDocument();
  });

  it('displays identical topologies empty state when diff has zero differences', async () => {
    const emptyDiff: SnapshotComparisonDiff = {
      base_snapshot_id: 'snap-same-1',
      target_snapshot_id: 'snap-same-2',
      added_nodes: [],
      removed_nodes: [],
      modified_nodes: [],
      added_edges: [],
      removed_edges: [],
      modified_edges: [],
      evidence_explanations: [],
    };

    vi.mocked(apiClient.compareSnapshots).mockResolvedValue(emptyDiff);

    render(<NetworkTwinView />);

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Snapshot Comparison/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /Snapshot Comparison/i }));

    await waitFor(() => {
      expect(screen.getByText(/Differential Topology Comparison/i)).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /Run Diff/i }));

    await waitFor(() => {
      expect(screen.getByText(/Identical Topologies Detected/i)).toBeInTheDocument();
    });
  });

  it('renders the 3 twin lifecycle navigation groups and confirms duplicated workbenches are removed', async () => {
    render(<NetworkTwinView />);

    await waitFor(() => {
      expect(screen.getByText('INGEST & RECONSTRUCT')).toBeInTheDocument();
      expect(screen.getByText('TOPOLOGY & ASSETS')).toBeInTheDocument();
      expect(screen.getByText('VERIFY & VALIDATE')).toBeInTheDocument();
    });

    // Confirm duplicate workbenches are removed from Twin
    expect(screen.queryByText('Real Captures & Differential')).not.toBeInTheDocument();
    expect(screen.queryByText('Incident Investigations')).not.toBeInTheDocument();
    expect(screen.queryByText('What-If Scenarios')).not.toBeInTheDocument();

    // Switch to INGEST & RECONSTRUCT -> Import & Ingestion
    const importsBtn = screen.getByRole('button', { name: /Import & Ingestion/i });
    fireEvent.click(importsBtn);

    await waitFor(() => {
      expect(screen.getByText(/Import Network Configuration/i)).toBeInTheDocument();
    });
  });

  it('toggles mobile workspace drawer and displays active tool name', async () => {
    render(<NetworkTwinView />);

    await waitFor(() => {
      expect(screen.getByTestId('mobile-active-workspace')).toBeInTheDocument();
    });

    expect(screen.getByTestId('mobile-active-workspace')).toHaveTextContent('Active: Asset Explorer');

    // Toggle button opens the drawer
    const toggleBtn = screen.getByRole('button', { name: /Toggle workspace navigation menu/i });
    fireEvent.click(toggleBtn);
    expect(toggleBtn).toHaveAttribute('aria-expanded', 'true');

    // Clicking it again closes the drawer
    fireEvent.click(toggleBtn);
    expect(toggleBtn).toHaveAttribute('aria-expanded', 'false');
  });

  it('renders Import & Ingestion tab safely with missing sha256_hash and undefined imported_at_iso without slice crash', async () => {
    const rawCaptures = [
      {
        capture_id: 'cap-legacy-raw-01',
        filename: 'legacy_capture.pcap', // note filename and content_sha256 instead of file_name/sha256_hash
        content_sha256: '9876543210abcdef9876543210abcdef',
        file_size_bytes: 2048,
        format: 'pcap',
        // sha256_hash is undefined
      },
    ];

    const rawImports = [
      {
        import_id: 'imp-legacy-01',
        source_name: 'legacy_routes.cfg',
        source_type: 'ROUTING_TABLE',
        items_imported: 3,
        status: 'completed',
        errors: [],
        // imported_at_iso is undefined
      },
    ];

    vi.mocked(apiClient.listCaptures).mockResolvedValue(rawCaptures as unknown as CaptureMetadata[]);
    vi.mocked(apiClient.listImports).mockResolvedValue(rawImports as unknown as ConfigImportResult[]);

    render(<NetworkTwinView />);

    await waitFor(() => {
      expect(screen.getByRole('heading', { level: 1, name: /Network Digital Twin/i })).toBeInTheDocument();
    });

    const importsBtn = screen.getByRole('button', { name: /Import & Ingestion/i });
    fireEvent.click(importsBtn);

    await waitFor(() => {
      expect(screen.getByText('legacy_capture.pcap')).toBeInTheDocument();
      expect(screen.getByText(/SHA: 9876543210ab.../i)).toBeInTheDocument();
      expect(screen.getByText('legacy_routes.cfg')).toBeInTheDocument();
      expect(screen.getByText(/\+3 items/i)).toBeInTheDocument();
    });
  });

  it('submits configuration import with semantic type and auto-detected or selected format', async () => {
    vi.mocked(apiClient.importConfiguration).mockResolvedValue({
      import_id: 'imp-new-123',
      source_name: 'core-router-routes',
      source_type: 'ROUTING_TABLE',
      format: 'routing_table',
      items_imported: 4,
      status: 'completed',
      errors: [],
      created_at_iso: '2026-10-20T12:00:00Z',
    } as unknown as ConfigImportResult);

    render(<NetworkTwinView />);

    await waitFor(() => {
      expect(screen.getByRole('heading', { level: 1, name: /Network Digital Twin/i })).toBeInTheDocument();
    });

    const importsBtn = screen.getByRole('button', { name: /Import & Ingestion/i });
    fireEvent.click(importsBtn);

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Submit & Ingest Configuration/i })).toBeInTheDocument();
    });

    const submitBtn = screen.getByRole('button', { name: /Submit & Ingest Configuration/i });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(apiClient.importConfiguration).toHaveBeenCalledWith(
        expect.objectContaining({
          source_name: 'core-router-routes',
          format: 'routing_table',
        })
      );
      expect(screen.getByText(/Imported 4 items successfully from 'core-router-routes'/i)).toBeInTheDocument();
    });
  });

  it('deletes imported configuration with confirmation and displays success feedback without accidental POST', async () => {
    const rawImports = [
      {
        import_id: 'imp-del-01',
        source_name: 'unwanted_routes.cfg',
        source_type: 'ROUTING_TABLE',
        items_imported: 2,
        status: 'completed',
        errors: [],
        imported_at_iso: '2026-10-20T12:00:00Z',
      },
    ];

    vi.mocked(apiClient.listImports).mockResolvedValue(rawImports as unknown as ConfigImportResult[]);
    vi.mocked(apiClient.deleteConfigImport).mockResolvedValue({ status: 'DELETED', import_id: 'imp-del-01' });
    vi.spyOn(window, 'confirm').mockReturnValue(true);

    render(<NetworkTwinView />);

    await waitFor(() => {
      expect(screen.getByRole('heading', { level: 1, name: /Network Digital Twin/i })).toBeInTheDocument();
    });

    const importsBtn = screen.getByRole('button', { name: /Import & Ingestion/i });
    fireEvent.click(importsBtn);

    await waitFor(() => {
      expect(screen.getByText('unwanted_routes.cfg')).toBeInTheDocument();
    });

    const deleteBtn = screen.getByRole('button', { name: /Delete import unwanted_routes\.cfg/i });
    fireEvent.click(deleteBtn);

    await waitFor(() => {
      expect(window.confirm).toHaveBeenCalled();
      expect(apiClient.deleteConfigImport).toHaveBeenCalledWith('imp-del-01');
      expect(screen.getByText(/Configuration import 'unwanted_routes\.cfg' deleted successfully\./i)).toBeInTheDocument();
    });
  });
});
