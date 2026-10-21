import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { ProtocolResearchLabView } from '../views/ProtocolResearchLabView';
import { apiClient } from '../api/client';

vi.mock('../api/client', () => {
  return {
    apiClient: {
      listCorpusCaptures: vi.fn(),
      getCorpusSummary: vi.fn(),
      getCorpusCapture: vi.fn(),
      validateCapture: vi.fn(),
      runDifferentialTest: vi.fn(),
      runE2EValidation: vi.fn(),
      listBenchmarkFixtures: vi.fn(),
      runBenchmark: vi.fn(),
      listBenchmarkRuns: vi.fn(),
      getBenchmarkRun: vi.fn(),
      getBenchmarkSummary: vi.fn(),
      listTestingCampaigns: vi.fn(),
      listTestingCases: vi.fn(),
      listTestingFindings: vi.fn(),
      listRegressionFixtures: vi.fn(),
    },
  };
});

describe('ProtocolResearchLabView Component', () => {
  const mockCaptures = [
    {
      capture_id: 'real-web-traffic-pcap',
      name: 'Real HTTP, DNS & ARP Session (PCAP)',
      format: 'PCAP' as const,
      provenance: 'PUBLIC_CAPTURE' as const,
      source: 'Wireshark Sample Captures',
      license: 'GPL-2.0',
      attribution: 'Wireshark Foundation Community',
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      file_name: 'real-web-traffic.pcap',
      file_size_bytes: 661,
      packet_count: 9,
      protocols: ['ETHERNET', 'IPv4', 'ARP', 'DNS', 'HTTP', 'TCP'],
      scenarios: ['DNS Resolution', 'HTTP GET'],
      expected_outcomes: {
        total_packets: 9,
        total_flows: 2,
        dns_queries: 1,
        dns_responses: 1,
        http_requests: 1,
        http_responses: 1,
        tls_handshakes: 0,
        extracted_sni: null,
        vlan_tags: [],
        has_fragments: false,
        has_retransmissions: false,
        has_out_of_order: false,
        has_malformed: false,
        parser_status: 'SUCCESS',
      },
      known_limitations: ['Synthetic payloads'],
    },
  ];

  const mockCorpusSummary = {
    total_captures: 1,
    provenance_distribution: { PUBLIC_CAPTURE: 1 },
    format_distribution: { PCAP: 1 },
    supported_protocols: ['DNS', 'ETHERNET', 'HTTP', 'IPv4', 'TCP'],
    total_packet_count: 9,
  };

  const mockFixtures = [
    {
      fixture_id: 'handshake-core',
      name: 'TCP Handshake Core Baseline',
      category: 'CORE' as const,
      provenance: 'SYNTHETIC_FIXTURE' as const,
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
  ];

  const mockBenchmarkSummary = {
    total_runs: 1,
    verified_fixtures: 1,
    average_throughput_pps: 25000,
    average_pipeline_latency_ms: 45.2,
    deterministic_accuracy_pct: 100,
    models_beating_baseline_pct: 100,
    peak_memory_mb: 85.5,
    recent_runs: [],
  };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(apiClient.listCorpusCaptures).mockResolvedValue(mockCaptures);
    vi.mocked(apiClient.getCorpusSummary).mockResolvedValue(mockCorpusSummary);
    vi.mocked(apiClient.listBenchmarkFixtures).mockResolvedValue(mockFixtures);
    vi.mocked(apiClient.listBenchmarkRuns).mockResolvedValue([]);
    vi.mocked(apiClient.getBenchmarkSummary).mockResolvedValue(mockBenchmarkSummary);
    vi.mocked(apiClient.listTestingCampaigns).mockResolvedValue([]);
    vi.mocked(apiClient.listTestingCases).mockResolvedValue([]);
    vi.mocked(apiClient.listTestingFindings).mockResolvedValue([]);
    vi.mocked(apiClient.listRegressionFixtures).mockResolvedValue([]);
  });

  it('renders workstation header, operational badges, and primary navigation tabs', async () => {
    render(<ProtocolResearchLabView />);

    expect(screen.getByTestId('protocol-research-lab')).toBeDefined();
    expect(screen.getByText('Protocol Research Lab')).toBeDefined();
    expect(screen.getByText('C++ Systems Engine')).toBeDefined();
    expect(screen.getByText('Python Reference Oracle')).toBeDefined();

    expect(screen.getByTestId('tab-captures')).toBeDefined();
    expect(screen.getByTestId('tab-benchmarks')).toBeDefined();
    expect(screen.getByTestId('tab-fuzzing')).toBeDefined();
  });

  it('switches seamlessly to Validation Benchmarks & Profiling tab', async () => {
    render(<ProtocolResearchLabView />);

    const benchmarksTab = screen.getByTestId('tab-benchmarks');
    fireEvent.click(benchmarksTab);

    await waitFor(() => {
      expect(screen.getByTestId('benchmark-workbench')).toBeDefined();
      expect(screen.getByText('Reproducible Validation & Benchmarking')).toBeDefined();
    });
  });

  it('switches to Protocol Security Fuzzing & Mutation tab', async () => {
    render(<ProtocolResearchLabView />);

    const fuzzingTab = screen.getByTestId('tab-fuzzing');
    fireEvent.click(fuzzingTab);

    await waitFor(() => {
      expect(screen.getByTestId('security-testing-workbench')).toBeDefined();
    });
  });
});
