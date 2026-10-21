import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { RealCaptureWorkbench } from '../views/twin/RealCaptureWorkbench';
import { apiClient } from '../api/client';
import type {
  CaptureManifestItem,
  CorpusSummaryResponse,
  CaptureValidationReport,
  DifferentialTestResult,
} from '../types/captures';

vi.mock('../api/client', () => {
  return {
    apiClient: {
      listCorpusCaptures: vi.fn(),
      getCorpusSummary: vi.fn(),
      getCorpusCapture: vi.fn(),
      validateCapture: vi.fn(),
      runDifferentialTest: vi.fn(),
      runE2EValidation: vi.fn(),
    },
  };
});

describe('RealCaptureWorkbench Component', () => {
  const mockCaptures: CaptureManifestItem[] = [
    {
      capture_id: 'real-web-traffic-pcap',
      name: 'Real HTTP, DNS & ARP Session (PCAP)',
      format: 'PCAP',
      provenance: 'PUBLIC_CAPTURE',
      source: 'Wireshark Sample Captures (http.cap, dns.cap)',
      license: 'GPL-2.0',
      attribution: 'Wireshark Foundation Community Sample Traces',
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      file_name: 'real-web-traffic.pcap',
      file_size_bytes: 661,
      packet_count: 9,
      protocols: ['ETHERNET', 'IPv4', 'ARP', 'DNS', 'HTTP', 'TCP', 'UDP'],
      scenarios: ['DNS Query/Response', 'HTTP GET 200 OK', 'ARP Resolution'],
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
      known_limitations: ['Synthetic payloads for test boundaries'],
    },
    {
      capture_id: 'vlan-segmented-pcap',
      name: '802.1Q VLAN Segmented Traffic',
      format: 'PCAP',
      provenance: 'SYNTHETIC_FIXTURE',
      source: 'Internal Synthetic Network Generator',
      license: 'Apache-2.0',
      attribution: 'Protocol Engine Synthetic Test Corpus',
      sha256: 'abc1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd',
      file_name: 'vlan-segmented.pcap',
      file_size_bytes: 132,
      packet_count: 2,
      protocols: ['ETHERNET', 'VLAN', 'IPv4', 'UDP'],
      scenarios: ['VLAN 100 and VLAN 200 Isolation'],
      expected_outcomes: {
        total_packets: 2,
        total_flows: 2,
        dns_queries: 0,
        dns_responses: 0,
        http_requests: 0,
        http_responses: 0,
        tls_handshakes: 0,
        extracted_sni: null,
        vlan_tags: [100, 200],
        has_fragments: false,
        has_retransmissions: false,
        has_out_of_order: false,
        has_malformed: false,
        parser_status: 'SUCCESS',
      },
      known_limitations: ['Single frame per VLAN tag'],
    },
  ];

  const mockSummary: CorpusSummaryResponse = {
    total_captures: 2,
    provenance_distribution: {
      PUBLIC_CAPTURE: 1,
      SYNTHETIC_FIXTURE: 1,
    },
    format_distribution: {
      PCAP: 2,
    },
    supported_protocols: ['ARP', 'DNS', 'ETHERNET', 'HTTP', 'IPv4', 'TCP', 'UDP', 'VLAN'],
    total_packet_count: 11,
  };

  const mockValidationReport: CaptureValidationReport = {
    validation_id: 'val-report-12345',
    capture_id: 'real-web-traffic-pcap',
    timestamp: '2026-10-18T07:00:00Z',
    passed: true,
    total_packets_processed: 9,
    total_flows_observed: 2,
    protocol_distribution: { ETHERNET: 9, IPv4: 8, TCP: 6, HTTP: 2 },
    parser_status_counts: { SUCCESS: 9 },
    telemetry: {
      wall_duration_ms: 12.4,
      throughput_pps: 725.8,
      throughput_mbps: 0.42,
      peak_native_memory_bytes: 15728640,
      python_heap_bytes: 5242880,
    },
    field_differences: [],
    explanation: 'Bit-exact match across all 9 decoded frames between systems engine and reference oracle.',
  };

  const mockDiffResult: DifferentialTestResult = {
    test_id: 'diff-test-9999',
    relation_type: 'FORMAT_EQUIVALENCE',
    base_capture_id: 'real-web-traffic-pcap',
    transformed_capture_id: 'real-web-traffic-pcapng',
    passed: true,
    expected_invariant: 'PCAP and PCAPNG encodings produce identical protocol counts and flow tracks.',
    observed_behavior: 'PCAP: 9 pkts, 2 flows; PCAPNG: 9 pkts, 2 flows. Protocols match: true.',
    execution_time_ms: 18.2,
    details: { pcap_packets: 9, pcapng_packets: 9 },
  };

  const mockE2EResult = {
    validation_id: 'e2e-valid-5555',
    capture_id: 'real-web-traffic-pcap',
    capture_name: 'Real HTTP, DNS & ARP Session (PCAP)',
    provenance: 'PUBLIC_CAPTURE',
    file_sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    execution_time_ms: 45.6,
    engine_status: 'completed',
    packets_processed: 9,
    bytes_processed: 661,
    flows_tracked: 2,
    events_ingested: 9,
    topology_nodes_discovered: 4,
    topology_edges_discovered: 3,
    snapshot_id: 'snap-12345678',
    snapshot_fingerprint: 'snap-12345678',
    predictive_samples: 1,
    all_stages_verified: true,
  };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(apiClient.listCorpusCaptures).mockResolvedValue(mockCaptures);
    vi.mocked(apiClient.getCorpusSummary).mockResolvedValue(mockSummary);
    vi.mocked(apiClient.validateCapture).mockResolvedValue(mockValidationReport);
    vi.mocked(apiClient.runDifferentialTest).mockResolvedValue(mockDiffResult);
    vi.mocked(apiClient.runE2EValidation).mockResolvedValue(mockE2EResult);
  });

  it('renders corpus catalog, aggregate summary badges, and details', async () => {
    render(<RealCaptureWorkbench />);

    expect(screen.getByTestId('real-capture-workbench')).toBeDefined();

    await waitFor(() => {
      expect(screen.getAllByText('Real HTTP, DNS & ARP Session (PCAP)').length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText('802.1Q VLAN Segmented Traffic')).toBeDefined();
    });

    // Check summary counters
    expect(screen.getByText('Total Captures')).toBeDefined();
    expect(screen.getByText('Total Packets')).toBeDefined();
    expect(screen.getByText('11')).toBeDefined(); // total_packet_count
    expect(screen.getByText('8')).toBeDefined(); // supported_protocols.length
  });

  it('executes decoder oracle comparison and renders process telemetry', async () => {
    render(<RealCaptureWorkbench />);

    await waitFor(() => {
      expect(screen.getByText('Run Decoder Oracle')).toBeDefined();
    });

    const runBtn = screen.getByText('Run Decoder Oracle');
    fireEvent.click(runBtn);

    await waitFor(() => {
      expect(apiClient.validateCapture).toHaveBeenCalledWith('real-web-traffic-pcap');
      expect(screen.getByText(/PASSED \(Bit-Exact\)/)).toBeDefined();
      expect(screen.getByText('Isolated Process Resource Telemetry')).toBeDefined();
      expect(screen.getByText('12.4 ms')).toBeDefined();
      expect(screen.getByText('725.8 pps')).toBeDefined();
    });
  });

  it('executes differential metamorphic testing and displays invariant results', async () => {
    render(<RealCaptureWorkbench />);

    await waitFor(() => {
      expect(screen.getByText('MR-FORMAT (PCAP vs PCAPNG)')).toBeDefined();
    });

    const diffBtn = screen.getByText('MR-FORMAT (PCAP vs PCAPNG)');
    fireEvent.click(diffBtn);

    await waitFor(() => {
      expect(apiClient.runDifferentialTest).toHaveBeenCalledWith({
        relation_type: 'FORMAT_EQUIVALENCE',
        base_capture_id: 'real-web-traffic-pcap',
        transformed_capture_id: 'real-web-traffic-pcapng',
        shift_seconds: 60,
      });
      expect(screen.getByText('PCAP: 9 pkts, 2 flows; PCAPNG: 9 pkts, 2 flows. Protocols match: true.')).toBeDefined();
    });
  });

  it('executes end-to-end data path audit and verifies pipeline stages', async () => {
    render(<RealCaptureWorkbench />);

    await waitFor(() => {
      expect(screen.getByText('Run E2E Data Path')).toBeDefined();
    });

    const e2eBtn = screen.getByText('Run E2E Data Path');
    fireEvent.click(e2eBtn);

    await waitFor(() => {
      expect(apiClient.runE2EValidation).toHaveBeenCalledWith('real-web-traffic-pcap');
      expect(screen.getByText('End-to-End Pipeline Audit: All 6 Stages Grounded & Verified')).toBeDefined();
      expect(screen.getByText('45.6 ms total')).toBeDefined();
      expect(screen.getByText('9 events ingested')).toBeDefined();
    });
  });

  it('renders structured protocol stack inspection by layers (L2, L3, L4, L7)', async () => {
    render(<RealCaptureWorkbench />);

    await waitFor(() => {
      expect(screen.getByText('Layered Protocol Stack Inspection & Expected Invariants')).toBeDefined();
      expect(screen.getByText(/Layer 2: Link Layer/)).toBeDefined();
      expect(screen.getByText(/Layer 3: Network Layer/)).toBeDefined();
      expect(screen.getByText(/Layer 4: Transport Layer/)).toBeDefined();
      expect(screen.getByText(/Layer 7: Application Layer/)).toBeDefined();
      expect(screen.getByText(/Ethernet II/)).toBeDefined();
      expect(screen.getByText(/No Fragmentation \(Clean MTU\)/)).toBeDefined();
      expect(screen.getByText('Differential Verification Status: Unvalidated')).toBeDefined();
    });
  });

  it('filters capture corpus manifest based on search query', async () => {
    render(<RealCaptureWorkbench />);

    await waitFor(() => {
      expect(screen.getByPlaceholderText(/Search captures/)).toBeDefined();
    });

    const searchInput = screen.getByPlaceholderText(/Search captures/);
    fireEvent.change(searchInput, { target: { value: 'VLAN' } });

    await waitFor(() => {
      expect(screen.getByTestId('manifest-item-vlan-segmented-pcap')).toBeDefined();
      expect(screen.queryByTestId('manifest-item-real-web-traffic-pcap')).toBeNull();
    });
  });
});
