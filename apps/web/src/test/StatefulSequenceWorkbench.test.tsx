import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { StatefulSequenceWorkbench } from '../views/twin/StatefulSequenceWorkbench';
import { apiClient } from '../api/client';
import type {
  ProtocolSequence,
  SequenceExecutionResult,
  SequenceFinding,
  SequenceRegressionFixture,
  CoverageGapsResponse,
} from '../types/sequences';

vi.mock('../api/client', () => {
  return {
    apiClient: {
      listProtocolSequences: vi.fn(),
      getProtocolSequence: vi.fn(),
      generateSequenceSuite: vi.fn(),
      runProtocolSequence: vi.fn(),
      mutateProtocolSequence: vi.fn(),
      runSequenceDifferential: vi.fn(),
      listSequenceFindings: vi.fn(),
      minimizeSequenceFinding: vi.fn(),
      promoteSequenceRegression: vi.fn(),
      listSequenceRegressions: vi.fn(),
      getCoverageGaps: vi.fn(),
      exportSequenceBundle: vi.fn(),
    },
  };
});

describe('StatefulSequenceWorkbench Component', () => {
  const mockSequence: ProtocolSequence = {
    sequence_id: 'seq-tcp-handshake-42',
    name: 'Standard TCP 3-Way Handshake & FIN Teardown',
    description: 'RFC 793 / RFC 9293 connection lifecycle test',
    sequence_type: 'TCP_HANDSHAKE_TEARDOWN',
    seed: 42,
    generator_version: '1.0.0',
    steps: [
      {
        step_index: 0,
        timestamp_offset_ns: 0,
        source_ip: '192.168.1.100',
        destination_ip: '192.168.1.200',
        protocol: 'TCP',
        source_port: 49152,
        destination_port: 80,
        tcp_seq: 1000,
        tcp_ack: 0,
        tcp_flags: { syn: true, ack: false, fin: false, rst: false, psh: false, urg: false },
        label: 'Client SYN packet',
      },
      {
        step_index: 1,
        timestamp_offset_ns: 10_000_000,
        source_ip: '192.168.1.200',
        destination_ip: '192.168.1.100',
        protocol: 'TCP',
        source_port: 80,
        destination_port: 49152,
        tcp_seq: 5000,
        tcp_ack: 1001,
        tcp_flags: { syn: true, ack: true, fin: false, rst: false, psh: false, urg: false },
        label: 'Server SYN-ACK packet',
      },
      {
        step_index: 2,
        timestamp_offset_ns: 20_000_000,
        source_ip: '192.168.1.100',
        destination_ip: '192.168.1.200',
        protocol: 'TCP',
        source_port: 49152,
        destination_port: 80,
        tcp_seq: 1001,
        tcp_ack: 5001,
        tcp_flags: { syn: false, ack: true, fin: false, rst: false, psh: false, urg: false },
        label: 'Client ACK completing handshake',
      },
    ],
    expected_transitions: [
      {
        step_index: 2,
        flow_id: '192.168.1.100:49152-192.168.1.200:80-TCP',
        expected_state: 'ESTABLISHED',
        rationale: 'Three-way handshake completed',
      },
    ],
    expected_flow_count: 1,
    expected_properties: { zero_retransmissions: true },
    mutations: [],
    format: 'pcap',
    is_supported: true,
    created_at_iso: '2026-10-17T12:00:00Z',
  };

  const mockExecResult: SequenceExecutionResult = {
    execution_id: 'exec-seq-001',
    sequence_id: 'seq-tcp-handshake-42',
    exit_code: 0,
    duration_ms: 12.5,
    total_events_emitted: 3,
    total_flows_detected: 1,
    crash_detected: false,
    hang_timeout: false,
    schema_valid: true,
    state_transitions_verified: true,
    flow_isolation_verified: true,
    step_observations: [],
    diagnostic: null,
    executed_at_iso: '2026-10-17T12:00:01Z',
  };

  const mockFinding: SequenceFinding = {
    finding_id: 'find-seq-001',
    sequence_id: 'seq-tcp-handshake-42',
    severity: 'HIGH',
    category: 'FLOW_LEAKAGE',
    title: 'Flow Isolation Collision Detected',
    description: 'Engine merged distinct 5-tuples during concurrent flow test',
    root_cause_summary: 'Flow key collision in hash map',
    reproduction_command: 'protocol_engine.exe --input trace.pcap',
    fixture_path: 'fixtures/seq_001.pcap',
    fixture_hash: 'abc123hash',
    minimized: false,
    is_regression: false,
    created_at_iso: '2026-10-17T12:00:02Z',
  };

  const mockRegression: SequenceRegressionFixture = {
    regression_id: 'regr-seq-001',
    finding_id: 'find-seq-001',
    name: 'Concurrent Flow Isolation Invariant',
    sequence_type: 'TCP_SIMULTANEOUS_FLOWS',
    fixture_path: 'regressions/seq_001.pcap',
    fixture_hash: 'abc123hash',
    expected_exit_code: 0,
    expected_to_pass: true,
    created_at_iso: '2026-10-17T12:00:03Z',
    last_run_passed: true,
  };

  const mockCoverageGaps: CoverageGapsResponse = {
    engine_version: '0.1.0',
    supported_capabilities: [
      'TCP Handshake & Teardown State Tracking',
      'TCP Retransmission & Gap Sequence Detection',
      'Cross-Flow State Isolation',
    ],
    documented_coverage_gaps: [
      {
        feature: 'L4 IPv4/IPv6 Datagram Reassembly Cache',
        description: 'Analyzer decodes IP packets individually without holding non-initial fragments in an IP reassembly buffer.',
        behavior: 'Non-initial fragments parsed as raw payload',
        limitation_status: 'Documented Coverage Gap (Phase 05 Boundary)',
      },
    ],
  };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(apiClient.listProtocolSequences).mockResolvedValue([mockSequence]);
    vi.mocked(apiClient.listSequenceFindings).mockResolvedValue([mockFinding]);
    vi.mocked(apiClient.listSequenceRegressions).mockResolvedValue([mockRegression]);
    vi.mocked(apiClient.getCoverageGaps).mockResolvedValue(mockCoverageGaps);
    vi.mocked(apiClient.runProtocolSequence).mockResolvedValue({
      execution: mockExecResult,
      findings: [],
    });
  });

  it('renders stateful sequence workbench banner and metrics', async () => {
    render(<StatefulSequenceWorkbench />);

    expect(screen.getByText(/Stateful Protocol Fuzzing & Multi-Packet Sequence Verification/i)).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getAllByText('Standard TCP 3-Way Handshake & FIN Teardown').length).toBeGreaterThan(0);
    });
    expect(screen.getByText('Stored Sequences')).toBeInTheDocument();
    expect(screen.getByText('Sequence Findings')).toBeInTheDocument();
  });

  it('displays sequence steps ladder and expected state transitions', async () => {
    render(<StatefulSequenceWorkbench />);

    await waitFor(() => {
      expect(screen.getByText(/Client SYN packet/i)).toBeInTheDocument();
      expect(screen.getByText(/Server SYN-ACK packet/i)).toBeInTheDocument();
      expect(screen.getByText(/Client ACK completing handshake/i)).toBeInTheDocument();
    });

    expect(screen.getByText('ESTABLISHED')).toBeInTheDocument();
    expect(screen.getByText('Three-way handshake completed')).toBeInTheDocument();
  });

  it('executes protocol sequence and renders outcome badge', async () => {
    render(<StatefulSequenceWorkbench />);

    await waitFor(() => {
      expect(screen.getByText('Execute Sequence')).toBeInTheDocument();
    });

    const runBtn = screen.getByText('Execute Sequence');
    fireEvent.click(runBtn);

    await waitFor(() => {
      expect(apiClient.runProtocolSequence).toHaveBeenCalledWith('seq-tcp-handshake-42');
      expect(screen.getByText(/Execution Outcome: Exit Code 0/i)).toBeInTheDocument();
      expect(screen.getByText('Schema Valid (Draft 2020-12)')).toBeInTheDocument();
      expect(screen.getByText('Flow Isolation Verified')).toBeInTheDocument();
    });
  });

  it('opens and closes coverage gaps and limitations modal', async () => {
    render(<StatefulSequenceWorkbench />);

    const gapsBtn = screen.getByText('Coverage Gaps & Limits');
    fireEvent.click(gapsBtn);

    await waitFor(() => {
      expect(screen.getByText(/Engine Coverage Boundaries & Documented Limitations/i)).toBeInTheDocument();
      expect(screen.getByText(/L4 IPv4\/IPv6 Datagram Reassembly Cache/i)).toBeInTheDocument();
      expect(screen.getByText(/Documented Coverage Gap/i)).toBeInTheDocument();
    });

    const closeBtn = screen.getByText('Close');
    fireEvent.click(closeBtn);

    await waitFor(() => {
      expect(screen.queryByText(/Engine Coverage Boundaries & Documented Limitations/i)).not.toBeInTheDocument();
    });
  });
});
