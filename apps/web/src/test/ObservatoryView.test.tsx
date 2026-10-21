import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { ObservatoryView } from '../views/ObservatoryView';
import { apiClient } from '../api/client';
import type { AnalysisJob } from '../types/analysis';

vi.mock('../api/client', () => ({
  apiClient: {
    uploadCapture: vi.fn(),
    runDemoAnalysis: vi.fn(),
    getJob: vi.fn(),
    getJobEvents: vi.fn(),
    getJobFlows: vi.fn(),
  },
}));

const mockJob: AnalysisJob = {
  job_id: 'test-job-1234',
  filename: 'sample_capture.pcap',
  file_size_bytes: 1170,
  status: 'completed',
  created_at: '2026-04-17T08:00:00Z',
  completed_at: '2026-04-17T08:00:01Z',
  error_message: null,
  summary: {
    capture_file: 'sample_capture.pcap',
    total_packets: 15,
    total_bytes: 1170,
    wire_bytes: 1170,
    duration_ms: 2.5,
    start_time_iso: '2026-04-17T08:00:00.000Z',
    end_time_iso: '2026-04-17T08:00:00.033Z',
    packets_per_sec: 6000,
    throughput_mbps: 3.74,
    total_flows: 4,
    dns_queries: 1,
    dns_responses: 1,
    http_requests: 1,
    http_responses: 1,
    tls_handshakes: 1,
    quic_datagrams: 0,
    protocol_counts: {
      Ethernet: 15,
      IPv4: 13,
      TCP: 9,
      UDP: 2,
      ICMP: 2,
      DNS: 2,
      HTTP: 2,
      TLS: 1,
    },
    parser_status_counts: {
      ok: 15,
    },
    tcp_state_counts: {
      ESTABLISHED: 2,
    },
    anomalies: [],
    flows: [
      {
        flow_id: 'flow-http-1',
        ip_proto: 'TCP',
        src_ip: '192.168.1.50',
        src_port: 49152,
        dst_ip: '192.168.1.100',
        dst_port: 80,
        vlan_id: null,
        state: 'ESTABLISHED',
        packets_forward: 3,
        packets_reverse: 2,
        bytes_forward: 350,
        bytes_reverse: 280,
        duration_ms: 4.0,
        app_protocol: 'HTTP',
        info: 'Host: api.twin.internal',
        retransmissions: 0,
        out_of_order: 0,
      },
      {
        flow_id: 'flow-dns-1',
        ip_proto: 'UDP',
        src_ip: '192.168.1.50',
        src_port: 53535,
        dst_ip: '192.168.1.1',
        dst_port: 53,
        vlan_id: null,
        state: 'STATELESS',
        packets_forward: 1,
        packets_reverse: 1,
        bytes_forward: 65,
        bytes_reverse: 81,
        duration_ms: 2.0,
        app_protocol: 'DNS',
        info: 'api.twin.internal',
        retransmissions: 0,
        out_of_order: 0,
      },
    ],
  },
};

describe('ObservatoryView Component', () => {
  it('renders initial state with upload controls and demo buttons', () => {
    render(<ObservatoryView />);

    expect(screen.getByText(/Network Observatory/i)).toBeInTheDocument();
    expect(screen.getByText(/Upload PCAP \/ PCAPNG/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^Load Sample PCAP$/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Load Sample PCAPNG/i })).toBeInTheDocument();
    expect(screen.getByText(/No capture loaded yet/i)).toBeInTheDocument();
  });

  it('runs sample PCAP analysis and renders telemetry dashboard and flow table', async () => {
    vi.mocked(apiClient.runDemoAnalysis).mockResolvedValue({
      job_id: 'test-job-1234',
      filename: 'sample_capture.pcap',
      file_size_bytes: 1170,
      status: 'completed',
      message: 'Analyzed',
      summary: mockJob.summary,
    });
    vi.mocked(apiClient.getJob).mockResolvedValue(mockJob);

    render(<ObservatoryView />);

    const sampleBtn = screen.getByRole('button', { name: /^Load Sample PCAP$/i });
    fireEvent.click(sampleBtn);

    await waitFor(() => {
      expect(screen.getAllByText('15').length).toBeGreaterThan(0);
      expect(screen.getAllByText('4').length).toBeGreaterThan(0);
      expect(screen.getByText('flow-http-1')).toBeInTheDocument();
      expect(screen.getByText('flow-dns-1')).toBeInTheDocument();
      expect(screen.getByText('192.168.1.50:49152')).toBeInTheDocument();
      expect(screen.getByText('Host: api.twin.internal')).toBeInTheDocument();
    });

    // Test protocol filtering
    const select = screen.getByRole('combobox');
    fireEvent.change(select, { target: { value: 'UDP' } });

    await waitFor(() => {
      expect(screen.queryByText('flow-http-1')).not.toBeInTheDocument();
      expect(screen.getByText('flow-dns-1')).toBeInTheDocument();
    });
  });

  it('correctly displays PTP capture telemetry with 0 DNS and accurate parser integrity', async () => {
    const mockPtpJob: AnalysisJob = {
      job_id: 'test-ptp-job',
      filename: 'IEEE1588_Precision Time Protocol-PTPv2-Sequence.pcap',
      file_size_bytes: 3312,
      status: 'completed',
      created_at: '2026-04-19T08:00:00Z',
      completed_at: '2026-04-19T08:00:01Z',
      error_message: null,
      summary: {
        capture_file: 'IEEE1588_Precision Time Protocol-PTPv2-Sequence.pcap',
        total_packets: 39,
        total_bytes: 3312,
        wire_bytes: 3312,
        duration_ms: 0.95,
        start_time_iso: '2007-08-08T09:18:39.342Z',
        end_time_iso: '2007-08-08T09:18:59.817Z',
        packets_per_sec: 40000,
        throughput_mbps: 27.6,
        total_flows: 3,
        dns_queries: 0,
        dns_responses: 0,
        http_requests: 0,
        http_responses: 0,
        tls_handshakes: 0,
        quic_datagrams: 0,
        ptp_messages: 39,
        protocol_counts: {
          Ethernet: 39,
          IPv4: 25,
          UDP: 25,
          PTP: 39,
        },
        parser_status_counts: {
          ok: 39,
        },
        tcp_state_counts: {},
        anomalies: [],
        flows: [
          {
            flow_id: 'flow-ptp-1',
            ip_proto: 'UDP',
            src_ip: '192.168.2.6',
            src_port: 319,
            dst_ip: '224.0.0.107',
            dst_port: 319,
            vlan_id: null,
            state: 'STATELESS',
            packets_forward: 16,
            packets_reverse: 0,
            bytes_forward: 1536,
            bytes_reverse: 0,
            duration_ms: 12891.4,
            app_protocol: 'PTP',
            info: 'Pdelay_Req (seq 40535)',
            retransmissions: 0,
            out_of_order: 0,
          },
        ],
      },
    };

    vi.mocked(apiClient.runDemoAnalysis).mockResolvedValue({
      job_id: 'test-ptp-job',
      filename: 'IEEE1588_Precision Time Protocol-PTPv2-Sequence.pcap',
      file_size_bytes: 3312,
      status: 'completed',
      message: 'Analyzed',
      summary: mockPtpJob.summary,
    });
    vi.mocked(apiClient.getJob).mockResolvedValue(mockPtpJob);

    render(<ObservatoryView />);
    const sampleBtn = screen.getByRole('button', { name: /^Load Sample PCAP$/i });
    fireEvent.click(sampleBtn);

    await waitFor(() => {
      // Packets and bytes match
      expect(screen.getAllByText('39').length).toBeGreaterThanOrEqual(2);
      expect(screen.getByText(/3,312 bytes/i)).toBeInTheDocument();

      // App transactions displays 39 PTP transactions, NOT 25 DNS
      expect(screen.getByText(/39 PTP/i)).toBeInTheDocument();
      expect(screen.queryByText(/25 DNS/i)).not.toBeInTheDocument();

      // Parser integrity reports ok count and percentage
      expect(screen.getByText(/\/ 39/)).toBeInTheDocument();
      expect(screen.getByText(/100.0% decoded ok · 0 errors/i)).toBeInTheDocument();

      // Flow displays PTP app protocol and info
      expect(screen.getByText('flow-ptp-1')).toBeInTheDocument();
      expect(screen.getAllByText('PTP').length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText('Pdelay_Req (seq 40535)')).toBeInTheDocument();
    });
  });
});
