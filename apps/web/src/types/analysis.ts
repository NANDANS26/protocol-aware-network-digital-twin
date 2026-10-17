import type { NetworkEvent } from '@contracts/network_event';

export interface FlowSummary {
  flow_id: string;
  ip_proto: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  vlan_id: number | null;
  state: string;
  packets_forward: number;
  packets_reverse: number;
  bytes_forward: number;
  bytes_reverse: number;
  duration_ms: number;
  app_protocol: string;
  info: string;
  retransmissions: number;
  out_of_order: number;
}

export interface AnalysisSummary {
  capture_file: string;
  total_packets: number;
  total_bytes: number;
  wire_bytes: number;
  duration_ms: number;
  start_time_iso: string;
  end_time_iso: string;
  packets_per_sec: number;
  throughput_mbps: number;
  total_flows: number;
  dns_queries: number;
  dns_responses: number;
  http_requests: number;
  http_responses: number;
  tls_handshakes: number;
  quic_datagrams: number;
  protocol_counts: Record<string, number>;
  parser_status_counts: Record<string, number>;
  tcp_state_counts: Record<string, number>;
  anomalies: string[];
  flows: FlowSummary[];
}

export interface AnalysisJob {
  job_id: string;
  filename: string;
  file_size_bytes: number;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  created_at: string;
  completed_at: string | null;
  error_message: string | null;
  summary: AnalysisSummary | null;
}

export interface JobUploadResponse {
  job_id: string;
  filename: string;
  file_size_bytes: number;
  status: string;
  message: string;
  summary: AnalysisSummary | null;
}

export interface FlowListResponse {
  job_id: string;
  total_flows: number;
  offset: number;
  limit: number;
  flows: FlowSummary[];
}

export interface EventListResponse {
  job_id: string;
  total_events: number;
  offset: number;
  limit: number;
  events: NetworkEvent[];
}
