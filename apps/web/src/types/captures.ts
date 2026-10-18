/**
 * Strongly Typed Contracts for Phase 09: Real-Capture Validation, Differential Testing & End-to-End Evidence.
 */

export type CaptureProvenance =
  | 'PUBLIC_CAPTURE'
  | 'AUTHORIZED_LOCAL'
  | 'SYNTHETIC_FIXTURE';

export type CaptureFormat = 'PCAP' | 'PCAPNG';

export type MetamorphicRelationType =
  | 'FORMAT_EQUIVALENCE'
  | 'TIMESTAMP_SHIFT'
  | 'NOISE_INJECTION'
  | 'PACKET_DUPLICATION'
  | 'PACKET_REORDERING';

export interface CaptureExpectedOutcome {
  total_packets: number;
  total_flows: number;
  dns_queries: number;
  dns_responses: number;
  http_requests: number;
  http_responses: number;
  tls_handshakes: number;
  extracted_sni?: string | null;
  vlan_tags: number[];
  has_fragments: boolean;
  has_retransmissions: boolean;
  has_out_of_order: boolean;
  has_malformed: boolean;
  parser_status: string;
}

export interface CaptureManifestItem {
  capture_id: string;
  name: string;
  format: CaptureFormat;
  provenance: CaptureProvenance;
  source: string;
  license: string;
  attribution: string;
  sha256: string;
  file_name: string;
  file_size_bytes: number;
  packet_count: number;
  protocols: string[];
  scenarios: string[];
  expected_outcomes: CaptureExpectedOutcome;
  known_limitations: string[];
}

export interface ProcessResourceTelemetry {
  wall_duration_ms: number;
  throughput_pps: number;
  throughput_mbps: number;
  peak_native_memory_bytes: number;
  python_heap_bytes: number;
}

export interface FieldComparisonDifference {
  packet_index: number;
  field_name: string;
  cpp_engine_value: unknown;
  reference_decoder_value: unknown;
  match: boolean;
}

export interface CaptureValidationReport {
  validation_id: string;
  capture_id: string;
  timestamp: string;
  passed: boolean;
  total_packets_processed: number;
  total_flows_observed: number;
  protocol_distribution: Record<string, number>;
  parser_status_counts: Record<string, number>;
  telemetry: ProcessResourceTelemetry;
  field_differences: FieldComparisonDifference[];
  explanation: string;
}

export interface DifferentialTestResult {
  test_id: string;
  relation_type: MetamorphicRelationType;
  base_capture_id: string;
  transformed_capture_id?: string | null;
  passed: boolean;
  expected_invariant: string;
  observed_behavior: string;
  execution_time_ms: number;
  details: Record<string, unknown>;
}

export interface CorpusSummaryResponse {
  total_captures: number;
  provenance_distribution: Record<string, number>;
  format_distribution: Record<string, number>;
  supported_protocols: string[];
  total_packet_count: number;
}
