/**
 * TypeScript contract interfaces for NetworkEvent schema v1.0.0.
 * Conforms strictly to schemas/v1/network_event.schema.json.
 */

export type ParserStatusType =
  | 'ok'
  | 'incomplete'
  | 'malformed'
  | 'unsupported_protocol'
  | 'checksum_error'
  | 'truncated';

export type FlowDirection = 'forward' | 'reverse' | 'unknown';

export type TransportProtocol =
  | 'TCP'
  | 'UDP'
  | 'ICMP'
  | 'ICMPv6'
  | 'SCTP'
  | 'OTHER';

export type IpVersion = 'IPv4' | 'IPv6';

export interface LinkLayer {
  source_mac?: string | null;
  destination_mac?: string | null;
  ether_type?: number | null;
  vlan_id?: number | null;
}

export interface NetworkLayerFlags {
  df?: boolean;
  mf?: boolean;
}

export interface NetworkLayer {
  version?: IpVersion | null;
  source_ip?: string | null;
  destination_ip?: string | null;
  ttl_or_hop_limit?: number | null;
  identification?: number | null;
  flags?: NetworkLayerFlags | null;
}

export interface TcpFlags {
  syn?: boolean;
  ack?: boolean;
  fin?: boolean;
  rst?: boolean;
  psh?: boolean;
  urg?: boolean;
  ece?: boolean;
  cwr?: boolean;
}

export interface TransportLayer {
  protocol?: TransportProtocol | null;
  source_port?: number | null;
  destination_port?: number | null;
  tcp_sequence_number?: number | null;
  tcp_acknowledgment_number?: number | null;
  tcp_flags?: TcpFlags | null;
  window_size?: number | null;
}

export interface ApplicationLayer {
  protocol?: string | null;
  payload_length_bytes: number;
  protocol_metadata: Record<string, unknown>;
  payload_hash_sha256?: string | null;
  sanitized_preview?: string | null;
}

export interface ParserStatus {
  status: ParserStatusType;
  diagnostic_code?: string | null;
  diagnostic_message?: string | null;
  bytes_consumed?: number | null;
  bytes_remaining?: number | null;
}

export interface Provenance {
  packet_index: number;
  wire_length_bytes: number;
  capture_length_bytes: number;
  capture_interface?: string | null;
  capture_file_path?: string | null;
}

export interface NetworkEvent {
  schema_version: '1.0.0';
  event_id: string;
  timestamp_ns: number;
  timestamp_iso: string;
  source_id: string;
  flow_id?: string | null;
  flow_direction?: FlowDirection | null;
  link_layer?: LinkLayer | null;
  network_layer?: NetworkLayer | null;
  transport_layer?: TransportLayer | null;
  application_layer?: ApplicationLayer | null;
  parser_status: ParserStatus;
  provenance: Provenance;
}
