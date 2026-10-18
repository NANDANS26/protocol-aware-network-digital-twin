/**
 * Network Intelligence, Topology Reconstruction & Evidence Types.
 * Matches backend contracts in schemas/v1 and network_twin.models.intelligence.
 */

export type IdentityStatus = 'CONFIRMED' | 'PROBABLE' | 'AMBIGUOUS' | 'CONFLICTING' | 'UNRESOLVED';

export type EvidenceClass =
  | 'DIRECTLY_OBSERVED'
  | 'DIRECT_OBSERVATION'
  | 'CONFIGURED'
  | 'INFERRED'
  | 'PREDICTED'
  | 'UNKNOWN';

export type EvidenceSourceType =
  | 'PCAP_OBSERVATION'
  | 'DNS_RESOLUTION'
  | 'ARP_RESOLUTION'
  | 'ROUTING_CONFIG'
  | 'INVENTORY_IMPORT';

export type NodeType = 'ASSET' | 'SUBNET' | 'SERVICE' | 'ROUTER' | 'INTERFACE' | 'DNS_RESOLVER';

export type EdgeType =
  | 'OBSERVED_COMMUNICATION'
  | 'SUBNET_ATTACHMENT'
  | 'SERVICE_DEPENDENCY'
  | 'CONFIGURED_ROUTE';

export interface Asset {
  asset_id: string;
  primary_ip?: string;
  mac_addresses: string[];
  ip_addresses: string[];
  hostnames: string[];
  device_class?: string;
  identity_status: IdentityStatus;
  conflicts?: string[];
  conflict_reasons?: string[];
  confidence: number;
  first_seen?: string;
  last_seen?: string;
  first_seen_iso?: string;
  last_seen_iso?: string;
  evidence_ids?: string[];
  metadata?: Record<string, unknown>;
}

export interface NetworkSegment {
  segment_id: string;
  cidr: string;
  ip_version: number;
  gateway_candidates: string[];
  assigned_asset_ids: string[];
  evidence_ids: string[];
  inferred: boolean;
}

export interface NetworkService {
  service_id: string;
  asset_id: string;
  ip_address: string;
  port: number;
  transport_protocol: string;
  application_protocol: string;
  banner_or_alpn?: string;
  first_seen_iso?: string;
  last_seen_iso?: string;
  evidence_ids: string[];
}

export interface CommunicationRelationship {
  relationship_id: string;
  source_asset_id: string;
  destination_asset_id: string;
  source_ip: string;
  destination_ip: string;
  transport_protocol: string;
  destination_port?: number;
  evidence_class: EvidenceClass;
  packet_count: number;
  byte_count: number;
  first_seen_iso?: string;
  last_seen_iso?: string;
  evidence_ids: string[];
}

export interface EvidenceRecord {
  evidence_id: string;
  source_type: EvidenceSourceType;
  source_artifact_id: string;
  packet_number_or_offset?: number;
  flow_key?: string;
  timestamp_iso?: string;
  confidence: number;
  extracted_attributes: Record<string, unknown>;
  notes?: string;
}

export interface TopologyNode {
  id: string;
  node_id?: string;
  label: string;
  node_type: NodeType;
  asset_id?: string;
  segment_id?: string;
  ip_addresses?: string[];
  mac_addresses?: string[];
  subnet_cidr?: string;
  service_port?: number;
  evidence_class?: EvidenceClass;
  properties?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

export interface TopologyEdge {
  id: string;
  edge_id?: string;
  source_node_id: string;
  target_node_id: string;
  edge_type: EdgeType;
  evidence_class?: EvidenceClass;
  primary_protocol?: string;
  protocol?: string;
  port?: number;
  packet_count: number;
  byte_count: number;
  evidence_ids?: string[];
  is_bidirectional?: boolean;
  properties?: Record<string, unknown>;
}

export interface TopologyGraph {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  generated_at_iso?: string;
  node_count: number;
  edge_count: number;
  subnets_count?: number;
  services_count?: number;
}

export interface TopologySnapshot {
  snapshot_id: string;
  name: string;
  created_at?: string;
  created_at_iso?: string;
  hash_fingerprint?: string;
  node_count: number;
  edge_count: number;
  source_captures: string[];
  source_configs: string[];
  graph_summary?: Record<string, unknown>;
}

export interface SnapshotComparisonDiff {
  base_snapshot_id: string;
  target_snapshot_id: string;
  compared_at_iso: string;
  added_nodes: TopologyNode[];
  removed_nodes: TopologyNode[];
  changed_nodes: Array<{
    node_id: string;
    field: string;
    base_value: unknown;
    target_value: unknown;
  }>;
  added_edges: TopologyEdge[];
  removed_edges: TopologyEdge[];
  changed_edges: Array<{
    edge_id: string;
    field: string;
    base_value: unknown;
    target_value: unknown;
  }>;
  evidence_explanations: string[];
}

export interface ConfigImportRequest {
  source_name: string;
  format: 'json' | 'csv';
  content: string;
}

export interface ConfigImportResult {
  import_id: string;
  source_name: string;
  source_type: string;
  imported_at_iso: string;
  items_imported: number;
  status: string;
  errors: string[];
}

export interface CaptureMetadata {
  capture_id: string;
  file_name: string;
  file_size_bytes: number;
  sha256_hash: string;
  packet_count: number;
  link_type: number;
  ingested_at_iso: string;
  format: string;
}

export interface TopTalker {
  src_ip: string;
  dst_ip: string;
  protocol: string;
  packets: number;
  bytes: number;
}

export interface ProtocolBreakdown {
  protocol: string;
  packets: number;
  bytes: number;
}
