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
  is_multicast?: boolean;
  is_l2_only?: boolean;
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

export interface SkippedOrRejectedRecord {
  item_id: string;
  item_type: 'ASSET' | 'SUBNET' | 'ROUTE' | 'NEIGHBOR' | 'FLOW' | 'SERVICE' | string;
  action: 'SKIPPED' | 'REJECTED';
  reason: string;
}

export interface ConsumptionAudit {
  consumed_assets_count: number;
  consumed_subnets_count: number;
  consumed_services_count: number;
  consumed_edges_count: number;
  consumed_subnets?: string[];
  source_captures?: string[];
  source_configs?: string[];
  skipped_or_rejected: SkippedOrRejectedRecord[];
}

export interface EvidenceCoverageSummary {
  directly_observed_pct: number;
  inferred_pct: number;
  configured_pct: number;
  total_elements: number;
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
  capture_id?: string | null;
  analysis_job_id?: string | null;
  graph_summary?: Record<string, unknown>;
  metadata?: {
    generator?: string;
    timestamp?: string;
    source_type?: string;
    capture_id?: string | null;
    capture_filename?: string | null;
    analysis_job_id?: string | null;
    derivation_method?: string;
    confidence?: number;
    node_count?: number;
    edge_count?: number;
    consumption_audit?: ConsumptionAudit;
    evidence_coverage?: EvidenceCoverageSummary;
    limitations?: string[];
    derived_model_id?: string;
    derived_model_fingerprint?: string;
    [key: string]: any;
  };
}

export interface DiffExplanationItem {
  type?: string;
  node_id?: string;
  edge_id?: string;
  evidence_class?: string;
  explanation?: string;
  evidence_ids?: string[];
  [key: string]: unknown;
}

export interface NodeDiffRecord {
  node_id: string;
  changes?: Record<string, { from?: unknown; to?: unknown }>;
  explanation?: string;
  type?: string;
  [key: string]: unknown;
}

export interface EdgeDiffRecord {
  edge_id: string;
  changes?: Record<string, { from?: unknown; to?: unknown }>;
  explanation?: string;
  evidence_class?: string;
  evidence_ids?: string[];
  type?: string;
  [key: string]: unknown;
}

export interface SnapshotComparisonDiff {
  base_snapshot_id: string;
  target_snapshot_id: string;
  compared_at_iso?: string;
  added_nodes: TopologyNode[];
  removed_nodes: TopologyNode[];
  modified_nodes?: NodeDiffRecord[];
  changed_nodes?: Array<{
    node_id: string;
    field?: string;
    base_value?: unknown;
    target_value?: unknown;
    changes?: Record<string, { from?: unknown; to?: unknown }>;
  }>;
  added_edges: TopologyEdge[];
  removed_edges: TopologyEdge[];
  modified_edges?: EdgeDiffRecord[];
  changed_edges?: Array<{
    edge_id: string;
    field?: string;
    base_value?: unknown;
    target_value?: unknown;
    changes?: Record<string, { from?: unknown; to?: unknown }>;
  }>;
  evidence_explanations: Array<DiffExplanationItem | string>;
}

export interface ConfigImportRequest {
  source_name: string;
  format: 'routing_table' | 'neighbor_table' | 'inventory' | 'json' | 'csv' | string;
  content: string;
}

export interface ConfigImportResult {
  import_id: string;
  source_name: string;
  source_type: string;
  format?: string;
  imported_at_iso?: string;
  created_at?: string;
  items_imported: number;
  status: string;
  errors: string[];
}

export interface CaptureMetadata {
  capture_id: string;
  file_name: string;
  filename?: string;
  file_size_bytes: number;
  sha256_hash: string;
  content_sha256?: string;
  packet_count: number;
  event_count?: number;
  accepted_count?: number;
  rejected_count?: number;
  unsupported_count?: number;
  link_type?: number;
  ingested_at_iso?: string;
  uploaded_at?: string;
  format: string;
  lifecycle_status?: string;
  active_analysis_run_id?: string;
  engine_version?: string;
  pipeline_version?: string;
  schema_version?: string;
}

export interface ActiveCaptureContext {
  capture_id: string;
  filename: string;
  content_sha256?: string;
  lifecycle_status: string;
  active_analysis_run_id?: string | null;
  latest_run?: Record<string, unknown> | null;
  packet_count: number;
  event_count: number;
  accepted_count: number;
  rejected_count: number;
  unsupported_count: number;
  engine_version: string;
  pipeline_version: string;
  schema_version: string;
  latest_snapshot_id?: string | null;
  snapshots_count: number;
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
