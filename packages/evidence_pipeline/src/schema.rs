use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LinkLayer {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ether_type: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vlan_id: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkLayerFlags {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub df: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mf: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkLayer {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_or_hop_limit: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identification: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<NetworkLayerFlags>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TcpFlags {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub syn: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ack: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fin: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rst: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub psh: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub urg: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ece: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwr: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransportLayer {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_sequence_number: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_acknowledgment_number: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_flags: Option<TcpFlags>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window_size: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApplicationLayer {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default)]
    pub payload_length_bytes: usize,
    #[serde(default)]
    pub protocol_metadata: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_hash_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sanitized_preview: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParserStatus {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostic_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostic_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_consumed: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_remaining: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Provenance {
    pub packet_index: u64,
    pub wire_length_bytes: u64,
    pub capture_length_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture_interface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture_file_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis_run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pipeline_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetworkEvent {
    pub schema_version: String,
    pub event_id: String,
    pub timestamp_ns: u64,
    pub timestamp_iso: String,
    pub source_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_direction: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link_layer: Option<LinkLayer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_layer: Option<NetworkLayer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport_layer: Option<TransportLayer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_layer: Option<ApplicationLayer>,
    pub parser_status: ParserStatus,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantinedRecord {
    pub raw_line: String,
    pub line_number: u64,
    pub error_code: String,
    pub error_message: String,
    pub capture_id: Option<String>,
    pub analysis_run_id: Option<String>,
    pub timestamp_utc: String,
}
