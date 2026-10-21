use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineReport {
    pub capture_id: String,
    pub analysis_run_id: String,
    pub schema_version: String,
    pub pipeline_version: String,
    pub input_count: u64,
    pub accepted_count: u64,
    pub rejected_count: u64,
    pub unsupported_count: u64,
    pub persisted_count: u64,
    pub duration_ms: f64,
    pub throughput_events_per_sec: f64,
    pub status: String,
    pub error_summary: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quarantine_file: Option<String>,
}
