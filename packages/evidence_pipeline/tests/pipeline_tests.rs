use evidence_pipeline::schema::NetworkEvent;
use evidence_pipeline::{run_pipeline, PipelineConfig, PIPELINE_VERSION};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use tempfile::NamedTempFile;

#[test]
fn test_valid_event_normalization() {
    let raw_event = r#"{"schema_version":"1.0.0","event_id":"9e3779b9-7c15-4f4a-a7ff-516a8291e5b9","timestamp_ns":1776412800000000000,"timestamp_iso":"2026-04-17T08:00:00.000000000Z","source_id":"sample.pcap","flow_id":null,"flow_direction":null,"link_layer":{"source_mac":"00:11:22:33:44:55","destination_mac":"ff:ff:ff:ff:ff:ff","ether_type":2054,"vlan_id":null},"network_layer":{"version":null,"source_ip":"192.168.1.50","destination_ip":"192.168.1.1","ttl_or_hop_limit":null,"identification":null,"flags":null},"transport_layer":null,"application_layer":null,"parser_status":{"status":"ok","diagnostic_code":null,"diagnostic_message":null,"bytes_consumed":42,"bytes_remaining":0},"provenance":{"packet_index":0,"wire_length_bytes":42,"capture_length_bytes":42,"capture_interface":null,"capture_file_path":"sample.pcap"}}"#;

    let mut in_file = NamedTempFile::new().unwrap();
    writeln!(in_file, "{}", raw_event).unwrap();
    let out_file = NamedTempFile::new().unwrap();
    let quar_file = NamedTempFile::new().unwrap();
    let report_file = NamedTempFile::new().unwrap();

    let config = PipelineConfig {
        input_path: in_file.path().to_str().unwrap().to_string(),
        output_path: out_file.path().to_str().unwrap().to_string(),
        quarantine_path: Some(quar_file.path().to_str().unwrap().to_string()),
        report_path: Some(report_file.path().to_str().unwrap().to_string()),
        capture_id: "cap-test-123".to_string(),
        analysis_run_id: "run-test-456".to_string(),
        schema_version: "1.0.0".to_string(),
    };

    let report = run_pipeline(config).unwrap();
    assert_eq!(report.input_count, 1);
    assert_eq!(report.accepted_count, 1);
    assert_eq!(report.rejected_count, 0);

    let mut reader = BufReader::new(File::open(out_file.path()).unwrap());
    let mut out_line = String::new();
    reader.read_line(&mut out_line).unwrap();

    let normalized: NetworkEvent = serde_json::from_str(&out_line).unwrap();
    assert_eq!(
        normalized.provenance.capture_id,
        Some("cap-test-123".to_string())
    );
    assert_eq!(
        normalized.provenance.analysis_run_id,
        Some("run-test-456".to_string())
    );
    assert_eq!(
        normalized.provenance.pipeline_version,
        Some(PIPELINE_VERSION.to_string())
    );
    // Check MAC normalization to uppercase
    assert_eq!(
        normalized.link_layer.unwrap().destination_mac,
        Some("FF:FF:FF:FF:FF:FF".to_string())
    );
}

#[test]
fn test_malformed_and_invalid_quarantining() {
    let mut in_file = NamedTempFile::new().unwrap();
    // Line 1: Malformed JSON
    writeln!(in_file, "{{malformed json line").unwrap();
    // Line 2: Invalid Schema Version
    writeln!(in_file, r#"{{"schema_version":"0.9.0","event_id":"9e3779b9-7c15-4f4a-a7ff-516a8291e5b9","timestamp_ns":1776412800000000000,"timestamp_iso":"2026-04-17T08:00:00Z","source_id":"test","parser_status":{{"status":"ok"}},"provenance":{{"packet_index":0,"wire_length_bytes":42,"capture_length_bytes":42}}}}"#).unwrap();
    // Line 3: Invalid IP Address
    writeln!(in_file, r#"{{"schema_version":"1.0.0","event_id":"9e3779b9-7c15-4f4a-a7ff-516a8291e5b9","timestamp_ns":1776412800000000000,"timestamp_iso":"2026-04-17T08:00:00Z","source_id":"test","network_layer":{{"source_ip":"999.999.999.999"}},"parser_status":{{"status":"ok"}},"provenance":{{"packet_index":0,"wire_length_bytes":42,"capture_length_bytes":42}}}}"#).unwrap();
    // Line 4: Valid Event
    writeln!(in_file, r#"{{"schema_version":"1.0.0","event_id":"9e3779b9-7c15-4f4a-a7ff-516a8291e5b9","timestamp_ns":1776412800000000000,"timestamp_iso":"2026-04-17T08:00:00Z","source_id":"test","network_layer":{{"source_ip":"10.0.0.1"}},"parser_status":{{"status":"ok"}},"provenance":{{"packet_index":3,"wire_length_bytes":64,"capture_length_bytes":64}}}}"#).unwrap();

    let out_file = NamedTempFile::new().unwrap();
    let quar_file = NamedTempFile::new().unwrap();
    let report_file = NamedTempFile::new().unwrap();

    let config = PipelineConfig {
        input_path: in_file.path().to_str().unwrap().to_string(),
        output_path: out_file.path().to_str().unwrap().to_string(),
        quarantine_path: Some(quar_file.path().to_str().unwrap().to_string()),
        report_path: Some(report_file.path().to_str().unwrap().to_string()),
        capture_id: "cap-err-1".to_string(),
        analysis_run_id: "run-err-1".to_string(),
        schema_version: "1.0.0".to_string(),
    };

    let report = run_pipeline(config).unwrap();
    assert_eq!(report.input_count, 4);
    assert_eq!(report.accepted_count, 1);
    assert_eq!(report.rejected_count, 3);
    assert_eq!(report.status, "PARTIAL");

    // Check quarantine file lines
    let quar_reader = BufReader::new(File::open(quar_file.path()).unwrap());
    let quar_lines: Vec<String> = quar_reader.lines().map(|l| l.unwrap()).collect();
    assert_eq!(quar_lines.len(), 3);
}

#[test]
fn test_deterministic_normalization() {
    let raw_event = r#"{"schema_version":"1.0.0","event_id":"9e3779b9-7c15-4f4a-a7ff-516a8291e5b9","timestamp_ns":1776412800000000000,"timestamp_iso":"2026-04-17T08:00:00Z","source_id":"sample.pcap","network_layer":{"source_ip":"192.168.1.1","destination_ip":"192.168.1.2"},"transport_layer":{"protocol":"tcp","source_port":1234,"destination_port":80},"parser_status":{"status":"ok"},"provenance":{"packet_index":0,"wire_length_bytes":64,"capture_length_bytes":64}}"#;

    let mut in_file = NamedTempFile::new().unwrap();
    writeln!(in_file, "{}", raw_event).unwrap();
    let out_file1 = NamedTempFile::new().unwrap();
    let out_file2 = NamedTempFile::new().unwrap();

    let config1 = PipelineConfig {
        input_path: in_file.path().to_str().unwrap().to_string(),
        output_path: out_file1.path().to_str().unwrap().to_string(),
        quarantine_path: None,
        report_path: None,
        capture_id: "cap-det".to_string(),
        analysis_run_id: "run-det".to_string(),
        schema_version: "1.0.0".to_string(),
    };

    let config2 = PipelineConfig {
        input_path: in_file.path().to_str().unwrap().to_string(),
        output_path: out_file2.path().to_str().unwrap().to_string(),
        quarantine_path: None,
        report_path: None,
        capture_id: "cap-det".to_string(),
        analysis_run_id: "run-det".to_string(),
        schema_version: "1.0.0".to_string(),
    };

    run_pipeline(config1).unwrap();
    run_pipeline(config2).unwrap();

    let content1 = std::fs::read_to_string(out_file1.path()).unwrap();
    let content2 = std::fs::read_to_string(out_file2.path()).unwrap();
    assert_eq!(content1, content2);
}
