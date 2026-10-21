use evidence_pipeline::{run_pipeline, PipelineConfig};
use std::path::PathBuf;
use std::process::Command;
use tempfile::NamedTempFile;

#[test]
fn test_cpp_engine_output_to_rust_pipeline() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir.parent().unwrap().parent().unwrap();
    let engine_exe = repo_root
        .join("build")
        .join("engine")
        .join("Release")
        .join("protocol_engine.exe");

    if !engine_exe.exists() {
        eprintln!(
            "protocol_engine.exe not found at {:?}, skipping integration test",
            engine_exe
        );
        return;
    }

    let pcap_path = repo_root
        .join("tests")
        .join("fixtures")
        .join("sample_capture.pcap");
    assert!(pcap_path.exists(), "Sample pcap file must exist");

    let raw_events = NamedTempFile::new().unwrap();
    let summary_file = NamedTempFile::new().unwrap();

    // 1. Run C++ engine to produce raw JSONL events
    let cpp_status = Command::new(&engine_exe)
        .arg("--pcap")
        .arg(&pcap_path)
        .arg("--out")
        .arg(raw_events.path())
        .arg("--summary")
        .arg(summary_file.path())
        .status()
        .expect("Failed to execute C++ engine");

    assert!(cpp_status.success(), "C++ engine must succeed");

    // 2. Run Rust evidence pipeline to normalize and validate
    let canonical_events = NamedTempFile::new().unwrap();
    let quarantine = NamedTempFile::new().unwrap();
    let report_file = NamedTempFile::new().unwrap();

    let config = PipelineConfig {
        input_path: raw_events.path().to_str().unwrap().to_string(),
        output_path: canonical_events.path().to_str().unwrap().to_string(),
        quarantine_path: Some(quarantine.path().to_str().unwrap().to_string()),
        report_path: Some(report_file.path().to_str().unwrap().to_string()),
        capture_id: "cap-e2e-cpp-rust".to_string(),
        analysis_run_id: "run-e2e-cpp-rust".to_string(),
        schema_version: "1.0.0".to_string(),
    };

    let report = run_pipeline(config).expect("Rust pipeline must succeed on real C++ output");
    assert_eq!(report.input_count, 15, "sample_capture.pcap has 15 packets");
    assert_eq!(report.accepted_count, 15, "All 15 events must be accepted");
    assert_eq!(report.rejected_count, 0, "Zero events rejected");
    assert_eq!(report.status, "COMPLETED");
}
