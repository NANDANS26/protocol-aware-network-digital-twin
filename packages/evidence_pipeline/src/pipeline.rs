use crate::normalizer::normalize_event;
use crate::report::PipelineReport;
use crate::schema::{NetworkEvent, QuarantinedRecord};
use crate::validator::validate_event;
use chrono::Utc;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::time::Instant;

pub const PIPELINE_VERSION: &str = "1.0.0";

#[derive(Debug, Clone)]
pub struct PipelineConfig {
    pub input_path: String,
    pub output_path: String,
    pub quarantine_path: Option<String>,
    pub report_path: Option<String>,
    pub capture_id: String,
    pub analysis_run_id: String,
    pub schema_version: String,
}

pub fn run_pipeline(config: PipelineConfig) -> Result<PipelineReport, Box<dyn std::error::Error>> {
    let start_time = Instant::now();

    let input_file = File::open(&config.input_path)?;
    let reader = BufReader::new(input_file);

    let output_file = File::create(&config.output_path)?;
    let mut writer = BufWriter::new(output_file);

    let mut quarantine_writer: Option<BufWriter<File>> = match &config.quarantine_path {
        Some(path) => {
            let file = File::create(path)?;
            Some(BufWriter::new(file))
        }
        None => None,
    };

    let mut input_count: u64 = 0;
    let mut accepted_count: u64 = 0;
    let mut rejected_count: u64 = 0;
    let mut unsupported_count: u64 = 0;
    let mut error_summary: Vec<String> = Vec::new();

    for (idx, line_res) in reader.lines().enumerate() {
        let line_num = (idx + 1) as u64;
        let line = line_res?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        input_count += 1;

        // 1. JSON parse attempt
        let event_res: Result<NetworkEvent, serde_json::Error> = serde_json::from_str(trimmed);
        match event_res {
            Ok(raw_event) => {
                // Check if parser status is unsupported_protocol
                let is_unsupported = raw_event.parser_status.status == "unsupported_protocol";

                // 2. Schema and semantics validation
                match validate_event(&raw_event, &config.schema_version) {
                    Ok(()) => {
                        // 3. Normalization and provenance enrichment
                        let normalized = normalize_event(
                            raw_event,
                            &config.capture_id,
                            &config.analysis_run_id,
                            PIPELINE_VERSION,
                        );

                        // Serialize canonical line
                        serde_json::to_writer(&mut writer, &normalized)?;
                        writer.write_all(b"\n")?;

                        if is_unsupported {
                            unsupported_count += 1;
                        }
                        accepted_count += 1;
                    }
                    Err(val_err) => {
                        rejected_count += 1;
                        let err_msg = val_err.to_string();
                        if error_summary.len() < 50 {
                            error_summary.push(format!("Line {}: {}", line_num, err_msg));
                        }

                        if let Some(qw) = &mut quarantine_writer {
                            let rec = QuarantinedRecord {
                                raw_line: trimmed.to_string(),
                                line_number: line_num,
                                error_code: "SCHEMA_VALIDATION_ERROR".to_string(),
                                error_message: err_msg,
                                capture_id: Some(config.capture_id.clone()),
                                analysis_run_id: Some(config.analysis_run_id.clone()),
                                timestamp_utc: Utc::now().to_rfc3339(),
                            };
                            serde_json::to_writer(&mut *qw, &rec)?;
                            qw.write_all(b"\n")?;
                        }
                    }
                }
            }
            Err(parse_err) => {
                rejected_count += 1;
                let err_msg = format!("Malformed JSON: {}", parse_err);
                if error_summary.len() < 50 {
                    error_summary.push(format!("Line {}: {}", line_num, err_msg));
                }

                if let Some(qw) = &mut quarantine_writer {
                    let rec = QuarantinedRecord {
                        raw_line: trimmed.to_string(),
                        line_number: line_num,
                        error_code: "MALFORMED_JSON_LINE".to_string(),
                        error_message: err_msg,
                        capture_id: Some(config.capture_id.clone()),
                        analysis_run_id: Some(config.analysis_run_id.clone()),
                        timestamp_utc: Utc::now().to_rfc3339(),
                    };
                    serde_json::to_writer(&mut *qw, &rec)?;
                    qw.write_all(b"\n")?;
                }
            }
        }
    }

    writer.flush()?;
    if let Some(qw) = &mut quarantine_writer {
        qw.flush()?;
    }

    let elapsed = start_time.elapsed();
    let duration_ms = elapsed.as_secs_f64() * 1000.0;
    let throughput = if duration_ms > 0.0 {
        (input_count as f64) / (duration_ms / 1000.0)
    } else {
        0.0
    };

    let status = if input_count == 0 {
        "EMPTY".to_string()
    } else if rejected_count == 0 {
        "COMPLETED".to_string()
    } else if accepted_count > 0 {
        "PARTIAL".to_string()
    } else {
        "FAILED".to_string()
    };

    let report = PipelineReport {
        capture_id: config.capture_id.clone(),
        analysis_run_id: config.analysis_run_id.clone(),
        schema_version: config.schema_version.clone(),
        pipeline_version: PIPELINE_VERSION.to_string(),
        input_count,
        accepted_count,
        rejected_count,
        unsupported_count,
        persisted_count: accepted_count,
        duration_ms,
        throughput_events_per_sec: throughput,
        status,
        error_summary,
        quarantine_file: config.quarantine_path.clone(),
    };

    if let Some(report_path) = &config.report_path {
        let report_file = File::create(report_path)?;
        let rw = BufWriter::new(report_file);
        serde_json::to_writer_pretty(rw, &report)?;
    }

    Ok(report)
}
