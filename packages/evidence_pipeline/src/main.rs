use clap::Parser;
use evidence_pipeline::{run_pipeline, PipelineConfig, PIPELINE_VERSION};
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "evidence_pipeline",
    author = "Protocol Digital Twin Systems Architecture Team",
    version = PIPELINE_VERSION,
    about = "Validates, normalizes, and transports C++ engine packet observation events into canonical schemas"
)]
struct Args {
    /// Path to raw JSONL events from C++ engine
    #[arg(short, long)]
    input: String,

    /// Path to write canonical validated JSONL events
    #[arg(short, long)]
    out: String,

    /// Optional path to write quarantined/rejected events with error diagnostics
    #[arg(short, long)]
    quarantine: Option<String>,

    /// Optional path to write the JSON pipeline validation and reconciliation report
    #[arg(short, long)]
    report: Option<String>,

    /// Authoritative Capture ID
    #[arg(long)]
    capture_id: String,

    /// Authoritative Analysis Run / Job ID
    #[arg(long)]
    analysis_run_id: String,

    /// Expected canonical schema version
    #[arg(long, default_value = "1.0.0")]
    schema_version: String,
}

fn main() -> ExitCode {
    let args = Args::parse();

    let config = PipelineConfig {
        input_path: args.input,
        output_path: args.out,
        quarantine_path: args.quarantine,
        report_path: args.report,
        capture_id: args.capture_id,
        analysis_run_id: args.analysis_run_id,
        schema_version: args.schema_version,
    };

    match run_pipeline(config) {
        Ok(report) => {
            eprintln!(
                "[Rust Evidence Pipeline] Completed: {} input, {} accepted, {} rejected, {} persisted in {:.2}ms ({:.1} evt/s)",
                report.input_count,
                report.accepted_count,
                report.rejected_count,
                report.persisted_count,
                report.duration_ms,
                report.throughput_events_per_sec
            );
            if report.status == "FAILED" {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(err) => {
            eprintln!("[Rust Evidence Pipeline] Fatal error: {}", err);
            ExitCode::FAILURE
        }
    }
}
