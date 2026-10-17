#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include "engine/config.hpp"
#include "engine/engine.hpp"
#include "engine/logger.hpp"
#include "engine/analysis_pipeline.hpp"

void print_usage(const char* prog_name) {
    std::cout << "Usage: " << prog_name << " [options]\n"
              << "Options:\n"
              << "  --help, -h            Show this help message\n"
              << "  --version, -v         Show engine version information\n"
              << "  --pcap, --input <f>   Analyze a PCAP or PCAPNG capture file\n"
              << "  --out <f>             Output canonical JSONL events to file\n"
              << "  --summary <f>         Output JSON analysis summary to file\n"
              << "  --benchmark           Print performance metrics and throughput to stdout\n"
              << "  --workers <n>         Worker concurrency hint (default: hardware concurrency)\n"
              << "  --max-packets <n>     Process up to n packets\n"
              << "  --synthetic <count>   Run with synthetic packet generator\n"
              << "  --interface <name>    Capture from network interface\n"
              << "  --batch-size <n>      Process batch size (default: 100)\n"
              << "  --log-level <level>   Log level: DEBUG, INFO, WARNING, ERROR (default: INFO)\n";
}

int main(int argc, char* argv[]) {
    engine::PipelineConfig pipeline_config;
    engine::EngineConfig legacy_config;
    legacy_config.source_type = engine::PacketSourceType::Synthetic;
    legacy_config.batch_size = 10;
    legacy_config.log_level = "INFO";

    bool use_pipeline = false;
    bool benchmark_mode = false;
    uint32_t workers = 1;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return 0;
        } else if (arg == "--version" || arg == "-v") {
            std::cout << "Protocol-Aware Network Digital Twin Engine v1.0.0 (C++20)\n"
                      << "Schema Version: 1.0.0\n";
            return 0;
        } else if ((arg == "--pcap" || arg == "--pcapng" || arg == "--input") && i + 1 < argc) {
            pipeline_config.input_path = argv[++i];
            legacy_config.source_type = engine::PacketSourceType::PcapFile;
            legacy_config.source_target = pipeline_config.input_path;
            use_pipeline = true;
        } else if (arg == "--out" && i + 1 < argc) {
            pipeline_config.events_output_path = argv[++i];
            use_pipeline = true;
        } else if (arg == "--summary" && i + 1 < argc) {
            pipeline_config.summary_output_path = argv[++i];
            use_pipeline = true;
        } else if (arg == "--benchmark") {
            benchmark_mode = true;
            use_pipeline = true;
        } else if (arg == "--workers" && i + 1 < argc) {
            workers = static_cast<uint32_t>(std::stoul(argv[++i]));
            (void)workers;
        } else if (arg == "--max-packets" && i + 1 < argc) {
            pipeline_config.max_packets = std::stoull(argv[++i]);
        } else if (arg == "--synthetic" && i + 1 < argc) {
            legacy_config.source_type = engine::PacketSourceType::Synthetic;
            legacy_config.batch_size = static_cast<uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "--interface" && i + 1 < argc) {
            legacy_config.source_type = engine::PacketSourceType::LiveInterface;
            legacy_config.source_target = argv[++i];
        } else if (arg == "--batch-size" && i + 1 < argc) {
            legacy_config.batch_size = static_cast<uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "--log-level" && i + 1 < argc) {
            legacy_config.log_level = argv[++i];
        } else {
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    engine::Logger::instance().set_level(engine::parse_log_level(legacy_config.log_level));

    if (use_pipeline) {
        if (pipeline_config.input_path.empty()) {
            std::cerr << "Error: Pipeline requires an input capture file (--pcap or --input)\n";
            return 1;
        }

        LOG_INFO("Main", "Starting Analysis Pipeline for: " + pipeline_config.input_path);
        engine::AnalysisPipeline pipeline(pipeline_config);
        engine::AnalysisReport report = pipeline.run();

        if (benchmark_mode) {
            std::cout << "\n==================================================\n"
                      << "PROTOCOL ANALYSIS ENGINE PERFORMANCE BENCHMARK\n"
                      << "==================================================\n"
                      << "Capture File:     " << report.capture_file << "\n"
                      << "Total Packets:    " << report.total_packets << "\n"
                      << "Total Bytes:      " << report.total_bytes << " bytes\n"
                      << "Execution Time:   " << std::fixed << std::setprecision(2) << report.duration_ms << " ms\n"
                      << "Packet Rate:      " << std::fixed << std::setprecision(0) << report.packets_per_sec << " pkts/sec\n"
                      << "Throughput:       " << std::fixed << std::setprecision(2) << report.throughput_mbps << " Mbps\n"
                      << "Total Flows:      " << report.total_flows << "\n"
                      << "DNS Queries:      " << report.dns_queries << ", Responses: " << report.dns_responses << "\n"
                      << "HTTP Requests:    " << report.http_requests << ", Responses: " << report.http_responses << "\n"
                      << "TLS Handshakes:   " << report.tls_handshakes << "\n"
                      << "QUIC Datagrams:   " << report.quic_datagrams << "\n";

            std::cout << "\nProtocol Distribution:\n";
            for (const auto& [p, cnt] : report.protocol_counts) {
                std::cout << "  - " << std::left << std::setw(12) << p << ": " << cnt << " packets\n";
            }

            std::cout << "\nParser Status:\n";
            for (const auto& [st, cnt] : report.parser_status_counts) {
                std::cout << "  - " << std::left << std::setw(12) << st << ": " << cnt << " packets\n";
            }

            if (!report.anomalies.empty()) {
                std::cout << "\nAnomalies Detected (" << report.anomalies.size() << "):\n";
                for (size_t a = 0; a < std::min(report.anomalies.size(), size_t(5)); ++a) {
                    std::cout << "  * " << report.anomalies[a] << "\n";
                }
            }
            std::cout << "==================================================\n\n";
        }

        LOG_INFO("Main", "Analysis finished. Processed " + std::to_string(report.total_packets) +
                 " packets (" + std::to_string(report.total_flows) + " flows).");
        return 0;
    }

    // Fallback legacy execution mode
    LOG_INFO("Main", "Starting Network Protocol Analysis Engine Foundation...");
    std::string err;
    engine::ProtocolEngine eng(legacy_config);

    engine::StatusCode init_res = eng.initialize(err);
    if (init_res != engine::StatusCode::Success) {
        std::cerr << "Engine initialization failed: " << err << "\n";
        return 1;
    }

    engine::StatusCode start_res = eng.start(err);
    if (start_res != engine::StatusCode::Success) {
        std::cerr << "Engine start failed: " << err << "\n";
        return 1;
    }

    uint32_t processed = eng.process_batch(legacy_config.batch_size);
    LOG_INFO("Main", "Processed " + std::to_string(processed) + " packets in batch execution");

    eng.stop();
    auto metrics = eng.get_metrics();
    LOG_INFO("Main", "Shutdown complete. Total packets: " +
             std::to_string(metrics.total_packets_processed) +
             ", bytes: " + std::to_string(metrics.total_bytes_processed));

    return 0;
}
