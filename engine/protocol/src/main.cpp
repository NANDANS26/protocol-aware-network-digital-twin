#include <iostream>
#include <string>
#include <vector>
#include "engine/config.hpp"
#include "engine/engine.hpp"
#include "engine/logger.hpp"

void print_usage(const char* prog_name) {
    std::cout << "Usage: " << prog_name << " [options]\n"
              << "Options:\n"
              << "  --help                Show this help message\n"
              << "  --version             Show engine version information\n"
              << "  --synthetic <count>   Run with synthetic packet generator (default: 10 packets)\n"
              << "  --pcap <path>         Inspect packets from a PCAP file\n"
              << "  --interface <name>    Attempt capture from network interface (requires driver/privileges)\n"
              << "  --batch-size <n>      Process batch size (default: 100)\n"
              << "  --log-level <level>   Log level: DEBUG, INFO, WARNING, ERROR (default: INFO)\n";
}

int main(int argc, char* argv[]) {
    engine::EngineConfig config;
    config.source_type = engine::PacketSourceType::Synthetic;
    config.batch_size = 10;
    config.log_level = "INFO";

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return 0;
        } else if (arg == "--version" || arg == "-v") {
            std::cout << "Protocol-Aware Network Digital Twin Engine v0.1.0 (C++20)\n"
                      << "Schema Version: 1.0.0\n";
            return 0;
        } else if (arg == "--synthetic" && i + 1 < argc) {
            config.source_type = engine::PacketSourceType::Synthetic;
            config.batch_size = static_cast<uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "--pcap" && i + 1 < argc) {
            config.source_type = engine::PacketSourceType::PcapFile;
            config.source_target = argv[++i];
        } else if (arg == "--interface" && i + 1 < argc) {
            config.source_type = engine::PacketSourceType::LiveInterface;
            config.source_target = argv[++i];
        } else if (arg == "--batch-size" && i + 1 < argc) {
            config.batch_size = static_cast<uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "--log-level" && i + 1 < argc) {
            config.log_level = argv[++i];
        } else {
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    engine::Logger::instance().set_level(engine::parse_log_level(config.log_level));
    LOG_INFO("Main", "Starting Network Protocol Analysis Engine Foundation...");

    std::string err;
    engine::ProtocolEngine eng(config);

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

    uint32_t processed = eng.process_batch(config.batch_size);
    LOG_INFO("Main", "Processed " + std::to_string(processed) + " packets in batch execution");

    eng.stop();
    auto metrics = eng.get_metrics();
    LOG_INFO("Main", "Shutdown complete. Total packets: " +
             std::to_string(metrics.total_packets_processed) +
             ", bytes: " + std::to_string(metrics.total_bytes_processed));

    return 0;
}
