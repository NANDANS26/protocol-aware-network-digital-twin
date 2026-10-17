#include "engine/engine.hpp"
#include "engine/logger.hpp"

namespace engine {

ProtocolEngine::ProtocolEngine()
    : ProtocolEngine(EngineConfig{}) {}

ProtocolEngine::ProtocolEngine(EngineConfig config)
    : config_(std::move(config)) {}

ProtocolEngine::~ProtocolEngine() {
    stop();
}

StatusCode ProtocolEngine::initialize(std::string& error_message) {
    LOG_INFO("Engine", "Initializing Protocol Analysis Engine...");

    StatusCode status = config_.validate(error_message);
    if (status != StatusCode::Success) {
        LOG_ERROR("Engine", "Configuration validation failed: " + error_message);
        return status;
    }

    packet_source_ = create_packet_source(config_);
    if (!packet_source_) {
        error_message = "Failed to instantiate packet source";
        LOG_ERROR("Engine", error_message);
        return StatusCode::InternalError;
    }

    LOG_INFO("Engine", "Engine initialized successfully with source: " + config_.source_target);
    return StatusCode::Success;
}

StatusCode ProtocolEngine::start(std::string& error_message) {
    if (!packet_source_) {
        StatusCode init_status = initialize(error_message);
        if (init_status != StatusCode::Success) {
            return init_status;
        }
    }

    StatusCode open_status = packet_source_->open(error_message);
    if (open_status != StatusCode::Success) {
        LOG_ERROR("Engine", "Failed to open packet source: " + error_message);
        return open_status;
    }

    is_running_ = true;
    metrics_.is_running = true;
    LOG_INFO("Engine", "Protocol Analysis Engine started successfully");
    return StatusCode::Success;
}

uint32_t ProtocolEngine::process_batch(uint32_t max_packets) {
    if (!is_running_ || !packet_source_) {
        return 0;
    }

    uint32_t processed = 0;
    RawPacket packet;

    while (processed < max_packets) {
        StatusCode res = packet_source_->read_next_packet(packet);
        if (res == StatusCode::EndOfFile) {
            LOG_INFO("Engine", "Packet source reached EOF");
            stop();
            break;
        }
        if (res != StatusCode::Success) {
            metrics_.total_parse_errors++;
            break;
        }

        metrics_.total_packets_processed++;
        metrics_.total_bytes_processed += packet.capture_length_bytes;
        processed++;
    }

    return processed;
}

void ProtocolEngine::stop() {
    if (is_running_) {
        LOG_INFO("Engine", "Stopping Protocol Analysis Engine...");
        if (packet_source_) {
            packet_source_->close();
        }
        is_running_ = false;
        metrics_.is_running = false;
        LOG_INFO("Engine", "Engine stopped. Total packets processed: " +
                 std::to_string(metrics_.total_packets_processed));
    }
}

bool ProtocolEngine::is_running() const {
    return is_running_;
}

EngineMetrics ProtocolEngine::get_metrics() const {
    return metrics_;
}

const EngineConfig& ProtocolEngine::get_config() const {
    return config_;
}

} // namespace engine
