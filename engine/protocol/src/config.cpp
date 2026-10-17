#include "engine/config.hpp"

namespace engine {

StatusCode EngineConfig::validate(std::string& error_message) const {
    if (snaplen_bytes == 0 || snaplen_bytes > 262144) {
        error_message = "snaplen_bytes must be between 1 and 262144";
        return StatusCode::InvalidConfig;
    }

    if (buffer_size_bytes < 65536) {
        error_message = "buffer_size_bytes must be at least 64KB (65536 bytes)";
        return StatusCode::InvalidConfig;
    }

    if (batch_size == 0 || batch_size > 50000) {
        error_message = "batch_size must be between 1 and 50000";
        return StatusCode::InvalidConfig;
    }

    if (source_type == PacketSourceType::PcapFile && source_target.empty()) {
        error_message = "PcapFile source requires a non-empty file path in source_target";
        return StatusCode::InvalidConfig;
    }

    if (source_type == PacketSourceType::LiveInterface && source_target.empty()) {
        error_message = "LiveInterface source requires a valid interface name in source_target";
        return StatusCode::InvalidConfig;
    }

    error_message.clear();
    return StatusCode::Success;
}

} // namespace engine
