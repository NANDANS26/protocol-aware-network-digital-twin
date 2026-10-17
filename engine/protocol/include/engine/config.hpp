#pragma once

#include <string>
#include <optional>
#include <cstdint>
#include "engine/types.hpp"

namespace engine {

enum class PacketSourceType {
    Synthetic,
    PcapFile,
    LiveInterface
};

struct EngineConfig {
    PacketSourceType source_type{PacketSourceType::Synthetic};
    std::string source_target{"default_synthetic"}; // File path or interface name
    uint32_t snaplen_bytes{65535};
    uint32_t buffer_size_bytes{2 * 1024 * 1024}; // 2 MB buffer
    bool promiscuous_mode{false};
    std::optional<std::string> bpf_filter;
    uint32_t batch_size{100};
    std::string log_level{"INFO"};

    [[nodiscard]] StatusCode validate(std::string& error_message) const;
};

} // namespace engine
