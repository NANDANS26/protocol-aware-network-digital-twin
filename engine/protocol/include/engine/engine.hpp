#pragma once

#include <memory>
#include <atomic>
#include "engine/config.hpp"
#include "engine/packet_source.hpp"
#include "engine/types.hpp"

namespace engine {

struct EngineMetrics {
    uint64_t total_packets_processed{0};
    uint64_t total_bytes_processed{0};
    uint64_t total_parse_errors{0};
    bool is_running{false};
};

class ProtocolEngine {
public:
    ProtocolEngine();
    explicit ProtocolEngine(EngineConfig config);
    ~ProtocolEngine();

    [[nodiscard]] StatusCode initialize(std::string& error_message);
    [[nodiscard]] StatusCode start(std::string& error_message);
    uint32_t process_batch(uint32_t max_packets = 100);
    void stop();

    [[nodiscard]] bool is_running() const;
    [[nodiscard]] EngineMetrics get_metrics() const;
    [[nodiscard]] const EngineConfig& get_config() const;

private:
    EngineConfig config_;
    std::unique_ptr<IPacketSource> packet_source_;
    std::atomic<bool> is_running_{false};
    EngineMetrics metrics_;
};

} // namespace engine
