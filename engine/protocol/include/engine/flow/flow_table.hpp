#pragma once

#include <unordered_map>
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include "engine/flow/flow_key.hpp"
#include "engine/flow/tcp_state_tracker.hpp"

namespace engine::flow {

struct FlowRecord {
    std::string flow_id;
    FlowKey key;
    TcpStateTracker tcp_tracker;
    uint64_t first_seen_ns{0};
    uint64_t last_seen_ns{0};
    uint64_t forward_packets{0};
    uint64_t forward_bytes{0};
    uint64_t reverse_packets{0};
    uint64_t reverse_bytes{0};
    std::string detected_app_protocol{"UNKNOWN"};
    uint32_t dns_query_count{0};
    uint32_t dns_response_count{0};
    uint32_t http_request_count{0};
    uint32_t http_response_count{0};
    bool tls_client_hello_seen{false};
    bool tls_server_hello_seen{false};
    std::string tls_sni;
    std::string tls_cipher;
    std::string tls_version;
    std::string tls_alpn;
};

class FlowTable {
public:
    explicit FlowTable(size_t max_flows = 100000);

    FlowRecord& get_or_create(const FlowKey& key, uint64_t timestamp_ns, bool& is_new);
    [[nodiscard]] const FlowRecord* find(const FlowKey& key) const;
    [[nodiscard]] size_t size() const;
    [[nodiscard]] std::vector<FlowRecord> get_all_records() const;
    void clear();

private:
    size_t max_flows_{100000};
    mutable std::mutex mutex_;
    std::unordered_map<FlowKey, FlowRecord> table_;
};

} // namespace engine::flow
