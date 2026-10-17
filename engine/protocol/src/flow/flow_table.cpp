#include "engine/flow/flow_table.hpp"

namespace engine::flow {

FlowTable::FlowTable(size_t max_flows)
    : max_flows_(max_flows) {}

FlowRecord& FlowTable::get_or_create(const FlowKey& key, uint64_t timestamp_ns, bool& is_new) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = table_.find(key);
    if (it != table_.end()) {
        is_new = false;
        it->second.last_seen_ns = timestamp_ns;
        return it->second;
    }

    // Capacity check: if at capacity, prune one closed or oldest flow
    if (table_.size() >= max_flows_) {
        auto prune_it = table_.begin();
        for (auto candidate = table_.begin(); candidate != table_.end(); ++candidate) {
            if (candidate->second.tcp_tracker.is_closed()) {
                prune_it = candidate;
                break;
            }
        }
        table_.erase(prune_it);
    }

    is_new = true;
    FlowRecord rec{};
    rec.flow_id = key.to_flow_id();
    rec.key = key;
    rec.first_seen_ns = timestamp_ns;
    rec.last_seen_ns = timestamp_ns;

    auto [inserted_it, _] = table_.emplace(key, std::move(rec));
    return inserted_it->second;
}

const FlowRecord* FlowTable::find(const FlowKey& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = table_.find(key);
    if (it != table_.end()) {
        return &it->second;
    }
    return nullptr;
}

size_t FlowTable::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return table_.size();
}

std::vector<FlowRecord> FlowTable::get_all_records() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<FlowRecord> records;
    records.reserve(table_.size());
    for (const auto& [_, rec] : table_) {
        records.push_back(rec);
    }
    return records;
}

void FlowTable::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    table_.clear();
}

} // namespace engine::flow
