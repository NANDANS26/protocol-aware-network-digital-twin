#include "engine/flow/flow_key.hpp"
#include <iomanip>
#include <sstream>

namespace engine::flow {

namespace {

// 64-bit FNV-1a hash algorithm
uint64_t fnv1a_hash(const void* data, size_t size, uint64_t hash = 14695981039346656037ULL) {
    const auto* ptr = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < size; ++i) {
        hash ^= ptr[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

} // namespace

FlowKey::FlowKey(std::string src_ip, uint16_t src_port,
                 std::string dst_ip, uint16_t dst_port,
                 TransportProtocol protocol)
    : initiator_{std::move(src_ip), src_port},
      responder_{std::move(dst_ip), dst_port},
      protocol_(protocol) {

    // Determine canonical endpoint ordering for bidirectional identity
    if (initiator_ < responder_) {
        endpoint_a_ = initiator_;
        endpoint_b_ = responder_;
    } else {
        endpoint_a_ = responder_;
        endpoint_b_ = initiator_;
    }

    // Compute canonical hash
    uint64_t h = fnv1a_hash(endpoint_a_.ip.data(), endpoint_a_.ip.size());
    h = fnv1a_hash(&endpoint_a_.port, sizeof(endpoint_a_.port), h);
    h = fnv1a_hash(endpoint_b_.ip.data(), endpoint_b_.ip.size(), h);
    h = fnv1a_hash(&endpoint_b_.port, sizeof(endpoint_b_.port), h);
    auto proto_byte = static_cast<uint8_t>(protocol_);
    h = fnv1a_hash(&proto_byte, sizeof(proto_byte), h);
    hash_value_ = h;
}

FlowDirection FlowKey::get_packet_direction(const std::string& src_ip, uint16_t src_port) const {
    if (src_ip == initiator_.ip && (initiator_.port == 0 || src_port == initiator_.port)) {
        return FlowDirection::Forward;
    }
    if (src_ip == responder_.ip && (responder_.port == 0 || src_port == responder_.port)) {
        return FlowDirection::Reverse;
    }
    return FlowDirection::Unknown;
}

uint64_t FlowKey::hash() const {
    return hash_value_;
}

std::string FlowKey::to_flow_id() const {
    std::ostringstream ss;
    ss << "flow-" << std::hex << std::setfill('0') << std::setw(16) << hash_value_;
    return ss.str();
}

std::string FlowKey::to_string() const {
    std::ostringstream ss;
    ss << endpoint_a_.ip << ":" << endpoint_a_.port
       << " <-> "
       << endpoint_b_.ip << ":" << endpoint_b_.port
       << " [" << flow::to_string(protocol_) << "]";
    return ss.str();
}

} // namespace engine::flow
