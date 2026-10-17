#pragma once

#include <string>
#include <cstdint>
#include <tuple>
#include <functional>

namespace engine::flow {

enum class TransportProtocol : uint8_t {
    Unknown = 0,
    TCP = 6,
    UDP = 17,
    ICMP = 1,
    ICMPv6 = 58,
    SCTP = 132,
    Other = 255
};

inline const char* to_string(TransportProtocol proto) {
    switch (proto) {
        case TransportProtocol::TCP: return "TCP";
        case TransportProtocol::UDP: return "UDP";
        case TransportProtocol::ICMP: return "ICMP";
        case TransportProtocol::ICMPv6: return "ICMPv6";
        case TransportProtocol::SCTP: return "SCTP";
        default: return "OTHER";
    }
}

enum class FlowDirection {
    Forward,
    Reverse,
    Unknown
};

inline const char* to_string(FlowDirection dir) {
    switch (dir) {
        case FlowDirection::Forward: return "forward";
        case FlowDirection::Reverse: return "reverse";
        default: return "unknown";
    }
}

struct Endpoint {
    std::string ip;
    uint16_t port{0};

    bool operator==(const Endpoint& other) const {
        return port == other.port && ip == other.ip;
    }

    bool operator<(const Endpoint& other) const {
        if (ip != other.ip) return ip < other.ip;
        return port < other.port;
    }
};

class FlowKey {
public:
    FlowKey() = default;
    FlowKey(std::string src_ip, uint16_t src_port,
            std::string dst_ip, uint16_t dst_port,
            TransportProtocol protocol);

    [[nodiscard]] const Endpoint& get_initiator() const { return initiator_; }
    [[nodiscard]] const Endpoint& get_responder() const { return responder_; }
    [[nodiscard]] const Endpoint& get_endpoint_a() const { return endpoint_a_; }
    [[nodiscard]] const Endpoint& get_endpoint_b() const { return endpoint_b_; }
    [[nodiscard]] TransportProtocol get_protocol() const { return protocol_; }

    [[nodiscard]] FlowDirection get_packet_direction(const std::string& src_ip, uint16_t src_port) const;
    [[nodiscard]] uint64_t hash() const;
    [[nodiscard]] std::string to_flow_id() const;
    [[nodiscard]] std::string to_string() const;

    bool operator==(const FlowKey& other) const {
        return protocol_ == other.protocol_ &&
               endpoint_a_ == other.endpoint_a_ &&
               endpoint_b_ == other.endpoint_b_;
    }

private:
    Endpoint initiator_{};
    Endpoint responder_{};
    Endpoint endpoint_a_{}; // Canonical smaller
    Endpoint endpoint_b_{}; // Canonical larger
    TransportProtocol protocol_{TransportProtocol::Unknown};
    uint64_t hash_value_{0};
};

} // namespace engine::flow

namespace std {
template <>
struct hash<engine::flow::FlowKey> {
    size_t operator()(const engine::flow::FlowKey& key) const noexcept {
        return static_cast<size_t>(key.hash());
    }
};
} // namespace std
