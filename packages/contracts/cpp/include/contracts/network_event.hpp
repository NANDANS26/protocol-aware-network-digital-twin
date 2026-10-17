#pragma once

#include <cstdint>
#include <string>
#include <optional>
#include <vector>
#include <map>

namespace contracts {

enum class ParserStatusCode {
    Ok,
    Incomplete,
    Malformed,
    UnsupportedProtocol,
    ChecksumError,
    Truncated
};

inline std::string to_string(ParserStatusCode code) {
    switch (code) {
        case ParserStatusCode::Ok: return "ok";
        case ParserStatusCode::Incomplete: return "incomplete";
        case ParserStatusCode::Malformed: return "malformed";
        case ParserStatusCode::UnsupportedProtocol: return "unsupported_protocol";
        case ParserStatusCode::ChecksumError: return "checksum_error";
        case ParserStatusCode::Truncated: return "truncated";
        default: return "unknown";
    }
}

enum class TransportProtocol {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Sctp,
    Other
};

inline std::string to_string(TransportProtocol proto) {
    switch (proto) {
        case TransportProtocol::Tcp: return "TCP";
        case TransportProtocol::Udp: return "UDP";
        case TransportProtocol::Icmp: return "ICMP";
        case TransportProtocol::Icmpv6: return "ICMPv6";
        case TransportProtocol::Sctp: return "SCTP";
        case TransportProtocol::Other: return "OTHER";
        default: return "UNKNOWN";
    }
}

struct LinkLayer {
    std::optional<std::string> source_mac;
    std::optional<std::string> destination_mac;
    std::optional<uint16_t> ether_type;
    std::optional<uint16_t> vlan_id;
};

struct NetworkLayer {
    std::optional<std::string> version; // "IPv4" or "IPv6"
    std::optional<std::string> source_ip;
    std::optional<std::string> destination_ip;
    std::optional<uint8_t> ttl_or_hop_limit;
    std::optional<uint16_t> identification;
    bool flag_df{false};
    bool flag_mf{false};
};

struct TcpFlags {
    bool syn{false};
    bool ack{false};
    bool fin{false};
    bool rst{false};
    bool psh{false};
    bool urg{false};
    bool ece{false};
    bool cwr{false};
};

struct TransportLayer {
    std::optional<TransportProtocol> protocol;
    std::optional<uint16_t> source_port;
    std::optional<uint16_t> destination_port;
    std::optional<uint32_t> tcp_sequence_number;
    std::optional<uint32_t> tcp_acknowledgment_number;
    std::optional<TcpFlags> tcp_flags;
    std::optional<uint16_t> window_size;
};

struct ApplicationLayer {
    std::optional<std::string> protocol;
    uint32_t payload_length_bytes{0};
    std::optional<std::string> payload_hash_sha256;
    std::optional<std::string> sanitized_preview;
};

struct ParserStatus {
    ParserStatusCode status{ParserStatusCode::Ok};
    std::optional<std::string> diagnostic_code;
    std::optional<std::string> diagnostic_message;
    std::optional<uint32_t> bytes_consumed;
    std::optional<uint32_t> bytes_remaining;
};

struct Provenance {
    uint64_t packet_index{0};
    uint32_t wire_length_bytes{0};
    uint32_t capture_length_bytes{0};
    std::optional<std::string> capture_interface;
    std::optional<std::string> capture_file_path;
};

struct NetworkEvent {
    std::string schema_version{"1.0.0"};
    std::string event_id; // UUID
    uint64_t timestamp_ns{0};
    std::string timestamp_iso;
    std::string source_id;
    std::optional<std::string> flow_id;
    std::optional<std::string> flow_direction; // "forward", "reverse", "unknown"
    std::optional<LinkLayer> link_layer;
    std::optional<NetworkLayer> network_layer;
    std::optional<TransportLayer> transport_layer;
    std::optional<ApplicationLayer> application_layer;
    ParserStatus parser_status;
    Provenance provenance;
};

} // namespace contracts
