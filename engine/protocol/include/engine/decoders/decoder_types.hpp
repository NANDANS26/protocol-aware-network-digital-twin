#pragma once

#include <cstdint>
#include <string>
#include <span>
#include <optional>
#include <vector>

namespace engine::decoders {

enum class ChecksumStatus {
    Valid,
    Invalid,
    Indeterminate,
    NotApplicable
};

inline const char* to_string(ChecksumStatus status) {
    switch (status) {
        case ChecksumStatus::Valid: return "Valid";
        case ChecksumStatus::Invalid: return "Invalid";
        case ChecksumStatus::Indeterminate: return "Indeterminate";
        default: return "NotApplicable";
    }
}

enum class DecodeResult {
    Success = 0,
    TruncatedHeader,
    InvalidLength,
    InvalidChecksum,
    UnsupportedVersion,
    MalformedOptions,
    MalformedExtensionChain,
    UnknownProtocol
};

inline const char* to_string(DecodeResult res) {
    switch (res) {
        case DecodeResult::Success: return "Success";
        case DecodeResult::TruncatedHeader: return "TruncatedHeader";
        case DecodeResult::InvalidLength: return "InvalidLength";
        case DecodeResult::InvalidChecksum: return "InvalidChecksum";
        case DecodeResult::UnsupportedVersion: return "UnsupportedVersion";
        case DecodeResult::MalformedOptions: return "MalformedOptions";
        case DecodeResult::MalformedExtensionChain: return "MalformedExtensionChain";
        case DecodeResult::UnknownProtocol: return "UnknownProtocol";
        default: return "Error";
    }
}

struct MacAddress {
    uint8_t bytes[6]{0};

    [[nodiscard]] std::string to_string() const;
    [[nodiscard]] bool is_broadcast() const;
    [[nodiscard]] bool is_multicast() const;
};

struct VlanTag {
    uint16_t tpid{0x8100};   // 0x8100 for 802.1Q, 0x88A8 for 802.1ad Service Tag (Q-in-Q)
    uint16_t vlan_id{0};     // 12-bit VLAN identifier (0..4095)
    uint8_t priority{0};     // 3-bit Priority Code Point (PCP)
    bool drop_eligible{false};// 1-bit Canonical Format Indicator (CFI) / DEI
};

struct DecodedEthernet {
    MacAddress destination_mac;
    MacAddress source_mac;
    uint16_t ether_type{0};
    std::vector<VlanTag> vlan_tags;
    std::span<const uint8_t> payload;
};

struct DecodedArp {
    uint16_t hardware_type{1}; // 1 = Ethernet
    uint16_t protocol_type{0x0800}; // 0x0800 = IPv4
    uint8_t hardware_size{6};
    uint8_t protocol_size{4};
    uint16_t opcode{1}; // 1 = Request, 2 = Reply
    MacAddress sender_mac;
    std::string sender_ip;
    MacAddress target_mac;
    std::string target_ip;
};

struct DecodedIPv4 {
    uint8_t version{4};
    uint8_t ihl{5}; // Header length in 32-bit words
    uint8_t dscp{0};
    uint8_t ecn{0};
    uint16_t total_length{0};
    uint16_t identification{0};
    bool flag_df{false};
    bool flag_mf{false};
    uint16_t fragment_offset{0}; // In 8-byte units
    uint8_t ttl{64};
    uint8_t protocol{0}; // 6 = TCP, 17 = UDP, 1 = ICMP
    uint16_t header_checksum{0};
    ChecksumStatus checksum_status{ChecksumStatus::Indeterminate};
    std::string source_ip;
    std::string destination_ip;
    bool is_fragment{false};
    std::span<const uint8_t> payload;
};

struct IPv6ExtensionHeader {
    uint8_t type{0};
    uint16_t length{0};
};

struct DecodedIPv6 {
    uint8_t version{6};
    uint8_t traffic_class{0};
    uint32_t flow_label{0};
    uint16_t payload_length{0};
    uint8_t next_header{0}; // Base next header
    uint8_t upper_layer_protocol{0}; // Final resolved transport protocol
    uint8_t hop_limit{64};
    std::string source_ip;
    std::string destination_ip;
    std::vector<IPv6ExtensionHeader> extension_headers;
    bool is_fragment{false};
    uint32_t fragment_id{0};
    uint16_t fragment_offset{0};
    bool fragment_m_flag{false};
    std::span<const uint8_t> payload;
};

struct DecodedIcmp {
    bool is_icmpv6{false};
    uint8_t type{0};
    uint8_t code{0};
    uint16_t checksum{0};
    std::optional<uint16_t> echo_id;
    std::optional<uint16_t> echo_sequence;
    std::optional<std::string> quote_summary;
    std::span<const uint8_t> payload;
};

struct DecodedUdp {
    uint16_t source_port{0};
    uint16_t destination_port{0};
    uint16_t length{0};
    uint16_t checksum{0};
    ChecksumStatus checksum_status{ChecksumStatus::Indeterminate};
    std::span<const uint8_t> payload;
};

struct TcpOption {
    uint8_t kind{0};
    uint8_t length{0};
    std::vector<uint8_t> data;
};

struct DecodedTcp {
    uint16_t source_port{0};
    uint16_t destination_port{0};
    uint32_t sequence_number{0};
    uint32_t acknowledgment_number{0};
    uint8_t data_offset{5}; // in 32-bit words
    bool flag_fin{false};
    bool flag_syn{false};
    bool flag_rst{false};
    bool flag_psh{false};
    bool flag_ack{false};
    bool flag_urg{false};
    bool flag_ece{false};
    bool flag_cwr{false};
    uint16_t window_size{0};
    uint16_t checksum{0};
    uint16_t urgent_pointer{0};
    ChecksumStatus checksum_status{ChecksumStatus::Indeterminate};
    std::vector<TcpOption> options;
    std::optional<uint16_t> opt_mss;
    std::optional<uint8_t> opt_window_scale;
    bool opt_sack_permitted{false};
    std::span<const uint8_t> payload;
};

} // namespace engine::decoders
