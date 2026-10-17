#pragma once

#include <span>
#include <cstdint>
#include <string>
#include <vector>
#include <optional>

namespace engine::protocols {

enum class QuicHeaderType {
    Unknown,
    LongInitial,
    Long0RTT,
    LongHandshake,
    LongRetry,
    LongVersionNegotiation,
    Short1RTT
};

struct QuicClassification {
    bool is_quic{false};
    QuicHeaderType header_type{QuicHeaderType::Unknown};
    uint32_t version{0};
    std::string version_name;
    std::vector<uint8_t> destination_connection_id;
    std::vector<uint8_t> source_connection_id;
    bool fixed_bit_set{false};
    std::string diagnostic;
};

class QuicClassifier {
public:
    static bool classify(
        std::span<const uint8_t> udp_payload,
        QuicClassification& out_class
    );

    static std::string format_version(uint32_t version);
    static std::string hex_cid(const std::vector<uint8_t>& cid);
};

} // namespace engine::protocols
