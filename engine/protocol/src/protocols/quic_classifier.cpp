#include "engine/protocols/quic_classifier.hpp"
#include <sstream>
#include <iomanip>

namespace engine::protocols {

namespace {

uint32_t read_u32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8)  |
            static_cast<uint32_t>(p[3]);
}

} // namespace

std::string QuicClassifier::format_version(uint32_t version) {
    switch (version) {
        case 0x00000000: return "Version Negotiation";
        case 0x00000001: return "QUIC v1 (RFC 9000)";
        case 0x6b333433: return "QUIC v2 (RFC 9369)";
        case 0xff00001d: return "QUIC draft-29";
        default: {
            std::ostringstream oss;
            oss << "0x" << std::hex << std::setw(8) << std::setfill('0') << version;
            return oss.str();
        }
    }
}

std::string QuicClassifier::hex_cid(const std::vector<uint8_t>& cid) {
    std::ostringstream oss;
    for (uint8_t b : cid) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return oss.str();
}

bool QuicClassifier::classify(
    std::span<const uint8_t> udp_payload,
    QuicClassification& out_class
) {
    out_class = QuicClassification{};

    if (udp_payload.empty()) {
        out_class.diagnostic = "Empty UDP payload";
        return false;
    }

    uint8_t first_byte = udp_payload[0];
    bool is_long_header = (first_byte & 0x80) != 0;
    bool fixed_bit = (first_byte & 0x40) != 0;
    out_class.fixed_bit_set = fixed_bit;

    if (is_long_header) {
        // Long Header requires at least 1 (first byte) + 4 (version) + 1 (DCID len) = 6 bytes
        if (udp_payload.size() < 6) {
            out_class.diagnostic = "Payload too short for QUIC Long Header";
            return false;
        }

        uint32_t version = read_u32(udp_payload.data() + 1);
        out_class.version = version;
        out_class.version_name = format_version(version);

        if (version == 0x00000000) {
            out_class.is_quic = true;
            out_class.header_type = QuicHeaderType::LongVersionNegotiation;
        } else {
            // Check fixed bit for RFC 9000
            if (!fixed_bit) {
                out_class.diagnostic = "QUIC long header without fixed bit set";
                // Could be greased or old version, but flag it
            }
            uint8_t pkt_type = (first_byte & 0x30) >> 4;
            switch (pkt_type) {
                case 0x00: out_class.header_type = QuicHeaderType::LongInitial; break;
                case 0x01: out_class.header_type = QuicHeaderType::Long0RTT; break;
                case 0x02: out_class.header_type = QuicHeaderType::LongHandshake; break;
                case 0x03: out_class.header_type = QuicHeaderType::LongRetry; break;
            }
            out_class.is_quic = true;
        }

        size_t offset = 5;
        uint8_t dcid_len = udp_payload[offset++];
        if (offset + dcid_len > udp_payload.size()) {
            out_class.diagnostic = "Truncated Destination Connection ID";
            return true;
        }
        out_class.destination_connection_id.assign(
            udp_payload.data() + offset,
            udp_payload.data() + offset + dcid_len
        );
        offset += dcid_len;

        if (offset < udp_payload.size()) {
            uint8_t scid_len = udp_payload[offset++];
            if (offset + scid_len <= udp_payload.size()) {
                out_class.source_connection_id.assign(
                    udp_payload.data() + offset,
                    udp_payload.data() + offset + scid_len
                );
            }
        }
        return true;
    } else {
        // Short Header (1-RTT)
        // Requires fixed bit = 1 in RFC 9000
        if (!fixed_bit) {
            out_class.diagnostic = "Not QUIC (fixed bit not set in short header)";
            return false;
        }

        // Short header packets in general require context for CID length, but must be at least some bytes
        if (udp_payload.size() < 5) {
            out_class.diagnostic = "Payload too short for QUIC Short Header";
            return false;
        }

        out_class.is_quic = true;
        out_class.header_type = QuicHeaderType::Short1RTT;
        out_class.version_name = "QUIC 1-RTT (Short Header)";
        return true;
    }
}

} // namespace engine::protocols
