#include "engine/decoders/icmp_decoder.hpp"

namespace engine::decoders {

DecodeResult IcmpDecoder::decode(
    std::span<const uint8_t> icmp_bytes,
    bool is_icmpv6,
    DecodedIcmp& out_icmp,
    std::string& diagnostic
) {
    out_icmp = {};
    out_icmp.is_icmpv6 = is_icmpv6;

    if (icmp_bytes.size() < 4) {
        diagnostic = "ICMP message truncated: length " + std::to_string(icmp_bytes.size()) + " < 4 bytes";
        return DecodeResult::TruncatedHeader;
    }

    out_icmp.type = icmp_bytes[0];
    out_icmp.code = icmp_bytes[1];
    out_icmp.checksum = (static_cast<uint16_t>(icmp_bytes[2]) << 8) | icmp_bytes[3];

    size_t offset = 4;

    // Check for Echo Request / Reply
    const bool is_echo = (!is_icmpv6 && (out_icmp.type == 8 || out_icmp.type == 0)) ||
                         (is_icmpv6  && (out_icmp.type == 128 || out_icmp.type == 129));

    if (is_echo && icmp_bytes.size() >= 8) {
        out_icmp.echo_id = (static_cast<uint16_t>(icmp_bytes[4]) << 8) | icmp_bytes[5];
        out_icmp.echo_sequence = (static_cast<uint16_t>(icmp_bytes[6]) << 8) | icmp_bytes[7];
        offset = 8;
    } else if ((!is_icmpv6 && (out_icmp.type == 3 || out_icmp.type == 11)) ||
               (is_icmpv6  && (out_icmp.type == 1 || out_icmp.type == 3))) {
        // Destination unreachable or Time exceeded: 4 bytes unused/length + original IP header quote
        if (icmp_bytes.size() > 8) {
            out_icmp.quote_summary = "Quoted IP header length " + std::to_string(icmp_bytes.size() - 8) + " bytes";
            offset = 8;
        }
    }

    if (offset <= icmp_bytes.size()) {
        out_icmp.payload = icmp_bytes.subspan(offset);
    }

    return DecodeResult::Success;
}

} // namespace engine::decoders
