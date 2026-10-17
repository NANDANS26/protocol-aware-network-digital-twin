#include "engine/decoders/arp_decoder.hpp"
#include <cstring>

namespace engine::decoders {

DecodeResult ArpDecoder::decode(
    std::span<const uint8_t> arp_bytes,
    DecodedArp& out_arp,
    std::string& diagnostic
) {
    out_arp = {};

    // Standard Ethernet-IPv4 ARP is 28 bytes
    if (arp_bytes.size() < 28) {
        diagnostic = "ARP packet truncated: length " + std::to_string(arp_bytes.size()) + " < 28 bytes";
        return DecodeResult::TruncatedHeader;
    }

    const uint16_t htype = (static_cast<uint16_t>(arp_bytes[0]) << 8) | arp_bytes[1];
    const uint16_t ptype = (static_cast<uint16_t>(arp_bytes[2]) << 8) | arp_bytes[3];
    const uint8_t hlen = arp_bytes[4];
    const uint8_t plen = arp_bytes[5];
    const uint16_t oper  = (static_cast<uint16_t>(arp_bytes[6]) << 8) | arp_bytes[7];

    out_arp.hardware_type = htype;
    out_arp.protocol_type = ptype;
    out_arp.hardware_size = hlen;
    out_arp.protocol_size = plen;
    out_arp.opcode = oper;

    if (hlen == 6 && plen == 4) {
        std::memcpy(out_arp.sender_mac.bytes, arp_bytes.data() + 8, 6);
        out_arp.sender_ip = std::to_string(arp_bytes[14]) + "." +
                            std::to_string(arp_bytes[15]) + "." +
                            std::to_string(arp_bytes[16]) + "." +
                            std::to_string(arp_bytes[17]);

        std::memcpy(out_arp.target_mac.bytes, arp_bytes.data() + 18, 6);
        out_arp.target_ip = std::to_string(arp_bytes[24]) + "." +
                            std::to_string(arp_bytes[25]) + "." +
                            std::to_string(arp_bytes[26]) + "." +
                            std::to_string(arp_bytes[27]);
    }

    return DecodeResult::Success;
}

} // namespace engine::decoders
