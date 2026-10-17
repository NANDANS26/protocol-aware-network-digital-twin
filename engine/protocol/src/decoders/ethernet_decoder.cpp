#include "engine/decoders/ethernet_decoder.hpp"
#include <cstring>

namespace engine::decoders {

DecodeResult EthernetDecoder::decode(
    std::span<const uint8_t> frame_bytes,
    DecodedEthernet& out_eth,
    std::string& diagnostic
) {
    out_eth = {};

    // Standard Ethernet header is at least 14 bytes: Dst(6), Src(6), EtherType/Length(2)
    if (frame_bytes.size() < 14) {
        diagnostic = "Frame is truncated: length " + std::to_string(frame_bytes.size()) + " < 14 bytes";
        return DecodeResult::TruncatedHeader;
    }

    std::memcpy(out_eth.destination_mac.bytes, frame_bytes.data() + 0, 6);
    std::memcpy(out_eth.source_mac.bytes, frame_bytes.data() + 6, 6);

    size_t offset = 12;
    uint16_t ether_type = (static_cast<uint16_t>(frame_bytes[offset]) << 8) | frame_bytes[offset + 1];
    offset += 2;

    // Check for 802.1Q (0x8100) or 802.1ad (0x88A8, Q-in-Q) VLAN tags
    while ((ether_type == 0x8100 || ether_type == 0x88A8) && offset + 4 <= frame_bytes.size()) {
        uint16_t tci = (static_cast<uint16_t>(frame_bytes[offset]) << 8) | frame_bytes[offset + 1];
        VlanTag tag{};
        tag.tpid = ether_type;
        tag.priority = static_cast<uint8_t>((tci >> 13) & 0x07);
        tag.drop_eligible = ((tci >> 12) & 0x01) != 0;
        tag.vlan_id = tci & 0x0FFF;
        out_eth.vlan_tags.push_back(tag);
        offset += 2;

        ether_type = (static_cast<uint16_t>(frame_bytes[offset]) << 8) | frame_bytes[offset + 1];
        offset += 2;
    }

    out_eth.ether_type = ether_type;
    out_eth.payload = frame_bytes.subspan(offset);
    return DecodeResult::Success;
}

} // namespace engine::decoders
