#include "engine/decoders/udp_decoder.hpp"

namespace engine::decoders {

DecodeResult UdpDecoder::decode(
    std::span<const uint8_t> udp_bytes,
    DecodedUdp& out_udp,
    std::string& diagnostic
) {
    out_udp = {};

    if (udp_bytes.size() < 8) {
        diagnostic = "UDP header truncated: length " + std::to_string(udp_bytes.size()) + " < 8 bytes";
        return DecodeResult::TruncatedHeader;
    }

    const uint16_t src_port = (static_cast<uint16_t>(udp_bytes[0]) << 8) | udp_bytes[1];
    const uint16_t dst_port = (static_cast<uint16_t>(udp_bytes[2]) << 8) | udp_bytes[3];
    const uint16_t length   = (static_cast<uint16_t>(udp_bytes[4]) << 8) | udp_bytes[5];
    const uint16_t checksum = (static_cast<uint16_t>(udp_bytes[6]) << 8) | udp_bytes[7];

    if (length < 8) {
        diagnostic = "Invalid UDP length field: " + std::to_string(length) + " < 8 bytes";
        return DecodeResult::InvalidLength;
    }

    out_udp.source_port = src_port;
    out_udp.destination_port = dst_port;
    out_udp.length = length;
    out_udp.checksum = checksum;

    // Checksum: in IPv4 UDP, checksum=0 means transmitter did not compute checksum
    if (checksum == 0) {
        out_udp.checksum_status = ChecksumStatus::NotApplicable;
    } else {
        out_udp.checksum_status = ChecksumStatus::Indeterminate;
    }

    size_t payload_len = 0;
    size_t declared_payload_len = length - 8;
    size_t available_payload_bytes = udp_bytes.size() - 8;
    payload_len = (declared_payload_len <= available_payload_bytes) ? declared_payload_len : available_payload_bytes;

    out_udp.payload = udp_bytes.subspan(8, payload_len);
    return DecodeResult::Success;
}

} // namespace engine::decoders
