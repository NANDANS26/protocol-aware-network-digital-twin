#include "engine/decoders/ipv4_decoder.hpp"
#include <sstream>

namespace engine::decoders {

namespace {

uint16_t calculate_checksum(const uint8_t* data, size_t length) {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < length; i += 2) {
        sum += (static_cast<uint32_t>(data[i]) << 8) | data[i + 1];
    }
    if (length % 2 != 0) {
        sum += static_cast<uint32_t>(data[length - 1]) << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

} // namespace

DecodeResult IPv4Decoder::decode(
    std::span<const uint8_t> ip_bytes,
    DecodedIPv4& out_ipv4,
    std::string& diagnostic
) {
    out_ipv4 = {};

    if (ip_bytes.size() < 20) {
        diagnostic = "IPv4 packet truncated: length " + std::to_string(ip_bytes.size()) + " < 20 bytes";
        return DecodeResult::TruncatedHeader;
    }

    const uint8_t ver_ihl = ip_bytes[0];
    const uint8_t version = ver_ihl >> 4;
    const uint8_t ihl = ver_ihl & 0x0F;

    if (version != 4) {
        diagnostic = "Invalid IPv4 version: " + std::to_string(version);
        return DecodeResult::UnsupportedVersion;
    }

    if (ihl < 5) {
        diagnostic = "Invalid IPv4 IHL: " + std::to_string(ihl) + " (minimum is 5 words / 20 bytes)";
        return DecodeResult::InvalidLength;
    }

    const size_t header_len = static_cast<size_t>(ihl) * 4;
    if (ip_bytes.size() < header_len) {
        diagnostic = "IPv4 header truncated by options: length " + std::to_string(ip_bytes.size()) +
                     " < IHL length " + std::to_string(header_len);
        return DecodeResult::TruncatedHeader;
    }

    const uint8_t tos = ip_bytes[1];
    const uint16_t total_len = (static_cast<uint16_t>(ip_bytes[2]) << 8) | ip_bytes[3];
    const uint16_t ident = (static_cast<uint16_t>(ip_bytes[4]) << 8) | ip_bytes[5];
    const uint16_t flags_frag = (static_cast<uint16_t>(ip_bytes[6]) << 8) | ip_bytes[7];
    const uint8_t ttl = ip_bytes[8];
    const uint8_t protocol = ip_bytes[9];
    const uint16_t checksum = (static_cast<uint16_t>(ip_bytes[10]) << 8) | ip_bytes[11];

    out_ipv4.version = 4;
    out_ipv4.ihl = ihl;
    out_ipv4.dscp = tos >> 2;
    out_ipv4.ecn = tos & 0x03;
    out_ipv4.total_length = total_len;
    out_ipv4.identification = ident;
    out_ipv4.flag_df = ((flags_frag >> 14) & 0x01) != 0;
    out_ipv4.flag_mf = ((flags_frag >> 13) & 0x01) != 0;
    out_ipv4.fragment_offset = flags_frag & 0x1FFF;
    out_ipv4.ttl = ttl;
    out_ipv4.protocol = protocol;
    out_ipv4.header_checksum = checksum;
    out_ipv4.is_fragment = out_ipv4.flag_mf || (out_ipv4.fragment_offset > 0);

    // Format IP strings
    out_ipv4.source_ip = std::to_string(ip_bytes[12]) + "." +
                         std::to_string(ip_bytes[13]) + "." +
                         std::to_string(ip_bytes[14]) + "." +
                         std::to_string(ip_bytes[15]);

    out_ipv4.destination_ip = std::to_string(ip_bytes[16]) + "." +
                              std::to_string(ip_bytes[17]) + "." +
                              std::to_string(ip_bytes[18]) + "." +
                              std::to_string(ip_bytes[19]);

    // Checksum verification
    uint16_t csum_res = calculate_checksum(ip_bytes.data(), header_len);
    if (csum_res == 0) {
        out_ipv4.checksum_status = ChecksumStatus::Valid;
    } else {
        out_ipv4.checksum_status = ChecksumStatus::Invalid;
    }

    // Determine payload bounds respecting total_length
    size_t payload_len = 0;
    if (total_len >= header_len) {
        size_t ip_body_len = total_len - header_len;
        size_t available_bytes = ip_bytes.size() - header_len;
        payload_len = (ip_body_len <= available_bytes) ? ip_body_len : available_bytes;
    }

    out_ipv4.payload = ip_bytes.subspan(header_len, payload_len);
    return DecodeResult::Success;
}

} // namespace engine::decoders
