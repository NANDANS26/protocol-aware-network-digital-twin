#include "engine/decoders/ipv6_decoder.hpp"
#include <iomanip>
#include <sstream>

namespace engine::decoders {

std::string IPv6Decoder::format_ipv6_address(const uint8_t* bytes) {
    uint16_t words[8];
    for (int i = 0; i < 8; ++i) {
        words[i] = (static_cast<uint16_t>(bytes[i * 2]) << 8) | bytes[i * 2 + 1];
    }

    // Find longest run of zeros for RFC 5952 compression
    int best_start = -1;
    int best_len = 0;
    int cur_start = -1;
    int cur_len = 0;

    for (int i = 0; i < 8; ++i) {
        if (words[i] == 0) {
            if (cur_start == -1) {
                cur_start = i;
                cur_len = 1;
            } else {
                cur_len++;
            }
        } else {
            if (cur_len > best_len) {
                best_start = cur_start;
                best_len = cur_len;
            }
            cur_start = -1;
            cur_len = 0;
        }
    }
    if (cur_len > best_len) {
        best_start = cur_start;
        best_len = cur_len;
    }

    // Only compress if run is > 1 zero word
    if (best_len <= 1) {
        best_start = -1;
    }

    std::ostringstream ss;
    for (int i = 0; i < 8; ++i) {
        if (best_start != -1 && i >= best_start && i < best_start + best_len) {
            if (i == best_start) {
                ss << "::";
            }
            continue;
        }
        if (i > 0 && !(best_start != -1 && i == best_start + best_len)) {
            if (ss.str().back() != ':') {
                ss << ":";
            }
        }
        ss << std::hex << words[i];
    }
    return ss.str();
}

DecodeResult IPv6Decoder::decode(
    std::span<const uint8_t> ip_bytes,
    DecodedIPv6& out_ipv6,
    std::string& diagnostic
) {
    out_ipv6 = {};

    if (ip_bytes.size() < 40) {
        diagnostic = "IPv6 packet truncated: length " + std::to_string(ip_bytes.size()) + " < 40 bytes";
        return DecodeResult::TruncatedHeader;
    }

    const uint32_t first_word = (static_cast<uint32_t>(ip_bytes[0]) << 24) |
                                (static_cast<uint32_t>(ip_bytes[1]) << 16) |
                                (static_cast<uint32_t>(ip_bytes[2]) << 8)  |
                                 static_cast<uint32_t>(ip_bytes[3]);

    const uint8_t version = (first_word >> 28) & 0x0F;
    if (version != 6) {
        diagnostic = "Invalid IPv6 version: " + std::to_string(version);
        return DecodeResult::UnsupportedVersion;
    }

    out_ipv6.version = 6;
    out_ipv6.traffic_class = static_cast<uint8_t>((first_word >> 20) & 0xFF);
    out_ipv6.flow_label = first_word & 0x000FFFFF;
    out_ipv6.payload_length = (static_cast<uint16_t>(ip_bytes[4]) << 8) | ip_bytes[5];
    out_ipv6.next_header = ip_bytes[6];
    out_ipv6.hop_limit = ip_bytes[7];

    out_ipv6.source_ip = format_ipv6_address(ip_bytes.data() + 8);
    out_ipv6.destination_ip = format_ipv6_address(ip_bytes.data() + 24);

    size_t offset = 40;
    uint8_t current_proto = out_ipv6.next_header;
    size_t ext_count = 0;
    constexpr size_t MAX_EXT_HEADERS = 8;

    while (ext_count < MAX_EXT_HEADERS) {
        // Extension header numbers: 0=Hop-by-hop, 43=Routing, 44=Fragment, 50=ESP, 51=AH, 60=DestOpts, 135=Mobility
        if (current_proto == 0 || current_proto == 43 || current_proto == 60 || current_proto == 135) {
            if (offset + 2 > ip_bytes.size()) {
                diagnostic = "Truncated IPv6 extension header";
                return DecodeResult::TruncatedHeader;
            }
            uint8_t next = ip_bytes[offset];
            uint8_t hdr_len_units = ip_bytes[offset + 1];
            size_t ext_hdr_len = (static_cast<size_t>(hdr_len_units) + 1) * 8;
            if (offset + ext_hdr_len > ip_bytes.size()) {
                diagnostic = "IPv6 extension header length exceeds packet bounds";
                return DecodeResult::InvalidLength;
            }
            out_ipv6.extension_headers.push_back({current_proto, static_cast<uint16_t>(ext_hdr_len)});
            offset += ext_hdr_len;
            current_proto = next;
            ext_count++;
        } else if (current_proto == 44) {
            // Fragment Header: Next(1), Reserved(1), FragOffset/M(2), Id(4) = 8 bytes fixed
            if (offset + 8 > ip_bytes.size()) {
                diagnostic = "Truncated IPv6 Fragment header";
                return DecodeResult::TruncatedHeader;
            }
            uint8_t next = ip_bytes[offset];
            uint16_t frag_field = (static_cast<uint16_t>(ip_bytes[offset + 2]) << 8) | ip_bytes[offset + 3];
            uint32_t ident = (static_cast<uint32_t>(ip_bytes[offset + 4]) << 24) |
                             (static_cast<uint32_t>(ip_bytes[offset + 5]) << 16) |
                             (static_cast<uint32_t>(ip_bytes[offset + 6]) << 8)  |
                              static_cast<uint32_t>(ip_bytes[offset + 7]);

            out_ipv6.is_fragment = true;
            out_ipv6.fragment_offset = frag_field & 0xFFF8;
            out_ipv6.fragment_m_flag = (frag_field & 0x0001) != 0;
            out_ipv6.fragment_id = ident;
            out_ipv6.extension_headers.push_back({current_proto, 8});
            offset += 8;
            current_proto = next;
            ext_count++;
        } else if (current_proto == 51) {
            // AH: Next(1), Len(1 in 4-byte units minus 2)
            if (offset + 2 > ip_bytes.size()) {
                return DecodeResult::TruncatedHeader;
            }
            uint8_t next = ip_bytes[offset];
            uint8_t payload_len = ip_bytes[offset + 1];
            size_t ah_len = (static_cast<size_t>(payload_len) + 2) * 4;
            if (offset + ah_len > ip_bytes.size()) {
                return DecodeResult::InvalidLength;
            }
            out_ipv6.extension_headers.push_back({current_proto, static_cast<uint16_t>(ah_len)});
            offset += ah_len;
            current_proto = next;
            ext_count++;
        } else {
            // Non-extension header reached (e.g. TCP 6, UDP 17, ICMPv6 58, ESP 50, etc.)
            break;
        }
    }

    out_ipv6.upper_layer_protocol = current_proto;

    size_t payload_len = (offset <= ip_bytes.size()) ? (ip_bytes.size() - offset) : 0;
    out_ipv6.payload = ip_bytes.subspan(offset, payload_len);
    return DecodeResult::Success;
}

} // namespace engine::decoders
