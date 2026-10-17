#include "engine/decoders/tcp_decoder.hpp"

namespace engine::decoders {

DecodeResult TcpDecoder::decode(
    std::span<const uint8_t> tcp_bytes,
    DecodedTcp& out_tcp,
    std::string& diagnostic
) {
    out_tcp = {};

    if (tcp_bytes.size() < 20) {
        diagnostic = "TCP header truncated: length " + std::to_string(tcp_bytes.size()) + " < 20 bytes";
        return DecodeResult::TruncatedHeader;
    }

    const uint16_t src_port = (static_cast<uint16_t>(tcp_bytes[0]) << 8) | tcp_bytes[1];
    const uint16_t dst_port = (static_cast<uint16_t>(tcp_bytes[2]) << 8) | tcp_bytes[3];
    const uint32_t seq_num  = (static_cast<uint32_t>(tcp_bytes[4]) << 24) |
                              (static_cast<uint32_t>(tcp_bytes[5]) << 16) |
                              (static_cast<uint32_t>(tcp_bytes[6]) << 8)  |
                               static_cast<uint32_t>(tcp_bytes[7]);

    const uint32_t ack_num  = (static_cast<uint32_t>(tcp_bytes[8]) << 24) |
                              (static_cast<uint32_t>(tcp_bytes[9]) << 16) |
                              (static_cast<uint32_t>(tcp_bytes[10]) << 8) |
                               static_cast<uint32_t>(tcp_bytes[11]);

    const uint8_t data_offset_byte = tcp_bytes[12];
    const uint8_t data_offset = data_offset_byte >> 4; // in 32-bit words
    const uint8_t flags = tcp_bytes[13];
    const uint16_t window_size = (static_cast<uint16_t>(tcp_bytes[14]) << 8) | tcp_bytes[15];
    const uint16_t checksum    = (static_cast<uint16_t>(tcp_bytes[16]) << 8) | tcp_bytes[17];
    const uint16_t urg_ptr     = (static_cast<uint16_t>(tcp_bytes[18]) << 8) | tcp_bytes[19];

    if (data_offset < 5) {
        diagnostic = "Invalid TCP data offset: " + std::to_string(data_offset) + " words (minimum is 5 words / 20 bytes)";
        return DecodeResult::InvalidLength;
    }

    const size_t header_len = static_cast<size_t>(data_offset) * 4;
    if (tcp_bytes.size() < header_len) {
        diagnostic = "TCP header truncated by options: length " + std::to_string(tcp_bytes.size()) +
                     " < data_offset " + std::to_string(header_len);
        return DecodeResult::TruncatedHeader;
    }

    out_tcp.source_port = src_port;
    out_tcp.destination_port = dst_port;
    out_tcp.sequence_number = seq_num;
    out_tcp.acknowledgment_number = ack_num;
    out_tcp.data_offset = data_offset;
    out_tcp.window_size = window_size;
    out_tcp.checksum = checksum;
    out_tcp.urgent_pointer = urg_ptr;

    // Flags breakdown
    out_tcp.flag_fin = (flags & 0x01) != 0;
    out_tcp.flag_syn = (flags & 0x02) != 0;
    out_tcp.flag_rst = (flags & 0x04) != 0;
    out_tcp.flag_psh = (flags & 0x08) != 0;
    out_tcp.flag_ack = (flags & 0x10) != 0;
    out_tcp.flag_urg = (flags & 0x20) != 0;
    out_tcp.flag_ece = (flags & 0x40) != 0;
    out_tcp.flag_cwr = (flags & 0x80) != 0;

    // Parse options if header_len > 20
    if (header_len > 20) {
        size_t opt_offset = 20;
        while (opt_offset < header_len) {
            uint8_t kind = tcp_bytes[opt_offset++];
            if (kind == 0) {
                // End of Option List
                break;
            }
            if (kind == 1) {
                // NOP
                continue;
            }
            if (opt_offset >= header_len) {
                break;
            }
            uint8_t len = tcp_bytes[opt_offset++];
            if (len < 2) {
                // Malformed option length
                break;
            }
            size_t data_len = len - 2;
            if (opt_offset + data_len > header_len) {
                // Option length exceeds header bounds
                break;
            }

            TcpOption opt{};
            opt.kind = kind;
            opt.length = len;
            opt.data.assign(tcp_bytes.data() + opt_offset, tcp_bytes.data() + opt_offset + data_len);

            if (kind == 2 && data_len == 2) {
                // MSS
                out_tcp.opt_mss = (static_cast<uint16_t>(opt.data[0]) << 8) | opt.data[1];
            } else if (kind == 3 && data_len == 1) {
                // Window Scale
                out_tcp.opt_window_scale = opt.data[0];
            } else if (kind == 4 && data_len == 0) {
                // SACK Permitted
                out_tcp.opt_sack_permitted = true;
            }

            out_tcp.options.push_back(std::move(opt));
            opt_offset += data_len;
        }
    }

    out_tcp.payload = tcp_bytes.subspan(header_len);
    return DecodeResult::Success;
}

} // namespace engine::decoders
