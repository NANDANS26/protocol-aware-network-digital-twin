#include "engine/protocols/ptp_parser.hpp"
#include <iomanip>
#include <sstream>

namespace engine::protocols {

bool PtpParser::parse(
    std::span<const uint8_t> payload,
    PtpMessage& out_msg,
    std::string& diagnostic
) {
    // Standard PTPv2 header is 34 bytes
    if (payload.size() < 34) {
        diagnostic = "PTP payload too short: " + std::to_string(payload.size()) + " < 34 bytes";
        return false;
    }

    const uint8_t byte0 = payload[0];
    const uint8_t byte1 = payload[1];

    out_msg.transport_specific = (byte0 >> 4) & 0x0F;
    out_msg.message_type = byte0 & 0x0F;

    // Validate message type (0-3, 8-D)
    PtpMessageType mtype = parse_ptp_message_type(out_msg.message_type);
    if (mtype == PtpMessageType::Other) {
        diagnostic = "Invalid PTP message type: " + std::to_string(out_msg.message_type);
        return false;
    }
    out_msg.message_type_name = to_string(mtype);

    out_msg.version = byte1 & 0x0F;
    if (out_msg.version == 2) {
        out_msg.version_name = "PTPv2";
    } else if (out_msg.version == 1) {
        out_msg.version_name = "PTPv1";
    } else {
        diagnostic = "Unsupported PTP version: " + std::to_string(out_msg.version);
        return false;
    }

    out_msg.message_length = (static_cast<uint16_t>(payload[2]) << 8) | payload[3];
    // Length check: message_length must be at least 34 bytes
    if (out_msg.message_length < 34) {
        diagnostic = "Invalid PTP message length: " + std::to_string(out_msg.message_length);
        return false;
    }

    out_msg.domain_number = payload[4];
    out_msg.flag_field = (static_cast<uint16_t>(payload[6]) << 8) | payload[7];

    // Correction field: 64-bit signed integer (scaled nanoseconds)
    uint64_t corr_raw = 0;
    for (size_t i = 8; i < 16; ++i) {
        corr_raw = (corr_raw << 8) | payload[i];
    }
    out_msg.correction_field_raw = static_cast<int64_t>(corr_raw);
    out_msg.correction_field_ns = static_cast<double>(out_msg.correction_field_raw) / 65536.0;

    // Source Port Identity (bytes 20..29: 8 bytes clockIdentity, 2 bytes portNumber)
    std::ostringstream sp_id;
    for (size_t i = 20; i < 28; ++i) {
        if (i > 20) sp_id << ":";
        sp_id << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(payload[i]);
    }
    uint16_t port_num = (static_cast<uint16_t>(payload[28]) << 8) | payload[29];
    sp_id << "/" << std::dec << port_num;
    out_msg.source_port_identity = sp_id.str();

    // Sequence ID (bytes 30..31)
    out_msg.sequence_id = (static_cast<uint16_t>(payload[30]) << 8) | payload[31];

    out_msg.control_field = payload[32];
    out_msg.log_message_interval = static_cast<int8_t>(payload[33]);

    return true;
}

} // namespace engine::protocols
