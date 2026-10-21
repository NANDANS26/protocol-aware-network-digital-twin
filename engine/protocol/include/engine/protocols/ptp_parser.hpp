#pragma once

#include <span>
#include <cstdint>
#include <string>

namespace engine::protocols {

enum class PtpMessageType : uint8_t {
    Sync = 0x0,
    Delay_Req = 0x1,
    Pdelay_Req = 0x2,
    Pdelay_Resp = 0x3,
    Follow_Up = 0x8,
    Delay_Resp = 0x9,
    Pdelay_Resp_Follow_Up = 0xA,
    Announce = 0xB,
    Signaling = 0xC,
    Management = 0xD,
    Other = 0xFF
};

inline const char* to_string(PtpMessageType type) {
    switch (type) {
        case PtpMessageType::Sync: return "Sync";
        case PtpMessageType::Delay_Req: return "Delay_Req";
        case PtpMessageType::Pdelay_Req: return "Pdelay_Req";
        case PtpMessageType::Pdelay_Resp: return "Pdelay_Resp";
        case PtpMessageType::Follow_Up: return "Follow_Up";
        case PtpMessageType::Delay_Resp: return "Delay_Resp";
        case PtpMessageType::Pdelay_Resp_Follow_Up: return "Pdelay_Resp_Follow_Up";
        case PtpMessageType::Announce: return "Announce";
        case PtpMessageType::Signaling: return "Signaling";
        case PtpMessageType::Management: return "Management";
        default: return "Unknown";
    }
}

inline PtpMessageType parse_ptp_message_type(uint8_t raw_type) {
    switch (raw_type & 0x0F) {
        case 0x0: return PtpMessageType::Sync;
        case 0x1: return PtpMessageType::Delay_Req;
        case 0x2: return PtpMessageType::Pdelay_Req;
        case 0x3: return PtpMessageType::Pdelay_Resp;
        case 0x8: return PtpMessageType::Follow_Up;
        case 0x9: return PtpMessageType::Delay_Resp;
        case 0xA: return PtpMessageType::Pdelay_Resp_Follow_Up;
        case 0xB: return PtpMessageType::Announce;
        case 0xC: return PtpMessageType::Signaling;
        case 0xD: return PtpMessageType::Management;
        default: return PtpMessageType::Other;
    }
}

struct PtpMessage {
    uint8_t transport_specific{0};
    uint8_t message_type{0};
    std::string message_type_name;
    uint8_t version{2};
    std::string version_name{"PTPv2"};
    uint16_t message_length{0};
    uint8_t domain_number{0};
    uint16_t flag_field{0};
    int64_t correction_field_raw{0};
    double correction_field_ns{0.0};
    std::string source_port_identity;
    uint16_t sequence_id{0};
    uint8_t control_field{0};
    int8_t log_message_interval{0};
};

class PtpParser {
public:
    static bool parse(
        std::span<const uint8_t> payload,
        PtpMessage& out_msg,
        std::string& diagnostic
    );
};

} // namespace engine::protocols
