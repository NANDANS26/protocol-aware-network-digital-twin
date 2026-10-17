#pragma once

#include <span>
#include <cstdint>
#include <string>
#include <vector>
#include <optional>

namespace engine::protocols {

enum class DnsType : uint16_t {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    ANY = 255,
    OTHER = 0
};

inline const char* to_string(DnsType type) {
    switch (type) {
        case DnsType::A: return "A";
        case DnsType::NS: return "NS";
        case DnsType::CNAME: return "CNAME";
        case DnsType::SOA: return "SOA";
        case DnsType::PTR: return "PTR";
        case DnsType::MX: return "MX";
        case DnsType::TXT: return "TXT";
        case DnsType::AAAA: return "AAAA";
        case DnsType::SRV: return "SRV";
        case DnsType::ANY: return "ANY";
        default: return "OTHER";
    }
}

inline DnsType parse_dns_type(uint16_t val) {
    switch (val) {
        case 1: return DnsType::A;
        case 2: return DnsType::NS;
        case 5: return DnsType::CNAME;
        case 6: return DnsType::SOA;
        case 12: return DnsType::PTR;
        case 15: return DnsType::MX;
        case 16: return DnsType::TXT;
        case 28: return DnsType::AAAA;
        case 33: return DnsType::SRV;
        case 255: return DnsType::ANY;
        default: return DnsType::OTHER;
    }
}

struct DnsQuestion {
    std::string name;
    DnsType type{DnsType::A};
    uint16_t qclass{1}; // 1 = IN (Internet)
};

struct DnsResourceRecord {
    std::string name;
    DnsType type{DnsType::A};
    uint16_t rclass{1};
    uint32_t ttl{0};
    uint16_t rdlength{0};
    std::string rdata_string; // Formatted IPv4, IPv6, domain, or text
};

struct DnsMessage {
    uint16_t transaction_id{0};
    bool is_response{false};
    uint8_t opcode{0};
    bool authoritative{false};
    bool truncated{false};
    bool recursion_desired{false};
    bool recursion_available{false};
    uint8_t response_code{0}; // 0 = NOERROR, 3 = NXDOMAIN, etc.
    std::vector<DnsQuestion> questions;
    std::vector<DnsResourceRecord> answers;
    std::vector<DnsResourceRecord> authorities;
    std::vector<DnsResourceRecord> additionals;
};

class DnsParser {
public:
    static bool parse(
        std::span<const uint8_t> payload,
        bool is_tcp,
        DnsMessage& out_msg,
        std::string& diagnostic
    );

    static bool read_name(
        std::span<const uint8_t> msg_bytes,
        size_t& offset,
        std::string& out_name,
        int recursion_depth = 0
    );
};

} // namespace engine::protocols
