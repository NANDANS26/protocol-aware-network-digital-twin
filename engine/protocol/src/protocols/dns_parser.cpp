#include "engine/protocols/dns_parser.hpp"
#include <sstream>

namespace engine::protocols {

namespace {

constexpr int MAX_POINTER_DEPTH = 16;

std::string format_ipv4(const uint8_t* bytes) {
    return std::to_string(bytes[0]) + "." +
           std::to_string(bytes[1]) + "." +
           std::to_string(bytes[2]) + "." +
           std::to_string(bytes[3]);
}

std::string format_ipv6(const uint8_t* bytes) {
    std::ostringstream ss;
    for (int i = 0; i < 8; ++i) {
        if (i > 0) ss << ":";
        uint16_t w = (static_cast<uint16_t>(bytes[i * 2]) << 8) | bytes[i * 2 + 1];
        ss << std::hex << w;
    }
    return ss.str();
}

} // namespace

bool DnsParser::read_name(
    std::span<const uint8_t> msg_bytes,
    size_t& offset,
    std::string& out_name,
    int recursion_depth
) {
    if (recursion_depth > MAX_POINTER_DEPTH) {
        return false; // Pointer loop detected
    }

    size_t cur = offset;
    bool jumped = false;
    size_t jump_end = 0;
    out_name.clear();

    while (cur < msg_bytes.size()) {
        uint8_t len = msg_bytes[cur];

        if (len == 0) {
            // Null terminator for root label
            cur++;
            if (!jumped) {
                offset = cur;
            }
            return true;
        }

        if ((len & 0xC0) == 0xC0) {
            // Pointer to another location in message
            if (cur + 1 >= msg_bytes.size()) {
                return false;
            }
            uint16_t ptr_offset = ((static_cast<uint16_t>(len & 0x3F)) << 8) | msg_bytes[cur + 1];
            if (!jumped) {
                jump_end = cur + 2;
                jumped = true;
            }
            cur = ptr_offset;
            recursion_depth++;
            if (recursion_depth > MAX_POINTER_DEPTH) {
                return false;
            }
            continue;
        }

        // Standard label: 1..63 octets
        cur++;
        if (cur + len > msg_bytes.size()) {
            return false;
        }

        if (!out_name.empty()) {
            out_name.push_back('.');
        }
        out_name.append(reinterpret_cast<const char*>(msg_bytes.data() + cur), len);
        cur += len;

        if (!jumped) {
            offset = cur;
        }
    }

    if (jumped) {
        offset = jump_end;
    }
    return true;
}

bool DnsParser::parse(
    std::span<const uint8_t> payload,
    bool is_tcp,
    DnsMessage& out_msg,
    std::string& diagnostic
) {
    out_msg = {};

    size_t offset = 0;
    if (is_tcp) {
        if (payload.size() < 2) {
            diagnostic = "TCP DNS payload truncated: missing length prefix";
            return false;
        }
        uint16_t tcp_len = (static_cast<uint16_t>(payload[0]) << 8) | payload[1];
        offset = 2;
        if (payload.size() - 2 < tcp_len) {
            diagnostic = "TCP DNS message truncated: length " + std::to_string(payload.size() - 2) + " < " + std::to_string(tcp_len);
            return false;
        }
    }

    std::span<const uint8_t> dns_data = payload.subspan(offset);

    // DNS Header is 12 bytes
    if (dns_data.size() < 12) {
        diagnostic = "DNS header truncated: length " + std::to_string(dns_data.size()) + " < 12 bytes";
        return false;
    }

    out_msg.transaction_id = (static_cast<uint16_t>(dns_data[0]) << 8) | dns_data[1];
    const uint16_t flags = (static_cast<uint16_t>(dns_data[2]) << 8) | dns_data[3];
    const uint16_t qdcount = (static_cast<uint16_t>(dns_data[4]) << 8) | dns_data[5];
    const uint16_t ancount = (static_cast<uint16_t>(dns_data[6]) << 8) | dns_data[7];
    const uint16_t nscount = (static_cast<uint16_t>(dns_data[8]) << 8) | dns_data[9];
    const uint16_t arcount = (static_cast<uint16_t>(dns_data[10]) << 8) | dns_data[11];

    out_msg.is_response = (flags & 0x8000) != 0;
    out_msg.opcode = static_cast<uint8_t>((flags >> 11) & 0x0F);
    out_msg.authoritative = (flags & 0x0400) != 0;
    out_msg.truncated = (flags & 0x0200) != 0;
    out_msg.recursion_desired = (flags & 0x0100) != 0;
    out_msg.recursion_available = (flags & 0x0080) != 0;
    out_msg.response_code = static_cast<uint8_t>(flags & 0x000F);

    size_t cur = 12;

    // 1. Parse Question Section
    for (uint16_t i = 0; i < qdcount; ++i) {
        DnsQuestion q{};
        if (!read_name(dns_data, cur, q.name)) {
            diagnostic = "Failed parsing DNS Question name at index " + std::to_string(i);
            return false;
        }
        if (cur + 4 > dns_data.size()) {
            diagnostic = "Truncated DNS Question type/class";
            return false;
        }
        uint16_t qtype = (static_cast<uint16_t>(dns_data[cur]) << 8) | dns_data[cur + 1];
        uint16_t qclass = (static_cast<uint16_t>(dns_data[cur + 2]) << 8) | dns_data[cur + 3];
        cur += 4;
        q.type = parse_dns_type(qtype);
        q.qclass = qclass;
        out_msg.questions.push_back(std::move(q));
    }

    // Lambda to parse Resource Records
    auto parse_rr_section = [&](uint16_t count, std::vector<DnsResourceRecord>& out_vec) -> bool {
        for (uint16_t i = 0; i < count; ++i) {
            DnsResourceRecord rr{};
            if (!read_name(dns_data, cur, rr.name)) {
                return false;
            }
            if (cur + 10 > dns_data.size()) {
                return false;
            }
            uint16_t rtype = (static_cast<uint16_t>(dns_data[cur]) << 8) | dns_data[cur + 1];
            uint16_t rclass = (static_cast<uint16_t>(dns_data[cur + 2]) << 8) | dns_data[cur + 3];
            uint32_t ttl = (static_cast<uint32_t>(dns_data[cur + 4]) << 24) |
                           (static_cast<uint32_t>(dns_data[cur + 5]) << 16) |
                           (static_cast<uint32_t>(dns_data[cur + 6]) << 8)  |
                            static_cast<uint32_t>(dns_data[cur + 7]);
            uint16_t rdlen = (static_cast<uint16_t>(dns_data[cur + 8]) << 8) | dns_data[cur + 9];
            cur += 10;

            if (cur + rdlen > dns_data.size()) {
                return false;
            }

            rr.type = parse_dns_type(rtype);
            rr.rclass = rclass;
            rr.ttl = ttl;
            rr.rdlength = rdlen;

            if (rr.type == DnsType::A && rdlen == 4) {
                rr.rdata_string = format_ipv4(dns_data.data() + cur);
            } else if (rr.type == DnsType::AAAA && rdlen == 16) {
                rr.rdata_string = format_ipv6(dns_data.data() + cur);
            } else if (rr.type == DnsType::CNAME || rr.type == DnsType::NS || rr.type == DnsType::PTR) {
                size_t cname_offset = cur;
                std::string target_domain;
                if (read_name(dns_data, cname_offset, target_domain)) {
                    rr.rdata_string = target_domain;
                }
            } else if (rr.type == DnsType::TXT && rdlen > 0) {
                uint8_t txt_len = dns_data[cur];
                if (txt_len + 1 <= rdlen) {
                    rr.rdata_string.assign(reinterpret_cast<const char*>(dns_data.data() + cur + 1), txt_len);
                }
            } else {
                rr.rdata_string = "[binary " + std::to_string(rdlen) + " bytes]";
            }

            cur += rdlen;
            out_vec.push_back(std::move(rr));
        }
        return true;
    };

    // 2. Parse Answers
    if (!parse_rr_section(ancount, out_msg.answers)) {
        return true; // Partial decode returned gracefully
    }

    // 3. Parse Authority Records
    if (!parse_rr_section(nscount, out_msg.authorities)) {
        return true;
    }

    // 4. Parse Additional Records
    parse_rr_section(arcount, out_msg.additionals);

    return true;
}

} // namespace engine::protocols
