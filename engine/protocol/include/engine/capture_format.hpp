#pragma once

#include <cstdint>
#include <string>

namespace engine {

enum class LinkType : uint32_t {
    NullLoopback = 0,
    Ethernet = 1,
    AX25 = 3,
    IEEE802_5 = 6,
    ARCNET_BSD = 7,
    SLIP = 8,
    PPP = 9,
    FDDI = 10,
    RawIPv4 = 12,
    RawIPv6 = 14,
    PPP_HDLC = 50,
    PPP_Ether = 51,
    LinuxSLL = 113,      // Linux Cooked Capture v1
    IEEE802_11 = 105,    // Raw 802.11
    LinuxSLL2 = 276,     // Linux Cooked Capture v2
    Unsupported = 0xFFFF
};

inline const char* to_string(LinkType type) {
    switch (type) {
        case LinkType::NullLoopback: return "Null/Loopback";
        case LinkType::Ethernet: return "Ethernet";
        case LinkType::RawIPv4: return "Raw IPv4";
        case LinkType::RawIPv6: return "Raw IPv6";
        case LinkType::LinuxSLL: return "Linux Cooked (SLL)";
        case LinkType::LinuxSLL2: return "Linux Cooked v2 (SLL2)";
        case LinkType::IEEE802_11: return "IEEE 802.11";
        default: return "Unsupported LinkType";
    }
}

enum class TimestampResolution {
    Microsecond,
    Nanosecond
};

struct CaptureInterfaceInfo {
    uint32_t index{0};
    LinkType link_type{LinkType::Ethernet};
    uint32_t snaplen{65535};
    TimestampResolution ts_resolution{TimestampResolution::Microsecond};
    uint64_t ts_resolution_denominator{1000000}; // 10^6 for microsecond
    std::string name;
    std::string description;
};

} // namespace engine
