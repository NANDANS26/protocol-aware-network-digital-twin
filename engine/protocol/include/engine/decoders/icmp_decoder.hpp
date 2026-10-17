#pragma once

#include <span>
#include <cstdint>
#include <string>
#include "engine/decoders/decoder_types.hpp"

namespace engine::decoders {

class IcmpDecoder {
public:
    static DecodeResult decode(
        std::span<const uint8_t> icmp_bytes,
        bool is_icmpv6,
        DecodedIcmp& out_icmp,
        std::string& diagnostic
    );
};

} // namespace engine::decoders
