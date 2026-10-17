#pragma once

#include <span>
#include <cstdint>
#include <string>
#include "engine/decoders/decoder_types.hpp"

namespace engine::decoders {

class IPv6Decoder {
public:
    static DecodeResult decode(
        std::span<const uint8_t> ip_bytes,
        DecodedIPv6& out_ipv6,
        std::string& diagnostic
    );

    static std::string format_ipv6_address(const uint8_t* bytes);
};

} // namespace engine::decoders
