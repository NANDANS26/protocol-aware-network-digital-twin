#pragma once

#include <span>
#include <cstdint>
#include <string>
#include "engine/decoders/decoder_types.hpp"

namespace engine::decoders {

class IPv4Decoder {
public:
    static DecodeResult decode(
        std::span<const uint8_t> ip_bytes,
        DecodedIPv4& out_ipv4,
        std::string& diagnostic
    );
};

} // namespace engine::decoders
