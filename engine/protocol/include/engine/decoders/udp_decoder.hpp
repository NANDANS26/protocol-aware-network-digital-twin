#pragma once

#include <span>
#include <cstdint>
#include <string>
#include "engine/decoders/decoder_types.hpp"

namespace engine::decoders {

class UdpDecoder {
public:
    static DecodeResult decode(
        std::span<const uint8_t> udp_bytes,
        DecodedUdp& out_udp,
        std::string& diagnostic
    );
};

} // namespace engine::decoders
