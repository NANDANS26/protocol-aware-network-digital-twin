#pragma once

#include <span>
#include <cstdint>
#include <string>
#include "engine/decoders/decoder_types.hpp"

namespace engine::decoders {

class ArpDecoder {
public:
    static DecodeResult decode(
        std::span<const uint8_t> arp_bytes,
        DecodedArp& out_arp,
        std::string& diagnostic
    );
};

} // namespace engine::decoders
