#pragma once

#include <span>
#include <cstdint>
#include <string>
#include "engine/decoders/decoder_types.hpp"

namespace engine::decoders {

class EthernetDecoder {
public:
    static DecodeResult decode(
        std::span<const uint8_t> frame_bytes,
        DecodedEthernet& out_eth,
        std::string& diagnostic
    );
};

} // namespace engine::decoders
