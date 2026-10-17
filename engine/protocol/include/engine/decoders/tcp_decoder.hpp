#pragma once

#include <span>
#include <cstdint>
#include <string>
#include "engine/decoders/decoder_types.hpp"

namespace engine::decoders {

class TcpDecoder {
public:
    static DecodeResult decode(
        std::span<const uint8_t> tcp_bytes,
        DecodedTcp& out_tcp,
        std::string& diagnostic
    );
};

} // namespace engine::decoders
