#include "engine/decoders/decoder_types.hpp"
#include <iomanip>
#include <sstream>

namespace engine::decoders {

std::string MacAddress::to_string() const {
    std::ostringstream ss;
    for (int i = 0; i < 6; ++i) {
        if (i > 0) ss << ":";
        ss << std::hex << std::uppercase << std::setfill('0') << std::setw(2)
           << static_cast<int>(bytes[i]);
    }
    return ss.str();
}

bool MacAddress::is_broadcast() const {
    return bytes[0] == 0xFF && bytes[1] == 0xFF && bytes[2] == 0xFF &&
           bytes[3] == 0xFF && bytes[4] == 0xFF && bytes[5] == 0xFF;
}

bool MacAddress::is_multicast() const {
    return (bytes[0] & 0x01) != 0;
}

} // namespace engine::decoders
