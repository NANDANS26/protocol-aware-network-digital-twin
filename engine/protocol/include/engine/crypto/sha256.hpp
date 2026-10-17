#pragma once

#include <span>
#include <cstdint>
#include <string>

namespace engine::crypto {

std::string sha256_hex(std::span<const uint8_t> data);

} // namespace engine::crypto
