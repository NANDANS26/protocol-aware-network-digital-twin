#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <chrono>

namespace engine {

enum class StatusCode {
    Success = 0,
    InvalidConfig,
    SourceOpenFailed,
    ReadError,
    EndOfFile,
    DeviceNotFound,
    PermissionDenied,
    InternalError
};

inline const char* to_string(StatusCode code) {
    switch (code) {
        case StatusCode::Success: return "Success";
        case StatusCode::InvalidConfig: return "InvalidConfig";
        case StatusCode::SourceOpenFailed: return "SourceOpenFailed";
        case StatusCode::ReadError: return "ReadError";
        case StatusCode::EndOfFile: return "EndOfFile";
        case StatusCode::DeviceNotFound: return "DeviceNotFound";
        case StatusCode::PermissionDenied: return "PermissionDenied";
        case StatusCode::InternalError: return "InternalError";
        default: return "Unknown";
    }
}

struct RawPacket {
    uint64_t index{0};
    uint64_t timestamp_ns{0};
    uint32_t wire_length_bytes{0};
    uint32_t capture_length_bytes{0};
    std::vector<uint8_t> data;
};

struct PacketSourceStats {
    uint64_t packets_received{0};
    uint64_t packets_dropped{0};
    uint64_t bytes_received{0};
};

} // namespace engine
