#pragma once

#include <span>
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <optional>

namespace engine::protocols {

enum class HttpMessageType {
    Unknown,
    Request,
    Response
};

struct HttpHeader {
    std::string name;
    std::string value;
};

struct HttpMessage {
    HttpMessageType type{HttpMessageType::Unknown};
    std::string version{"HTTP/1.1"};

    // Request fields
    std::optional<std::string> method;
    std::optional<std::string> target;

    // Response fields
    std::optional<uint16_t> status_code;
    std::optional<std::string> reason_phrase;

    // Metadata headers
    std::vector<HttpHeader> headers;
    std::optional<std::string> host;
    std::optional<std::string> user_agent;
    std::optional<std::string> content_type;
    std::optional<uint64_t> content_length;
    bool is_chunked{false};
    size_t body_bytes_seen{0};
};

class HttpParser {
public:
    static bool parse(
        std::span<const uint8_t> payload,
        HttpMessage& out_msg,
        std::string& diagnostic
    );

    static bool is_likely_http(std::span<const uint8_t> payload);
};

} // namespace engine::protocols
