#include "engine/protocols/http_parser.hpp"
#include <algorithm>
#include <cctype>
#include <sstream>

namespace engine::protocols {

namespace {

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, (last - first + 1));
}

} // namespace

bool HttpParser::is_likely_http(std::span<const uint8_t> payload) {
    if (payload.size() < 4) return false;

    // Check for common HTTP methods
    if (payload.size() >= 4 && std::memcmp(payload.data(), "GET ", 4) == 0) return true;
    if (payload.size() >= 5 && std::memcmp(payload.data(), "POST ", 5) == 0) return true;
    if (payload.size() >= 4 && std::memcmp(payload.data(), "PUT ", 4) == 0) return true;
    if (payload.size() >= 7 && std::memcmp(payload.data(), "DELETE ", 7) == 0) return true;
    if (payload.size() >= 5 && std::memcmp(payload.data(), "HEAD ", 5) == 0) return true;
    if (payload.size() >= 8 && std::memcmp(payload.data(), "OPTIONS ", 8) == 0) return true;
    if (payload.size() >= 6 && std::memcmp(payload.data(), "PATCH ", 6) == 0) return true;

    // Check for HTTP response signature: "HTTP/1." or "HTTP/2"
    if (payload.size() >= 7 && std::memcmp(payload.data(), "HTTP/1.", 7) == 0) return true;
    if (payload.size() >= 6 && std::memcmp(payload.data(), "HTTP/2", 6) == 0) return true;

    return false;
}

bool HttpParser::parse(
    std::span<const uint8_t> payload,
    HttpMessage& out_msg,
    std::string& diagnostic
) {
    out_msg = {};

    if (!is_likely_http(payload)) {
        diagnostic = "Payload does not match HTTP/1.x framing signature";
        return false;
    }

    // Convert span to string view or parse line by line up to double CRLF
    std::string text(reinterpret_cast<const char*>(payload.data()), std::min(payload.size(), size_t(8192)));
    std::istringstream stream(text);
    std::string start_line;

    if (!std::getline(stream, start_line)) {
        diagnostic = "Truncated HTTP start line";
        return false;
    }

    start_line = trim(start_line);
    if (start_line.empty()) {
        return false;
    }

    // 1. Check if Request or Response
    if (start_line.rfind("HTTP/1.", 0) == 0) {
        // Response: HTTP/1.1 200 OK
        out_msg.type = HttpMessageType::Response;
        std::istringstream line_stream(start_line);
        std::string ver, code_str, reason;
        line_stream >> ver >> code_str;
        std::getline(line_stream, reason);

        out_msg.version = ver;
        try {
            out_msg.status_code = static_cast<uint16_t>(std::stoul(code_str));
        } catch (...) {
            out_msg.status_code = 0;
        }
        out_msg.reason_phrase = trim(reason);
    } else {
        // Request: GET /index.html HTTP/1.1
        std::istringstream line_stream(start_line);
        std::string method, target, ver;
        line_stream >> method >> target >> ver;

        if (method.empty() || target.empty()) {
            diagnostic = "Malformed HTTP request line: " + start_line;
            return false;
        }

        out_msg.type = HttpMessageType::Request;
        out_msg.method = method;
        out_msg.target = target;
        out_msg.version = ver.empty() ? "HTTP/1.1" : ver;
    }

    // 2. Parse Headers
    std::string line;
    while (std::getline(stream, line)) {
        line = trim(line);
        if (line.empty()) {
            // End of headers (\r\n\r\n reached)
            break;
        }

        size_t colon_pos = line.find(':');
        if (colon_pos == std::string::npos) {
            continue;
        }

        std::string name = trim(line.substr(0, colon_pos));
        std::string value = trim(line.substr(colon_pos + 1));
        std::string lower_name = to_lower(name);

        // Security rule: Never record sensitive credential headers
        if (lower_name == "authorization" || lower_name == "proxy-authorization" ||
            lower_name == "cookie" || lower_name == "set-cookie") {
            out_msg.headers.push_back({name, "[REDACTED]"});
            continue;
        }

        if (lower_name == "host") {
            out_msg.host = value;
        } else if (lower_name == "user-agent") {
            out_msg.user_agent = value;
        } else if (lower_name == "content-type") {
            out_msg.content_type = value;
        } else if (lower_name == "content-length") {
            try {
                out_msg.content_length = std::stoull(value);
            } catch (...) {}
        } else if (lower_name == "transfer-encoding" && to_lower(value).find("chunked") != std::string::npos) {
            out_msg.is_chunked = true;
        }

        out_msg.headers.push_back({name, value});
    }

    return true;
}

} // namespace engine::protocols
