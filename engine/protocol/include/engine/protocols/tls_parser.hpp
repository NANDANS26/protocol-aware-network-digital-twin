#pragma once

#include <span>
#include <cstdint>
#include <string>
#include <vector>
#include <optional>

namespace engine::protocols {

enum class TlsContentType : uint8_t {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
    Heartbeat = 24,
    Unknown = 0
};

enum class TlsHandshakeType : uint8_t {
    HelloRequest = 0,
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtensions = 8,
    Certificate = 11,
    ServerKeyExchange = 12,
    CertificateRequest = 13,
    ServerHelloDone = 14,
    CertificateVerify = 15,
    ClientKeyExchange = 16,
    Finished = 20,
    KeyUpdate = 24,
    Unknown = 255
};

struct TlsMetadata {
    bool is_tls{false};
    TlsContentType content_type{TlsContentType::Unknown};
    uint16_t record_version{0};
    uint16_t record_length{0};

    // Handshake specifics
    std::optional<TlsHandshakeType> handshake_type;
    std::optional<uint16_t> client_version;
    std::optional<std::string> sni;
    std::vector<uint16_t> offered_ciphers;
    std::optional<uint16_t> selected_cipher;
    std::vector<std::string> alpn_protocols;
    std::optional<std::string> selected_alpn;
    std::optional<std::string> negotiated_version; // e.g. "TLS 1.3", "TLS 1.2"
    bool is_encrypted_application_data{false};
};

class TlsParser {
public:
    static bool parse(
        std::span<const uint8_t> payload,
        TlsMetadata& out_meta,
        std::string& diagnostic
    );

    static std::string format_tls_version(uint16_t version);
    static std::string format_cipher_suite(uint16_t cipher);
};

} // namespace engine::protocols
