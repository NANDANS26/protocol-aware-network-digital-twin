#include "engine/protocols/tls_parser.hpp"
#include <sstream>
#include <iomanip>
#include <unordered_map>

namespace engine::protocols {

namespace {

uint16_t read_u16(const uint8_t* p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

uint32_t read_u24(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 16) |
           (static_cast<uint32_t>(p[1]) << 8) |
            static_cast<uint32_t>(p[2]);
}

} // namespace

std::string TlsParser::format_tls_version(uint16_t version) {
    switch (version) {
        case 0x0304: return "TLS 1.3";
        case 0x0303: return "TLS 1.2";
        case 0x0302: return "TLS 1.1";
        case 0x0301: return "TLS 1.0";
        case 0x0300: return "SSL 3.0";
        default: {
            std::ostringstream oss;
            oss << "0x" << std::hex << std::setw(4) << std::setfill('0') << version;
            return oss.str();
        }
    }
}

std::string TlsParser::format_cipher_suite(uint16_t cipher) {
    static const std::unordered_map<uint16_t, std::string> ciphers = {
        {0x1301, "TLS_AES_128_GCM_SHA256"},
        {0x1302, "TLS_AES_256_GCM_SHA384"},
        {0x1303, "TLS_CHACHA20_POLY1305_SHA256"},
        {0x1304, "TLS_AES_128_CCM_SHA256"},
        {0x1305, "TLS_AES_128_CCM_8_SHA256"},
        {0xc02b, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
        {0xc02c, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"},
        {0xc02f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
        {0xc030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
        {0xcca8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"},
        {0xcca9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"},
        {0x009c, "TLS_RSA_WITH_AES_128_GCM_SHA256"},
        {0x009d, "TLS_RSA_WITH_AES_256_GCM_SHA384"},
        {0x002f, "TLS_RSA_WITH_AES_128_CBC_SHA"},
        {0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA"}
    };

    auto it = ciphers.find(cipher);
    if (it != ciphers.end()) {
        return it->second;
    }
    std::ostringstream oss;
    oss << "0x" << std::hex << std::setw(4) << std::setfill('0') << cipher;
    return oss.str();
}

bool TlsParser::parse(
    std::span<const uint8_t> payload,
    TlsMetadata& out_meta,
    std::string& diagnostic
) {
    out_meta = TlsMetadata{};

    // Minimal TLS record is 5 bytes: ContentType (1) + Version (2) + Length (2)
    if (payload.size() < 5) {
        diagnostic = "Payload too short for TLS record header";
        return false;
    }

    uint8_t raw_type = payload[0];
    if (raw_type < 20 || raw_type > 24) {
        diagnostic = "Invalid TLS content type";
        return false;
    }

    uint16_t record_ver = read_u16(payload.data() + 1);
    // Legacy record version is typically 0x0301 (TLS 1.0) to 0x0304 (TLS 1.3), or 0x0300 (SSL 3.0)
    if (record_ver < 0x0300 || record_ver > 0x0304) {
        diagnostic = "Invalid TLS record version";
        return false;
    }

    uint16_t record_len = read_u16(payload.data() + 3);

    out_meta.is_tls = true;
    out_meta.content_type = static_cast<TlsContentType>(raw_type);
    out_meta.record_version = record_ver;
    out_meta.record_length = record_len;

    if (out_meta.content_type == TlsContentType::ApplicationData) {
        out_meta.is_encrypted_application_data = true;
        return true;
    }

    if (out_meta.content_type != TlsContentType::Handshake) {
        return true;
    }

    // Handshake parsing
    size_t offset = 5;
    if (payload.size() < offset + 4) {
        diagnostic = "Truncated TLS handshake header";
        return true; // Still TLS
    }

    uint8_t hs_type_raw = payload[offset];
    uint32_t hs_len = read_u24(payload.data() + offset + 1);
    offset += 4;

    out_meta.handshake_type = static_cast<TlsHandshakeType>(hs_type_raw);

    if (out_meta.handshake_type == TlsHandshakeType::ClientHello) {
        // ClientHello
        if (payload.size() < offset + 2 + 32 + 1) {
            diagnostic = "Truncated ClientHello";
            return true;
        }

        uint16_t client_ver = read_u16(payload.data() + offset);
        out_meta.client_version = client_ver;
        out_meta.negotiated_version = format_tls_version(client_ver);
        offset += 2; // version
        offset += 32; // random

        uint8_t session_id_len = payload[offset];
        offset += 1;
        if (payload.size() < offset + session_id_len + 2) {
            diagnostic = "Truncated ClientHello after session ID";
            return true;
        }
        offset += session_id_len;

        uint16_t cipher_suites_len = read_u16(payload.data() + offset);
        offset += 2;

        if (payload.size() < offset + cipher_suites_len + 1) {
            diagnostic = "Truncated ClientHello cipher suites";
            return true;
        }

        size_t num_ciphers = cipher_suites_len / 2;
        for (size_t i = 0; i < num_ciphers && offset + 2 <= payload.size(); ++i) {
            uint16_t c = read_u16(payload.data() + offset);
            out_meta.offered_ciphers.push_back(c);
            offset += 2;
        }

        if (offset >= payload.size()) return true;
        uint8_t comp_len = payload[offset];
        offset += 1;
        offset += comp_len;

        // Extensions
        if (offset + 2 <= payload.size()) {
            uint16_t extensions_len = read_u16(payload.data() + offset);
            offset += 2;
            size_t ext_end = std::min(payload.size(), offset + extensions_len);

            while (offset + 4 <= ext_end) {
                uint16_t ext_type = read_u16(payload.data() + offset);
                uint16_t ext_len = read_u16(payload.data() + offset + 2);
                offset += 4;

                if (offset + ext_len > ext_end) {
                    break;
                }

                if (ext_type == 0) { // server_name (SNI)
                    if (ext_len >= 5) {
                        uint16_t list_len = read_u16(payload.data() + offset);
                        if (list_len >= 3 && offset + 2 + list_len <= ext_end) {
                            uint8_t name_type = payload[offset + 2];
                            if (name_type == 0) { // host_name
                                uint16_t name_len = read_u16(payload.data() + offset + 3);
                                if (offset + 5 + name_len <= ext_end) {
                                    out_meta.sni = std::string(
                                        reinterpret_cast<const char*>(payload.data() + offset + 5),
                                        name_len
                                    );
                                }
                            }
                        }
                    }
                } else if (ext_type == 16) { // ALPN
                    if (ext_len >= 2) {
                        uint16_t alpn_list_len = read_u16(payload.data() + offset);
                        size_t a_off = offset + 2;
                        size_t a_end = std::min(ext_end, a_off + alpn_list_len);
                        while (a_off + 1 <= a_end) {
                            uint8_t proto_len = payload[a_off];
                            a_off += 1;
                            if (a_off + proto_len <= a_end) {
                                out_meta.alpn_protocols.emplace_back(
                                    reinterpret_cast<const char*>(payload.data() + a_off),
                                    proto_len
                                );
                                a_off += proto_len;
                            } else {
                                break;
                            }
                        }
                    }
                } else if (ext_type == 43) { // supported_versions (TLS 1.3)
                    if (ext_len >= 1) {
                        uint8_t vers_len = payload[offset];
                        size_t v_off = offset + 1;
                        size_t v_end = std::min(ext_end, v_off + vers_len);
                        while (v_off + 2 <= v_end) {
                            uint16_t ver = read_u16(payload.data() + v_off);
                            if (ver == 0x0304) {
                                out_meta.negotiated_version = "TLS 1.3";
                            }
                            v_off += 2;
                        }
                    }
                }

                offset += ext_len;
            }
        }
    } else if (out_meta.handshake_type == TlsHandshakeType::ServerHello) {
        // ServerHello
        if (payload.size() < offset + 2 + 32 + 1) {
            diagnostic = "Truncated ServerHello";
            return true;
        }

        uint16_t server_ver = read_u16(payload.data() + offset);
        out_meta.negotiated_version = format_tls_version(server_ver);
        offset += 2; // version
        offset += 32; // random

        uint8_t session_id_len = payload[offset];
        offset += 1;
        if (payload.size() < offset + session_id_len + 2) {
            diagnostic = "Truncated ServerHello after session ID";
            return true;
        }
        offset += session_id_len;

        uint16_t cipher = read_u16(payload.data() + offset);
        out_meta.selected_cipher = cipher;
        offset += 2;

        if (offset < payload.size()) {
            offset += 1; // compression method
        }

        // Extensions
        if (offset + 2 <= payload.size()) {
            uint16_t extensions_len = read_u16(payload.data() + offset);
            offset += 2;
            size_t ext_end = std::min(payload.size(), offset + extensions_len);

            while (offset + 4 <= ext_end) {
                uint16_t ext_type = read_u16(payload.data() + offset);
                uint16_t ext_len = read_u16(payload.data() + offset + 2);
                offset += 4;

                if (offset + ext_len > ext_end) {
                    break;
                }

                if (ext_type == 43) { // supported_versions in ServerHello indicates selected version
                    if (ext_len >= 2) {
                        uint16_t sel_ver = read_u16(payload.data() + offset);
                        out_meta.negotiated_version = format_tls_version(sel_ver);
                    }
                } else if (ext_type == 16) { // ALPN
                    if (ext_len >= 3) {
                        uint16_t alpn_list_len = read_u16(payload.data() + offset);
                        if (alpn_list_len >= 1 && offset + 2 < ext_end) {
                            uint8_t p_len = payload[offset + 2];
                            if (offset + 3 + p_len <= ext_end) {
                                out_meta.selected_alpn = std::string(
                                    reinterpret_cast<const char*>(payload.data() + offset + 3),
                                    p_len
                                );
                            }
                        }
                    }
                }

                offset += ext_len;
            }
        }
    }

    return true;
}

} // namespace engine::protocols
