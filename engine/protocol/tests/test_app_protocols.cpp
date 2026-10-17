#include "doctest.h"
#include "engine/protocols/dns_parser.hpp"
#include "engine/protocols/http_parser.hpp"
#include "engine/protocols/tls_parser.hpp"
#include "engine/protocols/quic_classifier.hpp"
#include "engine/crypto/sha256.hpp"

using namespace engine::protocols;

TEST_CASE("SHA-256 matches NIST standard test vectors") {
    // NIST test vector: "" (empty string)
    // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    const std::vector<uint8_t> empty{};
    CHECK(engine::crypto::sha256_hex(empty) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    // NIST test vector: "abc"
    // ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    const std::string abc = "abc";
    const std::vector<uint8_t> abc_bytes(abc.begin(), abc.end());
    CHECK(engine::crypto::sha256_hex(abc_bytes) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST_CASE("DnsParser parses query with qname and type") {
    const std::vector<uint8_t> dns_query = {
        0x12, 0x34,                         // Transaction ID
        0x01, 0x00,                         // Flags (RD=1)
        0x00, 0x01,                         // Questions: 1
        0x00, 0x00,                         // Answer RRs: 0
        0x00, 0x00,                         // Authority RRs: 0
        0x00, 0x00,                         // Additional RRs: 0
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,                               // Terminating 0
        0x00, 0x01,                         // Type A (1)
        0x00, 0x01                          // Class IN (1)
    };

    DnsMessage out;
    std::string diag;
    bool ok = DnsParser::parse(dns_query, false, out, diag);
    CHECK(ok);
    CHECK(out.transaction_id == 0x1234);
    CHECK_FALSE(out.is_response);
    CHECK(out.questions.size() == 1);
    CHECK(out.questions[0].name == "example.com");
    CHECK(out.questions[0].type == DnsType::A);
}

TEST_CASE("DnsParser protects against infinite compression pointer loops") {
    const std::vector<uint8_t> loop_pkt = {
        0x12, 0x34,
        0x01, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0xc0, 0x0c,                         // Pointer to offset 12 (itself)
        0x00, 0x01,
        0x00, 0x01
    };

    DnsMessage out;
    std::string diag;
    bool ok = DnsParser::parse(loop_pkt, false, out, diag);
    CHECK_FALSE(ok);
    CHECK_FALSE(diag.empty());
}

TEST_CASE("HttpParser extracts request details and redacts credentials") {
    const std::string raw_http =
        "POST /api/v1/auth/login HTTP/1.1\r\n"
        "Host: api.example.com\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "Authorization: Bearer super_secret_access_token_12345\r\n"
        "Cookie: session=xyz987; tracker=abc\r\n"
        "Content-Length: 13\r\n"
        "\r\n"
        "{\"user\":\"bob\"}";

    const std::vector<uint8_t> payload(raw_http.begin(), raw_http.end());
    HttpMessage out;
    std::string diag;
    bool ok = HttpParser::parse(payload, out, diag);

    CHECK(ok);
    CHECK(out.type == HttpMessageType::Request);
    CHECK(out.method.value_or("") == "POST");
    CHECK(out.target.value_or("") == "/api/v1/auth/login");
    CHECK(out.host.has_value());
    CHECK(out.host.value() == "api.example.com");
    CHECK(out.content_length.has_value());
    CHECK(out.content_length.value() == 13);

    // Verify redaction of sensitive credentials in headers list
    for (const auto& h : out.headers) {
        if (h.name == "authorization") {
            CHECK(h.value == "[REDACTED]");
        } else if (h.name == "cookie") {
            CHECK(h.value == "[REDACTED]");
        }
    }
}

TEST_CASE("TlsParser parses ClientHello with SNI, ALPN, and cipher suites") {
    std::vector<uint8_t> ch = {
        0x16, 0x03, 0x01, 0x00, 0x41,       // Record header: Handshake, TLS 1.0, len 65
        0x01, 0x00, 0x00, 0x3d,             // ClientHello, len 61
        0x03, 0x03                          // Client version: TLS 1.2
    };
    for (int i = 0; i < 32; ++i) ch.push_back(0xaa);
    ch.push_back(0x00);                     // Session ID length: 0
    ch.push_back(0x00); ch.push_back(0x04); // Cipher suites len: 4
    ch.push_back(0x13); ch.push_back(0x01); // TLS_AES_128_GCM_SHA256
    ch.push_back(0xc0); ch.push_back(0x2f); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    ch.push_back(0x01); ch.push_back(0x00); // Compression len 1 (null compression)

    // Extensions: len 16
    ch.push_back(0x00); ch.push_back(0x10);
    // Ext 00 00 (SNI), len 12
    ch.push_back(0x00); ch.push_back(0x00);
    ch.push_back(0x00); ch.push_back(0x0c);
    // ServerNameList: len 10
    ch.push_back(0x00); ch.push_back(0x0a);
    // NameType: 0 (host_name), NameLen: 7
    ch.push_back(0x00);
    ch.push_back(0x00); ch.push_back(0x07);
    ch.push_back('e'); ch.push_back('x'); ch.push_back('a'); ch.push_back('m');
    ch.push_back('p'); ch.push_back('l'); ch.push_back('e');

    TlsMetadata out;
    std::string diag;
    bool ok = TlsParser::parse(ch, out, diag);

    CHECK(ok);
    CHECK(out.is_tls);
    CHECK(out.content_type == TlsContentType::Handshake);
    CHECK(out.handshake_type.has_value());
    CHECK(out.handshake_type.value() == TlsHandshakeType::ClientHello);
    CHECK(out.offered_ciphers.size() == 2);
    CHECK(out.sni.has_value());
    CHECK(out.sni.value() == "example");
}

TEST_CASE("QuicClassifier identifies Long Header Initial and parses CIDs") {
    const std::vector<uint8_t> quic_pkt = {
        0xc0,
        0x00, 0x00, 0x00, 0x01,
        0x04,
        0x01, 0x02, 0x03, 0x04,
        0x04,
        0x05, 0x06, 0x07, 0x08
    };

    QuicClassification out;
    bool ok = QuicClassifier::classify(quic_pkt, out);
    CHECK(ok);
    CHECK(out.is_quic);
    CHECK(out.header_type == QuicHeaderType::LongInitial);
    CHECK(out.version == 1);
    CHECK(out.version_name == "QUIC v1 (RFC 9000)");
    CHECK(out.destination_connection_id.size() == 4);
    CHECK(QuicClassifier::hex_cid(out.destination_connection_id) == "01020304");
    CHECK(QuicClassifier::hex_cid(out.source_connection_id) == "05060708");
}
