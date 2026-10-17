#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "engine/analysis_pipeline.hpp"
#include "engine/capture_reader.hpp"
#include "engine/crypto/sha256.hpp"

#include <chrono>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <algorithm>

namespace engine {

namespace {

std::string escape_json(const std::string& s) {
    std::ostringstream o;
    for (char c : s) {
        switch (c) {
            case '"': o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\b': o << "\\b"; break;
            case '\f': o << "\\f"; break;
            case '\n': o << "\\n"; break;
            case '\r': o << "\\r"; break;
            case '\t': o << "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) <= 0x1f) {
                    o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
                } else {
                    o << c;
                }
        }
    }
    return o.str();
}

} // namespace

AnalysisPipeline::AnalysisPipeline(PipelineConfig config)
    : config_(std::move(config)) {
    if (!config_.events_output_path.empty()) {
        event_writer_ = std::make_unique<std::ofstream>(config_.events_output_path, std::ios::trunc);
    }
}

AnalysisPipeline::~AnalysisPipeline() {
    if (event_writer_ && event_writer_->is_open()) {
        event_writer_->close();
    }
}

std::string AnalysisPipeline::format_iso_timestamp(uint64_t ns) const {
    time_t sec = static_cast<time_t>(ns / 1'000'000'000ULL);
    uint32_t remainder_ns = static_cast<uint32_t>(ns % 1'000'000'000ULL);

    std::tm tm_buf{};
#if defined(_WIN32)
    gmtime_s(&tm_buf, &sec);
#else
    gmtime_r(&sec, &tm_buf);
#endif

    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%S")
        << '.' << std::setw(9) << std::setfill('0') << remainder_ns << 'Z';
    return oss.str();
}

std::string AnalysisPipeline::generate_event_id(uint64_t packet_idx, uint64_t ts_ns) const {
    uint64_t h1 = packet_idx ^ 0x9e3779b97f4a7c15ULL;
    uint64_t h2 = ts_ns ^ 0xbf58476d1ce4e5b9ULL;

    uint32_t p1 = static_cast<uint32_t>(h1 >> 32);
    uint16_t p2 = static_cast<uint16_t>(h1 & 0xffff);
    uint16_t p3 = (static_cast<uint16_t>((h1 >> 16) & 0x0fff)) | 0x4000;
    uint16_t p4 = (static_cast<uint16_t>((h2 >> 48) & 0x3fff)) | 0x8000;
    uint64_t p5 = h2 & 0xffffffffffffULL;

    std::ostringstream oss;
    oss << std::hex << std::setfill('0')
        << std::setw(8) << p1 << '-'
        << std::setw(4) << p2 << '-'
        << std::setw(4) << p3 << '-'
        << std::setw(4) << p4 << '-'
        << std::setw(12) << p5;
    return oss.str();
}

void AnalysisPipeline::emit_event(const std::string& json_line) {
    if (event_writer_ && event_writer_->is_open()) {
        (*event_writer_) << json_line << "\n";
    }
}

AnalysisReport AnalysisPipeline::run() {
    AnalysisReport report;
    report.capture_file = config_.input_path;

    CaptureReader reader;
    std::string open_diag;
    StatusCode sc = reader.open(config_.input_path, open_diag);
    if (sc != StatusCode::Success) {
        report.anomalies.push_back("Failed to open capture: " + open_diag);
        return report;
    }

    auto wall_start = std::chrono::steady_clock::now();
    uint64_t packet_idx = 0;
    uint64_t first_ts_ns = 0;
    uint64_t last_ts_ns = 0;

    std::unordered_map<std::string, std::string> flow_app_proto;
    std::unordered_map<std::string, std::string> flow_info;

    RawPacket pkt;
    while (reader.read_next_packet(pkt) == StatusCode::Success) {
        if (config_.max_packets && packet_idx >= *config_.max_packets) {
            break;
        }

        report.total_packets++;
        report.total_bytes += pkt.data.size();
        report.wire_bytes += pkt.wire_length_bytes;

        if (packet_idx == 0) {
            first_ts_ns = pkt.timestamp_ns;
        }
        last_ts_ns = pkt.timestamp_ns;

        std::string parser_status = "ok";
        std::string diag_code = "";
        std::string diag_msg = "";

        if (pkt.data.size() < pkt.wire_length_bytes) {
            parser_status = "truncated";
            diag_code = "SNAPLEN_TRUNCATED";
            diag_msg = "Captured length is less than original wire length";
            report.parser_status_counts["truncated"]++;
        }

        std::string flow_id_str = "";
        std::string flow_dir_str = "unknown";
        std::string link_layer_json = "null";
        std::string network_layer_json = "null";
        std::string transport_layer_json = "null";
        std::string app_layer_json = "null";

        size_t bytes_consumed = 0;
        size_t bytes_remaining = pkt.data.size();

        // 1. Link Layer
        std::span<const uint8_t> l2_payload = pkt.data;
        std::optional<uint16_t> current_vlan;

        if (pkt.link_type == LinkType::Ethernet) {
            decoders::DecodedEthernet eth;
            std::string eth_diag;
            decoders::DecodeResult res = decoders::EthernetDecoder::decode(l2_payload, eth, eth_diag);
            if (res == decoders::DecodeResult::Success) {
                report.protocol_counts["Ethernet"]++;
                if (!eth.vlan_tags.empty()) {
                    report.protocol_counts["VLAN"]++;
                    current_vlan = eth.vlan_tags.front().vlan_id;
                }

                std::ostringstream ll;
                ll << "{\"source_mac\":\"" << eth.source_mac.to_string() << "\","
                   << "\"destination_mac\":\"" << eth.destination_mac.to_string() << "\","
                   << "\"ether_type\":" << eth.ether_type << ",";
                if (current_vlan) {
                    ll << "\"vlan_id\":" << *current_vlan;
                } else {
                    ll << "\"vlan_id\":null";
                }
                ll << "}";
                link_layer_json = ll.str();

                l2_payload = eth.payload;
                bytes_consumed += (pkt.data.size() - l2_payload.size());

                // 2. Network Layer
                if (eth.ether_type == 0x0800) { // IPv4
                    decoders::DecodedIPv4 ip4;
                    std::string ip4_diag;
                    decoders::DecodeResult ip_res = decoders::IPv4Decoder::decode(l2_payload, ip4, ip4_diag);
                    if (ip_res == decoders::DecodeResult::Success) {
                        report.protocol_counts["IPv4"]++;
                        if (ip4.checksum_status == decoders::ChecksumStatus::Invalid) {
                            parser_status = "checksum_error";
                            diag_code = "IPV4_CHECKSUM_MISMATCH";
                            diag_msg = "Calculated IPv4 header checksum did not match header value";
                            report.parser_status_counts["checksum_error"]++;
                            report.anomalies.push_back("Packet " + std::to_string(packet_idx) + ": IPv4 checksum error");
                        }

                        std::ostringstream nl;
                        nl << "{\"version\":\"IPv4\","
                           << "\"source_ip\":\"" << ip4.source_ip << "\","
                           << "\"destination_ip\":\"" << ip4.destination_ip << "\","
                           << "\"ttl_or_hop_limit\":" << static_cast<int>(ip4.ttl) << ","
                           << "\"identification\":" << ip4.identification << ","
                           << "\"flags\":{\"df\":" << (ip4.flag_df ? "true" : "false") << ",\"mf\":" << (ip4.flag_mf ? "true" : "false") << "}}";
                        network_layer_json = nl.str();

                        // 3. Transport Layer
                        if (ip4.is_fragment && ip4.fragment_offset > 0) {
                            report.protocol_counts["IPv4-Fragment"]++;
                            std::ostringstream tl;
                            tl << "{\"protocol\":\"Fragment\","
                               << "\"source_port\":null,"
                               << "\"destination_port\":null,"
                               << "\"tcp_sequence_number\":null,"
                               << "\"tcp_acknowledgment_number\":null,"
                               << "\"tcp_flags\":null,"
                               << "\"window_size\":null,"
                               << "\"fragment_offset\":" << ip4.fragment_offset << "}";
                            transport_layer_json = tl.str();
                        } else if (ip4.protocol == 6) { // TCP
                            decoders::DecodedTcp tcp;
                            std::string tcp_diag;
                            decoders::DecodeResult tcp_res = decoders::TcpDecoder::decode(ip4.payload, tcp, tcp_diag);
                            if (tcp_res == decoders::DecodeResult::Success) {
                                report.protocol_counts["TCP"]++;

                                std::ostringstream tl;
                                tl << "{\"protocol\":\"TCP\","
                                   << "\"source_port\":" << tcp.source_port << ","
                                   << "\"destination_port\":" << tcp.destination_port << ","
                                   << "\"tcp_sequence_number\":" << tcp.sequence_number << ","
                                   << "\"tcp_acknowledgment_number\":" << tcp.acknowledgment_number << ","
                                   << "\"tcp_flags\":{"
                                   << "\"syn\":" << (tcp.flag_syn ? "true" : "false") << ","
                                   << "\"ack\":" << (tcp.flag_ack ? "true" : "false") << ","
                                   << "\"fin\":" << (tcp.flag_fin ? "true" : "false") << ","
                                   << "\"rst\":" << (tcp.flag_rst ? "true" : "false") << ","
                                   << "\"psh\":" << (tcp.flag_psh ? "true" : "false") << ","
                                   << "\"urg\":" << (tcp.flag_urg ? "true" : "false") << ","
                                   << "\"ece\":" << (tcp.flag_ece ? "true" : "false") << ","
                                   << "\"cwr\":" << (tcp.flag_cwr ? "true" : "false") << "},"
                                   << "\"window_size\":" << tcp.window_size << "}";
                                transport_layer_json = tl.str();

                                // Flow Tracking
                                flow::FlowKey fkey(
                                    ip4.source_ip,
                                    tcp.source_port,
                                    ip4.destination_ip,
                                    tcp.destination_port,
                                    flow::TransportProtocol::TCP
                                );
                                flow_id_str = fkey.to_flow_id();
                                flow::FlowDirection dir = fkey.get_packet_direction(ip4.source_ip, tcp.source_port);
                                flow_dir_str = flow::to_string(dir);

                                bool is_new = false;
                                auto& fentry = flow_table_.get_or_create(fkey, pkt.timestamp_ns, is_new);
                                if (dir == flow::FlowDirection::Forward) {
                                    fentry.forward_packets++;
                                    fentry.forward_bytes += pkt.data.size();
                                } else {
                                    fentry.reverse_packets++;
                                    fentry.reverse_bytes += pkt.data.size();
                                }
                                fentry.last_seen_ns = pkt.timestamp_ns;

                                fentry.tcp_tracker.process_packet(tcp, dir, pkt.timestamp_ns);

                                // Application Layer parsing for TCP
                                if (!tcp.payload.empty()) {
                                    std::string sha = crypto::sha256_hex(tcp.payload);
                                    std::string preview = "";
                                    size_t preview_len = (std::min)(tcp.payload.size(), config_.max_payload_preview_bytes);
                                    for (size_t b = 0; b < preview_len; ++b) {
                                        uint8_t ch = tcp.payload[b];
                                        preview += (ch >= 32 && ch <= 126) ? static_cast<char>(ch) : '.';
                                    }

                                    protocols::HttpMessage http_msg;
                                    std::string http_diag;
                                    if (protocols::HttpParser::parse(tcp.payload, http_msg, http_diag)) {
                                        report.protocol_counts["HTTP"]++;
                                        flow_app_proto[flow_id_str] = "HTTP";

                                        std::ostringstream al;
                                        al << "{\"protocol\":\"HTTP\","
                                           << "\"payload_length_bytes\":" << tcp.payload.size() << ","
                                           << "\"payload_hash_sha256\":\"" << sha << "\","
                                           << "\"sanitized_preview\":\"" << escape_json(preview) << "\","
                                           << "\"protocol_metadata\":{";

                                        if (http_msg.type == protocols::HttpMessageType::Request) {
                                            report.http_requests++;
                                            fentry.http_request_count++;
                                            al << "\"type\":\"request\","
                                               << "\"method\":\"" << escape_json(http_msg.method.value_or("")) << "\","
                                               << "\"target\":\"" << escape_json(http_msg.target.value_or("")) << "\","
                                               << "\"host\":\"" << escape_json(http_msg.host.value_or("")) << "\"";
                                            if (http_msg.host) flow_info[flow_id_str] = "Host: " + *http_msg.host;
                                        } else if (http_msg.type == protocols::HttpMessageType::Response) {
                                            report.http_responses++;
                                            fentry.http_response_count++;
                                            al << "\"type\":\"response\","
                                               << "\"status_code\":" << http_msg.status_code.value_or(0) << ","
                                               << "\"reason_phrase\":\"" << escape_json(http_msg.reason_phrase.value_or("")) << "\"";
                                            if (http_msg.status_code) flow_info[flow_id_str] = "Status: " + std::to_string(*http_msg.status_code);
                                        }
                                        al << "}}";
                                        app_layer_json = al.str();
                                    } else {
                                        protocols::TlsMetadata tls_meta;
                                        std::string tls_diag;
                                        if (protocols::TlsParser::parse(tcp.payload, tls_meta, tls_diag) && tls_meta.is_tls) {
                                            report.protocol_counts["TLS"]++;
                                            flow_app_proto[flow_id_str] = "TLS";

                                            std::ostringstream al;
                                            al << "{\"protocol\":\"TLS\","
                                               << "\"payload_length_bytes\":" << tcp.payload.size() << ","
                                               << "\"payload_hash_sha256\":\"" << sha << "\","
                                               << "\"sanitized_preview\":\"" << escape_json(preview) << "\","
                                               << "\"protocol_metadata\":{"
                                               << "\"record_version\":\"" << protocols::TlsParser::format_tls_version(tls_meta.record_version) << "\",";

                                            if (tls_meta.handshake_type) {
                                                report.tls_handshakes++;
                                                if (*tls_meta.handshake_type == protocols::TlsHandshakeType::ClientHello) {
                                                    fentry.tls_client_hello_seen = true;
                                                    al << "\"handshake_type\":\"ClientHello\",";
                                                    if (tls_meta.sni) {
                                                        fentry.tls_sni = *tls_meta.sni;
                                                        al << "\"sni\":\"" << escape_json(*tls_meta.sni) << "\",";
                                                        flow_info[flow_id_str] = "SNI: " + *tls_meta.sni;
                                                    }
                                                    if (tls_meta.negotiated_version) {
                                                        al << "\"supported_version\":\"" << escape_json(*tls_meta.negotiated_version) << "\",";
                                                    }
                                                    al << "\"ciphers_offered\":" << tls_meta.offered_ciphers.size();
                                                } else if (*tls_meta.handshake_type == protocols::TlsHandshakeType::ServerHello) {
                                                    fentry.tls_server_hello_seen = true;
                                                    al << "\"handshake_type\":\"ServerHello\",";
                                                    if (tls_meta.selected_cipher) {
                                                        fentry.tls_cipher = protocols::TlsParser::format_cipher_suite(*tls_meta.selected_cipher);
                                                        al << "\"selected_cipher\":\"" << escape_json(fentry.tls_cipher) << "\",";
                                                    }
                                                    if (tls_meta.selected_alpn) {
                                                        fentry.tls_alpn = *tls_meta.selected_alpn;
                                                        al << "\"selected_alpn\":\"" << escape_json(*tls_meta.selected_alpn) << "\",";
                                                    }
                                                    al << "\"version\":\"" << escape_json(tls_meta.negotiated_version.value_or("")) << "\"";
                                                } else {
                                                    al << "\"handshake_type\":\"Other\"";
                                                }
                                            } else if (tls_meta.is_encrypted_application_data) {
                                                al << "\"content_type\":\"ApplicationData (Encrypted)\"";
                                            } else {
                                                al << "\"content_type\":\"Record\"";
                                            }
                                            al << "}}";
                                            app_layer_json = al.str();
                                        }
                                    }
                                }
                            } else {
                                parser_status = "malformed";
                                diag_code = "TCP_DECODE_FAILED";
                                diag_msg = tcp_diag;
                                report.parser_status_counts["malformed"]++;
                            }
                        } else if (ip4.protocol == 17) { // UDP
                            decoders::DecodedUdp udp;
                            std::string udp_diag;
                            decoders::DecodeResult udp_res = decoders::UdpDecoder::decode(ip4.payload, udp, udp_diag);
                            if (udp_res == decoders::DecodeResult::Success) {
                                report.protocol_counts["UDP"]++;

                                std::ostringstream tl;
                                tl << "{\"protocol\":\"UDP\","
                                   << "\"source_port\":" << udp.source_port << ","
                                   << "\"destination_port\":" << udp.destination_port << ","
                                   << "\"tcp_sequence_number\":null,"
                                   << "\"tcp_acknowledgment_number\":null,"
                                   << "\"tcp_flags\":null,"
                                   << "\"window_size\":null}";
                                transport_layer_json = tl.str();

                                flow::FlowKey fkey(
                                    ip4.source_ip,
                                    udp.source_port,
                                    ip4.destination_ip,
                                    udp.destination_port,
                                    flow::TransportProtocol::UDP
                                );
                                flow_id_str = fkey.to_flow_id();
                                flow::FlowDirection dir = fkey.get_packet_direction(ip4.source_ip, udp.source_port);
                                flow_dir_str = flow::to_string(dir);

                                bool is_new = false;
                                auto& fentry = flow_table_.get_or_create(fkey, pkt.timestamp_ns, is_new);
                                if (dir == flow::FlowDirection::Forward) {
                                    fentry.forward_packets++;
                                    fentry.forward_bytes += pkt.data.size();
                                } else {
                                    fentry.reverse_packets++;
                                    fentry.reverse_bytes += pkt.data.size();
                                }
                                fentry.last_seen_ns = pkt.timestamp_ns;

                                if (!udp.payload.empty()) {
                                    std::string sha = crypto::sha256_hex(udp.payload);
                                    std::string preview = "";
                                    size_t preview_len = (std::min)(udp.payload.size(), config_.max_payload_preview_bytes);
                                    for (size_t b = 0; b < preview_len; ++b) {
                                        uint8_t ch = udp.payload[b];
                                        preview += (ch >= 32 && ch <= 126) ? static_cast<char>(ch) : '.';
                                    }

                                    protocols::DnsMessage dns_msg;
                                    std::string dns_diag;
                                    if (protocols::DnsParser::parse(udp.payload, false, dns_msg, dns_diag)) {
                                        report.protocol_counts["DNS"]++;
                                        flow_app_proto[flow_id_str] = "DNS";

                                        if (dns_msg.is_response) {
                                            report.dns_responses++;
                                            fentry.dns_response_count++;
                                        } else {
                                            report.dns_queries++;
                                            fentry.dns_query_count++;
                                        }

                                        std::ostringstream al;
                                        al << "{\"protocol\":\"DNS\","
                                           << "\"payload_length_bytes\":" << udp.payload.size() << ","
                                           << "\"payload_hash_sha256\":\"" << sha << "\","
                                           << "\"sanitized_preview\":\"" << escape_json(preview) << "\","
                                           << "\"protocol_metadata\":{"
                                           << "\"transaction_id\":" << dns_msg.transaction_id << ","
                                           << "\"is_response\":" << (dns_msg.is_response ? "true" : "false") << ","
                                           << "\"response_code\":" << static_cast<int>(dns_msg.response_code);

                                        if (!dns_msg.questions.empty()) {
                                            al << ",\"query_name\":\"" << escape_json(dns_msg.questions[0].name) << "\"";
                                            al << ",\"query_type\":\"" << escape_json(protocols::to_string(dns_msg.questions[0].type)) << "\"";
                                            flow_info[flow_id_str] = dns_msg.questions[0].name;
                                        }
                                        if (!dns_msg.answers.empty()) {
                                            al << ",\"answers_count\":" << dns_msg.answers.size();
                                            al << ",\"first_answer\":\"" << escape_json(dns_msg.answers[0].rdata_string) << "\"";
                                            if (flow_info[flow_id_str].empty()) {
                                                flow_info[flow_id_str] = dns_msg.answers[0].rdata_string;
                                            }
                                        }
                                        al << "}}";
                                        app_layer_json = al.str();
                                    } else {
                                        protocols::QuicClassification quic_meta;
                                        if (protocols::QuicClassifier::classify(udp.payload, quic_meta) && quic_meta.is_quic) {
                                            report.protocol_counts["QUIC"]++;
                                            report.quic_datagrams++;
                                            flow_app_proto[flow_id_str] = "QUIC";

                                            std::ostringstream al;
                                            al << "{\"protocol\":\"QUIC\","
                                               << "\"payload_length_bytes\":" << udp.payload.size() << ","
                                               << "\"payload_hash_sha256\":\"" << sha << "\","
                                               << "\"sanitized_preview\":\"" << escape_json(preview) << "\","
                                               << "\"protocol_metadata\":{"
                                               << "\"version\":\"" << escape_json(quic_meta.version_name) << "\","
                                               << "\"dcid\":\"" << escape_json(protocols::QuicClassifier::hex_cid(quic_meta.destination_connection_id)) << "\""
                                               << "}}";
                                            app_layer_json = al.str();
                                            flow_info[flow_id_str] = quic_meta.version_name;
                                        }
                                    }
                                }
                            }
                        } else if (ip4.protocol == 1) { // ICMP
                            decoders::DecodedIcmp icmp;
                            std::string icmp_diag;
                            decoders::DecodeResult icmp_res = decoders::IcmpDecoder::decode(ip4.payload, false, icmp, icmp_diag);
                            if (icmp_res == decoders::DecodeResult::Success) {
                                report.protocol_counts["ICMP"]++;

                                std::ostringstream tl;
                                tl << "{\"protocol\":\"ICMP\","
                                   << "\"source_port\":null,"
                                   << "\"destination_port\":null,"
                                   << "\"tcp_sequence_number\":null,"
                                   << "\"tcp_acknowledgment_number\":null,"
                                   << "\"tcp_flags\":null,"
                                   << "\"window_size\":null}";
                                transport_layer_json = tl.str();

                                flow::FlowKey fkey(
                                    ip4.source_ip,
                                    0,
                                    ip4.destination_ip,
                                    0,
                                    flow::TransportProtocol::ICMP
                                );
                                flow_id_str = fkey.to_flow_id();
                                flow_dir_str = "forward";

                                bool is_new = false;
                                auto& fentry = flow_table_.get_or_create(fkey, pkt.timestamp_ns, is_new);
                                fentry.forward_packets++;
                                fentry.forward_bytes += pkt.data.size();
                                fentry.last_seen_ns = pkt.timestamp_ns;

                                flow_app_proto[flow_id_str] = "ICMP";
                                if (icmp.quote_summary) flow_info[flow_id_str] = *icmp.quote_summary;
                            }
                        }
                    } else {
                        parser_status = "malformed";
                        diag_code = "IPV4_DECODE_FAILED";
                        diag_msg = ip4_diag;
                        report.parser_status_counts["malformed"]++;
                    }
                } else if (eth.ether_type == 0x86DD) { // IPv6
                    decoders::DecodedIPv6 ip6;
                    std::string ip6_diag;
                    decoders::DecodeResult ip6_res = decoders::IPv6Decoder::decode(l2_payload, ip6, ip6_diag);
                    if (ip6_res == decoders::DecodeResult::Success) {
                        report.protocol_counts["IPv6"]++;

                        std::ostringstream nl;
                        nl << "{\"version\":\"IPv6\","
                           << "\"source_ip\":\"" << ip6.source_ip << "\","
                           << "\"destination_ip\":\"" << ip6.destination_ip << "\","
                           << "\"ttl_or_hop_limit\":" << static_cast<int>(ip6.hop_limit) << ","
                           << "\"identification\":null,"
                           << "\"flags\":null}";
                        network_layer_json = nl.str();

                        if (ip6.is_fragment && ip6.fragment_offset > 0) {
                            report.protocol_counts["IPv6-Fragment"]++;
                            std::ostringstream tl;
                            tl << "{\"protocol\":\"Fragment\","
                               << "\"source_port\":null,"
                               << "\"destination_port\":null,"
                               << "\"tcp_sequence_number\":null,"
                               << "\"tcp_acknowledgment_number\":null,"
                               << "\"tcp_flags\":null,"
                               << "\"window_size\":null,"
                               << "\"fragment_offset\":" << ip6.fragment_offset << "}";
                            transport_layer_json = tl.str();
                        } else if (ip6.upper_layer_protocol == 6) { // TCP over IPv6
                            decoders::DecodedTcp tcp;
                            std::string tcp_diag;
                            decoders::DecodeResult tcp_res = decoders::TcpDecoder::decode(ip6.payload, tcp, tcp_diag);
                            if (tcp_res == decoders::DecodeResult::Success) {
                                report.protocol_counts["TCP"]++;

                                std::ostringstream tl;
                                tl << "{\"protocol\":\"TCP\","
                                   << "\"source_port\":" << tcp.source_port << ","
                                   << "\"destination_port\":" << tcp.destination_port << ","
                                   << "\"tcp_sequence_number\":" << tcp.sequence_number << ","
                                   << "\"tcp_acknowledgment_number\":" << tcp.acknowledgment_number << ","
                                   << "\"tcp_flags\":{"
                                   << "\"syn\":" << (tcp.flag_syn ? "true" : "false") << ","
                                   << "\"ack\":" << (tcp.flag_ack ? "true" : "false") << ","
                                   << "\"fin\":" << (tcp.flag_fin ? "true" : "false") << ","
                                   << "\"rst\":" << (tcp.flag_rst ? "true" : "false") << ","
                                   << "\"psh\":" << (tcp.flag_psh ? "true" : "false") << ","
                                   << "\"urg\":" << (tcp.flag_urg ? "true" : "false") << ","
                                   << "\"ece\":" << (tcp.flag_ece ? "true" : "false") << ","
                                   << "\"cwr\":" << (tcp.flag_cwr ? "true" : "false") << "},"
                                   << "\"window_size\":" << tcp.window_size << "}";
                                transport_layer_json = tl.str();

                                flow::FlowKey fkey(
                                    ip6.source_ip,
                                    tcp.source_port,
                                    ip6.destination_ip,
                                    tcp.destination_port,
                                    flow::TransportProtocol::TCP
                                );
                                flow_id_str = fkey.to_flow_id();
                                flow::FlowDirection dir = fkey.get_packet_direction(ip6.source_ip, tcp.source_port);
                                flow_dir_str = flow::to_string(dir);

                                bool is_new = false;
                                auto& fentry = flow_table_.get_or_create(fkey, pkt.timestamp_ns, is_new);
                                if (dir == flow::FlowDirection::Forward) {
                                    fentry.forward_packets++;
                                    fentry.forward_bytes += pkt.data.size();
                                } else {
                                    fentry.reverse_packets++;
                                    fentry.reverse_bytes += pkt.data.size();
                                }
                                fentry.last_seen_ns = pkt.timestamp_ns;

                                fentry.tcp_tracker.process_packet(tcp, dir, pkt.timestamp_ns);
                            }
                        } else if (ip6.upper_layer_protocol == 17) { // UDP over IPv6
                            decoders::DecodedUdp udp;
                            std::string udp_diag;
                            decoders::DecodeResult udp_res = decoders::UdpDecoder::decode(ip6.payload, udp, udp_diag);
                            if (udp_res == decoders::DecodeResult::Success) {
                                report.protocol_counts["UDP"]++;

                                std::ostringstream tl;
                                tl << "{\"protocol\":\"UDP\","
                                   << "\"source_port\":" << udp.source_port << ","
                                   << "\"destination_port\":" << udp.destination_port << ","
                                   << "\"tcp_sequence_number\":null,"
                                   << "\"tcp_acknowledgment_number\":null,"
                                   << "\"tcp_flags\":null,"
                                   << "\"window_size\":null}";
                                transport_layer_json = tl.str();

                                flow::FlowKey fkey(
                                    ip6.source_ip,
                                    udp.source_port,
                                    ip6.destination_ip,
                                    udp.destination_port,
                                    flow::TransportProtocol::UDP
                                );
                                flow_id_str = fkey.to_flow_id();
                                flow::FlowDirection dir = fkey.get_packet_direction(ip6.source_ip, udp.source_port);
                                flow_dir_str = flow::to_string(dir);

                                bool is_new = false;
                                auto& fentry = flow_table_.get_or_create(fkey, pkt.timestamp_ns, is_new);
                                if (dir == flow::FlowDirection::Forward) {
                                    fentry.forward_packets++;
                                    fentry.forward_bytes += pkt.data.size();
                                } else {
                                    fentry.reverse_packets++;
                                    fentry.reverse_bytes += pkt.data.size();
                                }
                                fentry.last_seen_ns = pkt.timestamp_ns;
                            }
                        }
                    }
                } else if (eth.ether_type == 0x0806) { // ARP
                    decoders::DecodedArp arp;
                    std::string arp_diag;
                    decoders::DecodeResult arp_res = decoders::ArpDecoder::decode(l2_payload, arp, arp_diag);
                    if (arp_res == decoders::DecodeResult::Success) {
                        report.protocol_counts["ARP"]++;

                        std::ostringstream nl;
                        nl << "{\"version\":null,"
                           << "\"source_ip\":\"" << arp.sender_ip << "\","
                           << "\"destination_ip\":\"" << arp.target_ip << "\","
                           << "\"ttl_or_hop_limit\":null,"
                           << "\"identification\":null,"
                           << "\"flags\":null}";
                        network_layer_json = nl.str();
                    }
                }
            } else {
                parser_status = "malformed";
                diag_code = "ETHERNET_DECODE_FAILED";
                diag_msg = eth_diag;
                report.parser_status_counts["malformed"]++;
            }
        } else {
            report.protocol_counts["RawLink"]++;
        }

        if (parser_status == "ok") {
            report.parser_status_counts["ok"]++;
        }

        // Emit Canonical JSONL Event
        if (event_writer_ && event_writer_->is_open()) {
            std::string event_id = generate_event_id(packet_idx, pkt.timestamp_ns);
            std::string iso_time = format_iso_timestamp(pkt.timestamp_ns);

            std::ostringstream ev;
            ev << "{"
               << "\"schema_version\":\"1.0.0\","
               << "\"event_id\":\"" << event_id << "\","
               << "\"timestamp_ns\":" << pkt.timestamp_ns << ","
               << "\"timestamp_iso\":\"" << iso_time << "\","
               << "\"source_id\":\"" << escape_json(config_.input_path) << "\",";

            if (!flow_id_str.empty()) {
                ev << "\"flow_id\":\"" << flow_id_str << "\",";
            } else {
                ev << "\"flow_id\":null,";
            }

            if (flow_dir_str != "unknown") {
                ev << "\"flow_direction\":\"" << flow_dir_str << "\",";
            } else {
                ev << "\"flow_direction\":null,";
            }

            ev << "\"link_layer\":" << link_layer_json << ","
               << "\"network_layer\":" << network_layer_json << ","
               << "\"transport_layer\":" << transport_layer_json << ","
               << "\"application_layer\":" << app_layer_json << ","
               << "\"parser_status\":{"
               << "\"status\":\"" << parser_status << "\",";
            if (!diag_code.empty()) {
                ev << "\"diagnostic_code\":\"" << escape_json(diag_code) << "\",";
            } else {
                ev << "\"diagnostic_code\":null,";
            }
            if (!diag_msg.empty()) {
                ev << "\"diagnostic_message\":\"" << escape_json(diag_msg) << "\",";
            } else {
                ev << "\"diagnostic_message\":null,";
            }
            ev << "\"bytes_consumed\":" << bytes_consumed << ","
               << "\"bytes_remaining\":" << (pkt.data.size() - bytes_consumed)
               << "},"
               << "\"provenance\":{"
               << "\"packet_index\":" << packet_idx << ","
               << "\"wire_length_bytes\":" << pkt.wire_length_bytes << ","
               << "\"capture_length_bytes\":" << pkt.data.size() << ","
               << "\"capture_interface\":null,"
               << "\"capture_file_path\":\"" << escape_json(config_.input_path) << "\""
               << "}}";

            emit_event(ev.str());
        }

        packet_idx++;
    }

    auto wall_end = std::chrono::steady_clock::now();
    std::chrono::duration<double, std::milli> wall_dur = wall_end - wall_start;
    report.duration_ms = wall_dur.count();

    if (report.total_packets > 0) {
        report.start_time_iso = format_iso_timestamp(first_ts_ns);
        report.end_time_iso = format_iso_timestamp(last_ts_ns);

        double sec = report.duration_ms / 1000.0;
        if (sec > 0.000001) {
            report.packets_per_sec = static_cast<double>(report.total_packets) / sec;
            report.throughput_mbps = (static_cast<double>(report.total_bytes) * 8.0) / (sec * 1'000'000.0);
        }
    }

    report.total_flows = flow_table_.size();

    // Collect flow summaries
    auto all_records = flow_table_.get_all_records();
    for (const auto& entry : all_records) {
        FlowRecordSummary rec;
        rec.flow_id = entry.key.to_flow_id();
        rec.src_ip = entry.key.get_endpoint_a().ip;
        rec.src_port = entry.key.get_endpoint_a().port;
        rec.dst_ip = entry.key.get_endpoint_b().ip;
        rec.dst_port = entry.key.get_endpoint_b().port;
        rec.ip_proto = flow::to_string(entry.key.get_protocol());

        rec.packets_forward = entry.forward_packets;
        rec.packets_reverse = entry.reverse_packets;
        rec.bytes_forward = entry.forward_bytes;
        rec.bytes_reverse = entry.reverse_bytes;
        rec.start_ns = entry.first_seen_ns;
        rec.last_ns = entry.last_seen_ns;

        if (rec.last_ns > rec.start_ns) {
            rec.duration_ms = static_cast<double>(rec.last_ns - rec.start_ns) / 1'000'000.0;
        }

        if (entry.key.get_protocol() == flow::TransportProtocol::TCP) {
            rec.state = flow::to_string(entry.tcp_tracker.get_state());
            report.tcp_state_counts[rec.state]++;
            rec.retransmissions = entry.tcp_tracker.get_retransmit_count();
            rec.out_of_order = entry.tcp_tracker.get_out_of_order_count();
        } else {
            rec.state = "STATELESS";
        }

        auto it_app = flow_app_proto.find(rec.flow_id);
        if (it_app != flow_app_proto.end()) {
            rec.app_protocol = it_app->second;
        }

        auto it_info = flow_info.find(rec.flow_id);
        if (it_info != flow_info.end()) {
            rec.info = it_info->second;
        }

        report.flows.push_back(std::move(rec));
    }

    if (!config_.summary_output_path.empty()) {
        std::ofstream sum_file(config_.summary_output_path, std::ios::trunc);
        if (sum_file.is_open()) {
            sum_file << report.to_json() << "\n";
            sum_file.close();
        }
    }

    return report;
}

std::string AnalysisReport::to_json() const {
    std::ostringstream oss;
    oss << "{"
        << "\"capture_file\":\"" << escape_json(capture_file) << "\","
        << "\"total_packets\":" << total_packets << ","
        << "\"total_bytes\":" << total_bytes << ","
        << "\"wire_bytes\":" << wire_bytes << ","
        << "\"duration_ms\":" << duration_ms << ","
        << "\"start_time_iso\":\"" << start_time_iso << "\","
        << "\"end_time_iso\":\"" << end_time_iso << "\","
        << "\"packets_per_sec\":" << packets_per_sec << ","
        << "\"throughput_mbps\":" << throughput_mbps << ","
        << "\"total_flows\":" << total_flows << ","
        << "\"dns_queries\":" << dns_queries << ","
        << "\"dns_responses\":" << dns_responses << ","
        << "\"http_requests\":" << http_requests << ","
        << "\"http_responses\":" << http_responses << ","
        << "\"tls_handshakes\":" << tls_handshakes << ","
        << "\"quic_datagrams\":" << quic_datagrams << ",";

    // Protocol counts
    oss << "\"protocol_counts\":{";
    bool first = true;
    for (const auto& [p, cnt] : protocol_counts) {
        if (!first) oss << ",";
        oss << "\"" << escape_json(p) << "\":" << cnt;
        first = false;
    }
    oss << "},";

    // Parser status counts
    oss << "\"parser_status_counts\":{";
    first = true;
    for (const auto& [s, cnt] : parser_status_counts) {
        if (!first) oss << ",";
        oss << "\"" << escape_json(s) << "\":" << cnt;
        first = false;
    }
    oss << "},";

    // TCP state counts
    oss << "\"tcp_state_counts\":{";
    first = true;
    for (const auto& [st, cnt] : tcp_state_counts) {
        if (!first) oss << ",";
        oss << "\"" << escape_json(st) << "\":" << cnt;
        first = false;
    }
    oss << "},";

    // Anomalies
    oss << "\"anomalies\":[";
    first = true;
    for (const auto& anom : anomalies) {
        if (!first) oss << ",";
        oss << "\"" << escape_json(anom) << "\"";
        first = false;
    }
    oss << "],";

    // Flows
    oss << "\"flows\":[";
    first = true;
    for (const auto& f : flows) {
        if (!first) oss << ",";
        oss << "{"
            << "\"flow_id\":\"" << f.flow_id << "\","
            << "\"ip_proto\":\"" << f.ip_proto << "\","
            << "\"src_ip\":\"" << f.src_ip << "\","
            << "\"src_port\":" << f.src_port << ","
            << "\"dst_ip\":\"" << f.dst_ip << "\","
            << "\"dst_port\":" << f.dst_port << ",";
        if (f.vlan_id) {
            oss << "\"vlan_id\":" << *f.vlan_id << ",";
        } else {
            oss << "\"vlan_id\":null,";
        }
        oss << "\"state\":\"" << f.state << "\","
            << "\"packets_forward\":" << f.packets_forward << ","
            << "\"packets_reverse\":" << f.packets_reverse << ","
            << "\"bytes_forward\":" << f.bytes_forward << ","
            << "\"bytes_reverse\":" << f.bytes_reverse << ","
            << "\"duration_ms\":" << f.duration_ms << ","
            << "\"app_protocol\":\"" << f.app_protocol << "\","
            << "\"info\":\"" << escape_json(f.info) << "\","
            << "\"retransmissions\":" << f.retransmissions << ","
            << "\"out_of_order\":" << f.out_of_order
            << "}";
        first = false;
    }
    oss << "]}";

    return oss.str();
}

} // namespace engine
