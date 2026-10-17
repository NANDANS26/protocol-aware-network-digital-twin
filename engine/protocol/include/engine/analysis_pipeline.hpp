#pragma once

#include "engine/packet_source.hpp"
#include "engine/flow/flow_table.hpp"
#include "engine/flow/tcp_state_tracker.hpp"
#include "engine/reassembly/tcp_stream_reassembler.hpp"
#include "engine/decoders/ethernet_decoder.hpp"
#include "engine/decoders/ipv4_decoder.hpp"
#include "engine/decoders/ipv6_decoder.hpp"
#include "engine/decoders/arp_decoder.hpp"
#include "engine/decoders/icmp_decoder.hpp"
#include "engine/decoders/tcp_decoder.hpp"
#include "engine/decoders/udp_decoder.hpp"
#include "engine/protocols/dns_parser.hpp"
#include "engine/protocols/http_parser.hpp"
#include "engine/protocols/tls_parser.hpp"
#include "engine/protocols/quic_classifier.hpp"

#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <memory>
#include <fstream>

namespace engine {

struct PipelineConfig {
    std::string input_path;
    std::string events_output_path;
    std::string summary_output_path;
    bool enable_reassembly{true};
    size_t max_payload_preview_bytes{256};
    std::optional<uint64_t> max_packets;
};

struct FlowRecordSummary {
    std::string flow_id;
    std::string ip_proto;
    std::string src_ip;
    uint16_t src_port{0};
    std::string dst_ip;
    uint16_t dst_port{0};
    std::optional<uint16_t> vlan_id;
    std::string state;
    uint64_t packets_forward{0};
    uint64_t packets_reverse{0};
    uint64_t bytes_forward{0};
    uint64_t bytes_reverse{0};
    uint64_t start_ns{0};
    uint64_t last_ns{0};
    double duration_ms{0.0};
    std::string app_protocol{"UNKNOWN"};
    std::string info;
    uint32_t retransmissions{0};
    uint32_t out_of_order{0};
};

struct AnalysisReport {
    std::string capture_file;
    uint64_t total_packets{0};
    uint64_t total_bytes{0};
    uint64_t wire_bytes{0};
    double duration_ms{0.0};
    std::string start_time_iso;
    std::string end_time_iso;
    double packets_per_sec{0.0};
    double throughput_mbps{0.0};

    std::unordered_map<std::string, uint64_t> protocol_counts;
    std::unordered_map<std::string, uint64_t> parser_status_counts;
    std::unordered_map<std::string, uint64_t> tcp_state_counts;

    size_t total_flows{0};
    uint64_t dns_queries{0};
    uint64_t dns_responses{0};
    uint64_t http_requests{0};
    uint64_t http_responses{0};
    uint64_t tls_handshakes{0};
    uint64_t quic_datagrams{0};

    std::vector<std::string> anomalies;
    std::vector<FlowRecordSummary> flows;

    std::string to_json() const;
};

class AnalysisPipeline {
public:
    explicit AnalysisPipeline(PipelineConfig config);
    ~AnalysisPipeline();

    // Run the pipeline synchronously
    AnalysisReport run();

private:
    std::string format_iso_timestamp(uint64_t ns) const;
    std::string generate_event_id(uint64_t packet_idx, uint64_t ts_ns) const;
    void emit_event(const std::string& json_line);

    PipelineConfig config_;
    std::unique_ptr<std::ofstream> event_writer_;
    flow::FlowTable flow_table_;
};

} // namespace engine
