#pragma once

#include <string>
#include <vector>
#include <memory>
#include <fstream>
#include <optional>
#include "engine/types.hpp"
#include "engine/capture_format.hpp"

namespace engine {

enum class CaptureFileFormat {
    Unknown,
    ClassicPcap,
    PcapNg
};

class CaptureReader {
public:
    CaptureReader() = default;
    ~CaptureReader();

    [[nodiscard]] StatusCode open(const std::string& file_path, std::string& error_msg);
    [[nodiscard]] StatusCode read_next_packet(RawPacket& out_packet);
    void close();

    [[nodiscard]] bool is_open() const;
    [[nodiscard]] bool is_eof() const;
    [[nodiscard]] CaptureFileFormat get_format() const;
    [[nodiscard]] const std::vector<CaptureInterfaceInfo>& get_interfaces() const;
    [[nodiscard]] PacketSourceStats get_stats() const;

private:
    [[nodiscard]] StatusCode detect_and_open_pcap(uint32_t magic, std::string& error_msg);
    [[nodiscard]] StatusCode detect_and_open_pcapng(std::string& error_msg);
    [[nodiscard]] StatusCode read_pcap_packet(RawPacket& out_packet);
    [[nodiscard]] StatusCode read_pcapng_packet(RawPacket& out_packet);

    std::ifstream file_;
    std::string file_path_;
    CaptureFileFormat format_{CaptureFileFormat::Unknown};
    bool is_open_{false};
    bool is_eof_{false};
    bool byte_swapped_{false};
    uint64_t packet_index_{0};
    PacketSourceStats stats_{};

    // Classic PCAP metadata
    TimestampResolution pcap_ts_resolution_{TimestampResolution::Microsecond};
    LinkType pcap_link_type_{LinkType::Ethernet};
    uint32_t pcap_snaplen_{65535};

    // PCAPNG metadata
    std::vector<CaptureInterfaceInfo> interfaces_;
};

} // namespace engine
