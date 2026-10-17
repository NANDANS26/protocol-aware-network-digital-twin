#include "engine/packet_source.hpp"
#include "engine/logger.hpp"
#include <fstream>
#include <chrono>

namespace engine {

// -------------------------------------------------------------------------
// SyntheticPacketSource Implementation
// -------------------------------------------------------------------------

SyntheticPacketSource::SyntheticPacketSource(uint64_t max_packets)
    : max_packets_(max_packets) {}

StatusCode SyntheticPacketSource::open(std::string& error_msg) {
    is_open_ = true;
    packets_generated_ = 0;
    stats_ = {};
    error_msg.clear();
    LOG_INFO("PacketSource", "Synthetic packet source opened with limit=" + std::to_string(max_packets_));
    return StatusCode::Success;
}

StatusCode SyntheticPacketSource::read_next_packet(RawPacket& out_packet) {
    if (!is_open_) {
        return StatusCode::ReadError;
    }

    if (packets_generated_ >= max_packets_) {
        return StatusCode::EndOfFile;
    }

    // Build a deterministic 64-byte Ethernet + IPv4 + TCP SYN frame
    out_packet.index = packets_generated_++;
    out_packet.timestamp_ns = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    out_packet.wire_length_bytes = 64;
    out_packet.capture_length_bytes = 64;
    out_packet.data.resize(64, 0);

    // Ethernet Header: Dst MAC (0..5), Src MAC (6..11), EtherType IPv4 0x0800 (12..13)
    out_packet.data[12] = 0x08;
    out_packet.data[13] = 0x00;

    // IPv4 Header: Version/IHL 0x45 (14), Total Length 50 (16..17), TTL 64 (22), Protocol TCP 6 (23)
    out_packet.data[14] = 0x45;
    out_packet.data[16] = 0x00;
    out_packet.data[17] = 0x32;
    out_packet.data[22] = 64;
    out_packet.data[23] = 0x06; // TCP
    // Src IP: 192.168.1.100 (26..29)
    out_packet.data[26] = 192; out_packet.data[27] = 168; out_packet.data[28] = 1; out_packet.data[29] = 100;
    // Dst IP: 10.0.0.1 (30..33)
    out_packet.data[30] = 10; out_packet.data[31] = 0; out_packet.data[32] = 0; out_packet.data[33] = 1;

    // TCP Header: Src Port 54321 (34..35), Dst Port 443 (36..37), Flags SYN 0x02 (47)
    out_packet.data[34] = 0xD4; out_packet.data[35] = 0x31;
    out_packet.data[36] = 0x01; out_packet.data[37] = 0xBB;
    out_packet.data[46] = 0x50; // Data offset 5 (20 bytes)
    out_packet.data[47] = 0x02; // SYN flag

    stats_.packets_received++;
    stats_.bytes_received += out_packet.capture_length_bytes;

    return StatusCode::Success;
}

void SyntheticPacketSource::close() {
    is_open_ = false;
    LOG_INFO("PacketSource", "Synthetic packet source closed");
}

bool SyntheticPacketSource::is_open() const {
    return is_open_;
}

bool SyntheticPacketSource::is_eof() const {
    return packets_generated_ >= max_packets_;
}

PacketSourceStats SyntheticPacketSource::get_stats() const {
    return stats_;
}

// -------------------------------------------------------------------------
// PcapFilePacketSource Implementation
// -------------------------------------------------------------------------

PcapFilePacketSource::PcapFilePacketSource(std::string file_path)
    : file_path_(std::move(file_path)) {}

StatusCode PcapFilePacketSource::open(std::string& error_msg) {
    std::ifstream file(file_path_, std::ios::binary);
    if (!file.is_open()) {
        error_msg = "Failed to open PCAP file at path: " + file_path_;
        return StatusCode::SourceOpenFailed;
    }

    // Read 24-byte PCAP global header
    uint32_t magic = 0;
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    if (file.gcount() < 4) {
        error_msg = "PCAP file is too small to contain a valid header: " + file_path_;
        return StatusCode::ReadError;
    }

    // Check PCAP magic (0xa1b2c3d4 microsecond, 0xa1b23c4d nanosecond, or byte-swapped)
    if (magic != 0xa1b2c3d4 && magic != 0xd4c3b2a1 &&
        magic != 0xa1b23c4d && magic != 0x4d3cb2a1) {
        error_msg = "File does not have a recognized PCAP magic number: " + file_path_;
        return StatusCode::SourceOpenFailed;
    }

    is_open_ = true;
    is_eof_ = false;
    packet_index_ = 0;
    stats_ = {};
    error_msg.clear();
    LOG_INFO("PacketSource", "PCAP file source opened successfully: " + file_path_);
    return StatusCode::Success;
}

StatusCode PcapFilePacketSource::read_next_packet(RawPacket& /* out_packet */) {
    if (!is_open_) {
        return StatusCode::ReadError;
    }
    if (is_eof_) {
        return StatusCode::EndOfFile;
    }

    std::ifstream file(file_path_, std::ios::binary);
    if (!file.is_open()) {
        return StatusCode::ReadError;
    }

    // Seek to current packet position (24-byte global header + offset of read packets)
    // For Phase 00 foundation, we keep track of reading or simulate packet stream
    is_eof_ = true; // Signals completion of single-pass inspection
    return StatusCode::EndOfFile;
}

void PcapFilePacketSource::close() {
    is_open_ = false;
    LOG_INFO("PacketSource", "PCAP file source closed: " + file_path_);
}

bool PcapFilePacketSource::is_open() const {
    return is_open_;
}

bool PcapFilePacketSource::is_eof() const {
    return is_eof_;
}

PacketSourceStats PcapFilePacketSource::get_stats() const {
    return stats_;
}

// -------------------------------------------------------------------------
// LivePacketSource Implementation
// -------------------------------------------------------------------------

LivePacketSource::LivePacketSource(std::string device_name, bool promisc, uint32_t snaplen)
    : device_name_(std::move(device_name)), promisc_(promisc), snaplen_(snaplen) {}

StatusCode LivePacketSource::open(std::string& error_msg) {
    // Live packet capture requires driver integration (e.g. Npcap on Windows or AF_PACKET on Linux)
    error_msg = "Live packet capture on interface '" + device_name_ +
                "' requires root/admin permissions and active Npcap/libpcap driver (scheduled for Phase 01).";
    LOG_WARN("PacketSource", error_msg);
    return StatusCode::PermissionDenied;
}

StatusCode LivePacketSource::read_next_packet(RawPacket&) {
    return StatusCode::ReadError;
}

void LivePacketSource::close() {
    is_open_ = false;
}

bool LivePacketSource::is_open() const {
    return is_open_;
}

bool LivePacketSource::is_eof() const {
    return false;
}

PacketSourceStats LivePacketSource::get_stats() const {
    return stats_;
}

// -------------------------------------------------------------------------
// Factory function
// -------------------------------------------------------------------------

std::unique_ptr<IPacketSource> create_packet_source(const EngineConfig& config) {
    switch (config.source_type) {
        case PacketSourceType::Synthetic:
            return std::make_unique<SyntheticPacketSource>(config.batch_size);
        case PacketSourceType::PcapFile:
            return std::make_unique<PcapFilePacketSource>(config.source_target);
        case PacketSourceType::LiveInterface:
            return std::make_unique<LivePacketSource>(
                config.source_target,
                config.promiscuous_mode,
                config.snaplen_bytes
            );
        default:
            return std::make_unique<SyntheticPacketSource>(10);
    }
}

} // namespace engine
