#pragma once

#include <memory>
#include <string>
#include <vector>
#include "engine/types.hpp"
#include "engine/config.hpp"

namespace engine {

class IPacketSource {
public:
    virtual ~IPacketSource() = default;

    [[nodiscard]] virtual StatusCode open(std::string& error_msg) = 0;
    [[nodiscard]] virtual StatusCode read_next_packet(RawPacket& out_packet) = 0;
    virtual void close() = 0;
    [[nodiscard]] virtual bool is_open() const = 0;
    [[nodiscard]] virtual bool is_eof() const = 0;
    [[nodiscard]] virtual PacketSourceStats get_stats() const = 0;
};

class SyntheticPacketSource : public IPacketSource {
public:
    explicit SyntheticPacketSource(uint64_t max_packets = 10);
    ~SyntheticPacketSource() override = default;

    [[nodiscard]] StatusCode open(std::string& error_msg) override;
    [[nodiscard]] StatusCode read_next_packet(RawPacket& out_packet) override;
    void close() override;
    [[nodiscard]] bool is_open() const override;
    [[nodiscard]] bool is_eof() const override;
    [[nodiscard]] PacketSourceStats get_stats() const override;

private:
    uint64_t max_packets_{10};
    uint64_t packets_generated_{0};
    bool is_open_{false};
    PacketSourceStats stats_;
};

class CaptureReader;

class PcapFilePacketSource : public IPacketSource {
public:
    explicit PcapFilePacketSource(std::string file_path);
    ~PcapFilePacketSource() override;

    [[nodiscard]] StatusCode open(std::string& error_msg) override;
    [[nodiscard]] StatusCode read_next_packet(RawPacket& out_packet) override;
    void close() override;
    [[nodiscard]] bool is_open() const override;
    [[nodiscard]] bool is_eof() const override;
    [[nodiscard]] PacketSourceStats get_stats() const override;

private:
    std::string file_path_;
    std::unique_ptr<CaptureReader> reader_;
};

class LivePacketSource : public IPacketSource {
public:
    explicit LivePacketSource(std::string device_name, bool promisc, uint32_t snaplen);
    ~LivePacketSource() override = default;

    [[nodiscard]] StatusCode open(std::string& error_msg) override;
    [[nodiscard]] StatusCode read_next_packet(RawPacket& out_packet) override;
    void close() override;
    [[nodiscard]] bool is_open() const override;
    [[nodiscard]] bool is_eof() const override;
    [[nodiscard]] PacketSourceStats get_stats() const override;

private:
    std::string device_name_;
    bool promisc_{false};
    uint32_t snaplen_{65535};
    bool is_open_{false};
    PacketSourceStats stats_;
};

std::unique_ptr<IPacketSource> create_packet_source(const EngineConfig& config);

} // namespace engine
