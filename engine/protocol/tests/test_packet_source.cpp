#include "doctest.h"
#include "engine/packet_source.hpp"

TEST_CASE("SyntheticPacketSource: generates requested count with valid headers") {
    engine::SyntheticPacketSource src(5);
    std::string err;

    REQUIRE(src.open(err) == engine::StatusCode::Success);
    CHECK(src.is_open());
    CHECK(!src.is_eof());

    engine::RawPacket pkt;
    for (int i = 0; i < 5; ++i) {
        REQUIRE(src.read_next_packet(pkt) == engine::StatusCode::Success);
        CHECK(pkt.index == static_cast<uint64_t>(i));
        CHECK(pkt.wire_length_bytes == 64);
        CHECK(pkt.capture_length_bytes == 64);
        CHECK(pkt.data.size() == 64);

        // Verify Ethernet IPv4 EtherType (0x0800)
        CHECK(pkt.data[12] == 0x08);
        CHECK(pkt.data[13] == 0x00);

        // Verify IPv4 protocol TCP (6)
        CHECK(pkt.data[23] == 0x06);
    }

    CHECK(src.is_eof());
    CHECK(src.read_next_packet(pkt) == engine::StatusCode::EndOfFile);

    auto stats = src.get_stats();
    CHECK(stats.packets_received == 5);
    CHECK(stats.bytes_received == 5 * 64);

    src.close();
    CHECK(!src.is_open());
}

TEST_CASE("PcapFilePacketSource: handles missing file cleanly") {
    engine::PcapFilePacketSource src("non_existent_file_98765.pcap");
    std::string err;

    CHECK(src.open(err) == engine::StatusCode::SourceOpenFailed);
    CHECK(!src.is_open());
    CHECK(!err.empty());
}

TEST_CASE("LivePacketSource: reports permission/driver requirement gracefully") {
    engine::LivePacketSource src("eth0", false, 65535);
    std::string err;

    CHECK(src.open(err) == engine::StatusCode::PermissionDenied);
    CHECK(!src.is_open());
    CHECK(!err.empty());
}
