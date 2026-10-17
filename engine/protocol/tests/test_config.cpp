#include "doctest.h"
#include "engine/config.hpp"

TEST_CASE("EngineConfig: default configuration is valid") {
    engine::EngineConfig cfg;
    std::string err;
    CHECK(cfg.validate(err) == engine::StatusCode::Success);
    CHECK(err.empty());
}

TEST_CASE("EngineConfig: rejects zero snaplen") {
    engine::EngineConfig cfg;
    cfg.snaplen_bytes = 0;
    std::string err;
    CHECK(cfg.validate(err) == engine::StatusCode::InvalidConfig);
    CHECK(!err.empty());
}

TEST_CASE("EngineConfig: rejects small buffer size") {
    engine::EngineConfig cfg;
    cfg.buffer_size_bytes = 1024; // smaller than 64KB minimum
    std::string err;
    CHECK(cfg.validate(err) == engine::StatusCode::InvalidConfig);
    CHECK(!err.empty());
}

TEST_CASE("EngineConfig: PcapFile requires non-empty path") {
    engine::EngineConfig cfg;
    cfg.source_type = engine::PacketSourceType::PcapFile;
    cfg.source_target = "";
    std::string err;
    CHECK(cfg.validate(err) == engine::StatusCode::InvalidConfig);

    cfg.source_target = "capture.pcap";
    CHECK(cfg.validate(err) == engine::StatusCode::Success);
}

TEST_CASE("EngineConfig: LiveInterface requires interface target") {
    engine::EngineConfig cfg;
    cfg.source_type = engine::PacketSourceType::LiveInterface;
    cfg.source_target = "";
    std::string err;
    CHECK(cfg.validate(err) == engine::StatusCode::InvalidConfig);

    cfg.source_target = "eth0";
    CHECK(cfg.validate(err) == engine::StatusCode::Success);
}
