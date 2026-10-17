#include "doctest.h"
#include "engine/engine.hpp"

TEST_CASE("ProtocolEngine: full lifecycle with synthetic source") {
    engine::EngineConfig cfg;
    cfg.source_type = engine::PacketSourceType::Synthetic;
    cfg.batch_size = 8;
    cfg.log_level = "ERROR"; // quiet test output

    engine::ProtocolEngine eng(cfg);
    std::string err;

    REQUIRE(eng.initialize(err) == engine::StatusCode::Success);
    CHECK(!eng.is_running());

    REQUIRE(eng.start(err) == engine::StatusCode::Success);
    CHECK(eng.is_running());

    uint32_t processed = eng.process_batch(5);
    CHECK(processed == 5);

    auto metrics = eng.get_metrics();
    CHECK(metrics.total_packets_processed == 5);
    CHECK(metrics.total_bytes_processed == 5 * 64);
    CHECK(metrics.total_parse_errors == 0);

    // Process remaining
    processed = eng.process_batch(10);
    CHECK(processed == 3); // 8 - 5 = 3 remaining

    // Engine should have stopped automatically on EOF
    CHECK(!eng.is_running());

    eng.stop();
}

TEST_CASE("ProtocolEngine: rejects invalid configuration during initialization") {
    engine::EngineConfig cfg;
    cfg.snaplen_bytes = 0; // Invalid
    cfg.log_level = "ERROR";

    engine::ProtocolEngine eng(cfg);
    std::string err;

    CHECK(eng.initialize(err) == engine::StatusCode::InvalidConfig);
    CHECK(!err.empty());
    CHECK(!eng.is_running());
}
