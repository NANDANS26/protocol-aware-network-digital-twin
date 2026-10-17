#pragma once

#include <cstdint>
#include <string>
#include "engine/flow/flow_key.hpp"
#include "engine/decoders/decoder_types.hpp"

namespace engine::flow {

enum class TcpState {
    Closed,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Reset,
    Midstream
};

inline const char* to_string(TcpState state) {
    switch (state) {
        case TcpState::Closed: return "CLOSED";
        case TcpState::SynSent: return "SYN_SENT";
        case TcpState::SynReceived: return "SYN_RECEIVED";
        case TcpState::Established: return "ESTABLISHED";
        case TcpState::FinWait1: return "FIN_WAIT_1";
        case TcpState::FinWait2: return "FIN_WAIT_2";
        case TcpState::CloseWait: return "CLOSE_WAIT";
        case TcpState::Closing: return "CLOSING";
        case TcpState::LastAck: return "LAST_ACK";
        case TcpState::TimeWait: return "TIME_WAIT";
        case TcpState::Reset: return "RESET";
        case TcpState::Midstream: return "MIDSTREAM";
        default: return "UNKNOWN";
    }
}

struct EndpointTcpState {
    uint32_t is_syn_seen{0};
    uint32_t is_fin_seen{0};
    uint32_t initial_seq{0};
    uint32_t next_expected_seq{0};
    uint32_t highest_seq_seen{0};
    uint32_t last_ack_seen{0};
    uint32_t dup_ack_count{0};
    uint32_t retransmit_count{0};
    uint32_t out_of_order_count{0};
    uint16_t last_window{0};
};

class TcpStateTracker {
public:
    TcpStateTracker() = default;

    void process_packet(
        const decoders::DecodedTcp& tcp,
        FlowDirection direction,
        uint64_t timestamp_ns
    );

    [[nodiscard]] TcpState get_state() const { return state_; }
    [[nodiscard]] bool is_established() const { return state_ == TcpState::Established; }
    [[nodiscard]] bool is_closed() const {
        return state_ == TcpState::Closed || state_ == TcpState::TimeWait || state_ == TcpState::Reset;
    }
    [[nodiscard]] uint32_t get_generation() const { return generation_; }
    [[nodiscard]] uint32_t get_retransmit_count() const {
        return fwd_state_.retransmit_count + rev_state_.retransmit_count;
    }
    [[nodiscard]] uint32_t get_out_of_order_count() const {
        return fwd_state_.out_of_order_count + rev_state_.out_of_order_count;
    }
    [[nodiscard]] uint32_t get_dup_ack_count() const {
        return fwd_state_.dup_ack_count + rev_state_.dup_ack_count;
    }

private:
    TcpState state_{TcpState::Closed};
    uint32_t generation_{0};
    EndpointTcpState fwd_state_{}; // Initiator -> Responder
    EndpointTcpState rev_state_{}; // Responder -> Initiator
    bool handshake_syn_{false};
    bool handshake_syn_ack_{false};
    bool handshake_ack_{false};
};

} // namespace engine::flow
