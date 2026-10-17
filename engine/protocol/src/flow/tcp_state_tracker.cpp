#include "engine/flow/tcp_state_tracker.hpp"

namespace engine::flow {

void TcpStateTracker::process_packet(
    const decoders::DecodedTcp& tcp,
    FlowDirection direction,
    uint64_t /* timestamp_ns */
) {
    EndpointTcpState& sender_state = (direction == FlowDirection::Forward) ? fwd_state_ : rev_state_;
    EndpointTcpState& receiver_state = (direction == FlowDirection::Forward) ? rev_state_ : fwd_state_;

    const uint32_t payload_len = static_cast<uint32_t>(tcp.payload.size());

    // 1. Handle RST
    if (tcp.flag_rst) {
        state_ = TcpState::Reset;
        return;
    }

    // 2. Handle SYN and 3-way Handshake
    if (tcp.flag_syn) {
        if (!tcp.flag_ack) {
            // First SYN (Initiator)
            if (state_ == TcpState::Closed || state_ == TcpState::TimeWait || state_ == TcpState::Reset) {
                generation_++;
                handshake_syn_ = true;
                handshake_syn_ack_ = false;
                handshake_ack_ = false;
                sender_state.initial_seq = tcp.sequence_number;
                sender_state.next_expected_seq = tcp.sequence_number + 1;
                sender_state.highest_seq_seen = tcp.sequence_number;
                state_ = TcpState::SynSent;
            } else if (state_ == TcpState::SynSent && tcp.sequence_number == sender_state.initial_seq) {
                // SYN retransmission
                sender_state.retransmit_count++;
            }
            return;
        } else {
            // SYN-ACK (Responder)
            if (state_ == TcpState::SynSent) {
                handshake_syn_ack_ = true;
                sender_state.initial_seq = tcp.sequence_number;
                sender_state.next_expected_seq = tcp.sequence_number + 1;
                sender_state.highest_seq_seen = tcp.sequence_number;
                state_ = TcpState::SynReceived;
            } else if (state_ == TcpState::SynReceived && tcp.sequence_number == sender_state.initial_seq) {
                // SYN-ACK retransmission
                sender_state.retransmit_count++;
            }
            return;
        }
    }

    // 3. Complete 3-way Handshake (Final ACK)
    if (state_ == TcpState::SynReceived && tcp.flag_ack && !tcp.flag_syn && !tcp.flag_fin) {
        if (handshake_syn_ && handshake_syn_ack_) {
            handshake_ack_ = true;
            state_ = TcpState::Established;
        }
    }

    // 4. If packet arrives in Closed state with data or ACK, it's Midstream
    if (state_ == TcpState::Closed) {
        state_ = TcpState::Midstream;
    }

    // 5. Duplicate ACK detection
    if (tcp.flag_ack && payload_len == 0 && !tcp.flag_syn && !tcp.flag_fin) {
        if (tcp.acknowledgment_number == sender_state.last_ack_seen && tcp.window_size == sender_state.last_window) {
            sender_state.dup_ack_count++;
        } else {
            sender_state.last_ack_seen = tcp.acknowledgment_number;
            sender_state.last_window = tcp.window_size;
        }
    }

    // 6. Retransmission & Out-of-order detection for data
    if (payload_len > 0) {
        if (sender_state.highest_seq_seen > 0) {
            int32_t diff = static_cast<int32_t>(tcp.sequence_number - sender_state.highest_seq_seen);
            if (diff < 0) {
                // Sequence number is before highest seen -> retransmission
                sender_state.retransmit_count++;
            } else if (diff > 0) {
                // Gap in sequence space -> out-of-order segment
                sender_state.out_of_order_count++;
                sender_state.highest_seq_seen = tcp.sequence_number + payload_len;
            } else {
                sender_state.highest_seq_seen = tcp.sequence_number + payload_len;
            }
        } else {
            sender_state.highest_seq_seen = tcp.sequence_number + payload_len;
        }
    }

    // 7. FIN and teardown state transitions
    if (tcp.flag_fin) {
        sender_state.is_fin_seen = 1;
        if (state_ == TcpState::Established || state_ == TcpState::Midstream) {
            state_ = (direction == FlowDirection::Forward) ? TcpState::FinWait1 : TcpState::CloseWait;
        } else if (state_ == TcpState::FinWait1) {
            if (tcp.flag_ack) {
                state_ = TcpState::TimeWait;
            } else {
                state_ = TcpState::Closing;
            }
        } else if (state_ == TcpState::FinWait2) {
            state_ = TcpState::TimeWait;
        } else if (state_ == TcpState::CloseWait) {
            state_ = TcpState::LastAck;
        }
        return;
    }

    if (tcp.flag_ack) {
        if (state_ == TcpState::FinWait1 && receiver_state.is_fin_seen) {
            state_ = TcpState::FinWait2;
        } else if (state_ == TcpState::Closing && receiver_state.is_fin_seen) {
            state_ = TcpState::TimeWait;
        } else if (state_ == TcpState::LastAck && receiver_state.is_fin_seen) {
            state_ = TcpState::Closed;
        }
    }
}

} // namespace engine::flow
