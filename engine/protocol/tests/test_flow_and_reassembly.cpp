#include "doctest.h"
#include "engine/flow/flow_key.hpp"
#include "engine/flow/tcp_state_tracker.hpp"
#include "engine/reassembly/tcp_stream_reassembler.hpp"

using namespace engine::flow;
using namespace engine::reassembly;
using namespace engine::decoders;

TEST_CASE("FlowKey canonicalizes endpoint order and computes stable hash") {
    FlowKey k1("192.168.1.10", 54321, "10.0.0.1", 80, TransportProtocol::TCP);
    FlowKey k2("10.0.0.1", 80, "192.168.1.10", 54321, TransportProtocol::TCP);

    CHECK(k1 == k2);
    CHECK(k1.to_flow_id() == k2.to_flow_id());
    CHECK(k1.get_packet_direction("192.168.1.10", 54321) == FlowDirection::Forward);
    CHECK(k2.get_packet_direction("192.168.1.10", 54321) == FlowDirection::Reverse);
}

TEST_CASE("TcpStateTracker tracks full 3-way handshake and clean teardown") {
    TcpStateTracker tracker;
    CHECK(tracker.get_state() == TcpState::Closed);

    // 1. Client sends SYN (seq = 1000)
    DecodedTcp syn_seg;
    syn_seg.flag_syn = true;
    syn_seg.sequence_number = 1000;
    tracker.process_packet(syn_seg, FlowDirection::Forward, 1000);
    CHECK(tracker.get_state() == TcpState::SynSent);

    // 2. Server sends SYN+ACK (seq = 5000, ack = 1001)
    DecodedTcp syn_ack_seg;
    syn_ack_seg.flag_syn = true;
    syn_ack_seg.flag_ack = true;
    syn_ack_seg.sequence_number = 5000;
    syn_ack_seg.acknowledgment_number = 1001;
    tracker.process_packet(syn_ack_seg, FlowDirection::Reverse, 2000);
    CHECK(tracker.get_state() == TcpState::SynReceived);

    // 3. Client sends ACK (seq = 1001, ack = 5001)
    DecodedTcp ack_seg;
    ack_seg.flag_ack = true;
    ack_seg.sequence_number = 1001;
    ack_seg.acknowledgment_number = 5001;
    tracker.process_packet(ack_seg, FlowDirection::Forward, 3000);
    CHECK(tracker.get_state() == TcpState::Established);

    // 4. Client sends FIN
    DecodedTcp fin_seg;
    fin_seg.flag_fin = true;
    fin_seg.flag_ack = true;
    fin_seg.sequence_number = 1001;
    fin_seg.acknowledgment_number = 5001;
    tracker.process_packet(fin_seg, FlowDirection::Forward, 4000);
    CHECK(tracker.get_state() == TcpState::FinWait1);

    // 5. Server acks FIN
    DecodedTcp serv_ack;
    serv_ack.flag_ack = true;
    serv_ack.sequence_number = 5001;
    serv_ack.acknowledgment_number = 1002;
    tracker.process_packet(serv_ack, FlowDirection::Reverse, 5000);
    CHECK(tracker.get_state() == TcpState::FinWait2);

    // 6. Server sends FIN
    DecodedTcp serv_fin;
    serv_fin.flag_fin = true;
    serv_fin.flag_ack = true;
    serv_fin.sequence_number = 5001;
    serv_fin.acknowledgment_number = 1002;
    tracker.process_packet(serv_fin, FlowDirection::Reverse, 6000);
    CHECK(tracker.get_state() == TcpState::TimeWait);
}

TEST_CASE("TcpStreamReassembler reassembles out-of-order chunks and detects overlaps") {
    TcpStreamReassembler reassembler;

    // SYN packet at seq 1000
    reassembler.push_segment(true, 1000, std::span<const uint8_t>{}, true, false);
    CHECK(reassembler.get_forward().get_expected_seq() == 1001);

    // Out-of-order data: seq 1006..1010
    const std::vector<uint8_t> chunk2 = {'W', 'O', 'R', 'L', 'D'};
    reassembler.push_segment(true, 1006, chunk2, false, false);
    CHECK(reassembler.get_forward().get_contiguous_size() == 0);
    CHECK(reassembler.get_forward().get_out_of_order_segment_count() == 1);

    // In-order data fills gap: seq 1001..1005
    const std::vector<uint8_t> chunk1 = {'H', 'E', 'L', 'L', 'O'};
    reassembler.push_segment(true, 1001, chunk1, false, false);
    CHECK(reassembler.get_forward().get_contiguous_size() == 10);
    CHECK(reassembler.get_forward().get_expected_seq() == 1011);

    auto data = reassembler.get_forward().get_contiguous_data();
    std::string text(reinterpret_cast<const char*>(data.data()), data.size());
    CHECK(text == "HELLOWORLD");

    // Conflicting overlap segment
    const std::vector<uint8_t> conflict = {'X', 'X', '!'};
    reassembler.push_segment(true, 1008, conflict, false, false);
    CHECK(reassembler.get_forward().has_overlap_conflict() == true);
}
