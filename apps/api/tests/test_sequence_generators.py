"""
Unit tests for Stateful Sequence Generators and Mutation Operators (Phase 05).
"""

from network_twin.testing.sequence_generators import (
    apply_sequence_mutations,
    generate_all_canonical_sequences,
    generate_ip_fragmentation,
    generate_segmented_http_stream,
    generate_tcp_handshake_teardown,
    generate_tcp_retransmission_and_ooo,
    generate_tcp_rst_and_abort,
    generate_tcp_simultaneous_flows,
    sequence_to_pcap_bytes,
    sequence_to_pcapng_bytes,
)
from network_twin.testing.sequence_models import (
    ConnectionState,
    SequenceMutation,
    SequenceMutationType,
    SequenceType,
)


def test_generate_tcp_handshake_teardown():
    seq = generate_tcp_handshake_teardown(seed=42)
    assert seq.sequence_type == SequenceType.TCP_HANDSHAKE_TEARDOWN
    assert len(seq.steps) == 9
    assert seq.is_supported is True

    # Step 0 must be SYN, Step 1 SYN-ACK, Step 2 ACK
    assert seq.steps[0].tcp_flags["syn"] is True
    assert seq.steps[0].tcp_flags["ack"] is False

    assert seq.steps[1].tcp_flags["syn"] is True
    assert seq.steps[1].tcp_flags["ack"] is True

    assert seq.steps[2].tcp_flags["syn"] is False
    assert seq.steps[2].tcp_flags["ack"] is True

    # Transition assertions
    states = [t.expected_state for t in seq.expected_transitions]
    assert ConnectionState.SYN_SENT in states
    assert ConnectionState.SYN_RECEIVED in states
    assert ConnectionState.ESTABLISHED in states
    assert ConnectionState.FIN_WAIT_1 in states
    assert ConnectionState.TIME_WAIT in states


def test_generate_tcp_retransmission_and_ooo():
    seq = generate_tcp_retransmission_and_ooo(seed=101, wraparound_test=False)
    assert seq.sequence_type == SequenceType.TCP_RETRANSMISSION_OOO
    assert len(seq.steps) == 7
    assert seq.expected_properties["out_of_order_expected"] is True
    assert seq.expected_properties["retransmission_expected"] is True

    # Test 32-bit wraparound generation
    seq_wrap = generate_tcp_retransmission_and_ooo(seed=102, wraparound_test=True)
    assert seq_wrap.steps[0].tcp_seq == 0xFFFFFF00


def test_generate_tcp_rst_and_abort():
    seq = generate_tcp_rst_and_abort(seed=103)
    assert seq.sequence_type == SequenceType.TCP_RST_AND_ABORT
    assert len(seq.steps) == 4
    assert seq.steps[3].tcp_flags["rst"] is True

    reset_trans = [t for t in seq.expected_transitions if t.expected_state == ConnectionState.RESET]
    assert len(reset_trans) == 1


def test_generate_tcp_simultaneous_flows():
    seq = generate_tcp_simultaneous_flows(seed=104)
    assert seq.sequence_type == SequenceType.TCP_SIMULTANEOUS_FLOWS
    assert seq.expected_flow_count == 2
    assert len(seq.steps) == 7

    # Flow A has 192.168.1.100, Flow B has 10.0.0.5
    src_ips = {s.source_ip for s in seq.steps}
    assert "192.168.1.100" in src_ips
    assert "10.0.0.5" in src_ips


def test_generate_ip_fragmentation_documents_coverage_gap():
    seq = generate_ip_fragmentation(seed=105)
    assert seq.sequence_type == SequenceType.IP_FRAGMENTATION
    assert seq.is_supported is False
    assert seq.coverage_gap_notes is not None
    assert "reassembly cache" in seq.coverage_gap_notes.lower()


def test_generate_segmented_http_stream():
    seq = generate_segmented_http_stream(seed=106)
    assert seq.sequence_type == SequenceType.HTTP_SEGMENTED_STREAM
    assert len(seq.steps) == 6
    assert seq.steps[3].payload_hex != ""


def test_pcap_and_pcapng_serialization():
    seq = generate_tcp_handshake_teardown(seed=42)
    pcap_data = sequence_to_pcap_bytes(seq)
    assert len(pcap_data) > 24
    assert pcap_data[:4] == b"\xd4\xc3\xb2\xa1"  # Little-endian microsecond magic

    pcapng_data = sequence_to_pcapng_bytes(seq)
    assert len(pcapng_data) > 32
    assert pcapng_data[:4] == b"\n\r\r\n"  # Section Header Block magic


def test_deterministic_sequence_generation():
    seq1 = generate_tcp_handshake_teardown(seed=1337)
    seq2 = generate_tcp_handshake_teardown(seed=1337)
    assert seq1.steps[0].tcp_seq == seq2.steps[0].tcp_seq
    assert sequence_to_pcap_bytes(seq1) == sequence_to_pcap_bytes(seq2)


def test_sequence_mutation_operators():
    base_seq = generate_tcp_handshake_teardown(seed=50)

    # 1. Reorder
    mut_reorder = SequenceMutation(
        mutation_type=SequenceMutationType.REORDER_PACKETS,
        parameters={"idx1": 3, "idx2": 4},
        description="Reorder step 3 and 4",
    )
    reordered_seq = apply_sequence_mutations(base_seq, [mut_reorder], seed=51)
    assert len(reordered_seq.steps) == len(base_seq.steps)
    assert reordered_seq.steps[3].label == base_seq.steps[4].label

    # 2. Duplicate
    mut_dup = SequenceMutation(
        mutation_type=SequenceMutationType.DUPLICATE_PACKET,
        parameters={"target_step": 3},
        description="Duplicate step 3",
    )
    dup_seq = apply_sequence_mutations(base_seq, [mut_dup], seed=52)
    assert len(dup_seq.steps) == len(base_seq.steps) + 1

    # 3. Drop
    mut_drop = SequenceMutation(
        mutation_type=SequenceMutationType.DROP_PACKET,
        parameters={"target_step": 3},
        description="Drop step 3",
    )
    drop_seq = apply_sequence_mutations(base_seq, [mut_drop], seed=53)
    assert len(drop_seq.steps) == len(base_seq.steps) - 1

    # 4. Insert Noise
    mut_noise = SequenceMutation(
        mutation_type=SequenceMutationType.INSERT_UNRELATED_NOISE,
        parameters={},
        description="Inject noise",
    )
    noise_seq = apply_sequence_mutations(base_seq, [mut_noise], seed=54)
    assert len(noise_seq.steps) == len(base_seq.steps) + 1
    assert any(s.is_noise for s in noise_seq.steps)


def test_generate_all_canonical_sequences():
    all_seqs = generate_all_canonical_sequences(seed=10)
    assert len(all_seqs) == 7
    types = {s.sequence_type for s in all_seqs}
    assert SequenceType.TCP_HANDSHAKE_TEARDOWN in types
    assert SequenceType.TCP_SIMULTANEOUS_FLOWS in types
    assert SequenceType.IP_FRAGMENTATION in types
