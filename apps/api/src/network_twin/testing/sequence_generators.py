"""
Stateful Protocol Sequence Generators & Mutation Engine for Phase 05.

Produces multi-packet sequences covering TCP state machine transitions,
retransmissions, out-of-order delivery, flow isolation, IP fragmentation,
DNS transaction matching, and segmented HTTP/TLS application payloads.
"""

from __future__ import annotations

import datetime
import random
import struct

from network_twin.testing.sequence_models import (
    ConnectionState,
    ExpectedStateTransition,
    ProtocolSequence,
    SequenceMutation,
    SequenceMutationType,
    SequenceStep,
    SequenceType,
)


def _ip_to_bytes(ip_str: str) -> bytes:
    parts = [int(p) for p in ip_str.split(".")]
    return struct.pack("!BBBB", *parts)


def _calculate_checksum(data: bytes) -> int:
    if len(data) % 2 != 0:
        data += b"\x00"
    checksum = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    return (~checksum) & 0xFFFF


def _build_ipv4_packet(
    src_ip: str,
    dst_ip: str,
    protocol: int,
    payload: bytes,
    ident: int = 1000,
    frag_offset: int = 0,
    more_frags: bool = False,
    ttl: int = 64,
) -> bytes:
    flags_and_offset = frag_offset & 0x1FFF
    if more_frags:
        flags_and_offset |= 0x2000  # More Fragments bit

    ihl = 5
    version = 4
    ver_ihl = (version << 4) | ihl
    total_len = 20 + len(payload)

    header_without_cksum = (
        struct.pack(
            "!BBHHHBBH",
            ver_ihl,
            0,  # DSCP / ECN
            total_len,
            ident,
            flags_and_offset,
            ttl,
            protocol,
            0,  # Checksum placeholder
        )
        + _ip_to_bytes(src_ip)
        + _ip_to_bytes(dst_ip)
    )

    cksum = _calculate_checksum(header_without_cksum)
    header = (
        struct.pack(
            "!BBHHHBBH",
            ver_ihl,
            0,
            total_len,
            ident,
            flags_and_offset,
            ttl,
            protocol,
            cksum,
        )
        + _ip_to_bytes(src_ip)
        + _ip_to_bytes(dst_ip)
    )

    return header + payload


def _build_tcp_segment(
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: dict[str, bool],
    payload: bytes = b"",
    window: int = 64240,
) -> bytes:
    offset = 5  # 5 * 4 = 20 bytes
    offset_and_reserved = offset << 4

    flags_val = 0
    if flags.get("fin", False):
        flags_val |= 0x01
    if flags.get("syn", False):
        flags_val |= 0x02
    if flags.get("rst", False):
        flags_val |= 0x04
    if flags.get("psh", False):
        flags_val |= 0x08
    if flags.get("ack", False):
        flags_val |= 0x10
    if flags.get("urg", False):
        flags_val |= 0x20

    header = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq & 0xFFFFFFFF,
        ack & 0xFFFFFFFF,
        offset_and_reserved,
        flags_val,
        window,
        0,  # Checksum placeholder (often skipped or zero in trace captures)
        0,  # Urgent pointer
    )
    return header + payload


def _build_ethernet_frame(
    src_mac: str,
    dst_mac: str,
    ethertype: int,
    payload: bytes,
) -> bytes:
    src_b = bytes.fromhex(src_mac.replace(":", ""))
    dst_b = bytes.fromhex(dst_mac.replace(":", ""))
    return dst_b + src_b + struct.pack("!H", ethertype) + payload


def step_to_raw_packet(step: SequenceStep) -> bytes:
    """Converts a logical SequenceStep into a raw Ethernet II packet."""
    payload = bytes.fromhex(step.payload_hex) if step.payload_hex else b""

    if step.protocol.upper() == "TCP":
        l4 = _build_tcp_segment(
            src_port=step.source_port,
            dst_port=step.destination_port,
            seq=step.tcp_seq,
            ack=step.tcp_ack,
            flags=step.tcp_flags,
            payload=payload,
            window=step.tcp_window,
        )
        proto_num = 6
    elif step.protocol.upper() == "UDP":
        udp_len = 8 + len(payload)
        l4 = struct.pack("!HHHH", step.source_port, step.destination_port, udp_len, 0) + payload
        proto_num = 17
    elif step.protocol.upper() == "ICMP":
        l4 = struct.pack("!BBHHH", 8, 0, 0, 1, 1) + payload  # Echo Request
        l4 = struct.pack("!BBHHH", 8, 0, _calculate_checksum(l4), 1, 1) + payload
        proto_num = 1
    else:
        l4 = payload
        proto_num = 254  # Experimental

    l3 = _build_ipv4_packet(
        src_ip=step.source_ip,
        dst_ip=step.destination_ip,
        protocol=proto_num,
        payload=l4,
        ident=step.ip_id,
        frag_offset=step.ip_fragment_offset,
        more_frags=step.ip_more_fragments,
    )

    src_mac = "00:11:22:33:44:55" if not step.is_noise else "00:aa:bb:cc:dd:ee"
    dst_mac = "66:77:88:99:aa:bb" if not step.is_noise else "00:11:22:33:44:00"
    return _build_ethernet_frame(src_mac, dst_mac, 0x0800, l3)


def sequence_to_pcap_bytes(sequence: ProtocolSequence) -> bytes:
    """Serializes a ProtocolSequence to standard microsecond PCAP binary bytes."""
    # Global PCAP Header: Magic 0xa1b2c3d4 (microsecond, native endian), v2.4, tz 0, sigfigs 0, snaplen 65535, linktype 1 (Ethernet)
    global_hdr = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    base_time = 1776412800  # Fixed epoch 2026-04-17 08:00:00 UTC
    packet_records = bytearray()

    for step in sequence.steps:
        raw_pkt = step_to_raw_packet(step)
        offset_sec = step.timestamp_offset_ns // 1_000_000_000
        offset_usec = (step.timestamp_offset_ns % 1_000_000_000) // 1_000
        ts_sec = base_time + offset_sec
        ts_usec = offset_usec

        rec_hdr = struct.pack("<IIII", ts_sec, ts_usec, len(raw_pkt), len(raw_pkt))
        packet_records.extend(rec_hdr)
        packet_records.extend(raw_pkt)

    return global_hdr + bytes(packet_records)


def sequence_to_pcapng_bytes(sequence: ProtocolSequence) -> bytes:
    """Serializes a ProtocolSequence to standard PCAPNG binary bytes."""
    blocks = bytearray()

    # Section Header Block (SHB)
    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    shb_len = 12 + len(shb_body)
    shb = struct.pack("<II", 0x0A0D0D0A, shb_len) + shb_body + struct.pack("<I", shb_len)
    blocks.extend(shb)

    # Interface Description Block (IDB) LinkType 1 (Ethernet), snaplen 65535
    idb_body = struct.pack("<HHI", 1, 0, 65535)
    idb_len = 8 + len(idb_body) + 4
    idb = struct.pack("<II", 0x00000001, idb_len) + idb_body + struct.pack("<I", idb_len)
    blocks.extend(idb)

    # Enhanced Packet Blocks (EPBs)
    base_time = 1776412800
    for step in sequence.steps:
        raw_pkt = step_to_raw_packet(step)
        ts_total_usec = (base_time * 1_000_000) + (step.timestamp_offset_ns // 1_000)
        ts_high = (ts_total_usec >> 32) & 0xFFFFFFFF
        ts_low = ts_total_usec & 0xFFFFFFFF

        cap_len = len(raw_pkt)
        orig_len = len(raw_pkt)
        pad_len = (4 - (cap_len % 4)) % 4
        padded_pkt = raw_pkt + (b"\x00" * pad_len)

        epb_body = struct.pack("<IIII", 0, ts_high, ts_low, cap_len) + struct.pack("<I", orig_len) + padded_pkt
        epb_len = 8 + len(epb_body) + 4
        epb = struct.pack("<II", 0x00000006, epb_len) + epb_body + struct.pack("<I", epb_len)
        blocks.extend(epb)

    return bytes(blocks)


# ==============================================================================
# SEQUENCE GENERATORS
# ==============================================================================


def generate_tcp_handshake_teardown(
    seed: int = 42,
    client_ip: str = "192.168.1.100",
    server_ip: str = "192.168.1.200",
    client_port: int = 49152,
    server_port: int = 80,
) -> ProtocolSequence:
    """Generates a complete RFC 793/9293 3-way handshake, payload exchange, and 4-way FIN teardown."""
    rng = random.Random(seed)
    isn_c = rng.randint(1000, 50000)
    isn_s = rng.randint(50001, 99000)
    flow_id = f"{client_ip}:{client_port}-{server_ip}:{server_port}-TCP"

    steps: list[SequenceStep] = [
        # Step 0: Client -> Server SYN
        SequenceStep(
            step_index=0,
            timestamp_offset_ns=0,
            source_ip=client_ip,
            destination_ip=server_ip,
            source_port=client_port,
            destination_port=server_port,
            tcp_seq=isn_c,
            tcp_ack=0,
            tcp_flags={"syn": True, "ack": False, "fin": False, "rst": False, "psh": False, "urg": False},
            label="SYN (Initiator)",
        ),
        # Step 1: Server -> Client SYN-ACK
        SequenceStep(
            step_index=1,
            timestamp_offset_ns=10_000_000,  # +10ms
            source_ip=server_ip,
            destination_ip=client_ip,
            source_port=server_port,
            destination_port=client_port,
            tcp_seq=isn_s,
            tcp_ack=isn_c + 1,
            tcp_flags={"syn": True, "ack": True, "fin": False, "rst": False, "psh": False, "urg": False},
            label="SYN-ACK (Responder)",
        ),
        # Step 2: Client -> Server ACK -> ESTABLISHED
        SequenceStep(
            step_index=2,
            timestamp_offset_ns=20_000_000,  # +20ms
            source_ip=client_ip,
            destination_ip=server_ip,
            source_port=client_port,
            destination_port=server_port,
            tcp_seq=isn_c + 1,
            tcp_ack=isn_s + 1,
            tcp_flags={"syn": False, "ack": True, "fin": False, "rst": False, "psh": False, "urg": False},
            label="ACK (3-Way Handshake Complete)",
        ),
        # Step 3: Client -> Server Data
        SequenceStep(
            step_index=3,
            timestamp_offset_ns=30_000_000,
            source_ip=client_ip,
            destination_ip=server_ip,
            source_port=client_port,
            destination_port=server_port,
            tcp_seq=isn_c + 1,
            tcp_ack=isn_s + 1,
            tcp_flags={"syn": False, "ack": True, "fin": False, "rst": False, "psh": True, "urg": False},
            payload_hex=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n".hex(),
            label="HTTP Request Payload",
        ),
        # Step 4: Server -> Client ACK for Data
        SequenceStep(
            step_index=4,
            timestamp_offset_ns=40_000_000,
            source_ip=server_ip,
            destination_ip=client_ip,
            source_port=server_port,
            destination_port=client_port,
            tcp_seq=isn_s + 1,
            tcp_ack=isn_c + 1 + len(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            tcp_flags={"syn": False, "ack": True, "fin": False, "rst": False, "psh": False, "urg": False},
            label="Data ACK",
        ),
        # Step 5: Client -> Server FIN -> FIN_WAIT_1
        SequenceStep(
            step_index=5,
            timestamp_offset_ns=50_000_000,
            source_ip=client_ip,
            destination_ip=server_ip,
            source_port=client_port,
            destination_port=server_port,
            tcp_seq=isn_c + 1 + len(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            tcp_ack=isn_s + 1,
            tcp_flags={"syn": False, "ack": True, "fin": True, "rst": False, "psh": False, "urg": False},
            label="Client FIN",
        ),
        # Step 6: Server -> Client ACK -> FIN_WAIT_2
        SequenceStep(
            step_index=6,
            timestamp_offset_ns=60_000_000,
            source_ip=server_ip,
            destination_ip=client_ip,
            source_port=server_port,
            destination_port=client_port,
            tcp_seq=isn_s + 1,
            tcp_ack=isn_c + 2 + len(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            tcp_flags={"syn": False, "ack": True, "fin": False, "rst": False, "psh": False, "urg": False},
            label="Server ACK for FIN",
        ),
        # Step 7: Server -> Client FIN -> TIME_WAIT
        SequenceStep(
            step_index=7,
            timestamp_offset_ns=70_000_000,
            source_ip=server_ip,
            destination_ip=client_ip,
            source_port=server_port,
            destination_port=client_port,
            tcp_seq=isn_s + 1,
            tcp_ack=isn_c + 2 + len(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            tcp_flags={"syn": False, "ack": True, "fin": True, "rst": False, "psh": False, "urg": False},
            label="Server FIN",
        ),
        # Step 8: Client -> Server Final ACK -> CLOSED
        SequenceStep(
            step_index=8,
            timestamp_offset_ns=80_000_000,
            source_ip=client_ip,
            destination_ip=server_ip,
            source_port=client_port,
            destination_port=server_port,
            tcp_seq=isn_c + 2 + len(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            tcp_ack=isn_s + 2,
            tcp_flags={"syn": False, "ack": True, "fin": False, "rst": False, "psh": False, "urg": False},
            label="Client Final ACK (Teardown Complete)",
        ),
    ]

    expected_transitions = [
        ExpectedStateTransition(
            step_index=0, flow_id=flow_id, expected_state=ConnectionState.SYN_SENT, rationale="Initial SYN"
        ),
        ExpectedStateTransition(
            step_index=1, flow_id=flow_id, expected_state=ConnectionState.SYN_RECEIVED, rationale="SYN-ACK received"
        ),
        ExpectedStateTransition(
            step_index=2, flow_id=flow_id, expected_state=ConnectionState.ESTABLISHED, rationale="3-way Handshake ACK"
        ),
        ExpectedStateTransition(
            step_index=5,
            flow_id=flow_id,
            expected_state=ConnectionState.FIN_WAIT_1,
            rationale="Client initiates teardown via FIN",
        ),
        ExpectedStateTransition(
            step_index=7, flow_id=flow_id, expected_state=ConnectionState.TIME_WAIT, rationale="Both FINs exchanged"
        ),
    ]

    return ProtocolSequence(
        sequence_id=f"seq-tcp-handshake-{seed}",
        name="TCP Full Handshake and Graceful Teardown",
        description="RFC 793/9293 stateful sequence covering SYN, SYN-ACK, ACK, Data, FIN, and TIME_WAIT transitions",
        sequence_type=SequenceType.TCP_HANDSHAKE_TEARDOWN,
        seed=seed,
        generator_version="1.0.0",
        steps=steps,
        expected_transitions=expected_transitions,
        expected_flow_count=1,
        expected_properties={"closed_cleanly": True, "retransmission_count": 0, "out_of_order_count": 0},
        format="pcap",
        is_supported=True,
        created_at_iso=datetime.datetime.now(datetime.UTC).isoformat(),
    )


def generate_tcp_retransmission_and_ooo(
    seed: int = 43,
    wraparound_test: bool = False,
) -> ProtocolSequence:
    """Generates a sequence containing out-of-order segment arrival, duplicate segment, retransmissions, and wraparound."""
    rng = random.Random(seed)
    client_ip = "192.168.1.50"
    server_ip = "192.168.1.200"
    client_port = 52100
    server_port = 8080

    isn_c = 0xFFFFFF00 if wraparound_test else rng.randint(1000, 50000)
    isn_s = rng.randint(10000, 40000)
    flow_id = f"{client_ip}:{client_port}-{server_ip}:{server_port}-TCP"

    p1_payload = b"SEGMENT_01_AAAA"
    p2_payload = b"SEGMENT_02_BBBB"
    p3_payload = b"SEGMENT_03_CCCC"

    steps: list[SequenceStep] = [
        # Handshake
        SequenceStep(
            step_index=0,
            timestamp_offset_ns=0,
            source_ip=client_ip,
            destination_ip=server_ip,
            source_port=client_port,
            destination_port=server_port,
            tcp_seq=isn_c,
            tcp_ack=0,
            tcp_flags={"syn": True, "ack": False, "fin": False, "rst": False, "psh": False, "urg": False},
            label="SYN",
        ),
        SequenceStep(
            step_index=1,
            timestamp_offset_ns=10_000_000,
            source_ip=server_ip,
            destination_ip=client_ip,
            source_port=server_port,
            destination_port=client_port,
            tcp_seq=isn_s,
            tcp_ack=(isn_c + 1) & 0xFFFFFFFF,
            tcp_flags={"syn": True, "ack": True, "fin": False, "rst": False, "psh": False, "urg": False},
            label="SYN-ACK",
        ),
        SequenceStep(
            step_index=2,
            timestamp_offset_ns=20_000_000,
            source_ip=client_ip,
            destination_ip=server_ip,
            source_port=client_port,
            destination_port=server_port,
            tcp_seq=(isn_c + 1) & 0xFFFFFFFF,
            tcp_ack=(isn_s + 1) & 0xFFFFFFFF,
            tcp_flags={"syn": False, "ack": True, "fin": False, "rst": False, "psh": False, "urg": False},
            label="Handshake ACK -> ESTABLISHED",
        ),
        # Segment 1 delivered normally
        SequenceStep(
            step_index=3,
            timestamp_offset_ns=30_000_000,
            source_ip=client_ip,
            destination_ip=server_ip,
            source_port=client_port,
            destination_port=server_port,
            tcp_seq=(isn_c + 1) & 0xFFFFFFFF,
            tcp_ack=(isn_s + 1) & 0xFFFFFFFF,
            tcp_flags={"syn": False, "ack": True, "fin": False, "rst": False, "psh": False, "urg": False},
            payload_hex=p1_payload.hex(),
            label="Data Segment 1 (In Order)",
        ),
        # Segment 3 arrives BEFORE Segment 2 -> Out of order! Gap created!
        SequenceStep(
            step_index=4,
            timestamp_offset_ns=40_000_000,
            source_ip=client_ip,
            destination_ip=server_ip,
            source_port=client_port,
            destination_port=server_port,
            tcp_seq=(isn_c + 1 + len(p1_payload) + len(p2_payload)) & 0xFFFFFFFF,
            tcp_ack=(isn_s + 1) & 0xFFFFFFFF,
            tcp_flags={"syn": False, "ack": True, "fin": False, "rst": False, "psh": False, "urg": False},
            payload_hex=p3_payload.hex(),
            label="Data Segment 3 (Out of Order, Gap Present)",
        ),
        # Segment 2 arrives -> fills gap
        SequenceStep(
            step_index=5,
            timestamp_offset_ns=50_000_000,
            source_ip=client_ip,
            destination_ip=server_ip,
            source_port=client_port,
            destination_port=server_port,
            tcp_seq=(isn_c + 1 + len(p1_payload)) & 0xFFFFFFFF,
            tcp_ack=(isn_s + 1) & 0xFFFFFFFF,
            tcp_flags={"syn": False, "ack": True, "fin": False, "rst": False, "psh": False, "urg": False},
            payload_hex=p2_payload.hex(),
            label="Data Segment 2 (Fills Gap)",
        ),
        # Retransmission of Segment 1
        SequenceStep(
            step_index=6,
            timestamp_offset_ns=60_000_000,
            source_ip=client_ip,
            destination_ip=server_ip,
            source_port=client_port,
            destination_port=server_port,
            tcp_seq=(isn_c + 1) & 0xFFFFFFFF,
            tcp_ack=(isn_s + 1) & 0xFFFFFFFF,
            tcp_flags={"syn": False, "ack": True, "fin": False, "rst": False, "psh": False, "urg": False},
            payload_hex=p1_payload.hex(),
            label="Data Segment 1 (Duplicate Retransmission)",
        ),
    ]

    expected_transitions = [
        ExpectedStateTransition(
            step_index=2, flow_id=flow_id, expected_state=ConnectionState.ESTABLISHED, rationale="Handshake complete"
        ),
    ]

    return ProtocolSequence(
        sequence_id=f"seq-tcp-retrans-ooo-{seed}",
        name=f"TCP Retransmission, Out-of-Order & {'Wraparound' if wraparound_test else 'Sequence Gap'}",
        description="Validates state tracker and reassembler when packets arrive out-of-order, with duplicates and retransmissions.",
        sequence_type=SequenceType.TCP_RETRANSMISSION_OOO,
        seed=seed,
        generator_version="1.0.0",
        steps=steps,
        expected_transitions=expected_transitions,
        expected_flow_count=1,
        expected_properties={"retransmission_expected": True, "out_of_order_expected": True},
        format="pcap",
        is_supported=True,
        created_at_iso=datetime.datetime.now(datetime.UTC).isoformat(),
    )


def generate_tcp_rst_and_abort(seed: int = 44) -> ProtocolSequence:
    """Generates an immediate connection abort via RST packet and invalid flag handling."""
    client_ip = "192.168.1.10"
    server_ip = "192.168.1.20"
    client_port = 45000
    server_port = 80
    flow_id = f"{client_ip}:{client_port}-{server_ip}:{server_port}-TCP"

    steps: list[SequenceStep] = [
        # SYN
        SequenceStep(
            step_index=0,
            timestamp_offset_ns=0,
            source_ip=client_ip,
            destination_ip=server_ip,
            source_port=client_port,
            destination_port=server_port,
            tcp_seq=1000,
            tcp_flags={"syn": True, "ack": False, "fin": False, "rst": False, "psh": False, "urg": False},
            label="SYN",
        ),
        # SYN-ACK
        SequenceStep(
            step_index=1,
            timestamp_offset_ns=10_000_000,
            source_ip=server_ip,
            destination_ip=client_ip,
            source_port=server_port,
            destination_port=client_port,
            tcp_seq=5000,
            tcp_ack=1001,
            tcp_flags={"syn": True, "ack": True, "fin": False, "rst": False, "psh": False, "urg": False},
            label="SYN-ACK",
        ),
        # ACK -> ESTABLISHED
        SequenceStep(
            step_index=2,
            timestamp_offset_ns=20_000_000,
            source_ip=client_ip,
            destination_ip=server_ip,
            source_port=client_port,
            destination_port=server_port,
            tcp_seq=1001,
            tcp_ack=5001,
            tcp_flags={"syn": False, "ack": True, "fin": False, "rst": False, "psh": False, "urg": False},
            label="ACK",
        ),
        # Client sends RST -> RESET
        SequenceStep(
            step_index=3,
            timestamp_offset_ns=30_000_000,
            source_ip=client_ip,
            destination_ip=server_ip,
            source_port=client_port,
            destination_port=server_port,
            tcp_seq=1001,
            tcp_ack=0,
            tcp_flags={"syn": False, "ack": False, "fin": False, "rst": True, "psh": False, "urg": False},
            label="RST Packet",
        ),
    ]

    expected_transitions = [
        ExpectedStateTransition(
            step_index=2,
            flow_id=flow_id,
            expected_state=ConnectionState.ESTABLISHED,
            rationale="ESTABLISHED prior to RST",
        ),
        ExpectedStateTransition(
            step_index=3,
            flow_id=flow_id,
            expected_state=ConnectionState.RESET,
            rationale="RST unconditionally resets connection",
        ),
    ]

    return ProtocolSequence(
        sequence_id=f"seq-tcp-rst-{seed}",
        name="TCP Connection Abort via RST",
        description="Tests RFC 793 RST state transition to RESET and immediate termination.",
        sequence_type=SequenceType.TCP_RST_AND_ABORT,
        seed=seed,
        generator_version="1.0.0",
        steps=steps,
        expected_transitions=expected_transitions,
        expected_flow_count=1,
        expected_properties={"reset_detected": True},
        format="pcap",
        is_supported=True,
        created_at_iso=datetime.datetime.now(datetime.UTC).isoformat(),
    )


def generate_tcp_simultaneous_flows(seed: int = 45) -> ProtocolSequence:
    """Generates two interleaved TCP flows to verify flow table isolation and state independence."""
    flow_a_id = "192.168.1.100:49152-192.168.1.200:80-TCP"
    flow_b_id = "10.0.0.5:54321-10.0.0.6:443-TCP"

    steps: list[SequenceStep] = [
        # Flow A SYN
        SequenceStep(
            step_index=0,
            timestamp_offset_ns=0,
            source_ip="192.168.1.100",
            destination_ip="192.168.1.200",
            source_port=49152,
            destination_port=80,
            tcp_seq=1000,
            tcp_flags={"syn": True, "ack": False, "fin": False, "rst": False, "psh": False, "urg": False},
            label="Flow A: SYN",
        ),
        # Flow B SYN
        SequenceStep(
            step_index=1,
            timestamp_offset_ns=5_000_000,
            source_ip="10.0.0.5",
            destination_ip="10.0.0.6",
            source_port=54321,
            destination_port=443,
            tcp_seq=9000,
            tcp_flags={"syn": True, "ack": False, "fin": False, "rst": False, "psh": False, "urg": False},
            label="Flow B: SYN",
        ),
        # Flow A SYN-ACK
        SequenceStep(
            step_index=2,
            timestamp_offset_ns=10_000_000,
            source_ip="192.168.1.200",
            destination_ip="192.168.1.100",
            source_port=80,
            destination_port=49152,
            tcp_seq=2000,
            tcp_ack=1001,
            tcp_flags={"syn": True, "ack": True, "fin": False, "rst": False, "psh": False, "urg": False},
            label="Flow A: SYN-ACK",
        ),
        # Flow B SYN-ACK
        SequenceStep(
            step_index=3,
            timestamp_offset_ns=15_000_000,
            source_ip="10.0.0.6",
            destination_ip="10.0.0.5",
            source_port=443,
            destination_port=54321,
            tcp_seq=8000,
            tcp_ack=9001,
            tcp_flags={"syn": True, "ack": True, "fin": False, "rst": False, "psh": False, "urg": False},
            label="Flow B: SYN-ACK",
        ),
        # Flow A ACK -> ESTABLISHED
        SequenceStep(
            step_index=4,
            timestamp_offset_ns=20_000_000,
            source_ip="192.168.1.100",
            destination_ip="192.168.1.200",
            source_port=49152,
            destination_port=80,
            tcp_seq=1001,
            tcp_ack=2001,
            tcp_flags={"syn": False, "ack": True, "fin": False, "rst": False, "psh": False, "urg": False},
            label="Flow A: ACK -> ESTABLISHED",
        ),
        # Flow B RST -> RESET (Flow B fails/aborts, Flow A MUST remain ESTABLISHED)
        SequenceStep(
            step_index=5,
            timestamp_offset_ns=25_000_000,
            source_ip="10.0.0.5",
            destination_ip="10.0.0.6",
            source_port=54321,
            destination_port=443,
            tcp_seq=9001,
            tcp_ack=0,
            tcp_flags={"syn": False, "ack": False, "fin": False, "rst": True, "psh": False, "urg": False},
            label="Flow B: RST -> RESET",
        ),
        # Flow A continues Data transfer safely!
        SequenceStep(
            step_index=6,
            timestamp_offset_ns=30_000_000,
            source_ip="192.168.1.100",
            destination_ip="192.168.1.200",
            source_port=49152,
            destination_port=80,
            tcp_seq=1001,
            tcp_ack=2001,
            tcp_flags={"syn": False, "ack": True, "fin": False, "rst": False, "psh": True, "urg": False},
            payload_hex=b"HELLO FLOW A".hex(),
            label="Flow A: Data transfer after Flow B reset",
        ),
    ]

    expected_transitions = [
        ExpectedStateTransition(
            step_index=4,
            flow_id=flow_a_id,
            expected_state=ConnectionState.ESTABLISHED,
            rationale="Flow A handshake succeeds",
        ),
        ExpectedStateTransition(
            step_index=5, flow_id=flow_b_id, expected_state=ConnectionState.RESET, rationale="Flow B RST aborted"
        ),
        ExpectedStateTransition(
            step_index=6,
            flow_id=flow_a_id,
            expected_state=ConnectionState.ESTABLISHED,
            rationale="Flow A remains unaffected by Flow B reset",
        ),
    ]

    return ProtocolSequence(
        sequence_id=f"seq-simultaneous-flows-{seed}",
        name="Interleaved Simultaneous Flows Isolation",
        description="Proves that connection state tracking in Flow A is strictly isolated from aborts/transitions in Flow B.",
        sequence_type=SequenceType.TCP_SIMULTANEOUS_FLOWS,
        seed=seed,
        generator_version="1.0.0",
        steps=steps,
        expected_transitions=expected_transitions,
        expected_flow_count=2,
        expected_properties={"flow_isolation_maintained": True},
        format="pcap",
        is_supported=True,
        created_at_iso=datetime.datetime.now(datetime.UTC).isoformat(),
    )


def generate_ip_fragmentation(seed: int = 46) -> ProtocolSequence:
    """Generates an IPv4 fragmented datagram sequence (explicitly documented coverage limitation)."""
    client_ip = "192.168.1.10"
    server_ip = "192.168.1.20"
    ident = 0x4321

    steps: list[SequenceStep] = [
        # Fragment 1: Offset = 0, MF = True (contains initial UDP header)
        SequenceStep(
            step_index=0,
            timestamp_offset_ns=0,
            source_ip=client_ip,
            destination_ip=server_ip,
            source_port=53,
            destination_port=53,
            protocol="UDP",
            ip_id=ident,
            ip_fragment_offset=0,
            ip_more_fragments=True,
            payload_hex=(b"FRAGMENT_PART_1_AABBCCDD" * 8).hex(),
            label="IPv4 Fragment 1 (Offset 0, MF=1)",
        ),
        # Fragment 2: Offset = 24 (192 bytes / 8), MF = False (Final fragment)
        SequenceStep(
            step_index=1,
            timestamp_offset_ns=10_000_000,
            source_ip=client_ip,
            destination_ip=server_ip,
            source_port=53,
            destination_port=53,
            protocol="UDP",
            ip_id=ident,
            ip_fragment_offset=24,
            ip_more_fragments=False,
            payload_hex=(b"FRAGMENT_PART_2_EEFFGGHH" * 8).hex(),
            label="IPv4 Fragment 2 (Offset 24, MF=0)",
        ),
    ]

    return ProtocolSequence(
        sequence_id=f"seq-ip-fragmentation-{seed}",
        name="IPv4 Datagram Fragmentation Sequence",
        description="Generates multi-part fragmented IPv4 datagrams with More Fragments (MF) and offset fields.",
        sequence_type=SequenceType.IP_FRAGMENTATION,
        seed=seed,
        generator_version="1.0.0",
        steps=steps,
        expected_transitions=[],
        expected_flow_count=1,
        expected_properties={"is_fragment_flagged": True},
        format="pcap",
        is_supported=False,
        coverage_gap_notes="The C++ analyzer decodes IPv4/IPv6 fragment headers, ID, and offset flags, but per-packet processing does not implement an IP fragment reassembly cache. Fragmented L4 payloads are analyzed per-frame.",
        created_at_iso=datetime.datetime.now(datetime.UTC).isoformat(),
    )


def generate_segmented_http_stream(seed: int = 47) -> ProtocolSequence:
    """Generates an HTTP request split across multiple TCP segments to test stream handling."""
    client_ip = "192.168.1.100"
    server_ip = "192.168.1.200"
    client_port = 49152
    server_port = 80
    flow_id = f"{client_ip}:{client_port}-{server_ip}:{server_port}-TCP"

    part1 = b"GET /api/v1/network-twin "
    part2 = b"HTTP/1.1\r\nHost: "
    part3 = b"enterprise.corp.local\r\nAccept: application/json\r\n\r\n"

    steps: list[SequenceStep] = [
        # Handshake
        SequenceStep(
            step_index=0,
            timestamp_offset_ns=0,
            source_ip=client_ip,
            destination_ip=server_ip,
            source_port=client_port,
            destination_port=server_port,
            tcp_seq=1000,
            tcp_flags={"syn": True, "ack": False, "fin": False, "rst": False, "psh": False, "urg": False},
            label="SYN",
        ),
        SequenceStep(
            step_index=1,
            timestamp_offset_ns=10_000_000,
            source_ip=server_ip,
            destination_ip=client_ip,
            source_port=server_port,
            destination_port=client_port,
            tcp_seq=5000,
            tcp_ack=1001,
            tcp_flags={"syn": True, "ack": True, "fin": False, "rst": False, "psh": False, "urg": False},
            label="SYN-ACK",
        ),
        SequenceStep(
            step_index=2,
            timestamp_offset_ns=20_000_000,
            source_ip=client_ip,
            destination_ip=server_ip,
            source_port=client_port,
            destination_port=server_port,
            tcp_seq=1001,
            tcp_ack=5001,
            tcp_flags={"syn": False, "ack": True, "fin": False, "rst": False, "psh": False, "urg": False},
            label="ACK -> ESTABLISHED",
        ),
        # Segment 1 of HTTP request
        SequenceStep(
            step_index=3,
            timestamp_offset_ns=30_000_000,
            source_ip=client_ip,
            destination_ip=server_ip,
            source_port=client_port,
            destination_port=server_port,
            tcp_seq=1001,
            tcp_ack=5001,
            tcp_flags={"syn": False, "ack": True, "fin": False, "rst": False, "psh": False, "urg": False},
            payload_hex=part1.hex(),
            label="HTTP Request Part 1",
        ),
        # Segment 2 of HTTP request
        SequenceStep(
            step_index=4,
            timestamp_offset_ns=40_000_000,
            source_ip=client_ip,
            destination_ip=server_ip,
            source_port=client_port,
            destination_port=server_port,
            tcp_seq=1001 + len(part1),
            tcp_ack=5001,
            tcp_flags={"syn": False, "ack": True, "fin": False, "rst": False, "psh": False, "urg": False},
            payload_hex=part2.hex(),
            label="HTTP Request Part 2",
        ),
        # Segment 3 of HTTP request
        SequenceStep(
            step_index=5,
            timestamp_offset_ns=50_000_000,
            source_ip=client_ip,
            destination_ip=server_ip,
            source_port=client_port,
            destination_port=server_port,
            tcp_seq=1001 + len(part1) + len(part2),
            tcp_ack=5001,
            tcp_flags={"syn": False, "ack": True, "fin": False, "rst": False, "psh": True, "urg": False},
            payload_hex=part3.hex(),
            label="HTTP Request Part 3 (Final CRLF CRLF)",
        ),
    ]

    expected_transitions = [
        ExpectedStateTransition(
            step_index=2, flow_id=flow_id, expected_state=ConnectionState.ESTABLISHED, rationale="Handshake complete"
        ),
    ]

    return ProtocolSequence(
        sequence_id=f"seq-http-segmented-{seed}",
        name="Segmented HTTP/1.1 Request Stream",
        description="Evaluates TCP reassembly and HTTP parser behavior when HTTP request lines and headers are split across TCP segments.",
        sequence_type=SequenceType.HTTP_SEGMENTED_STREAM,
        seed=seed,
        generator_version="1.0.0",
        steps=steps,
        expected_transitions=expected_transitions,
        expected_flow_count=1,
        expected_properties={"contiguous_tcp_stream": True},
        format="pcap",
        is_supported=True,
        created_at_iso=datetime.datetime.now(datetime.UTC).isoformat(),
    )


# ==============================================================================
# SEQUENCE MUTATION OPERATORS
# ==============================================================================


def apply_sequence_mutations(
    sequence: ProtocolSequence,
    mutations: list[SequenceMutation],
    seed: int = 42,
) -> ProtocolSequence:
    """Deterministically applies one or more SequenceMutations to a base ProtocolSequence."""
    mutated_steps = [s.model_copy() for s in sequence.steps]

    for mut in mutations:
        mtype = mut.mutation_type

        if mtype == SequenceMutationType.REORDER_PACKETS:
            # Swap two non-essential or target steps if sequence length >= 2
            idx1 = mut.parameters.get("idx1", len(mutated_steps) - 2)
            idx2 = mut.parameters.get("idx2", len(mutated_steps) - 1)
            if 0 <= idx1 < len(mutated_steps) and 0 <= idx2 < len(mutated_steps):
                mutated_steps[idx1], mutated_steps[idx2] = mutated_steps[idx2], mutated_steps[idx1]

        elif mtype == SequenceMutationType.DUPLICATE_PACKET:
            target_idx = mut.parameters.get("target_step", min(3, len(mutated_steps) - 1))
            if 0 <= target_idx < len(mutated_steps):
                dup = mutated_steps[target_idx].model_copy()
                dup.timestamp_offset_ns += 5_000_000  # +5ms
                dup.label = f"DUPLICATE of step {target_idx}"
                mutated_steps.insert(target_idx + 1, dup)

        elif mtype == SequenceMutationType.DROP_PACKET:
            drop_idx = mut.parameters.get("target_step", len(mutated_steps) - 1)
            if 0 <= drop_idx < len(mutated_steps) and len(mutated_steps) > 1:
                mutated_steps.pop(drop_idx)

        elif mtype == SequenceMutationType.SHIFT_TIMESTAMPS:
            shift_ns = mut.parameters.get("shift_ns", 100_000_000)
            for s in mutated_steps:
                s.timestamp_offset_ns += shift_ns

        elif mtype == SequenceMutationType.INSERT_UNRELATED_NOISE:
            # Injects background ICMP echo request noise
            noise_step = SequenceStep(
                step_index=len(mutated_steps),
                timestamp_offset_ns=15_000_000,
                source_ip="172.16.0.1",
                destination_ip="172.16.0.254",
                protocol="ICMP",
                payload_hex=b"BACKGROUND_NOISE_PACKET".hex(),
                label="Injected Background ICMP Noise",
                is_noise=True,
            )
            insert_pos = min(2, len(mutated_steps))
            mutated_steps.insert(insert_pos, noise_step)

        elif mtype == SequenceMutationType.TRUNCATE_SEQUENCE:
            max_steps = mut.parameters.get("max_steps", max(2, len(mutated_steps) // 2))
            mutated_steps = mutated_steps[:max_steps]

    # Re-index all steps consecutively
    for i, s in enumerate(mutated_steps):
        s.step_index = i

    res = sequence.model_copy()
    res.sequence_id = f"{sequence.sequence_id}-mut-{seed}"
    res.steps = mutated_steps
    res.mutations = list(sequence.mutations) + mutations
    return res


def generate_all_canonical_sequences(seed: int = 42) -> list[ProtocolSequence]:
    """Generates the full suite of Phase 05 canonical protocol sequences."""
    return [
        generate_tcp_handshake_teardown(seed=seed),
        generate_tcp_retransmission_and_ooo(seed=seed + 1, wraparound_test=False),
        generate_tcp_retransmission_and_ooo(seed=seed + 2, wraparound_test=True),
        generate_tcp_rst_and_abort(seed=seed + 3),
        generate_tcp_simultaneous_flows(seed=seed + 4),
        generate_ip_fragmentation(seed=seed + 5),
        generate_segmented_http_stream(seed=seed + 6),
    ]
