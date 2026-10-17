"""Deterministic Protocol Test Case Generators & Mutation Operators.

Generates genuine byte-level PCAP and PCAPNG captures covering:
- Ethernet & 802.1Q/802.1ad VLAN tags
- IPv4 (normal, truncated, invalid IHL, bad checksum, fragment edge cases)
- IPv6 (normal, truncated, extension header chains)
- TCP (normal, flags edge cases, options parsing, corrupted offsets)
- UDP (normal, bad lengths, truncated payloads)
- DNS (queries, responses, compression pointer loops, OOB pointers)
- HTTP/1.1 (framing, header validation, chunked encoding edge cases)
- TLS ClientHello (SNI, ALPN, ciphers, malformed extensions)
- QUIC Classification (Initial, Handshake, fixed-bit mutations)
"""

import hashlib
import os
import random
import struct
from pathlib import Path

from network_twin.testing.models import (
    ExpectedBehavior,
    GenerationStrategy,
    MutationOperator,
    ProtocolTarget,
)


def checksum_ip(header_bytes: bytes) -> int:
    """Calculate 16-bit one's complement Internet Checksum."""
    if len(header_bytes) % 2 == 1:
        header_bytes += b"\x00"
    s = sum(struct.unpack(f"!{len(header_bytes)//2}H", header_bytes))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def write_classic_pcap(filepath: str | Path, packets: list[tuple[int, int, bytes]]) -> None:
    """Write classic microsecond PCAP file."""
    # Magic 0xa1b2c3d4, version 2.4, thiszone 0, sigfigs 0, snaplen 65535, linktype 1 (Ethernet)
    global_hdr = struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    with open(filepath, "wb") as f:
        f.write(global_hdr)
        for ts_sec, ts_usec, pkt_bytes in packets:
            pkt_hdr = struct.pack("!IIII", ts_sec, ts_usec, len(pkt_bytes), len(pkt_bytes))
            f.write(pkt_hdr)
            f.write(pkt_bytes)


def write_pcapng(filepath: str | Path, packets: list[tuple[int, int, bytes]]) -> None:
    """Write standard PCAPNG file with SHB, IDB, and EPBs."""
    with open(filepath, "wb") as f:
        # 1. Section Header Block (SHB)
        shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
        shb_len = 12 + len(shb_body)
        shb = struct.pack("<II", 0x0A0D0D0A, shb_len) + shb_body + struct.pack("<I", shb_len)
        f.write(shb)

        # 2. Interface Description Block (IDB)
        idb_body = struct.pack("<HHI", 1, 0, 65535)
        idb_len = 8 + len(idb_body) + 4
        idb = struct.pack("<II", 0x00000001, idb_len) + idb_body + struct.pack("<I", idb_len)
        f.write(idb)

        # 3. Enhanced Packet Blocks (EPB)
        for ts_sec, ts_usec, pkt_bytes in packets:
            ts_us = ts_sec * 1_000_000 + ts_usec
            ts_high = (ts_us >> 32) & 0xFFFFFFFF
            ts_low = ts_us & 0xFFFFFFFF
            cap_len = len(pkt_bytes)
            orig_len = len(pkt_bytes)
            pad_len = (4 - (cap_len % 4)) % 4
            padded_pkt = pkt_bytes + (b"\x00" * pad_len)

            epb_body = (
                struct.pack("<IIII", 0, ts_high, ts_low, cap_len)
                + struct.pack("<I", orig_len)
                + padded_pkt
            )
            epb_len = 8 + len(epb_body) + 4
            epb = struct.pack("<II", 0x00000006, epb_len) + epb_body + struct.pack("<I", epb_len)
            f.write(epb)


def make_ethernet_frame(
    dst_mac: str,
    src_mac: str,
    ether_type: int,
    payload: bytes,
    vlan_tags: list[tuple[int, int, int, int]] | None = None,
) -> bytes:
    """Constructs Ethernet II frame with optional single or multiple VLAN 802.1Q/802.1ad tags.

    vlan_tags item: (tpid, pcp, dei, vid)
    """
    dst_bytes = bytes.fromhex(dst_mac.replace(":", ""))
    src_bytes = bytes.fromhex(src_mac.replace(":", ""))
    hdr = dst_bytes + src_bytes

    if vlan_tags:
        for tpid, pcp, dei, vid in vlan_tags:
            tci = ((pcp & 0x07) << 13) | ((dei & 0x01) << 12) | (vid & 0x0FFF)
            hdr += struct.pack("!HH", tpid, tci)

    hdr += struct.pack("!H", ether_type)
    return hdr + payload


def make_ipv4_packet(
    src_ip: str,
    dst_ip: str,
    protocol: int,
    payload: bytes,
    identification: int = 0x1234,
    df: bool = True,
    mf: bool = False,
    frag_offset: int = 0,
    version: int = 4,
    ihl: int = 5,
    ttl: int = 64,
    corrupt_checksum: bool = False,
    total_length_override: int | None = None,
) -> bytes:
    """Constructs IPv4 header and payload with strict boundary control."""
    src_bytes = bytes(int(p) for p in src_ip.split("."))
    dst_bytes = bytes(int(p) for p in dst_ip.split("."))

    v_ihl = ((version & 0x0F) << 4) | (ihl & 0x0F)
    tos = 0
    header_len = ihl * 4
    total_len = (
        total_length_override if total_length_override is not None else header_len + len(payload)
    )

    flags_frag = (0x4000 if df else 0) | (0x2000 if mf else 0) | (frag_offset & 0x1FFF)

    # Base 20-byte header or padded if ihl > 5
    options_len = max(0, header_len - 20)
    options_padding = b"\x00" * options_len

    hdr_raw = struct.pack(
        "!BBHHHBBH4s4s",
        v_ihl,
        tos,
        total_len,
        identification,
        flags_frag,
        ttl,
        protocol,
        0,
        src_bytes,
        dst_bytes,
    )
    hdr_raw += options_padding

    if corrupt_checksum:
        cksum = 0xDEAD
    else:
        cksum = checksum_ip(hdr_raw)

    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        v_ihl,
        tos,
        total_len,
        identification,
        flags_frag,
        ttl,
        protocol,
        cksum,
        src_bytes,
        dst_bytes,
    )
    hdr += options_padding
    return hdr + payload


def make_ipv6_packet(
    src_ip: str,
    dst_ip: str,
    next_header: int,
    payload: bytes,
    hop_limit: int = 64,
    version: int = 6,
    extension_headers: list[tuple[int, bytes]] | None = None,
) -> bytes:
    """Constructs IPv6 packet with optional extension header chains."""
    import ipaddress

    src_bytes = ipaddress.IPv6Address(src_ip).packed
    dst_bytes = ipaddress.IPv6Address(dst_ip).packed

    ext_bytes = b""
    first_next_hdr = next_header
    if extension_headers:
        first_next_hdr = extension_headers[0][0]
        for i, (_nh, ext_data) in enumerate(extension_headers):
            chain_nh = extension_headers[i + 1][0] if i + 1 < len(extension_headers) else next_header
            # Extension header length in 8-octet units minus 1
            ext_len_units = (len(ext_data) + 2 + 7) // 8
            padded_data = ext_data.ljust(ext_len_units * 8 - 2, b"\x00")
            ext_bytes += struct.pack("!BB", chain_nh, ext_len_units - 1) + padded_data

    full_payload = ext_bytes + payload
    payload_len = len(full_payload)
    vtc_fl = ((version & 0x0F) << 28)

    hdr = struct.pack("!IHBB", vtc_fl, payload_len, first_next_hdr, hop_limit) + src_bytes + dst_bytes
    return hdr + full_payload


def make_tcp_segment(
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: dict[str, bool],
    payload: bytes = b"",
    window: int = 29200,
    options: bytes = b"",
    data_offset_override: int | None = None,
) -> bytes:
    """Constructs TCP segment with arbitrary flags and options."""
    data_offset = (
        data_offset_override
        if data_offset_override is not None
        else (20 + len(options) + 3) // 4
    )
    flags_val = 0
    if flags.get("fin"):
        flags_val |= 0x01
    if flags.get("syn"):
        flags_val |= 0x02
    if flags.get("rst"):
        flags_val |= 0x04
    if flags.get("psh"):
        flags_val |= 0x08
    if flags.get("ack"):
        flags_val |= 0x10
    if flags.get("urg"):
        flags_val |= 0x20
    if flags.get("ece"):
        flags_val |= 0x40
    if flags.get("cwr"):
        flags_val |= 0x80

    do_rsv = (data_offset & 0x0F) << 4
    # Pad options to 32-bit boundary
    pad_len = (4 - (len(options) % 4)) % 4
    full_options = options + (b"\x00" * pad_len)

    hdr = (
        struct.pack(
            "!HHIIBBHHH",
            src_port,
            dst_port,
            seq,
            ack,
            do_rsv,
            flags_val,
            window,
            0,
            0,
        )
        + full_options
    )
    return hdr + payload


def make_udp_datagram(
    src_port: int,
    dst_port: int,
    payload: bytes,
    length_override: int | None = None,
) -> bytes:
    """Constructs UDP datagram."""
    length = length_override if length_override is not None else 8 + len(payload)
    hdr = struct.pack("!HHHH", src_port, dst_port, length, 0)
    return hdr + payload


def make_dns_query(
    tx_id: int,
    qname: str,
    qtype: int = 1,
    pointer_loop: bool = False,
    pointer_oob: bool = False,
    qdcount: int = 1,
) -> bytes:
    """Constructs DNS Query with edge case pointers."""
    hdr = struct.pack("!HHHHHH", tx_id, 0x0100, qdcount, 0, 0, 0)
    if pointer_loop:
        # Loop: points back to its own offset (offset 12 in DNS message)
        body = b"\xc0\x0c" + struct.pack("!HH", qtype, 1)
        return hdr + body
    if pointer_oob:
        # Out-of-bounds pointer (0xFFFF)
        body = b"\xc0\xff" + struct.pack("!HH", qtype, 1)
        return hdr + body

    parts = qname.split(".")
    qname_bytes = b"".join(bytes([len(p)]) + p.encode("ascii") for p in parts) + b"\x00"
    return hdr + qname_bytes + struct.pack("!HH", qtype, 1)


def make_dns_response(
    tx_id: int,
    qname: str,
    ip: str,
    pointer_loop: bool = False,
) -> bytes:
    """Constructs DNS response with optional compression loop."""
    hdr = struct.pack("!HHHHHH", tx_id, 0x8180, 1, 1, 0, 0)
    if pointer_loop:
        return hdr + b"\xc0\x0c\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x7f\x00\x00\x01"

    parts = qname.split(".")
    qname_bytes = b"".join(bytes([len(p)]) + p.encode("ascii") for p in parts) + b"\x00"
    query = qname_bytes + struct.pack("!HH", 1, 1)

    ip_bytes = bytes(int(p) for p in ip.split("."))
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + ip_bytes
    return hdr + query + answer


def make_http_payload(
    method: str = "GET",
    path: str = "/index.html",
    headers: dict[str, str] | None = None,
    body: bytes = b"",
    bare_lf: bool = False,
    is_response: bool = False,
    status_code: int = 200,
) -> bytes:
    """Constructs HTTP request or response framing."""
    sep = b"\n" if bare_lf else b"\r\n"
    if is_response:
        res = f"HTTP/1.1 {status_code} OK".encode("ascii") + sep
    else:
        res = f"{method} {path} HTTP/1.1".encode("ascii") + sep

    if headers is None:
        headers = {}
    if body and "Content-Length" not in headers:
        headers["Content-Length"] = str(len(body))

    for k, v in headers.items():
        res += f"{k}: {v}".encode("ascii") + sep
    res += sep
    return res + body


def make_tls_client_hello(
    sni: str = "twin.internal",
    alpn: str = "h2",
    corrupt_length: bool = False,
    corrupt_sni: bool = False,
) -> bytes:
    """Constructs TLS ClientHello record."""
    sni_bytes = sni.encode("ascii")
    sni_len = 0xFFFF if corrupt_sni else len(sni_bytes)
    sni_ext = (
        struct.pack("!HH", 0x0000, len(sni_bytes) + 5)
        + struct.pack("!HBH", len(sni_bytes) + 3, 0, sni_len)
        + sni_bytes
    )

    alpn_bytes = alpn.encode("ascii")
    alpn_ext = (
        struct.pack("!HH", 0x0010, len(alpn_bytes) + 3)
        + struct.pack("!HB", len(alpn_bytes) + 1, len(alpn_bytes))
        + alpn_bytes
    )

    extensions = sni_ext + alpn_ext
    ciphers = struct.pack("!HHHH", 0x1301, 0x1302, 0xC02F, 0xC030)

    ch_body = (
        struct.pack("!H", 0x0303)
        + os.urandom(32)
        + b"\x00"
        + struct.pack("!H", len(ciphers))
        + ciphers
        + b"\x01\x00"
        + struct.pack("!H", len(extensions))
        + extensions
    )

    hs_len = 0xFFFFFF if corrupt_length else len(ch_body)
    hs_header = struct.pack("!B", 1) + struct.pack("!I", hs_len)[1:]
    record_payload = hs_header + ch_body
    record_header = struct.pack("!BHH", 22, 0x0301, len(record_payload))
    return record_header + record_payload


def make_quic_packet(
    dcid: bytes = b"\x01\x02\x03\x04\x05\x06\x07\x08",
    scid: bytes = b"\x11\x12\x13\x14",
    version: int = 0x00000001,
    packet_type: int = 0x00,  # Initial = 0x00
    corrupt_fixed_bit: bool = False,
) -> bytes:
    """Constructs QUIC Long Header Initial packet datagram."""
    # Byte 0: Header Form (1), Fixed Bit (1), Packet Type (2 bits), Reserved (2 bits), Packet Number Length (2 bits)
    first_byte = 0x80 | (0x00 if corrupt_fixed_bit else 0x40) | ((packet_type & 0x03) << 4) | 0x03
    hdr = struct.pack("!B", first_byte) + struct.pack("!I", version)
    hdr += struct.pack("!B", len(dcid)) + dcid
    hdr += struct.pack("!B", len(scid)) + scid
    # Token length 0
    hdr += b"\x00"
    # Length (varint 2-byte: 0x40 0x20 = 32 bytes)
    hdr += b"\x40\x20"
    # Packet number (4 bytes) + dummy payload
    hdr += struct.pack("!I", 1) + (b"\x99" * 28)
    return hdr


# -------------------------------------------------------------------------
# Test Case Matrix Generation
# -------------------------------------------------------------------------


class GeneratedCaseData:
    def __init__(
        self,
        name: str,
        protocol: ProtocolTarget,
        strategy: GenerationStrategy,
        mutation_sequence: list[MutationOperator],
        expected_behavior: ExpectedBehavior,
        packets: list[tuple[int, int, bytes]],
        fixture_format: str = "pcap",
    ):
        self.name = name
        self.protocol = protocol
        self.strategy = strategy
        self.mutation_sequence = mutation_sequence
        self.expected_behavior = expected_behavior
        self.packets = packets
        self.fixture_format = fixture_format


def generate_cases_for_target(
    target: ProtocolTarget,
    strategy: GenerationStrategy,
    seed: int,
    count: int = 5,
) -> list[GeneratedCaseData]:
    base_ts = 1776412800
    cases: list[GeneratedCaseData] = []

    for idx in range(count):
        case_seed = seed + idx * 37
        c_rng = random.Random(case_seed)

        # Baseline Conformance
        if strategy == GenerationStrategy.BASELINE_CONFORMANCE:
            if target == ProtocolTarget.ETHERNET:
                p = make_ethernet_frame("00:11:22:33:44:55", "00:AA:11:22:33:44", 0x0800, make_ipv4_packet("10.0.0.1", "10.0.0.2", 1, b"ping"))
                cases.append(GeneratedCaseData(f"eth_base_{idx}", target, strategy, [MutationOperator.NONE], ExpectedBehavior.ACCEPT_VALID, [(base_ts, 0, p)]))
            elif target == ProtocolTarget.VLAN:
                vlan_tag = [(0x8100, 2, 0, 100 + idx)]
                p = make_ethernet_frame("00:11:22:33:44:55", "00:AA:11:22:33:44", 0x0800, make_ipv4_packet("10.0.0.1", "10.0.0.2", 1, b"vlan_test"), vlan_tags=vlan_tag)
                cases.append(GeneratedCaseData(f"vlan_base_{idx}", target, strategy, [MutationOperator.NONE], ExpectedBehavior.ACCEPT_VALID, [(base_ts, 0, p)]))
            elif target == ProtocolTarget.IPV4:
                p = make_ethernet_frame("00:11:22:33:44:55", "00:AA:11:22:33:44", 0x0800, make_ipv4_packet("192.168.1.10", "192.168.1.20", 6, make_tcp_segment(1234, 80, 100, 0, {"syn": True})))
                cases.append(GeneratedCaseData(f"ipv4_base_{idx}", target, strategy, [MutationOperator.NONE], ExpectedBehavior.ACCEPT_VALID, [(base_ts, 0, p)]))
            elif target == ProtocolTarget.IPV6:
                p = make_ethernet_frame("00:11:22:33:44:55", "00:AA:11:22:33:44", 0x86DD, make_ipv6_packet("2001:db8::1", "2001:db8::2", 6, make_tcp_segment(1234, 80, 100, 0, {"syn": True})))
                cases.append(GeneratedCaseData(f"ipv6_base_{idx}", target, strategy, [MutationOperator.NONE], ExpectedBehavior.ACCEPT_VALID, [(base_ts, 0, p)]))
            elif target == ProtocolTarget.TCP:
                tcp = make_tcp_segment(50000 + idx, 443, 1000, 0, {"syn": True})
                p = make_ethernet_frame("00:11:22:33:44:55", "00:AA:11:22:33:44", 0x0800, make_ipv4_packet("192.168.1.10", "192.168.1.1", 6, tcp))
                cases.append(GeneratedCaseData(f"tcp_base_{idx}", target, strategy, [MutationOperator.NONE], ExpectedBehavior.ACCEPT_VALID, [(base_ts, 0, p)]))
            elif target == ProtocolTarget.UDP:
                udp = make_udp_datagram(5353, 5353, b"\x00\x00\x00\x00")
                p = make_ethernet_frame("00:11:22:33:44:55", "00:AA:11:22:33:44", 0x0800, make_ipv4_packet("192.168.1.10", "224.0.0.251", 17, udp))
                cases.append(GeneratedCaseData(f"udp_base_{idx}", target, strategy, [MutationOperator.NONE], ExpectedBehavior.ACCEPT_VALID, [(base_ts, 0, p)]))
            elif target == ProtocolTarget.DNS:
                dns = make_dns_query(0x1000 + idx, f"test{idx}.domain.local")
                p = make_ethernet_frame("00:11:22:33:44:55", "00:AA:11:22:33:44", 0x0800, make_ipv4_packet("192.168.1.10", "8.8.8.8", 17, make_udp_datagram(53535, 53, dns)))
                cases.append(GeneratedCaseData(f"dns_base_{idx}", target, strategy, [MutationOperator.NONE], ExpectedBehavior.ACCEPT_VALID, [(base_ts, 0, p)]))
            elif target == ProtocolTarget.HTTP:
                http = make_http_payload("GET", f"/item/{idx}", {"Host": "api.local", "User-Agent": "Tester"})
                tcp = make_tcp_segment(40000, 80, 1, 1, {"psh": True, "ack": True}, http)
                p = make_ethernet_frame("00:11:22:33:44:55", "00:AA:11:22:33:44", 0x0800, make_ipv4_packet("192.168.1.10", "192.168.1.100", 6, tcp))
                cases.append(GeneratedCaseData(f"http_base_{idx}", target, strategy, [MutationOperator.NONE], ExpectedBehavior.ACCEPT_VALID, [(base_ts, 0, p)]))
            elif target == ProtocolTarget.TLS_CLIENT_HELLO:
                tls = make_tls_client_hello(f"service{idx}.corp.internal")
                tcp = make_tcp_segment(40001, 443, 1, 1, {"psh": True, "ack": True}, tls)
                p = make_ethernet_frame("00:11:22:33:44:55", "00:AA:11:22:33:44", 0x0800, make_ipv4_packet("192.168.1.10", "192.168.1.100", 6, tcp))
                cases.append(GeneratedCaseData(f"tls_base_{idx}", target, strategy, [MutationOperator.NONE], ExpectedBehavior.ACCEPT_VALID, [(base_ts, 0, p)]))
            elif target == ProtocolTarget.QUIC_CLASSIFIER:
                quic = make_quic_packet()
                p = make_ethernet_frame("00:11:22:33:44:55", "00:AA:11:22:33:44", 0x0800, make_ipv4_packet("192.168.1.10", "192.168.1.100", 17, make_udp_datagram(4433, 443, quic)))
                cases.append(GeneratedCaseData(f"quic_base_{idx}", target, strategy, [MutationOperator.NONE], ExpectedBehavior.ACCEPT_VALID, [(base_ts, 0, p)]))

        # Mutation Fuzzing (Bit flips, checksum corruption, option tampering)
        elif strategy == GenerationStrategy.MUTATION_FUZZING:
            if target == ProtocolTarget.IPV4:
                # Corrupt checksum
                p = make_ethernet_frame("00:11:22:33:44:55", "00:AA:11:22:33:44", 0x0800, make_ipv4_packet("10.0.0.1", "10.0.0.2", 1, b"echo", corrupt_checksum=True))
                cases.append(GeneratedCaseData(f"ipv4_bad_cksum_{idx}", target, strategy, [MutationOperator.CORRUPT_CHECKSUM], ExpectedBehavior.SAFE_REJECT, [(base_ts, 0, p)]))
            elif target == ProtocolTarget.TCP:
                # Contradictory flags SYN+FIN
                tcp = make_tcp_segment(1234, 80, 100, 0, {"syn": True, "fin": True})
                p = make_ethernet_frame("00:11:22:33:44:55", "00:AA:11:22:33:44", 0x0800, make_ipv4_packet("10.0.0.1", "10.0.0.2", 6, tcp))
                cases.append(GeneratedCaseData(f"tcp_syn_fin_{idx}", target, strategy, [MutationOperator.CONTRADICTORY_FLAGS], ExpectedBehavior.ACCEPT_VALID, [(base_ts, 0, p)]))
            elif target == ProtocolTarget.DNS:
                # Pointer loop
                dns = make_dns_query(0x9999, "loop.internal", pointer_loop=True)
                p = make_ethernet_frame("00:11:22:33:44:55", "00:AA:11:22:33:44", 0x0800, make_ipv4_packet("10.0.0.1", "8.8.8.8", 17, make_udp_datagram(53535, 53, dns)))
                cases.append(GeneratedCaseData(f"dns_ptr_loop_{idx}", target, strategy, [MutationOperator.POINTER_LOOP], ExpectedBehavior.SAFE_REJECT, [(base_ts, 0, p)]))
            elif target == ProtocolTarget.TLS_CLIENT_HELLO:
                # Corrupt SNI extension length
                tls = make_tls_client_hello(corrupt_sni=True)
                p = make_ethernet_frame("00:11:22:33:44:55", "00:AA:11:22:33:44", 0x0800, make_ipv4_packet("10.0.0.1", "10.0.0.2", 6, make_tcp_segment(1234, 443, 1, 1, {"ack": True}, tls)))
                cases.append(GeneratedCaseData(f"tls_bad_sni_{idx}", target, strategy, [MutationOperator.MALFORMED_OPTIONS], ExpectedBehavior.SAFE_REJECT, [(base_ts, 0, p)]))
            elif target == ProtocolTarget.QUIC_CLASSIFIER:
                # Corrupted Fixed Bit (bit 6 = 0)
                quic = make_quic_packet(corrupt_fixed_bit=True)
                p = make_ethernet_frame("00:11:22:33:44:55", "00:AA:11:22:33:44", 0x0800, make_ipv4_packet("10.0.0.1", "10.0.0.2", 17, make_udp_datagram(4433, 443, quic)))
                cases.append(GeneratedCaseData(f"quic_bad_fixed_bit_{idx}", target, strategy, [MutationOperator.BIT_FLIP], ExpectedBehavior.SAFE_REJECT, [(base_ts, 0, p)]))
            else:
                # General random bit flip
                p = make_ethernet_frame("00:11:22:33:44:55", "00:AA:11:22:33:44", 0x0800, make_ipv4_packet("10.0.0.1", "10.0.0.2", 17, make_udp_datagram(1234, 5678, b"fuzz_data")))
                mutated = bytearray(p)
                flip_pos = c_rng.randint(14, len(mutated) - 1)
                mutated[flip_pos] ^= 0xFF
                cases.append(GeneratedCaseData(f"fuzz_bitflip_{target.lower()}_{idx}", target, strategy, [MutationOperator.BIT_FLIP], ExpectedBehavior.SAFE_REJECT, [(base_ts, 0, bytes(mutated))]))

        # Boundary Edge Cases
        elif strategy == GenerationStrategy.BOUNDARY_EDGE_CASES:
            if target == ProtocolTarget.VLAN:
                # Q-in-Q double VLAN tag (0x88A8 outer, 0x8100 inner)
                vlan_tags = [(0x88A8, 7, 1, 4094), (0x8100, 0, 0, 1)]
                p = make_ethernet_frame("00:11:22:33:44:55", "00:AA:11:22:33:44", 0x0800, make_ipv4_packet("10.0.0.1", "10.0.0.2", 1, b"qinq"), vlan_tags=vlan_tags)
                cases.append(GeneratedCaseData(f"vlan_qinq_boundary_{idx}", target, strategy, [MutationOperator.EXTREME_BOUNDARIES], ExpectedBehavior.ACCEPT_VALID, [(base_ts, 0, p)]))
            elif target == ProtocolTarget.IPV4:
                # Extreme TTL (TTL = 1 and TTL = 255)
                ttl_val = 1 if idx % 2 == 0 else 255
                p = make_ethernet_frame("00:11:22:33:44:55", "00:AA:11:22:33:44", 0x0800, make_ipv4_packet("10.0.0.1", "10.0.0.2", 1, b"ping", ttl=ttl_val))
                cases.append(GeneratedCaseData(f"ipv4_ttl_{ttl_val}_{idx}", target, strategy, [MutationOperator.EXTREME_BOUNDARIES], ExpectedBehavior.ACCEPT_VALID, [(base_ts, 0, p)]))
            elif target == ProtocolTarget.IPV6:
                # Extension header chain: Hop-by-Hop (0) -> Routing (43) -> TCP
                exts = [(0, b"\x00\x00\x00\x00\x00\x00"), (43, b"\x00\x00\x00\x00\x00\x00")]
                p = make_ethernet_frame("00:11:22:33:44:55", "00:AA:11:22:33:44", 0x86DD, make_ipv6_packet("2001:db8::1", "2001:db8::2", 6, make_tcp_segment(1234, 80, 1, 0, {"syn": True}), extension_headers=exts))
                cases.append(GeneratedCaseData(f"ipv6_ext_chain_{idx}", target, strategy, [MutationOperator.EXTREME_BOUNDARIES], ExpectedBehavior.ACCEPT_VALID, [(base_ts, 0, p)]))
            elif target == ProtocolTarget.TCP:
                # XMAS scan: FIN, URG, PSH, SYN, RST, ACK, ECE, CWR
                tcp = make_tcp_segment(1234, 80, 0xFFFFFFFF, 0xFFFFFFFF, {"fin": True, "syn": True, "rst": True, "psh": True, "ack": True, "urg": True, "ece": True, "cwr": True})
                p = make_ethernet_frame("00:11:22:33:44:55", "00:AA:11:22:33:44", 0x0800, make_ipv4_packet("10.0.0.1", "10.0.0.2", 6, tcp))
                cases.append(GeneratedCaseData(f"tcp_xmas_{idx}", target, strategy, [MutationOperator.EXTREME_BOUNDARIES], ExpectedBehavior.ACCEPT_VALID, [(base_ts, 0, p)]))
            elif target == ProtocolTarget.UDP:
                # UDP length 8 (header only, zero payload)
                p = make_ethernet_frame("00:11:22:33:44:55", "00:AA:11:22:33:44", 0x0800, make_ipv4_packet("10.0.0.1", "10.0.0.2", 17, make_udp_datagram(1234, 5678, b"")))
                cases.append(GeneratedCaseData(f"udp_zero_len_{idx}", target, strategy, [MutationOperator.EXTREME_BOUNDARIES], ExpectedBehavior.ACCEPT_VALID, [(base_ts, 0, p)]))
            elif target == ProtocolTarget.DNS:
                # Out-of-bounds compression pointer (points beyond message boundary)
                dns = make_dns_query(0x2222, "oob.internal", pointer_oob=True)
                p = make_ethernet_frame("00:11:22:33:44:55", "00:AA:11:22:33:44", 0x0800, make_ipv4_packet("10.0.0.1", "8.8.8.8", 17, make_udp_datagram(53535, 53, dns)))
                cases.append(GeneratedCaseData(f"dns_ptr_oob_{idx}", target, strategy, [MutationOperator.POINTER_OUT_OF_BOUNDS], ExpectedBehavior.SAFE_REJECT, [(base_ts, 0, p)]))
            elif target == ProtocolTarget.HTTP:
                # Bare LF instead of CRLF
                http = make_http_payload("GET", "/index.html", {"Host": "target.local"}, bare_lf=True)
                p = make_ethernet_frame("00:11:22:33:44:55", "00:AA:11:22:33:44", 0x0800, make_ipv4_packet("10.0.0.1", "10.0.0.2", 6, make_tcp_segment(1234, 80, 1, 1, {"psh": True, "ack": True}, http)))
                cases.append(GeneratedCaseData(f"http_bare_lf_{idx}", target, strategy, [MutationOperator.EXTREME_BOUNDARIES], ExpectedBehavior.ACCEPT_VALID, [(base_ts, 0, p)]))
            else:
                p = make_ethernet_frame("00:11:22:33:44:55", "00:AA:11:22:33:44", 0x0800, make_ipv4_packet("10.0.0.1", "10.0.0.2", 1, b"boundary"))
                cases.append(GeneratedCaseData(f"boundary_gen_{target.lower()}_{idx}", target, strategy, [MutationOperator.EXTREME_BOUNDARIES], ExpectedBehavior.ACCEPT_VALID, [(base_ts, 0, p)]))

        # Malformed Inputs (Truncations, invalid versions, bad lengths)
        elif strategy == GenerationStrategy.MALFORMED_INPUTS:
            if target == ProtocolTarget.ETHERNET:
                # Truncated Ethernet header (<14 bytes)
                p = b"\x00\x11\x22\x33\x44\x55\x00\xaa"  # 8 bytes
                cases.append(GeneratedCaseData(f"eth_truncated_{idx}", target, strategy, [MutationOperator.TRUNCATE_HEADER], ExpectedBehavior.SAFE_REJECT, [(base_ts, 0, p)]))
            elif target == ProtocolTarget.IPV4:
                # Invalid IPv4 version (version = 15 or 0)
                p = make_ethernet_frame("00:11:22:33:44:55", "00:AA:11:22:33:44", 0x0800, make_ipv4_packet("10.0.0.1", "10.0.0.2", 1, b"badver", version=15))
                cases.append(GeneratedCaseData(f"ipv4_bad_version_{idx}", target, strategy, [MutationOperator.INVALID_VERSION], ExpectedBehavior.SAFE_REJECT, [(base_ts, 0, p)]))
            elif target == ProtocolTarget.IPV6:
                # Truncated IPv6 (<40 bytes)
                eth = make_ethernet_frame("00:11:22:33:44:55", "00:AA:11:22:33:44", 0x86DD, b"\x60\x00\x00\x00\x00\x10\x06\x40" + (b"\xaa" * 16)) # 24 bytes only
                cases.append(GeneratedCaseData(f"ipv6_truncated_{idx}", target, strategy, [MutationOperator.TRUNCATE_HEADER], ExpectedBehavior.SAFE_REJECT, [(base_ts, 0, eth)]))
            elif target == ProtocolTarget.TCP:
                # Invalid TCP data offset (<5 words, e.g. 2 words)
                tcp = make_tcp_segment(1234, 80, 100, 0, {"syn": True}, data_offset_override=2)
                p = make_ethernet_frame("00:11:22:33:44:55", "00:AA:11:22:33:44", 0x0800, make_ipv4_packet("10.0.0.1", "10.0.0.2", 6, tcp))
                cases.append(GeneratedCaseData(f"tcp_bad_offset_{idx}", target, strategy, [MutationOperator.INVALID_LENGTH], ExpectedBehavior.SAFE_REJECT, [(base_ts, 0, p)]))
            elif target == ProtocolTarget.UDP:
                # UDP length field smaller than 8
                udp = make_udp_datagram(1234, 5678, b"data", length_override=4)
                p = make_ethernet_frame("00:11:22:33:44:55", "00:AA:11:22:33:44", 0x0800, make_ipv4_packet("10.0.0.1", "10.0.0.2", 17, udp))
                cases.append(GeneratedCaseData(f"udp_bad_length_{idx}", target, strategy, [MutationOperator.INVALID_LENGTH], ExpectedBehavior.SAFE_REJECT, [(base_ts, 0, p)]))
            elif target == ProtocolTarget.DNS:
                # Truncated DNS header (only 6 bytes)
                p = make_ethernet_frame("00:11:22:33:44:55", "00:AA:11:22:33:44", 0x0800, make_ipv4_packet("10.0.0.1", "8.8.8.8", 17, make_udp_datagram(53535, 53, b"\x12\x34\x01\x00\x00\x01")))
                cases.append(GeneratedCaseData(f"dns_truncated_{idx}", target, strategy, [MutationOperator.TRUNCATE_HEADER], ExpectedBehavior.SAFE_REJECT, [(base_ts, 0, p)]))
            elif target == ProtocolTarget.HTTP:
                # Malformed request line
                http = b"INVALID_REQUEST_LINE_WITHOUT_METHOD_OR_VERSION\r\n\r\n"
                p = make_ethernet_frame("00:11:22:33:44:55", "00:AA:11:22:33:44", 0x0800, make_ipv4_packet("10.0.0.1", "10.0.0.2", 6, make_tcp_segment(1234, 80, 1, 1, {"psh": True, "ack": True}, http)))
                cases.append(GeneratedCaseData(f"http_malformed_{idx}", target, strategy, [MutationOperator.MALFORMED_OPTIONS], ExpectedBehavior.SAFE_REJECT, [(base_ts, 0, p)]))
            elif target == ProtocolTarget.TLS_CLIENT_HELLO:
                # Truncated record header (3 bytes instead of 5)
                p = make_ethernet_frame("00:11:22:33:44:55", "00:AA:11:22:33:44", 0x0800, make_ipv4_packet("10.0.0.1", "10.0.0.2", 6, make_tcp_segment(1234, 443, 1, 1, {"psh": True, "ack": True}, b"\x16\x03\x01")))
                cases.append(GeneratedCaseData(f"tls_truncated_{idx}", target, strategy, [MutationOperator.TRUNCATE_HEADER], ExpectedBehavior.SAFE_REJECT, [(base_ts, 0, p)]))
            else:
                p = make_ethernet_frame("00:11:22:33:44:55", "00:AA:11:22:33:44", 0x0800, make_ipv4_packet("10.0.0.1", "10.0.0.2", 1, b"bad"))[:25]
                cases.append(GeneratedCaseData(f"malformed_{target.lower()}_{idx}", target, strategy, [MutationOperator.TRUNCATE_PAYLOAD], ExpectedBehavior.SAFE_REJECT, [(base_ts, 0, p)]))

        # Differential Equivalence (Classic PCAP vs PCAPNG)
        elif strategy == GenerationStrategy.DIFFERENTIAL_EQUIVALENCE:
            p = make_ethernet_frame("00:11:22:33:44:55", "00:AA:11:22:33:44", 0x0800, make_ipv4_packet("10.0.0.1", "10.0.0.2", 6, make_tcp_segment(1234 + idx, 80, 1000 + idx, 0, {"syn": True})))
            fmt = "pcapng" if idx % 2 == 1 else "pcap"
            cases.append(GeneratedCaseData(f"diff_{target.lower()}_{fmt}_{idx}", target, strategy, [MutationOperator.NONE], ExpectedBehavior.EQUIVALENT_PARSING, [(base_ts, 0, p)], fixture_format=fmt))

    return cases


def write_case_to_disk(case_data: GeneratedCaseData, output_dir: Path) -> tuple[str, str]:
    """Writes the generated case packets to disk and returns (absolute_path, sha256_hash)."""
    output_dir.mkdir(parents=True, exist_ok=True)
    extension = ".pcapng" if case_data.fixture_format == "pcapng" else ".pcap"
    filepath = output_dir / f"{case_data.name}{extension}"

    if case_data.fixture_format == "pcapng":
        write_pcapng(filepath, case_data.packets)
    else:
        write_classic_pcap(filepath, case_data.packets)

    with open(filepath, "rb") as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()

    return str(filepath.resolve()), file_hash
