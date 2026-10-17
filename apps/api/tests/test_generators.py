"""Unit tests for deterministic protocol generators and mutation operators."""

import pytest

from network_twin.testing.generators import (
    checksum_ip,
    generate_cases_for_target,
    make_dns_query,
    make_ethernet_frame,
    make_http_payload,
    make_ipv4_packet,
    make_ipv6_packet,
    make_quic_packet,
    make_tcp_segment,
    make_tls_client_hello,
    make_udp_datagram,
)
from network_twin.testing.models import (
    ExpectedBehavior,
    GenerationStrategy,
    MutationOperator,
    ProtocolTarget,
)


def test_internet_checksum_calculation():
    # RFC 1071 standard example
    data = b"\x45\x00\x00\x3c\x1c\x46\x40\x00\x40\x06\x00\x00\xac\x10\x0a\x63\xac\x10\x0a\x0c"
    ck = checksum_ip(data)
    assert 0 <= ck <= 0xFFFF
    # Recomputing checksum over data with checksum field filled should yield 0 in 1's complement
    hdr_with_ck = data[:10] + struct_pack_u16(ck) + data[12:]
    verify = checksum_ip(hdr_with_ck)
    assert verify == 0


def struct_pack_u16(val: int) -> bytes:
    import struct

    return struct.pack("!H", val)


def test_ethernet_and_vlan_generation():
    # Base frame
    raw_eth = make_ethernet_frame("00:11:22:33:44:55", "00:AA:BB:CC:DD:EE", 0x0800, b"payload")
    assert len(raw_eth) == 14 + len(b"payload")
    assert raw_eth[:6] == bytes.fromhex("001122334455")
    assert raw_eth[6:12] == bytes.fromhex("00AABBCCDDEE")

    # 802.1Q Single VLAN tag (0x8100, Priority 3, VID 100)
    vlan_eth = make_ethernet_frame(
        "00:11:22:33:44:55", "00:AA:BB:CC:DD:EE", 0x0800, b"payload", vlan_tags=[(0x8100, 3, 0, 100)]
    )
    assert len(vlan_eth) == 18 + len(b"payload")

    # 802.1ad Q-in-Q Double VLAN tags (0x88A8 outer, 0x8100 inner)
    qinq_eth = make_ethernet_frame(
        "00:11:22:33:44:55",
        "00:AA:BB:CC:DD:EE",
        0x0800,
        b"payload",
        vlan_tags=[(0x88A8, 7, 0, 200), (0x8100, 0, 0, 100)],
    )
    assert len(qinq_eth) == 22 + len(b"payload")


def test_ipv4_generation_and_mutations():
    # Standard packet
    ip = make_ipv4_packet("192.168.1.1", "192.168.1.2", 6, b"data")
    assert len(ip) == 20 + 4
    assert ip[0] == 0x45  # Ver 4, IHL 5
    assert ip[8] == 64  # TTL

    # Corrupt checksum mutation
    ip_bad_ck = make_ipv4_packet("192.168.1.1", "192.168.1.2", 6, b"data", corrupt_checksum=True)
    assert ip_bad_ck[10:12] == b"\xde\xad"

    # Extreme TTL mutation
    ip_ttl1 = make_ipv4_packet("192.168.1.1", "192.168.1.2", 6, b"data", ttl=1)
    assert ip_ttl1[8] == 1

    # Contradictory flags: DF + MF set
    ip_df_mf = make_ipv4_packet("192.168.1.1", "192.168.1.2", 6, b"data", df=True, mf=True)
    flags = (ip_df_mf[6] << 8) | ip_df_mf[7]
    assert (flags & 0x4000) != 0 and (flags & 0x2000) != 0


def test_ipv6_generation_and_extension_chains():
    # Base IPv6
    ip6 = make_ipv6_packet("2001:db8::1", "2001:db8::2", 6, b"tcp_payload")
    assert len(ip6) == 40 + len(b"tcp_payload")
    assert (ip6[0] >> 4) == 6

    # Extension headers: Hop-by-Hop (0) and Routing (43)
    exts = [(0, b"\x00\x00\x00\x00\x00\x00"), (43, b"\x00\x00\x00\x00\x00\x00")]
    ip6_ext = make_ipv6_packet("2001:db8::1", "2001:db8::2", 6, b"payload", extension_headers=exts)
    assert len(ip6_ext) > 40 + len(b"payload")
    assert ip6_ext[6] == 0  # First next header is Hop-by-Hop


def test_tcp_generation_and_flag_combinations():
    # SYN segment
    tcp_syn = make_tcp_segment(1234, 80, 100, 0, {"syn": True})
    assert len(tcp_syn) == 20
    assert tcp_syn[13] == 0x02  # SYN

    # XMAS scan segment (FIN + PSH + URG + SYN + RST + ACK + ECE + CWR)
    tcp_xmas = make_tcp_segment(
        1234,
        80,
        100,
        0,
        {"fin": True, "syn": True, "rst": True, "psh": True, "ack": True, "urg": True, "ece": True, "cwr": True},
    )
    assert tcp_xmas[13] == 0xFF


def test_udp_generation_and_lengths():
    udp = make_udp_datagram(53, 53535, b"payload")
    assert len(udp) == 8 + 7

    # Bad length override
    udp_bad_len = make_udp_datagram(53, 53535, b"payload", length_override=4)
    assert udp_bad_len[4:6] == b"\x00\x04"


def test_dns_generator_and_pointer_loops():
    # Standard query
    dns_q = make_dns_query(0x1234, "example.com")
    assert len(dns_q) > 12

    # Pointer loop
    dns_loop = make_dns_query(0x1234, "loop.internal", pointer_loop=True)
    assert b"\xc0\x0c" in dns_loop

    # Out of bounds pointer
    dns_oob = make_dns_query(0x1234, "oob.internal", pointer_oob=True)
    assert b"\xc0\xff" in dns_oob


def test_http_generator():
    req = make_http_payload("POST", "/api/v1/resource", {"Content-Type": "application/json"}, b'{"k":"v"}')
    assert b"POST /api/v1/resource HTTP/1.1\r\n" in req
    assert b"Content-Length: 9\r\n" in req
    assert req.endswith(b'{"k":"v"}')

    # Bare LF
    req_bare_lf = make_http_payload("GET", "/", bare_lf=True)
    assert b"\r\n" not in req_bare_lf
    assert b"\n" in req_bare_lf


def test_tls_client_hello_generator():
    ch = make_tls_client_hello("server.internal", "h2")
    assert ch[0] == 22  # Handshake record
    assert ch[1:3] == b"\x03\x01"  # TLS 1.0 record version
    assert ch[5] == 1  # Handshake type: ClientHello
    assert b"server.internal" in ch


def test_quic_classifier_generator():
    quic = make_quic_packet()
    assert (quic[0] & 0x80) != 0  # Long header
    assert (quic[0] & 0x40) != 0  # Fixed bit set

    # Fixed bit mutation
    quic_mut = make_quic_packet(corrupt_fixed_bit=True)
    assert (quic_mut[0] & 0x40) == 0  # Fixed bit zeroed


@pytest.mark.parametrize("target", list(ProtocolTarget))
@pytest.mark.parametrize(
    "strategy",
    [
        GenerationStrategy.BASELINE_CONFORMANCE,
        GenerationStrategy.MUTATION_FUZZING,
        GenerationStrategy.BOUNDARY_EDGE_CASES,
        GenerationStrategy.MALFORMED_INPUTS,
    ],
)
def test_all_protocol_targets_and_strategies_generate_cases(target, strategy):
    cases = generate_cases_for_target(target=target, strategy=strategy, seed=42, count=2)
    assert len(cases) == 2
    for c in cases:
        assert c.protocol == target
        assert c.strategy == strategy
        assert len(c.packets) >= 1
        assert isinstance(c.expected_behavior, ExpectedBehavior)
        assert isinstance(c.mutation_sequence[0], MutationOperator)
