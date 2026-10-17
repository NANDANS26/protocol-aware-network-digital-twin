"""
Deterministic PCAP and PCAPNG test fixture generator for Protocol-Aware Network Digital Twin.
Generates genuine byte-level packet captures for testing the C++ analysis engine.
"""

import struct
import os
from pathlib import Path


def checksum_ip(header_bytes: bytes) -> int:
    """Calculate 16-bit one's complement Internet Checksum."""
    if len(header_bytes) % 2 == 1:
        header_bytes += b'\x00'
    s = sum(struct.unpack(f"!{len(header_bytes)//2}H", header_bytes))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def make_ethernet_frame(dst_mac: str, src_mac: str, ether_type: int, payload: bytes) -> bytes:
    dst_bytes = bytes.fromhex(dst_mac.replace(":", ""))
    src_bytes = bytes.fromhex(src_mac.replace(":", ""))
    return dst_bytes + src_bytes + struct.pack("!H", ether_type) + payload


def make_ipv4_packet(src_ip: str, dst_ip: str, protocol: int, payload: bytes, identification: int = 0x1234, df: bool = True) -> bytes:
    src_parts = [int(p) for p in src_ip.split(".")]
    dst_parts = [int(p) for p in dst_ip.split(".")]
    src_bytes = bytes(src_parts)
    dst_bytes = bytes(dst_parts)

    ihl = 5
    version = 4
    v_ihl = (version << 4) | ihl
    tos = 0
    total_length = 20 + len(payload)
    flags_frag = 0x4000 if df else 0
    ttl = 64

    header_without_cksum = struct.pack(
        "!BBHHHBBH4s4s",
        v_ihl, tos, total_length, identification, flags_frag, ttl, protocol, 0, src_bytes, dst_bytes
    )
    cksum = checksum_ip(header_without_cksum)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        v_ihl, tos, total_length, identification, flags_frag, ttl, protocol, cksum, src_bytes, dst_bytes
    )
    return header + payload


def make_tcp_segment(src_port: int, dst_port: int, seq: int, ack: int, flags: dict, payload: bytes = b"", window: int = 29200) -> bytes:
    data_offset = 5 # 20 bytes
    flags_val = 0
    if flags.get("fin"): flags_val |= 0x01
    if flags.get("syn"): flags_val |= 0x02
    if flags.get("rst"): flags_val |= 0x04
    if flags.get("psh"): flags_val |= 0x08
    if flags.get("ack"): flags_val |= 0x10
    if flags.get("urg"): flags_val |= 0x20
    if flags.get("ece"): flags_val |= 0x40
    if flags.get("cwr"): flags_val |= 0x80

    do_rsv = (data_offset << 4)
    hdr = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, do_rsv, flags_val, window, 0, 0)
    return hdr + payload


def make_udp_datagram(src_port: int, dst_port: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    hdr = struct.pack("!HHHH", src_port, dst_port, length, 0)
    return hdr + payload


def make_dns_query(tx_id: int, qname: str, qtype: int = 1) -> bytes:
    hdr = struct.pack("!HHHHHH", tx_id, 0x0100, 1, 0, 0, 0) # RD=1
    qname_parts = qname.split(".")
    qname_bytes = b"".join(bytes([len(p)]) + p.encode("ascii") for p in qname_parts) + b"\x00"
    return hdr + qname_bytes + struct.pack("!HH", qtype, 1) # Class IN = 1


def make_dns_response(tx_id: int, qname: str, ip: str) -> bytes:
    hdr = struct.pack("!HHHHHH", tx_id, 0x8180, 1, 1, 0, 0) # QR=1, RD=1, RA=1
    qname_parts = qname.split(".")
    qname_bytes = b"".join(bytes([len(p)]) + p.encode("ascii") for p in qname_parts) + b"\x00"
    query = qname_bytes + struct.pack("!HH", 1, 1)

    ip_parts = [int(p) for p in ip.split(".")]
    ip_bytes = bytes(ip_parts)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + ip_bytes
    return hdr + query + answer


def make_tls_client_hello(sni: str) -> bytes:
    # Build minimal TLS 1.2 / 1.3 ClientHello record
    sni_bytes = sni.encode("ascii")
    sni_ext = (
        struct.pack("!HH", 0x0000, len(sni_bytes) + 5) + # Ext Type 0 (SNI)
        struct.pack("!HBH", len(sni_bytes) + 3, 0, len(sni_bytes)) +
        sni_bytes
    )

    alpn_str = b"h2"
    alpn_ext = (
        struct.pack("!HH", 0x0010, len(alpn_str) + 3) +
        struct.pack("!HB", len(alpn_str) + 1, len(alpn_str)) +
        alpn_str
    )

    extensions = sni_ext + alpn_ext
    ciphers = struct.pack("!HHHH", 0x1301, 0x1302, 0xc02f, 0xc030) # 4 ciphers = 8 bytes

    ch_body = (
        struct.pack("!H", 0x0303) + # TLS 1.2 client version
        os.urandom(32) +            # Random
        b"\x00" +                   # Session ID length 0
        struct.pack("!H", len(ciphers)) + ciphers +
        b"\x01\x00" +               # 1 compression method (null)
        struct.pack("!H", len(extensions)) + extensions
    )

    hs_header = struct.pack("!B", 1) + struct.pack("!I", len(ch_body))[1:] # Type 1 (ClientHello), uint24 len
    record_payload = hs_header + ch_body
    record_header = struct.pack("!BHH", 22, 0x0301, len(record_payload)) # Handshake, TLS 1.0 legacy
    return record_header + record_payload


def write_classic_pcap(filepath: str, packets: list):
    """Write classic microsecond PCAP file."""
    # Magic 0xa1b2c3d4, version 2.4, thiszone 0, sigfigs 0, snaplen 65535, linktype 1 (Ethernet)
    global_hdr = struct.pack("!IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

    with open(filepath, "wb") as f:
        f.write(global_hdr)
        for ts_sec, ts_usec, pkt_bytes in packets:
            pkt_hdr = struct.pack("!IIII", ts_sec, ts_usec, len(pkt_bytes), len(pkt_bytes))
            f.write(pkt_hdr)
            f.write(pkt_bytes)


def write_pcapng(filepath: str, packets: list):
    """Write standard PCAPNG file with SHB, IDB, and EPBs."""
    with open(filepath, "wb") as f:
        # 1. Section Header Block (SHB)
        # Type: 0x0A0D0D0A, Len: 28, Magic: 0x1A2B3C4D, Ver 1.0, SecLen: -1 (unknown)
        shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
        shb_len = 12 + len(shb_body)
        shb = struct.pack("<II", 0x0A0D0D0A, shb_len) + shb_body + struct.pack("<I", shb_len)
        f.write(shb)

        # 2. Interface Description Block (IDB)
        # Type: 0x00000001, LinkType: 1 (Ethernet), Reserved: 0, SnapLen: 65535
        idb_body = struct.pack("<HHI", 1, 0, 65535)
        idb_len = 8 + len(idb_body) + 4
        idb = struct.pack("<II", 0x00000001, idb_len) + idb_body + struct.pack("<I", idb_len)
        f.write(idb)

        # 3. Enhanced Packet Blocks (EPB)
        # Type: 0x00000006
        for ts_sec, ts_usec, pkt_bytes in packets:
            # Timestamp in microseconds (upper 32, lower 32)
            ts_us = ts_sec * 1_000_000 + ts_usec
            ts_high = (ts_us >> 32) & 0xFFFFFFFF
            ts_low = ts_us & 0xFFFFFFFF

            cap_len = len(pkt_bytes)
            orig_len = len(pkt_bytes)

            pad_len = (4 - (cap_len % 4)) % 4
            padded_pkt = pkt_bytes + (b"\x00" * pad_len)

            epb_body = struct.pack("<IIII", 0, ts_high, ts_low, cap_len) + struct.pack("<I", orig_len) + padded_pkt
            epb_len = 8 + len(epb_body) + 4
            epb = struct.pack("<II", 0x00000006, epb_len) + epb_body + struct.pack("<I", epb_len)
            f.write(epb)


def generate_all_fixtures():
    fixtures_dir = Path(__file__).resolve().parent
    fixtures_dir.mkdir(parents=True, exist_ok=True)

    base_time = 1776412800 # Fixed deterministic unix epoch (2026-04-17 08:00:00 UTC)

    # Prepare packets
    packets = []

    # 1. ARP Request & Reply
    arp_req = (
        struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) +
        bytes.fromhex("001122334455") + bytes([192, 168, 1, 50]) +
        bytes.fromhex("000000000000") + bytes([192, 168, 1, 1])
    )
    packets.append((base_time, 0, make_ethernet_frame("ffff:ffff:ffff".replace(":", ""), "00:11:22:33:44:55", 0x0806, arp_req)))

    arp_rep = (
        struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) +
        bytes.fromhex("00aa11223344") + bytes([192, 168, 1, 1]) +
        bytes.fromhex("001122334455") + bytes([192, 168, 1, 50])
    )
    packets.append((base_time, 1000, make_ethernet_frame("00:11:22:33:44:55", "00:aa:11:22:33:44", 0x0806, arp_rep)))

    # 2. ICMP Echo Request & Reply
    icmp_req = struct.pack("!BBHHH", 8, 0, 0, 0x4321, 1) + b"abcdefghijklmnopqrstuvw"
    ck = checksum_ip(icmp_req)
    icmp_req = struct.pack("!BBHHH", 8, 0, ck, 0x4321, 1) + b"abcdefghijklmnopqrstuvw"
    ip_icmp_req = make_ipv4_packet("192.168.1.50", "192.168.1.1", 1, icmp_req)
    packets.append((base_time, 2000, make_ethernet_frame("00:aa:11:22:33:44", "00:11:22:33:44:55", 0x0800, ip_icmp_req)))

    icmp_rep = struct.pack("!BBHHH", 0, 0, 0, 0x4321, 1) + b"abcdefghijklmnopqrstuvw"
    ck = checksum_ip(icmp_rep)
    icmp_rep = struct.pack("!BBHHH", 0, 0, ck, 0x4321, 1) + b"abcdefghijklmnopqrstuvw"
    ip_icmp_rep = make_ipv4_packet("192.168.1.1", "192.168.1.50", 1, icmp_rep)
    packets.append((base_time, 3000, make_ethernet_frame("00:11:22:33:44:55", "00:aa:11:22:33:44", 0x0800, ip_icmp_rep)))

    # 3. DNS Query and Response
    dns_q = make_dns_query(0xabcd, "api.twin.internal")
    udp_dns_q = make_udp_datagram(53535, 53, dns_q)
    ip_dns_q = make_ipv4_packet("192.168.1.50", "192.168.1.1", 17, udp_dns_q)
    packets.append((base_time, 10000, make_ethernet_frame("00:aa:11:22:33:44", "00:11:22:33:44:55", 0x0800, ip_dns_q)))

    dns_r = make_dns_response(0xabcd, "api.twin.internal", "192.168.1.100")
    udp_dns_r = make_udp_datagram(53, 53535, dns_r)
    ip_dns_r = make_ipv4_packet("192.168.1.1", "192.168.1.50", 17, udp_dns_r)
    packets.append((base_time, 12000, make_ethernet_frame("00:11:22:33:44:55", "00:aa:11:22:33:44", 0x0800, ip_dns_r)))

    # 4. HTTP Conversation
    # SYN
    tcp_syn = make_tcp_segment(49152, 80, 10000, 0, {"syn": True})
    packets.append((base_time, 20000, make_ethernet_frame("00:aa:11:22:33:44", "00:11:22:33:44:55", 0x0800, make_ipv4_packet("192.168.1.50", "192.168.1.100", 6, tcp_syn))))
    # SYN+ACK
    tcp_synack = make_tcp_segment(80, 49152, 20000, 10001, {"syn": True, "ack": True})
    packets.append((base_time, 21000, make_ethernet_frame("00:11:22:33:44:55", "00:aa:11:22:33:44", 0x0800, make_ipv4_packet("192.168.1.100", "192.168.1.50", 6, tcp_synack))))
    # ACK
    tcp_ack = make_tcp_segment(49152, 80, 10001, 20001, {"ack": True})
    packets.append((base_time, 22000, make_ethernet_frame("00:aa:11:22:33:44", "00:11:22:33:44:55", 0x0800, make_ipv4_packet("192.168.1.50", "192.168.1.100", 6, tcp_ack))))
    # HTTP GET
    http_req = b"GET /v1/status HTTP/1.1\r\nHost: api.twin.internal\r\nUser-Agent: TwinTester/1.0\r\nAuthorization: Bearer test_secret_token_123\r\n\r\n"
    tcp_http_req = make_tcp_segment(49152, 80, 10001, 20001, {"psh": True, "ack": True}, http_req)
    packets.append((base_time, 23000, make_ethernet_frame("00:aa:11:22:33:44", "00:11:22:33:44:55", 0x0800, make_ipv4_packet("192.168.1.50", "192.168.1.100", 6, tcp_http_req))))
    # HTTP 200 OK
    http_resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}"
    tcp_http_resp = make_tcp_segment(80, 49152, 20001, 10001 + len(http_req), {"psh": True, "ack": True}, http_resp)
    packets.append((base_time, 24000, make_ethernet_frame("00:11:22:33:44:55", "00:aa:11:22:33:44", 0x0800, make_ipv4_packet("192.168.1.100", "192.168.1.50", 6, tcp_http_resp))))

    # 5. TLS Handshake
    tls_ch = make_tls_client_hello("twin.internal")
    tcp_tls_syn = make_tcp_segment(49153, 443, 30000, 0, {"syn": True})
    packets.append((base_time, 30000, make_ethernet_frame("00:aa:11:22:33:44", "00:11:22:33:44:55", 0x0800, make_ipv4_packet("192.168.1.50", "192.168.1.100", 6, tcp_tls_syn))))
    tcp_tls_synack = make_tcp_segment(443, 49153, 40000, 30001, {"syn": True, "ack": True})
    packets.append((base_time, 31000, make_ethernet_frame("00:11:22:33:44:55", "00:aa:11:22:33:44", 0x0800, make_ipv4_packet("192.168.1.100", "192.168.1.50", 6, tcp_tls_synack))))
    tcp_tls_ack = make_tcp_segment(49153, 443, 30001, 40001, {"ack": True})
    packets.append((base_time, 32000, make_ethernet_frame("00:aa:11:22:33:44", "00:11:22:33:44:55", 0x0800, make_ipv4_packet("192.168.1.50", "192.168.1.100", 6, tcp_tls_ack))))
    tcp_tls_ch = make_tcp_segment(49153, 443, 30001, 40001, {"psh": True, "ack": True}, tls_ch)
    packets.append((base_time, 33000, make_ethernet_frame("00:aa:11:22:33:44", "00:11:22:33:44:55", 0x0800, make_ipv4_packet("192.168.1.50", "192.168.1.100", 6, tcp_tls_ch))))

    # Write files
    pcap_path = fixtures_dir / "sample_capture.pcap"
    pcapng_path = fixtures_dir / "sample_capture.pcapng"

    write_classic_pcap(str(pcap_path), packets)
    write_pcapng(str(pcapng_path), packets)

    print(f"Generated {len(packets)} packets to {pcap_path} and {pcapng_path}")


if __name__ == "__main__":
    generate_all_fixtures()
