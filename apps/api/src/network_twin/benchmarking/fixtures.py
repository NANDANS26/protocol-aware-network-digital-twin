"""Deterministic benchmark fixtures spanning hand-verifiable, policy-violation, and real captures."""

import hashlib
import io
import struct
from collections.abc import Callable
from pathlib import Path

from network_twin.benchmarking.models import (
    BenchmarkCategory,
    BenchmarkFixtureMeta,
    BenchmarkProvenance,
    ExpectedOutcome,
)
from network_twin.testing.generators import (
    make_dns_query,
    make_dns_response,
    make_ethernet_frame,
    make_ipv4_packet,
    make_tcp_segment,
    make_udp_datagram,
)


def _build_pcap_bytes(packets: list[tuple[int, int, bytes]]) -> bytes:
    """Helper to generate in-memory classic PCAP bytes."""
    global_hdr = struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    buf = io.BytesIO()
    buf.write(global_hdr)
    for ts_sec, ts_usec, pkt_bytes in packets:
        pkt_hdr = struct.pack("!IIII", ts_sec, ts_usec, len(pkt_bytes), len(pkt_bytes))
        buf.write(pkt_hdr)
        buf.write(pkt_bytes)
    return buf.getvalue()


def generate_handshake_fixture() -> bytes:
    """Generates a bit-exact 3-way TCP handshake."""
    mac_client = "00:11:22:33:44:55"
    mac_server = "aa:bb:cc:dd:ee:ff"
    ip_client = "10.0.0.10"
    ip_server = "10.0.0.20"
    port_client = 49152
    port_server = 80

    packets: list[tuple[int, int, bytes]] = []

    # 1. SYN
    tcp_syn = make_tcp_segment(port_client, port_server, seq=1000, ack=0, flags={"syn": True})
    ip_syn = make_ipv4_packet(ip_client, ip_server, protocol=6, payload=tcp_syn, identification=1)
    eth_syn = make_ethernet_frame(mac_server, mac_client, 0x0800, ip_syn)
    packets.append((1700000000, 0, eth_syn))

    # 2. SYN-ACK
    tcp_synack = make_tcp_segment(port_server, port_client, seq=5000, ack=1001, flags={"syn": True, "ack": True})
    ip_synack = make_ipv4_packet(ip_server, ip_client, protocol=6, payload=tcp_synack, identification=2)
    eth_synack = make_ethernet_frame(mac_client, mac_server, 0x0800, ip_synack)
    packets.append((1700000000, 10000, eth_synack))

    # 3. ACK
    tcp_ack = make_tcp_segment(port_client, port_server, seq=1001, ack=5001, flags={"ack": True})
    ip_ack = make_ipv4_packet(ip_client, ip_server, protocol=6, payload=tcp_ack, identification=3)
    eth_ack = make_ethernet_frame(mac_server, mac_client, 0x0800, ip_ack)
    packets.append((1700000000, 20000, eth_ack))

    return _build_pcap_bytes(packets)


def generate_dns_fixture() -> bytes:
    """Generates DNS query and response for host discovery."""
    mac_client = "00:11:22:33:44:55"
    mac_dns = "00:99:88:77:66:55"
    ip_client = "10.0.1.10"
    ip_dns = "10.0.1.1"

    packets: list[tuple[int, int, bytes]] = []

    # Query: db.corp.internal A
    dns_q = make_dns_query(tx_id=0x1234, qname="db.corp.internal")
    udp_q = make_udp_datagram(53535, 53, dns_q)
    ip_q = make_ipv4_packet(ip_client, ip_dns, protocol=17, payload=udp_q, identification=10)
    eth_q = make_ethernet_frame(mac_dns, mac_client, 0x0800, ip_q)
    packets.append((1700000100, 0, eth_q))

    # Response: db.corp.internal -> 10.0.3.50
    dns_r = make_dns_response(tx_id=0x1234, qname="db.corp.internal", ip="10.0.3.50")
    udp_r = make_udp_datagram(53, 53535, dns_r)
    ip_r = make_ipv4_packet(ip_dns, ip_client, protocol=17, payload=udp_r, identification=11)
    eth_r = make_ethernet_frame(mac_client, mac_dns, 0x0800, ip_r)
    packets.append((1700000100, 15000, eth_r))

    return _build_pcap_bytes(packets)


def generate_ssh_violation_fixture() -> bytes:
    """Generates packets attempting cross-segment SSH between restricted zones."""
    mac_src = "00:aa:11:22:33:44"
    mac_dst = "00:bb:55:66:77:88"
    ip_src = "10.0.1.15"  # Dev subnet
    ip_dst = "10.0.2.25"  # Secure Prod DB subnet

    packets: list[tuple[int, int, bytes]] = []
    tcp_syn = make_tcp_segment(52100, 22, seq=100, ack=0, flags={"syn": True})
    ip_syn = make_ipv4_packet(ip_src, ip_dst, protocol=6, payload=tcp_syn, identification=99)
    eth_syn = make_ethernet_frame(mac_dst, mac_src, 0x0800, ip_syn)
    packets.append((1700000200, 0, eth_syn))

    return _build_pcap_bytes(packets)


def generate_empty_pcap_fixture() -> bytes:
    """Generates a valid PCAP header with zero packet records."""
    return _build_pcap_bytes([])


def generate_scale_profiling_fixture(num_packets: int = 200, num_flows: int = 10) -> bytes:
    """Generates multi-flow traffic across multiple timestamps for throughput and ML evaluation."""
    packets: list[tuple[int, int, bytes]] = []
    base_ts = 1700001000

    for i in range(num_packets):
        flow_idx = i % num_flows
        client_ip = f"10.0.1.{10 + flow_idx}"
        server_ip = f"10.0.2.{20 + (flow_idx % 3)}"
        client_port = 40000 + flow_idx
        server_port = 80 if (flow_idx % 2 == 0) else 443

        ts_sec = base_ts + (i // 10)
        ts_usec = (i % 10) * 100000

        # Alternate SYN, PSH-ACK, FIN
        phase = (i // num_flows) % 3
        flags = {"syn": True} if phase == 0 else ({"psh": True, "ack": True} if phase == 1 else {"fin": True})
        payload = b"GET /benchmark HTTP/1.1\r\nHost: twin.local\r\n\r\n" if phase == 1 else b""

        tcp = make_tcp_segment(client_port, server_port, seq=1000 + i, ack=5000 + i, flags=flags, payload=payload)
        ip = make_ipv4_packet(client_ip, server_ip, protocol=6, payload=tcp, identification=1000 + i)
        eth = make_ethernet_frame("aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02", 0x0800, ip)
        packets.append((ts_sec, ts_usec, eth))

    return _build_pcap_bytes(packets)


def get_public_sample_capture_bytes() -> bytes:
    """Reads existing sample capture from repository test fixtures."""
    repo_root = Path(__file__).resolve().parents[5]
    fixture_path = repo_root / "tests" / "fixtures" / "sample_capture.pcap"
    if fixture_path.is_file():
        return fixture_path.read_bytes()
    # Fallback to handshake generator if not on disk
    return generate_handshake_fixture()


# Catalog of defined benchmark fixtures
BENCHMARK_FIXTURES: dict[str, tuple[BenchmarkFixtureMeta, Callable[[], bytes]]] = {}


def _register_fixture(meta: BenchmarkFixtureMeta, generator: Callable[[], bytes]):
    BENCHMARK_FIXTURES[meta.fixture_id] = (meta, generator)


# 1. Hand-verifiable 3-way handshake
_handshake_bytes = generate_handshake_fixture()
_register_fixture(
    BenchmarkFixtureMeta(
        fixture_id="handshake-core",
        name="Hand-Verifiable 3-Way TCP Handshake",
        category=BenchmarkCategory.HAND_VERIFIABLE_CORE,
        provenance=BenchmarkProvenance.SYNTHETIC_FIXTURE,
        description="Bit-exact 3-packet SYN / SYN-ACK / ACK sequence between 10.0.0.10 and 10.0.0.20.",
        packet_count=3,
        byte_size=len(_handshake_bytes),
        content_sha256=hashlib.sha256(_handshake_bytes).hexdigest(),
        expected_properties=ExpectedOutcome(
            min_packets=3,
            expected_flows=1,
            expected_lpm_next_hop="10.0.0.1",
            expected_forwarding_status="DELIVERED",
            expected_invariant_status="HOLD",
            ground_truth_rationale="RFC 793 compliant 3-way connection setup with valid next-hop routing and no ACL blocks.",
        ),
    ),
    generate_handshake_fixture,
)

# 2. Public sample capture
_sample_bytes = get_public_sample_capture_bytes()
_register_fixture(
    BenchmarkFixtureMeta(
        fixture_id="public-sample-pcap",
        name="Public Reference Capture (Mixed Protocols)",
        category=BenchmarkCategory.STATEFUL_FLOWS,
        provenance=BenchmarkProvenance.PUBLIC_CAPTURE,
        description="Public capture fixture containing mixed ARP, DNS, TCP, and HTTP protocol packets.",
        packet_count=10,
        byte_size=len(_sample_bytes),
        content_sha256=hashlib.sha256(_sample_bytes).hexdigest(),
        expected_properties=ExpectedOutcome(
            min_packets=10,
            expected_flows=2,
            expected_forwarding_status="DELIVERED",
            expected_invariant_status="HOLD",
            ground_truth_rationale="Standard reference traffic with observable multi-protocol conversation flows.",
        ),
    ),
    get_public_sample_capture_bytes,
)

# 3. DNS service resolution
_dns_bytes = generate_dns_fixture()
_register_fixture(
    BenchmarkFixtureMeta(
        fixture_id="dns-service-resolution",
        name="DNS Host Discovery & Resolution",
        category=BenchmarkCategory.DNS_TOPOLOGY_CHANGES,
        provenance=BenchmarkProvenance.SYNTHETIC_FIXTURE,
        description="DNS transaction query and response resolving hostname db.corp.internal to IP 10.0.3.50.",
        packet_count=2,
        byte_size=len(_dns_bytes),
        content_sha256=hashlib.sha256(_dns_bytes).hexdigest(),
        expected_properties=ExpectedOutcome(
            min_packets=2,
            expected_flows=1,
            expected_forwarding_status="DELIVERED",
            expected_invariant_status="HOLD",
            ground_truth_rationale="Bidirectional DNS transaction 0x1234 binds asset hostname to IP in topology graph.",
        ),
    ),
    generate_dns_fixture,
)

# 4. Security violation fixture
_ssh_bytes = generate_ssh_violation_fixture()
_register_fixture(
    BenchmarkFixtureMeta(
        fixture_id="security-ssh-violation",
        name="Cross-Subnet SSH Policy Breach",
        category=BenchmarkCategory.SECURITY_VIOLATION,
        provenance=BenchmarkProvenance.SYNTHETIC_FIXTURE,
        description="Restricted SSH attempt crossing boundary from Dev subnet 10.0.1.0/24 into Secure DB 10.0.2.0/24.",
        packet_count=1,
        byte_size=len(_ssh_bytes),
        content_sha256=hashlib.sha256(_ssh_bytes).hexdigest(),
        expected_properties=ExpectedOutcome(
            min_packets=1,
            expected_flows=1,
            expected_forwarding_status="DROPPED_BY_FIREWALL",
            expected_invariant_status="VIOLATED",
            ground_truth_rationale="Firewall ACL explicitly DENIES TCP port 22 between development and production database segments.",
        ),
    ),
    generate_ssh_violation_fixture,
)

# 5. Empty malformed capture
_empty_bytes = generate_empty_pcap_fixture()
_register_fixture(
    BenchmarkFixtureMeta(
        fixture_id="empty-malformed-edge",
        name="Zero-Packet Empty PCAP Boundary",
        category=BenchmarkCategory.MALFORMED_EDGE_CASES,
        provenance=BenchmarkProvenance.SYNTHETIC_FIXTURE,
        description="Syntactically valid PCAP header containing zero packet records.",
        packet_count=0,
        byte_size=len(_empty_bytes),
        content_sha256=hashlib.sha256(_empty_bytes).hexdigest(),
        expected_properties=ExpectedOutcome(
            min_packets=0,
            expected_flows=0,
            expected_forwarding_status=None,
            expected_invariant_status=None,
            ground_truth_rationale="Boundary condition: Parser must gracefully exit without crashing and report 0 packets.",
        ),
    ),
    generate_empty_pcap_fixture,
)

# 6. Scale & throughput profiling workload
_scale_bytes = generate_scale_profiling_fixture(num_packets=200, num_flows=10)
_register_fixture(
    BenchmarkFixtureMeta(
        fixture_id="scale-profiling-workload",
        name="200-Packet Multi-Flow Throughput Workload",
        category=BenchmarkCategory.SCALE_PROFILING,
        provenance=BenchmarkProvenance.SYNTHETIC_FIXTURE,
        description="200-packet multi-flow workload across 20 distinct time intervals for throughput and predictive accuracy benchmarking.",
        packet_count=200,
        byte_size=len(_scale_bytes),
        content_sha256=hashlib.sha256(_scale_bytes).hexdigest(),
        expected_properties=ExpectedOutcome(
            min_packets=200,
            expected_flows=10,
            expected_forwarding_status="DELIVERED",
            expected_invariant_status="HOLD",
            ground_truth_rationale="Dense traffic workload suitable for measuring processing throughput and ML baseline comparison.",
        ),
    ),
    lambda: generate_scale_profiling_fixture(num_packets=200, num_flows=10),
)


def list_benchmark_fixtures() -> list[BenchmarkFixtureMeta]:
    """Returns metadata for all available benchmark fixtures."""
    return [meta for meta, _ in BENCHMARK_FIXTURES.values()]


def get_benchmark_fixture(fixture_id: str) -> tuple[BenchmarkFixtureMeta, bytes]:
    """Retrieves metadata and raw byte content for a specified fixture."""
    if fixture_id not in BENCHMARK_FIXTURES:
        raise KeyError(f"Benchmark fixture '{fixture_id}' not found.")
    meta, generator = BENCHMARK_FIXTURES[fixture_id]
    return meta, generator()
