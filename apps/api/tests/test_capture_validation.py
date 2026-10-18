"""Tests for Phase 09 real capture validation, differential testing, and reference decoder."""

from fastapi.testclient import TestClient
from scripts.generate_capture_corpus import (
    make_arp,
    make_dns,
    make_ethernet,
    make_ipv4,
    make_tcp,
    make_udp,
    make_vlan_ethernet,
)

from network_twin.captures.corpus import CaptureCorpus
from network_twin.captures.differential import DifferentialValidator
from network_twin.captures.e2e_validator import EndToEndValidator
from network_twin.captures.models import MetamorphicRelationType
from network_twin.captures.reference_decoder import ReferenceDecoder
from network_twin.main import app


def test_corpus_manifest_loading():
    corpus = CaptureCorpus()
    items = corpus.list_captures()
    assert len(items) >= 8

    ids = [i.capture_id for i in items]
    assert "real-web-traffic-pcap" in ids
    assert "real-web-traffic-pcapng" in ids
    assert "vlan-segmented-pcap" in ids
    assert "ipv6-nd-traffic-pcap" in ids
    assert "tls-sni-handshake-pcap" in ids
    assert "tcp-retrans-ooo-pcap" in ids
    assert "ip-fragmentation-pcap" in ids
    assert "malformed-edge-cases-pcap" in ids
    assert "empty-zero-packets-pcap" in ids

    # Check properties
    for item in items:
        assert len(item.sha256) == 64
        assert item.license is not None
        assert item.attribution is not None
        assert item.file_size_bytes >= 0


def test_reference_decoder_direct():
    # 1. Ethernet + IPv4 + TCP
    tcp_b = make_tcp("192.168.1.10", "192.168.1.20", 12345, 80, 1000, 2000, {"syn": True, "ack": True})
    ip_b = make_ipv4("192.168.1.10", "192.168.1.20", 6, tcp_b)
    eth_b = make_ethernet("00:22:33:44:55:66", "00:11:22:33:44:55", 0x0800, ip_b)

    res = ReferenceDecoder.decode_packet(eth_b)
    assert res["status"] == "ok"
    assert res["link_layer"]["protocol"] == "Ethernet"
    assert res["link_layer"]["source_mac"] == "00:11:22:33:44:55"
    assert res["link_layer"]["destination_mac"] == "00:22:33:44:55:66"
    assert res["network_layer"]["protocol"] == "IPv4"
    assert res["network_layer"]["source_ip"] == "192.168.1.10"
    assert res["network_layer"]["destination_ip"] == "192.168.1.20"
    assert res["transport_layer"]["protocol"] == "TCP"
    assert res["transport_layer"]["source_port"] == 12345
    assert res["transport_layer"]["destination_port"] == 80
    assert res["transport_layer"]["flags"]["syn"] is True
    assert res["transport_layer"]["flags"]["ack"] is True

    # 2. 802.1Q VLAN
    vlan_eth = make_vlan_ethernet("00:22:33:44:55:66", "00:11:22:33:44:55", 100, 0x0800, ip_b)
    vlan_res = ReferenceDecoder.decode_packet(vlan_eth)
    assert vlan_res["link_layer"]["vlan_id"] == 100

    # 3. ARP
    arp_b = make_arp("00:11:22:33:44:55", "10.0.0.1", "00:00:00:00:00:00", "10.0.0.2", 1)
    eth_arp = make_ethernet("ff:ff:ff:ff:ff:ff", "00:11:22:33:44:55", 0x0806, arp_b)
    arp_res = ReferenceDecoder.decode_packet(eth_arp)
    assert arp_res["network_layer"]["protocol"] == "ARP"
    assert arp_res["network_layer"]["sender_ip"] == "10.0.0.1"

    # 4. DNS
    dns_b = make_dns(0x1234, "test.local", is_response=True, rdata_ip="10.0.0.50")
    udp_b = make_udp("10.0.0.1", "10.0.0.2", 53, 54321, dns_b)
    ip_udp = make_ipv4("10.0.0.1", "10.0.0.2", 17, udp_b)
    eth_dns = make_ethernet("00:22:33:44:55:66", "00:11:22:33:44:55", 0x0800, ip_udp)
    dns_res = ReferenceDecoder.decode_packet(eth_dns)
    assert dns_res["application_layer"]["protocol"] == "DNS"
    assert dns_res["application_layer"]["qname"] == "test.local"
    assert dns_res["application_layer"]["is_response"] is True


def test_differential_validator_web_traffic():
    validator = DifferentialValidator()
    report = validator.validate_capture("real-web-traffic-pcap")
    assert report.passed is True
    assert report.total_packets_processed == 9
    assert report.total_flows_observed == 2
    assert len(report.field_differences) == 0
    assert report.telemetry.wall_duration_ms > 0
    assert report.telemetry.throughput_pps > 0


def test_format_equivalence_pcap_vs_pcapng():
    validator = DifferentialValidator()
    diff_res = validator.test_format_equivalence("real-web-traffic-pcap", "real-web-traffic-pcapng")
    assert diff_res.passed is True
    assert diff_res.relation_type == MetamorphicRelationType.FORMAT_EQUIVALENCE
    assert diff_res.details["pcap_packets"] == diff_res.details["pcapng_packets"]
    assert diff_res.details["pcap_flows"] == diff_res.details["pcapng_flows"]


def test_metamorphic_timestamp_shift():
    validator = DifferentialValidator()
    diff_res = validator.test_metamorphic_timestamp_shift("real-web-traffic-pcap", shift_seconds=120)
    assert diff_res.passed is True
    assert diff_res.relation_type == MetamorphicRelationType.TIMESTAMP_SHIFT
    assert diff_res.details["base_packets"] == diff_res.details["shifted_packets"]
    assert diff_res.details["base_flows"] == diff_res.details["shifted_flows"]


def test_metamorphic_noise_injection():
    validator = DifferentialValidator()
    diff_res = validator.test_metamorphic_noise_injection("real-web-traffic-pcap")
    assert diff_res.passed is True
    assert diff_res.relation_type == MetamorphicRelationType.NOISE_INJECTION
    assert diff_res.details["noise_packets"] == diff_res.details["base_packets"] + 1
    assert diff_res.details["noise_flows"] == diff_res.details["base_flows"] + 1


def test_end_to_end_validation():
    e2e = EndToEndValidator()
    res = e2e.run_e2e_validation("real-web-traffic-pcap")
    assert res["all_stages_verified"] is True
    assert res["engine_status"] == "completed"
    assert res["packets_processed"] == 9
    assert res["flows_tracked"] >= 1
    assert res["events_ingested"] >= 1
    assert res["topology_nodes_discovered"] >= 1
    assert res["snapshot_id"] is not None


def test_captures_api_endpoints():
    client = TestClient(app)

    # 1. List
    resp = client.get("/api/v1/twin/captures")
    assert resp.status_code == 200
    captures = resp.json()
    assert len(captures) >= 8

    # 2. Summary
    sum_resp = client.get("/api/v1/twin/captures/summary")
    assert sum_resp.status_code == 200
    sum_data = sum_resp.json()
    assert sum_data["total_captures"] >= 8
    assert "IPv4" in sum_data["supported_protocols"]
    assert "TCP" in sum_data["supported_protocols"]

    # 3. Single Item
    item_resp = client.get("/api/v1/twin/captures/real-web-traffic-pcap")
    assert item_resp.status_code == 200
    item_data = item_resp.json()
    assert item_data["packet_count"] == 9

    # 4. Validate
    val_resp = client.post("/api/v1/twin/captures/real-web-traffic-pcap/validate")
    assert val_resp.status_code == 200
    val_data = val_resp.json()
    assert val_data["passed"] is True
    assert val_data["total_packets_processed"] == 9

    # 5. Differential format check
    diff_resp = client.post(
        "/api/v1/twin/captures/differential",
        json={
            "relation_type": "FORMAT_EQUIVALENCE",
            "base_capture_id": "real-web-traffic-pcap",
            "transformed_capture_id": "real-web-traffic-pcapng",
        },
    )
    assert diff_resp.status_code == 200
    assert diff_resp.json()["passed"] is True
