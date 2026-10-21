"""Regression tests for IEEE 1588 Precision Time Protocol (PTPv2) classification and DNS differentiation."""

import json
from pathlib import Path

from network_twin.services.analysis_service import analysis_service


def test_ptp_capture_classification_and_telemetry():
    """Verify IEEE 1588 PTP capture is classified as PTP and never falsely classified as DNS."""
    fixture_path = Path("tests/fixtures/IEEE1588_Precision_Time_Protocol_PTPv2_Sequence.pcap")
    if not fixture_path.is_file():
        upload_dir = Path("data/uploads")
        pcap_files = list(upload_dir.glob("*IEEE1588_Precision Time Protocol-PTPv2-Sequence.pcap"))
        assert len(pcap_files) > 0, "PTP test pcap fixture not found in tests/fixtures or data/uploads"
        fixture_path = pcap_files[0]

    with open(fixture_path, "rb") as f:
        content = f.read()

    job = analysis_service.analyze_capture(filename="IEEE1588_PTPv2_Sequence.pcap", content=content)
    assert job.status == "completed"
    assert job.summary is not None
    summary = job.summary

    # 1. Total packets and bytes match wire truth
    assert summary.total_packets == 39
    assert summary.total_bytes == 3312

    # 2. Protocol distribution reflects layer counts accurately
    assert summary.protocol_counts.get("Ethernet") == 39
    assert summary.protocol_counts.get("IPv4") == 25
    assert summary.protocol_counts.get("UDP") == 25
    assert summary.protocol_counts.get("PTP") == 39
    assert summary.protocol_counts.get("DNS", 0) == 0

    # 3. DNS transactions MUST be 0 (no false DNS queries or responses)
    assert summary.dns_queries == 0
    assert summary.dns_responses == 0
    assert summary.ptp_messages == 39

    # 4. Flows are reconstructed with PTP application protocol, not DNS
    assert summary.total_flows == 3
    for flow in summary.flows:
        assert flow.ip_proto == "UDP"
        assert flow.src_port in (319, 320)
        assert flow.dst_port in (319, 320)
        assert flow.app_protocol == "PTP"
        assert any(msg in flow.info for msg in ("Pdelay_Req", "Sync", "Announce"))

    # 5. Parser integrity reflects 100% ok decode
    assert summary.parser_status_counts.get("ok") == 39
    assert summary.parser_status_counts.get("malformed", 0) == 0
    assert summary.parser_status_counts.get("checksum_error", 0) == 0

    # 6. Event stream inspection
    events_path = Path("data/results") / f"{job.job_id}.events.jsonl"
    assert events_path.is_file()

    with open(events_path, encoding="utf-8") as f:
        events = [json.loads(line) for line in f if line.strip()]

    assert len(events) == 39

    eth_ptp_count = 0
    udp_ptp_319_count = 0
    udp_ptp_320_count = 0

    for ev in events:
        parser_st = ev.get("parser_status", {})
        assert parser_st.get("status") == "ok"
        assert parser_st.get("bytes_remaining") == 0

        app = ev.get("application_layer", {})
        assert app is not None
        assert app.get("protocol") == "PTP"
        meta = app.get("protocol_metadata", {})
        assert meta.get("version") == 2
        assert meta.get("version_name") == "PTPv2"

        ll = ev.get("link_layer", {})
        if ll.get("ether_type") == 0x88F7:
            eth_ptp_count += 1
            assert ev.get("network_layer") is None
            assert ev.get("transport_layer") is None
            assert meta.get("transport") == "Ethernet"
        elif ll.get("ether_type") == 0x0800:
            tl = ev.get("transport_layer", {})
            assert tl.get("protocol") == "UDP"
            assert meta.get("transport") == "UDP"
            if tl.get("source_port") == 319 or tl.get("destination_port") == 319:
                udp_ptp_319_count += 1
            elif tl.get("source_port") == 320 or tl.get("destination_port") == 320:
                udp_ptp_320_count += 1

    # Exact verified packet distribution
    assert eth_ptp_count == 14
    assert udp_ptp_319_count == 22
    assert udp_ptp_320_count == 3
