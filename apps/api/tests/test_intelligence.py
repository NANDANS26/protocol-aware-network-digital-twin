"""Unit tests for Network Intelligence: Identity Resolution, DNS Correlation, and Subnet Inference."""

from datetime import UTC, datetime

from network_twin.intelligence.dns_correlator import DnsCorrelator
from network_twin.intelligence.identity_resolver import IdentityResolver
from network_twin.intelligence.segment_inferrer import SegmentInferrer, infer_cidr_prefix
from network_twin.models.intelligence import IdentityStatus


def test_identity_resolution_confirmed_and_conflicting():
    resolver = IdentityResolver()
    now = datetime.now(UTC)

    # 1. Consistent IP and MAC observation -> CONFIRMED
    asset, evs = resolver.resolve_asset_from_observation(
        ip_str="192.168.1.10",
        mac_str="00:11:22:33:44:55",
        observed_time=now,
        source_id="cap-1",
        protocol="TCP",
        hostname="server1.internal",
    )
    assert asset.primary_ip == "192.168.1.10"
    assert asset.identity_status == IdentityStatus.CONFIRMED
    assert "00:11:22:33:44:55" in asset.mac_addresses
    assert "server1.internal" in asset.hostnames
    assert len(evs) == 1

    # 2. Re-observation with same MAC updates timestamps and maintains CONFIRMED
    asset2, _ = resolver.resolve_asset_from_observation(
        ip_str="192.168.1.10",
        mac_str="00:11:22:33:44:55",
        observed_time=now,
        source_id="cap-2",
        protocol="UDP",
    )
    assert asset2.asset_id == asset.asset_id
    assert "UDP" in asset2.observed_protocols

    # 3. Conflicting MAC on same IP without gateway/multicast -> CONFLICTING
    asset3, _ = resolver.resolve_asset_from_observation(
        ip_str="192.168.1.10",
        mac_str="aa:bb:cc:dd:ee:ff",
        observed_time=now,
        source_id="cap-3",
    )
    assert asset3.identity_status == IdentityStatus.CONFLICTING
    assert len(asset3.conflicts) > 0
    assert asset3.confidence < 0.5


def test_dns_correlation():
    correlator = DnsCorrelator()
    now = datetime.now(UTC)

    # Record Query
    tx = correlator.record_query(
        tx_id=42,
        qname="web.service.internal",
        client_ip="192.168.1.50",
        timestamp=now,
    )
    assert tx.tx_id == 42
    assert tx.is_matched is False

    # Record Response
    completed_tx, evs = correlator.record_response(
        tx_id=42,
        qname="web.service.internal",
        server_ip="192.168.1.1",
        answers=["10.0.0.100", "10.0.0.101"],
        timestamp=now,
        source_id="cap-1",
    )
    assert completed_tx.is_matched is True
    assert completed_tx.resolved_ips == ["10.0.0.100", "10.0.0.101"]
    assert len(evs) == 2

    # Query resolved hostnames
    hosts = correlator.get_hostnames_for_ip("10.0.0.100")
    assert "web.service.internal" in hosts


def test_segment_inferrer():
    inferrer = SegmentInferrer()
    now = datetime.now(UTC)

    # IPv4 CIDR inference
    cidr4 = infer_cidr_prefix("192.168.5.123")
    assert cidr4 == "192.168.5.0/24"

    # IPv6 CIDR inference
    cidr6 = infer_cidr_prefix("2001:db8:abcd:1234::1")
    assert cidr6 == "2001:db8:abcd:1234::/64"

    # Observe host and candidate gateway
    seg1 = inferrer.observe_ip("192.168.1.1", now, "cap-1")
    assert seg1.gateway_ip == "192.168.1.1"

    seg2 = inferrer.observe_ip("192.168.1.100", now, "cap-1")
    assert seg2.observed_host_count == 2
    assert seg2.gateway_ip == "192.168.1.1"
