"""Unit tests for Topology Graph construction, Snapshot creation, and Differential comparisons."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from network_twin.config import AppSettings
from network_twin.models.intelligence import (
    Asset,
    CommunicationRelationship,
    EvidenceType,
    IdentityStatus,
    NetworkSegment,
    NetworkService,
)
from network_twin.storage.metadata_store import MetadataStore
from network_twin.topology.graph_builder import GraphBuilder
from network_twin.topology.snapshot_manager import SnapshotManager


@pytest.fixture
def topology_test_env(tmp_path: Path):
    cfg = AppSettings(environment="testing", data_dir=str(tmp_path))
    store = MetadataStore(cfg)
    builder = GraphBuilder(store)
    manager = SnapshotManager(store, builder)
    return store, builder, manager


def test_graph_construction_and_snapshot_diff(topology_test_env):
    store, builder, manager = topology_test_env
    now = datetime.now(UTC)

    # 1. Populate initial state: 1 segment, 2 assets, 1 service, 1 relationship
    seg = NetworkSegment(
        segment_id="seg-192_168_1_0_24",
        cidr_prefix="192.168.1.0/24",
        address_family="IPv4",
        gateway_ip="192.168.1.1",
        observed_host_count=2,
        confidence=0.9,
        provenance="test",
        first_seen=now,
        last_seen=now,
    )
    store.upsert_segment(seg)

    asset1 = Asset(
        asset_id="asset-client",
        primary_ip="192.168.1.50",
        ip_addresses=["192.168.1.50"],
        mac_addresses=["00:11:22:33:44:50"],
        hostnames=["client.internal"],
        observed_protocols=["TCP"],
        observed_services=[],
        first_seen=now,
        last_seen=now,
        identity_status=IdentityStatus.CONFIRMED,
        confidence=0.95,
        conflicts=[],
        observation_sources=["cap-1"],
    )
    store.upsert_asset(asset1)

    asset2 = Asset(
        asset_id="asset-server",
        primary_ip="192.168.1.100",
        ip_addresses=["192.168.1.100"],
        mac_addresses=["00:11:22:33:44:10"],
        hostnames=["api.twin.internal"],
        observed_protocols=["TCP"],
        observed_services=["HTTP"],
        first_seen=now,
        last_seen=now,
        identity_status=IdentityStatus.CONFIRMED,
        confidence=0.95,
        conflicts=[],
        observation_sources=["cap-1"],
    )
    store.upsert_asset(asset2)

    svc = NetworkService(
        service_id="svc-http-80",
        asset_id="asset-server",
        server_ip="192.168.1.100",
        transport_protocol="TCP",
        port=80,
        app_protocol="HTTP",
        classification_confidence=0.95,
        first_seen=now,
        last_seen=now,
    )
    store.upsert_service(svc)

    rel = CommunicationRelationship(
        relationship_id="rel-client-server-tcp-80",
        src_asset_id="asset-client",
        dst_asset_id="asset-server",
        transport_protocol="TCP",
        src_port=49152,
        dst_port=80,
        app_protocol="HTTP",
        packet_count=10,
        byte_count=1200,
        first_seen=now,
        last_seen=now,
        flow_ids=["flow-1"],
        dns_transaction_ids=[],
        evidence_type=EvidenceType.PACKET_OBSERVED,
        directionality="bidirectional",
        confidence=1.0,
    )
    store.upsert_relationship(rel)

    # 2. Build graph and create baseline snapshot
    graph1 = builder.build_current_graph()
    assert graph1.node_count >= 4  # 1 segment + 2 assets + 1 service
    assert graph1.edge_count >= 3  # 2 subnet attachments + 1 service hosts + 1 communication

    snap1, _ = manager.create_snapshot("Baseline Snapshot", source_captures=["cap-1"])
    assert snap1.snapshot_id.startswith("snap-")
    assert snap1.node_count == graph1.node_count

    # 3. Add a new asset and new relationship to create state delta
    asset3 = Asset(
        asset_id="asset-dns",
        primary_ip="192.168.1.1",
        ip_addresses=["192.168.1.1"],
        mac_addresses=["00:11:22:33:44:01"],
        hostnames=["dns.internal"],
        observed_protocols=["UDP"],
        observed_services=["DNS"],
        first_seen=now,
        last_seen=now,
        identity_status=IdentityStatus.CONFIRMED,
        confidence=0.98,
        conflicts=[],
        observation_sources=["cap-2"],
    )
    store.upsert_asset(asset3)

    snap2, _ = manager.create_snapshot("Target Snapshot with DNS", source_captures=["cap-1", "cap-2"])
    assert snap2.node_count > snap1.node_count

    # 4. Compare snapshots
    diff = manager.compare_snapshots(snap1.snapshot_id, snap2.snapshot_id)
    assert len(diff.added_nodes) >= 1
    added_ids = {n.node_id for n in diff.added_nodes}
    assert "node-asset-dns" in added_ids
    assert len(diff.evidence_explanations) > 0
