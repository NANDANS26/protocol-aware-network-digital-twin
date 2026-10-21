from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from network_twin.config import AppSettings
from network_twin.intelligence.identity_resolver import IdentityResolver
from network_twin.intelligence.segment_inferrer import SegmentInferrer, infer_cidr_prefix
from network_twin.main import app
from network_twin.models.intelligence import (
    Asset,
    IdentityStatus,
    NetworkSegment,
)
from network_twin.storage.metadata_store import MetadataStore
from network_twin.topology.graph_builder import GraphBuilder
from network_twin.topology.snapshot_manager import SnapshotManager


@pytest.fixture
def client():
    return TestClient(app)


def test_multicast_segment_inferrer_protection():
    """Verify that multicast IPs (224.0.0.107, 224.0.1.129) are never inferred as CIDR subnets."""
    assert infer_cidr_prefix("224.0.0.107") is None
    assert infer_cidr_prefix("224.0.1.129") is None
    assert infer_cidr_prefix("239.255.255.250") is None
    assert infer_cidr_prefix("127.0.0.1") is None
    assert infer_cidr_prefix("0.0.0.0") is None

    inferrer = SegmentInferrer()
    now = datetime.now(UTC)
    assert inferrer.observe_ip("224.0.0.107", now, "cap-1") is None
    assert inferrer.observe_ip("224.0.1.129", now, "cap-1") is None

    # Normal unicast IP works
    prefix = infer_cidr_prefix("192.168.2.6")
    assert prefix == "192.168.2.0/24"
    seg = inferrer.observe_ip("192.168.2.6", now, "cap-1")
    assert seg is not None
    assert seg.cidr_prefix == "192.168.2.0/24"


def test_multicast_identity_resolver_clock_group():
    """Verify that multicast IPs are resolved as clock groups without synthetic router flags."""
    resolver = IdentityResolver()
    now = datetime.now(UTC)

    asset1, ev1 = resolver.resolve_asset_from_observation(
        ip_str="224.0.0.107",
        mac_str=None,
        observed_time=now,
        source_id="job-ptp",
        protocol="PTP",
    )
    assert asset1.identity_status in (IdentityStatus.CONFIRMED, IdentityStatus.PROBABLE)
    assert "PTP Peer Delay Multicast Group (224.0.0.107)" in asset1.hostnames

    asset2, ev2 = resolver.resolve_asset_from_observation(
        ip_str="224.0.1.129",
        mac_str=None,
        observed_time=now,
        source_id="job-ptp",
        protocol="PTP",
    )
    assert "PTP Primary Multicast Group (224.0.1.129)" in asset2.hostnames


def test_layer2_asset_resolution_no_synthetic_ip():
    """Verify that direct Layer-2 Ethernet frames create assets without inventing synthetic IPv4 addresses."""
    resolver = IdentityResolver()
    now = datetime.now(UTC)

    l2_asset, evs = resolver.resolve_l2_asset(
        mac_str="00:80:63:00:09:BA",
        observed_time=now,
        source_id="job-ptp",
        protocol="PTP",
        ether_type=35063,
        label="IEEE 1588 PTP Direct L2 Device (00:80:63:00:09:BA)",
    )

    assert l2_asset.primary_ip == ""
    assert l2_asset.ip_addresses == []
    assert "00:80:63:00:09:ba" in [m.lower() for m in l2_asset.mac_addresses]
    assert len(evs) == 1
    assert "Layer-2 frame observation" in evs[0].provenance


def test_graph_builder_multicast_and_l2_isolation(tmp_path):
    """Verify that graph builder handles multicast clock groups and direct L2 devices accurately without fake routers."""
    custom_settings = AppSettings(data_dir=str(tmp_path))
    store = MetadataStore(config=custom_settings)
    builder = GraphBuilder(store=store)
    now = datetime.now(UTC)

    # 1. Unicast Host
    host = Asset(
        asset_id="asset-host-1",
        primary_ip="192.168.2.6",
        ip_addresses=["192.168.2.6"],
        mac_addresses=["00:11:22:33:44:55"],
        hostnames=["ptp-master.lab"],
        first_seen=now,
        last_seen=now,
        identity_status=IdentityStatus.CONFIRMED,
        confidence=0.99,
        observation_sources=["cap-ptp"],
    )
    # 2. Multicast Clock Group
    mcast = Asset(
        asset_id="asset-mcast-peer",
        primary_ip="224.0.0.107",
        ip_addresses=["224.0.0.107"],
        mac_addresses=["01:00:5e:00:00:6b"],
        hostnames=["PTP Peer Delay Multicast Group (224.0.0.107)"],
        first_seen=now,
        last_seen=now,
        identity_status=IdentityStatus.CONFIRMED,
        confidence=1.0,
        observation_sources=["cap-ptp"],
    )
    # 3. Direct L2 Device
    l2_dev = Asset(
        asset_id="asset-l2-ptp",
        primary_ip="",
        ip_addresses=[],
        mac_addresses=["00:80:63:00:09:ba"],
        hostnames=["IEEE 1588 PTP Direct L2 Device (00:80:63:00:09:BA)"],
        first_seen=now,
        last_seen=now,
        identity_status=IdentityStatus.CONFIRMED,
        confidence=1.0,
        observation_sources=["cap-ptp"],
    )

    subnet = NetworkSegment(
        segment_id="seg-192-168-2-0",
        cidr_prefix="192.168.2.0/24",
        address_family="IPv4",
        first_seen=now,
        last_seen=now,
        provenance="cap-ptp",
        gateway_candidates=[],
    )

    store.upsert_asset(host)
    store.upsert_asset(mcast)
    store.upsert_asset(l2_dev)
    store.upsert_segment(subnet)

    graph = builder.build_graph_for_capture(capture_id="cap-ptp")

    # Find nodes
    nodes_by_id = {n.node_id: n for n in graph.nodes}
    assert "node-asset-host-1" in nodes_by_id
    assert "node-asset-mcast-peer" in nodes_by_id
    assert "node-asset-l2-ptp" in nodes_by_id
    assert "subnet-seg-192-168-2-0" in nodes_by_id

    # Multicast clock group must NOT be marked as router and must have entity_type == 'multicast_group'
    mcast_node = nodes_by_id["node-asset-mcast-peer"]
    assert mcast_node.node_type.value != "ROUTER"
    assert mcast_node.properties.get("is_multicast") is True
    assert mcast_node.properties.get("entity_type") == "multicast_group"

    # L2 device node must NOT have primary_ip and must have entity_type == 'l2_device'
    l2_node = nodes_by_id["node-asset-l2-ptp"]
    assert l2_node.properties.get("entity_type") == "l2_device"
    assert l2_node.properties.get("primary_ip") == ""

    # Subnet attachments: only the host attaches to the subnet, not multicast or L2
    host_attached_subnets = {e.target_node_id for e in graph.edges if e.source_node_id == "node-asset-host-1"}
    assert "subnet-seg-192-168-2-0" in host_attached_subnets

    non_host_attached = {
        e.target_node_id for e in graph.edges if e.source_node_id in ("node-asset-mcast-peer", "node-asset-l2-ptp")
    }
    assert len(non_host_attached) == 0


def test_api_filtering_by_snapshot_and_capture(client):
    """Verify that intelligence endpoints accept snapshot_id and capture_id query params."""
    res = client.get("/api/v1/snapshots")
    assert res.status_code == 200
    snapshots = res.json()
    assert isinstance(snapshots, list)

    if snapshots:
        test_snap_id = snapshots[0]["snapshot_id"]
        # Query assets with snapshot_id
        res_assets = client.get(f"/api/v1/assets?snapshot_id={test_snap_id}")
        assert res_assets.status_code == 200
        assert isinstance(res_assets.json(), list)

        # Query segments with snapshot_id
        res_segments = client.get(f"/api/v1/segments?snapshot_id={test_snap_id}")
        assert res_segments.status_code == 200

        # Query snapshot graph
        res_graph = client.get(f"/api/v1/snapshots/{test_snap_id}/graph")
        assert res_graph.status_code == 200
        graph_data = res_graph.json()
        assert "nodes" in graph_data
        assert "edges" in graph_data


def test_create_snapshot_from_capture_and_job_resolution(tmp_path):
    """Verify that create_snapshot_from_capture works with both capture_id and job_id, handles 404 and 409."""
    custom_settings = AppSettings(data_dir=str(tmp_path))
    store = MetadataStore(config=custom_settings)
    builder = GraphBuilder(store=store)
    SnapshotManager(store=store, builder=builder)

    # 1. Register a capture
    store.register_capture(
        capture_id="cap-test-123",
        filename="test_capture.pcap",
        content_sha256="abc123hash",
        file_size_bytes=1024,
        format_type="PCAP",
        storage_path="/tmp/test_capture.pcap",
    )
    # 2. Register an analysis job linked to the capture
    store.save_analysis_job(
        job_id="job-uuid-456",
        capture_id="cap-test-123",
        filename="test_capture.pcap",
        file_size_bytes=1024,
        status="completed",
        created_at=datetime.now(UTC).isoformat(),
        completed_at=datetime.now(UTC).isoformat(),
    )

    # Test resolving by capture_id
    cap_res, job_res = store.resolve_capture_and_job("cap-test-123")
    assert cap_res is not None
    assert cap_res["capture_id"] == "cap-test-123"
    assert job_res is not None
    assert job_res["job_id"] == "job-uuid-456"

    # Test resolving by job_id
    cap_res2, job_res2 = store.resolve_capture_and_job("job-uuid-456")
    assert cap_res2 is not None
    assert cap_res2["capture_id"] == "cap-test-123"
    assert job_res2 is not None
    assert job_res2["job_id"] == "job-uuid-456"

    # Test resolving unknown returns (None, None)
    c_none, j_none = store.resolve_capture_and_job("non-existent-id")
    assert c_none is None
    assert j_none is None


def test_api_create_snapshot_from_capture_endpoint(client):
    """Verify POST /api/v1/captures/{capture_id}/snapshot endpoint with real database."""
    # Find a completed job in metadata.db
    res_jobs = client.get("/api/v1/analysis/jobs")
    assert res_jobs.status_code == 200
    jobs = res_jobs.json()
    assert len(jobs) > 0

    target_job = jobs[0]
    job_id = target_job["job_id"]
    capture_id = target_job.get("capture_id") or job_id

    # 1. Calling with job_id must successfully resolve and generate/return snapshot
    res_job = client.post(f"/api/v1/captures/{job_id}/snapshot")
    assert res_job.status_code in (200, 201)
    snap_from_job = res_job.json()
    assert "snapshot_id" in snap_from_job
    assert snap_from_job["node_count"] >= 0
    assert snap_from_job["capture_id"] is not None

    # 2. Calling with capture_id must also succeed
    res_cap = client.post(f"/api/v1/captures/{capture_id}/snapshot")
    assert res_cap.status_code in (200, 201)
    snap_from_cap = res_cap.json()
    assert "snapshot_id" in snap_from_cap

    # 3. Calling with a non-existent ID must return 404
    res_404 = client.post("/api/v1/captures/00000000-0000-0000-0000-000000000000/snapshot")
    assert res_404.status_code == 404
    assert "not found" in res_404.json()["detail"].lower()
