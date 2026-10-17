"""End-to-End Integration Test for Phase 03: Executable Network Digital Twin & Verification."""

from datetime import UTC, datetime

import pytest
from httpx import ASGITransport, AsyncClient
from network_twin.config import AppSettings
from network_twin.main import create_app
from network_twin.models.intelligence import (
    Asset,
    EvidenceRecord,
    EvidenceType,
    IdentityStatus,
    NetworkSegment,
    NetworkService,
)
from network_twin.simulation.models import SimulationActionType
from network_twin.storage.metadata_store import MetadataStore
from network_twin.topology.graph_builder import GraphBuilder
from network_twin.topology.snapshot_manager import SnapshotManager


@pytest.fixture
def test_app(tmp_path):
    settings = AppSettings(
        environment="testing",
        debug=True,
        data_dir=str(tmp_path),
    )
    app = create_app(settings)
    store = MetadataStore(settings)
    app.state.metadata_store = store

    now = datetime.now(UTC)
    # Seed an auditable Phase 02 topology snapshot
    ev1 = EvidenceRecord(
        evidence_id="ev-p3-01",
        evidence_type=EvidenceType.PACKET_OBSERVED,
        source_type="pcap",
        source_artifact_id="capture-phase03.pcap",
        observation_timestamp=now,
        ingestion_timestamp=now,
        confidence=1.0,
        provenance="capture-phase03.pcap:1",
        details={"src_ip": "10.0.1.100", "dst_ip": "10.0.2.200"},
    )
    store.save_evidence_records([ev1])

    asset1 = Asset(
        asset_id="asset-web-100",
        primary_ip="10.0.1.100",
        ip_addresses=["10.0.1.100"],
        mac_addresses=["00:11:22:33:44:01"],
        hostnames=["web.corp.local"],
        observed_protocols=["TCP", "TLS"],
        observed_services=["443/TCP"],
        first_seen=now,
        last_seen=now,
        identity_status=IdentityStatus.CONFIRMED,
        confidence=1.0,
        conflicts=[],
        observation_sources=["capture-phase03.pcap"],
    )
    asset2 = Asset(
        asset_id="asset-db-200",
        primary_ip="10.0.2.200",
        ip_addresses=["10.0.2.200"],
        mac_addresses=["00:11:22:33:44:02"],
        hostnames=["db.corp.local"],
        observed_protocols=["TCP"],
        observed_services=["5432/TCP"],
        first_seen=now,
        last_seen=now,
        identity_status=IdentityStatus.CONFIRMED,
        confidence=1.0,
        conflicts=[],
        observation_sources=["capture-phase03.pcap"],
    )
    store.upsert_asset(asset1)
    store.upsert_asset(asset2)

    seg1 = NetworkSegment(
        segment_id="seg-10-0-1-0-24",
        cidr_prefix="10.0.1.0/24",
        address_family="IPv4",
        gateway_ip="10.0.1.1",
        observed_host_count=1,
        confidence=0.9,
        provenance="inferred",
        first_seen=now,
        last_seen=now,
    )
    seg2 = NetworkSegment(
        segment_id="seg-10-0-2-0-24",
        cidr_prefix="10.0.2.0/24",
        address_family="IPv4",
        gateway_ip="10.0.2.1",
        observed_host_count=1,
        confidence=0.9,
        provenance="inferred",
        first_seen=now,
        last_seen=now,
    )
    store.upsert_segment(seg1)
    store.upsert_segment(seg2)

    srv = NetworkService(
        service_id="srv-web-443",
        asset_id="asset-web-100",
        server_ip="10.0.1.100",
        port=443,
        transport_protocol="TCP",
        app_protocol="HTTPS",
        classification_confidence=1.0,
        first_seen=now,
        last_seen=now,
    )
    store.upsert_service(srv)

    # Build snapshot
    builder = GraphBuilder(store)
    mgr = SnapshotManager(store, builder)
    snap, _ = mgr.create_snapshot("Phase03-Baseline-Snapshot")

    return app, store, snap


@pytest.mark.asyncio
async def test_phase03_end_to_end_workflow(test_app):
    app, _store, snap = test_app
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Build Network Model from Snapshot
        build_payload = {
            "snapshot_id": snap.snapshot_id,
            "name": "E2E Operational Model",
            "custom_routes": [
                {
                    "node_id": "asset-web-100",
                    "destination_prefix": "10.0.2.0/24",
                    "next_hop_ip": "10.0.1.1",
                    "metric": 1,
                }
            ],
            "custom_acls": [
                {
                    "node_id": "asset-web-100",
                    "name": "Host Filter",
                    "default_policy": "DEFAULT_ALLOW",
                    "rules": [
                        {
                            "action": "PERMIT",
                            "direction": "INGRESS",
                            "protocol": "TCP",
                            "destination_port": 443,
                        }
                    ],
                }
            ],
        }

        build_resp = await client.post("/api/v1/models/build", json=build_payload)
        assert build_resp.status_code == 200
        model_data = build_resp.json()
        model_id = model_data["model_id"]
        assert model_id.startswith("model-")
        assert model_data["fingerprint"] != ""
        base_fingerprint = model_data["fingerprint"]

        # 2. Inspect Model & Limitations
        model_get_resp = await client.get(f"/api/v1/models/{model_id}")
        assert model_get_resp.status_code == 200
        assert len(model_get_resp.json()["nodes"]) >= 2

        limits_resp = await client.get(f"/api/v1/models/{model_id}/limitations")
        assert limits_resp.status_code == 200
        assert isinstance(limits_resp.json(), list)

        # 3. Query Reachability
        reach_query = {
            "model_id": model_id,
            "source_ip": "10.0.1.100",
            "destination_ip": "10.0.1.100",  # Local delivery
            "protocol": "TCP",
            "destination_port": 443,
        }
        reach_resp = await client.post("/api/v1/simulations/reachability", json=reach_query)
        assert reach_resp.status_code == 200
        reach_data = reach_resp.json()
        assert reach_data["status"] == "REACHABLE"
        assert reach_data["reason_code"] == "REACHABLE"

        # 4. Run Invariant Verification
        ver_resp = await client.post("/api/v1/verification/run", json={"model_id": model_id})
        assert ver_resp.status_code == 200
        ver_results = ver_resp.json()
        assert len(ver_results) >= 1
        assert any(r["reason_code"] == "CONFIGURATIONS_CONSISTENT" for r in ver_results)

        # 5. Create Counterfactual Scenario (Block port 443)
        scenario_payload = {
            "scenario_id": "scen-e2e-block-443",
            "name": "E2E Emergency Lockdown",
            "description": "Block all incoming HTTPS traffic",
            "base_model_id": model_id,
            "actions": [
                {
                    "action_type": SimulationActionType.ADD_FIREWALL_RULE.value,
                    "target_node_id": "asset-web-100",
                    "parameters": {
                        "rule_id": "rule-drop-443",
                        "action": "DENY",
                        "direction": "INGRESS",
                        "protocol": "TCP",
                        "destination_port": 443,
                        "position": 0,
                    },
                }
            ],
        }
        create_scen_resp = await client.post("/api/v1/simulations/scenarios", json=scenario_payload)
        assert create_scen_resp.status_code == 200

        # 6. Run Counterfactual Scenario
        run_resp = await client.post("/api/v1/simulations/scenarios/scen-e2e-block-443/run")
        assert run_resp.status_code == 200
        cf_result = run_resp.json()

        assert cf_result["baseline_fingerprint"] == base_fingerprint
        assert cf_result["counterfactual_fingerprint"] != base_fingerprint
        assert cf_result["applied_actions_count"] == 1
        assert "Scenario 'E2E Emergency Lockdown' applied 1 action(s)" in cf_result["summary_explanation"]

        # 7. Confirm Baseline Model Immuntability
        final_model_resp = await client.get(f"/api/v1/models/{model_id}")
        assert final_model_resp.status_code == 200
        assert final_model_resp.json()["fingerprint"] == base_fingerprint
