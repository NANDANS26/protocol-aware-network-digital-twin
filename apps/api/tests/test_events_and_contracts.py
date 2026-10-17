"""Tests for structured event contracts and JSON Schema validation."""

from uuid import uuid4

import jsonschema
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_get_event_schema(client: AsyncClient):
    response = await client.get("/api/v1/events/schema")
    assert response.status_code == 200
    schema = response.json()
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["title"] == "NetworkEvent"

    # Verify that it is a valid Draft 2020-12 schema
    jsonschema.Draft202012Validator.check_schema(schema)


@pytest.mark.asyncio
async def test_validate_valid_event(client: AsyncClient):
    event_payload = {
        "schema_version": "1.0.0",
        "event_id": str(uuid4()),
        "timestamp_ns": 1729153800123456789,
        "timestamp_iso": "2026-10-17T08:30:00.123456789Z",
        "source_id": "sensor-edge-01",
        "flow_id": "sha256-abc123flow",
        "flow_direction": "forward",
        "link_layer": {
            "source_mac": "00:1A:2B:3C:4D:5E",
            "destination_mac": "00:1A:2B:3C:4D:5F",
            "ether_type": 2048,
            "vlan_id": 100,
        },
        "network_layer": {
            "version": "IPv4",
            "source_ip": "192.168.1.10",
            "destination_ip": "10.0.0.50",
            "ttl_or_hop_limit": 64,
            "identification": 42000,
            "flags": {"df": True, "mf": False},
        },
        "transport_layer": {
            "protocol": "TCP",
            "source_port": 54321,
            "destination_port": 443,
            "tcp_sequence_number": 1000200,
            "tcp_acknowledgment_number": 0,
            "tcp_flags": {"syn": True, "ack": False},
            "window_size": 65535,
        },
        "application_layer": {
            "protocol": "TLS",
            "payload_length_bytes": 128,
            "protocol_metadata": {"tls_sni": "api.internal.network"},
            "payload_hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "sanitized_preview": "TLS ClientHello SNI: api.internal.network",
        },
        "parser_status": {
            "status": "ok",
            "diagnostic_code": None,
            "diagnostic_message": None,
            "bytes_consumed": 182,
            "bytes_remaining": 0,
        },
        "provenance": {
            "packet_index": 42,
            "wire_length_bytes": 182,
            "capture_length_bytes": 182,
            "capture_interface": "eth0",
            "capture_file_path": "/captures/demo.pcap",
        },
    }

    response = await client.post("/api/v1/events/validate", json=event_payload)
    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is True
    assert data["event_id"] == event_payload["event_id"]
    assert data["parser_status"] == "ok"


@pytest.mark.asyncio
async def test_validate_event_with_invalid_mac(client: AsyncClient):
    event_payload = {
        "schema_version": "1.0.0",
        "event_id": str(uuid4()),
        "timestamp_ns": 1729153800000000000,
        "timestamp_iso": "2026-10-17T08:30:00Z",
        "source_id": "sensor-01",
        "link_layer": {
            "source_mac": "INVALID-MAC-FORMAT",
        },
        "parser_status": {"status": "ok"},
        "provenance": {
            "packet_index": 1,
            "wire_length_bytes": 64,
            "capture_length_bytes": 64,
        },
    }

    response = await client.post("/api/v1/events/validate", json=event_payload)
    assert response.status_code == 422
    data = response.json()
    assert data["error"] == "ValidationError"
