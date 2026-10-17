"""Unit tests for configuration importers (Routing, Neighbor, and Inventory tables)."""

import json

import pytest

from network_twin.importers.config_framework import (
    ConfigurationImportError,
    DeviceInventoryImporter,
    NeighborTableImporter,
    RoutingTableImporter,
    get_importer,
)
from network_twin.models.intelligence import EvidenceClassification, TopologyEdgeType


def test_routing_table_importer_json():
    routes_json = json.dumps([
        {"destination": "10.0.0.0/24", "next_hop": "192.168.1.1", "interface": "eth0", "metric": "10"},
        {"destination": "172.16.0.0/16", "next_hop": "192.168.1.254", "interface": "eth1", "metric": "20"},
    ])

    importer = RoutingTableImporter("core-router-01")
    result, evidence_list, nodes, edges = importer.parse(routes_json)

    assert result.status == "completed"
    assert result.items_imported == 2
    assert len(evidence_list) == 2
    assert len(edges) == 2
    assert edges[0].edge_type == TopologyEdgeType.CONFIGURED_ROUTE
    assert edges[0].evidence_class == EvidenceClassification.CONFIGURED


def test_routing_table_importer_csv():
    routes_csv = """destination,gateway,interface,metric
192.168.100.0/24,192.168.1.1,eth0,10
default,192.168.1.254,eth0,100
"""
    importer = RoutingTableImporter("edge-router-02")
    result, _, _, edges = importer.parse(routes_csv)

    assert result.status == "completed"
    assert result.items_imported == 2
    assert len(edges) == 2


def test_neighbor_table_importer():
    arp_json = json.dumps([
        {"ip": "192.168.1.50", "mac": "00:50:56:c0:00:01", "interface": "eth0"},
        {"ip": "192.168.1.60", "mac": "00:50:56:c0:00:02", "interface": "eth0"},
    ])

    importer = NeighborTableImporter("switch-agg-01")
    result, evs, nodes, _ = importer.parse(arp_json)

    assert result.status == "completed"
    assert result.items_imported == 2
    assert len(evs) == 2
    assert len(nodes) == 2


def test_device_inventory_importer():
    inv_csv = """hostname,primary_ip,mac,role
db-master.twin.internal,192.168.1.80,00:11:22:33:44:80,database
fw-edge.twin.internal,192.168.1.1,00:11:22:33:44:01,firewall
"""
    importer = DeviceInventoryImporter("cmdb-export")
    result, _, nodes, _ = importer.parse(inv_csv)

    assert result.status == "completed"
    assert result.items_imported == 2
    assert nodes[1].node_type.value == "ROUTER"  # firewall mapped to ROUTER type


def test_importer_factory_unsupported():
    with pytest.raises(ConfigurationImportError):
        get_importer("unknown_format", "src")
