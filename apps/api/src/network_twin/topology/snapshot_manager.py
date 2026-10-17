"""Manages immutable versioned topology snapshots and differential comparisons."""

import hashlib
import logging
from datetime import UTC, datetime
from typing import Any

from network_twin.models.intelligence import (
    SnapshotComparisonDiff,
    TopologyGraph,
    TopologySnapshot,
)
from network_twin.storage.metadata_store import MetadataStore, metadata_store
from network_twin.topology.graph_builder import GraphBuilder, graph_builder

logger = logging.getLogger(__name__)


class SnapshotManager:
    """Creates reproducible network snapshots and evaluates structural/evidence differences."""

    def __init__(self, store: MetadataStore = metadata_store, builder: GraphBuilder = graph_builder):
        self.store = store
        self.builder = builder

    def create_snapshot(
        self,
        name: str,
        source_captures: list[str] | None = None,
        source_configs: list[str] | None = None,
    ) -> tuple[TopologySnapshot, TopologyGraph]:
        """Constructs an immutable topology snapshot from active state."""
        graph = self.builder.build_current_graph()
        captures = source_captures or [c["capture_id"] for c in self.store.list_captures()]
        configs = source_configs or [cfg.import_id for cfg in self.store.list_config_imports()]

        # Collect unresolved conflicts
        conflicts: list[str] = []
        for n in graph.nodes:
            node_conflicts = n.properties.get("conflicts", [])
            for c in node_conflicts:
                conflicts.append(f"{n.label}: {c}")

        # Deterministic snapshot ID based on graph state
        hasher = hashlib.sha256()
        hasher.update(name.encode())
        for n in sorted(graph.nodes, key=lambda x: x.node_id):
            hasher.update(f"{n.node_id}:{n.node_type}:{n.label}".encode())
        for e in sorted(graph.edges, key=lambda x: x.edge_id):
            hasher.update(f"{e.edge_id}:{e.source_node_id}->{e.target_node_id}:{e.edge_type}".encode())

        snapshot_id = f"snap-{hasher.hexdigest()[:16]}"
        now = datetime.now(UTC)

        snapshot = TopologySnapshot(
            snapshot_id=snapshot_id,
            name=name,
            created_at=now,
            source_captures=captures,
            source_configs=configs,
            identity_policy_version="1.0.0",
            graph_algorithm_version="1.0.0",
            node_count=graph.node_count,
            edge_count=graph.edge_count,
            unresolved_conflicts=conflicts,
            schema_version="1.0.0",
            metadata={"generator": "snapshot_manager", "timestamp": now.isoformat()},
        )

        self.store.save_snapshot(snapshot, graph)
        logger.info(
            "Created and persisted topology snapshot %s with %d nodes and %d edges",
            snapshot_id,
            graph.node_count,
            graph.edge_count,
        )
        return snapshot, graph

    def compare_snapshots(self, base_snapshot_id: str, target_snapshot_id: str) -> SnapshotComparisonDiff:
        """Computes differential analysis between two topology snapshots."""
        base_graph = self.store.get_snapshot_graph(base_snapshot_id)
        if not base_graph:
            raise KeyError(f"Base snapshot '{base_snapshot_id}' not found.")

        target_graph = self.store.get_snapshot_graph(target_snapshot_id)
        if not target_graph:
            raise KeyError(f"Target snapshot '{target_snapshot_id}' not found.")

        base_nodes = {n.node_id: n for n in base_graph.nodes}
        target_nodes = {n.node_id: n for n in target_graph.nodes}

        base_edges = {e.edge_id: e for e in base_graph.edges}
        target_edges = {e.edge_id: e for e in target_graph.edges}

        # Node differences
        added_nodes = [target_nodes[nid] for nid in target_nodes if nid not in base_nodes]
        removed_nodes = [base_nodes[nid] for nid in base_nodes if nid not in target_nodes]
        modified_nodes: list[dict[str, Any]] = []

        for nid in target_nodes:
            if nid in base_nodes:
                b_node = base_nodes[nid]
                t_node = target_nodes[nid]
                diffs: dict[str, Any] = {}
                if b_node.label != t_node.label:
                    diffs["label"] = {"from": b_node.label, "to": t_node.label}
                if b_node.node_type != t_node.node_type:
                    diffs["node_type"] = {"from": b_node.node_type, "to": t_node.node_type}
                if diffs:
                    modified_nodes.append({"node_id": nid, "changes": diffs})

        # Edge differences
        added_edges = [target_edges[eid] for eid in target_edges if eid not in base_edges]
        removed_edges = [base_edges[eid] for eid in base_edges if eid not in target_edges]
        modified_edges: list[dict[str, Any]] = []

        for eid in target_edges:
            if eid in base_edges:
                b_edge = base_edges[eid]
                t_edge = target_edges[eid]
                diffs: dict[str, Any] = {}
                if b_edge.packet_count != t_edge.packet_count:
                    diffs["packet_count"] = {"from": b_edge.packet_count, "to": t_edge.packet_count}
                if b_edge.byte_count != t_edge.byte_count:
                    diffs["byte_count"] = {"from": b_edge.byte_count, "to": t_edge.byte_count}
                if diffs:
                    modified_edges.append({"edge_id": eid, "changes": diffs})

        # Evidence explanations
        explanations: list[dict[str, Any]] = []
        for edge in added_edges:
            if edge.evidence_class.value == "DIRECT_OBSERVATION":
                desc = f"Newly observed communication ({edge.primary_protocol}) between {edge.source_node_id} and {edge.target_node_id} ({edge.packet_count} packets)"
            elif edge.evidence_class.value == "CONFIGURED":
                desc = f"New configured route imported between {edge.source_node_id} and {edge.target_node_id}"
            else:
                desc = f"Inferred relationship established: {edge.edge_type.value}"

            explanations.append(
                {
                    "type": "added_relationship",
                    "edge_id": edge.edge_id,
                    "evidence_class": edge.evidence_class.value,
                    "explanation": desc,
                    "evidence_ids": edge.evidence_ids,
                }
            )

        for node in added_nodes:
            explanations.append(
                {
                    "type": "added_entity",
                    "node_id": node.node_id,
                    "explanation": f"Newly discovered {node.node_type.value}: {node.label}",
                }
            )

        return SnapshotComparisonDiff(
            base_snapshot_id=base_snapshot_id,
            target_snapshot_id=target_snapshot_id,
            added_nodes=added_nodes,
            removed_nodes=removed_nodes,
            modified_nodes=modified_nodes,
            added_edges=added_edges,
            removed_edges=removed_edges,
            modified_edges=modified_edges,
            evidence_explanations=explanations,
        )


snapshot_manager = SnapshotManager()
