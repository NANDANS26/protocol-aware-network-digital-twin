"""Network Intelligence, Topology, Evidence, and Analytical Query Endpoints."""

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from network_twin.config import settings
from network_twin.importers.config_framework import ConfigurationImportError, get_importer
from network_twin.models.intelligence import (
    Asset,
    CommunicationRelationship,
    ConfigImportRequest,
    ConfigImportResult,
    EvidenceRecord,
    NetworkSegment,
    NetworkService,
    SnapshotComparisonDiff,
    TopologyGraph,
    TopologySnapshot,
)
from network_twin.storage.analytics_store import AnalyticsStore
from network_twin.storage.metadata_store import MetadataStore
from network_twin.topology.graph_builder import GraphBuilder
from network_twin.topology.snapshot_manager import SnapshotManager

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Network Intelligence & Topology"])


def get_metadata_store(request: Request) -> MetadataStore:
    if hasattr(request.app.state, "analysis_service"):
        return request.app.state.analysis_service.metadata_store
    if hasattr(request.app.state, "metadata_store"):
        return request.app.state.metadata_store
    config = getattr(request.app.state, "config", settings)
    store = MetadataStore(config)
    request.app.state.metadata_store = store
    return store


def get_graph_builder(
    request: Request,
    store: MetadataStore = Depends(get_metadata_store),
) -> GraphBuilder:
    return GraphBuilder(store)


def get_snapshot_manager(
    request: Request,
    store: MetadataStore = Depends(get_metadata_store),
    builder: GraphBuilder = Depends(get_graph_builder),
) -> SnapshotManager:
    return SnapshotManager(store, builder)


def get_analytics_store(request: Request) -> AnalyticsStore:
    if hasattr(request.app.state, "analysis_service"):
        return request.app.state.analysis_service.analytics_store
    if hasattr(request.app.state, "analytics_store"):
        return request.app.state.analytics_store
    config = getattr(request.app.state, "config", settings)
    store = AnalyticsStore(config)
    request.app.state.analytics_store = store
    return store


class CreateSnapshotRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    source_captures: list[str] | None = None
    source_configs: list[str] | None = None
    source_job_id: str | None = None


class CompareSnapshotsRequest(BaseModel):
    base_snapshot_id: str
    target_snapshot_id: str


# --- Captures ---


@router.get("/captures", response_model=list[dict[str, Any]])
async def list_captures(store: MetadataStore = Depends(get_metadata_store)):
    """Returns all registered capture files with SHA-256 fingerprints."""
    raw = store.list_captures()
    normalized = []
    for r in raw:
        item = dict(r)
        if "content_sha256" in item and "sha256_hash" not in item:
            item["sha256_hash"] = item["content_sha256"]
        if "filename" in item and "file_name" not in item:
            item["file_name"] = item["filename"]
        if "file_size_bytes" in item and "packet_count" not in item:
            # Provide safe default if packet_count not recorded
            item["packet_count"] = item.get("packet_count", 0)
        normalized.append(item)
    return normalized


@router.get("/captures/{capture_id}", response_model=dict[str, Any])
async def get_capture(capture_id: str, store: MetadataStore = Depends(get_metadata_store)):
    cap = store.get_capture(capture_id)
    if not cap:
        raise HTTPException(status_code=404, detail=f"Capture '{capture_id}' not found.")
    item = dict(cap)
    if "content_sha256" in item and "sha256_hash" not in item:
        item["sha256_hash"] = item["content_sha256"]
    if "filename" in item and "file_name" not in item:
        item["file_name"] = item["filename"]
    return item


@router.get("/captures/{capture_id}/runs", response_model=list[dict[str, Any]])
async def list_capture_runs(capture_id: str, store: MetadataStore = Depends(get_metadata_store)):
    """Retrieves all analysis runs executed for this capture with reconciliation reports."""
    cap = store.get_capture(capture_id)
    if not cap:
        raise HTTPException(status_code=404, detail=f"Capture '{capture_id}' not found.")
    return store.get_analysis_runs_for_capture(cap["capture_id"])


@router.get("/captures/{capture_id}/active-context", response_model=dict[str, Any])
async def get_capture_active_context(capture_id: str, store: MetadataStore = Depends(get_metadata_store)):
    """Retrieves authoritative active context metadata for a capture."""
    cap = store.get_capture(capture_id)
    if not cap:
        raise HTTPException(status_code=404, detail=f"Capture '{capture_id}' not found.")
    canonical_id = cap["capture_id"]
    active_run = store.get_active_analysis_run(canonical_id)
    snapshots = store.list_snapshots(capture_id=canonical_id)
    latest_snapshot = snapshots[0] if snapshots else None

    return {
        "capture_id": canonical_id,
        "filename": cap.get("filename"),
        "content_sha256": cap.get("content_sha256"),
        "lifecycle_status": cap.get("lifecycle_status", "COMPLETE"),
        "active_analysis_run_id": active_run.get("job_id") if active_run else cap.get("active_analysis_run_id"),
        "latest_run": active_run,
        "packet_count": cap.get("packet_count", 0),
        "event_count": cap.get("event_count", 0),
        "accepted_count": cap.get("accepted_count", 0),
        "rejected_count": cap.get("rejected_count", 0),
        "unsupported_count": cap.get("unsupported_count", 0),
        "engine_version": cap.get("engine_version", "1.0.0"),
        "pipeline_version": cap.get("pipeline_version", "1.0.0"),
        "schema_version": cap.get("schema_version", "1.0.0"),
        "latest_snapshot_id": latest_snapshot.snapshot_id if latest_snapshot else None,
        "snapshots_count": len(snapshots),
    }


# --- Assets ---


@router.get("/assets", response_model=list[Asset])
async def list_assets(
    q: str | None = Query(default=None, description="Search query for IP, MAC, or hostname"),
    status: str | None = Query(default=None, description="Identity status filter: CONFIRMED, PROBABLE, etc."),
    snapshot_id: str | None = Query(default=None, description="Filter assets belonging to specific snapshot"),
    capture_id: str | None = Query(default=None, description="Filter assets observed in specific capture or job"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    store: MetadataStore = Depends(get_metadata_store),
):
    """Lists observed and configured network assets with identity resolution status."""
    return store.list_assets(
        ip_query=q,
        identity_status=status,
        limit=limit,
        offset=offset,
        source_id=capture_id,
        snapshot_id=snapshot_id,
    )


@router.get("/assets/{asset_id}", response_model=Asset)
async def get_asset(asset_id: str, store: MetadataStore = Depends(get_metadata_store)):
    asset = store.get_asset(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found.")
    return asset


@router.get("/assets/{asset_id}/relationships", response_model=list[CommunicationRelationship])
async def get_asset_relationships(asset_id: str, limit: int = 100, store: MetadataStore = Depends(get_metadata_store)):
    return store.list_relationships(asset_id=asset_id, limit=limit)


# --- Network Segments & Services ---


@router.get("/segments", response_model=list[NetworkSegment])
async def list_segments(
    snapshot_id: str | None = Query(default=None, description="Filter segments by snapshot"),
    capture_id: str | None = Query(default=None, description="Filter segments by capture or job"),
    store: MetadataStore = Depends(get_metadata_store),
):
    """Lists inferred and configured IP subnets."""
    return store.list_segments(source_id=capture_id, snapshot_id=snapshot_id)


@router.get("/services", response_model=list[NetworkService])
async def list_services(
    asset_id: str | None = None,
    snapshot_id: str | None = Query(default=None, description="Filter services by snapshot"),
    store: MetadataStore = Depends(get_metadata_store),
):
    """Lists discovered network services and application protocols."""
    return store.list_services(asset_id=asset_id, snapshot_id=snapshot_id)


# --- Communication Relationships ---


@router.get("/relationships", response_model=list[CommunicationRelationship])
async def list_relationships(
    asset_id: str | None = None,
    snapshot_id: str | None = Query(default=None, description="Filter relationships by snapshot"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    store: MetadataStore = Depends(get_metadata_store),
):
    """Lists observed bidirectional communication relationships."""
    return store.list_relationships(asset_id=asset_id, limit=limit, offset=offset, snapshot_id=snapshot_id)


# --- Evidence Records ---


@router.get("/evidence", response_model=list[EvidenceRecord])
async def list_evidence(
    source_artifact_id: str | None = None,
    evidence_type: str | None = None,
    snapshot_id: str | None = Query(default=None, description="Filter evidence by snapshot"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    store: MetadataStore = Depends(get_metadata_store),
):
    """Inspects auditable evidence records supporting graph relationships."""
    return store.list_evidence(
        source_artifact_id=source_artifact_id,
        evidence_type=evidence_type,
        limit=limit,
        offset=offset,
        snapshot_id=snapshot_id,
    )


@router.get("/evidence/{evidence_id}", response_model=EvidenceRecord)
async def get_evidence(evidence_id: str, store: MetadataStore = Depends(get_metadata_store)):
    ev = store.get_evidence(evidence_id)
    if not ev:
        raise HTTPException(status_code=404, detail=f"Evidence record '{evidence_id}' not found.")
    return ev


# --- Configuration Imports ---


@router.post("/imports", response_model=ConfigImportResult)
async def import_configuration(req: ConfigImportRequest, store: MetadataStore = Depends(get_metadata_store)):
    """Safely imports routing tables, neighbor tables, or device inventories."""
    try:
        importer = get_importer(req.format, req.source_name, req.content)
        result, evidence_list, nodes, edges = importer.parse(req.content)

        store.save_config_import(result)
        store.save_evidence_records(evidence_list)

        logger.info("Successfully imported %d items from %s", result.items_imported, req.source_name)
        return result
    except ConfigurationImportError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        logger.error("Configuration import failure: %s", e)
        raise HTTPException(status_code=500, detail=f"Failed to process configuration: {e}") from e


@router.get("/imports", response_model=list[ConfigImportResult])
async def list_imports(store: MetadataStore = Depends(get_metadata_store)):
    return store.list_config_imports()


@router.delete("/imports/{import_id}")
async def delete_import(import_id: str, store: MetadataStore = Depends(get_metadata_store)):
    """Deletes an imported configuration record from the metadata store."""
    deleted = store.delete_config_import(import_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Import record '{import_id}' not found.")
    return {"status": "DELETED", "import_id": import_id}


# --- Topology Graph ---


@router.get("/topology", response_model=TopologyGraph)
async def get_current_topology(
    capture_id: str | None = Query(default=None, description="Scope topology to specific capture"),
    snapshot_id: str | None = Query(default=None, description="Scope topology to specific snapshot"),
    builder: GraphBuilder = Depends(get_graph_builder),
    store: MetadataStore = Depends(get_metadata_store),
):
    """Constructs and returns the active network topology graph from stored evidence, optionally scoped."""
    if snapshot_id:
        snap = store.get_snapshot(snapshot_id)
        if snap and snap.source_captures:
            return builder.build_graph_for_capture(capture_id=snap.source_captures)
    if capture_id:
        return builder.build_graph_for_capture(capture_id=capture_id)
    return builder.build_current_graph()


# --- Versioned Snapshots ---


@router.post("/snapshots", response_model=TopologySnapshot)
async def create_snapshot(
    req: CreateSnapshotRequest,
    mgr: SnapshotManager = Depends(get_snapshot_manager),
):
    """Creates a reproducible, versioned topology snapshot."""
    snapshot, _ = mgr.create_snapshot(
        name=req.name,
        source_captures=req.source_captures,
        source_configs=req.source_configs,
        job_id=req.source_job_id,
    )
    return snapshot


@router.post("/snapshots/reconstruct", response_model=TopologySnapshot)
async def reconstruct_model_snapshot(
    req: CreateSnapshotRequest,
    mgr: SnapshotManager = Depends(get_snapshot_manager),
):
    """Explicitly reconstructs and persists an immutable versioned model snapshot from selected captures and configuration inputs."""
    snapshot, _ = mgr.create_snapshot(
        name=req.name,
        source_captures=req.source_captures,
        source_configs=req.source_configs,
        job_id=req.source_job_id,
    )
    return snapshot


@router.post("/captures/{capture_id}/snapshot", response_model=TopologySnapshot)
async def create_snapshot_from_capture(
    capture_id: str,
    store: MetadataStore = Depends(get_metadata_store),
    mgr: SnapshotManager = Depends(get_snapshot_manager),
):
    """Explicitly creates or recreates a Digital Twin snapshot directly from an analyzed capture or job."""
    cap, job = store.resolve_capture_and_job(capture_id)
    if not cap:
        raise HTTPException(
            status_code=404,
            detail=f"Capture or analysis job '{capture_id}' not found.",
        )

    canonical_capture_id = cap["capture_id"]
    job_id = job.get("job_id") if job else None

    # Check status of analysis job
    if job:
        job_status = job.get("status", "completed")
        if job_status in ("pending", "processing"):
            raise HTTPException(
                status_code=409,
                detail=f"Analysis for capture '{canonical_capture_id}' is still in progress (status: {job_status}). Please wait for analysis to complete.",
            )
        elif job_status == "failed":
            err_msg = job.get("error_message") or "Analysis engine encountered an error."
            raise HTTPException(
                status_code=400,
                detail=f"Analysis for capture '{canonical_capture_id}' failed: {err_msg}",
            )

    try:
        snapshot, _ = mgr.create_snapshot(
            name=f"Capture Ingestion: {cap.get('filename', canonical_capture_id)}",
            source_captures=[canonical_capture_id],
            job_id=job_id,
            capture_filename=cap.get("filename"),
        )
        return snapshot
    except Exception as e:
        logger.exception(
            "Unexpected error generating digital twin snapshot for capture %s: %s", canonical_capture_id, e
        )
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate digital twin snapshot: {str(e)}",
        ) from e


@router.get("/snapshots", response_model=list[TopologySnapshot])
async def list_snapshots(
    capture_id: str | None = Query(default=None, description="Filter snapshots derived from specific capture"),
    store: MetadataStore = Depends(get_metadata_store),
):
    """Lists all versioned topology snapshots, optionally scoped to a capture."""
    return store.list_snapshots(capture_id=capture_id)


@router.get("/snapshots/{snapshot_id}", response_model=TopologySnapshot)
async def get_snapshot(snapshot_id: str, store: MetadataStore = Depends(get_metadata_store)):
    snap = store.get_snapshot(snapshot_id)
    if not snap:
        raise HTTPException(status_code=404, detail=f"Snapshot '{snapshot_id}' not found.")
    return snap


@router.get("/snapshots/{snapshot_id}/graph", response_model=TopologyGraph)
async def get_snapshot_graph(snapshot_id: str, store: MetadataStore = Depends(get_metadata_store)):
    graph = store.get_snapshot_graph(snapshot_id)
    if not graph:
        raise HTTPException(status_code=404, detail=f"Graph for snapshot '{snapshot_id}' not found.")
    return graph


@router.post("/snapshots/compare", response_model=SnapshotComparisonDiff)
async def compare_snapshots(
    req: CompareSnapshotsRequest,
    mgr: SnapshotManager = Depends(get_snapshot_manager),
):
    """Computes differential analysis between two topology snapshots with evidence explanations."""
    try:
        return mgr.compare_snapshots(req.base_snapshot_id, req.target_snapshot_id)
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e


# --- Analytics (DuckDB + Parquet) ---


@router.get("/analytics/top-talkers")
async def get_top_talkers(
    job_id: str,
    limit: int = Query(default=10, ge=1, le=100),
    store: AnalyticsStore = Depends(get_analytics_store),
):
    """Runs analytical aggregation over Parquet data via DuckDB."""
    return store.query_top_talkers(job_id=job_id, limit=limit)


@router.get("/analytics/protocol-breakdown")
async def get_protocol_breakdown(
    job_id: str,
    store: AnalyticsStore = Depends(get_analytics_store),
):
    """Runs analytical protocol breakdown over Parquet data via DuckDB."""
    return store.query_protocol_breakdown(job_id=job_id)


@router.get("/analytics/events")
async def query_parquet_events(
    job_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    protocol: str | None = None,
    ip: str | None = None,
    store: AnalyticsStore = Depends(get_analytics_store),
):
    """Direct fast columnar query over Parquet events via DuckDB."""
    return store.query_events(
        job_id=job_id,
        limit=limit,
        offset=offset,
        protocol=protocol,
        ip=ip,
    )
