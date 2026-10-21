"""FastAPI router for capture uploads, flow inspection, and protocol analysis."""

from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile, status

from network_twin.config import settings
from network_twin.models.analysis import (
    AnalysisJob,
    EventListResponse,
    FlowListResponse,
    JobUploadResponse,
)
from network_twin.services.analysis_service import AnalysisService

router = APIRouter(prefix="/analysis", tags=["Protocol Analysis"])


def get_analysis_service(request: Request) -> AnalysisService:
    if hasattr(request.app.state, "analysis_service"):
        return request.app.state.analysis_service
    config = getattr(request.app.state, "config", settings)
    service = AnalysisService(config)
    request.app.state.analysis_service = service
    return service


@router.post(
    "/upload",
    response_model=JobUploadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload PCAP or PCAPNG capture file for protocol analysis",
)
async def upload_capture(
    file: UploadFile = File(...),
    service: AnalysisService = Depends(get_analysis_service),
):
    """Uploads and decodes a PCAP/PCAPNG capture through the C++20 protocol engine."""
    filename = file.filename or "uploaded.pcap"
    content = await file.read()

    if not content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty.",
        )

    try:
        job = service.analyze_capture(filename=filename, content=content)
        return JobUploadResponse(
            job_id=job.job_id,
            capture_id=job.capture_id,
            filename=job.filename,
            file_size_bytes=job.file_size_bytes,
            status=job.status,
            message="Protocol analysis completed successfully.",
            summary=job.summary,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
    except RuntimeError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)) from e


@router.post(
    "/demo",
    response_model=JobUploadResponse,
    status_code=status.HTTP_200_OK,
    summary="Run protocol analysis on synthetic sample capture fixture",
)
async def run_demo_analysis(
    format: str = Query("pcap", pattern="^(pcap|pcapng)$"),
    service: AnalysisService = Depends(get_analysis_service),
):
    """Executes the C++ protocol engine on the deterministic test fixture."""
    project_root = Path(__file__).resolve().parents[5]
    ext = "pcapng" if format == "pcapng" else "pcap"
    fixture_path = project_root / "tests" / "fixtures" / f"sample_capture.{ext}"

    if not fixture_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sample fixture '{fixture_path.name}' not found.",
        )

    with open(fixture_path, "rb") as f:
        content = f.read()

    try:
        job = service.analyze_capture(filename=fixture_path.name, content=content)
        return JobUploadResponse(
            job_id=job.job_id,
            capture_id=job.capture_id,
            filename=job.filename,
            file_size_bytes=job.file_size_bytes,
            status=job.status,
            message=f"Sample {format.upper()} capture analyzed successfully.",
            summary=job.summary,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Demo analysis execution failed: {e}",
        ) from e


@router.get(
    "/jobs",
    response_model=list[AnalysisJob],
    summary="List all historical protocol analysis jobs",
)
async def list_jobs(service: AnalysisService = Depends(get_analysis_service)):
    """Retrieves all completed or processing analysis jobs."""
    return service.list_jobs()


@router.get(
    "/jobs/{job_id}",
    response_model=AnalysisJob,
    summary="Get status and summary metrics for an analysis job",
)
async def get_job(job_id: str, service: AnalysisService = Depends(get_analysis_service)):
    """Retrieves specific job details and protocol telemetry summary."""
    job = service.get_job(job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis job '{job_id}' not found.",
        )
    return job


@router.get(
    "/jobs/{job_id}/flows",
    response_model=FlowListResponse,
    summary="Get reconstructed bidirectional 5-tuple flow list",
)
async def get_job_flows(
    job_id: str,
    ip_proto: str | None = Query(None, description="Filter by protocol (e.g. TCP, UDP)"),
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    service: AnalysisService = Depends(get_analysis_service),
):
    """Retrieves paginated bidirectional flow records."""
    try:
        return service.get_job_flows(job_id=job_id, ip_proto=ip_proto, offset=offset, limit=limit)
    except KeyError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e


@router.get(
    "/jobs/{job_id}/events",
    response_model=EventListResponse,
    summary="Get paginated canonical network events for job",
)
async def get_job_events(
    job_id: str,
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    status_filter: str | None = Query(None, alias="status"),
    service: AnalysisService = Depends(get_analysis_service),
):
    """Streams schema-valid canonical events emitted by the C++ engine."""
    try:
        return service.get_job_events(job_id=job_id, offset=offset, limit=limit, status=status_filter)
    except KeyError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e
