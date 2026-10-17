"""FastAPI router for capture uploads, flow inspection, and protocol analysis."""

from pathlib import Path

from fastapi import APIRouter, File, HTTPException, Query, UploadFile, status

from network_twin.models.analysis import (
    AnalysisJob,
    EventListResponse,
    FlowListResponse,
    JobUploadResponse,
)
from network_twin.services.analysis_service import analysis_service

router = APIRouter(prefix="/analysis", tags=["Protocol Analysis"])


@router.post(
    "/upload",
    response_model=JobUploadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload PCAP or PCAPNG capture file for protocol analysis",
)
async def upload_capture(file: UploadFile = File(...)):
    """Uploads and decodes a PCAP/PCAPNG capture through the C++20 protocol engine."""
    filename = file.filename or "uploaded.pcap"
    content = await file.read()

    if not content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty.",
        )

    try:
        job = analysis_service.analyze_capture(filename=filename, content=content)
        return JobUploadResponse(
            job_id=job.job_id,
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
async def run_demo_analysis(format: str = Query("pcap", enum=["pcap", "pcapng"])):
    """Executes the C++ protocol engine on the deterministic test fixture."""
    project_root = Path(__file__).resolve().parents[5]
    ext = "pcapng" if format == "pcapng" else "pcap"
    fixture_path = project_root / "tests" / "fixtures" / f"sample_capture.{ext}"

    if not fixture_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Test fixture {fixture_path.name} not found.",
        )

    with open(fixture_path, "rb") as f:
        content = f.read()

    try:
        job = analysis_service.analyze_capture(filename=fixture_path.name, content=content)
        return JobUploadResponse(
            job_id=job.job_id,
            filename=job.filename,
            file_size_bytes=job.file_size_bytes,
            status=job.status,
            message=f"Sample fixture {fixture_path.name} analyzed successfully.",
            summary=job.summary,
        )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)) from e


@router.get(
    "/jobs",
    response_model=list[AnalysisJob],
    summary="List recent protocol analysis jobs",
)
async def list_jobs():
    return analysis_service.list_jobs()


@router.get(
    "/jobs/{job_id}",
    response_model=AnalysisJob,
    summary="Get status and summary of a specific analysis job",
)
async def get_job(job_id: str):
    job = analysis_service.get_job(job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis job {job_id} not found.",
        )
    return job


@router.get(
    "/jobs/{job_id}/flows",
    response_model=FlowListResponse,
    summary="Inspect reconstructed flows from an analysis job",
)
async def get_job_flows(
    job_id: str,
    ip_proto: str | None = Query(None, description="Filter by transport protocol (e.g. TCP, UDP, ICMP)"),
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
):
    try:
        return analysis_service.get_job_flows(
            job_id=job_id,
            ip_proto=ip_proto,
            offset=offset,
            limit=limit,
        )
    except KeyError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e


@router.get(
    "/jobs/{job_id}/events",
    response_model=EventListResponse,
    summary="Inspect canonical network events from an analysis job",
)
async def get_job_events(
    job_id: str,
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    status_filter: str | None = Query(None, alias="status", description="Filter by parser status (e.g. ok, malformed, truncated)"),
):
    try:
        return analysis_service.get_job_events(
            job_id=job_id,
            offset=offset,
            limit=limit,
            status=status_filter,
        )
    except KeyError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e
