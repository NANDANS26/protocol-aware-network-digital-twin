"""REST API endpoints for Phase 07 reproducible benchmarking and validation."""

import logging

from fastapi import APIRouter, HTTPException, Query, status

from network_twin.benchmarking.fixtures import list_benchmark_fixtures
from network_twin.benchmarking.models import (
    BenchmarkFixtureMeta,
    BenchmarkRunRecord,
    BenchmarkRunRequest,
    BenchmarkSummaryResponse,
)
from network_twin.benchmarking.runner import BenchmarkRunner
from network_twin.storage.metadata_store import metadata_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/benchmarks", tags=["Benchmarking & Real-World Validation"])
benchmark_runner = BenchmarkRunner(metadata_store)


@router.get("/fixtures", response_model=list[BenchmarkFixtureMeta])
def get_benchmark_fixtures():
    """Returns the catalog of versioned benchmark fixtures with provenance and expected outcomes."""
    return list_benchmark_fixtures()


@router.post("/run", response_model=BenchmarkSummaryResponse, status_code=status.HTTP_201_CREATED)
def execute_benchmark_run(req: BenchmarkRunRequest):
    """Executes a benchmark run against a specified fixture or the entire validation suite."""
    try:
        if req.fixture_id == "all":
            summary = benchmark_runner.run_suite(random_seed=req.random_seed)
            return summary
        else:
            benchmark_runner.run_fixture(req.fixture_id, random_seed=req.random_seed)
            return metadata_store.get_benchmark_summary()
    except KeyError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e
    except Exception as e:
        logger.error("Benchmark execution error: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Benchmark execution failed: {e}"
        ) from e


@router.get("/runs", response_model=list[BenchmarkRunRecord])
def list_benchmark_runs(limit: int = Query(default=50, ge=1, le=200)):
    """Lists past benchmark run audit records in reverse chronological order."""
    return metadata_store.list_benchmark_runs(limit=limit)


@router.get("/runs/{run_id}", response_model=BenchmarkRunRecord)
def get_benchmark_run(run_id: str):
    """Retrieves full audit report for a specific benchmark run."""
    run = metadata_store.get_benchmark_run(run_id)
    if not run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Benchmark run with ID '{run_id}' not found.",
        )
    return run


@router.get("/summary", response_model=BenchmarkSummaryResponse)
def get_benchmark_summary():
    """Returns aggregate summary metrics across all benchmark runs."""
    return metadata_store.get_benchmark_summary()
