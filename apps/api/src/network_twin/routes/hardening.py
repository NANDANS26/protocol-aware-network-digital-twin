"""API Routes for Adversarial Verification and Hardening."""

from fastapi import APIRouter, HTTPException, status

from network_twin.hardening.cases import get_all_adversarial_cases
from network_twin.hardening.models import (
    AdversarialRunSummary,
    AdversarialTestCase,
)
from network_twin.hardening.runner import AdversarialRunner

router = APIRouter(prefix="/twin/hardening", tags=["adversarial-hardening"])
runner = AdversarialRunner()


@router.get(
    "/cases",
    response_model=list[AdversarialTestCase],
    summary="List all hand-verifiable adversarial test cases",
)
def list_cases() -> list[AdversarialTestCase]:
    """Returns metadata and expected oracles for all registered adversarial test cases."""
    return get_all_adversarial_cases()


@router.post(
    "/run",
    response_model=AdversarialRunSummary,
    summary="Execute the adversarial verification suite",
)
def run_adversarial_suite() -> AdversarialRunSummary:
    """Executes all adversarial cases against the network twin and returns full evidence records."""
    return runner.run_all()


@router.get(
    "/latest",
    response_model=AdversarialRunSummary,
    summary="Get latest adversarial run summary",
)
def get_latest_run() -> AdversarialRunSummary:
    """Retrieves the most recent adversarial verification run results."""
    summary = runner.get_latest_summary()
    if not summary:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No adversarial verification runs have been executed yet.",
        )
    return summary


@router.get(
    "/runs/{run_id}",
    response_model=AdversarialRunSummary,
    summary="Get an adversarial run by ID",
)
def get_run(run_id: str) -> AdversarialRunSummary:
    """Retrieves an adversarial verification run by its run ID."""
    summary = runner.get_run_by_id(run_id)
    if not summary:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Adversarial run '{run_id}' not found.",
        )
    return summary
