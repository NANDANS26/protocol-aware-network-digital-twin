"""
FastAPI Router for Phase 10: Evidence-Backed Incident Investigation & Root-Cause Analysis.
"""

import logging
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from network_twin.investigations.engine import InvestigationEngine
from network_twin.investigations.models import (
    CreateInvestigationRequest,
    InvestigationCase,
)
from network_twin.simulation.models import SimulationActionType
from network_twin.storage.metadata_store import metadata_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/twin/investigations", tags=["Incident Investigation & Root-Cause Analysis"])
_engine = InvestigationEngine(metadata_store=metadata_store)


class CounterfactualRunRequest(BaseModel):
    scenario_name: str = Field(..., min_length=3, max_length=100)
    action_type: SimulationActionType = Field(..., description="Hypothetical remedial action type")
    action_parameters: dict[str, Any] = Field(default_factory=dict, description="Parameters for simulated change")


@router.post("", response_model=InvestigationCase)
def create_investigation(req: CreateInvestigationRequest) -> InvestigationCase:
    """Creates a new versioned incident investigation case."""
    try:
        return _engine.create_investigation(req)
    except Exception as e:
        logger.error("Failed creating investigation: %s", e)
        raise HTTPException(status_code=500, detail=f"Failed creating investigation: {e}") from e


@router.get("", response_model=list[InvestigationCase])
def list_investigations() -> list[InvestigationCase]:
    """Lists all stored investigation cases."""
    return metadata_store.list_investigations()


@router.get("/{investigation_id}", response_model=InvestigationCase)
def get_investigation(investigation_id: str) -> InvestigationCase:
    """Retrieves full investigation case details with evidence graph and ranked explanations."""
    case = metadata_store.get_investigation(investigation_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Investigation '{investigation_id}' not found.")
    return case


@router.post("/{investigation_id}/execute", response_model=InvestigationCase)
def execute_investigation(investigation_id: str) -> InvestigationCase:
    """Executes the deterministic root-cause investigation workflow."""
    try:
        return _engine.execute_investigation(investigation_id)
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except Exception as e:
        logger.error("Investigation execution failed: %s", e)
        raise HTTPException(status_code=500, detail=f"Execution error: {e}") from e


@router.post("/{investigation_id}/counterfactual", response_model=InvestigationCase)
def run_investigation_counterfactual(
    investigation_id: str,
    req: CounterfactualRunRequest,
) -> InvestigationCase:
    """Applies an isolated counterfactual change to compare side-by-side with baseline."""
    try:
        return _engine.run_counterfactual(
            investigation_id=investigation_id,
            scenario_name=req.scenario_name,
            action_type=req.action_type,
            action_parameters=req.action_parameters,
        )
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except Exception as e:
        logger.error("Counterfactual execution failed: %s", e)
        raise HTTPException(status_code=500, detail=f"Counterfactual error: {e}") from e


@router.get("/{investigation_id}/export")
def export_investigation(investigation_id: str) -> dict[str, Any]:
    """Exports reproducible investigation artifact with complete evidence graph and verification details."""
    case = metadata_store.get_investigation(investigation_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Investigation '{investigation_id}' not found.")
    return case.model_dump()


@router.delete("/{investigation_id}")
def delete_investigation(investigation_id: str) -> dict[str, bool]:
    """Deletes an investigation case."""
    deleted = metadata_store.delete_investigation(investigation_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Investigation '{investigation_id}' not found.")
    return {"deleted": True}
