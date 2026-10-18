"""
FastAPI Router for Phase 10: Evidence-Backed Incident Investigation & Root-Cause Analysis.
"""

import logging
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from network_twin.investigations.engine import InvestigationEngine
from network_twin.investigations.integrity import compare_executions
from network_twin.investigations.models import (
    AuditPackExport,
    CreateInvestigationRequest,
    ExecutionIntegrityReport,
    InvestigationCase,
    InvestigationExecutionRecord,
    ReplayComparison,
)
from network_twin.simulation.models import SimulationActionType
from network_twin.storage.metadata_store import metadata_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/twin/investigations", tags=["Incident Investigation & Root-Cause Analysis"])
_engine = InvestigationEngine(metadata_store=metadata_store)


class ReplayExecutionResponse(BaseModel):
    replayed_execution: InvestigationExecutionRecord
    comparison: ReplayComparison


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


# --- Phase 11: Reproducible Replay, Integrity & Audit Pack Endpoints ---


@router.get("/{investigation_id}/executions", response_model=list[InvestigationExecutionRecord])
def list_investigation_executions(investigation_id: str) -> list[InvestigationExecutionRecord]:
    """Lists all historical execution records for an investigation case, newest first."""
    case = metadata_store.get_investigation(investigation_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Investigation '{investigation_id}' not found.")
    return _engine.list_executions(investigation_id)


@router.get("/{investigation_id}/executions/{execution_id}", response_model=InvestigationExecutionRecord)
def get_investigation_execution(investigation_id: str, execution_id: str) -> InvestigationExecutionRecord:
    """Retrieves an immutable execution record by execution_id."""
    record = _engine.get_execution(execution_id)
    if not record or record.investigation_id != investigation_id:
        raise HTTPException(status_code=404, detail=f"Execution '{execution_id}' not found.")
    return record


@router.post(
    "/{investigation_id}/executions/{execution_id}/verify-integrity",
    response_model=ExecutionIntegrityReport,
)
def verify_execution_integrity_route(investigation_id: str, execution_id: str) -> ExecutionIntegrityReport:
    """Audits cryptographic integrity of recorded evidence items and source references."""
    try:
        record = _engine.get_execution(execution_id)
        if not record or record.investigation_id != investigation_id:
            raise HTTPException(status_code=404, detail=f"Execution '{execution_id}' not found.")
        return _engine.verify_execution(execution_id)
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except Exception as e:
        logger.error("Integrity verification failed: %s", e)
        raise HTTPException(status_code=500, detail=f"Verification failed: {e}") from e


@router.post(
    "/{investigation_id}/executions/{execution_id}/replay",
    response_model=ReplayExecutionResponse,
)
def replay_investigation_execution(investigation_id: str, execution_id: str) -> ReplayExecutionResponse:
    """Deterministically replays an investigation execution using recorded inputs and model state."""
    try:
        record = _engine.get_execution(execution_id)
        if not record or record.investigation_id != investigation_id:
            raise HTTPException(status_code=404, detail=f"Execution '{execution_id}' not found.")
        replayed_exec, comparison = _engine.replay_execution(investigation_id, execution_id)
        return ReplayExecutionResponse(replayed_execution=replayed_exec, comparison=comparison)
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except Exception as e:
        logger.error("Execution replay failed: %s", e)
        raise HTTPException(status_code=500, detail=f"Replay failed: {e}") from e


@router.get(
    "/{investigation_id}/executions/{execution_id}/compare/{other_execution_id}",
    response_model=ReplayComparison,
)
def compare_investigation_executions(
    investigation_id: str,
    execution_id: str,
    other_execution_id: str,
) -> ReplayComparison:
    """Compares two historical executions to identify semantic differences in findings or evidence."""
    orig = _engine.get_execution(execution_id)
    other = _engine.get_execution(other_execution_id)
    if not orig or orig.investigation_id != investigation_id:
        raise HTTPException(status_code=404, detail=f"Original execution '{execution_id}' not found.")
    if not other or other.investigation_id != investigation_id:
        raise HTTPException(status_code=404, detail=f"Target execution '{other_execution_id}' not found.")
    return compare_executions(orig, other)


@router.get(
    "/{investigation_id}/executions/{execution_id}/audit-pack",
    response_model=AuditPackExport,
)
def export_execution_audit_pack(investigation_id: str, execution_id: str) -> AuditPackExport:
    """Exports a self-contained, verifiable audit package for an execution."""
    try:
        record = _engine.get_execution(execution_id)
        if not record or record.investigation_id != investigation_id:
            raise HTTPException(status_code=404, detail=f"Execution '{execution_id}' not found.")
        return _engine.export_audit_pack(execution_id)
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except Exception as e:
        logger.error("Audit pack export failed: %s", e)
        raise HTTPException(status_code=500, detail=f"Audit pack export failed: {e}") from e


@router.get(
    "/{investigation_id}/executions/{execution_id}/export",
    response_model=AuditPackExport,
)
def export_execution_alias(investigation_id: str, execution_id: str) -> AuditPackExport:
    """Alias for /audit-pack."""
    return export_execution_audit_pack(investigation_id, execution_id)
