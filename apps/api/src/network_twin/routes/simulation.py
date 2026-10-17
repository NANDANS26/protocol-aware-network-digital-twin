"""REST API endpoints for Executable Network Models, Reachability Simulation, Counterfactual Scenarios, and Security Verification."""

import logging
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from network_twin.config import settings
from network_twin.simulation.forwarding_engine import ForwardingEngine
from network_twin.simulation.model_builder import ModelBuilder
from network_twin.simulation.models import (
    CounterfactualResult,
    ModelLimitation,
    NetworkModel,
    ReachabilityQuery,
    ReachabilityResult,
    SecurityInvariant,
    SimulationScenario,
    VerificationResult,
)
from network_twin.simulation.scenario_engine import ScenarioEngine
from network_twin.simulation.verification_engine import VerificationEngine
from network_twin.storage.metadata_store import MetadataStore

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Simulation & Deterministic Verification"])


def get_metadata_store(request: Request) -> MetadataStore:
    if hasattr(request.app.state, "analysis_service"):
        return request.app.state.analysis_service.metadata_store
    if hasattr(request.app.state, "metadata_store"):
        return request.app.state.metadata_store
    config = getattr(request.app.state, "config", settings)
    store = MetadataStore(config)
    request.app.state.metadata_store = store
    return store


def get_forwarding_engine() -> ForwardingEngine:
    return ForwardingEngine()


def get_verification_engine(fwd: ForwardingEngine = Depends(get_forwarding_engine)) -> VerificationEngine:
    return VerificationEngine(forwarding_engine=fwd)


def get_scenario_engine(
    fwd: ForwardingEngine = Depends(get_forwarding_engine),
    ver: VerificationEngine = Depends(get_verification_engine),
) -> ScenarioEngine:
    return ScenarioEngine(forwarding_engine=fwd, verification_engine=ver)


def get_model_builder(store: MetadataStore = Depends(get_metadata_store)) -> ModelBuilder:
    return ModelBuilder(store)


# --- Request Models ---

class BuildModelRequest(BaseModel):
    snapshot_id: str
    name: str | None = None
    custom_routes: list[dict[str, Any]] | None = None
    custom_acls: list[dict[str, Any]] | None = None
    custom_zones: list[dict[str, Any]] | None = None


class RunVerificationRequest(BaseModel):
    model_id: str
    invariant_ids: list[str] | None = None
    scenario_id: str | None = None


# --- Network Models Endpoints ---

@router.post("/models/build", response_model=NetworkModel)
async def build_network_model(
    req: BuildModelRequest,
    builder: ModelBuilder = Depends(get_model_builder),
):
    """Builds an executable formal NetworkModel from a persistent topology snapshot."""
    try:
        return builder.build_from_snapshot(
            snapshot_id=req.snapshot_id,
            name=req.name,
            custom_routes=req.custom_routes,
            custom_acls=req.custom_acls,
            custom_zones=req.custom_zones,
        )
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except Exception as e:
        logger.error("Failed to build model: %s", e)
        raise HTTPException(status_code=400, detail=f"Failed to build network model: {e}") from e


@router.get("/models", response_model=list[NetworkModel])
async def list_models(store: MetadataStore = Depends(get_metadata_store)):
    """Lists all constructed NetworkModels."""
    return store.list_network_models()


@router.get("/models/{model_id}", response_model=NetworkModel)
async def get_model(model_id: str, store: MetadataStore = Depends(get_metadata_store)):
    """Retrieves full specification of an executable NetworkModel."""
    model = store.get_network_model(model_id)
    if not model:
        raise HTTPException(status_code=404, detail=f"NetworkModel '{model_id}' not found.")
    return model


@router.get("/models/{model_id}/limitations", response_model=list[ModelLimitation])
async def get_model_limitations(model_id: str, store: MetadataStore = Depends(get_metadata_store)):
    """Returns explicit known omissions and unsupported semantics for the model."""
    model = store.get_network_model(model_id)
    if not model:
        raise HTTPException(status_code=404, detail=f"NetworkModel '{model_id}' not found.")
    return model.known_limitations


# --- Reachability Simulation Endpoints ---

@router.post("/simulations/reachability", response_model=ReachabilityResult)
async def evaluate_reachability(
    query: ReachabilityQuery,
    store: MetadataStore = Depends(get_metadata_store),
    forwarding: ForwardingEngine = Depends(get_forwarding_engine),
):
    """Deterministically evaluates packet forwarding and reachability between source and destination."""
    if not query.model_id:
        # Fall back to latest constructed model
        models = store.list_network_models()
        if not models:
            raise HTTPException(
                status_code=400,
                detail="No NetworkModel available. Please build a model from a snapshot first.",
            )
        model = models[0]
    else:
        model = store.get_network_model(query.model_id)
        if not model:
            raise HTTPException(status_code=404, detail=f"NetworkModel '{query.model_id}' not found.")

    return forwarding.evaluate_reachability(model, query)


# --- Counterfactual Scenarios Endpoints ---

@router.post("/simulations/scenarios", response_model=SimulationScenario)
async def create_scenario(
    scenario: SimulationScenario,
    store: MetadataStore = Depends(get_metadata_store),
):
    """Registers an isolated counterfactual simulation scenario."""
    base_model = store.get_network_model(scenario.base_model_id)
    if not base_model:
        raise HTTPException(
            status_code=404,
            detail=f"Base NetworkModel '{scenario.base_model_id}' not found.",
        )

    store.save_scenario(scenario)
    return scenario


@router.get("/simulations/scenarios", response_model=list[SimulationScenario])
async def list_scenarios(
    base_model_id: str | None = None,
    store: MetadataStore = Depends(get_metadata_store),
):
    """Lists registered counterfactual simulation scenarios."""
    return store.list_scenarios(base_model_id=base_model_id)


@router.get("/simulations/scenarios/{scenario_id}", response_model=SimulationScenario)
async def get_scenario(scenario_id: str, store: MetadataStore = Depends(get_metadata_store)):
    scenario = store.get_scenario(scenario_id)
    if not scenario:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found.")
    return scenario


@router.post("/simulations/scenarios/{scenario_id}/run", response_model=CounterfactualResult)
async def run_scenario(
    scenario_id: str,
    store: MetadataStore = Depends(get_metadata_store),
    scenario_engine: ScenarioEngine = Depends(get_scenario_engine),
):
    """Executes a counterfactual scenario against its base model without modifying baseline state."""
    scenario = store.get_scenario(scenario_id)
    if not scenario:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found.")

    base_model = store.get_network_model(scenario.base_model_id)
    if not base_model:
        raise HTTPException(
            status_code=404,
            detail=f"Base model '{scenario.base_model_id}' for scenario not found.",
        )

    invariants = store.list_invariants()

    try:
        cf_model, result = scenario_engine.run_scenario(base_model, scenario, invariants=invariants)
        # Save counterfactual model and run results
        store.save_network_model(cf_model)
        store.save_counterfactual_result(result)
        return result
    except Exception as e:
        logger.error("Failed to run scenario: %s", e)
        raise HTTPException(status_code=400, detail=f"Scenario execution failed: {e}") from e


# --- Security Invariants Endpoints ---

@router.get("/verification/invariants", response_model=list[SecurityInvariant])
async def list_invariants(store: MetadataStore = Depends(get_metadata_store)):
    """Lists registered security invariants."""
    return store.list_invariants()


@router.post("/verification/invariants", response_model=SecurityInvariant)
async def create_invariant(
    invariant: SecurityInvariant,
    store: MetadataStore = Depends(get_metadata_store),
):
    """Registers a formal security invariant for policy verification."""
    store.save_invariant(invariant)
    return invariant


@router.post("/verification/run", response_model=list[VerificationResult])
async def run_verification(
    req: RunVerificationRequest,
    store: MetadataStore = Depends(get_metadata_store),
    engine: VerificationEngine = Depends(get_verification_engine),
):
    """Executes deterministic security invariant verification against a model."""
    model = store.get_network_model(req.model_id)
    if not model:
        raise HTTPException(status_code=404, detail=f"NetworkModel '{req.model_id}' not found.")

    all_invariants = store.list_invariants()
    if req.invariant_ids:
        invariants_to_run = [inv for inv in all_invariants if inv.invariant_id in req.invariant_ids]
    else:
        invariants_to_run = all_invariants

    if not invariants_to_run:
        # If no custom invariants exist, create default security invariants suite
        invariants_to_run = _get_default_invariants(model)
        for inv in invariants_to_run:
            store.save_invariant(inv)

    results = engine.verify_all(model, invariants_to_run)
    run_id = f"vrun-{uuid.uuid4().hex[:12]}"
    store.save_verification_run(run_id, req.model_id, req.scenario_id, results)
    return results


@router.get("/verification/results/{result_id}", response_model=list[VerificationResult])
async def get_verification_results(result_id: str, store: MetadataStore = Depends(get_metadata_store)):
    results = store.get_verification_run(result_id)
    if not results:
        raise HTTPException(status_code=404, detail=f"Verification run '{result_id}' not found.")
    return results


def _get_default_invariants(model: NetworkModel) -> list[SecurityInvariant]:
    """Generates baseline default security invariants based on model zones and subnets."""
    from network_twin.simulation.models import InvariantDefinition, InvariantSeverity, InvariantType

    invariants: list[SecurityInvariant] = [
        SecurityInvariant(
            invariant_id="inv-zone-isolation-trusted",
            name="Untrusted Zone Isolation",
            description="Untrusted network endpoints must not directly reach internal trusted endpoints.",
            invariant_type=InvariantType.ISOLATION,
            severity=InvariantSeverity.CRITICAL,
            definition=InvariantDefinition(
                source_zone_or_cidr="zone-untrusted",
                protected_zone="zone-trusted",
                description="Strict boundary isolation between untrusted and trusted zones",
            ),
        ),
        SecurityInvariant(
            invariant_id="inv-config-consistency",
            name="Configuration & Routing Consistency",
            description="Detect contradictory route entries, unroutable next-hops, and shadowed firewall rules.",
            invariant_type=InvariantType.CONFIGURATION_CONSISTENCY,
            severity=InvariantSeverity.HIGH,
            definition=InvariantDefinition(
                description="Global configuration consistency audit",
            ),
        ),
    ]

    return invariants
