"""Route package initialization."""

from fastapi import APIRouter

from network_twin.routes.analysis import router as analysis_router
from network_twin.routes.benchmarks import router as benchmarks_router
from network_twin.routes.captures import router as captures_router
from network_twin.routes.events import router as events_router
from network_twin.routes.hardening import router as hardening_router
from network_twin.routes.health import router as health_router
from network_twin.routes.intelligence import router as intelligence_router
from network_twin.routes.predictive import router as predictive_router
from network_twin.routes.sequences import router as sequences_router
from network_twin.routes.simulation import router as simulation_router
from network_twin.routes.testing import router as testing_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(events_router)
api_router.include_router(analysis_router)
api_router.include_router(intelligence_router)
api_router.include_router(simulation_router)
api_router.include_router(testing_router)
api_router.include_router(sequences_router)
api_router.include_router(predictive_router)
api_router.include_router(benchmarks_router)
api_router.include_router(hardening_router)
api_router.include_router(captures_router)

__all__ = ["api_router"]
