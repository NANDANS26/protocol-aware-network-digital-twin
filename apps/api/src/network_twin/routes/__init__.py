"""Route package initialization."""

from fastapi import APIRouter

from network_twin.routes.analysis import router as analysis_router
from network_twin.routes.events import router as events_router
from network_twin.routes.health import router as health_router
from network_twin.routes.intelligence import router as intelligence_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(events_router)
api_router.include_router(analysis_router)
api_router.include_router(intelligence_router)

__all__ = ["api_router"]
