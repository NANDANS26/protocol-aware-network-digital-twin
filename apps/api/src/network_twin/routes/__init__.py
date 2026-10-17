"""Route package initialization."""

from fastapi import APIRouter

from network_twin.routes.events import router as events_router
from network_twin.routes.health import router as health_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(events_router)

__all__ = ["api_router"]
