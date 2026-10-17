"""Health and readiness API endpoints."""

from contracts.health import HealthStatusResponse
from fastapi import APIRouter, Depends, Request, Response, status

from network_twin.config import AppSettings, settings
from network_twin.services.subsystem_service import SubsystemService

router = APIRouter(tags=["System Health & Lifecycle"])


def get_subsystem_service(request: Request) -> SubsystemService:
    cfg: AppSettings = getattr(request.app.state, "config", settings)
    return SubsystemService(cfg)


@router.get(
    "/health",
    response_model=HealthStatusResponse,
    summary="Application Process Liveness",
    description="Reports the process lifecycle state, version, and current subsystem states.",
)
async def get_health(
    service: SubsystemService = Depends(get_subsystem_service),
) -> HealthStatusResponse:
    return service.get_health()


@router.get(
    "/ready",
    response_model=HealthStatusResponse,
    summary="Application Dependency Readiness",
    description="Evaluates whether mandatory subsystems and database connections are operational.",
)
async def get_readiness(
    response: Response,
    service: SubsystemService = Depends(get_subsystem_service),
) -> HealthStatusResponse:
    is_ready, health_report = service.get_readiness()
    if not is_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    else:
        response.status_code = status.HTTP_200_OK
    return health_report


@router.get(
    "/version",
    summary="System and Schema Versioning",
    description="Returns semantic versions for API, C++ Engine interface, and structured event schemas.",
)
async def get_version():
    return {
        "app_name": settings.app_name,
        "app_version": settings.app_version,
        "schema_version": settings.schema_version,
        "environment": settings.environment,
    }
