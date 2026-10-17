"""Main FastAPI application factory and entry point."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from network_twin.config import AppSettings, settings
from network_twin.errors import register_error_handlers
from network_twin.logging import configure_logging
from network_twin.middleware import RequestCorrelationMiddleware
from network_twin.routes import api_router


def create_app(app_config: AppSettings = settings) -> FastAPI:
    """Creates and configures a FastAPI application instance."""
    # Configure structured logging
    configure_logging(level="DEBUG" if app_config.debug else "INFO")

    app = FastAPI(
        title=app_config.app_name,
        version=app_config.app_version,
        description="Protocol-Aware Network Digital Twin & Security Verification Engine - Foundation API",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )
    app.state.config = app_config

    # Security: Restrict CORS to configured origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=app_config.cors_allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

    # Middleware: Request correlation and body limits
    app.add_middleware(
        RequestCorrelationMiddleware,
        max_body_bytes=app_config.max_request_body_bytes,
    )

    # Centralized exception handlers
    register_error_handlers(app)

    # Include versioned API router
    app.include_router(api_router, prefix=app_config.api_prefix)

    @app.get("/", tags=["Root"])
    async def root():
        return {
            "name": app_config.app_name,
            "version": app_config.app_version,
            "api_prefix": app_config.api_prefix,
            "health_endpoint": f"{app_config.api_prefix}/health",
            "readiness_endpoint": f"{app_config.api_prefix}/ready",
            "docs_url": "/docs",
        }

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "network_twin.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )
