"""Centralized error handling and exception converters."""

import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger("network_twin.errors")


def get_request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "unknown")


def register_error_handlers(app: FastAPI) -> None:
    """Registers application-wide exception handlers."""

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        req_id = get_request_id(request)
        formatted_errors = []
        for err in exc.errors():
            loc = " -> ".join(str(p) for p in err.get("loc", []))
            formatted_errors.append(
                {
                    "field": loc,
                    "message": err.get("msg", "Validation error"),
                    "type": err.get("type", "value_error"),
                }
            )

        logger.warning(
            f"Validation error on {request.method} {request.url.path}",
            extra={"request_id": req_id, "errors": formatted_errors},
        )

        return JSONResponse(
            status_code=422,
            content={
                "error": "ValidationError",
                "message": "Input validation failed for request payload or query parameters.",
                "details": formatted_errors,
                "request_id": req_id,
            },
            headers={"X-Request-ID": req_id},
        )

    @app.exception_handler(StarletteHTTPException)
    @app.exception_handler(HTTPException)
    async def http_exception_handler(
        request: Request, exc: StarletteHTTPException | HTTPException
    ) -> JSONResponse:
        req_id = get_request_id(request)
        detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)

        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": "HTTPException",
                "message": detail,
                "status_code": exc.status_code,
                "request_id": req_id,
            },
            headers={"X-Request-ID": req_id, **(getattr(exc, "headers", None) or {})},
        )

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        req_id = get_request_id(request)
        logger.error(
            f"Unhandled server error on {request.method} {request.url.path}: {str(exc)}",
            extra={"request_id": req_id},
            exc_info=True,
        )

        # Never leak traceback or sensitive connection details in production/API response
        return JSONResponse(
            status_code=500,
            content={
                "error": "InternalServerError",
                "message": "An unexpected error occurred. The incident has been logged.",
                "request_id": req_id,
            },
            headers={"X-Request-ID": req_id},
        )
