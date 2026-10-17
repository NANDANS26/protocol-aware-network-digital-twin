"""Event validation and schema inspection endpoints."""

import json
from pathlib import Path

from contracts.network_event import NetworkEvent
from fastapi import APIRouter, HTTPException, status

router = APIRouter(prefix="/events", tags=["Event Ingestion & Schema"])

SCHEMA_PATH = Path(__file__).resolve().parents[5] / "schemas" / "v1" / "network_event.schema.json"


@router.get("/schema", summary="Get Canonical NetworkEvent JSON Schema")
async def get_event_schema():
    """Returns the canonical JSON Schema v1 for NetworkEvent."""
    if not SCHEMA_PATH.exists():
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Canonical schema file not found on disk",
        )
    try:
        with open(SCHEMA_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to read schema: {str(exc)}",
        ) from exc


@router.post("/validate", summary="Validate Structured Network Event")
async def validate_event(event: NetworkEvent):
    """Validates an incoming NetworkEvent against the Pydantic model contract.

    Returns the validated event summary and verification acknowledgement.
    """
    return {
        "valid": True,
        "event_id": str(event.event_id),
        "schema_version": event.schema_version,
        "parser_status": event.parser_status.status,
        "source_id": event.source_id,
        "timestamp_ns": event.timestamp_ns,
        "timestamp_iso": event.timestamp_iso,
    }
