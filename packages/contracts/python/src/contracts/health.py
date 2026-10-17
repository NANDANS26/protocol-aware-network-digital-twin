"""Health and readiness contract definitions."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class OverallHealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    NOT_READY = "not_ready"


class SubsystemState(str, Enum):
    OK = "ok"
    DEGRADED = "degraded"
    DOWN = "down"
    DISABLED = "disabled"
    PLANNED = "planned"


class OperationalState(str, Enum):
    OPERATIONAL = "operational"
    UNAVAILABLE = "unavailable"
    PLANNED = "planned"


class SubsystemReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: SubsystemState
    operational_state: OperationalState
    details: str | None = None
    last_checked: datetime | None = None


class HealthStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: OverallHealthStatus
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    version: str
    schema_version: str = "1.0.0"
    environment: str = "development"
    subsystems: dict[str, SubsystemReport]
