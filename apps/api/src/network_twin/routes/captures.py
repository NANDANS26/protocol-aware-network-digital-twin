"""FastAPI router for Phase 09 real capture validation and differential testing."""

import logging
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from network_twin.captures.corpus import CaptureCorpus
from network_twin.captures.differential import DifferentialValidator
from network_twin.captures.e2e_validator import EndToEndValidator
from network_twin.captures.models import (
    CaptureManifestItem,
    CaptureValidationReport,
    DifferentialTestResult,
    MetamorphicRelationType,
)

logger = logging.getLogger("network_twin.routes.captures")

router = APIRouter(prefix="/twin/captures", tags=["Capture Validation & Differential Testing"])
_corpus = CaptureCorpus()
_validator = DifferentialValidator(_corpus)
_e2e_validator = EndToEndValidator(_corpus)


class DifferentialRunRequest(BaseModel):
    relation_type: MetamorphicRelationType = Field(..., description="Metamorphic relation to evaluate")
    base_capture_id: str = Field(..., description="Base capture ID")
    transformed_capture_id: str | None = Field(None, description="Transformed or secondary capture ID")
    shift_seconds: int = Field(60, description="Offset in seconds for timestamp shift testing")


class CorpusSummaryResponse(BaseModel):
    total_captures: int
    provenance_distribution: dict[str, int]
    format_distribution: dict[str, int]
    supported_protocols: list[str]
    total_packet_count: int


@router.get("", response_model=list[CaptureManifestItem])
def list_corpus_captures() -> list[CaptureManifestItem]:
    """Lists all versioned capture fixtures in the corpus with complete provenance metadata."""
    return _corpus.list_captures()


@router.get("/summary", response_model=CorpusSummaryResponse)
def get_corpus_summary() -> CorpusSummaryResponse:
    """Returns aggregated summary of the capture corpus."""
    items = _corpus.list_captures()
    prov_dist: dict[str, int] = {}
    fmt_dist: dict[str, int] = {}
    protocols: set[str] = set()
    total_pkts = 0

    for item in items:
        prov_dist[item.provenance.value] = prov_dist.get(item.provenance.value, 0) + 1
        fmt_dist[item.format.value] = fmt_dist.get(item.format.value, 0) + 1
        protocols.update(item.protocols)
        total_pkts += item.packet_count

    return CorpusSummaryResponse(
        total_captures=len(items),
        provenance_distribution=prov_dist,
        format_distribution=fmt_dist,
        supported_protocols=sorted(list(protocols)),
        total_packet_count=total_pkts,
    )


@router.get("/{capture_id}", response_model=CaptureManifestItem)
def get_corpus_capture(capture_id: str) -> CaptureManifestItem:
    """Retrieves metadata and ground-truth expectation for a specific capture."""
    item = _corpus.get_capture(capture_id)
    if not item:
        raise HTTPException(status_code=404, detail=f"Capture fixture '{capture_id}' not found.")
    return item


@router.post("/{capture_id}/validate", response_model=CaptureValidationReport)
def validate_capture(capture_id: str) -> CaptureValidationReport:
    """Validates raw capture bytes through C++ engine and compares field-by-field against reference decoder."""
    try:
        return _validator.validate_capture(capture_id)
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except Exception as e:
        logger.error("Capture validation failed: %s", e)
        raise HTTPException(status_code=500, detail=f"Validation error: {e}") from e


@router.post("/differential", response_model=DifferentialTestResult)
def run_differential_test(req: DifferentialRunRequest) -> DifferentialTestResult:
    """Executes metamorphic or differential relation check on capture fixtures."""
    try:
        if req.relation_type == MetamorphicRelationType.FORMAT_EQUIVALENCE:
            if not req.transformed_capture_id:
                raise HTTPException(
                    status_code=400,
                    detail="transformed_capture_id is required for format equivalence testing.",
                )
            return _validator.test_format_equivalence(req.base_capture_id, req.transformed_capture_id)

        elif req.relation_type == MetamorphicRelationType.TIMESTAMP_SHIFT:
            return _validator.test_metamorphic_timestamp_shift(req.base_capture_id, req.shift_seconds)

        elif req.relation_type == MetamorphicRelationType.NOISE_INJECTION:
            return _validator.test_metamorphic_noise_injection(req.base_capture_id)

        else:
            raise HTTPException(status_code=400, detail=f"Unsupported relation type: {req.relation_type}")

    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except Exception as e:
        logger.error("Differential test failed: %s", e)
        raise HTTPException(status_code=500, detail=f"Differential execution error: {e}") from e


@router.post("/{capture_id}/e2e")
def run_end_to_end_validation(capture_id: str) -> dict[str, Any]:
    """Executes the full end-to-end data path from PCAP bytes to predictions without mocks."""
    try:
        return _e2e_validator.run_e2e_validation(capture_id)
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except Exception as e:
        logger.error("End-to-end validation error: %s", e)
        raise HTTPException(status_code=500, detail=f"E2E validation failure: {e}") from e
