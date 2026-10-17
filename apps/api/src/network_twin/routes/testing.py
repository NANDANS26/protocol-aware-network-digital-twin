"""FastAPI REST routes for Protocol Security Testing, Fuzzing, and Differential Verification."""

import logging

from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import FileResponse
from pydantic import BaseModel

from network_twin.storage.metadata_store import metadata_store
from network_twin.testing.campaign_service import CampaignService
from network_twin.testing.differential import run_pcap_vs_pcapng_differential
from network_twin.testing.generators import make_ethernet_frame, make_ipv4_packet, make_tcp_segment
from network_twin.testing.models import (
    CampaignCreateRequest,
    ExecutionResult,
    Finding,
    RegressionFixture,
    RegressionRunResult,
    ReproductionArtifact,
    TestCampaign,
    TestCase,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/testing", tags=["Security Testing & Fuzzing"])
service = CampaignService(metadata_store=metadata_store)


class PromoteRequest(BaseModel):
    name: str = ""


# --- Campaigns ---


@router.post(
    "/campaigns",
    response_model=TestCampaign,
    status_code=status.HTTP_201_CREATED,
    summary="Create and optionally execute a bounded protocol test campaign",
)
def create_campaign(req: CampaignCreateRequest):
    try:
        campaign = service.create_campaign(req)
        return campaign
    except Exception as e:
        logger.error("Failed to create campaign: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get(
    "/campaigns",
    response_model=list[TestCampaign],
    summary="List all protocol security test campaigns",
)
def list_campaigns():
    return metadata_store.list_campaigns()


@router.get(
    "/campaigns/{campaign_id}",
    response_model=TestCampaign,
    summary="Get campaign status and metrics",
)
def get_campaign(campaign_id: str):
    campaign = metadata_store.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail=f"Campaign {campaign_id} not found")
    return campaign


@router.post(
    "/campaigns/{campaign_id}/run",
    response_model=TestCampaign,
    summary="Execute or resume a test campaign",
)
def run_campaign(campaign_id: str):
    try:
        return service.execute_campaign(campaign_id)
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve)) from ve
    except Exception as e:
        logger.error("Failed to run campaign %s: %s", campaign_id, e, exc_info=True)
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get(
    "/campaigns/{campaign_id}/cases",
    response_model=list[TestCase],
    summary="List test cases for a campaign",
)
def list_campaign_test_cases(
    campaign_id: str,
    target: str | None = Query(None, description="Filter by protocol target"),
    status_filter: str | None = Query(None, alias="status", description="Filter by status"),
):
    return metadata_store.list_test_cases(campaign_id=campaign_id, target=target, status=status_filter)


# --- Test Cases ---


@router.get(
    "/cases/{case_id}",
    response_model=dict,
    summary="Get single test case details and execution result",
)
def get_test_case_details(case_id: str):
    tc = metadata_store.get_test_case(case_id)
    if not tc:
        raise HTTPException(status_code=404, detail=f"Test case {case_id} not found")
    exec_res = metadata_store.get_execution_result(case_id)
    return {
        "test_case": tc.model_dump(),
        "execution_result": exec_res.model_dump() if exec_res else None,
    }


@router.post(
    "/cases/{case_id}/rerun",
    response_model=ExecutionResult,
    summary="Rerun a single test case on demand",
)
def rerun_test_case(case_id: str):
    try:
        return service.rerun_test_case(case_id)
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve)) from ve
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


# --- Findings ---


@router.get(
    "/findings",
    response_model=list[Finding],
    summary="List detected security test findings",
)
def list_findings(
    campaign_id: str | None = Query(None),
    severity: str | None = Query(None),
    protocol: str | None = Query(None),
    status_filter: str | None = Query(None, alias="status"),
):
    return metadata_store.list_findings(
        campaign_id=campaign_id,
        severity=severity,
        protocol=protocol,
        status=status_filter,
    )


@router.get(
    "/findings/{finding_id}",
    response_model=Finding,
    summary="Get detailed finding metadata",
)
def get_finding(finding_id: str):
    finding = metadata_store.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")
    return finding


@router.post(
    "/findings/{finding_id}/minimize",
    response_model=ReproductionArtifact,
    summary="Run delta debugging minimization on finding fixture",
)
def minimize_finding(finding_id: str):
    try:
        return service.minimize_finding(finding_id)
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve)) from ve
    except Exception as e:
        logger.error("Minimization failed for %s: %s", finding_id, e, exc_info=True)
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.post(
    "/findings/{finding_id}/promote",
    response_model=RegressionFixture,
    summary="Promote a confirmed finding to a permanent regression fixture",
)
def promote_finding(finding_id: str, req: PromoteRequest):
    try:
        return service.promote_to_regression(finding_id, req.name)
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve)) from ve
    except Exception as e:
        logger.error("Promotion failed for %s: %s", finding_id, e, exc_info=True)
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get(
    "/findings/{finding_id}/export",
    summary="Export self-contained reproduction bundle (ZIP)",
)
def export_bundle(finding_id: str):
    try:
        bundle_path = service.export_reproduction_bundle(finding_id)
        return FileResponse(
            path=str(bundle_path),
            filename=bundle_path.name,
            media_type="application/zip",
        )
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve)) from ve
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


# --- Regressions ---


@router.get(
    "/regressions",
    response_model=list[RegressionFixture],
    summary="List all registered regression fixtures",
)
def list_regressions():
    return metadata_store.list_regression_fixtures()


@router.post(
    "/regressions/{fixture_id}/run",
    response_model=RegressionRunResult,
    summary="Execute regression test fixture and verify pass/fail",
)
def run_regression(fixture_id: str):
    try:
        return service.run_regression_fixture(fixture_id)
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve)) from ve
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


# --- Differential Test Runner ---


@router.post(
    "/differential/quick-check",
    summary="Execute on-demand PCAP vs PCAPNG differential equivalence test",
)
def run_quick_differential():
    try:
        p = make_ethernet_frame(
            "00:11:22:33:44:55",
            "00:AA:11:22:33:44",
            0x0800,
            make_ipv4_packet("10.0.0.1", "10.0.0.2", 6, make_tcp_segment(4444, 80, 100, 0, {"syn": True})),
        )
        packets = [(1776412800, 0, p)]
        diff_res = run_pcap_vs_pcapng_differential(service.runner, packets)
        return diff_res.model_dump()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e
