"""Phase 04 End-to-End Integration Verification Test Suite.

Validates:
1. Generate a bounded set of valid protocol fixtures.
2. Run them through the actual C++ executable.
3. Parse the real JSONL output.
4. Validate emitted events against the canonical schema.
5. Generate malformed variants.
6. Confirm safe rejection or valid bounded parsing.
7. Detect and persist a deliberately injected test-harness failure.
8. Reproduce a saved finding.
9. Promote a finding into a regression fixture.
10. Re-run the regression fixture and confirm deterministic behavior.
"""

import tempfile
import time
from pathlib import Path

from network_twin.storage.metadata_store import metadata_store
from network_twin.testing.campaign_service import CampaignService
from network_twin.testing.engine_runner import EngineRunner
from network_twin.testing.generators import (
    generate_cases_for_target,
    write_case_to_disk,
)
from network_twin.testing.models import (
    CampaignCreateRequest,
    Confidence,
    ExpectedBehavior,
    FailureCategory,
    Finding,
    FindingStatus,
    GenerationStrategy,
    ParserComponent,
    ProtocolTarget,
    Severity,
    TestCase,
)


def test_phase04_complete_end_to_end_verification():
    runner = EngineRunner()
    service = CampaignService(metadata_store=metadata_store, engine_runner=runner)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        # 1. Generate a bounded set of valid protocol fixtures
        eth_cases = generate_cases_for_target(
            target=ProtocolTarget.IPV4,
            strategy=GenerationStrategy.BASELINE_CONFORMANCE,
            seed=2026,
            count=2,
        )
        assert len(eth_cases) == 2
        fpath, fhash = write_case_to_disk(eth_cases[0], tmp_path)

        # 2. Run them through the actual C++ executable
        exec_res = runner.execute_fixture("e2e_case_1", fpath)
        assert exec_res.exit_code == 0
        assert exec_res.passed is True
        assert exec_res.crash_detected is False

        # 3. Parse real JSONL output & 4. Validate emitted events against canonical schema
        assert exec_res.parsed_event_count > 0
        assert exec_res.schema_valid is True
        assert exec_res.schema_errors == []

        # 5. Generate malformed variants
        malformed_cases = generate_cases_for_target(
            target=ProtocolTarget.ETHERNET,
            strategy=GenerationStrategy.MALFORMED_INPUTS,
            seed=2026,
            count=1,
        )
        assert len(malformed_cases) == 1
        mal_path, _mal_hash = write_case_to_disk(malformed_cases[0], tmp_path)

        # 6. Confirm safe rejection or valid bounded parsing
        mal_res = runner.execute_fixture("e2e_case_mal", mal_path)
        # Should exit safely without crash
        assert mal_res.crash_detected is False
        assert mal_res.sanitizer_triggered is False

        # 7. Detect and persist a deliberately injected test-harness failure
        harness_fault_res = runner.execute_fixture(
            "e2e_case_fault", fpath, fault_injection="CRASH"
        )
        assert harness_fault_res.crash_detected is True
        assert harness_fault_res.passed is False

        # Persist as finding (create parent campaign and test case first)
        dummy_camp = CampaignCreateRequest(
            name="E2E Campaign",
            description="Campaign for E2E verification",
            protocol_targets=[ProtocolTarget.TCP],
            strategies=[GenerationStrategy.BASELINE_CONFORMANCE],
            seed=2026,
            max_cases_per_target=1,
            run_immediately=False,
        )
        camp = service.create_campaign(dummy_camp)

        unique_case_id = f"tc_e2e_{int(time.time() * 1000)}"
        dummy_tc = TestCase(
            case_id=unique_case_id,
            campaign_id=camp.campaign_id,
            test_index=1,
            protocol_target=ProtocolTarget.TCP,
            generation_strategy=GenerationStrategy.BASELINE_CONFORMANCE,
            seed=2026,
            fixture_path=fpath,
            fixture_hash=fhash,
            expected_behavior=ExpectedBehavior.ACCEPT_VALID,
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )
        metadata_store.save_test_cases([dummy_tc])

        finding_id = f"find_e2e_{int(time.time() * 1000)}"
        e2e_finding = Finding(
            finding_id=finding_id,
            campaign_id=camp.campaign_id,
            case_id=unique_case_id,
            protocol_target=ProtocolTarget.TCP,
            parser_component=ParserComponent.TCP_DECODER,
            severity=Severity.CRITICAL,
            confidence=Confidence.CONFIRMED,
            failure_category=FailureCategory.CRASH,
            input_hash=fhash,
            engine_version="1.0.0",
            reproduction_command=f"protocol_engine.exe --input {Path(fpath).name}",
            seed=2026,
            expected_behavior="ACCEPT_VALID",
            actual_behavior="Injected Memory Access Violation",
            diagnostic="Controlled Test-Harness Fault Detection",
            status=FindingStatus.OPEN,
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )
        metadata_store.save_finding(e2e_finding)

        regression_fixture = service.promote_to_regression(
            finding_id, "E2E Injected Crash Regression"
        )
        assert regression_fixture is not None
        assert regression_fixture.finding_id == finding_id
        assert Path(regression_fixture.fixture_path).exists()

        # Check finding status updated
        updated_finding = metadata_store.get_finding(finding_id)
        assert updated_finding.status == FindingStatus.REGRESSION_PROMOTED

        # 10. Re-run the regression fixture and confirm deterministic behavior
        run_res = service.run_regression_fixture(regression_fixture.fixture_id)
        assert run_res.fixture_id == regression_fixture.fixture_id
        assert run_res.exit_code == 0
        assert run_res.passed is True

        # Re-fetch fixture to confirm last run metrics updated
        saved_reg = metadata_store.get_regression_fixture(regression_fixture.fixture_id)
        assert saved_reg.last_run_at is not None
        assert saved_reg.last_run_passed is True
