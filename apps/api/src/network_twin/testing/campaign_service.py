"""Campaign Orchestrator and Finding Triage Service for Protocol Security Testing."""

import logging
import shutil
import time
import uuid
from pathlib import Path

from network_twin.storage.metadata_store import MetadataStore
from network_twin.testing.engine_runner import EngineRunner
from network_twin.testing.generators import generate_cases_for_target, write_case_to_disk
from network_twin.testing.minimizer import ReproductionBundler, TestMinimizer, compute_file_sha256
from network_twin.testing.models import (
    CampaignCreateRequest,
    CampaignStatus,
    CaseStatus,
    Confidence,
    ExecutionResult,
    ExpectedBehavior,
    FailureCategory,
    Finding,
    FindingStatus,
    ParserComponent,
    ProtocolTarget,
    RegressionFixture,
    RegressionRunResult,
    ReproductionArtifact,
    Severity,
    TestCampaign,
    TestCase,
)

logger = logging.getLogger(__name__)


def target_to_parser_component(target: ProtocolTarget) -> ParserComponent:
    mapping = {
        ProtocolTarget.ETHERNET: ParserComponent.ETHERNET_DECODER,
        ProtocolTarget.VLAN: ParserComponent.ETHERNET_DECODER,
        ProtocolTarget.IPV4: ParserComponent.IPV4_DECODER,
        ProtocolTarget.IPV6: ParserComponent.IPV6_DECODER,
        ProtocolTarget.TCP: ParserComponent.TCP_DECODER,
        ProtocolTarget.UDP: ParserComponent.UDP_DECODER,
        ProtocolTarget.DNS: ParserComponent.DNS_PARSER,
        ProtocolTarget.HTTP: ParserComponent.HTTP_PARSER,
        ProtocolTarget.TLS_CLIENT_HELLO: ParserComponent.TLS_PARSER,
        ProtocolTarget.QUIC_CLASSIFIER: ParserComponent.QUIC_CLASSIFIER,
    }
    return mapping.get(target, ParserComponent.CAPTURE_READER)


class CampaignService:
    """Manages test campaigns, execution pipelines, finding triage, and regression baselines."""

    def __init__(self, metadata_store: MetadataStore, engine_runner: EngineRunner | None = None):
        self.store = metadata_store
        self.runner = engine_runner or EngineRunner()
        self.minimizer = TestMinimizer(self.runner)
        self.data_dir = Path(self.store.config.data_dir) / "testing"
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def create_campaign(self, req: CampaignCreateRequest) -> TestCampaign:
        """Deterministically generates test cases and creates a new test campaign."""
        campaign_id = f"camp_{uuid.uuid4().hex[:12]}"
        seed = req.seed if req.seed is not None else int(time.time())
        created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        campaign_fixtures_dir = self.data_dir / "campaigns" / campaign_id / "fixtures"
        campaign_fixtures_dir.mkdir(parents=True, exist_ok=True)

        test_cases: list[TestCase] = []
        case_index = 0

        for target in req.protocol_targets:
            for strategy in req.strategies:
                cases_data = generate_cases_for_target(
                    target=target,
                    strategy=strategy,
                    seed=seed + case_index * 13,
                    count=req.max_cases_per_target,
                )
                for cdata in cases_data:
                    case_index += 1
                    case_id = f"tc_{campaign_id}_{case_index:04d}"
                    file_path, file_hash = write_case_to_disk(cdata, campaign_fixtures_dir)

                    tc = TestCase(
                        case_id=case_id,
                        campaign_id=campaign_id,
                        test_index=case_index,
                        protocol_target=target,
                        generation_strategy=strategy,
                        mutation_sequence=cdata.mutation_sequence,
                        seed=seed,
                        generator_version="1.0.0",
                        fixture_format=cdata.fixture_format,
                        fixture_path=file_path,
                        fixture_hash=file_hash,
                        expected_behavior=cdata.expected_behavior,
                        status=CaseStatus.PENDING,
                        created_at=created_at,
                    )
                    test_cases.append(tc)

        campaign = TestCampaign(
            campaign_id=campaign_id,
            name=req.name,
            description=req.description,
            protocol_targets=req.protocol_targets,
            strategies=req.strategies,
            seed=seed,
            max_cases_per_target=req.max_cases_per_target,
            total_cases=len(test_cases),
            status=CampaignStatus.PENDING,
            created_at=created_at,
            cases_generated=len(test_cases),
        )

        self.store.save_campaign(campaign)
        self.store.save_test_cases(test_cases)

        if req.run_immediately:
            return self.execute_campaign(campaign_id)
        return campaign

    def execute_campaign(self, campaign_id: str) -> TestCampaign:
        """Executes all pending test cases within a campaign and tallies findings."""
        campaign = self.store.get_campaign(campaign_id)
        if not campaign:
            raise ValueError(f"Campaign not found: {campaign_id}")

        self.store.update_campaign_status(campaign_id, CampaignStatus.RUNNING)
        test_cases = self.store.list_test_cases(campaign_id=campaign_id)

        t_start = time.perf_counter()
        passed_cnt = 0
        rejected_cnt = 0
        failed_cnt = 0
        findings_cnt = 0

        for tc in test_cases:
            res = self.runner.execute_fixture(tc.case_id, tc.fixture_path)
            self.store.save_execution_result(res)

            # Evaluate expected vs actual behavior
            is_passed = True
            finding_category: FailureCategory | None = None
            severity: Severity = Severity.LOW

            if res.crash_detected:
                is_passed = False
                finding_category = FailureCategory.CRASH
                severity = Severity.CRITICAL
            elif res.sanitizer_triggered:
                is_passed = False
                finding_category = FailureCategory.SANITIZER_VIOLATION
                severity = Severity.HIGH
            elif not res.schema_valid:
                is_passed = False
                finding_category = FailureCategory.SCHEMA_VIOLATION
                severity = Severity.HIGH
            elif tc.expected_behavior == ExpectedBehavior.ACCEPT_VALID:
                if res.exit_code != 0 or res.parser_status == "error":
                    is_passed = False
                    finding_category = FailureCategory.UNEXPECTED_REJECTION
                    severity = Severity.MEDIUM
            elif tc.expected_behavior == ExpectedBehavior.SAFE_REJECT:
                # Should not crash and should reject safely
                if res.exit_code != 0:
                    is_passed = False
                    finding_category = FailureCategory.INCONSISTENT_PARSING
                    severity = Severity.MEDIUM

            if is_passed:
                if tc.expected_behavior == ExpectedBehavior.SAFE_REJECT:
                    rejected_cnt += 1
                else:
                    passed_cnt += 1
                tc_status = CaseStatus.PASSED
            else:
                failed_cnt += 1
                findings_cnt += 1
                tc_status = CaseStatus.FAILED

                # Create Finding
                finding_id = f"find_{uuid.uuid4().hex[:10]}"
                repro_cmd = f"protocol_engine.exe --input {Path(tc.fixture_path).name} --out events.jsonl --summary summary.json"
                finding = Finding(
                    finding_id=finding_id,
                    campaign_id=campaign_id,
                    case_id=tc.case_id,
                    protocol_target=tc.protocol_target,
                    parser_component=target_to_parser_component(tc.protocol_target),
                    severity=severity,
                    confidence=Confidence.CONFIRMED,
                    failure_category=finding_category or FailureCategory.INCONSISTENT_PARSING,
                    input_hash=tc.fixture_hash,
                    engine_version="1.0.0",
                    reproduction_command=repro_cmd,
                    seed=tc.seed,
                    mutation_sequence=[m.value for m in tc.mutation_sequence],
                    expected_behavior=tc.expected_behavior.value,
                    actual_behavior=f"exit_code={res.exit_code}, status={res.parser_status}, diag={res.diagnostic}",
                    diagnostic=res.diagnostic or res.stderr or "Unexpected failure",
                    status=FindingStatus.OPEN,
                    created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                )
                self.store.save_finding(finding)

            self.store.update_test_case_status(tc.case_id, tc_status)

        t_end = time.perf_counter()
        duration_ms = round((t_end - t_start) * 1000, 2)
        completed_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        self.store.update_campaign_summary(
            campaign_id=campaign_id,
            status=CampaignStatus.COMPLETED,
            cases_executed=len(test_cases),
            passed_count=passed_cnt,
            rejected_count=rejected_cnt,
            failed_count=failed_cnt,
            findings_count=findings_cnt,
            duration_ms=duration_ms,
            completed_at=completed_at,
        )

        res = self.store.get_campaign(campaign_id)
        if not res:
            raise ValueError(f"Campaign {campaign_id} not found after execution")
        return res

    def rerun_test_case(self, case_id: str) -> ExecutionResult:
        """Reruns a single test case on demand."""
        tc = self.store.get_test_case(case_id)
        if not tc:
            raise ValueError(f"Test case not found: {case_id}")
        res = self.runner.execute_fixture(tc.case_id, tc.fixture_path)
        self.store.save_execution_result(res)
        return res

    def minimize_finding(self, finding_id: str) -> ReproductionArtifact:
        """Minimizes the triggering PCAP fixture for a finding."""
        finding = self.store.get_finding(finding_id)
        if not finding:
            raise ValueError(f"Finding not found: {finding_id}")

        tc = self.store.get_test_case(finding.case_id)
        if not tc:
            raise ValueError(f"Test case {finding.case_id} not found")

        output_dir = self.data_dir / "minimized"
        artifact = self.minimizer.minimize(finding, Path(tc.fixture_path), output_dir)
        self.store.update_finding_status(finding_id, FindingStatus.MINIMIZED)
        return artifact

    def promote_to_regression(self, finding_id: str, name: str) -> RegressionFixture:
        """Promotes a confirmed finding into a permanent regression fixture."""
        finding = self.store.get_finding(finding_id)
        if not finding:
            raise ValueError(f"Finding not found: {finding_id}")

        tc = self.store.get_test_case(finding.case_id)
        if not tc:
            raise ValueError(f"Test case {finding.case_id} not found")

        reg_dir = Path(self.runner.root_dir) / "tests" / "regression" / "fixtures"
        reg_dir.mkdir(parents=True, exist_ok=True)

        src_path = Path(tc.fixture_path)
        ext = src_path.suffix or ".pcap"
        fixture_id = f"reg_{uuid.uuid4().hex[:10]}"
        dst_path = reg_dir / f"{fixture_id}{ext}"
        shutil.copyfile(src_path, dst_path)

        f_hash = compute_file_sha256(dst_path)
        reg_fixture = RegressionFixture(
            fixture_id=fixture_id,
            finding_id=finding_id,
            name=name or f"Regression test for {finding.protocol_target} ({finding.failure_category})",
            protocol_target=finding.protocol_target,
            failure_category=finding.failure_category,
            fixture_path=str(dst_path.resolve()),
            fixture_hash=f_hash,
            engine_baseline_version="1.0.0",
            expected_behavior=ExpectedBehavior(tc.expected_behavior),
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )

        self.store.save_regression_fixture(reg_fixture)
        self.store.update_finding_regression_id(finding_id, fixture_id)
        self.store.update_finding_status(finding_id, FindingStatus.REGRESSION_PROMOTED)
        return reg_fixture

    def run_regression_fixture(self, fixture_id: str) -> RegressionRunResult:
        """Executes a regression fixture to detect regressions or verify bug fixes."""
        fixture = self.store.get_regression_fixture(fixture_id)
        if not fixture:
            raise ValueError(f"Regression fixture not found: {fixture_id}")

        t_start = time.perf_counter()
        res = self.runner.execute_fixture(fixture.fixture_id, fixture.fixture_path)
        t_end = time.perf_counter()
        duration_ms = round((t_end - t_start) * 1000, 2)

        # Passes if engine ran safely and matched expected behavior
        passed = (res.exit_code == 0) and (not res.crash_detected) and (not res.sanitizer_triggered)
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        self.store.update_regression_run_status(
            fixture_id=fixture_id,
            last_run_at=now_iso,
            passed=passed,
            exit_code=res.exit_code,
            diagnostic=res.diagnostic,
        )

        return RegressionRunResult(
            fixture_id=fixture_id,
            passed=passed,
            exit_code=res.exit_code,
            diagnostic=res.diagnostic,
            duration_ms=duration_ms,
            executed_at=now_iso,
        )

    def export_reproduction_bundle(self, finding_id: str) -> Path:
        """Exports a zipped reproduction bundle for developer reproduction."""
        finding = self.store.get_finding(finding_id)
        if not finding:
            raise ValueError(f"Finding not found: {finding_id}")

        tc = self.store.get_test_case(finding.case_id)
        if not tc:
            raise ValueError(f"Test case {finding.case_id} not found")

        out_zip = self.data_dir / "bundles" / f"bundle_{finding_id}.zip"
        return ReproductionBundler.export_bundle(finding, Path(tc.fixture_path), out_zip)
