"""Phase 07 End-to-End Integration Test: Reproducible Benchmarking & Network Twin Audit."""

import pytest
from network_twin.benchmarking.models import (
    BaselineComparisonStatus,
    BenchmarkCategory,
    BenchmarkProvenance,
)
from network_twin.benchmarking.runner import BenchmarkRunner
from network_twin.storage.metadata_store import MetadataStore


@pytest.fixture
def integrated_runner(tmp_path):
    from network_twin.config import AppSettings
    from network_twin.services.analysis_service import AnalysisService

    cfg = AppSettings(data_dir=str(tmp_path), database_url=None)
    store = MetadataStore(cfg)
    service = AnalysisService(cfg)
    return BenchmarkRunner(meta_store=store, analysis_service=service)


def test_phase07_end_to_end_validation_pipeline(integrated_runner):
    """Executes the full end-to-end benchmark suite validating all pipeline stages and ground-truth supremacy."""
    # 1. Run the entire benchmark suite
    summary = integrated_runner.run_suite(random_seed=42)

    assert summary.total_runs >= 5
    assert summary.verified_fixtures_count >= 5
    assert summary.deterministic_accuracy_pct == 100.0

    # 2. Inspect individual run records for stage-specific verification
    runs_by_fixture = {r.fixture_id: r for r in summary.runs}

    # A. Hand-Verifiable Core TCP Handshake
    hs = runs_by_fixture["handshake-core"]
    assert hs.provenance == BenchmarkProvenance.SYNTHETIC_FIXTURE
    assert hs.category == BenchmarkCategory.HAND_VERIFIABLE_CORE
    assert hs.decoding.packets_decoded == 3
    assert hs.deterministic.forwarding_status == "DELIVERED"
    assert hs.deterministic.forwarding_matches_expected is True
    assert hs.deterministic.invariant_status == "HOLD"
    assert hs.consensus.ground_truth_held is True

    # B. Microsegmentation Security Violation
    sec = runs_by_fixture["security-ssh-violation"]
    assert sec.category == BenchmarkCategory.SECURITY_VIOLATION
    assert sec.deterministic.forwarding_status == "DROPPED_BY_FIREWALL"
    assert sec.deterministic.forwarding_matches_expected is True
    assert sec.deterministic.invariant_status == "VIOLATED"
    assert sec.deterministic.invariant_matches_expected is True
    # Ground truth supremacy check: Statistical ML must NEVER convert dropped traffic into pass
    assert sec.consensus.consensus_status == "DIVERGENT"
    assert sec.consensus.ground_truth_held is True

    # C. Empty Capture Boundary
    empty = runs_by_fixture["empty-malformed-edge"]
    assert empty.category == BenchmarkCategory.MALFORMED_EDGE_CASES
    assert empty.decoding.packets_decoded == 0
    assert empty.status == "COMPLETED"

    # D. Scale Profiling Workload
    scale = runs_by_fixture["scale-profiling-workload"]
    assert scale.category == BenchmarkCategory.SCALE_PROFILING
    assert scale.decoding.packets_decoded >= 100
    assert scale.decoding.throughput_pkts_per_sec > 0.0
    assert scale.operational.total_runtime_ms > 0.0
    assert scale.operational.peak_memory_mb >= 0.0

    # Model evaluation on held-out windows
    assert scale.predictive is not None
    assert scale.predictive.comparison_status in [
        BaselineComparisonStatus.BEATS_BASELINE,
        BaselineComparisonStatus.LAGS_BASELINE,
    ]
    assert scale.predictive.conformal_coverage_pct == 90.0
    assert scale.predictive.conformal_interval_mean_width > 0.0
    assert scale.predictive.ood_shifted_score > scale.predictive.ood_in_dist_score

    # 3. Database Migration Integrity Check
    with integrated_runner.metadata_store._get_connection() as conn:
        cur = conn.execute("SELECT MAX(version) FROM schema_migrations;")
        assert cur.fetchone()[0] == 6

        cur = conn.execute("SELECT COUNT(*) FROM benchmark_runs;")
        assert cur.fetchone()[0] >= 5

        cur = conn.execute("SELECT COUNT(*) FROM benchmark_metrics;")
        assert cur.fetchone()[0] >= 5
