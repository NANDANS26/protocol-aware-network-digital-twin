"""Unit tests for Phase 07 benchmarking, real-world validation, and profiling."""

import pytest
from fastapi.testclient import TestClient

from network_twin.benchmarking.fixtures import BENCHMARK_FIXTURES, list_benchmark_fixtures
from network_twin.benchmarking.models import (
    BaselineComparisonStatus,
    BenchmarkCategory,
    BenchmarkProvenance,
)
from network_twin.benchmarking.runner import BenchmarkRunner
from network_twin.main import app
from network_twin.storage.metadata_store import MetadataStore


@pytest.fixture
def test_meta_store(tmp_path):
    from network_twin.config import AppSettings

    cfg = AppSettings(data_dir=str(tmp_path), database_url=None)
    return MetadataStore(cfg)


@pytest.fixture
def benchmark_runner(test_meta_store):
    return BenchmarkRunner(meta_store=test_meta_store)


@pytest.fixture
def client():
    return TestClient(app)


def test_benchmark_fixtures_registered():
    """Verify that all benchmark fixtures have valid metadata, categories, and hash integrity."""
    fixtures = list_benchmark_fixtures()
    assert len(fixtures) >= 5

    categories = {f.category for f in fixtures}
    assert BenchmarkCategory.HAND_VERIFIABLE_CORE in categories
    assert BenchmarkCategory.SECURITY_VIOLATION in categories
    assert BenchmarkCategory.MALFORMED_EDGE_CASES in categories
    assert BenchmarkCategory.SCALE_PROFILING in categories

    for f in fixtures:
        assert f.fixture_id in BENCHMARK_FIXTURES
        assert len(f.content_sha256) == 64
        assert f.expected_properties.ground_truth_rationale != ""


def test_benchmark_runner_handshake_core(benchmark_runner):
    """Verify deterministic execution and LPM reachability on hand-verifiable TCP handshake."""
    record = benchmark_runner.run_fixture("handshake-core")

    assert record.fixture_id == "handshake-core"
    assert record.provenance == BenchmarkProvenance.SYNTHETIC_FIXTURE
    assert record.status == "COMPLETED"
    assert record.deterministic.forwarding_status == "DELIVERED"
    assert record.deterministic.forwarding_matches_expected is True
    assert record.deterministic.invariant_status == "HOLD"
    assert record.deterministic.invariant_matches_expected is True
    assert record.consensus.consensus_status == "ALIGNED"
    assert record.consensus.ground_truth_held is True


def test_benchmark_runner_security_ssh_violation(benchmark_runner):
    """Verify ground truth supremacy: firewall ACL drop must be upheld in verification and consensus."""
    record = benchmark_runner.run_fixture("security-ssh-violation")

    assert record.fixture_id == "security-ssh-violation"
    assert record.status == "COMPLETED"
    assert record.deterministic.forwarding_status == "DROPPED_BY_FIREWALL"
    assert record.deterministic.forwarding_matches_expected is True
    assert record.deterministic.invariant_status == "VIOLATED"
    assert record.deterministic.invariant_matches_expected is True
    assert record.consensus.consensus_status == "DIVERGENT"
    assert record.consensus.ground_truth_held is True
    assert "firewall ACL drop supersedes statistical forecast" in record.consensus.explanation


def test_benchmark_runner_empty_pcap(benchmark_runner):
    """Verify graceful handling of 0-packet boundary edge case without parser crash."""
    record = benchmark_runner.run_fixture("empty-malformed-edge")

    assert record.fixture_id == "empty-malformed-edge"
    assert record.decoding.packets_decoded == 0
    assert record.status == "COMPLETED"
    assert record.deterministic.forwarding_matches_expected is True
    assert record.consensus.consensus_status == "COMPLEMENTARY"


def test_benchmark_runner_scale_profiling(benchmark_runner):
    """Verify multi-window traffic workload evaluation with baseline comparison and uncertainty intervals."""
    record = benchmark_runner.run_fixture("scale-profiling-workload")

    assert record.fixture_id == "scale-profiling-workload"
    assert record.status == "COMPLETED"
    assert record.decoding.packets_decoded >= 100
    assert record.decoding.throughput_pkts_per_sec >= 0.0

    # Predictive stage
    assert record.predictive is not None
    assert record.predictive.comparison_status in [
        BaselineComparisonStatus.BEATS_BASELINE,
        BaselineComparisonStatus.LAGS_BASELINE,
    ]
    assert record.predictive.conformal_coverage_pct == 90.0
    assert record.predictive.conformal_interval_mean_width is not None
    assert record.predictive.conformal_interval_mean_width > 0.0
    assert record.predictive.ood_in_dist_score is not None
    assert record.predictive.ood_shifted_score > record.predictive.ood_in_dist_score


def test_benchmark_rest_api_flow(client):
    """Test full REST API lifecycle for listing fixtures, triggering runs, and retrieving summaries."""
    # 1. List fixtures
    resp = client.get("/api/v1/benchmarks/fixtures")
    assert resp.status_code == 200
    fixtures = resp.json()
    assert len(fixtures) >= 5

    # 2. Trigger run on handshake fixture
    resp = client.post("/api/v1/benchmarks/run", json={"fixture_id": "handshake-core"})
    assert resp.status_code == 201
    summary = resp.json()
    assert summary["total_runs"] >= 1
    assert summary["deterministic_accuracy_pct"] == 100.0

    # 3. List runs
    resp = client.get("/api/v1/benchmarks/runs")
    assert resp.status_code == 200
    runs = resp.json()
    assert len(runs) >= 1
    run_id = runs[0]["run_id"]

    # 4. Get specific run
    resp = client.get(f"/api/v1/benchmarks/runs/{run_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["run_id"] == run_id

    # 5. Get summary
    resp = client.get("/api/v1/benchmarks/summary")
    assert resp.status_code == 200
    summary = resp.json()
    assert summary["total_runs"] >= 1
