"""Adversarial Verification Test Runner with persistent evidence storage."""

import json
import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path

from network_twin.config import settings
from network_twin.hardening.cases import ALL_ADVERSARIAL_CASES
from network_twin.hardening.models import (
    AdversarialRunSummary,
    AdversarialTestResult,
)

logger = logging.getLogger("network_twin.hardening.runner")


class AdversarialRunner:
    """Orchestrates execution of the adversarial verification suite."""

    def __init__(self, storage_dir: Path | None = None):
        self.storage_dir = storage_dir or (Path(settings.data_dir) / "hardening")
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def run_all(self) -> AdversarialRunSummary:
        """Runs all registered adversarial verification cases deterministically."""
        run_id = f"adv-run-{uuid.uuid4().hex[:12]}"
        logger.info("Starting adversarial verification run: %s", run_id)

        results: list[AdversarialTestResult] = []
        category_breakdown: dict[str, dict[str, int]] = {}

        for case_fn in ALL_ADVERSARIAL_CASES:
            res = case_fn()
            results.append(res)

            cat = res.category.value
            if cat not in category_breakdown:
                category_breakdown[cat] = {"total": 0, "passed": 0, "failed": 0}
            category_breakdown[cat]["total"] += 1
            if res.passed:
                category_breakdown[cat]["passed"] += 1
            else:
                category_breakdown[cat]["failed"] += 1

        total = len(results)
        passed = sum(1 for r in results if r.passed)
        failed = total - passed

        summary = AdversarialRunSummary(
            run_id=run_id,
            timestamp_iso=datetime.now(UTC).isoformat(),
            total_cases=total,
            passed_cases=passed,
            failed_cases=failed,
            all_passed=(failed == 0),
            category_breakdown=category_breakdown,
            results=results,
        )

        # Persist run summary to disk
        summary_path = self.storage_dir / f"{run_id}.json"
        with open(summary_path, "w", encoding="utf-8") as f:
            f.write(summary.model_dump_json(indent=2))

        # Update latest pointer
        latest_path = self.storage_dir / "latest.json"
        with open(latest_path, "w", encoding="utf-8") as f:
            f.write(summary.model_dump_json(indent=2))

        logger.info(
            "Adversarial run %s completed: %d/%d passed (%s)",
            run_id,
            passed,
            total,
            "SUCCESS" if summary.all_passed else "FAILURE",
        )
        return summary

    def get_latest_summary(self) -> AdversarialRunSummary | None:
        """Retrieves the most recent adversarial run summary, if available."""
        latest_path = self.storage_dir / "latest.json"
        if not latest_path.exists():
            return None
        try:
            with open(latest_path, encoding="utf-8") as f:
                data = json.load(f)
            return AdversarialRunSummary.model_validate(data)
        except Exception as e:
            logger.warning("Failed to load latest adversarial summary: %s", e)
            return None

    def get_run_by_id(self, run_id: str) -> AdversarialRunSummary | None:
        """Retrieves a specific run by ID."""
        run_path = self.storage_dir / f"{run_id}.json"
        if not run_path.exists():
            return None
        try:
            with open(run_path, encoding="utf-8") as f:
                data = json.load(f)
            return AdversarialRunSummary.model_validate(data)
        except Exception as e:
            logger.warning("Failed to load adversarial run %s: %s", run_id, e)
            return None
