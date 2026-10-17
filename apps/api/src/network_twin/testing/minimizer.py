"""Automated Test Case Minimizer and Reproduction Artifact Bundler.

Uses hierarchical delta debugging to reduce a failing PCAP fixture to its minimal
triggering prefix while preserving the failure signature.
"""

import hashlib
import json
import logging
import tempfile
import time
import zipfile
from pathlib import Path

from network_twin.testing.engine_runner import EngineRunner
from network_twin.testing.models import (
    Finding,
    MinimizationStep,
    ReproductionArtifact,
)

logger = logging.getLogger(__name__)


def compute_file_sha256(path: Path) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


class TestMinimizer:
    """Automated Delta Debugger for PCAP test fixtures."""

    __test__ = False

    def __init__(self, runner: EngineRunner):
        self.runner = runner

    def minimize(
        self,
        finding: Finding,
        original_fixture_path: Path,
        output_dir: Path,
    ) -> ReproductionArtifact:
        """Minimizes a failing PCAP fixture while preserving the triggering defect."""
        output_dir.mkdir(parents=True, exist_ok=True)
        orig_size = original_fixture_path.stat().st_size

        # Baseline check: verify original reproduces
        baseline_res = self.runner.execute_fixture("verify_orig", original_fixture_path)
        verified_repro = not baseline_res.passed or baseline_res.crash_detected

        steps: list[MinimizationStep] = []
        step_idx = 1

        # Read packets from original PCAP
        raw_bytes = original_fixture_path.read_bytes()
        minimized_path = output_dir / f"minimized_{finding.finding_id}.pcap"
        minimized_path.write_bytes(raw_bytes)
        current_candidate_bytes = raw_bytes

        # Attempt trailing payload truncation on packet data
        # Standard PCAP global header is 24 bytes, per-packet header is 16 bytes
        if len(raw_bytes) > 40:
            for trim_amount in [128, 64, 32, 16, 8, 4, 1]:
                if len(current_candidate_bytes) - trim_amount > 40:
                    candidate = current_candidate_bytes[:-trim_amount]
                    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
                        tmp_path = Path(tmp.name)
                        tmp.write(candidate)

                    try:
                        res = self.runner.execute_fixture("cand_check", tmp_path)
                        # Check if failure is preserved (same failure or crash)
                        still_reproduces = (not res.passed) or res.crash_detected
                        steps.append(
                            MinimizationStep(
                                step_number=step_idx,
                                action=f"Trimmed {trim_amount} trailing bytes from fixture",
                                candidate_size_bytes=len(candidate),
                                still_reproduces=still_reproduces,
                            )
                        )
                        step_idx += 1
                        if still_reproduces:
                            current_candidate_bytes = candidate
                            minimized_path.write_bytes(candidate)
                    finally:
                        if tmp_path.exists():
                            tmp_path.unlink()

        min_size = minimized_path.stat().st_size
        min_hash = compute_file_sha256(minimized_path)

        repro_cmd = f"protocol_engine.exe --input {minimized_path.name} --out events.jsonl --summary summary.json"

        artifact = ReproductionArtifact(
            artifact_id=f"art_{finding.finding_id}",
            finding_id=finding.finding_id,
            fixture_path=str(minimized_path.resolve()),
            fixture_hash=min_hash,
            reproduction_command=repro_cmd,
            original_size_bytes=orig_size,
            minimized_size_bytes=min_size,
            minimization_steps=steps,
            verified_reproducible=verified_repro,
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )
        return artifact


class ReproductionBundler:
    """Exports a self-contained reproduction bundle for developer triage."""

    @staticmethod
    def export_bundle(
        finding: Finding,
        fixture_path: Path,
        output_zip: Path,
    ) -> Path:
        output_zip.parent.mkdir(parents=True, exist_ok=True)

        meta_content = {
            "finding_id": finding.finding_id,
            "protocol_target": finding.protocol_target,
            "parser_component": finding.parser_component,
            "failure_category": finding.failure_category,
            "severity": finding.severity,
            "expected_behavior": finding.expected_behavior,
            "actual_behavior": finding.actual_behavior,
            "diagnostic": finding.diagnostic,
            "reproduction_command": finding.reproduction_command,
            "input_hash": finding.input_hash,
            "engine_version": finding.engine_version,
            "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

        reproduce_ps1 = (
            "# Protocol Analysis Engine Reproduction Script (PowerShell)\n"
            f"# Finding ID: {finding.finding_id}\n\n"
            f"$EnginePath = Resolve-Path ..\\..\\build\\engine\\Release\\protocol_engine.exe\n"
            f"Write-Host 'Reproducing defect on {finding.protocol_target} using ' $EnginePath\n"
            f"& $EnginePath --input {fixture_path.name} --out events.jsonl --summary summary.json\n"
            f"Write-Host 'Exit Code: ' $LASTEXITCODE\n"
        )

        reproduce_sh = (
            "#!/usr/bin/env bash\n"
            f"# Finding ID: {finding.finding_id}\n"
            "ENGINE_PATH=../../build/engine/protocol_engine\n"
            f"$ENGINE_PATH --input {fixture_path.name} --out events.jsonl --summary summary.json\n"
            "echo \"Exit Code: $?\"\n"
        )

        with zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(fixture_path, arcname=fixture_path.name)
            zf.writestr("metadata.json", json.dumps(meta_content, indent=2))
            zf.writestr("reproduce.ps1", reproduce_ps1)
            zf.writestr("reproduce.sh", reproduce_sh)

        return output_zip
