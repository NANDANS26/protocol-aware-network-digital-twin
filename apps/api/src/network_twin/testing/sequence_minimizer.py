"""
Sequence-Aware Delta Debugging Minimizer & Reproduction Bundler for Phase 05.

Performs hierarchical sequence minimization to remove unrelated flows, non-essential
packets, and redundant steps while strictly preserving the failure signature.
Exports standalone, self-contained reproduction bundles in ZIP format.
"""

from __future__ import annotations

import io
import json
import zipfile

from network_twin.testing.sequence_generators import sequence_to_pcap_bytes
from network_twin.testing.sequence_models import (
    ProtocolSequence,
    SequenceFinding,
    SequenceReproductionMetadata,
)
from network_twin.testing.sequence_runner import SequenceRunner


class SequenceMinimizer:
    """Minimizes multi-packet sequences by eliminating non-essential flows, steps, and bytes."""

    __test__ = False

    def __init__(self, runner: SequenceRunner | None = None):
        self.runner = runner or SequenceRunner(timeout_sec=5.0)

    def minimize(
        self,
        sequence: ProtocolSequence,
        finding: SequenceFinding,
        max_iterations: int = 15,
    ) -> tuple[ProtocolSequence, SequenceReproductionMetadata]:
        """
        Hierarchically minimizes the failing ProtocolSequence while verifying that
        each reduction still reproduces the target finding's failure category.
        """
        original_step_count = len(sequence.steps)
        current_steps = [s.model_copy() for s in sequence.steps]
        removed_indices: list[int] = []

        # 1. Coarse reduction: Remove unrelated noise packets
        i = len(current_steps) - 1
        while i >= 0:
            if current_steps[i].is_noise:
                candidate_steps = current_steps[:i] + current_steps[i + 1 :]
                for new_idx, st in enumerate(candidate_steps):
                    st.step_index = new_idx
                cand_seq = sequence.model_copy()
                cand_seq.steps = candidate_steps

                res, new_findings = self.runner.execute(cand_seq)
                if any(f.category == finding.category for f in new_findings) or (
                    res.crash_detected and finding.category.value == "CRASH"
                ):
                    current_steps = candidate_steps
                    removed_indices.append(i)
            i -= 1

        # 2. Backward elimination of non-handshake steps
        iteration = 0
        step_idx = len(current_steps) - 1
        while step_idx >= 3 and iteration < max_iterations:
            iteration += 1
            candidate_steps = current_steps[:step_idx] + current_steps[step_idx + 1 :]
            for new_idx, st in enumerate(candidate_steps):
                st.step_index = new_idx

            cand_seq = sequence.model_copy()
            cand_seq.steps = candidate_steps

            res, new_findings = self.runner.execute(cand_seq)
            reproduced = any(f.category == finding.category for f in new_findings)
            if finding.category.value == "CRASH" and res.crash_detected:
                reproduced = True

            if reproduced:
                current_steps = candidate_steps
                removed_indices.append(step_idx)
            step_idx -= 1

        minimized_seq = sequence.model_copy()
        minimized_seq.sequence_id = f"{sequence.sequence_id}-minimized"
        minimized_seq.steps = current_steps

        minimized_count = len(current_steps)
        reduction_ratio = (
            (original_step_count - minimized_count) / float(original_step_count) if original_step_count > 0 else 0.0
        )

        cli_cmd = f"protocol_engine.exe --input {minimized_seq.sequence_id}.pcap --out out.jsonl"
        ps1 = f"# Protocol Engine Sequence Reproduction Script (PowerShell)\n& .\\protocol_engine.exe --input .\\{minimized_seq.sequence_id}.pcap --out .\\out.jsonl\n"
        sh = f"#!/usr/bin/env bash\n./protocol_engine --input ./{minimized_seq.sequence_id}.pcap --out ./out.jsonl\n"

        meta = SequenceReproductionMetadata(
            finding_id=finding.finding_id,
            sequence_id=sequence.sequence_id,
            original_step_count=original_step_count,
            minimized_step_count=minimized_count,
            reduction_ratio=reduction_ratio,
            removed_steps=sorted(removed_indices),
            cli_command=cli_cmd,
            reproduction_script_ps1=ps1,
            reproduction_script_sh=sh,
        )

        return minimized_seq, meta


class SequenceReproductionBundler:
    """Creates a self-contained ZIP reproduction bundle for a sequence finding."""

    __test__ = False

    @staticmethod
    def create_bundle(
        sequence: ProtocolSequence,
        finding: SequenceFinding,
        metadata: SequenceReproductionMetadata,
    ) -> bytes:
        """Returns binary ZIP archive containing fixture, scripts, and metadata."""
        pcap_data = sequence_to_pcap_bytes(sequence)
        zip_buf = io.BytesIO()

        with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
            # 1. PCAP Fixture
            zf.writestr(f"{sequence.sequence_id}.pcap", pcap_data)

            # 2. Reproduction scripts
            zf.writestr("reproduce_sequence.ps1", metadata.reproduction_script_ps1)
            zf.writestr("reproduce_sequence.sh", metadata.reproduction_script_sh)

            # 3. Metadata JSON
            meta_dict = {
                "finding_id": finding.finding_id,
                "sequence_id": sequence.sequence_id,
                "title": finding.title,
                "category": finding.category.value,
                "severity": finding.severity.value,
                "root_cause_summary": finding.root_cause_summary,
                "original_steps": metadata.original_step_count,
                "minimized_steps": metadata.minimized_step_count,
                "reduction_ratio": metadata.reduction_ratio,
                "removed_steps": metadata.removed_steps,
                "reproduction_command": metadata.cli_command,
            }
            zf.writestr("metadata.json", json.dumps(meta_dict, indent=2))

        return zip_buf.getvalue()
