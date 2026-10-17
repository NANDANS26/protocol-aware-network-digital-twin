"""Safe execution harness for running generated PCAP/PCAPNG fixtures through the C++ protocol analysis engine."""

import json
import logging
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

import jsonschema

from network_twin.testing.models import ExecutionResult

logger = logging.getLogger(__name__)

WINDOWS_CRASH_CODES = {
    0xC0000005: "Access Violation (0xC0000005)",
    0xC000001D: "Illegal Instruction (0xC000001D)",
    0xC00000FD: "Stack Overflow (0xC00000FD)",
    0xC0000409: "Stack Buffer Overrun / Security Check Failure (0xC0000409)",
}


class EngineRunner:
    """Safe, sandboxed offline execution coordinator for the C++ protocol engine."""

    def __init__(self, binary_path: str | Path | None = None, schema_path: str | Path | None = None):
        cur = Path(__file__).resolve().parent
        while cur.parent != cur:
            if (cur / "pytest.ini").exists() and (cur / "schemas").exists():
                break
            cur = cur.parent
        self.root_dir = cur
        self.binary_path = self._resolve_binary(binary_path)
        self.schema_validator = self._load_schema_validator(schema_path)

    def _resolve_binary(self, override: str | Path | None) -> Path:
        if override:
            p = Path(override).resolve()
            if p.exists():
                return p

        # Check standard build artifact locations
        candidates = [
            self.root_dir / "build" / "engine" / "Release" / "protocol_engine.exe",
            self.root_dir / "build" / "engine" / "protocol_engine.exe",
            self.root_dir / "build" / "engine" / "Debug" / "protocol_engine.exe",
            self.root_dir / "build" / "engine" / "protocol_engine",
        ]
        for c in candidates:
            if c.exists():
                return c

        logger.warning("Could not find compiled protocol_engine binary in standard search paths.")
        return candidates[0]

    def _load_schema_validator(self, schema_path: str | Path | None) -> jsonschema.Draft202012Validator | None:
        p = Path(schema_path) if schema_path else (self.root_dir / "schemas" / "v1" / "network_event.schema.json")
        if p.exists():
            try:
                with open(p, encoding="utf-8") as f:
                    schema_data = json.load(f)
                return jsonschema.Draft202012Validator(schema_data)
            except Exception as e:
                logger.warning("Failed to initialize JSON schema validator: %s", e)
        return None

    def execute_fixture(
        self,
        case_id: str,
        fixture_path: str | Path,
        timeout_sec: float = 5.0,
        max_packets: int = 1000,
        fault_injection: str | None = None,
    ) -> ExecutionResult:
        """Executes the C++ protocol analyzer against a fixture safely and deterministically."""
        p_fixture = Path(fixture_path).resolve()
        result_id = f"exec_{int(time.time()*1000)}_{case_id}"

        # Controlled test harness fault injection
        if fault_injection == "CRASH":
            return ExecutionResult(
                result_id=result_id,
                case_id=case_id,
                exit_code=3221225477,
                stderr="CRASH: Injected Memory Access Violation (0xC0000005)",
                execution_time_ms=10.0,
                crash_detected=True,
                passed=False,
                diagnostic="Injected Memory Access Violation",
                executed_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            )
        if fault_injection == "HANG":
            return ExecutionResult(
                result_id=result_id,
                case_id=case_id,
                exit_code=-1,
                stderr=f"TIMEOUT: Execution exceeded hard limit of {timeout_sec}s",
                execution_time_ms=timeout_sec * 1000,
                passed=False,
                diagnostic=f"Process execution timed out after {timeout_sec}s",
                executed_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            )
        if fault_injection == "SCHEMA":
            return ExecutionResult(
                result_id=result_id,
                case_id=case_id,
                exit_code=0,
                schema_valid=False,
                schema_errors=["Field 'schema_version' is missing or malformed"],
                passed=False,
                diagnostic="Schema contract violation in generated events",
                executed_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            )

        if not p_fixture.exists():
            return ExecutionResult(
                result_id=result_id,
                case_id=case_id,
                exit_code=1,
                stderr=f"Fixture file not found: {p_fixture}",
                passed=False,
                diagnostic="Missing input fixture",
                executed_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            )

        if not self.binary_path.exists():
            return ExecutionResult(
                result_id=result_id,
                case_id=case_id,
                exit_code=1,
                stderr=f"Engine executable not found at: {self.binary_path}",
                passed=False,
                diagnostic="Missing engine binary",
                executed_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            )

        with tempfile.TemporaryDirectory() as tmpdir:
            out_events = Path(tmpdir) / "events.jsonl"
            out_summary = Path(tmpdir) / "summary.json"

            cmd = [
                str(self.binary_path),
                "--input",
                str(p_fixture),
                "--out",
                str(out_events),
                "--summary",
                str(out_summary),
                "--max-packets",
                str(max_packets),
            ]

            t_start = time.perf_counter()
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout_sec,
                    check=False,
                )
                t_end = time.perf_counter()
                duration_ms = (t_end - t_start) * 1000

                exit_code = proc.returncode
                stdout_str = proc.stdout
                stderr_str = proc.stderr

            except subprocess.TimeoutExpired as te:
                t_end = time.perf_counter()
                return ExecutionResult(
                    result_id=result_id,
                    case_id=case_id,
                    exit_code=-1,
                    stdout=te.stdout.decode() if isinstance(te.stdout, bytes) else (te.stdout or ""),
                    stderr=f"Engine hung: timeout after {timeout_sec}s",
                    execution_time_ms=(t_end - t_start) * 1000,
                    passed=False,
                    diagnostic=f"Execution timeout ({timeout_sec}s exceeded)",
                    executed_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                )

            # Analyze exit codes and sanitizers
            crash_detected = False
            diagnostic = None
            if exit_code in WINDOWS_CRASH_CODES or exit_code < 0:
                crash_detected = True
                diagnostic = WINDOWS_CRASH_CODES.get(exit_code, f"Process crashed with exit code {exit_code}")

            sanitizer_triggered = False
            if "AddressSanitizer" in stderr_str or "runtime error:" in stderr_str:
                sanitizer_triggered = True
                diagnostic = "Sanitizer violation detected in engine output"

            # Parse and validate events against canonical schema
            events: list[dict[str, Any]] = []
            schema_valid = True
            schema_errors: list[str] = []
            if out_events.exists():
                with open(out_events, encoding="utf-8") as f:
                    for line_idx, line in enumerate(f):
                        line_str = line.strip()
                        if not line_str:
                            continue
                        try:
                            ev = json.loads(line_str)
                            events.append(ev)
                            if self.schema_validator:
                                errors = list(self.schema_validator.iter_errors(ev))
                                if errors:
                                    schema_valid = False
                                    for err in errors:
                                        schema_errors.append(f"Line {line_idx+1}: {err.message}")
                        except json.JSONDecodeError as jde:
                            schema_valid = False
                            schema_errors.append(f"Line {line_idx+1}: Invalid JSON ({jde})")

            # Parse summary report
            parser_status = "ok"
            anomalies = []
            if out_summary.exists():
                try:
                    with open(out_summary, encoding="utf-8") as f:
                        summary_data = json.load(f)
                    anomalies = summary_data.get("anomalies", [])
                    st_counts = summary_data.get("parser_status_counts", {})
                    if st_counts.get("error", 0) > 0:
                        parser_status = "error"
                    elif st_counts.get("partial", 0) > 0:
                        parser_status = "partial"
                except Exception:
                    pass

            passed = (not crash_detected) and (not sanitizer_triggered) and schema_valid and (exit_code == 0)

            return ExecutionResult(
                result_id=result_id,
                case_id=case_id,
                exit_code=exit_code,
                stdout=stdout_str[:4096],
                stderr=stderr_str[:4096],
                execution_time_ms=round(duration_ms, 2),
                parser_status=parser_status,
                parsed_event_count=len(events),
                schema_valid=schema_valid,
                schema_errors=schema_errors[:10],
                anomalies_detected=anomalies[:10],
                sanitizer_triggered=sanitizer_triggered,
                crash_detected=crash_detected,
                passed=passed,
                diagnostic=diagnostic,
                executed_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            )
