# Protocol-Aware Network Digital Twin & Security Verification Engine

[![Phase 11 Reproducible Investigation Replay & Evidence Integrity](https://img.shields.io/badge/Phase%2011-Replay%20%26%20Integrity%20Verified-brightgreen)](#)
[![C++ Standard](https://img.shields.io/badge/C%2B%2B-20-blue)](#)
[![Python Version](https://img.shields.io/badge/Python-3.11%2B-blue)](#)
[![React](https://img.shields.io/badge/Frontend-React%20%2B%20TypeScript-blue)](#)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

An enterprise-grade, high-performance platform for network protocol analysis, stateful connection tracking, evidence-based topology reconstruction, versioned digital twinning, deterministic formal verification, isolated protocol fuzzing, predictive network world modeling, reproducible end-to-end benchmarking, adversarial verification hardening, real-capture differential testing, evidence-backed incident investigation, and reproducible investigation replay with cryptographic evidence integrity.

---

## 1. Product Mission & Long-Term Architecture

The platform provides a unified system combining low-latency systems software with formal methods:

1. **High-Performance C++20 Protocol Analysis Engine**: Zero-copy packet parsing across physical and virtual network interfaces.
2. **Protocol-Aware Flow & Connection-State Tracking**: Stateful TCP/UDP connection reconstruction and reassembly.
3. **Evidence-Based Network Topology Reconstruction**: Automated Layer-2 and Layer-3 host and interface discovery from observed traffic.
4. **Versioned Network Digital Twin**: Immutable state graph tracking network changes, device states, and active routes.
5. **Deterministic Security-Property Verification**: Formal invariant checking and automated counterexample generation.
6. **Counterfactual Network Simulation**: Predictive "what-if" testing on digital twin snapshots prior to change execution.
7. **Isolated Protocol Fuzzing & Differential Testing**: Deep parser verification, metamorphic testing, and automated delta minimization.
8. **Stateful Protocol Sequence Testing**: Multi-packet state-machine fuzzing, TCP transition checking, and differential testing.
9. **Predictive Network World Model**: Time-windowed feature extraction, baseline comparison, 90% conformal uncertainty intervals, Out-of-Distribution (OOD) distance gating, and deterministic ground-truth supremacy consensus.
10. **Reproducible Validation & Benchmarking**: End-to-end pipeline audit, ground-truth supremacy verification, versioned dataset fixtures, and empirical resource profiling.
11. **Adversarial Verification & Trustworthy Hardening**: Independent hand-verifiable oracles, snapshot immutability, elimination of false PASS on unresolved evidence, true subnet and port ACL shadowing detection, and parser resilience.
12. **Real-Capture Validation & Mathematical Differential Oracle**: Versioned capture corpus with verifiable provenance, independent pure Python reference decoder, metamorphic invariant testing (PCAP vs PCAPNG format equivalence, timestamp shifting, noise injection), and isolated native process memory telemetry.
13. **Evidence-Backed Incident Investigation & Root-Cause Analysis**: Strongly typed incident cases, epistemological evidence grounding (OBSERVED, INFERRED, SIMULATED, PREDICTED), zero-fabrication guardrails, 5 specialized workflows (Connectivity, Policy, DNS, Relationship, Changes), and isolated counterfactual remediation validation.
14. **Reproducible Investigation Replay & Cryptographic Evidence Integrity**: Immutable execution snapshots (`InvestigationExecutionRecord`), RFC 8785 canonical evidence serialization with SHA-256 fingerprinting, epistemological integrity disclaimers, deterministic replay engine (`REPLAY_IDENTICAL` vs `REPLAY_DIFFERENT`), structural finding diffing, and exportable audit packages.
15. **Professional React Engineering Workstation**: High-density dark engineering visual shell, incident investigation & replay cockpit, real-capture workbench, adversarial hardening workbench, benchmark workbench, predictive workbench, and telemetry cockpit.

---

## 2. Current Implementation Status (Phase 11 Operational)

Phase 11 delivers reproducible investigation replay and cryptographic evidence integrity built on top of the verified digital twin:

- **Epistemological Classification & Integrity Disclaimers**: Rigorous separation between `OBSERVED`, `INFERRED`, `SIMULATED`, and `PREDICTED` evidence, accompanied by mandatory disclaimers distinguishing cryptographic data integrity from external physical ground truth.
- **Cryptographic Evidence Hashing**: Canonical RFC 8785 JSON serialization with sorted keys and consistent float/datetime formatting. Generates per-item SHA-256 hashes and composite evidence graph digests.
- **Execution vs. Case Separation (Schema v8)**: Mutable incident case definitions (`investigation_cases`) are cleanly separated from immutable execution records (`investigation_executions`), maintaining full run lineage (`replay_of_execution_id`).
- **Deterministic Replay Engine**: Re-executes historical investigations against isolated digital twin states with strict input dependency validation (`REPLAY_NOT_POSSIBLE` if inputs missing), returning structural diffs (`ReplayComparison`) and bounded replay statuses (`REPLAY_IDENTICAL`, `REPLAY_DIFFERENT`, `REPLAY_INCOMPLETE`).
- **Verifiable Audit Packages**: Self-contained exportable JSON audit packages (`AuditPackExport`) bundling execution metadata, canonical evidence graphs, integrity reports, ranked findings, and step-by-step reproduction instructions.
- **REST API Contracts**: 6 endpoints under `/api/v1/twin/investigations` for execution history, verification, replay, diff comparison, and audit export.
- **React Replay Cockpit & Integrity Ledger**: Integrated into `InvestigationWorkbench.tsx` with Execution History table, inline cryptographic verification reports, Replay Comparison modal, and Audit Pack download modal.
- **Comprehensive Quality Gates**: 176 passed pytest tests (0 failures), 46 passed Vitest tests (0 failures), 100% C++ engine tests (26 doctest cases / 183 assertions), strict TypeScript (`tsc --noEmit`), and Ruff linting (0 errors).

See [docs/status/implementation-status.md](docs/status/implementation-status.md), [docs/audits/phase10_investigation_audit.md](docs/audits/phase10_investigation_audit.md), and [docs/audits/phase11_replay_integrity_audit.md](docs/audits/phase11_replay_integrity_audit.md) for full audit reports.

---

## 3. Repository Organization

```
/
  apps/
    api/              # FastAPI Python backend service
    web/              # React + TypeScript + Vite + Tailwind workstation
  engine/
    protocol/         # C++20 network protocol analysis systems engine
  packages/
    contracts/        # Canonical cross-language bindings (Python, TS, C++)
  schemas/            # Canonical JSON Schema v1 definitions (Single Source of Truth)
  migrations/         # Database migrations (PostgreSQL / Alembic)
  tests/              # Cross-subsystem integration & smoke test suite
  docs/               # Technical specifications, ADRs, guides, roadmap
    architecture/     # System architecture & component specifications
    decisions/        # Architecture Decision Records (ADR 0001)
    development/      # Developer workflow & setup guide
    testing/          # Testing strategy & automated quality gates
    operations/       # Security & safe-testing policy
    roadmap/          # Multi-phase roadmap & measurable exit criteria
    status/           # Component implementation status registry
  scripts/            # Cross-platform developer scripts (PowerShell & Bash)
  Makefile            # Root task runner
```

---

## 4. Prerequisites

- **C++20 Compiler**: Visual Studio 2022 (MSVC 19.34+) or GCC 11+ or Clang 14+.
- **CMake**: 3.20 or newer.
- **Python**: 3.11+ (Python 3.14 compatible).
- **Node.js**: Node 20+ with npm or pnpm.
- **Git**: 2.40+.

---

## 5. Quick Start

### One-Command Setup
Using PowerShell on Windows:
```powershell
.\scripts\dev.ps1 setup
```
Or using Make on POSIX/Linux:
```bash
make setup
```

### Running the Services

#### 1. Start the Backend API (FastAPI)
```powershell
.\scripts\dev.ps1 run-api
# Or: make run-api
```
- API Base: `http://127.0.0.1:8000`
- Interactive Swagger UI: `http://127.0.0.1:8000/docs`
- Health Endpoint: `http://127.0.0.1:8000/api/v1/health`

#### 2. Start the Frontend Workstation (React + Vite)
```powershell
.\scripts\dev.ps1 run-web
# Or: make run-web
```
- Workstation URL: `http://localhost:5173`

#### 3. Run the C++ Systems Engine Standalone
```powershell
# Generate 10 synthetic packets and inspect structured output
.\build\engine\Release\protocol_engine.exe --synthetic 10

# Inspect an existing PCAP capture file
.\build\engine\Release\protocol_engine.exe --pcap sample.pcap
```

---

## 6. Automated Quality Gates & Testing

To execute all quality gates across C++, Python, TypeScript, and contracts:

```powershell
.\scripts\dev.ps1 check-all
# Or: make check-all
```

Individual test suites:
- **C++ Engine Tests**: `.\scripts\dev.ps1 test-engine` or `ctest --test-dir build/engine -C Release --output-on-failure`
- **Backend Tests**: `.\scripts\dev.ps1 test-api` or `pytest apps/api/tests tests/integration`
- **Frontend Tests**: `.\scripts\dev.ps1 test-web` or `cd apps/web && npm run test`
- **TypeScript Typecheck**: `.\scripts\dev.ps1 typecheck` or `cd apps/web && npm run typecheck`
- **Python Linter**: `.\scripts\dev.ps1 lint` or `ruff check apps/api packages/contracts/python`

---

## 7. Next Implementation Target: Phase 01

With the Phase 00 foundation complete and verified, the exact next step is **Phase 01**:
- Full PCAP / PCAPNG parser implementation in `PcapFilePacketSource`.
- Zero-copy protocol decoders (Ethernet, 802.1Q, IPv4, IPv6, ARP, TCP, UDP, ICMP).
- Stateful bidirectional flow correlation (canonical 5-tuple hash) and TCP state machine tracking.
- High-throughput streaming IPC bridge between `protocol_engine` and Python control plane.

See [docs/roadmap/phases.md](docs/roadmap/phases.md) for the complete roadmap.
