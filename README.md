# Protocol-Aware Network Digital Twin & Security Verification Engine

[![Phase 10 Evidence-Backed Network Investigations](https://img.shields.io/badge/Phase%2010-Incident%20Investigations%20Verified-brightgreen)](#)
[![C++ Standard](https://img.shields.io/badge/C%2B%2B-20-blue)](#)
[![Python Version](https://img.shields.io/badge/Python-3.11%2B-blue)](#)
[![React](https://img.shields.io/badge/Frontend-React%20%2B%20TypeScript-blue)](#)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

An enterprise-grade, high-performance platform for network protocol analysis, stateful connection tracking, evidence-based topology reconstruction, versioned digital twinning, deterministic formal verification, isolated protocol fuzzing, predictive network world modeling, reproducible end-to-end benchmarking, adversarial verification hardening, real-capture differential testing, and evidence-backed incident investigation.

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
14. **Professional React Engineering Workstation**: High-density dark engineering visual shell, incident investigation workbench, real-capture workbench, adversarial hardening workbench, benchmark workbench, predictive workbench, and telemetry cockpit.

---

## 2. Current Implementation Status (Phase 10 Operational)

Phase 10 delivers an evidence-grounded, explainable incident investigation subsystem built on top of the verified digital twin:

- **Epistemological Classification**: Rigorous separation between `OBSERVED` packet facts, `INFERRED` endpoint states, `SIMULATED` forwarding decisions, and `PREDICTED` statistical forecasts.
- **Strict Anti-Fabrication**: Unknown or unmodeled endpoints and packets produce explicit `INDETERMINATE` and `INSUFFICIENT_EVIDENCE` states; never fabricated confirmed causes.
- **5 Deterministic Investigation Workflows**:
  - *Connectivity Failure*: LPM routing, down interface detection, next-hop resolution, ACL drop tracing.
  - *Unexpected Policy Decision*: Firewall rule evaluation, default policy drops, rule shadowing detection.
  - *DNS & Service Resolution*: Non-zero RCODEs (NXDOMAIN/SERVFAIL), unresponded queries, zero-traffic detection.
  - *Unexpected Traffic Relationships*: Correlates observed flows vs reconstructed topology without rogue link fabrication.
  - *Change-Related Behavior*: Snapshot mutation diffing isolating structural and route alterations.
- **Isolated Counterfactual Remediation**: Deep-clones twin models in isolation, applies hypothetical mutations (`SET_INTERFACE_STATE`, `ADD_FIREWALL_RULE`, `ADD_ROUTE`), and verifies `REMEDIAL_ACTION_CONFIRMED` outcomes side-by-side.
- **Persistence & API Contracts**: SQLite Schema Version 7 migration (`investigation_cases`), 7 REST endpoints under `/api/v1/twin/investigations`.
- **React Incident Investigation Workbench**: Dedicated interactive workbench (`InvestigationWorkbench.tsx`) with workflow selector, epistemological badges, ranked root cause cards, evidence timeline/graph visualizer, side-by-side counterfactual comparisons, bounded limitations, and reproducible evidence instructions.
- **Comprehensive Quality Gates**: 166 passed pytest tests (0 failures), 44 passed Vitest tests (0 failures), 100% C++ engine tests (26 doctest cases / 183 assertions), strict TypeScript (`tsc --noEmit`), and Ruff linting (0 errors).

See [docs/status/implementation-status.md](docs/status/implementation-status.md), [docs/audits/phase09_capture_audit.md](docs/audits/phase09_capture_audit.md), and [docs/audits/phase10_investigation_audit.md](docs/audits/phase10_investigation_audit.md) for full audit reports.

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
