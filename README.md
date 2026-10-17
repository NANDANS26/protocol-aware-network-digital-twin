# Protocol-Aware Network Digital Twin & Security Verification Engine

[![Phase 08 Adversarial Hardening & Verification](https://img.shields.io/badge/Phase%2008-Adversarial%20Hardening%20Verified-brightgreen)](#)
[![C++ Standard](https://img.shields.io/badge/C%2B%2B-20-blue)](#)
[![Python Version](https://img.shields.io/badge/Python-3.11%2B-blue)](#)
[![React](https://img.shields.io/badge/Frontend-React%20%2B%20TypeScript-blue)](#)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

An enterprise-grade, high-performance platform for network protocol analysis, stateful connection tracking, evidence-based topology reconstruction, versioned digital twinning, deterministic formal verification, isolated protocol fuzzing, predictive network world modeling, reproducible end-to-end benchmarking, and adversarial verification hardening.

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
12. **Professional React Engineering Workstation**: High-density dark engineering visual shell, adversarial hardening workbench, benchmark workbench, predictive workbench, and telemetry cockpit.

---

## 2. Current Implementation Status (Phase 08 Operational)

Phase 08 discovers, demonstrates, and rectifies semantic correctness failures across the entire twin pipeline:

- **Independent Hand-Verifiable Oracles**: Dedicated hardening subsystem (`apps/api/src/network_twin/hardening/`) with 10 deterministic test cases across 6 disciplines (`ROUTING_FORWARDING`, `SECURITY_ISOLATION`, `CONFIG_CONSISTENCY`, `PARSER_RESILIENCE`, `PREDICTIVE_INTEGRITY`, `METAMORPHIC_INVARIANCE`).
- **Elimination of False PASS**: Formal security verification hardened against incomplete or unmodeled evidence; all invariant checks strictly return `INDETERMINATE` with `ROUTING_INDETERMINATE` when reachability is inconclusive, eliminating unproven false confidence.
- **Routing & Forwarding Hardening**: Rectified cross-IP version mismatch exceptions, enforced administrative `DOWN` interface state blocking, detected self-referencing next-hop loops (`FORWARDING_LOOP_DETECTED`), and populated egress interface attribution on path hops.
- **True Subnet & Port ACL Shadowing**: Implemented algorithmic CIDR containment, transport protocol overlap, and port containment checking to catch superset deny rules shadowing subsequent subset permit rules.
- **C++ Systems Engine Non-Initial Fragment Resilience**: Hardened `analysis_pipeline.cpp` so non-initial IPv4/IPv6 fragments (`fragment_offset > 0`) bypass L4 TCP/UDP decoders without corrupting flow state.
- **Predictive World Model Split Protections**: Bounded train/test ratios ($0.05 \le \text{test\_ratio} \le 0.5$) and rejected datasets with $< 4$ samples or single-class degenerate targets.
- **Adversarial Hardening REST API**: 4 endpoints under `/api/v1/twin/hardening` (`GET /cases`, `POST /run`, `GET /latest`, and `GET /runs/{run_id}`).
- **React Adversarial Hardening Workbench**: Dedicated workbench tab (`AdversarialHardeningWorkbench.tsx`) featuring oracle catalog, category filters, hand-verifiable mathematical rationale, live execution telemetry, expected-vs-observed outcome diffs, and audit trail ledger.
- **Comprehensive Quality Gates**: 151 passed pytest tests (0 failures), 36 passed Vitest tests (0 failures), 100% C++ engine tests (26 doctest cases / 183 assertions), strict TypeScript (`tsc --noEmit`), and Ruff linting (0 errors).

See [docs/status/implementation-status.md](docs/status/implementation-status.md) and [docs/audits/phase08_hardening_audit.md](docs/audits/phase08_hardening_audit.md) for full audit reports.

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
