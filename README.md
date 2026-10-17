# Protocol-Aware Network Digital Twin & Security Verification Engine

[![Phase 02 Twin](https://img.shields.io/badge/Phase%2002-Network%20Twin%20Verified-brightgreen)](#)
[![C++ Standard](https://img.shields.io/badge/C%2B%2B-20-blue)](#)
[![Python Version](https://img.shields.io/badge/Python-3.11%2B-blue)](#)
[![React](https://img.shields.io/badge/Frontend-React%20%2B%20TypeScript-blue)](#)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

An enterprise-grade, high-performance platform for network protocol analysis, stateful connection tracking, evidence-based topology reconstruction, versioned digital twinning, and deterministic formal security-property verification.

---

## 1. Product Mission & Long-Term Architecture

The platform provides a unified system combining low-latency systems software with formal methods:

1. **High-Performance C++20 Protocol Analysis Engine**: Zero-copy packet parsing across physical and virtual network interfaces.
2. **Protocol-Aware Flow & Connection-State Tracking**: Stateful TCP/UDP connection reconstruction and reassembly.
3. **Evidence-Based Network Topology Reconstruction**: Automated Layer-2 and Layer-3 host and interface discovery from observed traffic.
4. **Versioned Network Digital Twin**: Immutable state graph tracking network changes, device states, and active routes.
5. **Deterministic Security-Property Verification**: Formal invariant checking and automated counterexample generation.
6. **Counterfactual Network Simulation**: Predictive "what-if" testing on digital twin snapshots prior to change execution.
7. **Isolated Protocol Fuzzing & Differential Testing**: Deep parser verification and RFC compliance extraction.
8. **Constrained AI Investigation Agents**: Evidence-grounded agents with cryptographic proof linkages.
9. **Learned Network World Model**: Evaluated against deterministic verification baselines.
10. **Professional React Engineering Workstation**: High-density dark engineering visual shell and telemetry cockpit.

---

## 2. Current Implementation Status (Phase 02 Operational)

Phase 02 establishes a persistent, evidence-backed network intelligence layer and digital twin:

- **Persistent Relational Catalog (MetadataStore)**: SQLite with WAL mode, foreign keys, and versioned schema migrations storing captures, jobs, assets, segments, services, relationships, evidence records, snapshots, and configuration imports.
- **Columnar Event Store (AnalyticsStore)**: DuckDB + Parquet analytical storage for high-throughput packet events, supporting vector aggregation for `top-talkers` and `protocol-breakdown`.
- **Deterministic Identity Resolution**: Multi-dimensional correlation across IP, MAC, ARP, DNS, TLS SNI, and DHCP. Classifies identity as `CONFIRMED`, `PROBABLE`, `AMBIGUOUS`, `CONFLICTING`, or `UNRESOLVED` with explicit conflict explanations.
- **DNS & Service Correlation**: Bidirectional DNS transaction matching (0x0000 query/response correlation), A/AAAA/CNAME mapping to asset hostnames, and application protocol port mapping.
- **Subnet & Gateway Inference**: Algorithmic CIDR prefix inference (/24 for IPv4, /64 for IPv6) and candidate default gateway detection (.1, .254) strictly marked as `INFERRED`.
- **Configuration Importers**: Extensible importers for routing tables, ARP/neighbor tables, and CMDB device inventories (JSON/CSV) with strict schema validation.
- **Topology Graph Builder**: Typed nodes (`ASSET`, `SUBNET`, `SERVICE`, `ROUTER`) and edges (`OBSERVED_COMMUNICATION`, `SUBNET_ATTACHMENT`, `SERVICE_DEPENDENCY`, `CONFIGURED_ROUTE`) with explicit `EvidenceClass`.
- **Versioned Snapshots & Diff Engine**: Immutable snapshot creation with canonical SHA-256 fingerprinting, plus differential topology comparison generating evidence-backed structural explanations.
- **Network Intelligence REST API**: Full suite under `/api/v1/assets`, `/api/v1/segments`, `/api/v1/services`, `/api/v1/relationships`, `/api/v1/evidence`, `/api/v1/imports`, `/api/v1/topology`, `/api/v1/snapshots`, `/api/v1/analytics`.
- **React Network Twin Workstation**: 5-tab workstation view featuring Asset Explorer with identity diagnosis, interactive SVG Topology Graph with evidence-class filtering and node inspection, Auditable Evidence Inspector, Differential Snapshot Comparison with evidence explanations, and Configuration Ingestion & History.
- **Automated Pipeline**: C++ capture processing automatically converts output events to Parquet, executes identity resolution, extracts services and relationships, infers subnets, updates metadata catalog, and takes initial baseline snapshots. 34 pytest tests and 9 vitest tests passing.

See [docs/status/implementation-status.md](docs/status/implementation-status.md) for full status breakdown.

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
