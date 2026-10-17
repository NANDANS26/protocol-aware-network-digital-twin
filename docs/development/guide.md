# Developer Guide: Protocol-Aware Network Digital Twin Platform

## 1. Prerequisites and Tooling

To develop, build, and test all platform components locally, install:
- **C++20 Toolchain**:
  - Windows: Visual Studio 2022 (MSVC 19.34+) or MinGW-w64 with GCC 11+ or Clang 14+.
  - Linux: GCC 11+ or Clang 14+, CMake 3.20+.
  - macOS: Xcode Command Line Tools 14+, CMake 3.20+.
- **Python**: Python 3.11+ (tested on Python 3.14).
- **Node.js**: Node 20+ (tested on Node v24) and npm / pnpm.
- **Git**: Version 2.40+.

---

## 2. Directory Structure Overview

```
/
  apps/
    api/              # FastAPI Python backend application
    web/              # React + Vite + Tailwind CSS workstation
  engine/
    protocol/         # C++20 network protocol analysis systems engine
  packages/
    contracts/        # Canonical language bindings (Python, TypeScript, C++)
  schemas/            # Versioned JSON Schemas (Single Source of Truth)
  migrations/         # Database migrations (Alembic / PostgreSQL)
  tests/              # Cross-subsystem integration tests and fixtures
  docs/               # Architecture, ADRs, Development, Testing, Operations
  scripts/            # Developer automation scripts (cross-platform & PowerShell)
  Makefile            # Unified task runner
```

---

## 3. Quick Start & Setup

### A. Automatic Setup
Using make:
```bash
make setup
```
Or using PowerShell on Windows:
```powershell
.\scripts\dev.ps1 setup
```

### B. Manual Step-by-Step Setup

1. **Python Virtual Environment & Dependencies**:
   ```bash
   python -m venv .venv
   # Windows:
   .\.venv\Scripts\python -m pip install -r apps/api/requirements-dev.txt
   .\.venv\Scripts\python -m pip install -e packages/contracts/python
   .\.venv\Scripts\python -m pip install -e apps/api

   # Linux/macOS:
   ./.venv/bin/python -m pip install -r apps/api/requirements-dev.txt
   ./.venv/bin/python -m pip install -e packages/contracts/python
   ./.venv/bin/python -m pip install -e apps/api
   ```

2. **Frontend Dependencies**:
   ```bash
   cd apps/web
   npm install
   cd ../..
   ```

3. **C++20 Systems Engine Build**:
   ```bash
   cmake -B build/engine -S engine/protocol
   cmake --build build/engine --config Release
   ```

---

## 4. Running the Applications

### Starting the Backend API
```bash
# Using Makefile
make run-api

# Or directly:
.\.venv\Scripts\python -m uvicorn network_twin.main:app --host 127.0.0.1 --port 8000 --reload
```
API is accessible at `http://127.0.0.1:8000`.
Interactive Swagger UI is available at `http://127.0.0.1:8000/docs`.

### Starting the Frontend Workstation
```bash
# Using Makefile
make run-web

# Or directly:
cd apps/web && npm run dev
```
Workstation opens at `http://localhost:5173`.

### Running the C++ Protocol Engine Directly
```bash
# Synthetic packet generator (10 packets)
.\build\engine\Release\protocol_engine.exe --synthetic 10

# PCAP file inspection
.\build\engine\Release\protocol_engine.exe --pcap path/to/capture.pcap
```

---

## 5. Packet Capture Permissions & Safety Guidelines

- **File-Based Captures**: PCAP parsing operates entirely in unprivileged user space. Administrator or root privileges are **not** required for running tests or inspecting existing files.
- **Live Interface Capture**: Live capture requires administrative privileges and an installed packet capture driver (Npcap on Windows, libpcap / AF_PACKET on Linux).
- **Safe Testing Policy**: Active packet injection or network configuration alteration is strictly quarantined behind explicit flags. The engine operates in passive observation mode by default.
