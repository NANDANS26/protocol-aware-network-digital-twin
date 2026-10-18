# Contributing to Protocol Digital Twin Platform

Thank you for contributing to the **Protocol-Aware Network Digital Twin & Security Verification Engine**.

---

## 1. Core Development Workflow (`main` Only)

All active development is conducted directly on the `main` branch. Pull requests are supported as CI safeguards, but feature branching is not used unless explicitly requested.

When making updates, follow this exact development lifecycle:

1. **Inspect Working Tree**: Inspect current working tree, uncommitted modifications, and recent history.
2. **Stay on `main`**: Ensure the active branch is `main`. Never switch to feature branches unless specifically requested.
3. **Synchronize**: Pull or fast-forward from `origin/main` cleanly without discarding local work.
4. **Implement**: Implement requested changes preserving architecture boundaries and contracts.
5. **Run Local Quality Gates**: Execute relevant test suites locally (C++ CTest, Python pytest, Ruff, TypeScript typecheck, Vitest).
6. **Review Diff & Exclude Secrets**: Inspect `git status` and `git diff` to ensure no `.env` files, keys, temporary databases, or machine artifacts are staged.
7. **Descriptive Commit**: Commit with a structured Conventional Commits message (`feat(...)`, `fix(...)`, `test(...)`, `docs(...)`).
8. **Push Directly to `main`**: Push committed changes directly to `origin/main`.
9. **Monitor GitHub Actions**: Inspect the resulting CI pipeline execution on GitHub Actions.
10. **Report Results**: Document the commit hash, modified files, test results, and CI workflow status.

> **Caution**: Never use `git reset --hard`, force-push (`--force`), destructive cleanups, or history rewriting as routine fixes.

---

## 2. Engineering Standards & Invariants

1. **Architecture Boundaries**:
   - Systems C++20 engine: zero-copy decoding, flow tracking, packet readers.
   - Python FastAPI service: digital twin graph, simulation, predictive modeling, typed investigations.
   - React TypeScript workstation: interactive engineering cockpits, evidence graphs, replay inspectors.
   - Canonical contracts: schemas in `schemas/v1/` and contract packages across C++, Python, and TypeScript.
2. **Truthful Implementation**:
   - Zero fabrication of packet metadata, synthetic benchmarks, or security invariants.
   - Epistemological distinction: strictly label data as `OBSERVED`, `INFERRED`, `SIMULATED`, or `PREDICTED`.
3. **Hermetic & Offline Tests**:
   - All tests must run hermetically and offline without external paid services or live cloud infrastructure.
4. **Automated Quality Gates**:
   - C++: Compiles with `/W4` (MSVC) or `-Wall -Wextra -Wpedantic` (GCC/Clang) and passes `ctest`.
   - Python: 100% clean with `ruff check`, `ruff format --check`, and passes all `pytest` suites.
   - Frontend: 100% clean with `tsc --noEmit`, all Vitest tests pass, and `vite build` succeeds.
