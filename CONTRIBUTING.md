# Contributing to Protocol Digital Twin Platform

Thank you for your interest in contributing to the Protocol-Aware Network Digital Twin & Security Verification Engine.

## Code Standards & Invariants

1. **Architecture Boundaries**: Maintain strict separation between systems C++20 code, Python backend, TypeScript frontend, and canonical contracts.
2. **Deterministic Verification**: Tests must run hermetically and offline. Never commit tests that require live external cloud services or network access.
3. **Truthful Implementation**: Do not commit fake implementations, mock security findings, or artificial packet benchmarks. Label planned components as `planned`.
4. **Code Quality Gates**:
   - C++: Must compile with strict warnings (`/W4` on MSVC, `-Wall -Wextra` on GCC/Clang) and pass `protocol_engine_tests`.
   - Python: Must pass `ruff check` and `pytest`.
   - Frontend: Must pass `tsc --noEmit` and Vitest unit tests.
   - Contracts: All events must validate against `schemas/v1/network_event.schema.json`.

## Pull Request Process

1. Fork the repository and create a descriptive branch: `feature/xyz` or `fix/xyz`.
2. Ensure all quality gates pass locally before submitting:
   ```bash
   make test-all
   ```
3. Update documentation and roadmap items corresponding to your changes.
4. Submit the PR with a comprehensive summary of changes, executed commands, and test verification results.
