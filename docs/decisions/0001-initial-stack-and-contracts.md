# Architecture Decision Record (ADR) 0001
## Selection of Initial Technology Stack, Canonical Contracts, and Serialization Format

- **Status**: Accepted
- **Date**: 2026-10-17
- **Deciders**: Systems Engineering, Security Architecture, Backend & Frontend Leads

---

## 1. Context and Problem Statement

The Protocol-Aware Network Digital Twin platform requires:
1. Low-latency, deterministic, zero-copy packet processing in the data plane.
2. An asynchronous, type-safe API control plane for orchestration, metadata storage, and formal verification queries.
3. A responsive, typed, accessible engineering workstation.
4. A canonical, language-neutral structured-event contract shared across C++20, Python, and TypeScript without duplicated, drift-prone schemas.
5. Strict local reproducibility without relying on commercial APIs or unneeded distributed middleware.

---

## 2. Decision Drivers

- **Performance & Control**: In-kernel or raw socket packet ingestion demands native memory layout, deterministic resource boundaries, and zero runtime garbage collection pauses.
- **Contract Uniformity**: Events emitted by the C++ engine must be strictly consumable by Python validation models and TypeScript frontend visualizations without semantic divergence.
- **Developer Ergonomics**: Rapid local development on Linux, macOS, and Windows without mandatory container hypervisors or paid cloud dependencies.
- **Safety & Verification Grounding**: Truthful reporting of system states; no fabricated mock data.

---

## 3. Considered Options

### Strategy A: Protocol Buffers (Protobuf) + gRPC
- *Pros*: Binary serialization, generated code across languages, high wire efficiency.
- *Cons*: Requires `protoc` build-time tooling, compiler plugins, and binary payload decoding proxies for browser HTTP fetch in early foundation stages.

### Strategy B: Canonical JSON Schema (Draft 2020-12) with Native Language Bindings
- *Pros*: Language-neutral, human-readable for security auditing, native support in Python (Pydantic v2 / `jsonschema`), TypeScript (`packages/contracts/ts`), and C++ (`std::string` JSON serialization / struct mapping). Works out of the box with OpenAPI / Swagger UI without translation layers.
- *Cons*: Slightly larger wire size than Protobuf for massive raw packet captures (addressed in Phase 01/02 via Apache Arrow / binary ring buffers for bulk capture).

### Strategy C: Ad-Hoc TypeScript Interfaces / Pydantic Models
- *Pros*: Fast initial prototyping.
- *Cons*: High risk of schema drift between backend, frontend, and C++ engine.

---

## 4. Decision Outcome

We selected **Strategy B: Canonical JSON Schema as the Single Source of Truth**, supplemented by:
- **C++20** with CMake and `IPacketSource` abstraction for the systems engine.
- **Python 3.11+ / FastAPI / Pydantic v2** for the control and validation plane.
- **React / TypeScript in strict mode / Vite / Tailwind CSS** for the engineering workstation.
- **PostgreSQL / DuckDB** for relational catalog and high-speed analytical storage in subsequent phases.

### Contract Justification
1. The canonical schema is defined at `schemas/v1/network_event.schema.json`.
2. Python models in `packages/contracts/python` strictly mirror the JSON Schema and validate every field with `extra="forbid"`.
3. TypeScript interfaces in `packages/contracts/ts` mirror the JSON Schema in strict mode.
4. C++ structs in `packages/contracts/cpp` provide typed representation and JSON serialization.
5. In Phase 01/02, when packet ingestion rates exceed 1M packets/sec, zero-copy Arrow/FlatBuffers IPC will be added for the high-volume data path while preserving the JSON Schema as the canonical semantic contract.

---

## 5. Consequences

- **Positive**:
  - Full interoperability across C++, Python, and browser frontends.
  - Zero external code-generation binaries required to build or test.
  - Automated schema validation verified via `jsonschema.Draft202012Validator`.
  - Zero-trust sensitive data handling enforced at the schema level (`payload_hash_sha256` instead of raw payload logging).
- **Negative / Risks**:
  - Requires maintaining contract fidelity across language packages when schema revisions occur (mitigated by automated cross-language quality gate tests).
