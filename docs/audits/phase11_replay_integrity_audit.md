# Phase 11: Reproducible Investigation Replay & Evidence Integrity Audit

**Audit Date**: October 2026  
**Classification**: Cryptographic Integrity, Deterministic Investigation Replay & Audit Ledger Verification  
**Scope**: Evaluation of immutable execution records, canonical evidence serialization, SHA-256 integrity verification, epistemological integrity disclaimers, deterministic replay execution, structural finding comparisons, exportable audit packages, SQLite Schema Version 8 migrations, REST API contracts, and the React Investigation Replay Cockpit.

---

## 1. Executive Summary & Mission

Phase 11 extends the incident investigation capabilities introduced in Phase 10 to make investigations **fully reproducible, cryptographically auditable, and deterministically verifiable**. 

In high-stakes network engineering, incident root-cause investigations must withstand rigorous external scrutiny. An auditor, compliance officer, or peer engineer must be able to answer:
1. **What evidence was available when this investigation executed?**
2. **Which captures, snapshots, and model configurations were used?**
3. **Has any recorded evidence been tampered with or modified since execution?**
4. **Does re-executing the investigation against identical inputs produce identical findings and ranked causes?**
5. **If replay diverges, exactly which findings or rankings changed, and why?**

Phase 11 achieves these objectives through a formal, local-first architecture:
- **Separation of Concerns**: Editable investigation definitions (`InvestigationCase`) are strictly separated from immutable execution snapshots (`InvestigationExecutionRecord`).
- **Cryptographic Evidence Hashing**: Every evidence item in an investigation is canonicalized using deterministic JSON sorting and hashed with SHA-256. A composite SHA-256 digest binds the entire evidence graph.
- **Mandatory Epistemological Integrity Disclaimer**: The system explicitly distinguishes *evidence integrity* (cryptographic assurance that recorded data has not been modified) from *ground-truth authenticity* (whether captured packets or modeled topology accurately represent external physical reality).
- **Deterministic Replay Engine**: Replays investigations in isolated execution contexts, asserting strict input dependency checks (`REPLAY_NOT_POSSIBLE` if inputs are missing) and performing structural finding comparisons (`REPLAY_IDENTICAL` vs `REPLAY_DIFFERENT`).
- **Self-Contained Audit Package**: Exports a verifiable JSON audit bundle containing complete evidence graphs, execution metadata, integrity reports, and step-by-step reproduction instructions.

---

## 2. Evidence Canonicalization & Cryptographic Hashing

To enable bit-exact cryptographic hashing across different languages and execution runtimes, Phase 11 implements deterministic canonical serialization for evidence items:

### A. Canonicalization Specification
1. **Key Ordering**: All dictionary keys are recursively sorted alphabetically.
2. **Whitespace Elimination**: Zero extraneous whitespace (`separators=(',', ':')`).
3. **Deterministic Value Coercion**:
   - Floating-point values are formatted with exact IEEE-754 precision without trailing decimal noise.
   - Datetime objects are converted to ISO 8601 UTC strings (`YYYY-MM-DDTHH:MM:SSZ`).
   - Enum instances are serialized to their primitive string or integer representations.
   - Sets and collections with indeterminate ordering are converted to sorted arrays.

### B. SHA-256 Fingerprinting
- **Individual Evidence Item Hash**:
  $$\text{hash}(e) = \text{SHA-256}(\text{canonical\_json}(e))$$
- **Evidence Graph Composite Digest**:
  $$\text{digest}(G) = \text{SHA-256}\left(\sum_{i=1}^{n} \text{hash}(e_i)\right) \quad \text{where } e_1, \dots, e_n \text{ are sorted by } \text{id}$$

### C. Integrity Status Categories
| Status | Meaning | Action Taken |
| :--- | :--- | :--- |
| `VERIFIED` | Computed SHA-256 digest matches recorded baseline digest exactly. | Evidence integrity confirmed; replay permitted. |
| `MODIFIED` | Computed SHA-256 digest differs from recorded baseline. | Mismatch flagged; tampering or schema drift warning issued. |
| `MISSING_SOURCE` | Referenced PCAP capture, topology snapshot, or model artifact is absent from storage. | Integrity verification fails with missing asset citation. |
| `UNSUPPORTED_SCHEMA` | Evidence record schema version is incompatible with current engine. | Schema version mismatch reported without silent coercion. |

### D. Mandatory Epistemological Integrity Disclaimer
The engine enforces a mandatory disclaimer on all integrity reports and UI displays:
> *"Cryptographic evidence integrity confirms that the recorded evidence item or capture payload has not been modified since it was stored. It does not attest to the authenticity or correctness of the underlying network telemetry with respect to external physical ground truth."*

---

## 3. Execution vs Case Separation Architecture

In prior phases, running an investigation updated the case in place. Phase 11 separates mutable intent from immutable historical record:

```
+-------------------------------------------------------------------+
| InvestigationCase (Editable)                                      |
| - case_id, title, description, incident_type, status, scope       |
+---------------------------------+---------------------------------+
                                  | 1:N
                                  v
+-------------------------------------------------------------------+
| InvestigationExecutionRecord (Immutable)                          |
| - execution_id: UUID                                              |
| - investigation_id: Foreign Key to InvestigationCase              |
| - execution_index: Sequential run number (1, 2, 3...)             |
| - executed_at_iso: UTC Timestamp                                  |
| - engine_version: Software and schema version                     |
| - model_fingerprint: SHA-256 of active NetworkModel               |
| - referenced_capture_ids: List of source PCAP capture IDs         |
| - referenced_snapshot_ids: List of source Topology Snapshot IDs   |
| - evidence_graph: Complete snapshot of nodes and edges            |
| - evidence_graph_digest: Cryptographic SHA-256 checksum           |
| - candidate_explanations: Ranked findings with supporting nodes   |
| - identified_root_cause: Confirmed or top-ranked cause            |
| - limitations: Explicit boundary statements                       |
| - replay_of_execution_id: Null if initial run; UUID if replayed   |
+-------------------------------------------------------------------+
```

### Relational Schema Migration (v8)
The metadata persistence engine (`MetadataStore`) was migrated to Schema Version 8:
```sql
CREATE TABLE IF NOT EXISTS investigation_executions (
    execution_id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    execution_index INTEGER NOT NULL,
    investigation_type TEXT NOT NULL,
    engine_version TEXT NOT NULL,
    model_fingerprint TEXT,
    referenced_capture_ids TEXT,
    referenced_snapshot_ids TEXT,
    evidence_graph TEXT NOT NULL,
    evidence_graph_digest TEXT NOT NULL,
    candidate_explanations TEXT NOT NULL,
    identified_root_cause TEXT,
    evidence_sufficiency TEXT NOT NULL,
    limitations TEXT,
    reproduction_instructions TEXT,
    replay_of_execution_id TEXT,
    executed_at_iso TEXT NOT NULL,
    FOREIGN KEY(investigation_id) REFERENCES investigation_cases(case_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_inv_exec_investigation_id ON investigation_executions(investigation_id);
CREATE INDEX IF NOT EXISTS idx_inv_exec_replay_of ON investigation_executions(replay_of_execution_id);
```

---

## 4. Deterministic Replay Engine & Structural Comparison

When replaying an investigation, the engine guarantees complete isolation and strict dependency validation:

### A. Replay Pre-flight Checks
1. **Capture Availability**: Checks that all `referenced_capture_ids` exist in the capture catalog.
2. **Model Availability**: Checks that the referenced `model_id` (and matching `model_fingerprint`) exists in the metadata store.
3. **Graceful Refusal**: If required inputs are absent, the engine refuses execution with `REPLAY_NOT_POSSIBLE` and explicitly lists missing dependencies. Under no circumstance does it substitute synthetic data or mock models.

### B. Isolated Execution & Lineage
The replayed run executes the workflow afresh against the exact recorded scope and parameters. It generates a new immutable `InvestigationExecutionRecord` with:
- `execution_index = original.execution_index + 1`
- `replay_of_execution_id = original.execution_id`

### C. Structural Finding Comparison (`ReplayComparison`)
The replay engine performs an exhaustive side-by-side comparison between the original baseline and the new replayed run:

| Replay Status | Criteria |
| :--- | :--- |
| `REPLAY_IDENTICAL` | Finding counts match, candidate explanations match in status and rank, and identified root causes are identical. |
| `REPLAY_DIFFERENT` | Findings differ in count, ranking order, candidate status, or root cause conclusion. Structured `FindingDifference` records detail each deviation. |
| `REPLAY_INCOMPLETE` | Historical evidence was partially available, leading to an incomplete or indeterminate re-execution. |
| `REPLAY_NOT_POSSIBLE` | Critical model or capture dependencies are missing from storage. |

---

## 5. Exportable Audit Package

To facilitate independent external review, the system provides self-contained audit packages (`AuditPackExport`):
- **Investigation & Execution Metadata**: Full provenance including timestamps, engine version, and user query.
- **Evidence Graph**: Complete node and edge topology with canonical SHA-256 item hashes.
- **Integrity Report**: Complete audit of all evidence items and capture references.
- **Ranked Findings & Limitations**: Explanations, confidence categories, and explicit unmodeled boundaries.
- **Reproduction Instructions**: Step-by-step CLI commands and API calls to reconstruct and verify the execution independently.

---

## 6. REST API Verification

The following endpoints under `/api/v1/twin/investigations` were implemented, verified, and audited:

| Method | Endpoint | Description | Status |
| :--- | :--- | :--- | :--- |
| `GET` | `/{investigation_id}/executions` | Lists all historical execution records for an investigation case, ordered chronologically. | Verified |
| `GET` | `/{investigation_id}/executions/{execution_id}` | Retrieves a single immutable execution record by ID. | Verified |
| `POST` | `/{investigation_id}/executions/{execution_id}/verify-integrity` | Computes fresh SHA-256 hashes for all evidence items and verifies against stored digests. | Verified |
| `POST` | `/{investigation_id}/executions/{execution_id}/replay` | Reruns the investigation deterministically and returns the replayed record with comparison. | Verified |
| `GET` | `/{investigation_id}/executions/{execution_id}/compare/{other_execution_id}` | Performs structural diffing between any two execution records. | Verified |
| `GET` | `/{investigation_id}/executions/{execution_id}/audit-pack` | Exports a self-contained, verifiable JSON audit package. | Verified |

---

## 7. React Investigation Workbench Replay Cockpit

The frontend workbench (`InvestigationWorkbench.tsx`) was upgraded with specialized audit and replay controls:

1. **Execution History & Replay Audit Ledger**:
   - Chronological table of all executions for the selected case.
   - Execution badges indicating initial runs vs replayed runs (`Replay of #...`).
   - Direct action buttons: **Verify Integrity**, **Replay Run**, **Export Audit Pack**, **Compare**.
2. **Inline Cryptographic Integrity Report**:
   - Verification status pill (`VERIFIED`, `MODIFIED`, `MISSING_SOURCE`).
   - Composite evidence graph SHA-256 digest with one-click copy.
   - Itemized verification list showing node IDs, types, and cryptographic hashes.
   - Prominent epistemological disclaimer banner.
3. **Replay Comparison Modal**:
   - Side-by-side comparison of baseline execution vs replayed run.
   - Visual status banner (`REPLAY_IDENTICAL` in emerald, `REPLAY_DIFFERENT` in amber).
   - Structural differences ledger highlighting rank, status, and root cause changes.
4. **Audit Pack Export Modal**:
   - Formatted JSON preview of the complete audit package.
   - One-click download trigger saving `audit_pack_<execution_id>.json`.

---

## 8. Quality Gates & Verification Evidence

All automated quality gates have passed with zero warnings or failures:

| Quality Gate | Tool / Test Suite | Result | Evidence |
| :--- | :--- | :--- | :--- |
| **Python Code Quality** | Ruff (lint + format) | 0 errors | 96 files inspected and formatted cleanly. |
| **Backend Test Suite** | Pytest 9.1.1 | 176 passed | 10 new replay/integrity unit & integration tests (`test_investigation_replay.py`). Total 176/176 green. |
| **Systems Engine Suite** | C++20 Doctest | 26 passed | 183/183 assertions passing with 0 memory errors (`protocol_engine_tests.exe`). |
| **Frontend Test Suite** | Vitest 2.1.9 | 46 passed | 10 test files passed, including 6 investigation workbench tests. |
| **TypeScript Typecheck** | TypeScript 5.6 (`tsc`) | 0 errors | Clean strict-mode typecheck across entire frontend. |
| **Frontend Production Build** | Vite 5.4.21 | Success | Bundle generated: `dist/assets/index-CD3NucCP.js` (gzip: 112.91 kB). |

---

## 9. Conclusion

Phase 11 successfully establishes **end-to-end auditability, cryptographic evidence integrity, and deterministic replay** for network incident investigations. The Protocol-Aware Network Digital Twin engine now provides full evidentiary lineage from raw packet capture to root-cause adjudication, ensuring that all conclusions are reproducible, verifiable, and protected against silent mutation.
