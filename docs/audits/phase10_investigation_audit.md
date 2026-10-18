# Phase 10: Evidence-Backed Network Incident Investigation & Root-Cause Analysis Audit

**Audit Date**: October 2026  
**Classification**: Formal Explainability, Grounded Incident Investigation & Counterfactual Remediation Audit  
**Scope**: Evaluation of typed incident models, epistemological evidence grounding, deterministic candidate ranking, anti-fabrication controls, isolated counterfactual simulation, API contracts, and the React Investigation Workbench.

---

## 1. Executive Summary & Mission

Phase 10 delivers a deterministic, explainable network incident investigation subsystem built on the Protocol-Aware Network Digital Twin & Security Verification Engine. Prior phases established deep packet inspection, topology reconstruction, deterministic reachability, security invariants, fuzzing, sequence testing, predictive models, adversarial verification, and capture validation. 

Phase 10 synthesizes these verified subsystems into an incident investigation workbench that:
1. **Requires Concrete Evidence Provenance**: Every assertion links directly to recorded evidence (decoded frames, flows, DNS/TLS metadata, topology nodes, routing entries, ACL rules, deterministic forwarding traces, or invariant evaluations).
2. **Enforces Strict Epistemological Distinctions**: Evidence items are explicitly classified as `OBSERVED`, `INFERRED`, `SIMULATED`, or `PREDICTED`. Simulated forwarding traces or statistical forecasts are never presented as observed ground truth.
3. **Implements Zero-Fabrication Guardrails**: When data is missing, unmodeled, or inconclusive, the engine strictly reports `INDETERMINATE` or `INSUFFICIENT_EVIDENCE`. Under no circumstance does the system invent packet IDs, MAC addresses, route configurations, or confirmed root causes.
4. **Executes 5 Specialized Deterministic Workflows**: Covers Connectivity Failures, Unexpected Policy Decisions, DNS/Service-Resolution Failures, Unexpected Traffic Relationships, and Change-Related Differential Behavior.
5. **Provides Isolated Counterfactual Verification**: Allows operators to test hypothetical remedial actions (e.g. restoring an interface to `UP`, adding a route, modifying firewall filters) in isolated digital twins without altering production baseline models.

---

## 2. Epistemological Evidence Framework

Every evidence item in the investigation graph carries a mandatory, non-negotiable classification:

| Evidence Class | Semantic Meaning | Concrete Origin | Example in Digital Twin |
| :--- | :--- | :--- | :--- |
| `OBSERVED` | Directly captured, empirically recorded packet or socket telemetry | Raw PCAP/PCAPNG capture frames, decoded protocol headers, observed flow records | Decoded DNS query with RCODE=NXDOMAIN, observed TCP SYN retransmissions |
| `INFERRED` | Statistically or heuristically derived state from multiple observations | GraphBuilder asset clustering, heuristic service resolution, subnet membership | Host asset inferred from MAC/IP observations, subnet IP range |
| `SIMULATED` | Deterministically generated state from formal forwarding and invariant models | `ForwardingEngine`, `VerificationEngine`, `ScenarioEngine` | Hop-by-hop forwarding trace, ACL rule match, interface administrative state check |
| `PREDICTED` | Statistical forecast or world-model projection subject to uncertainty | Phase 06 predictive models (arrival rates, forecast volume, change probability) | Forecasted flow volume, predicted topology drift probability |

### Epistemological Rules:
- An `INFERRED` or `SIMULATED` entity can **never** be labeled `OBSERVED`.
- A missing observation can **never** be replaced by an ungrounded inference.
- Explanations dependent on unmodeled topology are explicitly bounded with `CandidateStatus.INDETERMINATE`.

---

## 3. Explanation Ranking & Status Categories

Candidate explanations are deterministically ranked based on evidence graph connectivity and consistency rules without subjective confidence fabrication:

| Candidate Status | Mathematical / Evidentiary Criteria | System Assertion |
| :--- | :--- | :--- |
| `CONFIRMED_WITHIN_MODEL_SCOPE` | Formal forward simulator or packet decoder isolates the exact rule, interface, or response that deterministically explains the outcome with zero contradictions. | Deterministic proof within the bounds of the configured twin model. |
| `SUPPORTED_HYPOTHESIS` | Plausible structural explanation supported by observed flows and topology, but unobservable hardware or external state leaves partial ambiguity. | Strong evidentiary support; hardware carrier or upstream transit unverified. |
| `INDETERMINATE` | Multiple conflicting explanations exist with equal evidentiary support, or model scope is insufficient to disambiguate. | Ambiguous; engine refuses to select a definitive cause. |
| `INSUFFICIENT_EVIDENCE` | Critical endpoints, packets, or routes are absent from both captures and digital twin configurations. | Insufficient telemetry; investigation halts without speculative assertions. |

---

## 4. Specialized Deterministic Investigation Workflows

### A. Connectivity Failure Workflow
- **Scope**: Source IP, Destination IP, Protocol, Port, Model ID.
- **Trace Analysis**: Evaluates hop-by-hop longest-prefix-match (LPM) routing, next-hop resolution, interface administrative state (`UP` vs `DOWN`), and firewall filter drops.
- **Verification Result**: If an interface on the selected route is `DOWN`, the engine produces a `CONFIRMED_WITHIN_MODEL_SCOPE` candidate with supporting evidence `ev-cfg-interface-down` and `ev-sim-forwarding-result`. If source/destination nodes are unmodeled, it strictly returns `INDETERMINATE`.

### B. Unexpected Policy Decision Workflow
- **Scope**: Traffic endpoint tuple and expected vs observed action (`PERMIT` vs `DENY`).
- **Policy Analysis**: Evaluates ordered firewall rules on ingress/egress interfaces.
- **Verification Result**: Distinguishes between explicit rule matches (`ReasonCode.DROPPED_BY_FIREWALL`), default policy drops (`ReasonCode.DROPPED_BY_DEFAULT_POLICY`), rule shadowing, and incomplete model definitions.

### C. DNS & Service-Resolution Workflow
- **Scope**: Target hostname, time window, capture ID.
- **Protocol Analysis**: Scans DNS metadata for query/response transactions matching target hostname.
- **Verification Result**:
  - Validates non-zero RCODEs (e.g. `NXDOMAIN` RCODE 3, `SERVFAIL` RCODE 2).
  - Detects unresponded queries (query transmitted with zero corresponding response within timeout).
  - Confirms zero-traffic scenarios (hostname never queried in capture), generating `CandidateStatus.INSUFFICIENT_EVIDENCE`.

### D. Unexpected Traffic Relationship Workflow
- **Scope**: Source IP, Destination IP, observed flows vs topology graph.
- **Topology Analysis**: Compares observed communication relationships against reconstructed topology paths.
- **Anti-Fabrication Guardrail**: Explicitly disclaims physical topology assertions. Reports: *"Observed traffic between endpoints lacking modeled direct adjacency does not prove a rogue physical link or malicious intent; traffic may traverse unmodeled layer-2 switching, NAT, or VPN tunnels."*

### E. Change-Related Differential Behavior Workflow
- **Scope**: Baseline snapshot ID, Target snapshot ID, endpoint query.
- **Differential Analysis**: Correlates structural mutations (node additions/removals, route prefix modifications, interface state changes) between two fingerprinted digital twin snapshots against forwarding path alterations.

---

## 5. Isolated Counterfactual Investigation Subsystem

To test proposed incident remediations, the investigation engine provides isolated hypothetical simulation:
1. **Isolated Model Cloning**: Deep-copies the baseline digital twin model (`copy.deepcopy(model)`) with a unique `model_cf_*` identifier, ensuring baseline state is never mutated.
2. **Targeted Mutation**: Applies formal simulation actions (`SET_INTERFACE_STATE`, `ADD_FIREWALL_RULE`, `ADD_ROUTE`) through `ScenarioEngine`.
3. **Reachability Re-evaluation**: Executes the exact reachability query across the counterfactual model.
4. **Side-by-Side Comparison**: Compares baseline vs counterfactual status, yielding a verified `REMEDIAL_ACTION_CONFIRMED` outcome when a blocked path becomes reachable.

---

## 6. Persistence & Storage Migrations

The metadata persistence layer has been upgraded to Schema Version 7:
- **Migration**: Implemented `_migrate_to_v7()` in `MetadataStore`.
- **Relational Integrity**:
  ```sql
  CREATE TABLE IF NOT EXISTS investigation_cases (
      investigation_id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      investigation_type TEXT NOT NULL,
      scope_json TEXT NOT NULL,
      status TEXT NOT NULL,
      sufficiency TEXT NOT NULL,
      evidence_graph_json TEXT NOT NULL,
      candidate_explanations_json TEXT NOT NULL,
      primary_root_cause_id TEXT,
      counterfactual_comparisons_json TEXT NOT NULL,
      known_limitations_json TEXT NOT NULL,
      reproduction_steps_json TEXT NOT NULL,
      author TEXT NOT NULL,
      case_json TEXT NOT NULL
  );
  ```
- **Atomicity & Idempotency**: All writes utilize SQLite `ON CONFLICT(investigation_id) DO UPDATE` to ensure safe concurrent mutations.

---

## 7. REST API Contracts

All endpoints are registered under `/api/v1/twin/investigations`:

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/twin/investigations` | Creates a new typed investigation case with bounded scope. |
| `GET` | `/api/v1/twin/investigations` | Lists all saved investigation cases with summary sufficiency. |
| `GET` | `/api/v1/twin/investigations/{id}` | Retrieves full investigation case with evidence graph and candidate explanations. |
| `POST` | `/api/v1/twin/investigations/{id}/execute` | Executes deterministic investigation workflow, populating evidence and ranking causes. |
| `POST` | `/api/v1/twin/investigations/{id}/counterfactual` | Executes isolated counterfactual remediation scenario and appends comparison. |
| `GET` | `/api/v1/twin/investigations/{id}/export` | Exports complete audit trail and reproduction instructions as JSON. |
| `DELETE` | `/api/v1/twin/investigations/{id}` | Permanently deletes an investigation case. |

---

## 8. React Investigation Workbench

The frontend has been extended with the `InvestigationWorkbench` tab in the Network Twin view:
- **Case Management**: Create, list, execute, export, and delete investigation cases.
- **Epistemological Badges**: Color-coded badges for `OBSERVED` (emerald), `INFERRED` (sky), `SIMULATED` (purple), and `PREDICTED` (amber).
- **Candidate Explanations**: Ranked cards with supporting evidence, contradicting evidence, missing telemetry, and score breakdown.
- **Evidence Graph**: Visual cards for every node in the correlated evidence graph with explicit source references.
- **Counterfactual Remediation Panel**: Side-by-side comparison of baseline status vs counterfactual status with `REMEDIAL_ACTION_CONFIRMED` validation badge.
- **Bounded Limitations & Reproduction Steps**: Clean presentation of epistemological bounds and exact step-by-step reproduction instructions.

---

## 9. Comprehensive Quality Gate Verification

All quality gates across C++, Python, and React have been executed with 100% pass rates:

| Verification Suite | Target | Result | Evidence |
| :--- | :--- | :---: | :--- |
| **Python Unit Tests** | `pytest apps/api/tests` | **166 / 166 PASSED** | All existing + 7 new Phase 10 investigation tests passing. |
| **Python Code Linting** | `ruff check apps/api` | **ALL CHECKS PASSED** | Zero linting or formatting defects. |
| **C++ Core Engine** | `protocol_engine_tests.exe` | **26 / 26 PASSED** | 183 doctest assertions passing. |
| **Frontend Unit Tests** | `vitest run` | **44 / 44 PASSED** | 10 test files passing (including `InvestigationWorkbench.test.tsx`). |
| **TypeScript Compilation** | `tsc --noEmit` | **0 ERRORS** | Full strict type checking clean across web application. |
| **Production Build** | `npm run build` | **BUILT IN 8.52s** | Zero bundling defects, optimized production assets generated. |

---

## 10. Audit Sign-off

The Phase 10 implementation fulfills all specifications:
- Zero fabricated root causes or synthetic evidence masquerading as observed network state.
- Strict epistemological boundary enforcement between observed traffic, structural inferences, simulated traces, and statistical forecasts.
- Deterministic investigation workflows across connectivity, policy, DNS, traffic relationships, and snapshot changes.
- Isolated counterfactual simulation confirming hypothetical remediations.
- Complete API contracts, persistent database migrations, and interactive React workstation.
