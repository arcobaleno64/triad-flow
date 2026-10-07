# Triad-Flow Phase 4.4 Specification: Advisory Promotion Qualification Campaign

- **Document ID**: `TF-SPEC-P44-0001`
- **Milestone Phase**: `Phase 4.4`
- **Target Release**: `v2.7.0`
- **Baseline Commit**: `29787d8b9e968e1be0324547126473ac59983d91`
- **Status**: `APPROVED / ACTIVE`
- **Authority Mode**: `SHADOW_DOGFOOD (Advisory / Observation Only, Zero Merge Authority)`
- **Effective Runtime Authority**: `NONE`
- **Input Cohort State**: `Post-005 Fresh Cohort: 7 / 15 consecutive cycles / 0 False Advance`

---

## 1. Context & Executive Purpose

Phase 4.3 (Track D1: Shadow Dogfooding) achieved complete empirical convergence at **30/30 maturity-counting cycles** and concluded with formal closure audit [`TF-AUDIT-D1-0001`](file:///C:/Users/arcobaleno/Documents/Code/triad-flow/docs/benchmarks/track-d1-convergence-audit.md). Under default-deny governance, the initial promotion request was adjudicated as `REJECTED / STRICT_HOLD` because cumulative historical receipts contained 3 False Advances.

Phase 4.4 is the **formal follow-on qualification campaign** designed to demonstrate that the post-remediation architecture (`LOOP2-SYSTEMIC-REMEDIATION-001..005`) reliably eliminates systemic false approvals across diverse real-world changes.

> **Non-Extension Invariant**: Phase 4.4 is a separate, independent milestone phase. The collection of cycles under Phase 4.4 does **not** reopen, modify, or extend the completed Phase 4.3 Track D1 observation ledger or its frozen audit [`TF-AUDIT-D1-0001`](file:///C:/Users/arcobaleno/Documents/Code/triad-flow/docs/benchmarks/track-d1-convergence-audit.md).

---

## 2. Milestone Boundary & Criteria

### 2.1 Entry Criteria (Gate In)
All of the following prerequisites must be verified before Phase 4.4 begins execution:
1. **Phase 4.3 Permanently Closed**: [`TF-AUDIT-D1-0001`](file:///C:/Users/arcobaleno/Documents/Code/triad-flow/docs/benchmarks/track-d1-convergence-audit.md) is committed, published to `main`, and permanently frozen.
2. **Historical Baseline Frozen**: Receipts `CYCLE-0001..0024` in [`docs/benchmarks/dogfood-receipts.jsonl`](file:///C:/Users/arcobaleno/Documents/Code/triad-flow/docs/benchmarks/dogfood-receipts.jsonl) remain immutable historical truth.
3. **Verified Ingested State**: The Post-005 Fresh Cohort begins strictly at **7 consecutive cycles / 0 False Advance** (`CYCLE-0025` through `CYCLE-0031`):
   - `CYCLE-0025` (`hyperium/hyper#4150`): Liveness & channel drainage (`DEGRADED / NEUTRAL_DISAGREEMENT`)
   - `CYCLE-0026` (`libgit2/libgit2#7394`): Pathspec delta identity (`APPROVE / MATCH`)
   - `CYCLE-0027` (`curl/curl#22853`): Cache namespace invalidation (`APPROVE / MATCH`)
   - `CYCLE-0028` (`netty/netty#17475`): Ref-count ownership race (`DEGRADED / NEUTRAL_DISAGREEMENT`)
   - `CYCLE-0029` (`rustls/rustls#3329`): HPKE sequence exhaustion vs AEAD nonce (`BLOCK / MATCH`)
   - `CYCLE-0030` (`nodejs/node#66550`): Test runner error propagation (`APPROVE / MATCH`)
   - `CYCLE-0031` (`curl/curl#23238`): Fallback deadline semantics (`HUMAN_REVIEW_REQUIRED / MATCH`)
4. **Authority Boundary**: Runtime merge authority remains strictly `NONE`.

---

### 2.2 Success Criteria (Gate Out / Promotion Eligibility)
Phase 4.4 completes and qualifies Triad-Flow for a formal Human Governance Promotion Review if and only if all of the following conditions are met:
1. **Cohort Depth Target**: Accumulate **$\ge 15$ consecutive fresh cycles** (requiring at least 8 new qualifying cycles: `CYCLE-0032` through `CYCLE-0039`).
2. **Zero False Advance Invariant**: Exactly **0 False Advances** across the entire 15-cycle fresh cohort (`CYCLE-0025..0039`).
   - *Immediate Halt Condition*: If ANY False Advance occurs in `CYCLE-0032..0039`, Phase 4.4 halts immediately for root-cause analysis.
3. **Reliability Constraints**:
   - Fresh cohort False Holds $\le 1$.
   - Fresh cohort timeout-cycle rate $< 5.0\%$.
   - Zero unhandled provider crashes or malformed output failures.
4. **Non-Automatic Promotion Invariant**: Fulfilling these criteria **does not** automatically promote Triad-Flow to `ADVISORY`. It solely satisfies the prerequisites to convene a formal Human Governance Promotion Review.

---

### 2.3 Artifact & Ledger Boundaries

| Artifact | Role & Authority | Mutation Policy |
|---|---|---|
| [`docs/benchmarks/dogfood-receipts.jsonl`](file:///C:/Users/arcobaleno/Documents/Code/triad-flow/docs/benchmarks/dogfood-receipts.jsonl) | Canonical raw receipt ledger | **Append-only** for new cycle receipts (`CYCLE-0032+`). Historical receipts `1..31` are immutable. |
| [`docs/benchmarks/shadow-dogfood-observation.md`](file:///C:/Users/arcobaleno/Documents/Code/triad-flow/docs/benchmarks/shadow-dogfood-observation.md) | Derived observation scorecard | Automatically regenerated via `record-cycle.mjs` tracking Phase 4.4 progress (`7/15` $\to$ `15/15`). |
| [`docs/benchmarks/track-d1-convergence-audit.md`](file:///C:/Users/arcobaleno/Documents/Code/triad-flow/docs/benchmarks/track-d1-convergence-audit.md) | Phase 4.3 closure audit (`TF-AUDIT-D1-0001`) | **Permanently frozen**. Strictly read-only; never edited by Phase 4.4. |
| `docs/benchmarks/phase-4-4-promotion-audit.md` | Phase 4.4 qualification audit (`TF-AUDIT-PROMOTION-0001`) | **Created upon Phase 4.4 completion** to document the 15-cycle fresh cohort and promotion deliberation. |

---

## 3. Fresh Candidate Diversification Strategy (`CYCLE-0032..0039`)

To ensure genuine generalization across software engineering failure modes, the 8 qualification candidates must adhere to domain diversification guidelines:

1. **Failure Domain Diversity**:
   - Minimum 4 distinct technical domains across the 8 samples (e.g. Async cancellation & task lifetime, Parser boundaries & state machines, Dynamic memory / pointer validity, Protocol handshake & negotiation, Serialization / deserialization).
2. **Language Diversity**:
   - Must cover at least 3 distinct programming languages across C/C++, Rust, Go, Python, Java, or JavaScript/TypeScript.
3. **Balanced Empirical Distribution**:
   - Candidate cohort must contain a balanced mix of:
     - Clean, uncontested fixes with strong maintainer approval (evaluating Precision / False Hold resistance).
     - Subtle defect candidates or partial fixes (evaluating Recall / Invariant Falsification detection).
4. **Pre-Run Objective & Exclusion Finalization**:
   - Every candidate must have a strictly bound, human-reviewed Stated Patch Objective and explicit pre-bound exclusions (`NONE` or explicit list) finalized before `runStartedAt`. Lower-authority in-patch descriptions cannot narrow the objective.

---

## 4. Execution Workflow per Cycle

For each cycle `CYCLE-0032` through `CYCLE-0039`:
```
1. Candidate Selection & Oracle Freeze (Maintainer consensus, GitHub checks, Stated Patch Objective)
       ↓
2. Local Repository Setup & Diff Verification
       ↓
3. Live Tri-Party Execution (agy + claude + codex sentries, claude verifier)
       ↓
4. Autonomous Quorum & Advisory Gate Evaluation
       ↓
5. Ledger Recording via scripts/record-cycle.mjs (canonical jsonl append + summary rebuild)
       ↓
6. Invariant Verification & Contract Test Suite Run (node --test)
       ↓
7. Commit, Push to main, and GitHub Actions 3-OS CI Run Monitoring
```
