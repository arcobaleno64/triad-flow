# Triad-Flow Phase 4.4: Advisory Promotion Audit

- **Document ID:** `TF-AUDIT-PROMOTION-0001`
- **Governing specification:** `TF-SPEC-P44-0001` (`docs/roadmap/phase-4-4-advisory-qualification-spec.md`)
- **Audit scope:** Post-005 Fresh Cohort, `CYCLE-0025..CYCLE-0039` (15 canonical maturity-counting cycles)
- **Evidence snapshot:** [`73d357b642631e6f102ab8affb2bb2d36771cd1e`](https://github.com/arcobaleno64/triad-flow/commit/73d357b642631e6f102ab8affb2bb2d36771cd1e) on `main`
- **Audit date:** 2026-10-08 UTC
- **Status:** `AUDIT PREPARED / HUMAN ADJUDICATION PENDING`
- **Eligibility adjudication recommended:** `GATE_OUT_FAILED / NOT ELIGIBLE`
- **Authority:** `SHADOW_TO_ADVISORY = STRICT_HOLD`; `RUNTIME_AUTHORITY = NONE`

> **Controlling distinction:** `FRESH_COHORT_DEPTH = 15/15` and `FALSE_ADVANCE = 0` are true. They do **not** satisfy the complete Phase 4.4 Gate Out, because the fresh-cohort timeout-cycle rate breaches the explicit reliability threshold. This audit is submitted for human governance adjudication **without** promoting the runtime.

## 1. Executive adjudication

The planned Phase 4.4 eight-cycle qualification collection (`CYCLE-0032..0039`) is complete, and all 15 Post-005 fresh receipts are canonical maturity-counting observations. There were no fresh false advances or false holds, and the eight new cases have a balanced four-APPROVE/four-REQUEST_CHANGES Human Oracle distribution.

**However, `TF-SPEC-P44-0001 §2.2` makes the reliability constraints conjunctive.** Three of the 15 fresh cycles had nonzero timeout counts: `CYCLE-0028`, `CYCLE-0033`, and `CYCLE-0037`. Thus the **fresh timeout-cycle rate = 3 / 15 = 20.0%**, failing the **strictly less than 5.0%** requirement. This remains a failure even when quorum is preserved and the Advisory Gate blocks safely.

**Proposed formal result:** `PROMOTION_REVIEW_ELIGIBLE = FALSE` under the currently approved specification; `SHADOW_TO_ADVISORY = STRICT_HOLD`; `RUNTIME_AUTHORITY = NONE`. Convene a human **audit/adjudication** review to accept or challenge these findings, not an automatic advisory promotion.

## 2. Authority, provenance, and immutable artifacts

| Evidence | Pinned source | Finding |
|---|---|---|
| Governing criteria | [Phase 4.4 specification](https://github.com/arcobaleno64/triad-flow/blob/73d357b642631e6f102ab8affb2bb2d36771cd1e/docs/roadmap/phase-4-4-advisory-qualification-spec.md) | §2.2 requires ≥15 consecutive fresh cycles, 0 FA, ≤1 FH, timeout-cycle rate <5.0%, and no unhandled crashes or malformed failures. |
| Canonical receipts | [`dogfood-receipts.jsonl`](https://github.com/arcobaleno64/triad-flow/blob/73d357b642631e6f102ab8affb2bb2d36771cd1e/docs/benchmarks/dogfood-receipts.jsonl) | 39 total receipts, 38 maturity-counting, 15 consecutive canonical fresh receipts. |
| Derived scorecard | [`shadow-dogfood-observation.md`](https://github.com/arcobaleno64/triad-flow/blob/73d357b642631e6f102ab8affb2bb2d36771cd1e/docs/benchmarks/shadow-dogfood-observation.md) | Global timeout-cycle rate 7.9% (= 3/38); this is **not** the required fresh-cohort denominator. |
| Frozen Phase 4.3 audit | [`TF-AUDIT-D1-0001`](https://github.com/arcobaleno64/triad-flow/blob/73d357b642631e6f102ab8affb2bb2d36771cd1e/docs/benchmarks/track-d1-convergence-audit.md) | Unchanged blob SHA `25348dce3c33de69a4cd9c160a10cb254a656dee` when compared to Phase 4.4 baseline `29787d8b9e968e1be0324547126473ac59983d91`. |
| Phase 4.4 closing CI | [Actions run 37736022303](https://github.com/arcobaleno64/triad-flow/actions/runs/37736022303) | `success` at the exact evidence snapshot commit `73d357b642631e6f102ab8affb2bb2d36771cd1e`. |

An independent comparison against `29787d8` found its **31 original ledger lines unchanged byte-for-byte** as the prefix of the 39-line current ledger. New records are appended, not rewritten. Phase 4.3 closure remains frozen; this Phase 4.4 audit is a separate artifact. Historical 3 False Advances and 3 False Holds remain in the global ledger and are **not** expunged.

## 3. Gate Out verification matrix

| Requirement (`TF-SPEC-P44-0001 §2.2`) | Threshold | Observed | Result |
|---|---|---|---|
| Cohort depth | ≥15 consecutive fresh maturity-counting cycles | 15 / 15 (`0025..0039`) | **PASS** |
| Fresh False Advance | Exactly 0 | 0 / 15 | **PASS** |
| Fresh False Hold | ≤1 | 0 / 15 | **PASS** |
| Fresh timeout-cycle rate | <5.0% | **3 / 15 = 20.0%** | **FAIL / PROMOTION BLOCKER** |
| Malformed output | 0 unhandled failures | 0 `malformedOutputCount` in persisted receipts | **PASS for persisted metric only** |
| Unhandled provider crashes | 0 | No dedicated crash count or complete provider-failure taxonomy in projected receipts | **NOT INDEPENDENTLY VERIFIED** |
| Historical ledger freeze | No alteration of preexisting receipts | Earlier 31 receipt lines unchanged | **PASS** |
| Phase 4.3 audit freeze | Do not reopen or edit | Audit blob unchanged | **PASS** |
| Diversity (§3) | ≥4 domains, ≥3 languages; balanced positive/negative | ≥6 distinguishable domains; C, Rust, Java, Go, C++/JavaScript; 4/4 new Oracle mix | **PASS** |
| Non-automatic promotion | No authority change before human ruling | No authority-granting change in audited evidence; keep `STRICT_HOLD`/`NONE` | **REQUIRED / HOLD** |

**Calculation method:** count one timeout cycle if and only if the canonical receipt has `robustness.timeoutCount > 0`, independent of how many staged chunks timed out. The denominator includes **all** 15 `countsTowardMaturity === true` fresh cycles, including `DEGRADED`. This is the same timeout-cycle counting rule used by `scripts/record-cycle.mjs:renderSummary`; the difference from its global 7.9% projection is **cohort scope**, not an alternate formula. No trimming, timeout forgiveness, or post-hoc exclusions.

**Partial-evidence limit:** all 15 receipts show zero `malformedOutputCount` and zero `authFailureCount`. They do not record a dedicated `unhandledCrashCount`, and four indicate `executionComplete=false`; a separate raw-run provenance audit is needed before certifying the full "zero unhandled provider crashes" clause.

## 4. Canonical 15-cycle fresh-cohort evidence

| Cycle | Repository / PR | Human | Triad | Advisory Gate | Discrepancy | Timeout events | Execution complete |
|---|---|---|---|---|---|---:|---|
| CYCLE-0025 | `hyperium/hyper#4150` | REQUEST_CHANGES | DEGRADED | block | NEUTRAL_DISAGREEMENT | 0 | no |
| CYCLE-0026 | `libgit2/libgit2#7394` | APPROVE | APPROVE | pass | MATCH | 0 | yes |
| CYCLE-0027 | `curl/curl#22853` | APPROVE | APPROVE | pass | MATCH | 0 | yes |
| CYCLE-0028 | `netty/netty#17475` | REQUEST_CHANGES | DEGRADED | block | NEUTRAL_DISAGREEMENT | 1 | no |
| CYCLE-0029 | `rustls/rustls#3329` | REQUEST_CHANGES | BLOCK | block | MATCH | 0 | yes |
| CYCLE-0030 | `nodejs/node#66550` | APPROVE | APPROVE | pass | MATCH | 0 | yes |
| CYCLE-0031 | `curl/curl#23238` | APPROVE | HUMAN_REVIEW_REQUIRED | escalate | MATCH | 0 | yes |
| CYCLE-0032 | `python/cpython#158910` | APPROVE | APPROVE | pass | MATCH | 0 | yes |
| CYCLE-0033 | `rust-lang/rust#163058` | REQUEST_CHANGES | DEGRADED | block | NEUTRAL_DISAGREEMENT | 27 | no |
| CYCLE-0034 | `apache/kafka#23705` | APPROVE | APPROVE | pass | MATCH | 0 | yes |
| CYCLE-0035 | `containerd/containerd#14052` | APPROVE | APPROVE | pass | MATCH | 0 | yes |
| CYCLE-0036 | `python/cpython#158943` | REQUEST_CHANGES | BLOCK | block | MATCH | 0 | yes |
| CYCLE-0037 | `nodejs/node#65370` | REQUEST_CHANGES | DEGRADED | block | NEUTRAL_DISAGREEMENT | 5 | no |
| CYCLE-0038 | `nats-io/nats-server#8691` | APPROVE | APPROVE | pass | MATCH | 0 | yes |
| CYCLE-0039 | `rust-lang/rust#163872` | REQUEST_CHANGES | BLOCK | block | MATCH | 0 | yes |

### 4.1 Aggregate disposition accounting

- **Human Oracle:** 8 APPROVE, 7 REQUEST_CHANGES, 0 HOLD.
- **Triad states:** 7 APPROVE, 3 BLOCK, 4 DEGRADED, 1 HUMAN_REVIEW_REQUIRED.
- **Advisory Gate:** 7 pass, 7 block, 1 escalate; none confers runtime merge authority.
- **Recorded discrepancy:** 11 MATCH, 4 NEUTRAL_DISAGREEMENT, **0 FALSE_ADVANCE, 0 FALSE_HOLD**.
- **Completion:** 11/15 `executionComplete=true`, 4/15 false (`CYCLE-0025`, `CYCLE-0028`, `CYCLE-0033`, `CYCLE-0037`).
- **Mean total wall-clock per fresh cycle:** 176,160 ms, computed from `efficiency.totalWallClockMs` for all 15 cycles without outlier removal.
- **Gate classification convention:** A fail-closed DEGRADED block against REQUEST_CHANGES is `NEUTRAL_DISAGREEMENT` under the persisted discrepancy contract, not retroactively a `MATCH`. The HUMAN_REVIEW_REQUIRED escalation in `CYCLE-0031` remains its originally recorded `MATCH`, not a fabricated False Hold.

### 4.2 Timeout incident breakdown

| Cycle | Per-cycle `timeoutCount` | `stagedFallbackUsed` | `executionComplete` | Recorded outcome |
|---|---:|---|---|---|
| CYCLE-0028 | 1 | false | false | `DEGRADED`, `block` |
| CYCLE-0033 | 27 | true | false | `DEGRADED`, `block` |
| CYCLE-0037 | 5 | true | false | `DEGRADED`, `block` |

The 1 + 27 + 5 = **33 timeout events/chunks** correspond to only **3 timeout cycles**. The relevant eligibility numerator is **3**, not 33. For the **new Phase 4.4 eight-cycle segment alone**, the rate is 2/8 = **25.0%**; it also fails <5.0%. Quorum survival and correct fail-closed decisions demonstrate safety under degradation but do **not** establish the required operational reliability.

## 5. Phase 4.4 diversity and review fidelity

The eight newly selected cases `CYCLE-0032..0039` were:

| Cycle | Repository / PR | Primary domain | Language | Human Oracle | Gate |
|---|---|---|---|---|---|
| 0032 | `python/cpython#158910` | Borrowed-reference / memory lifetime | C | APPROVE | pass |
| 0033 | `rust-lang/rust#163058` | Markdown parser document boundaries | Rust | REQUEST_CHANGES | block (DEGRADED) |
| 0034 | `apache/kafka#23705` | Distributed membership metadata semantics | Java | APPROVE | pass |
| 0035 | `containerd/containerd#14052` | Registry query injection / security boundary | Go | APPROVE | pass |
| 0036 | `python/cpython#158943` | C macro evaluation semantics | C | REQUEST_CHANGES | block |
| 0037 | `nodejs/node#65370` | Asynchronous tracing context / event lifecycle | C++ / JavaScript | REQUEST_CHANGES | block (DEGRADED) |
| 0038 | `nats-io/nats-server#8691` | Distributed restore failure finalization | Go | APPROVE | pass |
| 0039 | `rust-lang/rust#163872` | Compiler feature-gate validation / performance | Rust | REQUEST_CHANGES | block |

New-segment totals: 4 positive and 4 negative human reviews; 4 pass, 4 block; 6 MATCH and 2 NEUTRAL_DISAGREEMENT. The domain/language quotas are fulfilled. This is **coverage evidence**, not a substitute for robustness.

### 5.1 Independent provenance limitations

- `humanOracleFinalizedAt <= sourceRunStartedAt` for all 15 receipts. This supports temporal ordering but does not independently reverify every GitHub reviewer identity or exact-head status.
- `dogfood-receipts.jsonl` records Oracle disposition, source times, commit head and notes; it does **not** retain the full pre-run `Stated Patch Objective` and exclusions text for each receipt. The producer can include an `objectiveContract` in the full run report, but its presence and binding were **not** established from the canonical receipt ledger alone.
- Before final human sign-off, attach or inspect immutable per-run objective contracts, exact-head reviewer evidence, and full provider execution records for `CYCLE-0025..0039`. Do not infer missing evidence from passing contract tests.
- The 39-receipt derived scorecard labels 15/15 as "Eligibility"; that label is a **depth-only projection** and cannot override the independent conjunction of §2.2's reliability constraints.

## 6. Decisions requested of the human governance reviewer

1. **Ratify factual evidence:** 39 total receipts, 38 maturity-counting, 15 consecutive fresh, 0 fresh FA, 0 fresh FH, **3/15 (20.0%) fresh timeout cycles**.
2. **Ratify Gate Out failure under the approved specification:** mark Phase 4.4 collection complete while withholding eligibility for formal `SHADOW → ADVISORY` promotion review.
3. **Direct reliability remediation:** investigate `CYCLE-0028`, `CYCLE-0033`, and `CYCLE-0037`, particularly diff-size/staged-chunking timeout behavior; register changes with new evidence and regression coverage.
4. **Preserve authority and evidence boundaries:** no receipt rewrites, no deletion/reclassification of timeout cycles, no reopening `TF-AUDIT-D1-0001`, and no runtime-authority change.
5. **Set a prospective requalification plan:** after remediation, define a separately documented eligibility campaign and decision rule. Do not retroactively redefine the original <5% threshold or simply add convenient cycles to dilute the failures. Any explicit governance exception would be a documented exception, **not** a PASS against the original Phase 4.4 spec.
6. **Resolve completeness/provenance limitations:** inspect the full run receipts for provider-crash coverage and pre-run objective/exclusion binding before approving any future promotion eligibility.

## 7. Formal adjudication record (awaiting human signature)

```text
DOCUMENT_ID = TF-AUDIT-PROMOTION-0001
PHASE_4_4_COLLECTION = COMPLETE
CANONICAL_RECEIPTS = 39
MATURITY_COUNTING_RECEIPTS = 38
FRESH_COHORT = CYCLE-0025..CYCLE-0039
FRESH_DEPTH = 15/15
FRESH_FALSE_ADVANCE = 0
FRESH_FALSE_HOLD = 0
FRESH_TIMEOUT_CYCLES = 3/15 (20.0%)
FRESH_TIMEOUT_TARGET = <5.0%
RELIABILITY_GATE = FAIL
PROMOTION_REVIEW_ELIGIBLE = FALSE
SHADOW_TO_ADVISORY = STRICT_HOLD
RUNTIME_AUTHORITY = NONE
HUMAN_AUDIT_REVIEW = PENDING
```

**Evidence freeze:** This report is evaluated at `73d357b642631e6f102ab8affb2bb2d36771cd1e` only. New information or source corrections require a new identified audit amendment and explicit human adjudication, not edits to the frozen Phase 4.3 audit or historic receipts.
