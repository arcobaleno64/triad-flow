# Implementation Plan: Triad-Flow v2.7.0 Real Change Observation (SHADOW_DOGFOOD)

## Goal Description
Following the formal release and baseline freeze of Triad-Flow v2.7.0 (`fdcabf861368edbe552a0427efcb89da47fd4cb7`), the project transitions from release engineering to operational assurance. This plan establishes the operational observation protocol for tracking **20–30 real change cycles** in `SHADOW_DOGFOOD` mode (`ADVISORY_ONLY`, runtime merge authority = `NONE`). It defines the 8-signal minimal receipt schema, append-only cycle ledger, lightweight ingestion tooling, failure-family recurrence accounting, and the `SHADOW -> ADVISORY` maturity gate checklist.

---

## Approved Boundaries

> [!IMPORTANT]
> **Production Code Lock**: All files under `src/` and `package.json` runtime dependencies remain frozen at v2.7.0. Authorized work is limited to `scripts/record-cycle.mjs`, `tests/record-cycle.test.mjs`, `docs/benchmarks/dogfood-receipts.jsonl`, `docs/benchmarks/shadow-dogfood-observation.md`, and this plan.

> [!IMPORTANT]
> **No new governance mechanism**: Do not add a database, hash chain, signed receipt ledger, always-on service, automatic Advisory promotion, fourth reviewer, or new runtime dependency.

### Storage Authority

```text
docs/benchmarks/dogfood-receipts.jsonl
= canonical append-only observation ledger
= Source of Truth

docs/benchmarks/shadow-dogfood-observation.md
= derived projection only
= may be deleted and regenerated from the ledger
= has no independent evidence authority
```

The recorder may append a new canonical receipt but must never rewrite prior ledger bytes. Duplicate `cycleId` values are rejected.

### Observation Target Scope
Real change cycles will be captured primarily on subsequent PRs and commits in `arcobaleno64/triad-flow`, with optional real diffs from related repositories when evaluated by Triad-Flow. **Only live real-change cycles with a finalized pre-run human oracle count toward the 20–30 maturity sample.** Mock cycles remain useful for schema, transport, and smoke testing but never enter the maturity denominator.

---

## Cycle Identity vs Run Attempts

A **cycle** is a real change / PR evaluation unit. A **run attempt** is one execution of the Triad review machinery against that cycle.

Required metadata:

```typescript
executionMode: "live" | "mock";
sourceRunId: string;
sourceRunTimestamp: string;
humanOracleFinalizedAt: string;
canonicalForCycle: true;
countsTowardMaturity: boolean;
```

The maturity predicate is:

```text
real change
AND executionMode == live
AND human oracle finalized before Triad result
AND canonical receipt for this cycle
```

Retries may exist as separate runtime telemetry, but only one canonical ledger receipt is permitted for a real change. The ledger rejects duplicate `cycleId` values, and a second qualifying live receipt for the same repository + exact commit SHA is rejected even under a different cycle ID. Retry attempts remain in source run telemetry rather than inflating the maturity sample.

---

## Human Oracle Ordering

The human disposition is the operational oracle and must be fixed **before** the Triad result is available.

Required order:

```text
1. Human disposition finalized
2. Immutable humanOracleFinalizedAt recorded
3. Triad live run executes
4. record-cycle.mjs ingests the completed run
5. comparison is computed
6. canonical receipt is appended
```

`record-cycle.mjs` is an ingestion/recording tool only. It does **not** launch live or mock model reviews. `scripts/dogfood-review.mjs` remains responsible for producing `dogfood-run.json`.

The recorder rejects a receipt when `humanOracleFinalizedAt >= sourceRunTimestamp`.

---

## The 8-Signal Minimal Receipt Schema

```typescript
interface CycleReceipt {
  schemaVersion: "1.0.0";
  cycleId: string;                  // canonical change-cycle identity
  timestamp: string;                // receipt append time, ISO 8601 UTC
  executionMode: "live" | "mock";
  sourceRunId: string;
  sourceRunTimestamp: string;
  humanOracleFinalizedAt: string;
  canonicalForCycle: true;
  countsTowardMaturity: boolean;

  repository: {
    name: string;
    commitSha: string;
    prNumber?: number;
    branch: string;
    diffStat: { files: number; additions: number; deletions: number };
  };

  // Signal 1: Ground Truth Oracle
  humanDisposition: "APPROVE" | "REQUEST_CHANGES" | "HOLD";
  humanNotes?: string;

  // Signal 2: Triad-Flow Consensus / Escalation Outcome
  triadDisposition: "APPROVE" | "BLOCK" | "DEGRADED" | "INCOMPLETE" | "HUMAN_REVIEW_REQUIRED";
  gateDecision: "pass" | "block";

  // Signal 3: Discrepancy Classification
  discrepancy: "MATCH" | "FALSE_ADVANCE" | "FALSE_HOLD" | "NEUTRAL_DISAGREEMENT";

  // Signal 4: Runtime Robustness
  robustness: {
    executionComplete: boolean;
    malformedOutputCount: number;
    timeoutCount: number;
    authFailureCount: number;
    stagedFallbackUsed: boolean;
  };

  // Signal 5: Assurance Value
  assurance: {
    disagreementCount: number;
    solitaryBlockerCount: number;
    verifierOverturns: number;
    verificationStatus: "NOT_ATTEMPTED" | "SUCCESS" | "FAILED";
  };

  // Signal 6: Efficiency & Cost
  efficiency: {
    totalWallClockMs: number;
    avgProviderLatencyMs: number;
    providerLatencies: Record<string, number>;
    estimatedCostUsd?: number;
  };

  // Signal 7: Routing Quality
  routing: {
    riskTier: 1 | 2 | 3 | 4 | null;
    chunkCount: number | null;       // null when the source run did not preserve this telemetry
    totalFindings: number;
    corroboratedFindings: number;
  };

  // Signal 8: Failure Family & Recurrence
  failureFamily: string | "NONE";   // lowercase kebab-case only
  recurrenceCount: number;          // qualifying live-cycle occurrences only
  escalationAction: "NONE" | "RELIABILITY_PRIORITY" | "IMMEDIATE_BLOCKER" | "ELEVATE_PRIORITY" | "DEFER";
}
```

`failureFamily` must be `NONE` or a canonical lowercase kebab-case slug such as `checkpoint-overwrite`, `literal-backslash`, or `deadline-budget`. Variants such as `literal_backslash`, `Literal-Backslash`, and `backslash path` are rejected.

---

## Discrepancy Truth Table

False-advance and false-hold rates apply only to autonomous binary Triad outcomes (`APPROVE` / `BLOCK`). Abstention and escalation outcomes do not silently enter those rates.

| Triad disposition | Human disposition | Discrepancy |
|---|---|---|
| APPROVE | APPROVE | MATCH |
| APPROVE | REQUEST_CHANGES / HOLD | FALSE_ADVANCE |
| BLOCK | APPROVE | FALSE_HOLD |
| BLOCK | REQUEST_CHANGES / HOLD | MATCH |
| DEGRADED / INCOMPLETE | HOLD | MATCH |
| DEGRADED / INCOMPLETE | APPROVE / REQUEST_CHANGES | NEUTRAL_DISAGREEMENT |
| HUMAN_REVIEW_REQUIRED | any finalized human outcome | MATCH (successful escalation, not autonomous correctness) |

`MATCH` for `HUMAN_REVIEW_REQUIRED` means the system correctly escalated authority; it does not mean Triad independently predicted the human decision.

---

## Debt Escalation & Triple-Loop Rules

| Event / Condition | Action / Escalation | Governor Posture |
|---|---|---|
| `discrepancy === "FALSE_ADVANCE"` | `IMMEDIATE_BLOCKER` | Suspend any autonomy promotion; root-cause review |
| qualifying `failureFamily` recurrence >= 2 | `ELEVATE_PRIORITY` | Promote debt to next milestone candidate |
| `discrepancy === "FALSE_HOLD"` | `RELIABILITY_PRIORITY` | Prioritize precision without weakening gates |
| telemetry-only issue | `DEFER` | Keep debt visible; no architecture change unless recurrent |
| one-off edge case without harm | `NONE` | Record only |

Recurrence is calculated from prior **maturity-counting live receipts**. Mock cycles never inflate recurrence.

---

## Proposed Changes

### `scripts/record-cycle.mjs`
A lightweight ingestion helper that:

1. Accepts an existing Track D1 `dogfood-run.json` via `--from`.
2. Requires `--cycle-id`, `--execution-mode`, human disposition, and `--human-finalized-at`.
3. Rejects contaminated oracle ordering (`humanOracleFinalizedAt >= sourceRunTimestamp`).
4. Computes the explicit discrepancy truth table above.
5. Converts verifier state to `NOT_ATTEMPTED | SUCCESS | FAILED`.
6. Validates canonical failure-family slugs and computes qualifying recurrence from the ledger.
7. Rejects duplicate `cycleId` values.
8. Appends exactly one JSON line to the canonical ledger.
9. Regenerates the Markdown projection from ledger contents.
10. Never launches provider CLIs.

Example:

```bash
node scripts/dogfood-review.mjs --live --out dogfood-run.json

node scripts/record-cycle.mjs \
  --from dogfood-run.json \
  --cycle-id CYCLE-0001 \
  --execution-mode live \
  --repository arcobaleno64/triad-flow \
  --pr 33 \
  --human APPROVE \
  --human-finalized-at 2026-10-04T01:00:00Z \
  --family NONE
```

A mock/schema smoke check may use `--execution-mode mock --dry-run`; it never counts toward maturity.

### `docs/benchmarks/dogfood-receipts.jsonl`
Canonical append-only JSONL observation ledger. Empty initially. No comments, headers, hash chain, database, or signatures.

### `docs/benchmarks/shadow-dogfood-observation.md`
Derived projection generated from the ledger. It contains baseline metadata, maturity scorecard, receipt table, recurrence table, and the Shadow -> Advisory checklist. It explicitly states that it has no independent evidence authority.

---

## Verification Plan

### Focused Tests
Add `tests/record-cycle.test.mjs` covering at minimum:

- ingestion-only CLI contract; legacy `--live` runner behavior is rejected
- human oracle timestamp must precede Triad result
- live real change counts toward maturity; mock and zero-change receipts do not
- explicit discrepancy truth table, including non-binary outcomes
- verifier `NOT_ATTEMPTED / SUCCESS / FAILED`
- canonical failure-family slug validation
- recurrence counting excludes mock/non-maturity receipts
- append-only ledger preserves prior bytes
- duplicate `cycleId` rejection leaves ledger unchanged
- derived Markdown regeneration from canonical ledger
- dry-run performs no writes

Command:

```bash
node --test tests/record-cycle.test.mjs
```

### Full Regression

```text
npm test:
- exit 0
- fail = 0
- existing 549-test baseline must not regress
- existing expected skip set remains unchanged unless explicitly justified
- new recorder tests are additive
```

The test total is expected to increase beyond 549 after adding recorder tests. The historical 549 / 546 pass / 3 skip release baseline is a floor/reference, not a frozen total.

### Structural Verification

- `src/` has no changes.
- `package.json` has no changes and runtime dependencies remain `{}`.
- `TF-EVIDENCE-0010` and all sealed evidence remain unchanged.
- No G4 benchmark rerun.
- No new database, service, hash chain, signature ledger, or promotion automation.

---

## Maturity Gate

The recorder does not promote authority. After at least 20–30 qualifying real change cycles, human governance may evaluate:

```text
SHADOW -> ADVISORY

AND no known systemic false-approve path
AND no new P0/P1 authority/provenance/coverage truthfulness family
AND PASS/BLOCK/DEGRADED/INCOMPLETE/HUMAN_REVIEW_REQUIRED classification is operationally stable
AND false-hold / override / latency / cost have an accepted operational baseline
```

`Runtime merge authority` remains `NONE` throughout this observation stage.

## Learning Loop

```text
Learning Owner: NONE
Triple-Loop: NO PERSISTENT CHANGE
```

This implementation operationalizes the already-approved SHADOW_DOGFOOD contract. It does not change Breadth Governor logic or Triad-Flow governance philosophy.
