# LOOP2-SYSTEMIC-REMEDIATION-005 Specification
## Invariant Preservation & Interference Review

**Status:** APPROVED FOR IMPLEMENTATION  
**Classification:** LOOP 2 (Systemic Remediation)  
**Authority Mode:** SHADOW_DOGFOOD (Advisory Only, Runtime Authority: NONE)  
**Learning Owner:** Primary = Sentry Review Model / Coverage Contract; Contributing = Risk Semantics / Review Routing; Not primary = Verifier, Gate, Human Oracle  
**Historical Cohort:** `CYCLE-0001..0024` FROZEN (24 receipts, 23 maturity cycles, 3 False Advances, 3 False Holds)  
**Fresh Cohort Status:** WP-03 STOPPED pending `REMEDIATION-REPLAY-0024` exit closure  

---

## 1. Problem Statement & Empirical Root Cause

In `CYCLE-0024` ([`redis/redis-py#4298`](https://github.com/redis/redis-py/pull/4298), head `c20c9498a9`), Triad-Flow recorded its third `FALSE_ADVANCE`.
All three sentries (`agy`, `claude`, `codex`) returned **0 findings**, leading to an unverified autonomous `APPROVE` on a patch containing a critical concurrency race condition that violates pool capacity accounting (`max_connections`).

### 1.1 The Abstract Failure Mechanism
The failure is not an isolated Python bug or a missing keyword in a checklist. It represents a fundamental structural blindspot in patch-centric review:

```text
Patch fixes failure path A
        ↓
moves / removes / delays state mutation
        ↓
path A becomes correct (clean failure cleanup, green tests)
        ↓
but invariant B depended on the original mutation timing
        ↓
alternate interleaving / concurrency / rollback path breaks!
```

In `redis-py#4298`:
- **Before:**
  ```text
  capacity check (0 < 1)
  → reserve slot (_created_connections += 1)
  → construct connection
  → failure leaks reservation slot permanently
  ```
- **Patch:**
  ```text
  capacity check (0 < 1)
  → construct connection
  → count slot on success (_created_connections += 1)
  ```
- **Fixes:** failure-path leak (passes new unit tests).
- **Breaks:** reservation atomicity under concurrent constructors. Two callers under `max_connections=1` both observe `0 < 1` before either increments the counter, creating two connections simultaneously and violating the capacity ceiling invariant.

### 1.2 Core Analytical Question
> **When a patch changes when, where, or whether state is mutated, does every invariant previously protected by that mutation still hold across success, failure, retry, cancellation, and interference paths?**

---

## 2. Workface Architecture

### Workface 1: Invariant Extraction (Not CWE Memorization)
Reviewers must not merely scan for syntactic CWE identifiers. When a diff touches state mutations:
1. **Identify Protected Invariants:**
   - Resource counters / capacities (`pool_size`, `max_connections`, quotas) -> `active + reserved <= max_limit`.
   - Ownership / leases / tokens -> `every allocated resource has exactly one owner; freed on all exit paths`.
   - Synchronization / locks / atomic flags -> `shared state read/write protected against concurrent modification`.
   - Lifecycle / state transitions -> `valid state ordering; rollback on partial failure`.

### Workface 2: Mutation-Relocation 4-Path Evaluation
Any movement, delay, removal, or conditional guarding of state mutations must be validated against four orthogonal paths:
1. **Success Path:** normal execution completes and leaves state coherent.
2. **Failure & Rollback Path:** exceptions, errors, or rejections roll back intermediate state without leaks or double-frees.
3. **Concurrent Interference Path:** multiple concurrent callers interleaving operations do not violate safety or bounds.
4. **Retry & Cancellation Path:** aborted or retried operations restore invariant before subsequent attempts.

**Invariant Rule:** A patch must not fix a failure-path leak by destroying reservation atomicity on the concurrent interference path.

### Workface 3: Interleaving Counterexample Obligation
For changes modifying state reservation or checking timing, the reviewer must construct a minimal interleaving test:
```text
Actor 1 checks precondition (e.g. count < limit) -> passes
Actor 2 checks precondition (e.g. count < limit) -> passes
Both enter allocation/construction before either commits count
Count exceeds limit -> Invariant violated!
```
If moving an increment/decrement after a fallible or blocking call opens a race window, the reviewer must flag `INVARIANT_VIOLATION`. The standard resolution is **reserve first, rollback in exception handler**, preserving both failure safety and reservation atomicity.

### Workface 4: Replay Gate & Empirical Exit Condition
1. `REMEDIATION-REPLAY-0024` on `redis/redis-py#4298` (exact head `c20c9498a9`) must be executed.
2. The replay MUST produce a finding and result in `BLOCK` or defensible `HUMAN_REVIEW_REQUIRED`.
3. If replay passes as `APPROVE`, WP-03 remains strictly HALTED.
4. Historical receipts `CYCLE-0001..0024` remain frozen and immutable.

---

## 3. Regression & Precision Matrix

| ID | Test Scenario | Expected Outcome | Purpose |
|---|---|---|---|
| A | `CYCLE-0024 exact replay` | Produces finding -> BLOCK / HUMAN_REVIEW_REQUIRED | Catches delayed increment breaking reservation atomicity |
| B | `Safe rollback pattern` | Zero blocking findings -> APPROVE | Verifies reserve-first + rollback-on-error is recognized as clean (precision guard) |
| C | `Pure local counter relocation` | Zero blocking findings -> APPROVE | Does not manufacture concurrency findings on thread-local/unshared state |
| D | `Ownership transfer` | Flags unhandled cancellation leak | Verifies ownership handoff covers failure/abort paths |
| E | `Bounded resource ceiling` | Flags check-then-act race | Verifies check-and-reserve atomicity under concurrent callers |
| F | `Retry / cancellation` | Flags uncleaned state across retries | Verifies state restoration before subsequent attempts |

---

## 4. Implementation Boundary & Non-Goals

1. **No Gate Changes:** The Gate operated correctly on 0 consensus findings. Adjusting Gate logic without fixing sentry detection is noise.
2. **No Routing Rewrite:** Keep 62-line diff routing intact; focus remediation on sentry reasoning.
3. **No Language-Specific Hacks:** Formulate the invariant rubric universally so it applies across Python, JS/TS, Go, Rust, Java, and C++.
4. **Zero Runtime Dependencies:** Maintain standard Node.js test and execution framework.
