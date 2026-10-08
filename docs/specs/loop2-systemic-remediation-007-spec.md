# LOOP2-SYSTEMIC-REMEDIATION-007 Specification
## Zero-Finding Quorum Verification, Verifier Omission Gate & Local Callee Context Architecture

**Status:** PROPOSED FOR IMPLEMENTATION
**Classification:** LOOP 2 (Systemic Remediation)
**Issue Reference:** GitHub Issue #37
**Authority Mode:** SHADOW_DOGFOOD (Advisory Only, Runtime Authority: NONE)
**Origin Failure:** `CYCLE-0047` False Advance (`ClickHouse/ClickHouse#123335`, Commit `18f9c9d0db2fb7374b0545f3fa9542809107702a`)
**Frozen Baseline:** Phase 4.5 Cohort `CYCLE-0040..0047` (8 cycles, 1 FA, 2 FH, 0 timeout cycles)
**Escalation Action:** `IMMEDIATE_BLOCKER`
**Primary Learning Owner:** Harness Gate Policy (`harness.mjs`), Verification Pipeline (`independent-verifier.mjs`, `dogfood-review.mjs`), Context Engine (`review-prompts.mjs`)

---

## 1. Governance Context & Problem Statement

In `CYCLE-0047`, Triad-Flow evaluated ClickHouse PR #123335. All three review sentries (`agy`, `claude`, `codex`) returned 0 findings. Quorum was achieved, and the Advisory Gate issued an unconditional `APPROVE`. However, the formal human reviewer (`Ergus`, GitHub `MEMBER`) issued `REQUEST_CHANGES` on the exact head commit, accompanied by an AI Review verification from `clickhouse-gh` identifying a concrete functional defect:
> `[src/Storages/MergeTree/MergeTreeIndexConditionText.cpp:1487]` The new `keeps_absent_key_rows` logic does not cover all-zero `FixedString` needles, because `traverseMapElementValueNode` and the `m.key_<k>` fallback still reject `isMapValueDefault(const_value, header)` before this branch. For `Map(String, FixedString(N))` plus a `mapValues(m)` text index, a query like `hasAnyTokens(m['k'], concat(char(0), char(0), char(0)))` can still skip the tokenizer/postprocessor rewrite and fall back to `splitByNonAlpha`, which drops the absent-key row again.

This discrepancy was classified as **`FALSE_ADVANCE`** (the 4th lifetime occurrence, breaching the Post-005 fresh cohort which had reached 22 consecutive zero-false-advance cycles).

Pursuant to governance policy:
- `CYCLE_0047 = FROZEN_FALSE_ADVANCE` (permanently recorded in `dogfood-receipts.jsonl`)
- `CYCLE_0048 = ON_HOLD_NOT_ASSIGNED`
- `PHASE_4_5_PROMOTION_ELIGIBILITY = FAIL`
- `SHADOW_TO_ADVISORY = STRICT_HOLD`
- `RUNTIME_AUTHORITY = NONE`
- `ISSUE_37 = OPEN`

`REMEDIATION-007` is established under GitHub Issue #37 to eliminate the architectural blind spots that enabled three sentries to unanimously advance a defective change without verification.

---

## 2. Root Cause Analysis (Workstream 007-A)

Detailed diagnostic evaluation (`scripts/rca-cycle-0047-diagnostics.mjs`, `docs/benchmarks/rca-cycle-0047-evidence.json`) establishes four interlocking root causes:

### 2.1 ClickHouse Defect Mechanism (Physical Fact)
1. In `src/Storages/MergeTree/MergeTreeIndexConditionText.cpp`:
   - Line 1329: `traverseFunctionNode` invokes `traverseMapElementValueNode(index_column_node, value_field)`.
   - Line 2209: `traverseMapElementValueNode` defines:
     ```cpp
     if (const_value.getType() != Field::Types::String || isMapValueDefault(const_value.safeGet<String>(), header))
         return false;
     ```
   - Line 1363: Fallback subcolumn identification path similarly enforces:
     ```cpp
     && !isMapValueDefault(value_field.safeGet<String>(), header)
     ```
2. When a query evaluates a default-valued needle (e.g. `repeat(char(0), 3)` on `FixedString`):
   - `isMapValueDefault` returns `true`.
   - `traverseMapElementValueNode` returns `false`.
   - `is_map_element_value` remains `false`.
   - Line 1487: `const bool keeps_absent_key_rows = is_map_element_value && absentMapValueMatches(...);` evaluates to `false`.
   - The query falls back to `splitByNonAlpha`, dropping absent-key rows.
3. This directly contradicts the frozen patch objective:
   > *"Preserve rows whose missing map keys evaluate to default values that match after tokenizer and postprocessor transformations, including default-valued search inputs."*

### 2.2 Sentry Diff-Context Truncation
1. Unified git diffs provide a localized 3-line radius around modified hunks.
2. In PR #123335, `traverseMapElementValueNode` was defined at line 2209, more than 500 lines away from the modified hunks (lines 1264–1685).
3. The sentry prompt contained `traverseMapElementValueNode(...)` solely as an opaque call; sentries were physically blind to its internal rejection of `isMapValueDefault`.
4. While context line 1363 (`!isMapValueDefault`) was visible in the diff, sentries treated it as pre-existing background code rather than cross-examining it against the newly introduced objective clause.

### 2.3 Triad-Flow Zero-Finding Verification Skip
1. In `scripts/dogfood-review.mjs` line 865:
   ```javascript
   if (findings.length > 0 && !isStructuralFailure) {
     verificationRecord = await conductIndependentVerification(...);
   }
   ```
2. When all three sentries return 0 findings, `conductIndependentVerification` is **completely bypassed** (`verificationRecord = null`, status `NOT_ATTEMPTED`).
3. Consequently, no independent verifier ever challenges a clean quorum claim.

### 2.4 Harness Gate Short-Circuit and Omission Blindness
1. In `src/core/harness.mjs` line 289:
   ```javascript
   const findings = Array.isArray(consensus.findings) ? consensus.findings : [];
   if (findings.length === 0) {
     return {
       decision: "approve",
       reason: "No blocking vulnerabilities found. CI/CD Gate passed.",
       criticals: []
     };
   }

   // If verificationRecord is provided, execute post-verification gate authority
   if (options?.verificationRecord) {
     return evaluatePostVerificationGate(consensus, options.verificationRecord, options);
   }
   ```
   **Line 289 short-circuits to `approve` BEFORE `options.verificationRecord` is checked.**
2. In `evaluatePostVerificationGate`:
   The gate evaluates only producer findings (`consensus.findings`). It completely ignores `verificationRecord.verifierOmissions`.
3. Deterministic test in `rca-cycle-0047-diagnostics.mjs` proved:
   Passing a clean consensus with a `verificationRecord` containing a **CRITICAL** omission still returned **`APPROVE`**!

---

## 3. Architecture Specification

### 3.1 Workstream 007-B: Zero-Finding Quorum Verification (Clean Challenge)
When the tri-party consensus yields 0 findings (`consensus.findings.length === 0`), Triad-Flow must NOT immediately issue an unverified approval.

1. **Clean Challenge Invocation:**
   - In `scripts/dogfood-review.mjs`:
     When `consensus.quorumReached === true` and `consensus.findings.length === 0`, `conductIndependentVerification` MUST be invoked with `mode: "clean_challenge"`.
2. **Clean Challenge Prompting:**
   - The verifier is explicitly presented with:
     - The stated `patchObjective` and pre-bound exclusions.
     - The fact that sentries reported 0 findings.
     - An adversarial mandate: "Actively cross-examine whether the implementation has edge-case omissions, unhandled data types, or contradictions with the declared objective (especially boundary inputs mentioned in the objective)."
     - Verifier reports any newly discovered defects in `verifierOmissions`.
3. **False Hold Prevention Invariant:**
   - The Clean Challenge does NOT invert the gate to `BLOCK` by default.
   - If the verifier confirms no defects (`verifierOmissions.length === 0`), the gate cleanly issues `APPROVE`.
   - Only confirmed, objective-falsifying, or critical/high omissions alter the disposition.

### 3.2 Workstream 007-C: Gate Harness Authority over Verifier Omissions
Modify `src/core/harness.mjs` to establish full gate authority over `verifierOmissions`:

1. **Eliminate Short-Circuit Before Verification:**
   - Move `if (options?.verificationRecord) return evaluatePostVerificationGate(...)` **above** the `if (findings.length === 0)` check.
   - When a `verificationRecord` is present, it MUST always govern gate evaluation.
2. **Incorporate `verifierOmissions` into `evaluatePostVerificationGate`:**
   - Iterate over `verificationRecord.verifierOmissions`:
     - Omission with severity `critical` or `high` -> `decision: "block"`.
     - Omission marked `falsifiesPatchObjective === true` -> `decision: "block"`.
     - Omission in Tier 1 with severity `medium` -> `decision: "block"`.
     - Omission in Tier 2 with severity `low` (not falsifying objective) -> advisory, does not block.
3. **Ensure Complete Verification Coverage Reporting:**
   - In `review-run-report.mjs` and SARIF export, surface verified omissions as distinct findings with provenance `source: "verifier_omission"`.

### 3.3 Workstream 007-D: Local Callee Context Enclosure Injection
Enhance `src/adapters/review-prompts.mjs` and `src/core/git-collector.mjs`:

1. When a unified diff calls a member function or local function in the same modified file that is not part of the diff hunks:
   - Extract the function signature and first N lines (or complete definition if < 30 lines) into `contextPackage.layers.layer1AstEnclosure.enclosingFunctions`.
   - Provide this context package to `buildEvidenceReviewPrompt`.
2. Sentries now have direct visibility into internal preconditions (such as `isMapValueDefault`) of called functions.

---

## 4. Invariants & Zero-Runtime-Dependency Contract

1. **Zero Runtime Dependencies:**
   - `package.json` runtime `dependencies` remains `{}`.
2. **Preservation of Existing Test Baseline:**
   - All 679 existing tests must pass with 0 regressions.
3. **Fail-Closed Verification Boundary:**
   - If the Clean Challenge verifier times out, encounters an auth error, or emits malformed output, the gate must fail-closed according to existing Tier risk policies (`DEGRADED` / `BLOCK`), never fabricating a synthetic clean approval.
4. **Strict LF Line Endings:**
   - All modified files must enforce `contains CR: false`.

---

## 5. Acceptance Criteria

1. [ ] `docs/benchmarks/rca-cycle-0047-evidence.json` exists and is validated.
2. [ ] `docs/benchmarks/rca-cycle-0047-diagnostic-report.json` exists and is validated.
3. [ ] `docs/specs/loop2-systemic-remediation-007-spec.md` approved.
4. [ ] `evaluateGateDecision` with 0 producer findings and 1 critical `verifierOmission` returns `BLOCK` (proven via regression test).
5. [ ] `dogfood-review.mjs` invokes Clean Challenge when `findings.length === 0`.
6. [ ] Full test suite passes (`npm test`, 679+ tests pass, 0 fail).
7. [ ] Three-platform CI passes across macOS Node 22, Ubuntu Node 18, Windows Node 20.
