# LOOP2-SYSTEMIC-REMEDIATION-007 Specification
## Zero-Finding Quorum Verification, Verifier Omission Assessment & Local Callee Context Architecture

**Status:** REVISED SPECIFICATION (Addressing Formal Review Feedback v2)
**Classification:** LOOP 2 (Systemic Remediation)
**Issue Reference:** GitHub Issue #37
**Authority Mode:** SHADOW_DOGFOOD (Advisory Only, Runtime Authority: NONE)
**Origin Failure:** `CYCLE-0047` False Advance (`ClickHouse/ClickHouse#123335`, Commit `18f9c9d0db2fb7374b0545f3fa9542809107702a`)
**Frozen Baseline:** Phase 4.5 Cohort `CYCLE-0040..0047` (8 cycles, 1 FA, 2 FH, 0 timeout cycles)
**Escalation Action:** `IMMEDIATE_BLOCKER`
**Primary Learning Owner:** Harness Gate Policy (`harness.mjs`), Verification Pipeline (`independent-verifier.mjs`, `dogfood-review.mjs`), Context Engine (`review-prompts.mjs`, `git-collector.mjs`)

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

Detailed diagnostic evaluation (`scripts/rca-cycle-0047-diagnostics.mjs`, `docs/benchmarks/rca-cycle-0047-evidence.json`, `docs/benchmarks/rca-cycle-0047-diagnostic-report.json`) establishes four interlocking root causes alongside explicitly documented evidence limitations:

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
3. Deterministic unit diagnostic in `rca-cycle-0047-diagnostics.mjs` proved:
   Passing a clean consensus with a `verificationRecord` containing a **CRITICAL** omission still returned **`APPROVE`**!

### 2.5 Explicit Evidence Limitations (EVIDENCE_LIMITATION)
1. **Raw Provider Stdout Unarchived:** Full raw stdout text emitted by live provider processes in CYCLE-0047 was not captured in the dogfood ledger prior to workspace git restore; status (`empty`), latency, and 0 findings are verified, but raw stdout strings are unarchived.
2. **Counterfactual Context Not Live Executed:** The counterfactual prompt with injected callee context was verified for structural and syntactic assembly in unit diagnostics, but has not been submitted to live provider APIs. It remains a diagnostic hypothesis, not empirical proof of live model detection.

---

## 3. Architecture Specification

### 3.1 Workstream 007-B: Clean Challenge Decision Matrix & Execution Contract
When the tri-party consensus yields 0 findings (`consensus.findings.length === 0`), Triad-Flow must NOT immediately issue an unverified approval. It must execute a formal **Clean Challenge** verification stage.

#### 3.1.1 Complete Clean Challenge Decision Matrix
The Advisory Gate disposition is governed strictly by the following deterministic truth table:

| Clean Challenge Result | Evaluated Condition | Advisory Gate Decision | Rationale |
|---|---|---|---|
| **Clean Confirmation** | Verifier execution complete (`ok: true`), 0 omissions, complete file coverage | `APPROVE` | Unanimous clean quorum independently verified against declared objective. |
| **Confirmed Objective Violation** | Omission verified with `evidenceSupport: "SUPPORTED"` AND `objectiveImpact: "FALSIFIES_PATCH_OBJECTIVE"` (any severity) | `BLOCK` | Verified functional regression directly contradicting patch claims. |
| **Confirmed Critical / High Omission** | Omission verified with `evidenceSupport: "SUPPORTED"` AND severity `critical` or `high` | `BLOCK` | Verified high-severity security/correctness defect missed by sentries. |
| **Supported Medium Omission (Tier 1)** | Omission verified with `evidenceSupport: "SUPPORTED"`, severity `medium`, in Tier 1 high-risk policy | `BLOCK` | High-risk repository policy strictly blocks on confirmed medium defects. |
| **Supported Medium Omission (Tier 2)** | Omission verified with `evidenceSupport: "SUPPORTED"`, severity `medium`, `DOES_NOT_FALSIFY_PATCH_OBJECTIVE` | `HUMAN_REVIEW_REQUIRED` | Defect confirmed but does not falsify objective; requires human adjudication without automatic hard block. |
| **Supported Low Omission (Tier 1)** | Omission verified with `evidenceSupport: "SUPPORTED"`, severity `low`, `DOES_NOT_FALSIFY_PATCH_OBJECTIVE` | `HUMAN_REVIEW_REQUIRED` | Tier 1 high-risk policy surfaces confirmed defects for human confirmation. |
| **Supported Low Omission (Tier 2)** | Omission verified with `evidenceSupport: "SUPPORTED"`, severity `low`, `DOES_NOT_FALSIFY_PATCH_OBJECTIVE` | `APPROVE` (Advisory) | Non-blocking minor finding; surfaces as advisory finding without blocking merge. |
| **Contested Omission (Tier 2)** | Omission marked `evidenceSupport: "CONTESTED"` by verifier reasoning / invariants | `APPROVE` (Advisory) | Invariants protect code path; solitary contested omission removed from blocking set. |
| **Contested Omission (Tier 1)** | Omission marked `evidenceSupport: "CONTESTED"` with severity `critical` or `high` | `HUMAN_REVIEW_REQUIRED` | High-severity contested defect under Tier 1 policy requires human adjudication. |
| **Unverified / Insufficient Evidence** | Omission reported but `evidenceSupport: "INSUFFICIENT_EVIDENCE"` (lacks concrete counterexample) | `HUMAN_REVIEW_REQUIRED` | Potential defect lacks conclusive proof; prevents False Hold while halting unverified advance. |
| **Context Insufficient / Uncertain** | Verifier explicitly declares `overallStatus: "UNCERTAIN"` or omission `evidenceSupport: "UNCERTAIN"` due to missing callee context | `HUMAN_REVIEW_REQUIRED` | Cleanliness cannot be certified without missing contextual boundaries; never APPROVE. |
| **Clean Challenge Missing / Bypassed** | Zero findings consensus reached, but `verificationRecord` is null, omitted, or missing | `BLOCK` (Fail-Closed) | Preliminary `preGate=approve` cannot grant final release; clean claim without verification fails closed. |
| **Execution Failure / Timeout / Malformed** | Verifier execution timed out, auth failure, or unparseable JSON output | `BLOCK` (Fail-Closed) | Verification incomplete; zero capability forgery under fail-closed contract. |

#### 3.1.2 Execution Isolation Constraints
1. **Zero Oracle Leakage:** The Clean Challenge prompt must NEVER receive Human Oracle verdicts, GitHub issue discussions, or reviewer comments.
2. **Verifier Provenance Isolation:** The verifier is invoked in a clean execution context with a specialized prompt (`mode: "clean_challenge"`). When Claude is used as the verifier, its provenance must be logged explicitly as `verifier_identity: "claude-5.5-sonnet (independent_verifier_stage)"`, acknowledging same-model-family status while enforcing strict prompt and execution session isolation.

---

### 3.2 Workstream 007-C: Record Trust Model & Run Context Binding (P1 Fix)

Directly awarding blocking authority to unvalidated verifier omissions risks converting False Advances into an explosion of False Holds. To establish authoritative, auditable, and unforgeable verification gates, `REMEDIATION-007` defines a **Dual-Layer Record Trust Model** and **Normalized Run Context Binding**.

#### 3.2.1 Structured Omission Assessment Schema
Every omission emitted in `verificationRecord.verifierOmissions` must adhere to this exact normalized schema:

```json
{
  "findingId": "omission-1",
  "title": "Concise issue title",
  "severity": "critical|high|medium|low|info",
  "evidenceSupport": "SUPPORTED|CONTESTED|INSUFFICIENT_EVIDENCE|UNCERTAIN",
  "objectiveImpact": "FALSIFIES_PATCH_OBJECTIVE|DOES_NOT_FALSIFY_PATCH_OBJECTIVE|NOT_ASSESSED",
  "locatorAccurate": true,
  "file": "path/to/file",
  "line_start": 1,
  "line_end": 1,
  "confirmationSource": "independent_validation",
  "reasoning": "Concrete, observable counterexample demonstrating failure",
  "dissent": null
}
```

1. **`evidenceSupport` Strict Evaluation Rules:**
   - `SUPPORTED`: Valid ONLY if the verifier supplies a non-empty `file`, valid positive `line_start`/`line_end`, non-empty `reasoning`, and a concrete, observable counterexample. A bare model self-claim without a verifiable failure path MUST be normalized by the verifier pipeline to `INSUFFICIENT_EVIDENCE`.
   - `INSUFFICIENT_EVIDENCE`: Verifier notes a theoretical concern or missing documentation without an observable failure path.
   - `CONTESTED`: Verifier demonstrates that the suspected flaw is unreachable, sanitized upstream, or protected by existing state invariants.
   - `UNCERTAIN`: Verifier cannot confirm reachability or behavior due to external dependencies or declared context gaps.
2. **`confirmationSource` Invariant:**
   - Must be set strictly by the trusted verification pipeline (`"independent_validation"`), never self-assigned by raw model text.

#### 3.2.2 Dual-Layer Record Trust Model (P1-01 Fix)
To prevent forged or detached objects from wielding gate authority:
1. **In-Process Capability Registry (`WeakSet`):**
   - Triad-Flow maintains a module-private registry: `const trustedVerificationRegistry = new WeakSet();`.
   - Only `conductIndependentVerification` can mint and register an active `verificationRecord` instance into this WeakSet upon successful validation.
   - Any plain object, detached copy, or synthetic mock passed to `evaluateGateDecision` that is not an active member of `trustedVerificationRegistry` is rejected immediately with:
     ```text
     Gate Fail-Closed: Untrusted verification record capability (UNTRUSTED_VERIFICATION_RECORD).
     ```
2. **Cross-Process & Persistent Verification Boundaries:**
   - When verification records are serialized across processes or persisted to disk, plain SHA-256 digests are treated strictly as Content Digests, NOT authentication proofs.
   - Cross-process authority requires cryptographic HMAC or signature authentication using an ephemeral run-scoped secret key, preventing replay or manipulation.

#### 3.2.3 Normalized Run Context Binding (P1-02 Fix)
To eliminate format collisions and mismatch rejections across internal components, Triad-Flow establishes a canonical `RunContext` structure and normalized comparison rules:

```javascript
export class RunContext {
  constructor(options = {}) {
    this.runId = String(options.runId || "");
    this.headSha = normalizeCommitSha(options.headSha || options.head || "");
    this.contentDigest = normalizeDigest(options.contentDigest || options.changeSetDigest || "");
    this.patchObjective = normalizeObjective(options.patchObjective || options.objectiveContract?.objective || "");
    this.objectiveContract = options.objectiveContract || null;
  }
}
```

1. **Digest Normalization (`normalizeDigest`):**
   - Strips optional `sha256:` prefix, trims whitespace, and converts to 64-character lowercase hexadecimal:
     ```javascript
     export function normalizeDigest(digest) {
       const raw = String(digest || "").trim().toLowerCase();
       return raw.startsWith("sha256:") ? raw.slice(7) : raw;
     }
     ```
   - Bound check: `normalizeDigest(verificationRecord.changeSetDigest) === normalizeDigest(runContext.contentDigest)`.
2. **Objective Normalization (`normalizeObjective`):**
   - Normalizes whitespace, trimming, and casing:
     ```javascript
     export function normalizeObjective(obj) {
       return String(obj || "").trim().replace(/\s+/g, " ");
     }
     ```
   - Source clarification: `patchObjective` is sourced from `runContext.patchObjective` (not assumed to exist on raw git `changeSet`).
   - Bound check: If `runContext.patchObjective` is non-empty, `normalizeObjective(verificationRecord.patchObjective) === normalizeObjective(runContext.patchObjective)`.
3. **Head SHA Normalization (`normalizeCommitSha`):**
   - `conductIndependentVerification` is updated to accept and record `headSha: runContext.headSha`.
   - Bound check: `normalizeCommitSha(verificationRecord.headSha) === normalizeCommitSha(runContext.headSha)`.
4. **Mismatch Rejection:**
   - If any bound check fails, the gate MUST reject the execution with:
     ```text
     Gate Fail-Closed: Verification record binding mismatch (FORGED_OR_STALE_RECORD).
     ```

#### 3.2.4 Gate Evaluation Pipeline Reordering
In `src/core/harness.mjs`:
1. First, verify trusted capability: `isTrustedVerificationRecord(options.verificationRecord)`.
2. Second, verify `RunContext` binding integrity.
3. Third, move `verificationRecord` processing **strictly before** `if (findings.length === 0)`:
   - When `findings.length === 0`:
     - If `!options.verificationRecord`: `decision: "block"`, `reason: "Clean Challenge missing: zero-finding consensus requires independent verification record"`.
     - If `options.verificationRecord`: Evaluate against §3.1.1 Clean Challenge Decision Matrix.

---

### 3.3 Workstream 007-D: Local Callee Context Engineering Contract
To eliminate diff-context truncation without causing context bloat or hallucinations, `REMEDIATION-007` establishes four hard engineering constraints for local callee extraction:

#### 3.3.1 Exact-Head Source Invariant
Callee function definitions MUST be extracted directly from the target commit using:
```bash
git show <headSha>:<filePath>
```
Extracting code from the working tree directory is strictly prohibited, as the local workspace may contain uncommitted modifications or telemetry artifacts.

#### 3.3.2 Deterministic Parsing & Context Gap Propagation
1. Extraction is restricted to member functions and file-local functions within the same file being modified by the diff.
2. If a called symbol has multiple overloads, is generated by a C++ macro, is a dynamic dispatch / virtual interface, or cannot be unambiguously located, the context engine MUST NOT guess.
3. It must record the callee in `contextPackage.layers.layer1AstEnclosure.unresolvedCallees` with reason `AMBIGUOUS_SYMBOL` or `MACRO_OR_DYNAMIC`.
4. **Context Gap Propagation:**
   - If an unresolved callee is on an execution path referenced by the diff and relates to input validation, default values, or error handling, the context engine records `contextGaps: [{ symbol, reason, file, line }]`.
   - This `contextGaps` block is rendered into the prompt under `[UNRESOLVED CODE CONTEXT GAPS]`.
   - **Verifier Mandate:** When a critical context gap exists, the Verifier MUST NOT certify clean; it must report `overallStatus: "UNCERTAIN"` or mark the boundary as `evidenceSupport: "UNCERTAIN"`, directing the Advisory Gate to `HUMAN_REVIEW_REQUIRED`.

#### 3.3.3 Strict Content Budget & Extraction Bounds
1. **Quantity Ceiling:** Maximum 5 callee functions per modified file; maximum 10 callee functions across the entire changeSet.
2. **Snippet Size Bound:**
   - If the callee function is short ($\le 30$ lines), extract the **complete function body**.
   - If the callee function is long ($> 30$ lines), extract the function signature, argument preconditions, input validation checks, early-return guards, and the closing brace (maximum 60 lines or 2,000 bytes per function). Arbitrary truncation of the first 30 lines is prohibited.
3. **Global Context Ceiling:** Total AST context package must not exceed **8,000 bytes**.
4. **Diff Non-Interference:** AST context is additive and must NEVER displace, truncate, or starve the diff hunks. Diff hunks retain absolute budget priority.

#### 3.3.4 Dual Visibility
The generated `contextPackage` MUST be injected simultaneously into:
1. Sentry review prompts (`buildEvidenceReviewPrompt` during primary review).
2. Clean Challenge verifier prompts (`buildVerificationPrompt` during verification).
Both sentries and verifiers operate on identical contextual enclosures.

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

## 5. Formal Acceptance Matrix (Gate Out)

The implementation must strictly satisfy the 18 normative test contracts prior to milestone closure:

| Test ID | Test Scenario | Expected Outcome |
|---|---|---|
| `007-B-01` | Clean Challenge completes successfully with 0 omissions | `decision: "approve"` |
| `007-B-02` | Clean Challenge encounters timeout budget exhaustion | Gate fails closed (`BLOCK` / `DEGRADED`) |
| `007-B-03` | Clean Challenge emits malformed or unparseable JSON | Gate fails closed (`BLOCK` / `DEGRADED`) |
| `007-B-04` | 0 Findings consensus but Clean Challenge missing / null record | Gate fails closed (`BLOCK`, reason: `Clean Challenge missing`) |
| `007-C-01` | Clean Challenge reports confirmed `FALSIFIES_PATCH_OBJECTIVE` omission | `decision: "block"` |
| `007-C-02` | Clean Challenge reports solitary unconfirmed Critical omission (`INSUFFICIENT_EVIDENCE`) | `decision: "human_review_required"` |
| `007-C-03` | In-process capability forgery probe (plain object with matching fields rejected) | Gate fails closed (`BLOCK`, `UNTRUSTED_VERIFICATION_RECORD`) |
| `007-C-04` | Verification record with mismatched `changeSetDigest`, `patchObjective`, or `headSha` | Rejection / `BLOCK` (`FORGED_OR_STALE_RECORD`) |
| `007-C-05` | Clean Challenge reports verified Low omission (`DOES_NOT_FALSIFY_PATCH_OBJECTIVE`) in Tier 2 | `decision: "approve"` + Advisory finding |
| `007-C-06` | Clean Challenge reports `CONTESTED` omission in Tier 2 | Advisory pass (`decision: "approve"`) |
| `007-C-07` | Clean Challenge reports verified Medium omission (`DOES_NOT_FALSIFY`) in Tier 1 | `decision: "block"` (Tier 1 strict policy) |
| `007-C-08` | Clean Challenge reports verified Medium omission (`DOES_NOT_FALSIFY`) in Tier 2 | `decision: "human_review_required"` |
| `007-C-09` | Clean Challenge reports `UNCERTAIN` omission or state | `decision: "human_review_required"` |
| `007-D-01` | Exact head extraction of out-of-diff callee definition (CYCLE-0047 SHA) | Successfully extracts `traverseMapElementValueNode` into context |
| `007-D-02` | Callee with ambiguous macro or dynamic overload propagated as context gap | Verifier flags `UNCERTAIN` -> `decision: "human_review_required"` |
| `007-D-03` | Context size exceeds 8 KB ceiling | Bounded extraction preserves diff without budget exhaustion |
| `007-R-01` | CYCLE-0047 post-hoc diagnostic re-test | Defect identified by Clean Challenge or callee context |
| `007-R-02` | CYCLE-0042 / CYCLE-0044 known positive controls | Clean Challenge confirms clean status without False Hold |
| `007-R-03` | Full test suite across 3 platforms (Node 18/20/22 on Ubuntu/macOS/Windows) | 679+ tests pass, 0 fail, 0 regressions |

---

## 6. Telemetry & Reliability Monitoring

Because the Clean Challenge introduces a secondary verifier execution on zero-finding changesets, the implementation must track operational overhead in `dogfood-run.json`:
1. `cleanChallengeAttempted: boolean`
2. `cleanChallengeDurationMs: number`
3. `cleanChallengeStatus: "SUCCESS" | "TIMEOUT" | "ERROR" | "SKIPPED"`
4. Cumulative cycle timeout rate must remain $< 5.0\%$, preserving the reliability guarantees established under REMEDIATION-006.
