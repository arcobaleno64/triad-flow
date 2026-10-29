# PR #39 G4 Batch 2 P1 Closure Dossier & Technical Verification

**Date**: 2026-10-26 / 2026-10-27  
**Repository**: `arcobaleno64/triad-flow`  
**Target PR**: #39 (`fix/remediation-007-clean-challenge`)  
**Target Exact HEAD**: `ec750e6010edd8d6f3fb8007a59994644b98862c`  
**Governing Decrees**: `PR39-SCHEMA2-G4-PILOT-FIVE-REVIEW-R1` (Executed), `PR39-SCHEMA2-G4-BATCH2-REVIEW-R1` (Adjudicated & Executed)  
**Governance Posture**: G1 (PASS) $\to$ G2 (PASS) $\to$ G3 (PASS) $\to$ G4 (Batch 1: 5 Resolved; Batch 2: `ra7kM` Resolved, 6 on Hold)

---

## 1. Executive Summary & Population State

Following the successful execution and closure of Pilot Five Current P1 review threads (`qo0uT`, `qo0uc`, `qwj_y`, `rTowu`, `rVNc5`) under Reviewer Decree `PR39-SCHEMA2-G4-PILOT-FIVE-REVIEW-R1`, this dossier conducted an exhaustive, physical-code audit of candidate Current P1 review threads under Default-Deny and Presumption of Non-Pass principles.

### Population Tracking (180 Total Threads)
- **Resolved**: 17 threads (Initial Pilot Five + Six P1s + Pilot Five Current P1s + `ra7kM`)
- **Unresolved**: 163 threads
  * **P1 Threads (116 Total)**:
    - **Current (28)**: 6 audited below on `STRICT_HOLD` (`rVNc6`, `rfkYi`, `rrHOc`, `rr-I6`, `tgXSH`, `tgXSI`), 22 remaining.
    - **Outdated (88)**: Retained on `STRICT_HOLD`.
  * **P2 Threads (47 Total)**:
    - **Current (26)**: Retained on `STRICT_HOLD`.
    - **Outdated (21)**: Retained on `STRICT_HOLD`.

---

## 2. Technical Audit of Candidate Batch 2 Threads

In accordance with the working agreements on evidence priority and the obligation of dissent, each thread was audited against the physical codebase at committed HEAD `ec750e6010edd8d6f3fb8007a59994644b98862c`.

### Summary Findings & Reviewer Adjudication Table

| Short ID | Thread ID | Severity | File Location | Physical Audit Status | Reviewer Ruling (`PR39-SCHEMA2-G4-BATCH2-REVIEW-R1`) | Action Taken |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `ra7kM` | `PRRT_kwDOUWarIc6ra7kM` | P1 | `src/core/context-builder.mjs:2238` | **FIXED_VERIFIED** | **AUTHORIZED** | **POST_REPLY & RESOLVED** |
| `rVNc6` | `PRRT_kwDOUWarIc6rVNc6` | P1 | `src/core/context-builder.mjs:1767` | **FIXED_PENDING_VERIFY** | **HOLD** (requires non-sensitive baseline test) | **STRICT_HOLD** |
| `rrHOc` | `PRRT_kwDOUWarIc6rrHOc` | P1 | `src/core/context-builder.mjs:3020` | **OPEN_REQUIRES_VERIFICATION** | **HOLD** (single-file branch uses raw diffHunks) | **STRICT_HOLD** |
| `tgXSH` | `PRRT_kwDOUWarIc6tgXSH` | P1 | `src/adapters/staged-review.mjs:600` | **FIXED_PENDING_VERIFY** | **HOLD** (requires forged callee negative test) | **STRICT_HOLD** |
| `tgXSI` | `PRRT_kwDOUWarIc6tgXSI` | P1 | `src/core/independent-verifier.mjs:801` | **FIXED_PENDING_VERIFY** | **HOLD** (requires out-of-manifest callee test) | **STRICT_HOLD** |
| `rfkYi` | `PRRT_kwDOUWarIc6rfkYi` | P1 | `src/adapters/review-prompts.mjs:260` | **OPEN_DEFECT** | **HOLD** (XML tag omits `file` attr) | **STRICT_HOLD** |
| `rr-I6` | `PRRT_kwDOUWarIc6rr-I6` | P1 | `src/core/context-builder.mjs:1688` | **OPEN_DEFECT** | **HOLD** (`BUILTIN_OBJECT_METHODS` skip precedes receiver check) | **STRICT_HOLD** |

---

### Detailed Per-Thread Technical Analysis

#### 1. Thread `ra7kM` (`PRRT_kwDOUWarIc6ra7kM`) — RESOLVED
- **Reviewer Comment**: "When an added call targets an imported sensitive helper, this branch silently skips it instead of recording it as unresolved. For example, `import { validateAccess } from './auth.js'` followed by an added `validateAccess(user)` produces neither a callee definition nor a `contextGap`, so a Clean Challenge can certify the change without seeing the authorization implementation. Imported sensitive calls should remain explicit external-context gaps unless their definitions are resolved."
- **Physical Code Evidence**:
  In `src/core/context-builder.mjs:2274-2295`:
  ```javascript
  const isImported = importedSymbols.has(candidate.symbol) ||
    (Array.isArray(candidate.qualifiers) && candidate.qualifiers.some(q => q !== "this" && importedSymbols.has(q))) ||
    Boolean(candidate.qualifier && candidate.qualifier !== "this" && importedSymbols.has(candidate.qualifier));

  if (isImported) {
    const unresolvedEntry = {
      symbol: candidate.symbol,
      ...(candidate.qualifier ? { qualifier: candidate.qualifier } : {}),
      reason: "EXTERNAL_CALLEE_UNRESOLVED",
      file: targetFile,
      line: candidate.line
    };
    unresolvedCallees.push(unresolvedEntry);
    if (candidate.isSensitive && candidate.isAdded) {
      contextGaps.push({
        ...unresolvedEntry,
        category: candidate.category || "input_validation",
        impact: `External imported callee definition unavailable on sensitive execution path`
      });
    }
    continue;
  }
  ```
- **Deterministic Test Proof**:
  `tests/remediation-007-clean-challenge.test.mjs:2301-2365` (`007-AUDIT-THREAD-38: External imported sensitive callee records EXTERNAL_CALLEE_UNRESOLVED context gap`):
  Tests both ESM `import` and CommonJS `require()` bindings; verifies that `authorizeAdminSession` and `verifySignature` emit `EXTERNAL_CALLEE_UNRESOLVED` context gaps.
  And `tests/remediation-007-clean-challenge.test.mjs:2564-2586` (`007-AUDIT-THREAD-38-NEGATIVE`): verifies that context lines calling sensitive imports do not create spurious context gaps.
- **Reviewer Adjudication**: Full G4-B authorization granted under `PR39-SCHEMA2-G4-BATCH2-REVIEW-R1`.

---

#### 2. Thread `rVNc6` (`PRRT_kwDOUWarIc6rVNc6`) — STRICT_HOLD
- **Reviewer Adjudication**: In `tests/remediation-007-clean-challenge.test.mjs:2071` (`007-AUDIT-THREAD-32`), the test used `sanitizeInput` as the first call. However, `classifySensitiveCategory("sanitizeInput")` already returns `"input_validation"`, meaning the first call was already sensitive. The test fails to directly prove an initially benign call (e.g. `helper()`) upgrading to sensitive when subsequently called with sensitive parameters.
- **Action Required to Unlock**: Provide a test showing an initially non-sensitive `helper()` upgrading `isSensitive` from `false` to `true` upon subsequent sensitive invocation.

---

#### 3. Thread `rrHOc` (`PRRT_kwDOUWarIc6rrHOc`) — STRICT_HOLD
- **Reviewer Adjudication**: While `src/core/context-builder.mjs:2809` isolates diffs in the multi-file path via `splitDiffByFiles`, in the single-file branch starting at line 3125, line 3134 takes `changeSet.diffHunks` directly and line 3232 passes it to `extractLocalCalleeContext`. A multi-file ChangeSet passed into single-file mode could still allow cross-file callee resolution pollution.
- **Action Required to Unlock**: Establish test proving single-file mode isolates diff hunks or that such unisolated packages fail closed at downstream verification gates.

---

#### 4. Threads `tgXSH` & `tgXSI` — STRICT_HOLD
- **Reviewer Adjudication**: While Schema v2 implemented dynamic freshness and manifest set-binding, existing tests in `schema-v2-set-binding.test.mjs` test manifest structure and completeness, but do not directly supply a forged callee definition while HEAD/Digest/Manifest match (`tgXSH`), nor a callee outside the manifest directly injected into package layers (`tgXSI`).
- **Action Required to Unlock**: Provide negative unit tests asserting fail-closed rejection on forged callee definitions and out-of-manifest snippets.

---

#### 5. Threads `rfkYi` & `rr-I6` — STRICT_HOLD (Open Defect Confirmed)
- Concurred between agent audit and reviewer:
  * `rfkYi`: `<callee>` XML serialization omits `file="..."`.
  * `rr-I6`: `BUILTIN_OBJECT_METHODS.has(sym)` early exit runs before receiver qualification.
- **Action Required to Unlock**: Code remediation in an authorized commit.

---

## 3. Reviewer Decree `PR39-SCHEMA2-G4-BATCH2-REVIEW-R1`

The Reviewer in ChatGPT conversation `6adf3e84-1770-83ee-9374-e18b6834e5d9` issued decree `PR39-SCHEMA2-G4-BATCH2-REVIEW-R1`:

```
PARTIAL_AUTHORIZATION
G4-A_REVIEW: COMPLETED
G4-B_REPLY: AUTHORIZED (ra7kM only)
G4-B_RESOLVE: AUTHORIZED (following reply verification)
Remaining 6 Threads: STRICT_HOLD
NEW_COMMIT / PUSH: NOT_AUTHORIZED
SQUASH_MERGE: NOT_AUTHORIZED
```

---

## 4. Execution Receipts for `ra7kM`

In accordance with the enforced transactional protocol:
`VERIFY_HEAD → VERIFY_THREAD → POST_REPLY → VERIFY_REPLY → RESOLVE → VERIFY_RESOLUTION`

1. **VERIFY_HEAD**:
   - HEAD SHA: `ec750e6010edd8d6f3fb8007a59994644b98862c` (Verified Match).
2. **VERIFY_THREAD**:
   - Thread ID: `PRRT_kwDOUWarIc6ra7kM` (Verified: `isResolved = false`, `comments = 1`).
3. **POST_REPLY**:
   - Comment ID: `PRRC_kwDOUWarIc8AAAABBU03VA`
   - Database ID: `4383913812`
   - Created At: `2026-10-27T00:23:19Z`
   - Content:
     ```markdown
     Addressed in `src/core/context-builder.mjs:2274-2295`, present in HEAD `ec750e6010edd8d6f3fb8007a59994644b98862c`.

     Imported callees are recorded as unresolved with `EXTERNAL_CALLEE_UNRESOLVED`. Sensitive calls on added lines also produce explicit context gaps instead of silently disappearing from verification coverage.

     Covered by `007-AUDIT-THREAD-38` (ES module and CommonJS imports) and `007-AUDIT-THREAD-38-NEGATIVE` (unchanged context-line exclusion) in `tests/remediation-007-clean-challenge.test.mjs`.

     GitHub Actions Run `40318991855` passed across Ubuntu, Windows, and macOS.
     ```
4. **VERIFY_REPLY**:
   - Verified present in GraphQL `thread.comments.nodes`.
5. **RESOLVE**:
   - Executed `resolveReviewThread(input: { threadId: "PRRT_kwDOUWarIc6ra7kM" })`.
6. **VERIFY_RESOLUTION**:
   - Confirmed on GitHub: `isResolved = true`.

---

## 5. Post-Execution Population State

- **GitHub Live Verification**:
  - Total Threads: 180
  - **Resolved Threads: 17** (9.44%)
  - **Unresolved Threads: 163** (90.56%)
    * P1 Unresolved: 116 (28 Current, 88 Outdated)
    * P2 Unresolved: 47 (26 Current, 21 Outdated)
