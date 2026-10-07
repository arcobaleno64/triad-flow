# Triad-Flow Loop 2 Systemic Remediation Specification (LOOP2-SYSTEMIC-REMEDIATION-003)

## 1. Executive Summary & Governance Authorization

### 1.1 Governance Status & Authority Classification
- **Remediation Cycle**: `LOOP2-SYSTEMIC-REMEDIATION-003`
- **Governance Classification**: **Strictly Loop 2 (Operational & Evaluative Realignment)**.
  - *Explicit Rejection of Loop 3*: The core governance philosophy, fail-closed principles, and Default-Deny invariants are empirically validated. The Shadow Dogfooding protocol functioned exactly as intended: 2 False Advances successfully halted premature promotion rather than allowing unearned authority elevation.
- **Autonomy Progression**: **`SHADOW -> ADVISORY` STRICT HOLD (REJECTED)**.
- **Runtime Authority**: **`NONE` (Zero write, merge, or branch-protection authority)**.
  - *Advisory Clarification*: Even upon eventual graduation to `ADVISORY`, Triad-Flow retains zero merge or branch-protection authority; advisory status solely governs recommendation reliability.
- **Historical Baseline**: Cycles `CYCLE-0001` through `CYCLE-0022` (receipts 1–22 in `docs/benchmarks/dogfood-receipts.jsonl`) are **PERMANENTLY FROZEN**. Historical receipts and scorecard records shall never be rewritten or retroactively modified.

### 1.2 Core Research Directive
The central research question for this remediation phase is:
> **Can Triad-Flow reliably discern the boundary between "partial improvement" and "unmet declared objective" without inflating all Low findings into blockers?**

---

## 2. Root Cause Decomposition: The Dual Failure Mechanisms of `false-advance`

Empirical analysis of the 22-cycle historical baseline identified two distinct, complementary failure mechanisms within the `false-advance` family:

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                   Dual Failure Mechanisms in false-advance                       │
├────────────────────────────────────────┬─────────────────────────────────────────┤
│ Failure Mechanism A:                   │ Failure Mechanism B:                    │
│ Verifier Semantic Leniency             │ Sentry Detection Blindspot              │
│ (CYCLE-0021, encode/httpx#3769)        │ (CYCLE-0022, pytest-dev/pytest#14714)   │
├────────────────────────────────────────┼─────────────────────────────────────────┤
│ • Sentry Detection: SUCCEEDED          │ • Sentry Detection: FAILED (0 findings) │
│   Claude reported Low finding          │   All 3 sentries missed retained xfail  │
│ • Verifier Assessment: FAILED          │ • Verifier Assessment: NOT INVOKED      │
│   Verifier confirmed finding was true, │   Zero findings triggered clean pass;   │
│   but judged DOES_NOT_FALSIFY as an    │   verifier was never engaged            │
│   "acceptable edge case"               │                                         │
│ • Root Cause: Lack of rigorous         │ • Root Cause: Reviewers lacked PR title/│
│   algebraic falsification rubric       │   objective and diff-exception checks   │
└────────────────────────────────────────┴─────────────────────────────────────────┘
```

### 2.1 Failure Mechanism A: Verifier Semantic Leniency (`CYCLE-0021`)
- **Observed Behavior**: Reviewer identified that unhandled exceptions in mounted transport shutdown leave subsequent mounts unclosed. Verifier marked the finding `SUPPORTED`, but marked `objectiveImpact: DOES_NOT_FALSIFY_PATCH_OBJECTIVE` on the grounds that it was an "edge case" within an otherwise positive cleanup refactor.
- **Defect**: The verifier evaluated the change against informal, forgiving standards ("is the patch better than before?") rather than testing whether the observable counterexample violates the patch's stated invariant within its declared scope.

### 2.2 Failure Mechanism B: Sentry Detection Blindspot (`CYCLE-0022`)
- **Observed Behavior**: The PR explicitly claimed universal coverage ("fail + stop in all cases"), yet the diff preserved `xfail(sys.version_info >= (3, 14))`. All three sentries (`agy`, `claude`, `codex`) evaluated the diff against generic bug checklists and reported 0 findings.
- **Defect**: Sentries reviewed diff hunks in an objective vacuum without access to the PR title, body, or stated scope, and without an explicit mandate to cross-examine retained exceptional behaviors (`xfail`, `skip`, feature guards, stubs, TODOs) against claimed scope. With 0 findings, the verifier was bypassed, resulting in an automated approval.

---

## 3. Work Package 1 (WP-01): Sentry Objective Alignment

### 3.1 Objective
Equip sentry reviewers (`agy`, `claude`, `codex`) with declared patch scope and explicit mandates to cross-examine diff-level exceptions against claimed functionality, eliminating Mechanism B blindspots.

### 3.2 Technical Specification

#### 3.2.1 Sentry Input & Adapter Contract
1. In `src/adapters/cli-transport.mjs` and `scripts/dogfood-review.mjs`:
   - `executeReview(input)` accepts `patchObjective` (and optional `prMetadata: { title, body, issue }`).
   - If provided, `patchObjective` is forwarded to `buildReviewPrompt` / `buildEvidenceReviewPrompt`.
2. In `src/adapters/review-prompts.mjs`:
   - Support `patchObjective` in `buildEvidenceReviewPrompt(changeSet, role, limits, contextPackage, options)`.
   - Expose `patchObjective` inside a dedicated prompt section: `[DECLARED OBJECTIVE & SCOPE CONSTRAINTS]`.

#### 3.2.2 Sentry Cross-Examination Prompt Mandate
The review prompt must explicitly instruct sentries:
```text
[DECLARED OBJECTIVE & EXCEPTIONAL BEHAVIOR CROSS-EXAMINATION]
Declared Patch Objective:
"<patchObjective>"

Mandatory Cross-Examination Rule:
When evaluating the diff, you must actively inspect all retained or introduced exceptional constructs, including:
- Test annotations: @pytest.mark.xfail, @pytest.mark.skip, it.skip, test.skip
- Control flow guards: version checks, platform guards, stubbed returns, unhandled fallback branches
- Lingering markers: TODO, FIXME, XXX, stub implementations

Evaluate against this exact criterion:
"Does retained exceptional behavior contradict the scope the change explicitly claims to complete?"

Discipline Constraints:
- Do NOT blindly flag every xfail or skip as a blocker. If the exception covers an explicitly documented exclusion or out-of-scope subsystem, it is acceptable.
- You MUST report a finding if the retained exception directly negates or restricts the scope that the patch explicitly claims to satisfy.
- When reporting an objective contradiction, set:
  - severity: "low" (or "medium" if user-facing regression)
  - type: "OBJECTIVE_CONTRADICTION"
  - title: "Retained exceptional behavior contradicts declared patch objective"
  - recommendation: Explain what residual condition remains unmet.
```

---

## 4. Work Package 2 (WP-02): Generalized Objective-Contradiction Rubric

### 4.1 Objective
Eliminate Verifier Semantic Leniency (Mechanism A) by replacing subjective prompts and brittle heuristics with an algebraic completeness rubric.

### 4.2 Mathematical Formulation of Objective Completeness
$$\text{Objective Completeness} = \text{Declared Scope} \times \text{Documented Exclusions} \times \text{Observable Residual Counterexample}$$

### 4.3 Verifier Falsification Truth Contract
An observable counterexample verified in code constitutes `FALSIFIES_PATCH_OBJECTIVE` if and only if all three conditions are satisfied:
1. **Scope Invariant**: The observable failure condition or defect falls strictly within the **Declared Scope** of the change.
2. **Exclusion Invariant**: The failure condition is **NOT Documented as an Explicit Exclusion, Known Limitation, or Out-of-Scope Boundary** in the PR title, body, or patch description.
3. **Observable Invariant Violation**: The counterexample demonstrates an observable scenario where the stated invariant, guarantee, or acceptance criterion fails to hold.

```
┌─────────────────────────────────┬──────────────────────┬────────────────────────┐
│ Condition                       │ Exclusion Status     │ Verifier Impact        │
├─────────────────────────────────┼──────────────────────┼────────────────────────┤
│ Counterexample in Declared Scope│ NOT documented       │ FALSIFIES_PATCH_OBJECTIVE │
│ Counterexample in Declared Scope│ Documented exclusion │ DOES_NOT_FALSIFY       │
│ Counterexample outside Scope    │ Any                  │ DOES_NOT_FALSIFY       │
│ No Stated Objective provided    │ N/A                  │ NOT_ASSESSED           │
└─────────────────────────────────┴──────────────────────┴────────────────────────┘
```

### 4.4 Prompt & Verification Contract in `src/core/independent-verifier.mjs`
Update `buildVerificationPrompt` to inject the formal algebraic falsification rubric:
```text
OBJECTIVE IMPACT ADJUDICATION RUBRIC:
When determining 'objectiveImpact', apply this strict algebraic rule:
1. "FALSIFIES_PATCH_OBJECTIVE": An observable failure path or defect exists within the DECLARED SCOPE that is NOT documented as an explicit exclusion or out-of-scope boundary.
   - Example: PR claims "ensure mounted transports are closed in all cases", but an exception in transport A aborts the cleanup before transport B is reached. This is in-scope, unexcluded, and violates the claim -> FALSIFIES_PATCH_OBJECTIVE.
   - Example: PR claims "fail test session on debugger quit in all cases", but Python 3.14 remains xfail'd without being documented as a deliberate external limitation -> FALSIFIES_PATCH_OBJECTIVE.
2. "DOES_NOT_FALSIFY_PATCH_OBJECTIVE":
   - The finding identifies an incidental imperfection, code style issue, or edge case outside the declared scope.
   - OR the limitation is explicitly documented in the patch description as an intended partial scope or known boundary.
3. "NOT_ASSESSED":
   - No stated patch objective was provided.
```

---

## 5. Work Package 3 (WP-03): Discriminative Post-Remediation Cohort Protocol

### 5.1 Authoritative Baseline Freeze
- Historical receipts `CYCLE-0001` through `CYCLE-0022` in `docs/benchmarks/dogfood-receipts.jsonl` are permanently sealed.
- Historical metrics: 2 False Advances, 3 False Holds, 21 qualifying maturity cycles.
- The new post-remediation evaluation begins at `CYCLE-0023`.

### 5.2 Fresh Cohort Acceptance Gates
To qualify for any reconsideration of autonomy progression, the fresh post-remediation cohort must satisfy:
1. **Volume & Continuity**: Minimum $\ge 15$ consecutive cycles under `LOOP2-SYSTEMIC-REMEDIATION-003`.
2. **False Advance Tolerance**: **Zero (0) False Advances**. Any recurrence of `FALSE_ADVANCE` triggers an immediate terminal review.
3. **False Hold Tolerance**: False Hold rate strictly $\le 10\%$.
4. **Mandatory Case Diversity**: To prevent "comfort pass" bias, the 15 fresh cycles must deliberately include at least one qualifying instance of each of the following eight behaviors:
   - Category 1: **Objective Contradiction** (retained xfail/guard negating claimed scope)
   - Category 2: **Partial Improvement with In-Scope Defect** (unhandled cleanup/lifecycle exception)
   - Category 3: **Documented Exclusion** (partial change with explicit exclusion passing as advisory)
   - Category 4: **In-Scope Boundary Defect** (edge case violating primary functionality)
   - Category 5: **Legitimate Advisory Low** (pure style / non-blocking note passing cleanly)
   - Category 6: **Reviewer Disagreement** (inter-provider dissent recorded in ledger)
   - Category 7: **Verifier Disagreement** (`CONTESTED` or `INSUFFICIENT_EVIDENCE`)
   - Category 8: **Escalation to Human** (`HUMAN_REVIEW_REQUIRED`)

---

## 6. Implementation & Test Contract

### 6.1 Modified Files
- `src/adapters/review-prompts.mjs`: Ingest `patchObjective`, format objective cross-examination section.
- `src/adapters/cli-transport.mjs`: Forward `patchObjective` from review inputs into prompt builders.
- `src/core/independent-verifier.mjs`: Update verification prompt with algebraic completeness rubric.
- `scripts/dogfood-review.mjs`: Forward `patchObjective` to reviewer adapters during live execution.
- `tests/loop2-systemic-remediation-003.test.mjs`: Dedicated contract test suite validating:
  - Sentry prompt includes objective cross-examination rules when `patchObjective` is provided.
  - Sentry prompt omits objective cross-examination block cleanly when `patchObjective` is absent.
  - Verifier prompt correctly formats algebraic rubric.
  - Falsification truth table behaves deterministically across scope, exclusions, and counterexamples.

### 6.2 Core Invariants
- **Zero Runtime Dependencies**: `package.json` runtime `dependencies` remains empty `{}`.
- **Strict LF Line Endings**: No CRLF line endings permitted.
- **Zero Test Regressions**: All 622 existing tests continue passing.
