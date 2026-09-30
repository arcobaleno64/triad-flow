# Triad-Flow v2.3 Controlled Remediation & Patch Jail Specification

**Document ID**: `TF-SPEC-REMEDIATION-v1.0.0`  
**Schema Version**: `1.0.0`  
**Status**: Normative Specification (v2.3 Design Baseline / Plan-Only)  
**Applicability**: Remediation lifecycle state machine, Patch Jail sandbox boundaries, cryptographic patch verification, and independent closure verification.

---

## 1. Core Principles & Objective

v2.2.x established **Auditable Empirical Evidence** and **Independent Verification** (`Producer → Deterministic Manifest → Independent Verifier`).  
v2.3 introduces the next evolutionary boundary: **Controlled Remediation**.

Automated remediation without structural boundaries devolves into "single-agent confirmation bias" (一人公司式內控) — where an LLM identifies an issue, authors a patch, approves its own work, and merges changes without defense-in-depth.

Triad-Flow v2.3 enforces three foundational invariants:

1. **Separation of Roles (Producer vs. Synthesizer vs. Verifier)**:
   - **Reviewer / Producer**: Detects candidate vulnerabilities.
   - **Patch Synthesizer**: Generates candidate diffs.
   - **Independent Verifier**: Evaluates patch correctness and confirms vulnerability closure.
   - *Invariant*: The synthesizing model has zero authority to close findings or waive security policies.

2. **Monotonic Defense (單調防禦)**:
   - A finding can **only** advance to a state that demands higher affirmative empirical proof.
   - Models are mathematically and programmatically prohibited from lowering severity, deleting findings, or self-declaring `CLOSED`.

3. **Plan-Only / Zero-Production Write Boundary (Patch Jail)**:
   - All trial remediations execute strictly inside disposable, isolated **Patch Jails** (ephemeral Git worktrees).
   - Automated merges to upstream or target branches are prohibited. Remediation generates cryptographically signed patch diffs, receipts, and closure records.

---

## 2. 9-State Canonical Remediation Lifecycle State Machine

```
              ┌───────────────────────────┐
              │           OPEN            │◄────────────────┐
              └─────────────┬─────────────┘                 │
                            │ [Synthesize Diff]             │
                            ▼                               │
              ┌───────────────────────────┐                 │
              │       FIX_PROPOSED        │                 │
              └─────────────┬─────────────┘                 │
                            │ [Human / Auth Policy Gate]    │
                            ▼                               │
              ┌───────────────────────────┐                 │
              │      PATCH_AUTHORIZED     │                 │
              └─────────────┬─────────────┘                 │
                            │ [Spawns Jail Worktree]        │
                            ▼                               │
              ┌───────────────────────────┐                 │
              │   PATCH_APPLIED_IN_JAIL   │                 │
              └─────────────┬─────────────┘                 │
                            │ [Deterministic Tests Green]   │ [Regression / Contested]
                            ▼                               │
              ┌───────────────────────────┐                 │
              │    FIXED_PENDING_VERIFY   │                 │
              └─────────────┬─────────────┘                 │
                            │                               │
            ┌───────────────┴───────────────┐               │
            │ [Heterogeneous Verifier Pass] │ [Contested]   │
            ▼                               ▼               │
    ┌───────────────┐               ┌───────────────┐       │
    │    CLOSED     │               │ REJECTED_FIX  ├───────┘
    └───────┬───────┘               └───────────────┘
            │
            │ [Regression Detected]
            ▼
    ┌───────────────┐
    │   REOPENED    │
    └───────────────┘
```

### 2.1 State Definitions

| State | Mutability | Definition |
|---|---|---|
| `OPEN` | Immutable Finding | The vulnerability has been confirmed by review consensus or benchmark golden comparison. No candidate fix has been approved. |
| `FIX_PROPOSED` | Plan-Only | The synthesizer model has produced a proposed unified diff, contextual rationale, and target file boundaries. |
| `PATCH_AUTHORIZED` | Gated | A human security lead or authorized policy engine has cryptographically signed approval to evaluate the patch in sandbox isolation. |
| `PATCH_APPLIED_IN_JAIL` | Sandbox Only | The patch diff has been applied inside an ephemeral Git worktree. Pre-patch and post-patch tree digests are computed. |
| `FIXED_PENDING_VERIFY` | Sandbox Only | All deterministic unit, regression, and security tests execute cleanly (exit 0) in the worktree without failures or dirty leaks. |
| `CLOSED` | Terminal Valid | An independent verifier (different model family or cold-start verifier) affirmatively confirms the defect is neutralized without side effects. |
| `REJECTED_FIX` | Terminal Rejection | The patch caused compile errors, test regressions, altered files outside scope, introduced new findings, or was contested by the verifier. |
| `WAIVED` | Terminal Exception | A human security lead issued a cryptographically signed waiver with documented rationale and explicit expiry timestamp. |
| `REOPENED` | Active | A previously `CLOSED` or `WAIVED` finding was observed again in a newer commit diff or test regression. |

### 2.2 Transition Invariants

| From | To | Authorized Actor | Required Affidavits & Evidence |
|---|---|---|---|
| `OPEN` | `FIX_PROPOSED` | Patch Synthesizer (Model) | Unified diff conforming to unified format; declared target files; patch rationale; line bounds. |
| `FIX_PROPOSED` | `PATCH_AUTHORIZED` | Human Gate / Security Policy | Authorization token; cryptographic digest of the candidate patch diff (`patchDiffDigest`). |
| `FIX_PROPOSED` | `REJECTED_FIX` | Human Gate / Synthesizer | Rejection reason (e.g. malformed syntax, non-viable architectural direction). |
| `PATCH_AUTHORIZED` | `PATCH_APPLIED_IN_JAIL` | Jail Orchestrator (Runtime) | Worktree creation evidence; pre-patch tree digest (`prePatchTreeDigest`); clean patch application. |
| `PATCH_APPLIED_IN_JAIL` | `FIXED_PENDING_VERIFY` | Deterministic Test Runner | Test suite exit code 0; zero regressions; non-target repository files bit-for-bit unchanged. |
| `PATCH_APPLIED_IN_JAIL` | `REJECTED_FIX` | Deterministic Test Runner | Compilation failure, runtime test failure, timeout, or worktree leak. |
| `FIXED_PENDING_VERIFY` | `CLOSED` | Independent Verifier | Canonical `verificationRecord` with verdict `SUPPORTED`, 100% locator/type/severity accuracy, 0 omissions. |
| `FIXED_PENDING_VERIFY` | `REJECTED_FIX` | Independent Verifier | Verdict `CONTESTED` or `INSUFFICIENT_EVIDENCE`; entries recorded in `disagreementLedger`. |
| `OPEN` / `FIX_PROPOSED` | `WAIVED` | Human Security Lead | Cryptographic signature; mandatory `expiryTimestamp`; risk assessment justification. |
| `CLOSED` / `WAIVED` | `REOPENED` | Benchmark / Audit Producer | Active finding re-observed on repository revision past closure commit. |

---

## 3. The Patch Jail Invariant Contract (Sandbox Specification)

> [!IMPORTANT]
> **Boundary Limitation Notice**: The reference implementation establishes a **Git Worktree Isolation Boundary** preventing changes from modifying the authoritative host repository. It is **not** an OS sandbox, hypervisor, or container; network denial and OS-level environment isolation are not guaranteed in this reference implementation.

The **Patch Jail** provides deterministic isolation so candidate code cannot tamper with host state, leak credentials, or alter uninspected files.

### 3.1 Worktree Isolation
1. **Disposable Worktrees**: Jails are spawned exclusively as secondary Git worktrees (`git worktree add <scratch_dir> <base_sha>`).
2. **RAII Cleanliness**: Worktrees are pruned and removed on exit (`git worktree remove --force`), guaranteeing zero lingering temporary branches or orphaned worktrees.
3. **HEAD Immutability**: The primary repository's working tree and branch pointers are untouched.

### 3.2 Secret Insulation
1. **No Production Credentials**: Secrets (`.env`, `token`, private keys, cloud tokens) are explicitly excluded from the Jail worktree.
2. **Dummy Mock Configs**: Tests execute against mocked credentials or local fixtures only.
3. **No External Network**: Default network egress is denied during sandbox test execution.

### 3.3 Restricted Blast Radius (Target File Constraint)
1. **Target File Scope**: Remediations are strictly permitted to alter **only** the vulnerable source files cited in the finding locator (`finding.file`).
2. **Forbidden Manifests**: The Jail strictly fails closed (`REJECTED_FIX`) if a patch touches:
   - CI/CD workflow manifests (`.github/workflows/**`)
   - Package dependency files (`package.json`, `package-lock.json`, `pnpm-lock.yaml`, `go.mod`, `pom.xml`)
   - Security configurations (`.gitignore`, audit configs, security rules)
   - Uncited source files

### 3.4 Cryptographic Digest Lineage
Every Patch Jail run must measure and record:
- `prePatchTreeDigest`: SHA-256 of the worktree content tree prior to patch application.
- `patchDiffDigest`: Canonical SHA-256 of the proposed unified diff.
- `postPatchTreeDigest`: SHA-256 of the worktree content tree after patch application.
- `deltaFiles`: List of changed files and line deltas, asserting non-target files have zero delta.

---

## 4. Remediation Receipt Schema (`schemaVersion: "1.0.0"`)

Every controlled remediation trial emits an immutable `remediation-receipt.json`:

```json
{
  "schemaVersion": "1.0.0",
  "receiptId": "rem-20260930-101500-abc1",
  "findingId": "agy-finding-001",
  "status": "CLOSED",
  "timestamps": {
    "startedAt": "2026-09-30T02:15:00.000Z",
    "completedAt": "2026-09-30T02:16:30.000Z"
  },
  "actors": {
    "producer": { "providerName": "agy", "modelName": "cli-default" },
    "synthesizer": { "providerName": "claude", "modelName": "opusplan" },
    "verifier": { "providerName": "claude", "modelName": "cli-default" },
    "authorizer": { "identity": "security-lead@company.internal", "type": "human" }
  },
  "patch": {
    "patchDiffDigest": "sha256:4f8a...",
    "targetFiles": ["src/db/user-repo.js"],
    "additions": 3,
    "deletions": 2,
    "rationale": "Restored parameterized query placeholders to eliminate SQL injection."
  },
  "jail": {
    "worktreeSha": "a4d0b92f06859e75223225fce72b0c3d0b25d23d",
    "prePatchTreeDigest": "sha256:b9b1...",
    "postPatchTreeDigest": "sha256:7c5d...",
    "isolatedExecutionPass": true
  },
  "deterministicChecks": {
    "testCommand": "npm test",
    "exitCode": 0,
    "passedCount": 35,
    "failedCount": 0,
    "regressionDetected": false
  },
  "closureVerification": {
    "verified": true,
    "verificationRecordDigest": "sha256:1e77...",
    "verdict": "SUPPORTED",
    "residualVulnerabilityDetected": false
  },
  "history": [
    { "from": "OPEN", "to": "FIX_PROPOSED", "at": "2026-09-30T02:15:05.000Z", "actor": "claude" },
    { "from": "FIX_PROPOSED", "to": "PATCH_AUTHORIZED", "at": "2026-09-30T02:15:15.000Z", "actor": "security-lead" },
    { "from": "PATCH_AUTHORIZED", "to": "PATCH_APPLIED_IN_JAIL", "at": "2026-09-30T02:15:20.000Z", "actor": "orchestrator" },
    { "from": "PATCH_APPLIED_IN_JAIL", "to": "FIXED_PENDING_VERIFY", "at": "2026-09-30T02:15:45.000Z", "actor": "test-runner" },
    { "from": "FIXED_PENDING_VERIFY", "to": "CLOSED", "at": "2026-09-30T02:16:30.000Z", "actor": "claude" }
  ]
}
```

---

## 5. Anti-Thrashing Guardrails & Goodhart Protection

### 5.1 Maximum Remediation Attempts (Stop Rule)
- An automated model is granted at most **2 remediation attempts** per finding.
- If a patch fails deterministic checks or is contested twice by the independent verifier, the state transitions definitively to `REJECTED_FIX`.
- Automated loops are terminated immediately to prevent token exhaustion and hallucinatory patch thrashing.

### 5.2 Anti-Degradation Invariants (Goodhart Protection)

> [!NOTE]
> **Goodhart Enforcement Scope**: The v2.3 Reference PoC implements v0 syntactic & modifier evasion protection (detecting `.skip`, `xit/xdescribe`, `@ts-ignore/@ts-nocheck`, `eslint-disable`). Deeper semantic protections (AST schema weakening detection and fine-grained coverage gate) are designated for subsequent engine iterations.

A patch is classified as a hostile regression and rejected automatically if it:
1. Comments out, deletes, or skips existing test cases to achieve a passing exit code.
2. Disables linter or type-checker warnings via inline suppresses (e.g. `// @ts-ignore`, `/* eslint-disable */`) without human authorization.
3. Swaps strict validation schemas with loose/permissive schemas (`any`, empty schema).
4. Drops test coverage by more than 0.1% on modified modules.

---

## 6. Version Boundary & Compatibility Policy

| Component | v2.2.x Baseline | v2.3.x Scope |
|---|---|---|
| **Corpus `TF-RBC-v0`** | Frozen Baseline (`sha256:cf9c...`) | Frozen Baseline (100% Unchanged) |
| **Receipt Schema** | Schema `1.0.0` (`audit-receipt.json`) | Retained verbatim; Remediation receipts layered separately (`remediation-receipt.json`) |
| **Independent Verification** | Normative Section 7 Contract | Reused as the mandatory gatekeeper between `FIXED_PENDING_VERIFY` and `CLOSED` |
| **Worktree / Patch Execution** | Read-only inspection / disposable test | Ephemeral **Patch Jail** worktree for trial remediation |
| **Remediation State** | Unspecified / Out-of-Scope | Normative 9-state machine; Plan-Only default; human authorization required |

---

## 7. Next Assurance Gate: Controlled Remediation Proof-of-Concept

> [!NOTE]
> **Validation Status**: Controlled Remediation reference path validated on `BENCH-REAL-001` (CWE-89 SQL Injection). Full generalization across all 20 corpus cases and multi-finding scenarios remains subject to subsequent gate iterations.

To achieve v2.3.0 readiness, Triad-Flow must demonstrate:
1. `BENCH-REAL-001` candidate patch formulated strictly in `FIX_PROPOSED` plan mode.
2. Ephemeral Git worktree successfully applies patch in isolation without polluting host repository.
3. Deterministic regression tests run inside worktree and record bit-for-bit tree digests.
4. Independent verifier confirms closure in `remediation-receipt.json` before any PR diff is presented to maintainers.
