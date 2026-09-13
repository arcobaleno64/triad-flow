# Triad-Flow Real Benchmark Corpus v0 Specification
**Document ID**: `TF-DOC-BENCH-REAL-V0`  
**Status**: Target Specification (Milestone 2 Real Provider Pilot)  
**Applicability**: Triad-Flow v2.1.0+ Empirical Evaluation  

---

## 1. Executive Summary & Objective

Triad-Flow has validated its deterministic consensus, quorum invariant, fail-closed gate, and OODA livelock prevention using synthetic simulations (`BENCHMARK_FRAMEWORK_TYPE = "Simulation / Synthetic Benchmark Framework"`).

This document establishes the architecture, schema, and standard operating procedures (SOP) for **Triad-Flow Real Benchmark Corpus v0** (`TF-RBC-v0`) — a frozen, human-adjudicated dataset of 15 realistic changes designed to empirically measure and compare:
1. **Single Reviewer (Macro Sentry only)**: Google `agy`
2. **Fixed Dual Reviewer (Always Heterogeneous Quorum)**: Google `agy` (Google) + Anthropic `claude` (Anthropic)
3. **Risk-Adaptive Dynamic Routing (Triad-Flow Core)**: Graph router directing small/Tier-2/3 changes to Single Sentry and Tier-1/large/critical changes to Heterogeneous Quorum.

---

## 2. Dataset Architecture & Schema

Each benchmark case represents an isolated, reproducible Git change package with frozen SHA references, ground-truth CWE labels, and strict line-distance tolerance bounds.

### 2.1 Benchmark Case Schema

```json
{
  "id": "BENCH-REAL-001",
  "title": "SQL Injection in User Query Handler",
  "riskTier": 1,
  "category": "vulnerable",
  "repository": {
    "url": "https://github.com/arcobaleno64/triad-flow-fixtures",
    "baseSha": "e4a2b1f8...",
    "headSha": "7c9d0e12..."
  },
  "changeSet": {
    "files": ["src/db/user-query.js"],
    "totalAdditions": 4,
    "totalDeletions": 1,
    "contentDigest": "sha256-..."
  },
  "goldenFindings": [
    {
      "cwe": "CWE-89",
      "type": "sql-injection",
      "file": "src/db/user-query.js",
      "line": 42,
      "severity": "critical",
      "rationale": "Direct SQL concatenation via unescaped query parameter"
    }
  ],
  "expectedGateDecision": "block",
  "lineTolerance": 50
}
```

### 2.2 Invariants & Scoring Rules

1. **Deterministic Evaluation**: Evaluated using [`src/core/scoring.mjs`](../src/core/scoring.mjs) via `verifyHeldOutBaseline(actualFindings, goldenFindings)`.
2. **Line Distance Tolerance**: Findings within 50 lines (`MAX_LINE_DISTANCE = 50`) of the golden line number match the instance, absorbing formatting and comment drift.
3. **1-to-1 Instance Matching**: A single reported finding cannot claim multiple golden instances unless separate evidence exists.
4. **Negative Controls (Immutability & False Block)**: Clean cases MUST NOT produce blocking findings (`expectedGateDecision: "approve"`). False blocks are penalized as False Block Rate (FBR).

---

## 3. Initial 15 Adjudicated Corpus Cases

| Case ID | Type / Tier | Primary Target File | Golden CWE | Description | Expected Gate |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **BENCH-REAL-001** | Vulnerable (Tier 1) | `src/db/user-repo.js` | `CWE-89` | Raw string concatenation in SQL user lookup | **BLOCK** |
| **BENCH-REAL-002** | Vulnerable (Tier 1) | `src/auth/jwt-service.js` | `CWE-798` | Hardcoded JWT signing secret and skipped verification | **BLOCK** |
| **BENCH-REAL-003** | Vulnerable (Tier 1) | `src/storage/file-fetcher.js` | `CWE-22` | Path traversal via unsanitized filename input | **BLOCK** |
| **BENCH-REAL-004** | Vulnerable (Tier 1) | `src/views/profile-render.js` | `CWE-79` | Unescaped innerHTML insertion in client-side renderer | **BLOCK** |
| **BENCH-REAL-005** | Vulnerable (Tier 1) | `src/api/invoice-handler.js` | `CWE-639` | Insecure Direct Object Reference (missing tenant auth) | **BLOCK** |
| **BENCH-REAL-006** | Vulnerable (Tier 1) | `src/webhook/dispatcher.js` | `CWE-918` | Server-Side Request Forgery via unfiltered webhook URL | **BLOCK** |
| **BENCH-REAL-007** | Vulnerable (Tier 1) | `src/tools/pdf-generator.js` | `CWE-78` | OS Command injection via `child_process.exec` | **BLOCK** |
| **BENCH-REAL-008** | Vulnerable (Tier 1) | `src/cache/session-store.js` | `CWE-502` | Deserialization of untrusted YAML / binary payload | **BLOCK** |
| **BENCH-REAL-009** | Vulnerable (Tier 1) | `src/auth/login-limiter.js` | `CWE-307` | Authentication bypass via disabled brute-force limiter | **BLOCK** |
| **BENCH-REAL-010** | Vulnerable (Tier 1) | `src/utils/deep-assign.js` | `CWE-1321` | Prototype pollution via `__proto__` property copy | **BLOCK** |
| **BENCH-REAL-011** | Vulnerable (Tier 1) | `src/finance/transfer.js` | `CWE-362` | Race condition (TOCTOU) in account balance debit | **BLOCK** |
| **BENCH-REAL-012** | Vulnerable (Tier 1) | `src/crypto/hmac-verify.js` | `CWE-208` | Non-constant-time secret comparison (timing attack) | **BLOCK** |
| **BENCH-REAL-013** | Clean (Tier 2) | `src/math/vector-calc.js` | None | Algorithmic optimization of vector dot product | **APPROVE** |
| **BENCH-REAL-014** | Clean (Tier 2) | `src/ui/table-layout.js` | None | Pure CSS class names and flexbox formatting updates | **APPROVE** |
| **BENCH-REAL-015** | Clean (Tier 3) | `docs/architecture.md` | None | Technical documentation typo fixes and diagram updates | **APPROVE** |

---

## 4. Evaluation Metrics & Comparison Matrix

Triad-Flow evaluates the benchmark corpus across three operational configurations:

### 4.1 Evaluation Setup Dimensions

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Evaluation Matrix                               │
├──────────────────────┬──────────────────────┬──────────────────────────┤
│ Configuration        │ Macro Provider       │ Micro Provider           │
├──────────────────────┼──────────────────────┼──────────────────────────┤
│ 1. Single (Macro)    │ Google agy           │ [None]                   │
│ 2. Dual (Hetero)     │ Google agy           │ Anthropic claude         │
│ 3. Risk-Adaptive     │ Google agy           │ Anthropic claude (Tier 1)│
└──────────────────────┴──────────────────────┴──────────────────────────┘
```

### 4.2 Core Metrics

1. **Recall Rate ($R$)**:
   $$\text{Recall} = \frac{\text{Caught Golden CWEs}}{\text{Total Golden CWEs}}$$
2. **Precision ($P$)**:
   $$\text{Precision} = \frac{\text{True Positive Findings}}{\text{Total Reported Findings}}$$
3. **False Block Rate ($FBR$)**:
   $$\text{FBR} = \frac{\text{Clean Cases with Block Decision}}{\text{Total Clean Cases}}$$
4. **Token Cost Ratio ($CR$)**:
   $$\text{Cost Ratio} = \frac{\text{Total Evaluated Tokens}}{\text{Single Sentry Baseline Tokens}}$$
5. **Latency Profile**:
   - Median (P50) wall-clock duration in milliseconds.
   - P95 wall-clock duration.

---

## 5. Standard Operating Procedure (SOP) for Corpus Ingestion

```
[Candidate PR / Diff]
         │
         ▼
[1. Patch Isolation] ─── Extract minimal standalone Git patch (zero extraneous files)
         │
         ▼
[2. Double-Blind Review] ── Assign 2 independent human reviewers to tag Golden CWE & Line
         │
         ▼
[3. Immutability Freeze] ── Compute SHA256 digest & commit into frozen repository
         │
         ▼
[4. Baseline Test Run] ── Execute verifyHeldOutBaseline with clean negative control
         │
         ▼
[5. Corpus Version Tag] ── Bump dataset tag (e.g. TF-RBC-v0.1.0)
```

---

## 6. Repository Immutability Commitment

During all benchmark executions, Triad-Flow operates strictly under the **Read-Only Adapter Invariant**:
- Repositories under evaluation are NEVER written to.
- `git status --porcelain` is asserted to be empty before and after every execution.
- No temporary files, tokens, or artifacts are created in the target workspace.
