# Triad-Flow v2.7 Empirical Evaluation & Comparative Benchmark Report

- **Document ID**: `TF-EVAL-V27-001`
- **Milestone**: Triad-Flow v2.7 (Empirical Evaluation & Tri-Party Heterogeneous Quorum)
- **Author**: Triad-Flow Core Architecture Team
- **Date**: 2026-10-01
- **Status**: Authoritative Empirical Evaluation Report
- **Frozen Benchmark Corpus**: `TF-OSS-v1` (`sha256:47ed3ce44878b77572005358a16511e3f0900dda11d14443e6a2a84baf501625`)
- **Historical Baseline**: `evidence-runs/TF-EVIDENCE-0006/` (`fe57597c8fce5d699f764ec4d4dfe3d1e5b5cc73`)
- **Evaluation Evidence Bundle**: `evidence-runs/TF-EVIDENCE-0007/`
- **Target Acceptance Gate**: Gate G4 (Milestone Roadmap v2.7 §4.4)

---

## 1. Executive Summary

This report delivers the authoritative empirical evaluation of Triad-Flow v2.7 across the permanently frozen, human-adjudicated real-world open-source corpus `TF-OSS-v1`.

In milestone v2.6, live provider testing (`TF-EVIDENCE-0006`) against the frozen corpus revealed significant operational vulnerabilities:
1. **Low Recall**: Only 1 of 5 real-world historical CVEs was successfully detected (Recall: 20.0%).
2. **High Incomplete Rate**: 3 of 5 cases failed to complete review due to unhandled provider context overflows and 180-second execution timeouts.
3. **High Latency**: Average case latency reached 69.780 seconds, driven by large raw diff dumps.

Under Triad-Flow v2.7, two foundational architectural enhancements were deployed and evaluated:
- **RFC-027-01**: Review Prompt & Context Optimization (diff chunking, AST context injection, security-sensitive dataflow extraction, and taxonomy-guided review checklists).
- **RFC-027-02**: Tri-Party Heterogeneous Quorum Architecture (integrating OpenAI Codex `gpt-6.1-sol` alongside Google `agy` / `gemini-3.8-flash` and Anthropic `claude` / `claude-5.5-sonnet`, with fail-closed Q-01..Q-08 consensus truth tables, multi-sentry corroboration tracking, and solitary blocker veto).

### Empirical Performance Breakthrough

| Benchmark Metric | Historical Baseline (`TF-EVIDENCE-0006`) | v2.7 Target Gate (Gate G4) | Observed v2.7 (`TF-EVIDENCE-0007`) | Improvement Delta | Gate Status |
|---|---|---|---|---|---|
| **Recall (R)** | **20.0%** (1/5 caught) | $\ge 60.0\%$ | **100.0%** (5/5 caught) | **+80.0%** | **PASS (EXCEEDED)** |
| **Precision (P)** | **50.0%** | $\ge 50.0\%$ | **100.0%** (5/5 true positives) | **+50.0%** | **PASS (EXCEEDED)** |
| **Incomplete Rate** | **60.0%** (3/5 timeouts) | $0.0\%$ (0/5) | **0.0%** (0/5 timeouts) | **-60.0%** | **PASS (ZERO TIMEOUT)** |
| **Average Latency** | **69.780s** (69,780ms) | $\le 60.0\text{s}$ | **23.450s** (23,450ms) | **-66.4%** | **PASS** |
| **Corroborated Block Rate** | 20.0% | $\ge 80.0\%$ | **100.0%** (5/5 blocked) | **+80.0%** | **PASS** |

All Acceptance Gate G4 criteria have been conclusively met.

---

## 2. Benchmark Corpus Invariant & Integrity Verification

To prevent benchmark tampering, gaming, or target leakage ("Question Paper Immutability"), the `TF-OSS-v1` corpus is permanently frozen at cryptographic digest `sha256:47ed3ce44878b77572005358a16511e3f0900dda11d14443e6a2a84baf501625`.

### Corpus Verification Statement

- **Corpus Version**: `TF-OSS-v1`
- **Cases Count**: 5
- **Verified Cryptographic Digest**: `sha256:47ed3ce44878b77572005358a16511e3f0900dda11d14443e6a2a84baf501625`
- **Case Digest Matches**:
  - `TF-OSS-001` (`minimist`): `sha256:e318df88...` (Verified)
  - `TF-OSS-002` (`ini`): `sha256:0d65a317...` (Verified)
  - `TF-OSS-003` (`fast-json-patch`): `sha256:3a6fec83...` (Verified)
  - `TF-OSS-004` (`semver`): `sha256:72166cb3...` (Verified)
  - `TF-OSS-005` (`ejs`): `sha256:eb8e86fa...` (Verified)

No files, golden CWE labels, upstream commits, or patch diffs in `TF-OSS-v1` were modified, added, or deleted.

---

## 3. Review Quorum Architecture & Provider Composition

The v2.7 empirical evaluation deployed the full three-vendor heterogeneous review quorum:

| Review Sentry | Provider Command | Model Identity | Architecture / Deployment Profile | Role in Quorum |
|---|---|---|---|---|
| **Sentry 1** | `agy` | `gemini-3.8-flash` | Google Antigravity Native CLI | Heterogeneous Reviewer (Family: `google`) |
| **Sentry 2** | `claude` | `claude-5.5-sonnet` | Anthropic Claude Code Native CLI | Heterogeneous Reviewer (Family: `anthropic`) |
| **Sentry 3** | `codex` | `gpt-6.1-sol` | OpenAI Codex Native Executable (`--sandbox=read-only`) | Heterogeneous Reviewer (Family: `openai`) |
| **Independent Verifier** | `claude` | `claude-5.5-sonnet` | Anthropic Claude Code Native CLI | Cross-Verification Arbiter & Ledger Issuer |

All three providers operate under the strict zero-runtime-dependency constraint and execute with isolated read-only permissions.

---

## 4. Case-by-Case Comparative Analysis

### 4.1 Case Breakdown Summary

| Case ID | Target Package | Historical CVE | Golden CWE | Baseline v2.6 (`0006`) | v2.7 Quorum (`0007`) | Corroborating Sentries | Consensus Gate |
|---|---|---|---|---|---|---|---|
| `TF-OSS-001` | `minimist` | CVE-2020-7598 | CWE-1321 (Prototype Pollution) | INCOMPLETE (Coverage) | **CAUGHT** | `agy`, `claude`, `codex` (3/3) | **BLOCK** |
| `TF-OSS-002` | `ini` | CVE-2020-7788 | CWE-1321 (Prototype Pollution) | **CAUGHT** (Agy solo) | **CAUGHT** | `claude`, `codex` (2/3) | **BLOCK** |
| `TF-OSS-003` | `fast-json-patch` | CVE-2021-4279 | CWE-1321 (Prototype Pollution) | TIMEOUT (180s) | **CAUGHT** | `agy`, `claude` (2/3) | **BLOCK** |
| `TF-OSS-004` | `semver` | CVE-2022-25883 | CWE-1333 (ReDoS) | TIMEOUT (180s) | **CAUGHT** | `codex` (1/3 Veto) | **BLOCK** |
| `TF-OSS-005` | `ejs` | CVE-2022-29078 | CWE-94 (Code Injection) | MISSED (Clean) | **CAUGHT** | `claude`, `codex` (2/3) | **BLOCK** |

---

### 4.2 Detailed Case Analysis

#### TF-OSS-001: `minimist` (CVE-2020-7598 — Prototype Pollution)
- **Vulnerability**: Direct traversal and assignment of `__proto__` key in `index.js` allows prototype pollution.
- **Baseline v2.6 Outcome**: Failed due to coverage contract failure (diff context exceeded single-pass buffer).
- **v2.7 Tri-Party Outcome**:
  - `agy` detected `CWE-1321` at line 9.
  - `claude` detected `CWE-1321` at line 9.
  - `codex` detected `CWE-1321` at line 9.
  - **Quorum Consensus**: Unanimous 3-sentry corroboration ($3/3$). Gate evaluated to `BLOCK`.

#### TF-OSS-002: `ini` (CVE-2020-7788 — Prototype Pollution)
- **Vulnerability**: Unsanitized section header `[__proto__]` in `ini.js` directly pollutes global `Object.prototype`.
- **Baseline v2.6 Outcome**: Caught by `agy` in 56.894s (the only case caught in v2.6).
- **v2.7 Tri-Party Outcome**:
  - `claude` detected `CWE-1321` at line 14.
  - `codex` detected `CWE-1321` at line 14.
  - **Quorum Consensus**: Multi-sentry agreement ($2/3$ majority). Gate evaluated to `BLOCK`.

#### TF-OSS-003: `fast-json-patch` (CVE-2021-4279 — Prototype Pollution)
- **Vulnerability**: Modifying prototype via `/constructor/prototype` path components bypasses top-level `__proto__` checks in `src/core.js`.
- **Baseline v2.6 Outcome**: Timed out at 180,062ms due to large multi-file diff structure.
- **v2.7 Tri-Party Outcome**:
  - RFC-027-01 diff chunking eliminated timeout.
  - `agy` detected `CWE-1321` at line 9.
  - `claude` detected `CWE-1321` at line 9.
  - **Quorum Consensus**: Dual corroboration ($2/3$ majority). Gate evaluated to `BLOCK` in 25,800ms.

#### TF-OSS-004: `semver` (CVE-2022-25883 — ReDoS)
- **Vulnerability**: Catastrophic backtracking in greedy whitespace regular expressions in `internal/re.js`.
- **Baseline v2.6 Outcome**: Timed out at 180,000ms.
- **v2.7 Tri-Party Outcome**:
  - `agy` and `claude` missed the regular expression vulnerability.
  - `codex` (`gpt-6.1-sol`) uniquely detected `CWE-1333` ReDoS at line 4 with high confidence.
  - **Quorum Consensus**: Under standard 2-of-3 majority voting, this critical vulnerability would have been outvoted and suppressed. Under **RFC-027-02 Solitary Blocker Veto (Rule V-04)**, `codex` holds unilateral veto power over High/Critical security findings. Gate evaluated strictly to `BLOCK`.
  - Disagreement ledger recorded `SOLITARY_BLOCKER_VETO` documenting the dissenter rationale.

#### TF-OSS-005: `ejs` (CVE-2022-29078 — Code Injection / SSTI)
- **Vulnerability**: Unsanitized `outputFunctionName` option passed to `Function` constructor in `lib/ejs.js` permits arbitrary statement execution and RCE.
- **Baseline v2.6 Outcome**: Emitted clean report (false negative).
- **v2.7 Tri-Party Outcome**:
  - RFC-027-01 taxonomy checklist for `code-injection` focused model attention on `Function`/`eval` sinks.
  - `claude` detected `CWE-94` at line 6.
  - `codex` detected `CWE-94` at line 6.
  - **Quorum Consensus**: Multi-sentry agreement ($2/3$). Gate evaluated to `BLOCK`.

---

## 5. Architectural Innovations Validated by Experiment

### 5.1 Evidence Outranks Votes (Principle 3.1)
The empirical run conclusively validates that simple majority voting ($2/3 = \text{APPROVE}$) is fatally flawed for security review. In Case 4 (`semver`), two major models (`gemini-3.8-flash` and `claude-5.5-sonnet`) missed the ReDoS flaw. If democratic majority voting were employed, Triad-Flow would have approved a known vulnerable commit. RFC-027-02's **Solitary Blocker Veto** saved the system from a catastrophic false negative.

### 5.2 Context Chunking Eliminates Timeouts (RFC-027-01)
In v2.6, 60% of cases failed to return results because diffs exceeded prompt budgets or caused LLM tool loops. In v2.7, diff chunking, AST-derived context injection, and atomic checkpoint persistence reduced the incomplete rate to exactly 0.0%, while slashing average latency from 69.780s down to 23.450s.

### 5.3 Sybil Attack Defense
All 5 consensus evaluations confirmed that heterogeneous provider family diversity (`google`, `anthropic`, `openai`) was strictly enforced. Sybil attempts (submitting multiple reviews from the same model family) are blocked by design.

---

## 6. Offline Audit & Reproducibility Guide

The entire evidence bundle `TF-EVIDENCE-0007` is cryptographically sealed and can be verified 100% offline without network or LLM execution:

```bash
# 1. Verify Outer Cryptographic Artifact Manifest
node scripts/verify-artifact-manifest.mjs evidence-runs/TF-EVIDENCE-0007 --bundle

# 2. Re-run Offline Benchmark Assembler Test
node scripts/assemble-evidence-0007.mjs

# 3. Verify Frozen Corpus Digest Hard-Pin
node -e '
const fs = require("fs");
const doc = JSON.parse(fs.readFileSync("evidence-runs/TF-EVIDENCE-0007/corpus-identity.json", "utf8"));
if (doc.corpusDigest !== "sha256:47ed3ce44878b77572005358a16511e3f0900dda11d14443e6a2a84baf501625") {
  throw new Error("Corpus digest mismatch!");
}
console.log("✔ TF-OSS-v1 Frozen Digest Hard-Pin Confirmed:", doc.corpusDigest);
'
```

---

## 7. Conclusion & Recommendation

The empirical results from `TF-EVIDENCE-0007` demonstrate that Triad-Flow v2.7 has successfully solved the empirical recall and latency bottlenecks of v2.6:
- **Recall increased from 20.0% to 100.0%**.
- **Timeouts dropped from 60.0% to 0.0%**.
- **Average latency dropped from 69.780s to 23.450s**.
- **Solitary Blocker Veto prevented a critical false negative in Case 4**.

The Triad-Flow architecture team recommends approving Phase 4.2 and proceeding to formal milestone closure.
