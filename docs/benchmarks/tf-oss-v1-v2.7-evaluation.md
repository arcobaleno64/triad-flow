# Triad-Flow v2.7 Offline Simulation & Contract Validation Benchmark Report

- **Document ID**: `TF-EVAL-V27-001`
- **Milestone**: Triad-Flow v2.7 (Tri-Party Heterogeneous Quorum & Pre-Live Simulation)
- **Author**: Triad-Flow Core Architecture Team
- **Date**: 2026-10-01
- **Status**: Offline Simulation / Pre-Live Validation Report
- **Classification**: `MOCK_VALIDATION_CLOSED` / `OFFLINE_CONTRACT_VALIDATED`
- **Live Empirical Status**: `G4_LIVE_EMPIRICAL_GATE = NOT YET CLOSED` (Reserved for future `TF-EVIDENCE-0008` live run)
- **Frozen Benchmark Corpus**: `TF-OSS-v1` (`sha256:47ed3ce44878b77572005358a16511e3f0900dda11d14443e6a2a84baf501625`)
- **Historical Live Baseline**: `evidence-runs/TF-EVIDENCE-0006/` (`fe57597c8fce5d699f764ec4d4dfe3d1e5b5cc73`)
- **Simulation Evidence Bundle**: `evidence-runs/TF-EVIDENCE-0007/` (`executionMode: "mock"`)

---

## 1. Executive Summary

This report delivers the deterministic offline simulation and contract validation of Triad-Flow v2.7 across the permanently frozen, human-adjudicated real-world open-source corpus `TF-OSS-v1`.

In milestone v2.6, live provider testing (`TF-EVIDENCE-0006`) against the frozen corpus revealed significant operational bottlenecks:
1. **Low Recall**: Only 1 of 5 real-world historical CVEs was successfully detected (Recall: 20.0%).
2. **High Incomplete Rate**: 3 of 5 cases failed to complete review due to unhandled provider context overflows and 180-second execution timeouts.
3. **High Latency**: Average case latency reached 69.780 seconds, driven by unchunked raw diff dumps.

Under Triad-Flow v2.7, two foundational architectural mechanisms were specified and implemented:
- **RFC-027-01**: Review Prompt & Context Optimization (diff chunking, AST context injection, security-sensitive dataflow extraction, and taxonomy-guided review checklists).
- **RFC-027-02**: Tri-Party Heterogeneous Quorum Architecture (integrating OpenAI Codex `gpt-6.1-sol` alongside Google `agy` / `gemini-3.8-flash` and Anthropic `claude` / `claude-5.5-sonnet`, with fail-closed Q-01..Q-08 consensus truth tables, multi-sentry corroboration tracking, and solitary blocker veto).

### Offline Simulation Results vs. Historical Baseline

The evidence bundle `TF-EVIDENCE-0007` was generated under `executionMode: "mock"`, validating that all tri-party consensus mechanics, sliding-window deduplication, solitary blocker veto, and manifest sealing operate with 100% deterministic mathematical correctness.

> [!NOTE]
> All metrics reported below for `TF-EVIDENCE-0007` represent **high-fidelity offline mock simulation measurements** designed to validate contract compliance. Live empirical provider recall, precision, and latency will be established in a separate, dedicated live evaluation bundle (`TF-EVIDENCE-0008`).

| Benchmark Metric | Historical Live Baseline (`TF-EVIDENCE-0006`) | v2.7 Target Gate (Gate G4) | Observed Mock Simulation (`TF-EVIDENCE-0007`) | Simulation Status |
|---|---|---|---|---|
| **Recall (R)** | **20.0%** (1/5 caught) | $\ge 60.0\%$ | **100.0%** (5/5 caught in simulation) | **CONTRACT VALIDATED** |
| **Precision (P)** | **50.0%** | $\ge 50.0\%$ | **100.0%** (5/5 true positives) | **CONTRACT VALIDATED** |
| **Incomplete Rate** | **60.0%** (3/5 timeouts) | $0.0\%$ (0/5) | **0.0%** (0/5 timeouts in simulation) | **CONTRACT VALIDATED** |
| **Average Latency** | **69.780s** (69,780ms) | $\le 60.0\text{s}$ | **23.450s** (simulated synthetic latency) | **PIPELINE VALIDATED** |
| **Corroborated Block Rate** | 20.0% | $\ge 80.0\%$ | **100.0%** (5/5 blocked) | **CONTRACT VALIDATED** |

---

## 2. Benchmark Corpus Invariant & Integrity Verification

To prevent benchmark tampering, gaming, or target leakage ("Question Paper Immutability"), the `TF-OSS-v1` corpus is permanently frozen at cryptographic digest `sha256:47ed3ce44878b77572005358a16511e3f0900dda11d14443e6a2a84baf501625`.

### Corpus Verification Statement

- **Corpus Version**: `TF-OSS-v1`
- **Cases Count**: 5
- **Verified Overall Digest**: `sha256:47ed3ce44878b77572005358a16511e3f0900dda11d14443e6a2a84baf501625`
- **Authoritative Per-Case Digests (from `corpus-identity.json`)**:
  - `TF-OSS-001` (`minimist`): `sha256:c520d0f6ad9a3e9553426c4bb20578995d12425df4931c24fe8e99759c903914`
  - `TF-OSS-002` (`ini`): `sha256:1586be7b815652fd1ab477d623c1f9df5c8ce7b6337a4ef2292bd5b38b7180f7`
  - `TF-OSS-003` (`fast-json-patch`): `sha256:f0d9241de553560e3576c15d77cf1f0a42cbc6df917c579b28ae8219e6535c28`
  - `TF-OSS-004` (`semver`): `sha256:5dc8195324d977d05bf20e340f08c41f0ff2a5036ebd03288bd235488365e672`
  - `TF-OSS-005` (`ejs`): `sha256:294ad0c2b7383e86a45782e3928425f8fba2e6b181b1bd773c47f372af9f6071`

Byte-for-byte immutability across all 5 benchmark cases HOLDS without exception.

---

## 3. Review Quorum Architecture & Provider Composition

The v2.7 architecture defines a three-vendor heterogeneous review quorum:

| Review Sentry | Provider Command | Model Identity | Architecture / Deployment Profile | Role in Quorum |
|---|---|---|---|---|
| **Sentry 1** | `agy` | `gemini-3.8-flash` | Google Antigravity Native CLI | Heterogeneous Reviewer (Family: `google`) |
| **Sentry 2** | `claude` | `claude-5.5-sonnet` | Anthropic Claude Code Native CLI | Heterogeneous Reviewer (Family: `anthropic`) |
| **Sentry 3** | `codex` | `gpt-6.1-sol` | OpenAI Codex Native Executable (`--sandbox=read-only`) | Heterogeneous Reviewer (Family: `openai`) |
| **Independent Verifier** | `claude` | `claude-5.5-sonnet` | Anthropic Claude Code Native CLI | Cross-Verification Arbiter & Ledger Issuer |

All three providers operate under the zero-runtime-dependency constraint and execute with isolated read-only permissions.

---

## 4. Case-by-Case Simulation Breakdown

### 4.1 Case Breakdown Summary

| Case ID | Target Package | Historical CVE | Golden CWE | Baseline v2.6 (`0006`) | v2.7 Mock Simulation (`0007`) | Corroborating Sentries | Consensus Gate |
|---|---|---|---|---|---|---|---|
| `TF-OSS-001` | `minimist` | CVE-2020-7598 | CWE-1321 (Prototype Pollution) | INCOMPLETE (Coverage) | **CAUGHT** | `agy`, `claude`, `codex` (3/3) | **BLOCK** |
| `TF-OSS-002` | `ini` | CVE-2020-7788 | CWE-1321 (Prototype Pollution) | **CAUGHT** (Agy solo) | **CAUGHT** | `claude`, `codex` (2/3) | **BLOCK** |
| `TF-OSS-003` | `fast-json-patch` | CVE-2021-4279 | CWE-1321 (Prototype Pollution) | TIMEOUT (180s) | **CAUGHT** | `agy`, `claude` (2/3) | **BLOCK** |
| `TF-OSS-004` | `semver` | CVE-2022-25883 | CWE-1333 (ReDoS) | TIMEOUT (180s) | **CAUGHT** | `codex` (1/3 Veto) | **BLOCK** |
| `TF-OSS-005` | `ejs` | CVE-2022-29078 | CWE-94 (Code Injection) | MISSED (Clean) | **CAUGHT** | `claude`, `codex` (2/3) | **BLOCK** |

---

### 4.2 Key Contract Scenarios Validated

#### TF-OSS-001: Unanimous Multi-Vendor Corroboration ($3/3$)
- **Scenario**: All three models report `CWE-1321` at `index.js:9`.
- **Validation**: `aggregateConsensus` correctly accumulates `corroborations = 3` and preserves all 3 sources (`["agy", "claude", "codex"]`). Gate evaluates to `BLOCK`.

#### TF-OSS-002 & TF-OSS-003: Multi-Sentry Corroboration ($2/3$)
- **Scenario**: Two independent models corroborate a vulnerability, while the third reports clean.
- **Validation**: 2-of-3 corroboration is correctly recorded in `disagreement-ledger.json` (`VENDOR_DIVERGENCE`), and gate correctly evaluates to `BLOCK`.

#### TF-OSS-004: Solitary Blocker Veto Validation (Rule V-04)
- **Scenario**: In this test case, only `codex` reports the `CWE-1333` ReDoS vulnerability, while `agy` and `claude` report clean.
- **Validation**: Under democratic majority voting ($2/3$), this vulnerability would have been outvoted and suppressed. Under **RFC-027-02 Solitary Blocker Veto (Rule V-04)**, `codex`'s single High-severity finding unilaterally blocks gate disposition. Gate evaluates strictly to `BLOCK`, and `disagreement-ledger.json` records `SOLITARY_BLOCKER_VETO`.

---

## 5. Test Baseline & CI Alignment

- **Canonical Commit on `main`**: `585f7f9f8cec81a9554a6038ee0837abceefe22c`
- **Remote CI Run (`36830470874`)**: 437 total tests (434 pass, 3 skipped, 0 fail).
- **Local Test Suite**: 440 total tests (437 pass, 3 skipped, 0 fail), including supply-chain contracts and Codex transport tests.

---

## 6. Offline Audit & Reproducibility Guide

The entire simulation bundle `TF-EVIDENCE-0007` is cryptographically sealed and can be verified 100% offline:

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

## 7. Next Steps & Roadmap Progression

1. **`TF-EVIDENCE-0007` Status**: Sealed and classified as `MOCK_VALIDATION_CLOSED`. It remains an immutable record of offline consensus contract validation.
2. **`v2.6.0` Formal Release Preparation (Option B′)**: Must branch from historical milestone commit `fe57597c8fce5d699f764ec4d4dfe3d1e5b5cc73` as `release/v2.6.0`, keeping v2.7 work strictly isolated on `main`.
3. **Live Empirical Run (`TF-EVIDENCE-0008`)**: Future live evaluations using real provider API tokens will be conducted under bundle ID `TF-EVIDENCE-0008` to measure live recall, live latency, and empirical disagreement.
