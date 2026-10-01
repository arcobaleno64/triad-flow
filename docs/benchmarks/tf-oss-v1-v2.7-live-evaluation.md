# Triad-Flow v2.7 Live Empirical Evaluation Benchmark Report

- **Document ID**: `TF-EVAL-V27-002`
- **Milestone**: Triad-Flow v2.7 (Tri-Party Heterogeneous Quorum Live Evaluation)
- **Author**: Triad-Flow Core Architecture Team
- **Date**: 2026-10-01
- **Status**: Authoritative Live Empirical Benchmark Report
- **Classification**: `LIVE_EMPIRICAL_EVALUATION_RECORDED` / `G4_LIVE_EMPIRICAL_GATE = NOT YET CLOSED`
- **Frozen Benchmark Corpus**: `TF-OSS-v1` (`sha256:47ed3ce44878b77572005358a16511e3f0900dda11d14443e6a2a84baf501625`)
- **Historical Live Baseline**: `evidence-runs/TF-EVIDENCE-0006/` (`fe57597c8fce5d699f764ec4d4dfe3d1e5b5cc73`)
- **Simulation Validation Baseline**: `evidence-runs/TF-EVIDENCE-0007/` (`executionMode: "mock"`)
- **Authoritative Live Bundle**: `evidence-runs/TF-EVIDENCE-0008/` (`executionMode: "live"`)

---

## 1. Executive Summary

This report establishes the authoritative, live empirical benchmark evaluation of Triad-Flow v2.7 against the permanently frozen, human-adjudicated real-world open-source corpus `TF-OSS-v1`.

In milestone v2.6, the live baseline run (`TF-EVIDENCE-0006`) against the frozen corpus revealed severe real-world operational bottlenecks:
1. **Low Recall**: Only 1 of 5 real-world historical CVEs was caught (Recall: 20.0%).
2. **High Incomplete Rate**: 3 of 5 cases timed out or suffered coverage omissions (Incomplete Rate: 60.0%).
3. **High Latency**: Average case latency reached 69.780 seconds.

Under Triad-Flow v2.7, two core architectural pillars were implemented and deployed:
- **RFC-027-01**: Review Prompt & Context Optimization (diff chunking, AST context injection, security-sensitive dataflow extraction, and taxonomy-guided review checklists).
- **RFC-027-02**: Tri-Party Heterogeneous Quorum Architecture (integrating OpenAI Codex `gpt-6.1-sol` alongside Google `agy` / `gemini-3.8-flash` and Anthropic `claude` / `claude-5.5-sonnet`, with fail-closed Q-01..Q-08 consensus truth tables, multi-sentry corroboration, and solitary blocker veto).

### Live Empirical Results vs. Baselines

The live evidence bundle `TF-EVIDENCE-0008` was generated via real CLI subprocess execution across all 3 vendor CLIs installed locally (`agy`, `claude`, `codex`) and independently verified by Claude 5.5 Sonnet:

| Benchmark Metric | Historical Live Baseline (`TF-EVIDENCE-0006`) | Canonical Roadmap Target (Gate G4) | Observed Live Empirical (`TF-EVIDENCE-0008`) | Gate Status |
|---|---|---|---|---|
| **Recall (R)** | **20.0%** (1/5 caught) | $> 20.0\%$ | **100.0%** (5/5 caught) | **PASS** |
| **Precision (P)** | **50.0%** | $\ge 50.0\%$ | **83.3%** (5/6 true positives) | **PASS** |
| **Incomplete Rate** | **60.0%** (3/5 timeouts) | **0.0%** (0/5 incomplete) | **40.0%** (2/5 incomplete) | **FAIL (Target Missed)** |
| **Average Latency** | **69.780s** (69,780ms) | $\le 60.0\text{s}$ | **63.856s** (p50: 43.431s) | **TARGET MISSED** |
| **Gate Correctness (`gatePolicyPass`)** | 20.0% (1/5 blocked) | **100.0%** (5/5 blocked) | **60.0%** (3/5 blocked) | **FAIL (TF-OSS-003/004 Approved)** |

> [!WARNING]
> While `TF-EVIDENCE-0008` achieved **100.0% Recall** (5/5 vulnerabilities detected), it **does not close Gate G4**:
> 1. **Incomplete Runs (40.0% vs. 0% target)**: `agy` returned malformed output in `TF-OSS-001` and `TF-OSS-003`.
> 2. **Gate Policy Divergence**: `TF-OSS-003` and `TF-OSS-004` received `actualGateDecision: "approve"` despite detecting vulnerabilities (`expectedGateDecision: "block"`).
> 3. **Latency Target Missed**: Average latency (63.856s) exceeded the 60.0s target.
>
> Gate G4 remains **NOT YET CLOSED** pending Phase 4.3 closure correction and a subsequent clean empirical run (`TF-EVIDENCE-0009`).

---

## 2. Benchmark Corpus Invariant & Integrity Verification

The `TF-OSS-v1` corpus is permanently frozen to guarantee question paper immutability. No golden label, test case, diff, or file fixture was modified.

- **Corpus Version**: `TF-OSS-v1`
- **Cases Count**: 5
- **Verified Overall Digest**: `sha256:47ed3ce44878b77572005358a16511e3f0900dda11d14443e6a2a84baf501625`
- **Authoritative Per-Case Digests (from `corpus-identity.json`)**:
  - `TF-OSS-001` (`minimist`): `sha256:c520d0f6ad9a3e9553426c4bb20578995d12425df4931c24fe8e99759c903914`
  - `TF-OSS-002` (`ini`): `sha256:1586be7b815652fd1ab477d623c1f9df5c8ce7b6337a4ef2292bd5b38b7180f7`
  - `TF-OSS-003` (`fast-json-patch`): `sha256:f0d9241de553560e3576c15d77cf1f0a42cbc6df917c579b28ae8219e6535c28`
  - `TF-OSS-004` (`semver`): `sha256:5dc8195324d977d05bf20e340f08c41f0ff2a5036ebd03288bd235488365e672`
  - `TF-OSS-005` (`ejs`): `sha256:294ad0c2b7383e86a45782e3928425f8fba2e6b181b1bd773c47f372af9f6071`

Byte-for-byte immutability holds across all 5 benchmark cases without exception.

---

## 3. Review Quorum Architecture & Provider Composition

The live evaluation executed with three heterogeneous frontier providers:

| Review Sentry | Provider Command | Model Identity | Architecture / Deployment Profile | Role in Quorum |
|---|---|---|---|---|
| **Sentry 1** | `agy` (v1.2.14) | `gemini-3.8-flash` | Google Antigravity Native CLI (`--mode=plan --disable-slash-commands --print`) | Heterogeneous Reviewer (Family: `google`) |
| **Sentry 2** | `claude` (v2.1.286) | `claude-5.5-sonnet` | Anthropic Claude Code Native CLI (`-p --tools=`) | Heterogeneous Reviewer (Family: `anthropic`) |
| **Sentry 3** | `codex` (v0.159.2) | `gpt-6.1-sol` | OpenAI Codex Native Executable (`exec --sandbox=read-only --ephemeral --color never -o <file>`) | Heterogeneous Reviewer (Family: `openai`) |
| **Independent Verifier** | `claude` | `claude-5.5-sonnet` | Anthropic Claude Code Native CLI (isolated verification session) | Cross-Verification Arbiter & Ledger Issuer |

---

## 4. Case-by-Case Empirical Breakdown

| Case ID | Target Package | Historical CVE | Golden CWE | Baseline v2.6 (`0006`) | Live Empirical v2.7 (`0008`) | Sentry Corroborations | Gate Decision |
|---|---|---|---|---|---|---|---|
| `TF-OSS-001` | `minimist` | CVE-2020-7598 | CWE-1321 | INCOMPLETE | **CAUGHT** | `claude`, `codex` (2/3) | **BLOCK** |
| `TF-OSS-002` | `ini` | CVE-2020-7788 | CWE-1321 | **CAUGHT** (`agy` solo) | **CAUGHT** | `agy`, `claude`, `codex` (3/3) | **BLOCK** |
| `TF-OSS-003` | `fast-json-patch` | CVE-2021-4279 | CWE-1321 | TIMEOUT | **CAUGHT** | `claude`, `codex` (2/3) | `APPROVE` (Advisory) |
| `TF-OSS-004` | `semver` | CVE-2022-25883 | CWE-1333 | TIMEOUT | **CAUGHT** | `claude`, `codex` (2/3) | `APPROVE` (Advisory) |
| `TF-OSS-005` | `ejs` | CVE-2022-29078 | CWE-94 | MISSED | **CAUGHT** | `agy` (1/3 Solitary Blocker Veto) | **BLOCK** |

---

## 5. Architectural Invariant Validations in Live Execution

### 5.1 Solitary Blocker Veto (Rule V-04) in Real-World Action (`TF-OSS-005`)
In `TF-OSS-005` (`ejs` / CVE-2022-29078):
- Anthropic `claude` and OpenAI `codex` both evaluated the diff as clean and returned 0 findings.
- Google `agy` uniquely discovered the Critical code injection flaw:
  > *"Code injection via outputFunctionName in template compilation"* (CWE-94, Severity: Critical, `lib/ejs.js:6-10`).
- Under standard democratic majority voting ($2/3$), this true critical vulnerability would have been suppressed.
- Under **RFC-027-02 Solitary Blocker Veto**, `agy`'s finding unilaterally forced the gate to **BLOCK**.
- Independent verification by Claude 5.5 Sonnet confirmed the finding and recorded the divergence in `disagreement-ledger.json`.

### 5.2 Multi-Vendor Corroboration ($2/3$ and $3/3$)
- **$3/3$ Unanimous Corroboration**: In `TF-OSS-002` (`ini`), all three vendors independently identified prototype pollution on section decoding (`ini.js:13-16`), converging with $3/3$ corroboration.
- **$2/3$ Independent Corroboration**: In `TF-OSS-001`, `TF-OSS-003`, and `TF-OSS-004`, Claude and Codex corroborated findings with high spatial and semantic alignment.

### 5.3 Resilient Degradation & Incomplete Handling
In `TF-OSS-001` and `TF-OSS-003`, `agy` experienced malformed output during live JSON extraction. In accordance with RFC-027-02 Section 12 fail-closed semantics, the quorum degraded gracefully to the remaining 2 independent heterogeneous providers (`claude` + `codex`) without crashing or fabricating synthetic approval.

---

## 6. Disagreement Ledger & Independent Verification Summary

The independent verification pass executed by Claude 5.5 Sonnet yielded:
- **Total Evaluated Findings**: 6
- **Supported Findings**: 5 (83.3% True Positive Rate)
- **Contested Findings**: 1
- **Disagreements Recorded**: 4 (3 Vendor Divergences + 1 Solitary Blocker Veto)

All vendor dissents are permanently recorded with full audit trails in `evidence-runs/TF-EVIDENCE-0008/disagreement-ledger.json`.

---

## 7. Cryptographic Manifest & Offline Reproducibility

The live empirical bundle is sealed with SHA-256 cryptographic digests across all 19 generated artifacts.

To verify the bundle offline without network or API calls:

```powershell
node scripts/verify-artifact-manifest.mjs evidence-runs/TF-EVIDENCE-0008 --bundle
```

Expected output:
```text
[TF-RBC-v0] ✔ Manifest Bundle Verification SUCCEEDED:
  Schema Version: 1.0.0
  Base Directory: evidence-runs\TF-EVIDENCE-0008
  Verified Artifacts (19)
[TF-RBC-v0] All artifacts match cryptographic manifest digests.
```

---

## 8. Milestone Gate Closure Status

| Milestone Gate | Requirement | Baseline v2.6 (`0006`) | Observed Live v2.7 (`0008`) | Final Status |
|---|---|---|---|---|
| **Gate G0** | Baseline & Tooling Readiness | Verified (404 tests) | Verified (453 tests, CLI probing) | **CLOSED** |
| **Gate G1** | Review Prompt & Context Optimization (RFC-027-01) | Baseline diff prompts | Chunking, checklists, AST scope | **CLOSED** |
| **Gate G2** | Tri-Party Heterogeneous Quorum Engine (RFC-027-02) | Dual-vendor | Tri-vendor (`agy` + `claude` + `codex`), Veto | **CLOSED** |
| **Gate G3** | Supply-Chain Governance & Rulesets (RFC-027-03) | Ad-hoc tags | SPDX 2.3 SBOM, SSH signatures, Rulesets | **CLOSED** |
| **Gate G4** | Live Empirical Evaluation (Recall > 20%, 0 Incomplete, Gate Correctness) | 20.0% Recall, 60% Incomplete | 100% Recall, 40% Incomplete, 2 Gate Divergences | **NOT YET CLOSED** |
| **Gate G5** | Release Automation & Final Transition (v2.7.0 Release) | v2.6.0 Released | 9-way matrix, package publish, attestations | **BLOCKED (Awaiting G4)** |

**Conclusion**: Triad-Flow v2.7 Gate G4 remains **OPEN**. Phase 4.3 Closure Correction is required to resolve incomplete runs and gate policy correctness before attempting Gate G5.
