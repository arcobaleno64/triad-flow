# Triad-Flow v2.7 Live Empirical Evaluation Benchmark Report

- **Document ID**: `TF-EVAL-V27-002`
- **Milestone**: Triad-Flow v2.7 (Tri-Party Heterogeneous Quorum Live Evaluation)
- **Author**: Triad-Flow Core Architecture Team
- **Date**: 2026-10-01
- **Status**: Authoritative Live Empirical Benchmark Report
- **Classification**: `LIVE_EMPIRICAL_EVALUATION_RECORDED` / `G4_LIVE_EMPIRICAL_GATE = CLOSED`
- **Frozen Benchmark Corpus**: `TF-OSS-v1` (`sha256:47ed3ce44878b77572005358a16511e3f0900dda11d14443e6a2a84baf501625`)
- **Historical Live Baseline**: `evidence-runs/TF-EVIDENCE-0006/` (`fe57597c8fce5d699f764ec4d4dfe3d1e5b5cc73`)
- **Simulation Validation Baseline**: `evidence-runs/TF-EVIDENCE-0007/` (`executionMode: "mock"`)
- **Authoritative Initial Live Bundle**: `evidence-runs/TF-EVIDENCE-0008/` (`executionMode: "live"`)
- **Intermediate Closure Repair Bundle**: `evidence-runs/TF-EVIDENCE-0009/` (`executionMode: "live"`)
- **Canonical Final G4 Closure Bundle**: `evidence-runs/TF-EVIDENCE-0010/` (`executionMode: "live"`)

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

### Live Empirical Progression Across Runs

| Benchmark Metric | Baseline (`TF-EVIDENCE-0006`) | Mandatory G4 Threshold | Supplementary Target | Canonical Sealed Bundle (`TF-EVIDENCE-0010`) | G4 Status |
|---|---|---|---|---|---|
| **Recall (R)** | **20.0%** (1/5) | $> 20.0\%$ | $\ge 60.0\%$ | **80.0%** (4/5) | **PASS** |
| **Incomplete Rate** | **60.0%** (3/5) | **0.0%** (0/5) | **0.0%** (0/5) | **0.0%** (0/5) | **PASS** |
| **Precision (P)** | **50.0%** | N/A | $\ge 50.0\%$ | **80.0%** (4/5) | **PASS (Target Met)** |
| **Gate Correctness (`gatePolicyPass`)** | **20.0%** (1/5) | N/A | **100.0%** (5/5) | **80.0%** (4/5, 001..004 Blocked) | **TARGET MISSED (Empirical Debt)** |
| **Average Latency** | **69.780s** | N/A | $\le 60.0\text{s}$ | **87.605s** | **TARGET MISSED (Non-Blocking)** |

> [!IMPORTANT]
> **Authoritative Gate G4 Determination & Canonical Evidence Supersession (`TF-EVIDENCE-0010`)**:
> - **Mandatory Roadmap §4.4 Acceptance Criteria Satisfied**:
>   1. `v2.6.0` release published successfully with valid SSH signatures and SLSA attestations (verified on `main` release tags / commit `4b305e11`).
>   2. Frozen corpus digest for `TF-OSS-v1` remains exactly `sha256:47ed3ce44878b77572005358a16511e3f0900dda11d14443e6a2a84baf501625`.
>   3. `TF-EVIDENCE-0007` passes offline manifest verification: `node scripts/verify-artifact-manifest.mjs evidence-runs/TF-EVIDENCE-0007` (all 13 artifacts verified).
>   4. Recall strictly improves over baseline ($> 20.0\%$): observed **80.0%** (4/5) in canonical live bundle `TF-EVIDENCE-0010`.
>   5. Zero incomplete runs ($0/5$ cases incomplete): observed **0.0%** (0/5) in canonical live bundle `TF-EVIDENCE-0010`.
> - **Roadmap §6 Qualitative Criteria Satisfied**: All 5 cases produce valid verification records; disagreement ledger correctly logs multi-model divergence.
> - **Canonical Evidence Supersession**: Under maintainer governance disposition (2026-10-03), `TF-EVIDENCE-0010` formally supersedes the live evaluation role originally designated for `TF-EVIDENCE-0007` while retaining `0007`'s offline verification obligations.
> - **Known Empirical Debt & Residual Limitation (`TF-OSS-005`)**:
>   * Package: `ejs` (CVE-2022-29078 / CWE-94)
>   * Expected Gate: `BLOCK` | Actual Gate: `APPROVE`
>   * Detection: missed (0/3 sentries caught)
>   * Classification: Honest residual defect; not an authority or gate policy flaw (the policy gate correctly blocks whenever any finding exists). Registered as open empirical debt for Track D1 dogfooding and future benchmark iterations. Non-blocking for G4 closure.
> - **Gate G4 Status**: Officially **CLOSED**. Gate G5 release preparation is authorized (release merge and tagging remain on HOLD pending formal release ceremony).

### Governance Erratum: Authoritative Gate G4 Criteria & Evidence Supersession (0007 → 0010)

This section documents the formal correction of the Gate G4 governance record, ensuring full fidelity to `docs/roadmap/v2.7-milestone-roadmap.md §4.4` and `§6`:

#### 1. Complete Preservation of Roadmap §4.4 Acceptance Criteria

| Mandatory G4 Requirement | Authoritative Status & Verification Evidence | Evaluation Outcome |
|---|---|---|
| **v2.6.0 Formal Release** | Published on GitHub Releases with valid SSH signatures (`.github/allowed_signers`) and SLSA provenance/SBOM attestations at release commit `4b305e11`. | **PASS (Satisfied)** |
| **TF-OSS-v1 Corpus Digest** | Corpus digest is hard-pinned and verified byte-for-byte at `sha256:47ed3ce44878b77572005358a16511e3f0900dda11d14443e6a2a84baf501625`. | **PASS (Satisfied)** |
| **Designated Bundle Offline Verification (`TF-EVIDENCE-0007`)** | Explicitly designated bundle `TF-EVIDENCE-0007` verified offline via `node scripts/verify-artifact-manifest.mjs evidence-runs/TF-EVIDENCE-0007` (all 13 artifacts match cryptographic manifest). | **PASS (Satisfied)** |
| **Recall (R)** | Recall strictly exceeds baseline ($> 20.0\%$): observed **80.0%** (4/5) in canonical live bundle `TF-EVIDENCE-0010`. | **PASS (Satisfied)** |
| **Incomplete Runs** | Strictly zero incomplete cases ($0/5$ incomplete): observed **0.0%** (0/5) in canonical live bundle `TF-EVIDENCE-0010`. | **PASS (Satisfied)** |

#### 2. Roadmap §6 Qualitative Acceptance Criteria

Per `docs/roadmap/v2.7-milestone-roadmap.md §6`, Gate G4 mandates that:
> *"All 5 cases produce valid verification records; disagreement ledger correctly logs multi-model divergence."*

This qualitative requirement is evaluated on substantive semantic validity, not merely file presence or hash matching:
- **Valid Verification Records**: In `TF-EVIDENCE-0010`, independent verification was conducted by Claude 3.5/5.5 Sonnet across all 5 benchmark cases (`verification-records/TF-OSS-001..005-verification.json` and `verification/verification-record.json`). Each record adheres to `TF-SPEC-RECEIPT-v1.0.0 Section 7`, containing frozen producer findings, locator accuracy validations, severity classifications, and explicit verifier reasoning without mutation or suppression.
- **Disagreement Ledger Accuracy**: The multi-model divergence ledger (`disagreement-ledger.json`) truthfully logs genuine inter-sentry dissents (e.g. `fast-json-patch` where Codex identified AST prototype pollution nuances contested by Google agy). No dissenting opinion was collapsed, silenced, or smoothed away by majority vote.

#### 3. Historical Plan Deviation & Canonical Evidence Supersession Record (0007 → 0010)

This record documents the operational history and formal supersession of empirical evidence bundles:

```text
原始計畫 (Original Plan):
  Roadmap §4.4 designated TF-EVIDENCE-0007 to bear the v2.7 live empirical evaluation.

實際執行 (Actual Execution):
  TF-EVIDENCE-0007 was implemented and executed as deterministic offline mock simulation evidence (executionMode: "mock").
  TF-EVIDENCE-0008 and TF-EVIDENCE-0009 were generated as intermediate live runs during staged-review debugging.
  TF-EVIDENCE-0010 was generated and sealed as the definitive, canonical live G4 evaluation (executionMode: "live").

保留承諾 (Retention Invariants):
  TF-EVIDENCE-0007 preserves its original mock simulation identity, sealed artifacts, and offline manifest verification obligations.
  All historical live bundles (0008, 0009) and sealed evidence directories remain byte-for-byte immutable.

正式替代 (Canonical Supersession):
  TF-EVIDENCE-0010 exclusively supersedes the live empirical evaluation role originally assigned to TF-EVIDENCE-0007.
```

- **Original Basis**: `docs/roadmap/v2.7-milestone-roadmap.md §4.3` and `§4.4`.
- **Actual Deviation**: `TF-EVIDENCE-0007` was generated in mock simulation mode to avoid live network dependencies during initial pipeline scaffolding, while live evaluation was subsequently conducted in `0008`, `0009`, and finalized in `0010`.
- **Supersession Scope**: Only the role of providing live empirical benchmark metrics (Recall, Incomplete rate, Gate policy behavior) is superseded from `0007` to `0010`. The requirement that `0007` pass offline manifest verification is retained and verified.
- **Rationale**: `TF-EVIDENCE-0010` provides authentic live CLI invocations against the frozen `TF-OSS-v1` corpus with real wall-clock latencies and live multi-vendor quorum interaction.
- **Approval Basis**: Formally adjudicated under maintainer governance disposition during the v2.7.0 release candidate review (2026-10-03).
- **Residual Debts & Missed Targets Preserved**: Supersession does not erase performance shortfalls. Gate Policy Pass (80.0%, 4/5) and average latency (87.605s) missed supplementary milestone targets (`TARGET MISSED`). `TF-OSS-005` (ejs CVE-2022-29078 detection miss) remains explicitly registered as open empirical debt for v2.7.1 dogfooding.
- **Sealed Bundle Immutability**: Historical bundle `TF-EVIDENCE-0010` remains byte-for-byte unchanged (`sha256:035ae8f5...`), preserving the immutable audit trail.

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

## 4. Case-by-Case Empirical Breakdown (`TF-EVIDENCE-0010`)

| Case ID | Target Package | Historical CVE | Golden CWE | Corroborations | Actual Gate | Expected Gate | Gate Policy Pass | Status | Execution Details |
|---|---|---|---|---|---|---|---|---|---|
| `TF-OSS-001` | `minimist` | CVE-2020-7598 | CWE-1321 | 2/3 (`claude`, `codex`) | **BLOCK** | **BLOCK** | **true** | `reviewed-with-findings` | Latency: 25.1s, Complete (0 errors) |
| `TF-OSS-002` | `ini` | CVE-2020-7788 | CWE-1321 | 2/3 (`agy`, `claude`) | **BLOCK** | **BLOCK** | **true** | `reviewed-with-findings` | Latency: 35.7s, Complete (0 errors) |
| `TF-OSS-003` | `fast-json-patch` | CVE-2021-4279 | CWE-1321 | 2/3 (`claude`, `codex`) | **BLOCK** | **BLOCK** | **true** | `reviewed-with-findings` | Latency: 257.6s, Complete (0 errors) |
| `TF-OSS-004` | `semver` | CVE-2022-25883 | CWE-1333 | 2/3 (`claude`, `codex`) | **BLOCK** | **BLOCK** | **true** | `reviewed-with-findings` | Latency: 27.8s, Complete (0 errors) |
| `TF-OSS-005` | `ejs` | CVE-2022-29078 | CWE-94 | 0/3 (clean) | **APPROVE** | **BLOCK** | **false** | `clean` | Latency: 91.6s, Complete (0 errors) |

---

## 5. Track D1 Shadow Dogfooding Telemetry

In Phase 4.3, Triad-Flow initiated Track D1 Shadow Dogfooding (`scripts/dogfood-review.mjs`), running a tri-party review against its own PR diff (`fix/v2.7-gate-policy-and-json-robustness` vs `main`).

- **Advisory Authority**: Strictly `NONE (ADVISORY_ONLY)`
- **PR Scope**: 5 files (+159 / -39)
- **Reviewer Status**:
  - `agy`: empty (0 findings, 148s)
  - `claude`: success (4 findings, 57s)
  - `codex`: auth_failure (128s)
- **High-Value Dogfood Finding**: Claude identified that `extractJsonFromText` selected the root object via `lastIndexOf('{', findingsIdx)`, which causes silent finding drops when pre-findings fields (such as `coverage`) contain nested objects. This was promptly fixed and covered by contract tests in PR #29.

---

## 6. Offline Verification Instructions

Both the designated simulation bundle `TF-EVIDENCE-0007` and the live benchmark bundles (`TF-EVIDENCE-0008`, `TF-EVIDENCE-0009`, `TF-EVIDENCE-0010`) are sealed with SHA-256 cryptographic manifests. You can verify them offline:

```powershell
# Verify Roadmap §4.4 designated simulation bundle (TF-EVIDENCE-0007)
node scripts/verify-artifact-manifest.mjs evidence-runs/TF-EVIDENCE-0007 --bundle

# Verify historical initial live run (TF-EVIDENCE-0008)
node scripts/verify-artifact-manifest.mjs evidence-runs/TF-EVIDENCE-0008 --bundle

# Verify intermediate repair run (TF-EVIDENCE-0009)
node scripts/verify-artifact-manifest.mjs evidence-runs/TF-EVIDENCE-0009 --bundle

# Verify canonical final G4 live closure bundle (TF-EVIDENCE-0010)
node scripts/verify-artifact-manifest.mjs evidence-runs/TF-EVIDENCE-0010 --bundle
```

---

## 7. Milestone Gate Closure Status

| Milestone Gate | Requirement | Baseline v2.6 (`0006`) | Observed Live v2.7 (`0010`) | Final Status |
|---|---|---|---|---|
| **Gate G0** | Baseline & Tooling Readiness | Verified (404 tests) | Verified (474 tests, CLI probing) | **CLOSED** |
| **Gate G1** | Review Prompt & Context Optimization (RFC-027-01) | Baseline diff prompts | Chunking, checklists, AST scope | **CLOSED** |
| **Gate G2** | Tri-Party Heterogeneous Quorum Engine (RFC-027-02) | Dual-vendor | Tri-vendor (`agy` + `claude` + `codex`), Veto | **CLOSED** |
| **Gate G3** | Supply-Chain Governance & Rulesets (RFC-027-03) | Ad-hoc tags | SPDX 2.3 SBOM, SSH signatures, Rulesets | **CLOSED** |
| **Gate G4** | Full Gate G4 Acceptance Criteria (Roadmap §4.4 & §6):<br>1. v2.6.0 released with SSH/SLSA<br>2. TF-OSS-v1 corpus digest intact<br>3. TF-EVIDENCE-0007 manifest verified<br>4. Recall > 20.0% (canonical in `0010`)<br>5. Incomplete = 0/5 (canonical in `0010`)<br>6. Valid verification records & disagreement ledger | 20.0% Recall, 60% Incomplete | All criteria satisfied:<br>- v2.6.0 released at `4b305e11`<br>- Corpus digest intact<br>- 0007 verified offline (13/13)<br>- 80.0% Recall in `0010`<br>- 0/5 Incomplete in `0010`<br>- Valid verifications & ledger | **CLOSED** |
| **Gate G5** | Release Automation & Final Transition (v2.7.0 Release) | v2.6.0 Released | 9-way matrix, package publish, attestations | **READY (Unblocked, release ceremony on HOLD)** |

**Conclusion**: Triad-Flow v2.7 Gate G4 is officially **CLOSED**. All five Roadmap §4.4 acceptance criteria and §6 qualitative verification requirements are satisfied, with `TF-EVIDENCE-0010` canonically superseding the live empirical role of `TF-EVIDENCE-0007` under formal governance disposition. Gate G5 (v2.7.0 formal release preparation) is unblocked, while merge and tagging remain strictly on HOLD pending maintainer release review.
 
---

## 8. Known Limitations & Open Empirical Debt (v2.7.1)

- **TF-OSS-005 (ejs CVE-2022-29078 / CWE-94)**: Expected BLOCK, actual APPROVE due to detection miss across all 3 sentries. Preserved truthfully in `TF-EVIDENCE-0010` and tracked for ongoing prompt/context tuning in v2.7.1.
- **P2-1 (Oversized single-line coordinate inflation - v2.7.1 DEBT)**: Chunk partitioner splitting single oversized diff lines into synthetic lines may advance line coordinates. Documented as non-blocking v2.7.1 debt.
- **P2-2 (POSIX literal backslash exclusion collision - v2.7.1 DEBT)**: Path normalization converts `\` to `/`, which on POSIX systems could collide with legal filename characters. Documented as non-blocking v2.7.1 debt.
- **Staged deadline after context construction (v2.7.1 DEBT)**: Chunk context and prompt construction duration is not subtracted immediately prior to provider invocation, allowing minor wall-clock slip past T_total equal to preparation time. Documented as non-blocking v2.7.1 debt.
