# Triad-Flow Immutable Evidence Bundle: TF-EVIDENCE-0010

## Bundle Identity
- **Bundle ID**: `TF-EVIDENCE-0010`
- **Title**: TF-OSS-v1 v2.7 Live Empirical Evidence & Tri-Party Heterogeneous Quorum Bundle
- **Triad-Flow Version**: `2.5.1`
- **Evidence Source Commit**: `7e280de1f9c23a119e52b7752c2e4ae09e75687d`
- **Corpus Version**: `TF-OSS-v1` (Historical OSS Replay Corpus, Permanently Frozen)
- **Corpus Digest**: `sha256:47ed3ce44878b77572005358a16511e3f0900dda11d14443e6a2a84baf501625`
- **Sealed At**: `2026-10-02T02:47:04.219Z`
- **Execution Mode**: `LIVE (Real Provider CLIs)`

## Participating Reviewer Models & Quorum Architecture
| Role | Sentry Binary | Vendor / Family | Model Identity | Consensus Role | Execution Constraints |
|---|---|---|---|---|---|
| Review Sentry 1 | `agy` | Google | `gemini-3.8-flash` | Corroboration & Solo Finding | `--mode=plan --disable-slash-commands --print` |
| Review Sentry 2 | `claude` | Anthropic | `claude-5.5-sonnet` | Corroboration & Solo Finding | `-p --tools=` |
| Review Sentry 3 | `codex` | OpenAI | `gpt-6.1-sol` | Corroboration & Solo Finding | `exec --sandbox=read-only --ephemeral --color never -o <file>` |
| Independent Verifier | `claude` | Anthropic | `claude-5.5-sonnet` | Cross-Verification Arbiter | Isolated Independent Verification |

## Empirical Results Across Evaluated Cases
| Case ID | Upstream Package | CVE ID | Golden CWE | Corroboration | Actual Gate | Status | Findings Caught | Latency |
|---|---|---|---|---|---|---|---|---|
| `TF-OSS-001` | minimist | CVE-2020-7598 | CWE-1321 | 3/3 | `BLOCK` | `reviewed-with-findings` | 1/1 | 25134ms |
| `TF-OSS-002` | ini | CVE-2020-7788 | CWE-1321 | 2/3 | `BLOCK` | `reviewed-with-findings` | 1/1 | 35746ms |
| `TF-OSS-003` | fast-json-patch | CVE-2021-4279 | CWE-1321 | 3/3 | `BLOCK` | `reviewed-with-findings` | 1/1 | 257660ms |
| `TF-OSS-004` | semver | CVE-2022-25883 | CWE-1333 | 1/3 | `BLOCK` | `reviewed-with-findings` | 1/1 | 27827ms |
| `TF-OSS-005` | ejs | CVE-2022-29078 | CWE-94 | 0/3 | `APPROVE` | `clean` | 0/1 | 91660ms |

### Key Benchmark Metrics vs Canonical Roadmap Gate G4
| Metric | Historical Baseline (TF-EVIDENCE-0006) | G4 Strict Acceptance Criterion | v2.7 Milestone Target | Observed (TF-EVIDENCE-0010) | Gate Status |
|---|---|---|---|---|---|
| **Recall (R)** | 20.0% (1/5) | > 20.0% | >= 60.0% | **80.0%** (4/5) | **PASS** |
| **Precision (P)** | 50.0% | >= 50.0% | >= 50.0% | **80.0%** (4/5) | **PASS** |
| **Incomplete Rate** | 60.0% (3/5) | 0.0% (0/5) | 0.0% (0/5) | **0.0%** (0/5) | **PASS** |
| **Gate Policy Pass** | 20.0% (1/5) | 100.0% (5/5) | 100.0% (5/5) | **80.0%** (4/5) | **FAIL** |
| **Average Latency** | 69.780s | <= 60.000s | <= 60.000s | **87.605s** (87605ms) | **TARGET MISSED** |

## Independent Verification Summary
- **Verifier**: Anthropic `claude` (`claude-5.5-sonnet`)
- **Total Evaluations**: 5
- **Supported Count**: 5
- **Contested Count**: 0
- **Disagreements Recorded**: 4

## Offline Verification Instructions
This bundle contains authoritative cryptographic receipts and manifests. You can verify all claims offline:

```bash
node scripts/verify-artifact-manifest.mjs evidence-runs/TF-EVIDENCE-0010 --bundle
```
