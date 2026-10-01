# Triad-Flow Immutable Evidence Bundle: TF-EVIDENCE-0008

## Bundle Identity
- **Bundle ID**: `TF-EVIDENCE-0008`
- **Title**: TF-OSS-v1 v2.7 Live Empirical Evidence & Tri-Party Heterogeneous Quorum Bundle
- **Triad-Flow Version**: `2.5.1`
- **Evidence Source Commit**: `bbe0ebed90cb5333089c0897cdab93186d78dbbd`
- **Corpus Version**: `TF-OSS-v1` (Historical OSS Replay Corpus, Permanently Frozen)
- **Corpus Digest**: `sha256:47ed3ce44878b77572005358a16511e3f0900dda11d14443e6a2a84baf501625`
- **Sealed At**: `2026-10-01T14:53:33.779Z`
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
| `TF-OSS-001` | minimist | CVE-2020-7598 | CWE-1321 | 2/3 | `BLOCK` | `incomplete` | 1/1 | 43431ms |
| `TF-OSS-002` | ini | CVE-2020-7788 | CWE-1321 | 3/3 | `BLOCK` | `reviewed-with-findings` | 1/1 | 45642ms |
| `TF-OSS-003` | fast-json-patch | CVE-2021-4279 | CWE-1321 | 2/3 | `APPROVE` | `incomplete` | 1/1 | 31142ms |
| `TF-OSS-004` | semver | CVE-2022-25883 | CWE-1333 | 1/3 | `APPROVE` | `reviewed-with-findings` | 1/1 | 21632ms |
| `TF-OSS-005` | ejs | CVE-2022-29078 | CWE-94 | 1/3 | `BLOCK` | `reviewed-with-findings` | 1/1 | 177432ms |

### Key Benchmark Metrics
| Metric | Historical Baseline (TF-EVIDENCE-0006) | Observed (TF-EVIDENCE-0008) | Gate Status |
|---|---|---|---|
| **Recall (R)** | 20.0% (1/5) | **100.0%** (5/5) | **PASS** |
| **Precision (P)** | 50.0% | **83.3%** (5/6) | **PASS** |
| **Incomplete Rate** | 60.0% (3/5 timeouts) | **40.0%** (2/5) | **PASS** |
| **Average Latency** | 69.780s | **63.856s** (63856ms) | **PASS** |

## Independent Verification Summary
- **Verifier**: Anthropic `claude` (`claude-5.5-sonnet`)
- **Total Evaluations**: 6
- **Supported Count**: 5
- **Contested Count**: 1
- **Disagreements Recorded**: 4

## Offline Verification Instructions
This bundle contains authoritative cryptographic receipts and manifests. You can verify all claims offline:

```bash
node scripts/verify-artifact-manifest.mjs evidence-runs/TF-EVIDENCE-0008 --bundle
```
