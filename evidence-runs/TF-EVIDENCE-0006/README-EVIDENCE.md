# Triad-Flow Immutable Evidence Bundle: TF-EVIDENCE-0006

## Bundle Identity
- **Bundle ID**: `TF-EVIDENCE-0006`
- **Title**: TF-OSS-v1 Real-World External Validity Live Provider Experiment Bundle
- **Triad-Flow Version**: `2.5.1`
- **Evidence Source Commit**: `5198750b39b92ded2db604e2e11002b7417042f6`
- **Corpus Version**: `TF-OSS-v1` (Historical OSS Replay Corpus)
- **Corpus Digest**: `sha256:47ed3ce44878b77572005358a16511e3f0900dda11d14443e6a2a84baf501625`
- **Sealed At**: `2026-09-30T12:51:16.193Z`
- **Execution Mode**: `LIVE (Real Provider CLIs)`

## Participating Reviewer Models
| Role | CLI Command | Vendor / Family | Model Identity | Trust Tier |
|---|---|---|---|---|
| Macro Sentry (Producer) | `agy` | Google | `gemini-3.8-flash` | `reported` |
| Micro Sentry / Verifier | `claude` | Anthropic | `claude-5.5-sonnet` | `reported` |

## Empirical Results Across 5 Real-World CVE Cases
| Case ID | Upstream Package | CVE ID | Golden CWE | Actual Gate | Status | Findings Caught | Latency |
|---|---|---|---|---|---|---|---|
| `TF-OSS-001` | minimist argument parsing | CWE-1321 | CWE-1321 | `BLOCK` | `incomplete` | 0/1 | 24490ms |
| `TF-OSS-002` | ini file section decoding | CWE-1321 | CWE-1321 | `BLOCK` | `reviewed-with-findings` | 1/1 | 56894ms |
| `TF-OSS-003` | JSON-Patch constructor/prototype path | CWE-1321 | CWE-1321 | `BLOCK` | `incomplete` | 0/1 | 180062ms |
| `TF-OSS-004` | semver | CWE-1333 | CWE-1333 | `APPROVE` | `reviewed-with-findings` | 0/1 | 58512ms |
| `TF-OSS-005` | ejs | CWE-94 | CWE-94 | `BLOCK` | `incomplete` | 0/1 | 28941ms |

### Key Benchmark Metrics
- **Recall (R)**: 20.0% (1/5 Golden CWEs caught)
- **Precision (P)**: 50.0% (1/2 Findings verified)
- **False Block Rate (FBR)**: N/A (all 5 cases are real vulnerability diffs)
- **Latency Profile**: P50 = 56894ms, P95 = 180062ms, Avg = 69780ms
- **Token Expenditure**: Unreported by local CLI reviewers (null token preserved under Contract 4)

## Independent Verification Summary
- **Verifier**: Anthropic `claude` (`claude-5.5-sonnet`)
- **Total Evaluations**: 2
- **Supported Count**: 2
- **Contested Count**: 0
- **Verifier Omissions**: 9
- **Disagreements Recorded**: 1

## Bundle File Tree
```text
TF-EVIDENCE-0006/
├── corpus-identity.json          # Deterministic TF-OSS-v1 corpus identity & digests
├── release-identity.json         # High-level provenance & run cross-reference
├── audit-receipt.json            # Authoritative audit receipt with provider provenance
├── benchmark-results.json        # Full empirical benchmark evaluation results
├── disagreement-ledger.json      # Structured disagreement ledger from independent verifier
├── evidence-index.json           # Byte-level manifest of all files in bundle
├── artifact-manifest.json        # Cryptographic SHA-256 manifest of the bundle
├── README-EVIDENCE.md            # Offline verification guide & experiment report
└── verification/
    ├── TF-OSS-001-verification.json
    ├── TF-OSS-002-verification.json
    ├── TF-OSS-003-verification.json
    ├── TF-OSS-004-verification.json
    ├── TF-OSS-005-verification.json
    └── verification-record.json  # Aggregate verification record across all cases
```

## Verification Instructions (100% Offline)
This bundle contains authoritative cryptographic receipts and manifests. You can verify all claims offline without network or LLM execution:

### Step 1: Verify Outer Artifact Manifest
```bash
node scripts/verify-artifact-manifest.mjs evidence-runs/TF-EVIDENCE-0006
```

### Step 2: Validate Verification Records
```bash
node -e '
const fs = require("fs");
const { validateVerificationRecord } = require("./src/core/independent-verifier.mjs");
const cases = ["TF-OSS-001", "TF-OSS-002", "TF-OSS-003", "TF-OSS-004", "TF-OSS-005"];
for (const id of cases) {
  const record = JSON.parse(fs.readFileSync(`evidence-runs/TF-EVIDENCE-0006/verification/${id}-verification.json`, "utf8"));
  const res = validateVerificationRecord(record);
  if (!res.valid) { console.error(`INVALID ${id}:`, res.errors); process.exit(1); }
  console.log(`✔ ${id} Verification Record Validated Successfully`);
}
'
```

### Step 3: Validate Frozen Corpus Identity
```bash
node -e '
const fs = require("fs");
const doc = JSON.parse(fs.readFileSync("evidence-runs/TF-EVIDENCE-0006/corpus-identity.json", "utf8"));
if (doc.corpusDigest !== "sha256:47ed3ce44878b77572005358a16511e3f0900dda11d14443e6a2a84baf501625") throw new Error("Corpus digest mismatch");
console.log("✔ TF-OSS-v1 Frozen Digest Hard-Pin Confirmed:", doc.corpusDigest);
'
```
