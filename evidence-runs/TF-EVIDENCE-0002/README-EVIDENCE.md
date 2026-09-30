# Triad-Flow Immutable Evidence Bundle: TF-EVIDENCE-0002

## Bundle Identity
- **Bundle ID**: `TF-EVIDENCE-0002`
- **Title**: Controlled Remediation Multi-Defect Verification Bundle (5 CWEs)
- **Triad-Flow Version**: `2.3.0`
- **Git Commit**: `c9d0b6e8b51b08f9c888ccee5aeae42180c70987`
- **Corpus Version**: `TF-RBC-v0`
- **Corpus Digest**: `sha256:cf9c4596cca5910bf1c493590e16a4333782defea779a39488fa95f6b16fb82b`
- **Sealed At**: `2026-09-30T04:16:56.232Z`
- **Remediated Defects**: 5 Tier-1 CWEs (`BENCH-REAL-001` through `005`)

## Multi-Defect Remediation Summary
| Case ID | CWE | Vulnerability Title | Target File | Status | Synthesizer | Authorizer | Verifier |
|---|---|---|---|:---:|:---:|:---:|:---:|
| `BENCH-REAL-001` | `CWE-89` | SQL Injection in User Query Handler | `undefined` | **CLOSED** | `codex` | `security-lead@triad.flow` | `claude` |
| `BENCH-REAL-002` | `CWE-798` | Hardcoded JWT Secret and Verification Bypass | `undefined` | **CLOSED** | `codex` | `security-lead@triad.flow` | `claude` |
| `BENCH-REAL-003` | `CWE-22` | Path Traversal in File Fetcher | `undefined` | **CLOSED** | `codex` | `security-lead@triad.flow` | `claude` |
| `BENCH-REAL-004` | `CWE-79` | Stored and DOM XSS in Profile Render | `undefined` | **CLOSED** | `codex` | `security-lead@triad.flow` | `claude` |
| `BENCH-REAL-005` | `CWE-639` | IDOR in Invoice Handler | `undefined` | **CLOSED** | `codex` | `security-lead@triad.flow` | `claude` |

## 9-State Lifecycle Invariants & Defense Guarantees
Every candidate remediation strictly enforced the normative 9-state lifecycle:
```text
OPEN -> FIX_PROPOSED -> PATCH_AUTHORIZED -> PATCH_APPLIED_IN_JAIL -> FIXED_PENDING_VERIFY -> CLOSED
```
- **Repository Write Isolation**: Patch Jail executed in ephemeral detached Git worktrees; authoritative repository branch remained bit-level immutable.
- **Fail-Closed Gate Enforcement**: Human Authorization, Deterministic Test execution, and Independent Closure Verification were all affirmatively evaluated.
- **Heterogeneous Multi-Model Verification**: All fixes synthesized by Codex were independently verified by Claude against Section 7 invariants.

## Bundle Contents
```text
TF-EVIDENCE-0002/
├── corpus-identity.json             # Deterministic TF-RBC-v0 corpus identity & digests
├── release-identity.json            # High-level provenance, run parameters & cross-reference
├── evidence-index.json              # Byte-level manifest of all files in bundle
├── artifact-manifest.json           # Cryptographic SHA-256 manifest of the bundle
├── README-EVIDENCE.md               # Offline verification instructions
├── patches/                         # Canonical unified diff patches for each defect
│   ├── BENCH-REAL-001.patch
│   ├── BENCH-REAL-002.patch
│   ├── BENCH-REAL-003.patch
│   ├── BENCH-REAL-004.patch
│   └── BENCH-REAL-005.patch
├── remediation-receipts/            # Immutable Schema 1.0.0 remediation receipts
│   ├── BENCH-REAL-001-receipt.json
│   ├── BENCH-REAL-002-receipt.json
│   ├── BENCH-REAL-003-receipt.json
│   ├── BENCH-REAL-004-receipt.json
│   └── BENCH-REAL-005-receipt.json
└── verification/                    # Section 7 independent closure verification records
    ├── BENCH-REAL-001-verification.json
    ├── BENCH-REAL-002-verification.json
    ├── BENCH-REAL-003-verification.json
    ├── BENCH-REAL-004-verification.json
    └── BENCH-REAL-005-verification.json
```

## Verification Instructions (100% Offline)
This bundle contains authoritative receipts and manifests. You can verify all cryptographic claims offline without invoking any LLMs or network services.

### Step 1: Verify the Outer Bundle Manifest
```bash
node scripts/verify-artifact-manifest.mjs evidence-runs/TF-EVIDENCE-0002
```

### Step 2: Validate Remediation Receipts (Schema 1.0.0)
```bash
node -e '
const fs = require("fs");
const { validateRemediationReceipt } = require("./src/core/controlled-remediation.mjs");
const cases = ["BENCH-REAL-001", "BENCH-REAL-002", "BENCH-REAL-003", "BENCH-REAL-004", "BENCH-REAL-005"];
for (const id of cases) {
  const receipt = JSON.parse(fs.readFileSync(`evidence-runs/TF-EVIDENCE-0002/remediation-receipts/${id}-receipt.json`, "utf8"));
  validateRemediationReceipt(receipt);
  console.log(`✔ ${id} Receipt Validated (Status: ${receipt.status})`);
}
'
```

### Step 3: Validate Independent Verification Records (Section 7 Invariants)
```bash
node -e '
const fs = require("fs");
const { validateVerificationRecord } = require("./src/core/independent-verifier.mjs");
const cases = ["BENCH-REAL-001", "BENCH-REAL-002", "BENCH-REAL-003", "BENCH-REAL-004", "BENCH-REAL-005"];
for (const id of cases) {
  const record = JSON.parse(fs.readFileSync(`evidence-runs/TF-EVIDENCE-0002/verification/${id}-verification.json`, "utf8"));
  const res = validateVerificationRecord(record);
  if (!res.valid) { console.error(`INVALID ${id}:`, res.errors); process.exit(1); }
  console.log(`✔ ${id} Section 7 Verification Record Validated`);
}
'
```
