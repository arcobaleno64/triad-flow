# Triad-Flow Immutable Evidence Bundle: TF-EVIDENCE-0001

## Bundle Identity
- **Bundle ID**: `TF-EVIDENCE-0001`
- **Title**: Dual-Provider Live Evidence & Independent Verification Pilot Bundle
- **Triad-Flow Version**: `2.2.1`
- **Git Commit**: `a4d0b92f06859e75223225fce72b0c3d0b25d23d`
- **Corpus Version**: `TF-RBC-v0`
- **Corpus Digest**: `sha256:cf9c4596cca5910bf1c493590e16a4333782defea779a39488fa95f6b16fb82b`
- **Target Case**: `BENCH-REAL-001` (SQL Injection in User Query Handler)
- **Sealed At**: `2026-09-30T00:56:31.566Z`

## Bundle Contents
```text
TF-EVIDENCE-0001/
├── corpus-identity.json          # Deterministic TF-RBC-v0 corpus identity & digests
├── release-identity.json         # High-level provenance & run cross-reference
├── disagreement-ledger.json      # Structured disagreement ledger from independent verifier
├── evidence-index.json           # Byte-level manifest of all files in bundle
├── artifact-manifest.json        # Cryptographic SHA-256 manifest of the bundle
├── README-EVIDENCE.md            # This offline verification guide
├── verification/
│   └── verification-record.json  # Live Claude independent verification record of AGY finding
└── provider-runs/
    ├── agy-run-1/                # Google agy Run #1 (receipt, results, summary, manifest)
    ├── agy-run-2/                # Google agy Run #2 (receipt, results, summary, manifest)
    ├── claude-run-1/             # Anthropic claude Run #1 (receipt, results, summary, manifest)
    └── claude-run-2/             # Anthropic claude Run #2 (receipt, results, summary, manifest)
```

## Verification Instructions (100% Offline)
This bundle contains authoritative receipts and manifests. You can verify all cryptographic claims offline without invoking any LLMs or network services.

### Step 1: Verify the Outer Bundle Manifest
```bash
node scripts/verify-artifact-manifest.mjs evidence-runs/TF-EVIDENCE-0001
```

### Step 2: Verify Individual Provider Run Manifests
```bash
node scripts/verify-artifact-manifest.mjs evidence-runs/TF-EVIDENCE-0001/provider-runs/agy-run-1
node scripts/verify-artifact-manifest.mjs evidence-runs/TF-EVIDENCE-0001/provider-runs/agy-run-2
node scripts/verify-artifact-manifest.mjs evidence-runs/TF-EVIDENCE-0001/provider-runs/claude-run-1
node scripts/verify-artifact-manifest.mjs evidence-runs/TF-EVIDENCE-0001/provider-runs/claude-run-2
```

### Step 3: Validate Independent Verification Record (Section 7 Invariants)
```bash
node -e '
const fs = require("fs");
const { validateVerificationRecord } = require("./src/core/independent-verifier.mjs");
const record = JSON.parse(fs.readFileSync("evidence-runs/TF-EVIDENCE-0001/verification/verification-record.json", "utf8"));
const res = validateVerificationRecord(record);
if (!res.valid) { console.error("INVALID:", res.errors); process.exit(1); }
console.log("✔ Verification Record Section 7 Invariants Validated Successfully!");
'
```

## Ground-Truth Observations
All claims, latencies, recall, precision, and verifier evaluations are recorded directly inside the respective `audit-receipt.json` and `verification-record.json` files. This README serves solely as an index and verification guide.
