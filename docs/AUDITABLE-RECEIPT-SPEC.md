# Triad-Flow v2.2.0 Auditable Receipt & Provenance Specification
**Document ID**: `TF-SPEC-RECEIPT-v1.0.0`  
**Schema Version**: `1.0.0`  
**Status**: Normative Contract (v2.2.0 Baseline)  
**Applicability**: All benchmark suites, audit receipts, and release manifest bundles  

---

## 1. Core Principles & Objective

v2.2.0 shifts the benchmark paradigm from "counting test passes" to **Auditable Empirical Evidence**.
Every benchmark finding and metric must answer:
1. **What was tested?** (Deterministic corpus & case digest)
2. **When and where was it tested?** (Run metadata & execution environment)
3. **What tools evaluated it?** (Strict provider provenance with source trust tiers)
4. **What did it produce?** (Cryptographically signed findings and gate decisions)

---

## 2. Five Invariant Contracts

### Contract 1: Receipt Schema Versioning
- File: `audit-receipt.json`
- Top-level mandatory field: `schemaVersion: "1.0.0"`.
- **Reader Requirement**: Any parser encountering an unknown major version (`major !== 1`) MUST fail-closed with `UnsupportedReceiptSchemaError`. Backward-compatible minor/patch changes (`1.x.y`) are permitted.

### Contract 2: Separation of Stable Identity vs Run Metadata
To prevent run noise (timestamps, run IDs, hostnames, temp paths) from corrupting dataset identity:
- `identity` contains ONLY immutable benchmark inputs.
- `run` contains execution session metadata.
- **Strict Invariant**: Timestamps, machine names, process IDs, and transient file paths are strictly prohibited from contributing to `corpusDigest` or `caseDigest`.

```json
{
  "schemaVersion": "1.0.0",
  "identity": {
    "corpusVersion": "TF-RBC-v0.2.0",
    "corpusDigest": "sha256:...",
    "caseDigests": {
      "BENCH-REAL-001": "sha256:..."
    }
  },
  "run": {
    "runId": "run-20260929-151000-abc1",
    "startedAt": "2026-09-29T07:10:00.000Z",
    "finishedAt": "2026-09-29T07:15:30.000Z",
    "environment": {
      "platform": "win32",
      "arch": "x64",
      "nodeVersion": "v22.16.0"
    }
  },
  "systemProvenance": {
    "commitSha": "3af1e6d...",
    "branch": "main",
    "triadFlowVersion": "2.2.0"
  },
  "providerProvenance": {},
  "results": {}
}
```

### Contract 3: Canonicalization & Digest Specification
To guarantee bit-for-bit identical digests across Windows, Linux, and macOS:
1. **Character Encoding**: UTF-8 without BOM.
2. **Line Endings**: LF (`\n`, `0x0A`). CRLF (`\r\n`) must be normalized to LF before hashing.
3. **Path Normalization**: Repository-relative POSIX paths using forward slashes (`/`). Leading slashes and `.` segments removed.
4. **Key Ordering**: All object keys must be sorted lexicographically (`keys.sort()`).
5. **JSON Serialization**: Deterministic canonical JSON (no extraneous whitespace, standard escaping).
6. **Hash Algorithm**: SHA-256, encoded as lowercase hex prefixed with `sha256:`.
7. **Prompt Splitting**:
   - `promptTemplateDigest`: SHA-256 of the frozen benchmark prompt template.
   - `renderedPromptDigest`: SHA-256 of the fully-rendered prompt after diff/context injection.

### Contract 4: Provider Provenance & Source Trust Tiers
Never assume model identity or token usage without verifiable evidence:
- **Trust Tiers for Values (`source`)**:
  - `cli`: Extracted directly from external CLI `--version` or help output.
  - `runtime`: Extracted from provider process execution metadata / API response envelopes.
  - `reported`: Claimed by the model inside its generated findings JSON.
  - `inferred`: Derived from configuration or heuristics.
  - `unavailable`: Data not observed.
- **Model Identity Rule**: `actualModel` must record `{ value: string|null, source: string }`. If not explicitly reported by CLI or runtime, it MUST be `{ value: null, source: "unavailable" }`. Guessing is strictly prohibited.
- **Usage Rule**: `usageSource: "authoritative" | "unavailable"`. Unreported tokens remain `null` and are never coerced to zero.
- **Claude Profile Readiness Invariant**:
  `reviewProfileReady: true` requires all 7 conditions:
  1. Binary detected (`claude` in PATH)
  2. Version parsed
  3. Canonical profile matched
  4. Mandatory safety flags verified (`-p`, `--tools=`)
  5. Live invocation succeeds
  6. Output contract validates (schema & gate)
  7. Working tree unchanged (`git status --porcelain` empty, HEAD unaltered)

### Contract 5: Baseline Artifact Manifest
Every completed live benchmark run produces an immutable bundle:
- `artifact-manifest.json`:
  ```json
  {
    "schemaVersion": "1.0.0",
    "artifacts": {
      "benchmark-results.json": "sha256:...",
      "audit-receipt.json": "sha256:...",
      "summary.md": "sha256:..."
    },
    "metadata": {
      "runId": "...",
      "commitSha": "...",
      "corpusDigest": "sha256:...",
      "receiptDigest": "sha256:...",
      "resultsDigest": "sha256:..."
    }
  }
  ```
- Any modification to any artifact is immediately detectable.
- Release assets for milestone baselines include this bundle.

---

## 3. Empirical Pareto Comparison Bounds

1. **Experimental Control**: Single, Dual, and Risk-Adaptive modes must execute on the exact same corpus version, same provider CLI versions, same prompt templates, and within the same execution window.
2. **Metrics Measured**:
   - Recall Rate ($R$)
   - Precision ($P$)
   - False Block Rate ($FBR$)
   - Median (P50) and P90 wall-clock latency (ms)
   - Authoritative Token Usage (total and P50, only reported when `usageSource === "authoritative"`)
   - Provider failures & quorum failures
   - Per-case outcome breakdown
3. **Claim Boundary**: Reports must only state:
   > "Under these fixed benchmark conditions, Configuration A demonstrates non-inferiority to B on Recall/FBR with lower observed latency/token usage."
   No generalization to "optimal" or "cheaper in general" is permitted.

---

## 4. Phase Gates

| Phase | Gate Milestone | Required Acceptance Criterion |
|---|---|---|
| **Phase 1 (Alpha)** | Deterministic Identity & Canonical Receipt | Cross-platform canonicalization produces identical `corpusDigest` on Win/Linux/macOS; schema reader rejects unknown major. |
| **Phase 2 (Beta)** | Auditable Provider Provenance & Pilot | AGY + Claude canonical live pilots emit verified provenance and satisfy the 7-point readiness contract. |
| **Phase 3 (RC)** | Protected Workflow & Manifest Bundle | Protected GitHub Actions workflow (`workflow_dispatch`) generates and verifies `artifact-manifest.json`. |
| **Phase 4 (Release)** | Auditable Empirical Baseline | Complete Single, Dual, and Adaptive comparative evaluation derived from a single auditable run set attached to Release. |

---

## 5. Scope Invariants (What Triad-Flow v2.2.0 Will NOT Do)

1. **No Autonomous Factory Modification**: `factory` remains plan-only/zero-write.
2. **No Codex Profile Guesswork**: Canonical profiles restricted to Google `agy` and Anthropic `claude`. Generic codex remains unpromoted.
3. **No PR CI Live Invocations**: Live reviewer executions remain strictly isolated to manual `workflow_dispatch` on protected branches.
4. **No Corpus Case Expansion**: Frozen at 20 cases (12 vulnerable, 8 clean controls).
5. **No Synthetic Zero Usage**: Missing tokens remain `null`.
