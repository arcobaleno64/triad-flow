# Triad-Flow Real-World OSS Benchmark Corpus v1 Specification
**Document ID**: `TF-DOC-BENCH-OSS-V1`  
**Status**: Normative Specification (`TF-OSS-v1`)  
**Applicability**: Triad-Flow v2.6.0+ Empirical External Validity Evaluation  
**Immutability Invariant**: Cases, base files, and patch diffs in `TF-OSS-v1` are cryptographically pinned. Any alteration requires bumping to a new version (e.g. `TF-OSS-v2`).

---

## 1. Executive Summary & Problem Statement

Triad-Flow v2.2.0–v2.5.1 established formal guarantees for multi-sentry consensus, epistemic humility, Patch Jail isolation, container execution authority, and auditable cryptographic receipts. However, benchmark evaluations prior to v2.6 utilized synthetic and self-designed scenarios (`TF-RBC-v0`).

This specification establishes **Triad-Flow Real-World OSS Corpus v1 (`TF-OSS-v1`)** to address external validity:
> *"Does Triad-Flow hold up when evaluated against historical security vulnerabilities and patches from real open-source production repositories?"*

`TF-OSS-v1` comprises 5 human-adjudicated, high-profile Node.js open-source packages with historical CVE/GHSA disclosures, pinned git commit references, real-world unified diffs, and deterministic offline test suites.

---

## 2. Dataset Architecture & Schema

Each `TF-OSS-v1` case represents an isolated, reproducible package repository with:
1. **Pinned Upstream Repository Metadata**: Canonical upstream repository URL, vulnerable commit reference, and fix commit reference.
2. **Ground-Truth Security Taxonomy**: Associated CVE ID, GitHub Security Advisory (GHSA) ID, Common Weakness Enumeration (CWE), and CVSS severity.
3. **Target File Boundaries**: Strict target file allowlist enforcing Patch Jail confinement.
4. **Deterministic Typed Command Runner**: Standard `{ command, args }` command specification (e.g. `{ command: "node", args: ["test/test.js"] }`) runnable inside both Git worktrees and container sandboxes with zero external network access (`--network=none`).
5. **Pre/Post Test Oracle**: Deterministic test script using native Node.js assertions (`node:assert`) that fails closed prior to patch application and passes cleanly after patch application.

### 2.1 Case Definition Schema

```json
{
  "id": "TF-OSS-001",
  "name": "minimist",
  "title": "Prototype Pollution via __proto__ in minimist",
  "cve": "CVE-2020-7598",
  "ghsa": "GHSA-vh95-rmgr-6w4m",
  "cwe": "CWE-1321",
  "severity": "high",
  "upstream": {
    "repository": "https://github.com/minimistjs/minimist",
    "vulnerableCommit": "388a963",
    "fixCommit": "63e7ed0"
  },
  "targetFiles": ["index.js"],
  "testRunner": {
    "command": "node",
    "args": ["test/test.js"]
  },
  "goldenFindings": [
    {
      "cwe": "CWE-1321",
      "type": "prototype-pollution",
      "file": "index.js",
      "line": 9,
      "severity": "high",
      "rationale": "Object prototype pollution via unvalidated __proto__ property in argument keys"
    }
  ]
}
```

---

## 3. The 5 Curated Real-World OSS Benchmark Cases

| ID | Repository | CVE / GHSA | CWE / Category | Target File | Vulnerability Mechanism |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TF-OSS-001** | `minimist` | `CVE-2020-7598`<br>`GHSA-vh95-rmgr-6w4m` | `CWE-1321`<br>Prototype Pollution | `index.js` | Direct traversal across `__proto__` in argument key hierarchy permits remote object prototype pollution. |
| **TF-OSS-002** | `ini` | `CVE-2020-7788`<br>`GHSA-q9h2-87cx-55g6` | `CWE-1321`<br>Prototype Pollution | `ini.js` | INI section header `[__proto__]` assignment pollutes global `Object.prototype`. |
| **TF-OSS-003** | `fast-json-patch` | `CVE-2021-4279`<br>`GHSA-q7cm-758j-8q94` | `CWE-1321`<br>Prototype Pollution | `src/core.js` | JSON-Patch `add`/`replace` operation via path `/constructor/prototype` bypasses basic `__proto__` filter. |
| **TF-OSS-004** | `semver` | `CVE-2022-25883`<br>`GHSA-c2qf-rxjj-qqgw` | `CWE-1333`<br>ReDoS | `internal/re.js` | Unbounded greedy whitespace tokenization in version range regex causes catastrophic backtracking. |
| **TF-OSS-005** | `ejs` | `CVE-2022-29078`<br>`GHSA-phwq-j96m-2c2q` | `CWE-94`<br>Code Injection / SSTI | `lib/ejs.js` | Unsanitized `outputFunctionName` option permits arbitrary JavaScript statement interpolation during compilation. |

---

## 4. Evaluation Invariants & Execution Guarantees

1. **Zero Runtime Dependencies**: All case fixtures and deterministic test runners execute via pure Node.js standard libraries (`node:assert`, `node:fs`, `node:path`), ensuring hermetic execution without requiring `npm install` or external internet connectivity.
2. **Container Authority Compliance**: Every case conforms to the v2.5.1 Container Authority model. Tests specify typed command runners (`{ command, args }`) compatible with `ContainerDriver` and `WorktreeDriver`.
3. **Patch Jail Boundary Enforcement**: Patches are applied strictly to declared `targetFiles`. Modification to unauthorized files (such as `package.json`, CI workflows, or out-of-scope files) triggers immediate `PatchJailSecurityError` (Fail-Closed).
4. **Digest Continuity**: Pre-patch tree digest ($T_0$), patch diff digest ($D$), post-patch tree digest ($T_1$), and post-test tree digest ($T_{test}$) are tracked and verified against state tampering.
5. **Batch Remediation Verification**: Multiple real OSS findings can be submitted into `BatchRemediationSession`. Conflicting target files are detected via the conflict DAG, and non-conflicting findings are executed in deterministic topological order with granular receipt generation.
