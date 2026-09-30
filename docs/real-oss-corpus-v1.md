# Triad-Flow Real-World OSS Benchmark Corpus v1 Specification
**Document ID**: `TF-DOC-BENCH-OSS-V1`  
**Status**: Normative Specification (`TF-OSS-v1`)  
**Applicability**: Triad-Flow v2.6.0+ Empirical External Validity Evaluation  
**Nature**: Real-World OSS Historical Corpus / Offline Reproducible Replay Corpus  
**Immutability Invariant**: Cases, base files, upstream commit SHAs, and patch diffs in `TF-OSS-v1` are cryptographically pinned. Any alteration alters the corpus digest and requires a version bump (e.g. `TF-OSS-v2`).

---

## 1. Executive Summary & Problem Statement

Triad-Flow v2.2.0–v2.5.1 established formal guarantees for multi-sentry consensus, epistemic humility, Patch Jail isolation, container execution authority, and auditable cryptographic receipts. However, benchmark evaluations prior to v2.6 utilized synthetic and self-designed scenarios (`TF-RBC-v0`).

This specification establishes **Triad-Flow Real-World OSS Corpus v1 (`TF-OSS-v1`)** to address external validity:
> *"Does Triad-Flow hold up when evaluated against historical security vulnerabilities and patches from real open-source production repositories?"*

`TF-OSS-v1` is an **offline reproducible replay corpus** derived from 5 human-adjudicated, high-profile Node.js open-source packages. Each case encapsulates historical CVE/GHSA disclosures, authentic 40-character upstream commit hashes, real-world unified diffs, and deterministic offline test suites. In mock execution mode, 100% recall validates benchmark harness and scoring contracts; empirical provider performance requires live execution (`--live`).

---

## 2. Dataset Architecture & Schema

Each `TF-OSS-v1` case represents an isolated, reproducible package repository with:
1. **Pinned Upstream Repository Metadata**: Canonical upstream repository URL, authentic 40-character vulnerable commit SHA, and 40-character fix commit SHA.
2. **Ground-Truth Security Taxonomy**: Associated CVE ID, GitHub Security Advisory (GHSA) ID, Common Weakness Enumeration (CWE), and CVSS severity with documented taxonomy sources.
3. **Target File Boundaries**: Strict target file allowlist enforcing Patch Jail confinement.
4. **Deterministic Typed Command Runner**: Standard `{ command, args }` command specification (e.g. `{ command: "node", args: ["test/test.js"] }`) runnable inside both Git worktrees and container sandboxes with zero external network access (`--network=none`).
5. **Pre/Post Test Oracle**: Deterministic test script using native Node.js assertions (`node:assert`) that fails closed prior to patch application and passes cleanly after patch application.

---

## 3. The 5 Curated Real-World OSS Benchmark Cases

| ID | Repository | CVE / GHSA | CWE & Taxonomy | Commits (40-char SHA) | Target File | Vulnerability Mechanism |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **TF-OSS-001** | `minimistjs/minimist` | `CVE-2020-7598`<br>`GHSA-vh95-rmgr-6w4m` | `CWE-1321`<br>Medium (CVSS 5.6 NVD/GHSA) | Vuln: `47acf72c715a630bf9ea013867f47f1dd69dfc54`<br>Fix: `63e7ed05aa4b1889ec2f3b196426db4500cbda94` | `index.js` | Direct traversal across `__proto__` in argument key hierarchy permits remote object prototype pollution. |
| **TF-OSS-002** | `npm/ini` | `CVE-2020-7788`<br>`GHSA-qqgx-2p2h-9c37` | `CWE-1321`<br>High (CVSS 7.3 GHSA/NVD) | Vuln: `738eca59d77d8cfdddf5c477c17a0d8f8fbfe0fd`<br>Fix: `56d2805e07ccd94e2ba0984ac9240ff02d44b6f1` | `ini.js` | INI section header `[__proto__]` assignment pollutes global `Object.prototype`. |
| **TF-OSS-003** | `Starcounter-Jack/JSON-Patch` | `CVE-2021-4279`<br>`GHSA-8gh8-hqwg-xf34` | `CWE-1321`<br>High (CVSS 7.5 NVD/GHSA) | Vuln: `34d6405b2cc0a04ab67335fe0c1e845ba480f4ab`<br>Fix: `7ad6af41eabb2d799f698740a91284d762c955c9` | `src/core.js` | JSON-Patch `add`/`replace` operation via path `/constructor/prototype` bypasses basic `__proto__` filter. |
| **TF-OSS-004** | `npm/node-semver` | `CVE-2022-25883`<br>`GHSA-c2qf-rxjj-qqgw` | `CWE-1333`<br>High (CVSS 7.5 ReDoS) | Vuln: `2f738e9a70d9b9468b7b69e9ed3e12418725c650`<br>Fix: `717534ee353682f3bcf33e60a8af4292626d4441` | `internal/re.js` | Unbounded greedy whitespace tokenization in version range regex causes catastrophic backtracking (PR #564). |
| **TF-OSS-005** | `mde/ejs` | `CVE-2022-29078`<br>`GHSA-phwq-j96m-2c2q` | Dual: NVD `CWE-94` / GHSA `CWE-74`<br>Critical (CVSS 9.8) | Vuln: `c120527315e159ee48570f73936691f33113ec25`<br>Fix: `15ee698583c98dadc456639d6245580d17a24baf` | `lib/ejs.js` | Unsanitized `outputFunctionName` option permits arbitrary JavaScript statement interpolation during compilation. |

---

## 4. Cryptographic Identity & Exact Pinning

The immutable identity of `TF-OSS-v1` is derived deterministically from canonicalized case contents, upstream metadata, patch diffs, and the corpus version:

```text
Corpus Version: TF-OSS-v1
Expected Corpus Digest:
sha256:47ed3ce44878b77572005358a16511e3f0900dda11d14443e6a2a84baf501625

Case Digests:
• TF-OSS-001: sha256:c520d0f6ad9a3e9553426c4bb20578995d12425df4931c24fe8e99759c903914
• TF-OSS-002: sha256:1586be7b815652fd1ab477d623c1f9df5c8ce7b6337a4ef2292bd5b38b7180f7
• TF-OSS-003: sha256:f0d9241de553560e3576c15d77cf1f0a42cbc6df917c579b28ae8219e6535c28
• TF-OSS-004: sha256:5dc8195324d977d05bf20e340f08c41f0ff2a5036ebd03288bd235488365e672
• TF-OSS-005: sha256:294ad0c2b7383e86a45782e3928425f8fba2e6b181b1bd773c47f372af9f6071
```

Any modification to base files, upstream SHAs, or test assertions fails closed via automated cryptographic assertions.

---

## 5. Evaluation Invariants & Execution Guarantees

1. **Zero Runtime Dependencies**: All case fixtures and deterministic test runners execute via pure Node.js standard libraries (`node:assert`, `node:fs`, `node:path`), ensuring hermetic execution without requiring `npm install` or external internet connectivity.
2. **Container Authority Compliance**: Every case conforms to the v2.5.1 Container Authority model. Tests specify typed command runners (`{ command, args }`) compatible with `ContainerDriver` and `WorktreeDriver`.
3. **Patch Jail Boundary Enforcement**: Patches are applied strictly to declared `targetFiles`. Modification to unauthorized files triggers immediate `PatchJailSecurityError` (Fail-Closed).
4. **Digest Continuity**: Pre-patch tree digest ($T_0$), patch diff digest ($D$), post-patch tree digest ($T_1$), and post-test tree digest ($T_{test}$) are tracked and verified against state tampering.
5. **Batch Remediation Verification**: Multiple real OSS findings can be submitted into `BatchRemediationSession`. Conflicting target files are detected via the conflict DAG, and non-conflicting findings are executed in deterministic topological order with granular receipt generation.
