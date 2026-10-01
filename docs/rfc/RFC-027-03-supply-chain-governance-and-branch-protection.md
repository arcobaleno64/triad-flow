# RFC-027-03: Supply-Chain Governance, Branch Protection & Release Automation

- **RFC Identifier**: RFC-027-03
- **Title**: Supply-Chain Governance, Branch Protection & Release Automation
- **Target Milestone**: Triad-Flow v2.7 (with Formal v2.6.0 Release Specification)
- **Author**: Triad-Flow Core Architecture Team (Worker RFC-027-03)
- **Status**: Proposed / Authoritative Specification
- **Created**: 2026-10-01
- **Last Updated**: 2026-10-01
- **Baseline Milestone Commit**: `fe57597c8fce5d699f764ec4d4dfe3d1e5b5cc73`
- **Milestone Closure Status**: `V2.6_MILESTONE_CLOSED`
- **Current Package Version**: `2.5.1`
- **Frozen Benchmark Corpus**: `TF-OSS-v1` (`sha256:47ed3ce44878b77572005358a16511e3f0900dda11d14443e6a2a84baf501625`)
- **Authoritative Historical Evidence**: `TF-EVIDENCE-0006`
- **Runtime Dependency Invariant**: Exactly zero runtime npm dependencies (`package.json` contains no `dependencies`)
- **Test Baseline**: 404 total / 401 pass / 3 expected skips / 0 fail

---

## 1. Status

This document is in **Proposed** status. It establishes the mandatory supply-chain governance policies, GitHub repository branch and tag rulesets, cryptographic release identity protocols, and post-publish verification mechanisms for the Triad-Flow project. It governs both the preservation of the closed `v2.6` milestone and the end-to-end automated release pipeline for `v2.6.0` and `v2.7.0`.

---

## 2. Context

Triad-Flow is an autonomous, dependency-free consensus and adaptive control engine designed to orchestrate heterogeneous AI security reviewers (Google `agy`, Anthropic `claude`, and OpenAI Codex `gpt-6.1-sol`) to evaluate software diffs against fail-closed security gates.

In prior milestones (v2.0 through v2.5), Triad-Flow maintained an internal trust boundary centered around runtime immutability and test execution. However, as documented in historical security reviews (`SECURITY.md:49-50`), the project operated without formal branch ruleset enforcement, without signed commit requirements, without machine-readable software bills of materials (SBOMs), and without cryptographic release attestations.

The completion of the v2.6 milestone marked a major transition:
1. The real-world open-source corpus `TF-OSS-v1` was permanently sealed at digest `sha256:47ed3ce44878b77572005358a16511e3f0900dda11d14443e6a2a84baf501625`.
2. The authoritative live empirical baseline `TF-EVIDENCE-0006` (Recall: 20.0%, Precision: 50.0%, Latency: 69.780s) was established at commit `fe57597c8fce5d699f764ec4d4dfe3d1e5b5cc73` with status `V2.6_MILESTONE_CLOSED`.
3. The codebase maintained `2.5.1` in `package.json` to prevent accidental premature release before formal supply-chain controls were established.

To transition Triad-Flow into an enterprise-grade, verifiably secure toolchain capable of meeting US Federal Executive Order 14028, NIST SP 800-218 (SSDF v1.1), and OWASP ASVS v5.0.0 standards, this RFC defines the complete supply-chain governance framework.

This RFC operates in concert with:
- **RFC-027-01 (Review Prompt & Context Optimization)**: Defines AST/dataflow context injection, diff chunking, and multi-pass review strategies without altering the frozen `TF-OSS-v1` benchmark.
- **RFC-027-02 (Tri-Party Heterogeneous Quorum Architecture)**: Defines provider profiles, corroboration quorums, blocking authority, and fail-closed degradation truth tables.
- **Milestone Roadmap v2.7 (`docs/roadmap/v2.7-milestone-roadmap.md`)**: Phased execution schedule and acceptance gates.

---

## 3. Problem Statement

Modern software supply chains face severe risks across code authoring, build execution, and distribution. Specifically, Triad-Flow must resolve the following technical and procedural vulnerabilities:

1. **Unprotected Main Branch Vulnerabilities**: Direct pushes, history rewrites (`git push --force`), non-fast-forward merges, unsigned commits, or unreviewed pull requests can introduce unverified or malicious logic directly into the production branch.
2. **Build-Time Privilege Escalation (Runner Abuse)**: CI release workflows that run with write permissions (`contents: write`, `id-token: write`) while checking out arbitrary untrusted tag scripts can be exploited to exfiltrate tokens, compromise release builds, or tamper with binary tarballs.
3. **Milestone Closure vs Software Release Conflation**: If a milestone closure commit is modified to publish a release without strict boundary controls, historical benchmark artifacts (`TF-OSS-v1`, `TF-EVIDENCE-0006`) risk byte-level mutation or invalidation.
4. **Version Drift Across Core Interfaces**: Triad-Flow exports its version across three distinct layers: npm metadata (`package.json`), SARIF 2.1.0 driver metadata (`src/core/harness.mjs`), and review audit telemetry (`src/core/review-run-report.mjs`). If these drift out of lockstep, downstream security analysis tools consume contradictory version claims.
5. **Absence of Cryptographic Provenance**: Downstream consumers of `@arcobaleno64/triad-flow` tarballs cannot verify whether a published tarball was built by an authorized maintainer, on an authorized GitHub Actions runner, from an authorized Git commit reachable from `main`.
6. **Regulatory Compliance Gaps**: Federal procurement and high-assurance deployments require formal compliance with NIST SP 800-218 (SSDF v1.1) and OWASP ASVS v5.0.0. Without explicit, line-by-line mappings to implementing controls, compliance cannot be audited.

---

## 4. Goals

1. **4-Tier Branch Governance Hierarchy**: Codify an unambiguous boundary between GitHub-enforced rulesets, Triad-Flow CI checks, repository policies, and procedural maintainer governance.
2. **Authoritative GitHub Ruleset JSON Specifications**: Provide fully specified, declarative JSON schemas for `main` and `refs/tags/v*` enforcing linear history, required PR reviews, diagonal CI matrix checks, signed commits, and zero admin bypass.
3. **Decoupled Milestone Closure & Release Automation**: Formalize the precise, byte-preserving procedure for the official `v2.6.0` release, while automating the full pipeline for `v2.7.0`.
4. **Hardware-Backed SSH Tag & Commit Signatures**: Mandate OpenSSH digital signatures for all release tags, cryptographically verified against repository-pinned `.github/allowed_signers`.
5. **3-Target Version Lockstep**: Enforce automated synchronization across `package.json`, `src/core/harness.mjs`, and `src/core/review-run-report.mjs` via `scripts/bump-version.mjs`.
6. **9-Way Exhaustive Release Verification Matrix**: Require clean execution across 3 Operating Systems (Ubuntu, Windows, macOS) × 3 Node.js LTS versions (18, 20, 22) prior to artifact generation.
7. **Zero-Checkout Hardened Release Publisher**: Ensure the release job with write and OIDC minting permissions checks out zero code, downloading only pre-verified artifacts from the read-only matrix.
8. **SPDX 2.3 SBOM & SHA-256 Byte-Level Identity**: Generate deterministic SPDX 2.3 SBOMs using native npm tooling without runtime dependencies, accompanied by `triad-flow.spdx.json.sha256`.
9. **SLSA Build Provenance & In-Toto Attestations**: Publish cryptographically signed provenance and SBOM predicate attestations via GitHub OIDC.
10. **Automated Post-Publish Verification (`verify-published`)**: Download released assets from GitHub Releases, verify attestations, execute a fresh clone, run the full test suite, and validate CLI health (`triad-flow doctor`).
11. **Deterministic 3-Stage Rollback & Revocation Protocol**: Define automated and procedural rollback rules for verify, publish, and post-publish failures.
12. **Normative Security Standards Alignment**: Deliver exhaustive, itemized mappings to NIST SP 800-218 (SSDF v1.1) and OWASP ASVS v5.0.0.
13. **Zero Runtime NPM Dependency Contract**: Guarantee that all supply-chain governance, SBOM generation, and release mechanisms require exactly zero runtime npm dependencies.

---

## 5. Non-Goals

1. **No Runtime Dependencies**: This RFC will not add npm packages to `dependencies` in `package.json`. All tooling must rely strictly on the Node.js standard library and native npm capabilities.
2. **No Mutation of Frozen Historical Baselines**: This RFC does not mutate or regenerate `TF-OSS-v1` files, golden CWE labels, corpus digests, or `TF-EVIDENCE-0006` historical evidence.
3. **No Direct Production Code Changes**: As a planning and architecture specification, this RFC defines requirements and contracts without modifying core production source files.
4. **No Direct GitHub Repository Mutation During Planning**: The ruleset JSON schemas and CI configurations are defined herein for maintainer activation upon RFC approval, not applied via API during planning.
5. **No OS-Level Sandboxing Guarantee**: As established in `SECURITY.md`, Triad-Flow executes child CLI reviewer processes with the privileges of the calling user. OS-level containment is out of scope.
6. **No Proprietary Third-Party SAAS Lock-In**: All attestations and signatures rely on open standards (OpenSSH, SPDX 2.3, in-toto, SLSA, GitHub native OIDC).

---

## 6. Terminology

- **GitHub Repository Ruleset**: Modern, declarative GitHub branch and tag governance mechanism replacing legacy branch protection rules. Evaluated at the platform API level.
- **4-Tier Governance Model**: Triad-Flow's architectural classification separating controls across:
  - *Tier 1*: GitHub Platform-Enforced Controls (Ruleset API)
  - *Tier 2*: Triad-Flow CI-Enforced Controls (GitHub Actions)
  - *Tier 3*: Recommended Repository Settings (GitHub Repo Config)
  - *Tier 4*: Procedural Governance (Maintainer Operational Protocols)
- **Fast-Forward Only & Linear History**: Git commit topology prohibiting merge commits on `main`. Enforces either squash-and-merge or rebase-and-merge, maintaining a single linear DAG.
- **Strict Required Status Checks**: CI checks that must pass against the *head* of the pull request branch after it has been synchronized with the latest `main` commit.
- **`.github/allowed_signers`**: The OpenSSH public key file pinned in the repository, containing principal identities (maintainer emails), namespace declarations (`namespaces="git"`), and authorized public keys.
- **Zero-Checkout Publish Job**: A CI job design pattern where the runner is granted elevated credentials (`contents: write`, `id-token: write`) but deliberately executes `actions/checkout` zero times, eliminating the risk of arbitrary script execution from untrusted tags.
- **SLSA Build Provenance**: Verifiable metadata adhering to Supply-chain Levels for Software Artifacts (SLSA) Level 3 build specifications, attesting how, where, and from what source an artifact was compiled.
- **In-Toto Predicate**: An attestation payload schema binding an artifact digest (the subject) to an authoritative statement (such as an SPDX SBOM).
- **SPDX 2.3 SBOM**: System Package Data Exchange version 2.3 machine-readable Software Bill of Materials documenting component dependencies, licenses, and package digests.
- **Byte-Level SHA-256 Identity**: A detached cryptographic hash file (`.sha256`) certifying that an emitted asset (e.g. `triad-flow.spdx.json`) is byte-for-byte identical to the build artifact.
- **Milestone Closure vs Software Release**: The separation of a completed engineering milestone (sealed commit with immutable evidence) from the formal publishing of versioned software release artifacts.
- **Break-Glass Emergency Hotfix**: A dual-custody procedural exception protocol for bypassing standard gates during active, critical security incidents without compromising audit trails.

---

## 7. Threat Model

### 7.1 Threat Actors

| Actor ID | Description | Capabilities | Motivation |
|---|---|---|---|
| **T1: Compromised Contributor** | An authorized developer account whose credentials (SSH, GitHub token) have been exfiltrated. | Can author commits, open pull requests, and trigger PR CI runs. | Inject subtle backdoors, weaken consensus checks, or alter test oracles. |
| **T2: Malicious PR Author** | External untrusted contributor submitting adversarial code or disguised exploits. | Can open PRs from forks, submit modified fixtures or evasion payloads. | Exploit consensus parser vulnerabilities, bypass anti-evasion filters. |
| **T3: Rogue Administrator** | Repository owner or admin attempting to unilaterally bypass security gates or force-push. | Platform admin rights on GitHub. | Speed up deployment, bypass failing checks, or cover up regressions. |
| **T4: Tag Hijacker / Impersonator** | Attacker attempting to create or rewrite `refs/tags/v*` tags to distribute trojaned code. | Push access to git repository or compromised deploy key. | Trick downstream users into downloading malicious releases. |
| **T5: Malicious Build Runner / Script** | Compromised npm postinstall script or malicious workflow step executing in CI. | Access to workflow runner environment, environment variables, and OIDC tokens. | Steal GitHub write tokens, mint fraudulent attestations, tamper with tarball. |
| **T6: Upstream Dependency Poisoner** | Attacker compromising an npm package in the project's dependency tree. | Code execution during `npm install` or runtime. | Remote code execution, credential harvesting, supply chain contagion. |
| **T7: In-Transit Asset Tamperer** | Attacker intercepting download traffic or compromising a mirror CDN. | Ability to modify bytes of downloaded `.tgz` or SBOM files. | Distribute modified binaries to end users. |
| **T8: Historical Evidence Revisionist** | Malicious actor attempting to modify `TF-OSS-v1` corpus or `TF-EVIDENCE-0006` to falsely inflate benchmark scores. | Push access to repository history. | Falsify research claims, hide security review recall deficiencies. |

### 7.2 Trust Boundaries

```
[ Developer Workstation ]
           │
           │  Boundary A: SSH Commit / Tag Signature Verification
           ▼
[ GitHub Repository Remote ]
     │                │
     │ PR Trigger     │ Tag Push
     ▼                ▼
[ Boundary B: PR CI ] [ Boundary C: Release Verify Matrix ]
 (Read-Only Token)      (Read-Only Token, 9 OS/Node Matrix)
                               │
                               │ Upload Verified Artifacts
                               ▼
                      [ Boundary D: Zero-Checkout Publish ]
                       (Write Token, OIDC Attestations, NO git checkout)
                               │
                               │ Push GitHub Release
                               ▼
                      [ Boundary E: Published Distribution ]
                       (Download Assets, Verify-Published Job, Consumer)
```

- **Boundary A (Local Workstation to Git Remote)**: Protects git refs against unsigned or unauthorized commits and tags. Enforced by GitHub Ruleset and OpenSSH signature verification.
- **Boundary B (Untrusted PR to CI Runner)**: Isolates pull requests. Enforces read-only permissions (`contents: read`), prevents secret exfiltration, and requires diagonal matrix execution.
- **Boundary C (Signed Tag to Release Matrix)**: Verifies tag signature against `.github/allowed_signers` and runs exhaustive 9-way test matrix under read-only permissions.
- **Boundary D (Artifact Handoff to Publish Job)**: Eliminates code execution risks. The publish job runs with `contents: write` and `id-token: write` but *never checks out the repository*.
- **Boundary E (Release Assets to Consumers)**: Cryptographic verification of published artifacts via SLSA provenance, SPDX in-toto attestations, and detached SHA-256 checksums.

### 7.3 STRIDE Threat Analysis

| STRIDE Category | Specific Supply-Chain Threat | Mitigating Control & Architectural Enforcement |
|---|---|---|
| **Spoofing** | Attacker impersonates core maintainer to publish fraudulent release tag. | GitHub Ruleset mandates SSH-signed tags; CI step `Assert tag is signed by authorized release key` validates signature against `.github/allowed_signers`. |
| **Tampering** | Malicious script modifies `triad-flow.spdx.json` or npm tarball during release build. | Tarball and SBOM are generated in read-only `verify` job, uploaded as workflow artifacts, and passed to a zero-checkout `publish` job. SHA-256 byte digest is verified in `verify-published`. |
| **Repudiation** | Maintainer denies creating a released version or claims release was unauthorized. | Hardware-backed OpenSSH signatures bind the Git tag to a specific physical key and maintainer email. GitHub OIDC provenance cryptographically records runner identity and workflow SHA. |
| **Information Disclosure** | Fork PR workflow exposes API secrets or maintainer tokens in CI runner logs. | PR CI workflow runs with `contents: read` and zero secrets. Secrets are restricted to manually dispatched benchmark runs and protected environments. |
| **Denial of Service** | Contributor pushes broken code that halts development or merges out-of-date branch. | GitHub Ruleset enforces `strict_required_status_checks_policy: true` and `required_review_thread_resolution: true`. Merges blocked until branch is current with `main`. |
| **Elevation of Privilege** | Repository admin pushes directly to `main` without PR or CI check. | GitHub Ruleset sets `bypass_actors: []` (empty array), enforcing rules on repository administrators (`enforce_admins: true`). |

---

## 8. Architecture

### 8.1 Four-Tier Branch Governance Model

Triad-Flow governs code changes through four distinct, non-overlapping enforcement tiers:

```
┌────────────────────────────────────────────────────────────────────────┐
│ TIER 1: GitHub Platform-Enforced Controls (API & Ruleset Engine)       │
│ - Mandatory Pull Request before merge                                  │
│ - Required Approving Reviews (minimum 1, Code Owners required)         │
│ - Dismissal of stale reviews upon new push                             │
│ - Linear History enforced (Fast-Forward only; rebase/squash merge)     │
│ - Direct push, force-push, and branch deletion strictly blocked        │
│ - Required signed commits (GPG / SSH / S/MIME)                         │
│ - Zero Administrator Bypass (`bypass_actors: []`)                      │
│ - Tag protection ruleset on `refs/tags/v*` (deletion & moving blocked) │
├────────────────────────────────────────────────────────────────────────┤
│ TIER 2: Triad-Flow CI-Enforced Controls (GitHub Actions Workflows)     │
│ - PR CI: Diagonal 3 OS × 3 Node matrix (`ubuntu/18`, `win/20`, `mac/22`)│
│ - Release CI: Full 9-way matrix (Ubuntu, Win, Mac × Node 18, 20, 22)   │
│ - 3-Target Version Lockstep check (`npm run check-version`)            │
│ - SSH Tag Signature verification via `git verify-tag` against signers  │
│ - Main reachability verification via GitHub Compare API                │
│ - Deterministic SPDX 2.3 SBOM generation & SHA-256 byte verification   │
│ - Cryptographic SLSA Provenance & In-Toto SBOM Attestation minting     │
│ - Zero-Checkout Publish Job execution                                  │
│ - Post-release `verify-published` sanity check (clean clone & doctor)  │
├────────────────────────────────────────────────────────────────────────┤
│ TIER 3: Repository Recommended Configuration (GitHub Settings)         │
│ - Default workflow permissions set to `contents: read`                 │
│ - Secret scanning & push protection enabled across all branches        │
│ - Fork PR workflows prohibited from accessing repository secrets       │
│ - GitHub Actions environment protection with required reviewers        │
├────────────────────────────────────────────────────────────────────────┤
│ TIER 4: Procedural Governance (Maintainer Operational Protocols)       │
│ - Milestone Closure vs Software Release Decoupling protocol            │
│ - Permitted release-only commit changes (version bump + notes only)    │
│ - Hardware-backed SSH signing key storage (YubiKey / FIDO2)            │
│ - Deterministic 3-stage failure rollback & revocation protocol         │
│ - Dual-custody break-glass emergency hotfix procedure                  │
│ - Absolute immutability of `TF-OSS-v1` and `TF-EVIDENCE-0006`          │
└────────────────────────────────────────────────────────────────────────┘
```

### 8.2 Cryptographic Tag & Commit Signature Pipeline

All Git commits merged into `main` and all release tags matching `refs/tags/v*` must be cryptographically signed using OpenSSH digital signatures (`ssh-ed25519` or `ecdsa-sha2-nistp256`).

#### Verification Mechanism
1. The repository maintains an authoritative signer list at `.github/allowed_signers`.
2. Each entry defines the maintainer principal (email), namespace (`namespaces="git"`), key type, and base64-encoded public key.
3. During the `verify` job of `.github/workflows/release.yml`, the runner executes:
   ```bash
   git config gpg.format ssh
   git config gpg.ssh.allowedSignersFile .github/allowed_signers
   git verify-tag "$GITHUB_REF_NAME"
   ```
4. If the tag is unsigned, signed with an unrecognized key, or signed for a namespace other than `git`, `git verify-tag` returns a non-zero exit status, halting the release pipeline immediately.

### 8.3 Release Pipeline Architecture (4 Stages)

The release automation workflow (`.github/workflows/release.yml`) operates across four deterministic stages:

```
[ Stage 1: Exhaustive Verification Matrix (9 Jobs) ]
  ├── Ubuntu Latest (Node 18, 20, 22)
  ├── Windows Latest (Node 18, 20, 22)
  └── macOS Latest (Node 18, 20, 22)
  Each job executes:
    - Assert tag matches package.json version
    - Assert tag is on main (via Compare API)
    - Assert tag is signed by authorized release key (.github/allowed_signers)
    - npm test (404 baseline tests)
    - npm run check-version (3-target lockstep)
    - npm pack --dry-run (CRLF and packaging allowlist check)
  Job (Ubuntu, Node 20) additionally executes:
    - npm pack -> *.tgz
    - npm sbom --sbom-format=spdx > triad-flow.spdx.json
    - sha256sum triad-flow.spdx.json > triad-flow.spdx.json.sha256
    - Upload artifacts: package-tarball, package-sbom
         │
         ▼ (Requires all 9 matrix jobs to pass)
[ Stage 2: Zero-Checkout Hardened Publish Job ]
  Permissions: contents: write, id-token: write, attestations: write
  Actions:
    - actions/checkout is EXCLUDED (Zero-Checkout)
    - Download package-tarball and package-sbom artifacts
    - Attest build provenance (*.tgz) via actions/attest-build-provenance
    - Attest SPDX SBOM (*.tgz + triad-flow.spdx.json) via actions/attest
    - Attest SBOM file identity (triad-flow.spdx.json) via actions/attest-build-provenance
    - gh release create with release notes, tarball, SBOM, and SHA-256 digest
         │
         ▼ (Requires release creation to succeed)
[ Stage 3: Independent Post-Publish Verification (`verify-published`) ]
  Permissions: contents: read
  Actions:
    - Download released assets from GitHub Release
    - gh attestation verify *.tgz
    - sha256sum --check triad-flow.spdx.json.sha256
    - gh attestation verify triad-flow.spdx.json
    - gh attestation verify *.tgz --predicate-type https://spdx.dev/Document
    - Fresh git clone of published tag from GitHub into isolated directory
    - Verify clone package.json version matches tag
    - npm test (run full test suite against published tag)
    - node bin/triad-flow.mjs doctor (validate CLI health)
         │
         ▼
[ Stage 4: Release Sealed & Validated ]
```

### 8.4 Version Bump Synchronization Engine

Triad-Flow enforces 3-target lockstep versioning via `scripts/bump-version.mjs`. The three synchronized files are:
1. `package.json`: NPM package manifest (`version: "X.Y.Z"`).
2. `src/core/harness.mjs`: SARIF 2.1.0 telemetry driver block (`tool.driver.version`). Anchored to `/(name: "Triad-Flow Sentry",\s*\n\s*version: ")([^"]*)(")/` to prevent rewriting unrelated strings.
3. `src/core/review-run-report.mjs`: Structured review audit telemetry block (`export const TOOL_VERSION = "X.Y.Z"`).

The version bumper is strictly SemVer compliant (`/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/`). Running `npm run check-version` in CI validates that all three targets agree, failing the build if any discrepancy exists.

---

## 9. Data Schemas

### 9.1 GitHub Ruleset JSON Schema for `main`

The complete, authoritative GitHub Ruleset specification for the `main` branch (conforming to GitHub REST API `POST /repos/{owner}/{repo}/rulesets`):

```json
{
  "name": "Triad-Flow Main Branch Protection Ruleset",
  "target": "branch",
  "enforcement": "active",
  "conditions": {
    "ref_name": {
      "include": [
        "~DEFAULT_BRANCH"
      ],
      "exclude": []
    }
  },
  "rules": [
    {
      "type": "deletion"
    },
    {
      "type": "non_fast_forward"
    },
    {
      "type": "required_linear_history"
    },
    {
      "type": "required_signatures"
    },
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 1,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": true,
        "require_last_push_approval": true,
        "required_review_thread_resolution": true
      }
    },
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": true,
        "required_status_checks": [
          {
            "context": "ci (ubuntu-latest, 18)"
          },
          {
            "context": "ci (windows-latest, 20)"
          },
          {
            "context": "ci (macos-latest, 22)"
          }
        ]
      }
    }
  ],
  "bypass_actors": []
}
```

### 9.2 GitHub Tag Ruleset JSON Schema for `refs/tags/v*`

The complete, authoritative GitHub Ruleset specification for release tags (conforming to GitHub REST API `POST /repos/{owner}/{repo}/rulesets`):

```json
{
  "name": "Triad-Flow Release Tag Protection Ruleset",
  "target": "tag",
  "enforcement": "active",
  "conditions": {
    "ref_name": {
      "include": [
        "refs/tags/v*"
      ],
      "exclude": []
    }
  },
  "rules": [
    {
      "type": "deletion"
    },
    {
      "type": "non_fast_forward"
    },
    {
      "type": "creation"
    }
  ],
  "bypass_actors": []
}
```

*Note on Tag Creation and Bypass Actors*: In accordance with the non-negotiable Default Zero-Bypass Policy, `bypass_actors` defaults strictly to `[]`. Where GitHub Ruleset `creation` prevention requires an explicit repository role exception for authorized release managers, GitHub REST API mandates valid role IDs (`actor_id: 2` for Maintainer, `actor_id: 5` for Admin; `actor_id: 1` is invalid in the GitHub API schema). If an administrative bypass actor is temporarily configured during release automation, it must specify `actor_id: 5` (Admin) or `actor_id: 2` (Maintain), and be immediately revoked post-release per the emergency hotfix / release restoration protocol. All created release tags must additionally pass SSH signature verification against `.github/allowed_signers` in CI.

### 9.3 `.github/allowed_signers` Schema & Specification

The `.github/allowed_signers` file adheres to standard OpenSSH allowed signers syntax (RFC 4253 / `ssh-keygen -Y`):

```text
# Triad-Flow Release Authority Allowed Signers
# Format: <principal> namespaces="git" <keytype> <key>
T11306458@live.yuntech.edu.tw namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHL7akYtHsReAW8BuFRAG6JuH9I9opJLNwlVFLoz1OvM
```

- **Principal**: Email address of authorized release authority.
- **Namespaces**: Strictly limited to `git` to prevent key cross-use for SSH login or host authentication.
- **Key Type**: Must be modern high-assurance type (`ssh-ed25519` or `ecdsa-sha2-nistp256`). RSA keys are deprecated.
- **Public Key**: Base64-encoded public key.

### 9.4 Release Identity Manifest Schema (`release-identity.json`)

To document the formal release binding for audits:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "TriadFlowReleaseIdentity",
  "type": "object",
  "required": [
    "releaseTag",
    "targetCommitSha",
    "version",
    "signerPrincipal",
    "signerKeyType",
    "reachabilityStatus",
    "corpusDigest",
    "matrixJobsCompleted",
    "tarballSha256",
    "sbomSha256"
  ],
  "properties": {
    "releaseTag": { "type": "string", "pattern": "^v(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)$" },
    "targetCommitSha": { "type": "string", "pattern": "^[0-9a-f]{40}$" },
    "version": { "type": "string", "pattern": "^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)$" },
    "signerPrincipal": { "type": "string", "format": "email" },
    "signerKeyType": { "type": "string", "enum": ["ssh-ed25519", "ecdsa-sha2-nistp256"] },
    "reachabilityStatus": { "type": "string", "enum": ["identical", "behind"] },
    "corpusDigest": { "type": "string", "const": "sha256:47ed3ce44878b77572005358a16511e3f0900dda11d14443e6a2a84baf501625" },
    "matrixJobsCompleted": { "type": "integer", "const": 9 },
    "tarballSha256": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
    "sbomSha256": { "type": "string", "pattern": "^[0-9a-f]{64}$" }
  },
  "additionalProperties": false
}
```

### 9.5 SPDX 2.3 SBOM Specification Schema

Generated via `npm sbom --sbom-format=spdx`. The emitted `triad-flow.spdx.json` adheres to the SPDX 2.3 specification:

```json
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "@arcobaleno64/triad-flow",
  "documentNamespace": "http://spdx.org/spdxdocs/@arcobaleno64/triad-flow-2.7.0",
  "creationInfo": {
    "creators": ["Tool: npm/sbom"],
    "created": "2026-10-01T00:00:00Z"
  },
  "packages": [
    {
      "name": "@arcobaleno64/triad-flow",
      "SPDXID": "SPDXRef-Package-arcobaleno64-triad-flow",
      "versionInfo": "2.7.0",
      "downloadLocation": "git+https://github.com/arcobaleno64/triad-flow.git",
      "filesAnalyzed": false,
      "licenseDeclared": "Apache-2.0",
      "licenseConcluded": "Apache-2.0"
    }
  ],
  "relationships": []
}
```

*Note*: Because Triad-Flow maintains zero runtime dependencies, the packages array contains exclusively the root package, guaranteeing zero third-party vulnerability inheritance.

### 9.6 SHA-256 Digest File Schema (`triad-flow.spdx.json.sha256`)

Adheres strictly to coreutils `sha256sum` output format:
```text
<64-character-hex-digest>  triad-flow.spdx.json
```
Verified via `sha256sum --check triad-flow.spdx.json.sha256`.

### 9.7 SLSA Provenance Predicate Schema

Minted via GitHub OIDC (`actions/attest-build-provenance`). The in-toto statement binds the published tarball to the build environment:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "arcobaleno64-triad-flow-2.7.0.tgz",
      "digest": {
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      }
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://actions.github.com/buildtypes/runner/v1",
      "externalParameters": {
        "workflow": {
          "ref": "refs/tags/v2.7.0",
          "repository": "https://github.com/arcobaleno64/triad-flow",
          "path": ".github/workflows/release.yml"
        }
      },
      "internalParameters": {
        "github": {
          "event_name": "push",
          "repository_id": "800000000",
          "run_id": "1234567890"
        }
      }
    },
    "runDetails": {
      "builder": {
        "id": "https://github.com/actions/runner"
      }
    }
  }
}
```

---

## 10. CLI / Configuration Contract

### 10.1 `scripts/bump-version.mjs`

```text
Usage:
  node scripts/bump-version.mjs <version>
  node scripts/bump-version.mjs --check [version]

Options:
  --check        Verify every target already agrees. Uses package.json when version is omitted.
  --root <dir>   Run against a different repository root (useful for integration tests).
  --help         Print usage help.

Exit Codes:
  0: Success (all targets updated or all targets verified in lockstep).
  1: Discrepancy detected (one or more targets do not match expected version).
  2: Semantic version syntax error or invalid CLI arguments.
```

### 10.2 CI Workflow Contracts

#### PR CI (`.github/workflows/pull-request-ci.yml`)
- **Trigger**: Pull request targeting `main` or direct push to `main`.
- **Permissions**: `contents: read` strictly.
- **Diagonal Matrix**:
  - `ubuntu-latest` with Node.js `18`
  - `windows-latest` with Node.js `20`
  - `macos-latest` with Node.js `22`
- **Execution**:
  - `npm test`
  - `npm run check-version`
  - `npm pack --dry-run`

#### Release CI (`.github/workflows/release.yml`)
- **Trigger**: Push to `refs/tags/v*`.
- **Permissions Strategy**:
  - Top-level: `contents: read`
  - `verify` job: `contents: read`
  - `publish` job: `contents: write`, `id-token: write`, `attestations: write` (Zero Checkout)
  - `verify-published` job: `contents: read`

### 10.3 CLI Post-Publish Health Contract (`triad-flow doctor`)

Upon fresh installation in `verify-published`, `bin/triad-flow.mjs doctor` must execute with exit code 0:
```bash
node bin/triad-flow.mjs doctor
```
Contract:
- Reports clean Node runtime version (`>=18.0.0`).
- Validates git executable availability.
- Confirms zero dependency installation integrity.
- Confirms default consensus rules engine initialized.

---

## 11. State / Transition Model

### 11.1 Milestone Closure Preservation vs Release Transition

```
┌────────────────────────────────────────────────────────┐
│ Current State: V2.6_MILESTONE_CLOSED                   │
│ - Canonical Commit: fe57597c8fce5d699f764ec4d4dfe3d1e5b│
│ - Package Version: 2.5.1                               │
│ - Corpus Digest: sha256:47ed3ce448... (Frozen)         │
│ - Evidence: TF-EVIDENCE-0006 (Frozen)                  │
└──────────────────────────┬─────────────────────────────┘
                           │
                           │ Step 1: Version-Bump Commit
                           │ (node scripts/bump-version.mjs 2.6.0)
                           │ ONLY package.json, harness.mjs,
                           │ and review-run-report.mjs modified
                           ▼
┌────────────────────────────────────────────────────────┐
│ State: RELEASE_CANDIDATE_COMMITTED                     │
│ - Merged to main via signed commit & PR                │
│ - All 3 targets report 2.6.0                           │
│ - TF-OSS-v1 & TF-EVIDENCE-0006 100% UNTOUCHED          │
└──────────────────────────┬─────────────────────────────┘
                           │
                           │ Step 2: Annotated SSH Tag Creation
                           │ git tag -s -u <principal> v2.6.0 -m "..."
                           │ git push origin v2.6.0
                           ▼
┌────────────────────────────────────────────────────────┐
│ State: RELEASE_VERIFYING (GitHub Actions)              │
│ - Tag matches package.json version                     │
│ - Tag on main branch                                   │
│ - SSH signature verified against allowed_signers       │
│ - 9-way matrix tests pass (404 tests)                  │
│ - SBOM & SHA-256 generated                             │
└──────────────────────────┬─────────────────────────────┘
                           │
                           │ Step 3: Zero-Checkout Publish
                           │ Attestations minted via OIDC
                           │ Assets attached to GitHub Release
                           ▼
┌────────────────────────────────────────────────────────┐
│ State: RELEASE_PUBLISHED                               │
│ - Release assets live on GitHub                        │
└──────────────────────────┬─────────────────────────────┘
                           │
                           │ Step 4: Verify-Published Job
                           │ Attestation verification + Fresh clone test
                           ▼
┌────────────────────────────────────────────────────────┐
│ Final State: RELEASE_SEALED (Immutable Software Release)│
└────────────────────────────────────────────────────────┘
```

### 11.2 Release Execution State Machine

```
              ┌─────────────────────┐
              │  TAG_PUSH_RECEIVED  │
              └──────────┬──────────┘
                         │
                         ▼
              ┌─────────────────────┐
         ┌───►│ VERIFY_IN_PROGRESS  │
         │    └──────────┬──────────┘
         │               │
         │       ┌───────┴───────┐
         │       │               │
         │       ▼ Pass          ▼ Fail
         │ ┌───────────┐   ┌────────────────┐
         │ │ VERIFIED  │   │ VERIFY_FAILED  │──► [HALT: Release Aborted, No Artifacts]
         │ └─────┬─────┘   └────────────────┘
         │       │
         │       ▼
         │ ┌───────────┐
         │ │ PUBLISH   │
         │ └─────┬─────┘
         │       │
         │   ┌───┴───┐
         │   │       │
         │   ▼ Pass  ▼ Fail
         │ ┌───────────┐   ┌────────────────┐
         │ │ PUBLISHED │   │ PUBLISH_FAILED │──► [HALT: Inspect Draft, Revoke Release]
         │ └─────┬─────┘   └────────────────┘
         │       │
         │       ▼
         │ ┌───────────────────┐
         │ │ VERIFY_PUBLISHED  │
         │ └─────────┬─────────┘
         │           │
         │       ┌───┴───┐
         │       │       │
         │       ▼ Pass  ▼ Fail
         │ ┌───────────┐   ┌───────────────────────┐
         │ │  SEALED   │   │ POST_VERIFY_FAILED    │
         │ └─────────┬─┘   └───────────┬───────────┘
         │           │                 │
         │           │                 ▼
         │           │     ┌───────────────────────┐
         │           │     │    RELEASE_REVOKED    │
         │           │     │ (Mark Pre-Release,    │
         │           │     │  Delete Tarball,      │
         │           │     │  Author Patch PR)     │
         └───────────┴─────┴───────────────────────┘
```

---

## 12. Failure Modes

| ID | Failure Mode | Trigger Condition | Detection Point | Automated Impact | Recovery / Remediation |
|---|---|---|---|---|---|
| **F1** | **Tag / Version Mismatch** | Git tag `v2.6.0` pushed but `package.json` contains `2.5.1`. | Step `Assert tag matches package.json version` (`release.yml:25-33`). | Workflow exits with status 1; pipeline terminates immediately. | Run `npm run bump-version 2.6.0`, commit to `main`, re-tag. |
| **F2** | **Diverged / Off-Main Tag** | Tag created on local experimental or topic branch not merged to `main`. | Step `Assert the tag is on main` (`release.yml:34-46`) via Compare API. | Compare status is `ahead` or `diverged`; workflow exits with status 1. | Merge topic branch to `main` through PR, push tag pointing to `main` commit. |
| **F3** | **Unsigned / Untrusted Tag** | Tag created without `-s` or signed with SSH key absent from `.github/allowed_signers`. | Step `Assert tag is signed by authorized release key` (`release.yml:47-55`). | `git verify-tag` exits non-zero; workflow terminates immediately. | Tag must be deleted and recreated using authorized hardware-backed SSH key. |
| **F4** | **Matrix Test Failure** | Flaky or failing test on Windows/macOS or Node 18/20/22. | Step `npm test` across any of the 9 matrix jobs. | That matrix job fails; `needs: verify` blocks `publish` job execution. | Fix test failure in PR to `main`, merge, create new release tag. |
| **F5** | **Version Target Drift** | `package.json` was updated but `harness.mjs` or `review-run-report.mjs` was omitted. | Step `npm run check-version` (`release.yml:57`). | `scripts/bump-version.mjs` exits with code 1; workflow terminates. | Run `npm run bump-version <version>` to bring all 3 targets into lockstep. |
| **F6** | **CRLF Shebang / Packaging Leak** | File checked in with Windows `CRLF` line endings or dirty file outside `files` array. | Step `npm pack --dry-run` (`release.yml:58`). | Packaging check fails; workflow terminates before artifact generation. | Convert file to `LF` line endings, check `.gitattributes`, verify `package.json` `files`. |
| **F7** | **Attestation Minting Failure** | GitHub OIDC service degradation or timeout during provenance signing. | Step `Attest build provenance` in `publish` job. | Action fails; release is not created. | Retrigger the release workflow once GitHub OIDC service recovers. |
| **F8** | **Post-Publish Sanity Failure** | Published package fails `doctor` check or `npm test` after clean clone. | Step `verify-published` job. | Workflow marks run as failed, triggers maintainer notification. | Execute deterministic 3-stage failure and revocation protocol (Section 17). |
| **F9** | **Corpus / Baseline Tampering** | Single byte modified in `TF-OSS-v1` or `TF-EVIDENCE-0006`. | Matrix test `tests/real-oss-corpus.test.mjs`. | Digest assertion fails: `Cryptographic pin fails closed`; release halted. | Revert tampering immediately; restore authoritative baseline files. |
| **F10** | **Emergency Hotfix Under Active Attack** | Zero-day CVE requires emergency fix while normal 2-reviewer quorum unavailable. | PR creation against `main`. | Normal PR review blocks merge. | Execute Dual-Custody Break-Glass Protocol (Section 17.2). |

---

## 13. Fail-Closed Semantics

Triad-Flow’s supply-chain architecture enforces strict default-deny (fail-closed) semantics across every gate:

1. **Tag Signature Fail-Closed**: In `release.yml`, `git verify-tag` executes under `set -e`. If `.github/allowed_signers` is missing, corrupted, or does not contain the key matching the tag signature, git exits non-zero and the entire pipeline terminates. Zero artifacts are compiled.
2. **Main Reachability Fail-Closed**: If the GitHub compare API returns any status other than `identical` or `behind` (e.g. `diverged`, `ahead`, `unknown`, or an API HTTP error), the workflow executes `exit 1`. Untrusted branches cannot trigger release publishing.
3. **Matrix Exhaustion Fail-Closed**: The `publish` job specifies `needs: verify`. In GitHub Actions, if any single job in a matrix of 9 fails, the downstream dependent job is skipped by default. A publish action can never execute if any supported OS or Node version fails.
4. **Zero-Checkout Defense-in-Depth**: Even if an unauthorized tag bypassed git verification, the `publish` job checks out *no repository code*. The runner executes only GitHub-authored, SHA-pinned actions (`actions/download-artifact`, `actions/attest`, `gh release create`), eliminating arbitrary code execution vectors.
5. **Post-Publish Verification Fail-Closed**: The `verify-published` job independently downloads the released assets from the public release API and validates signatures using the GitHub public transparency log. If any attestation or test fails, the release is immediately flagged for revocation.

---

## 14. Security Considerations

### 14.1 Principle of Least Privilege in CI
- All workflows set global permissions to `contents: read`.
- No workflow uses `permissions: write-all`.
- The `publish` job requests only:
  - `contents: write` (to upload release assets and release notes)
  - `id-token: write` (to mint short-lived OIDC token for SLSA attestations)
  - `attestations: write` (to write attestations to GitHub attestation storage)
- No long-lived GitHub personal access tokens (PATs) or deploy keys are stored in repository secrets.

### 14.2 Separation of Duties
- **Code Author**: Authors PR changes, signs Git commits.
- **Code Reviewer / Code Owner**: Reviews PR, validates security requirements, approves PR merge.
- **Release Authority**: Possesses authorized hardware-backed SSH key matching `.github/allowed_signers`, creates and signs Git tag.
- **Automated Runner**: Executes isolated tests, generates SBOM, mints OIDC attestations, creates release.

### 14.3 Hardware-Backed SSH Signing Key Hygiene
Maintainers authorized in `.github/allowed_signers` must generate and store their signing keys on hardware security modules (YubiKey 5 Series or FIDO2 tokens) using resident keys (`ssh-keygen -t ed25519-sk`). Private keys cannot be exfiltrated from the physical token.

### 14.4 Supply-Chain Surface Minimization
Triad-Flow maintains zero runtime npm dependencies. This provides absolute immunity against:
- Malicious npm package updates (dependency confusion, typosquatting).
- Transitive dependency vulnerabilities.
- Compromised upstream maintainer accounts in the npm registry ecosystem.

---

## 15. Compatibility

1. **Git Compatibility**: OpenSSH signing is natively supported in Git `>= 2.34.0`. Compatible with all modern Linux distributions, Windows Git Bash, and macOS Xcode command-line tools.
2. **Node.js LTS Compatibility**: Fully compatible with Node.js `18.x`, `20.x`, and `22.x` across Linux, Windows, and macOS.
3. **SPDX Specification Compatibility**: Emitted SBOMs adhere to SPDX 2.3 JSON specification, fully ingestable by dependency-track, Trivy, Grype, and GitHub Dependency Graph.
4. **SARIF Compatibility**: SARIF output generated by `src/core/harness.mjs` retains strict compliance with SARIF 2.1.0 §3.19.3, correctly referencing the synchronized tool version.

---

## 16. Migration Plan

### Phase 1: Ruleset Configuration & Key Registration (Day 1)
1. Commit `.github/allowed_signers` with core maintainer SSH public keys.
2. Establish GitHub Ruleset on `main` following Section 9.1 schema.
3. Establish GitHub Tag Ruleset on `refs/tags/v*` following Section 9.2 schema.
4. Verify PR CI workflow status check contexts (`ci (ubuntu-latest, 18)`, `ci (windows-latest, 20)`, `ci (macos-latest, 22)`).

### Phase 2: Formal v2.6.0 Milestone Closure Release (Day 2)
1. Verify repository is on canonical commit `fe57597c8fce5d699f764ec4d4dfe3d1e5b5cc73`.
2. Confirm `TF-OSS-v1` digest is `sha256:47ed3ce44878b77572005358a16511e3f0900dda11d14443e6a2a84baf501625`.
3. Confirm `TF-EVIDENCE-0006` directory is unmodified.
4. Execute `node scripts/bump-version.mjs 2.6.0`.
5. Create release PR with commit `chore(release): formal v2.6.0 software release`.
6. Merge PR to `main` via linear rebase/squash after all status checks pass.
7. Create annotated SSH tag:
   ```bash
   git tag -s -u T11306458@live.yuntech.edu.tw v2.6.0 -m "Release v2.6.0: Real-World OSS Corpus v1 & Live Provider Baseline"
   git push origin v2.6.0
   ```
8. Observe automated release workflow execution, attestation minting, and `verify-published` sanity check.

### Phase 3: v2.7 Development Under Ruleset Governance (Ongoing)
1. All v2.7 work (RFC-027-01 and RFC-027-02) proceeds under active ruleset enforcement.
2. Direct pushes to `main` prohibited. All contributions require signed commits and PR reviews.

### Phase 4: v2.7.0 Release Automation Execution (Milestone Completion)
1. Execute live empirical benchmark run `TF-EVIDENCE-0007` against frozen `TF-OSS-v1`.
2. Run `node scripts/bump-version.mjs 2.7.0`.
3. Open release PR, verify status checks, merge to `main`.
4. Sign and push `v2.7.0` tag. Full automated pipeline builds, attests, publishes, and verifies `v2.7.0`.

---

## 17. Rollback Plan

### 17.1 Deterministic 3-Stage Release Failure & Revocation Protocol

If any release execution fails, maintainers must adhere to the corresponding recovery protocol based on the stage of failure:

#### Stage 1 Failure: During `verify` Job
- **Symptom**: Test failure, signature failure, main reachability failure, or version check failure.
- **State**: No release exists; no assets have been published.
- **Protocol**:
  1. Delete the local Git tag: `git tag -d vX.Y.Z`.
  2. If the tag was pushed to GitHub, delete the remote tag: `git push origin --delete vX.Y.Z`.
  3. Fix the underlying issue on a feature branch, open a PR to `main`.
  4. Once merged, create and push the tag again.

#### Stage 2 Failure: During `publish` Job
- **Symptom**: OIDC timeout, attestation failure, or GitHub Releases API failure.
- **State**: Matrix tests passed, but GitHub release may exist in a partial or draft state.
- **Protocol**:
  1. Inspect the GitHub Release page. If a draft release exists, delete the draft release.
  2. Do NOT distribute the tarball assets.
  3. Re-run the failed GitHub Actions workflow from the GitHub UI (`Re-run failed jobs`).
  4. If failure persists due to GitHub infrastructure outage, wait for service restoration and re-run.

#### Stage 3 Failure: During `verify-published` Job
- **Symptom**: Post-publish verification fails (attestation verify mismatch, checksum mismatch, fresh clone test failure, or `doctor` error).
- **State**: The release is publicly visible and downloadable on GitHub Releases.
- **Protocol**:
  1. **Immediate Revocation**: Edit the GitHub Release via CLI immediately:
     ```bash
     gh release edit vX.Y.Z --prerelease --title "[REVOKED] vX.Y.Z" --notes "CRITICAL: This release failed post-publication verification and has been revoked. Do NOT install."
     ```
  2. **Asset Deletion**: Delete the downloadable binary tarball (`*.tgz`) from the release assets:
     ```bash
     gh release delete-asset vX.Y.Z "*.tgz" --yes
     ```
  3. **History Invariant**: Do NOT rewrite `main` git history. Do NOT force-push or rebase `main`.
  4. **Emergency Patch**: Immediately author an emergency patch PR fixing the failure, bumping the version to `vX.Y.(Z+1)` via `npm run bump-version`, and execute the full release pipeline.

### 17.2 Dual-Custody Break-Glass Emergency Hotfix Protocol

In the event of an active, catastrophic security vulnerability (e.g. zero-day vulnerability in Triad-Flow CLI) where emergency remediation must be deployed immediately:

1. **Invocation Criteria**: Requires mutual consent of at least two designated project maintainers.
2. **Temporary Ruleset Modification**: An authorized repository administrator temporarily adds an emergency bypass actor to the GitHub Ruleset.
3. **Audit Trail Logging**:
   - The administrator must file an emergency GitHub Security Advisory documenting the incident.
   - All commits pushed during the bypass must be cryptographically signed with the administrator's hardware SSH key.
4. **Immediate Ruleset Restoration**: The bypass actor must be removed from the ruleset immediately upon merging the fix (`bypass_actors: []`).
5. **Post-Mortem**: A mandatory public post-mortem and audit receipt must be published within 48 hours.

---

## 18. Test Contracts

The following automated test contracts (implemented in `tests/supply-chain.test.mjs` and related test suites) continuously enforce this specification:

- **Contract 1: `.github/allowed_signers` Integrity**:
  - Validates `.github/allowed_signers` exists.
  - Asserts that all lines contain valid email principals, `namespaces="git"`, and valid SSH public keys (`ssh-ed25519` or `ecdsa-`).
- **Contract 2: Release Workflow Step Compliance**:
  - Validates `.github/workflows/release.yml` contains `allowedSignersFile`.
  - Asserts execution of `git verify-tag`.
  - Asserts generation of SPDX SBOM (`--sbom-format=spdx`), checksum generation (`sha256sum`), and OIDC attestations (`actions/attest-build-provenance`, `actions/attest`).
- **Contract 3: SPDX 2.3 SBOM Schema Validity**:
  - Executes `npm sbom --sbom-format=spdx` in a child process.
  - Asserts output is valid JSON matching `spdxVersion: "SPDX-2.3"`.
  - Asserts root package name matches `package.json` (`@arcobaleno64/triad-flow`).
  - Asserts version matches `package.json` version.
- **Contract 4: Rejection of Unsigned or Untrusted Tags**:
  - Creates a temporary git repository, commits a file, and creates an unsigned tag (`git tag -a v-unsigned -m "unsigned"`).
  - Executes `git verify-tag` configured with `.github/allowed_signers`.
  - Asserts `git verify-tag` exits non-zero with error message `no signature found`.
- **Contract 5: 3-Target Version Lockstep**:
  - Executes `node scripts/bump-version.mjs --check`.
  - Asserts zero drift between `package.json`, `src/core/harness.mjs`, and `src/core/review-run-report.mjs`.
- **Contract 6: Main Reachability Verification**:
  - Mock test verifying that tags not pointing to descendants or ancestors of `main` are rejected with `is not reachable from main`.
- **Contract 7: Package Allowlist & CRLF Prevention**:
  - Executes `npm pack --dry-run`.
  - Verifies that only allowed files (`bin`, `src`, `scripts`, `tests/fixtures`, docs) are packaged.
  - Asserts zero carriage returns (`\r\n`) in shebang lines of executable binaries (`bin/triad-flow.mjs`).

---

## 19. Evidence & Audit Requirements

Every official Triad-Flow release produces an immutable, machine-verifiable audit trail:

1. **Git Tag Signature Object**: Stored permanently in the Git repository database, containing the signed payload, timestamp, and SSH signature block.
2. **GitHub Actions Workflow Log**: Complete, append-only build execution log retained in GitHub Actions for at least 90 days.
3. **Cryptographic Attestations (GitHub Transparency Log)**:
   - Build Provenance Attestation (SLSA v1.0).
   - In-Toto SBOM Predicate Attestation binding tarball SHA-256 to `triad-flow.spdx.json`.
   - SBOM File Identity Attestation binding `triad-flow.spdx.json` to the build run.
4. **Detached SHA-256 Digest**: `triad-flow.spdx.json.sha256` published alongside the release assets.
5. **Frozen Benchmark Protection Receipts**: Confirmation that `tests/real-oss-corpus.test.mjs` passed during the release run, guaranteeing that `TF-OSS-v1` remained byte-for-byte identical to `sha256:47ed3ce44878b77572005358a16511e3f0900dda11d14443e6a2a84baf501625`.

---

## 20. Acceptance Criteria

- [ ] GitHub Ruleset JSON for `main` is completely specified with required PR, code owner review, strict diagonal checks, linear history, signed commits, and zero admin bypass.
- [ ] GitHub Tag Ruleset JSON for `refs/tags/v*` is completely specified to block deletion, modification, and unprivileged creation.
- [ ] Decoupling of formal `v2.6.0` release from `v2.7.0` automation is explicitly codified.
- [ ] `v2.6.0` release procedure guarantees zero mutation to `TF-OSS-v1` and `TF-EVIDENCE-0006`.
- [ ] SSH tag signature verification against `.github/allowed_signers` is fully specified and covered by contract tests.
- [ ] 3-target version synchronization across `package.json`, `src/core/harness.mjs`, and `src/core/review-run-report.mjs` is enforced by `scripts/bump-version.mjs`.
- [ ] 9-way exhaustive release matrix (Ubuntu, Windows, macOS × Node 18, 20, 22) is specified in `.github/workflows/release.yml`.
- [ ] Publish job enforces zero git checkout (`actions/checkout` omitted) while using elevated write permissions.
- [ ] Deterministic SPDX 2.3 SBOM and SHA-256 checksum generation is specified.
- [ ] SLSA build provenance, in-toto SBOM predicate, and independent SBOM file attestations are specified.
- [ ] Post-publish verification (`verify-published`) fresh clone, test suite execution, and `triad-flow doctor` check are specified.
- [ ] Deterministic 3-stage failure rollback & revocation protocol is specified.
- [ ] Normative mappings to NIST SP 800-218 (SSDF v1.1) across all four practice groups (PO, PS, PW, RV) are complete with exact implementing artifacts.
- [ ] Normative mappings to OWASP ASVS v5.0.0 are complete with exact implementing artifacts.
- [ ] NIST SP 800-218 Rev.1 / SSDF v1.2 draft concepts are explicitly labeled as non-normative draft guidance.
- [ ] Zero runtime npm dependency contract is strictly maintained.

---

## 21. Open Questions & Future Considerations

### 21.1 Open Questions

1. **NPM Registry Publishing vs GitHub Releases**:
   - *Question*: Should the release pipeline automatically publish `@arcobaleno64/triad-flow` to the public npm registry via npm provenance (OIDC), or remain distributed exclusively via GitHub Releases and direct Git tags?
   - *Recommendation*: Maintain GitHub Releases as the primary authoritative distribution point in v2.7.0. If npm publishing is activated, it must run as a subsequent zero-checkout step in `publish` using npm 2FA with provenance (`npm publish --provenance --access public`).

2. **Hardware Key Multi-Signer Thresholds**:
   - *Question*: Should future major versions require multi-party threshold signatures (e.g. 2-of-3 maintainer signatures) on release tags?
   - *Analysis*: Git currently supports only single-signature verification per tag object via `git verify-tag`. Multi-signature verification would require custom tooling or in-toto link attestations. Deferred to v3.0 planning.

### 21.2 Normative Security Framework Mapping Tables

#### Normative NIST SP 800-218 (SSDF v1.1) Mapping Matrix

| Practice Group | Task ID | SSDF Task Description | Triad-Flow Control & Implementing Artifact |
|---|---|---|---|
| **Prepare the Organization (PO)** | **PO.1.1** | Identify and document all security requirements for organization's software development. | `SECURITY.md`, `docs/AUDITABLE-RECEIPT-SPEC.md`, `docs/CONTROLLED-REMEDIATION-SPEC.md`, `ORIGINAL_REQUEST.md` (Fail-closed gates, Zero-dependency contract, Monotonic defense). |
| | **PO.1.2** | Implement security requirements throughout the SDLC. | PR CI status checks in `.github/workflows/pull-request-ci.yml`, automated pre/post-commit test runs, release verification in `release.yml`. |
| | **PO.1.3** | Maintain and update security requirements. | Architectural RFC process (`RFC-027-01`, `02`, `03`), SemVer release governance, immutable milestone baselines. |
| | **PO.2.1** | Implement roles and responsibilities. | `.github/allowed_signers` (designated release authorities), strict role separation: Producer (`agy`), Verifier (`claude`), Quorum (`loop.mjs`). |
| | **PO.3.1** | Specify, select, configure, and maintain development tools. | Zero-runtime-dependency architecture; pinned Node.js engines `>=18.0.0` in `package.json:58-60`; native Node test runner (`node:test`, `node:assert`). |
| | **PO.3.2** | Manage toolchain security. | Pinned GitHub Actions commit SHAs (`actions/checkout@de0fac2...`, `actions/setup-node@53b839...`); zero npm lockfile vulnerability vector. |
| | **PO.4.1** | Define criteria for software security checks. | `evaluateGateDecision` (`src/core/harness.mjs:261`): returns `block` on critical/high findings, unreached quorum, untrusted consensus, or uncorroborated single sentry. |
| | **PO.4.2** | Implement software security check criteria. | 404 automated tests; AST semantic checks in `src/core/anti-evasion-guard.mjs`; consensus semantics validation in `src/core/consensus-state.mjs`. |
| | **PO.5.1** | Protect development environments. | PR CI runs with least privilege (`contents: read`); Patch Jail disposable worktree isolation (`WorktreeDriver`); Container sandbox isolation (`ContainerDriver` with `--network=none`). |
| | **PO.5.2** | Enforce access control and least privilege. | GitHub Actions permissions scoping: `publish` job is the only job with `contents: write`, and checks out zero code. |
| **Protect the Software (PS)** | **PS.1.1** | Store all code in version control with integrity and access controls. | GitHub Ruleset on `main`: linear history, force-push blocked, branch deletion blocked, mandatory PR reviews, required signed commits. |
| | **PS.2.1** | Provide a mechanism for verifying software release integrity. | Annotated SSH tag signing verified via `git verify-tag` against `.github/allowed_signers`; SPDX 2.3 SBOM (`triad-flow.spdx.json`); SHA-256 digests; SLSA build provenance attestations (`actions/attest-build-provenance`). |
| | **PS.3.1** | Archive and protect each software release. | Immutable GitHub Releases; immutable tag protection ruleset (`refs/tags/v*`); offline cryptographic evidence bundles (`evidence-runs/TF-EVIDENCE-0006/`). |
| **Produce Well-Secured Software (PW)** | **PW.1.1** | Design software to meet security requirements (threat modeling). | `SECURITY.md` Sections 1 & 2 (Trust model, fail-closed boundaries, OS sandbox boundaries, anti-evasion threat model); RFC-027-03 Section 7. |
| | **PW.1.2** | Design software architecture to mitigate risks. | Tri-party heterogeneous quorum (`agy`, `claude`, `codex`); monotonic defense; patch jail confinement. |
| | **PW.2.1** | Review software design for security. | RFC peer review process; multi-agent independent verification with disagreement ledger recording (`src/core/independent-verifier.mjs`). |
| | **PW.4.1** | Reuse existing, well-secured software when feasible. | Zero runtime npm dependencies; zero untrusted third-party packages; pure Node.js standard library primitives (`node:crypto`, `node:fs`, `node:child_process`). |
| | **PW.5.1** | Adhere to secure coding practices. | Explicit test coverage against Prototype Pollution (`TF-OSS-001`, `002`, `003`), ReDoS (`TF-OSS-004`), and Code Injection (`TF-OSS-005`); path traversal prevention in `manifest-bundle.mjs`. |
| | **PW.6.1** | Configure compilation, interpreter, and build processes. | Native Node.js ESM execution; `npm pack --dry-run` validating CRLF shebang and package file allowlist; strict tarball boundary. |
| | **PW.7.1** | Review human-readable code to identify vulnerabilities. | Automated multi-model consensus review engine (`bin/triad-flow.mjs review`); structured evidence prompts; independent verifier passes. |
| | **PW.7.2** | Perform SAST / semantic analysis. | `ExternalAstAdapter` and `anti-evasion-guard.mjs` checking constant branch bypasses, empty catch blocks, and weakened security calls. |
| | **PW.8.1** | Test executable code to identify vulnerabilities and verify compliance. | Automated 404-test baseline across 37 test suites; 3 OS × 3 Node test matrix; reproducible `TF-OSS-v1` real-world benchmark harness. |
| | **PW.9.1** | Configure software to have secure settings by default. | Default-deny / fail-closed gate policy (`evaluateGateDecision` defaults to `block` on any anomaly, zero bypass flags for security gate). |
| **Respond to Vulnerabilities (RV)** | **RV.1.1** | Identify and confirm vulnerabilities on an ongoing basis. | Vulnerability reporting via GitHub Security Advisories (`SECURITY.md:59`); weekly automated matrix verification (`nightly.yml`); real-world benchmark replay. |
| | **RV.2.1** | Assess, prioritize, and remediate vulnerabilities. | Controlled Remediation Engine (`CONTROLLED-REMEDIATION-SPEC.md`: 9-state lifecycle machine, Patch Jail worktree containment, verifiable patch diffs). |
| | **RV.2.2** | Track remediation progress and prevent regressions. | Monotonic defense invariant; pre/post patch test oracles; `REOPENED` state detection upon test regression. |
| | **RV.3.1** | Analyze vulnerabilities to identify root causes. | CWE taxonomy classification; CVE/GHSA advisory mapping; structured disagreement tracking via Disagreement Ledger (`disagreement-ledger.json`). |

#### Normative OWASP ASVS v5.0.0 Mapping Matrix

| ASVS Chapter / Section | ASVS Requirement Description | Triad-Flow Control & Implementing Artifact |
|---|---|---|
| **V1.14 Build & Deployment** | **V1.14.1**: Verify that the build pipeline is hardened, access-controlled, and audited. | `.github/workflows/pull-request-ci.yml` and `release.yml` with least privilege permissions (`contents: read`); zero checkout in write-enabled `publish` job. |
| | **V1.14.2**: Verify that an SBOM is generated in a machine-readable format (e.g. SPDX 2.3). | `npm run sbom:generate` emits `triad-flow.spdx.json` (SPDX 2.3 format), verified by `sha256sum --check` and `tests/supply-chain.test.mjs`. |
| | **V1.14.3**: Verify that build and release artifacts are cryptographically attested. | GitHub Attestations: `actions/attest-build-provenance` on `*.tgz`, `actions/attest` with SPDX SBOM predicate, and independent SBOM file attestation. |
| **V4.1 / V4.3 Access Control** | **V4.1.1 / V4.3.1**: Enforce access control and principle of least privilege on releases. | GitHub Ruleset on `main`; SSH-signed Git tag verification against `.github/allowed_signers` prevents unauthorized release creation. |
| **V5.1 Input Validation** | **V5.1.1**: Treat external CLI outputs and untrusted data under review with strict validation. | `validateConsensusSemantics`, `validateVerificationRecord`, `validateArtifactManifest`, `validateSarifStructure`; strict schema fail-closed parsers. |
| **V5.5 Deserialization & Object Security** | **V5.5.1**: Protect against object injection and prototype pollution (CWE-1321). | Pinned regression cases in `TF-OSS-001`, `TF-OSS-002`, `TF-OSS-003`; input sanitization in argument parsing and configuration loaders. |
| **V8.2 Cryptographic Integrity** | **V8.2.1**: Use approved cryptographic hashing algorithms with canonical serialization. | `src/core/canonical-digest.mjs`: SHA-256 with LF line normalization, UTF-8 encoding without BOM, and lexicographically sorted JSON keys. |
| | **V8.2.2**: Verify digital signatures on release tags and commits. | SSH ED25519 signatures verified via `git verify-tag` against `.github/allowed_signers` (`tests/supply-chain.test.mjs:76-100`). |
| **V10.1 Code Integrity** | **V10.1.1**: Protect source code in repository against tampering and unauthorized changes. | GitHub Ruleset: linear history, signed commits, pull requests required, force-push blocked, branch deletion blocked. |
| | **V10.1.2**: Verify release packages match source code and pass post-install verification. | `verify-published` job in `release.yml`: fresh clone of published tag, version verification, clean test run (`npm test`), and `doctor` command execution. |
| **V11.1 Business Logic Security** | **V11.1.1**: Enforce fail-closed business logic and gate decisions. | `evaluateGateDecision` in `src/core/harness.mjs`: blocks on any high/critical finding, missing quorum, untrusted consensus, or incomplete coverage. |
| | **V11.1.2**: Enforce monotonic defense and state machine invariants. | `CONTROLLED-REMEDIATION-SPEC.md`: findings cannot be downgraded, self-closed, or waived without explicit authorized cryptographic credentials. |
| **V12.1 File System Confinement** | **V12.1.1**: Restrict file operations to target directories; prevent path traversal and symlink escapes. | `PatchJailSecurityError` on unauthorized file modification; path traversal checks (`..` rejection) in `manifest-bundle.mjs:447-450`; network isolation (`--network=none`). |
| **V14.2 Dependency Management** | **V14.2.1**: Minimize or eliminate third-party runtime dependencies. | Zero runtime npm dependencies (`package.json` `dependencies: {}`); zero production lockfile; native Node standard library runtime. |
| **V15 AI / Model Assurance** | **V15.1**: Validate AI-generated findings without conferring implicit authority. | Non-authoritative model self-reporting (`SECURITY.md:51-53`); independent verifier cross-examination; multi-vendor corroboration quorum. |
| | **V15.2**: Preserve dissent and disagreement records across consensus minting. | `disagreement-ledger.json` records verified vs contested vs insufficient evidence findings without silent suppression. |

---

### 21.3 Non-Normative Draft Guidance: NIST SP 800-218 Rev.1 / SSDF v1.2 Draft Concepts

*Notice*: The following items are non-normative draft concepts from NIST SP 800-218 Rev.1 / SSDF v1.2 drafts, included for forward-looking architectural planning only:

1. **AI/ML Model Provenance & Verification (Draft Practice PO.1.4)**:
   - *Draft Concept*: Tracking AI model families, parameters, training cutoffs, and execution trust tiers to prevent hallucination in security-critical code paths.
   - *Triad-Flow Architectural Alignment*: Contract 4 of `docs/AUDITABLE-RECEIPT-SPEC.md` (`sourceTrustTiers`: `cli`, `runtime`, `reported`, `inferred`, `unavailable`) and model provenance schemas defined in RFC-027-02.
2. **Machine-Readable Vulnerability Exploitability eXchange (VEX) (Draft Practice PS.2.2)**:
   - *Draft Concept*: Emitting standardized VEX (OpenVEX / CSAF) documents alongside SBOMs to attest that reported upstream vulnerabilities are not exploitable in the target toolchain.
   - *Triad-Flow Architectural Alignment*: Planned future release workflow extension to generate a detached `triad-flow.openvex.json` document attesting to zero exploitable vulnerabilities given zero runtime dependencies.
3. **Automated Multi-Stage Verification of AI-Synthesized Code (Draft Practice PW.7.3)**:
   - *Draft Concept*: Mandatory automated multi-stage sandboxing and test execution before accepting AI-generated patches into source repositories.
   - *Triad-Flow Architectural Alignment*: `PatchJail` ephemeral worktree test execution (`FIXED_PENDING_VERIFY`) and independent verifier confirmation before transitioning remediation issues to `CLOSED`.
