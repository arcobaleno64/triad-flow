# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.10.0] - 2026-10-29

### Added
- **Real-World Multi-Language Benchmark Suite (TF-OSS-v2)**:
  - 10 curated human-adjudicated real-world OSS repository cases spanning 5 languages (C, Rust, Go, Python, JavaScript) and 8 CWE families:
    • `TF-OSS-201` (`redis/redis`): C / CWE-125 Out-of-bounds Read (CVE-2021-32761)
    • `TF-OSS-202` (`curl/curl`): C / CWE-416 Use After Free (CVE-2023-38546)
    • `TF-OSS-203` (`rustls/rustls`): Rust / CWE-323 Nonce Reuse (CVE-2024-39908)
    • `TF-OSS-204` (`hyperium/hyper`): Rust / CWE-835 Infinite Loop (CVE-2021-32714)
    • `TF-OSS-205` (`containerd/containerd`): Go / CWE-22 Path Traversal (CVE-2022-23648)
    • `TF-OSS-206` (`python/cpython`): Python / CWE-20 Improper Input Validation (CVE-2023-24329)
    • `TF-OSS-207` (`nodejs/node`): C++/JS / CWE-755 Exception Handling Desync (CVE-2023-30589)
    • `TF-OSS-208` (`mde/ejs`): JS / CWE-94 Code Injection (CVE-2022-29078)
    • `TF-OSS-209` (`nats-io/nats-server`): Go / CWE-400 Uncontrolled Resource Consumption (CVE-2020-26892)
    • `TF-OSS-210` (`git/git`): C / CWE-190 Integer Overflow (CVE-2023-22490)
  - Cryptographically frozen corpus digest: `sha256:87d0720fbca96d4e8d2070260d25631eecb9ae84b60b77a0729fc23dd1975117`.
  - CLI support for `--corpus=v2` and `-v2` flags across benchmark runners.
- **Empirical Evaluation Evidence Bundle (TF-EVIDENCE-0011)**:
  - Assembled 29 cryptographically verified artifacts sealed via `artifact-manifest.json`.
  - Achieved 100% recall (10/10 caught goldens), zero incomplete runs (0/10), and 100% gate policy correctness (10/10 BLOCK).
  - Recorded solitary blocker veto for `TF-OSS-204` and vendor divergence profiles in `disagreement-ledger.json`.
- **CLI Subcommand Manuals & Documentation**:
  - Comprehensive `--help` and `-h` support with per-subcommand usage manuals for `doctor`, `demo`, `review`, `factory`, and `benchmark`.

## [2.9.0] - 2026-10-29

### Added
- **3-Tier Cross-File Symbol Resolution & Standard Library Exemption**:
  - Tier 1 exact export index, Tier 2 ast-grep semantic search, and Tier 3 repo-wide regex fallback.
  - Standard library built-in exemption for Node.js, C, Go, Python, and Rust core symbols.
- **Track D1 50-Cycle Dogfood Governance Closure**:
  - All 50 dogfood audit cycles completed and archived with zero unhandled livelocks.

## [2.7.0] - 2026-10-02

### Added
- **Tri-Party Heterogeneous Quorum Engine (RFC-027-02)**:
  - Canonical OpenAI Codex (`gpt-6.1-sol`) provider integration alongside Google Antigravity (`gemini-3.8-flash`) and Anthropic Claude Code (`claude-5.5-sonnet`).
  - Windows-native executable resolution (`codex.exe`) with `shell: false` execution (addressing Node.js CVE-2024-27980).
  - Isolated message extraction via `-o` parameter to eliminate banner stdout pollution.
  - Fail-closed Q-01..Q-08 consensus truth tables, multi-sentry corroboration tracking, and solitary blocker veto.
- **Review Prompt & Context Optimization (RFC-027-01)**:
  - Structured evidence-oriented review prompts with taxonomy-guided checklists (CWE-1321, CWE-1333, CWE-94, CWE-78, CWE-22).
  - Layer 1-3 ContextPackage injection (AST enclosures, module scope, and call graph).
  - Deterministic diff chunking, checkpoint store, and cross-chunk reconciliation.
- **Supply-Chain Governance & Rulesets (RFC-027-03)**:
  - Active GitHub Rulesets protecting `main` and release tags (`refs/tags/v*`).
  - SPDX 2.3 Software Bill of Materials (SBOM) generation (`npm run sbom:generate`).
  - SSH tag signature verification with `.github/allowed_signers`.
  - 3-target version lockstep enforcement (`scripts/bump-version.mjs`).
- **Empirical Evaluation & Dogfooding (TF-OSS-v1)**:
  - Full live empirical benchmark bundle sealed as `TF-EVIDENCE-0010` over the frozen `TF-OSS-v1` corpus.
  - Recall improved from 20.0% to 80.0% (>20% criterion met).
  - Incomplete runs reduced from 60.0% baseline to strictly 0/5 (0.0%).
  - Gate policy enforcement blocking 4/5 historical CVE cases.
  - Dogfood Track D1 shadow review capability (`scripts/dogfood-review.mjs`).

### Fixed
- Fixed false-positive authentication errors in `CliReviewAdapter` caused by interactive prompt echoes matching bare regexes.
- Defused Google Gemini content safety filter refusals on dynamic code evaluation diffs (CWE-94) and added transient refusal retry.
- Fixed root JSON extraction in `extractJsonFromText` to handle nested objects preceding `findings`.
- Hardened sandbox execution against container namespace leaks (`TF_NAMESPACE_LEAK`).

### Known Residual Debt & Governance Errata
- **TF-OSS-005 (ejs CVE-2022-29078 / CWE-94)**: Expected BLOCK, actual APPROVE due to detection miss (0/3 sentries caught). Registered as open empirical debt for ongoing dogfooding and future benchmark hardening; non-blocking for G4.
- **Gate G4 Acceptance Criteria & Evidence Supersession (0007 → 0010)**: Authoritative G4 acceptance criteria are governed by Roadmap §4.4 (v2.6.0 release, frozen corpus digest, `TF-EVIDENCE-0007` manifest verification, Recall >20%, 0/5 incomplete) and §6 qualitative verification (valid verification records, multi-model disagreement ledger). Formal governance disposition supersedes the live evaluation role from mock bundle `TF-EVIDENCE-0007` to canonical live bundle `TF-EVIDENCE-0010`, while retaining `0007`'s offline verification obligations. Fully documented in [`docs/benchmarks/tf-oss-v1-v2.7-live-evaluation.md`](docs/benchmarks/tf-oss-v1-v2.7-live-evaluation.md). Sealed historical bundles `TF-EVIDENCE-0007` and `TF-EVIDENCE-0010` remain byte-for-byte unchanged.
- **P2-1 (Oversized single-line coordinate inflation - v2.7.1 DEBT)**: Splitting one physical diff line into multiple synthetic +/- lines can advance source coordinates and produce inaccurate locators. This is an edge-case correctness debt deferred to v2.7.1 to preserve narrow release repair scope.
- **P2-2 (POSIX literal backslash exclusion collision - v2.7.1 DEBT)**: On POSIX filesystems, "\" is a legal filename character, whereas exclusion normalization collapses "\" into "/". Current release branch diffs do not exercise literal backslash paths; deferred to v2.7.1.
- **Staged deadline after context construction (v2.7.1 DEBT)**: remainingGlobalMs and effectiveChunkTimeoutMs are computed prior to synchronous context and prompt construction. While preventing N × timeout provider-budget escapes, total wall-clock time may exceed T_total by chunk context-construction time; deferred to v2.7.1 for pre-invocation deadline recomputation.

## [2.6.0] - 2026-10-01
- Milestone baseline closure at commit `fe57597c8fce5d699f764ec4d4dfe3d1e5b5cc73`.
- Sealed authoritative empirical baseline `TF-EVIDENCE-0006`.
