# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
  - SPDX 2.3 Software Bill of Materials (SBOM) generation (`scripts/generate-sbom.mjs`).
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

### Known Residual Debt
- **TF-OSS-005 (ejs CVE-2022-29078 / CWE-94)**: Expected BLOCK, actual APPROVE due to detection miss (0/3 sentries caught). Registered as open empirical debt for ongoing dogfooding and future benchmark hardening.

## [2.6.0] - 2026-10-01
- Milestone baseline closure at commit `fe57597c8fce5d699f764ec4d4dfe3d1e5b5cc73`.
- Sealed authoritative empirical baseline `TF-EVIDENCE-0006`.
