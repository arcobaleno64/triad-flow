# RFC-027-02: Tri-Party Heterogeneous Quorum Consensus & Canonical Codex Integration

- **Status**: PROPOSED
- **Authors**: Triad-Flow Architecture Team (Worker RFC-027-02)
- **Target Release**: Triad-Flow v2.7.0
- **Created**: 2026-10-01
- **Authoritative Baseline**: Commit `fe57597c8fce5d699f764ec4d4dfe3d1e5b5cc73` (`V2.6_MILESTONE_CLOSED`, 404 tests passing)
- **Dependencies**: RFC-027-01 (Review Prompt & Context Optimization), RFC-027-03 (Supply-Chain Governance & Branch Protection)
- **Normative References**: NIST SP 800-218 (SSDF v1.1) Tasks PW.1, PW.2, PW.7, PW.8, RV.1; OWASP ASVS v5.0.0; Node.js Security Advisory CVE-2024-27980; Node.js DEP0190.

---

## 1. Status

This document is a formal specification for Triad-Flow v2.7. It is currently in `PROPOSED` status within the v2.7 planning milestone. Implementation is bounded by the Planning-Only Boundary constraint: no production source code, benchmark fixtures (`TF-OSS-v1`), or historical evidence bundles (`TF-EVIDENCE-0006`) are modified during this architectural design phase.

Upon ratification, this specification governs the architectural expansion of Triad-Flow's consensus engine from a two-party sentry mechanism to a three-vendor heterogeneous review quorum, introduces the canonical OpenAI Codex (`gpt-6.1-sol`) provider profile, defines decoupled corroboration and solitary blocking authorities, formalizes deterministic fallback degradation, and establishes mathematical proof of invariant fail-closed security.

---

## 2. Context

Triad-Flow was originally conceived as an autonomous, multi-agent code review and security gate engine. In version 2.5 and the v2.6 milestone closure (`fe57597c8fce5d699f764ec4d4dfe3d1e5b5cc73`), Triad-Flow established an evidence-bound, dual-sentry consensus mechanism (`STRICT_HETEROGENEOUS` in `src/core/loop.mjs`). This architecture coupled two distinct provider families:
1. Google (`agy` CLI driving `gemini-3.8-flash` in `macro` structural analysis);
2. Anthropic (`claude` CLI driving `claude-5.5-sonnet` in `micro` defect auditing).

Consensus authority in Triad-Flow is protected by an in-process capability model (`src/core/consensus-state.mjs`) employing a module-private `WeakSet` (`trustedConsensusRegistry`). Plain objects, forged tokens, or model self-attestations cannot grant CI/CD gate passage. Only the evidence-bound issuer `issueConsensusFromEvidence` can mint trusted capabilities, and the gate evaluator (`evaluateGateDecision` in `src/core/harness.mjs`) strictly fails closed on untrusted or non-quorate reports.

While the two-provider system achieved robust fail-closed guarantees on historical synthetic benchmarks, real-world deployment across diverse open-source codebases (as measured in empirical run `TF-EVIDENCE-0006` on the frozen `TF-OSS-v1` corpus) revealed critical operational bottlenecks:
- **Provider Liveness Fragility**: When one of two sentries experiences transient rate limits, authentication timeouts, or transport crashes, the entire review pipeline must abort to maintain heterogeneous safety, leaving no viable secondary heterogeneous fallback.
- **Bimodal Blind Spots**: Two providers represent two distinct architectural biases. While Google `gemini-3.8-flash` provides large-window structural mapping and Anthropic `claude-5.5-sonnet` provides nuanced AST reasoning, neither provider alone provides sufficient coverage against subtle algorithmic flaws, data-flow vulnerabilities, or supply-chain edge cases that OpenAI's Codex series excels in detecting.
- **Corroboration Ambiguity**: In a dual-provider system, agreement is binary: either both providers agree ($2/2$), or they diverge ($1/1$). There is no tie-breaking mechanism or ability to achieve multi-party corroboration without sacrificing vendor diversity.

Triad-Flow v2.7 introduces OpenAI Codex (`gpt-6.1-sol`) as a third first-class provider, completing a true tri-party heterogeneous review quorum spanning Google, Anthropic, and OpenAI.

---

## 3. Problem Statement

Expanding from two to three review providers introduces severe architectural, security, and algorithmic challenges that cannot be resolved through trivial majority voting:

### 3.1 The Fatal Flaw of Naive Majority Voting (2-of-3 Fallacy)
In democratic voting systems, a 2-of-3 majority represents consensus. In security verification, applying a naive "2-of-3 = APPROVE" rule is catastrophic:
- Suppose Provider A (Google) and Provider B (Anthropic) report clean diffs (zero findings).
- Suppose Provider C (OpenAI Codex) identifies an authentic, exploitable Critical Remote Code Execution (RCE) or SQL Injection vulnerability with valid code locators.
- Under a naive 2-of-3 majority vote, the two clean reports would outvote the lone critical finding ($2 > 1$), issuing an `APPROVE` verdict and allowing severe vulnerabilities to merge into production!
- **Core Security Axiom**: A security harness must never allow majority voting to suppress or erase authentic, high-severity vulnerability evidence. Approval authority and blocking authority must be fundamentally decoupled.

### 3.2 Platform-Specific CLI Invocation Hazards (Windows CVE-2024-27980 & DEP0190)
Empirical investigations of the Codex CLI (`codex-cli 0.159.2`) on Windows environments revealed severe process-spawning hazards:
1. `codex` is distributed globally via npm as a batch wrapper (`codex.cmd`).
2. Spawning `.cmd` files in Node.js 18.20.2+, 20.12.2+, 21.7.2+, 22+, and 24+ on Windows with `{ shell: false }` triggers an immediate fatal `EINVAL` error (Node.js security fix for Command Injection CVE-2024-27980).
3. Attempting to bypass this by setting `{ shell: true }` emits runtime deprecation warnings (`(node) [DEP0190] DeprecationWarning: Passing args to a child process with shell option true...`) and re-exposes the execution harness to shell argument injection attacks.
4. Triad-Flow requires a deterministic, zero-dependency mechanism to resolve the underlying native binary (`codex.exe`) or invoke `codex.js` directly with `shell: false`.

### 3.3 Output Contamination & Parse Failure in Codex CLI
When `codex exec` executes non-interactively, its standard output (`stdout`) interleaves:
- ANSI escape sequences and color codes;
- Promotional headers, version banners, and session IDs;
- User prompt echoes;
- Diagnostic hook logs (`hook: SessionStart`, `hook: ToolCall`);
- Post-execution token counts and billing metrics.

Feeding raw `stdout` into JSON extraction algorithms causes frequent parse failures (`parsed: null`) or captures truncated prompt echoes instead of the model's actual review payload. The architecture requires an isolated, side-channel delivery mechanism that guarantees 100% pure JSON output extraction.

### 3.4 Invariant Degradation & Fail-Closed Fallback
When executing three providers across external networks, provider failure (timeout, network partition, token exhaustion, authentication invalidation) is an inevitability. If Provider C fails, the system must degrade to a dual-provider (2/3) quorum. If two providers fail on a low-risk change, it may degrade to a single-sentry (1/3) fast path. However:
- Degradation must maintain strict vendor-family heterogeneity.
- A missing or failing provider must **never** be synthetically synthesized as "clean" or "zero findings."
- On high-risk changesets (Tier 1: Auth, Crypto, CI, Security, or $\ge 50$ lines), single-provider degradation must be strictly prohibited, failing closed immediately.

---

## 4. Goals

1. **Canonical Codex Provider Profile**: Formalize the complete execution profile for OpenAI Codex (`codex` CLI / `gpt-6.1-sol`), including native executable resolution on Windows, argument allowlists, mandatory read-only sandboxing, environment isolation, and clean output capture.
2. **Side-Channel Output Isolation**: Specify the `-o <tempFile>` (and `--output-last-message`) file isolation protocol for Codex, completely eliminating CLI banner and hook log contamination.
3. **Decoupled Quorum Semantics**: Define a deterministic tri-party consensus protocol separating:
   - **Corroboration Quorum**: Two-vendor agreement on findings to elevate confidence and priority;
   - **Approval Authority**: Unanimous non-blocking disposition among active, healthy sentries;
   - **Solitary Blocking Authority**: Universal veto power granted to any single provider reporting an authentic Critical or High finding.
4. **Deterministic Fallback Degradation**: Specify formal state machines and truth tables for $3/3 \to 2/3 \to 1/3 \to 0/3$ degradation, preserving vendor diversity and risk-tier boundaries.
5. **Evidence-Aware Finding Deduplication**: Implement multi-attribute defect matching based on canonical file paths, line span overlap ($\pm 5$ lines), and vulnerability classification (CWE / Rule ID / Defect Type), ensuring unrelated issues at identical locators are never merged.
6. **Strict Severity Preservation**: Guarantee mathematically that finding aggregation calculates $\max(\text{severity})$ across all reporting sources and never downgrades severity.
7. **Tri-Party Disagreement Ledger**: Extend the auditing ledger to track three-party consensus divergences, solitary blockers, and verifier omissions.
8. **Mathematical Fail-Closed Proof**: Formally prove that adding a third provider never weakens existing fail-closed gate guarantees.
9. **Zero Runtime Dependencies**: Preserve the invariant of zero runtime npm dependencies, utilizing only Node.js native standard libraries (`node:child_process`, `node:fs`, `node:path`, `node:crypto`).

---

## 5. Non-Goals

1. **Benchmarking Alteration**: Modifying the frozen `TF-OSS-v1` corpus, patches, golden CWE labels, or historical `TF-EVIDENCE-0006` artifacts.
2. **Production Source Modification During Planning**: Editing `src/core/` or `src/adapters/` files prior to milestone implementation authorization.
3. **Third-Party SDK Inclusion**: Adding `@openai/openai`, `@anthropic-ai/sdk`, or `@google/genai` npm packages.
4. **Remote Token Passing / SaaS Delegation**: Relying on external cloud orchestration servers, SaaS proxies, or unverified remote execution endpoints.
5. **Weakening of Fail-Closed Gates**: Introducing fuzzy heuristic overrides, user bypass flags, or soft-fail warnings for high-risk security gates.

---

## 6. Terminology

- **Sentry**: An autonomous, local CLI reviewer adapter executing a distinct foundational model under strict read-only constraints.
- **Heterogeneous Quorum**: A review quorum comprising sentries drawn from strictly distinct model vendor families (`google`, `anthropic`, `openai`). Multiple models from the same vendor family (e.g. `gpt-4o` and `gpt-6.1-sol`) do NOT constitute a heterogeneous quorum.
- **Corroboration Quorum**: A consensus threshold ($k \ge 2$ independent vendors) that validates and corroborates the factual existence of a specific vulnerability finding or clean disposition.
- **Approval Authority**: The specific evidentiary threshold required to issue a CI/CD Gate `approve` decision. In Triad-Flow, approval authority requires unanimous non-blocking consensus among participating sentries with complete diff coverage.
- **Solitary Blocking Authority (Veto)**: The authority granted to any single sentry to force a Gate `block` decision whenever it detects an authentic Critical or High severity defect, regardless of whether other sentries reported zero findings.
- **In-Process Trusted Capability**: An unforgeable token minted exclusively into a module-private `WeakSet` (`trustedConsensusRegistry`) by `issueConsensusFromEvidence`, certifying that consensus was derived from verified, healthy sentry reports.
- **Native Binary Resolution**: The platform-aware resolution mechanism that locates and invokes the compiled native executable (`codex.exe`) on Windows rather than an npm shell wrapper (`codex.cmd`), eliminating CVE-2024-27980 `EINVAL` hazards.
- **Side-Channel Output Isolation**: Directing a CLI tool to write its terminal agent message to a dedicated temporary file via `-o <tempFile>`, bypassing stdout log contamination.
- **Disagreement Ledger**: An immutable, structured audit artifact capturing all divergences between sentries, including solitary blockers, locator disputes, and severity conflicts.
- **Risk Tier**: The categorization of a changeset:
  - **Tier 1 (High-Risk)**: Changes touching authentication, cryptography, CI/CD workflows, security policies, or $\ge 50$ changed lines. Requires full heterogeneous quorum ($3/3$ or $2/2$).
  - **Tier 2/3 (Low-Risk)**: Localized documentation, formatting, or isolated non-security changes $< 50$ lines. Eligible for single-sentry fallback.

---

## 7. Threat Model

The Triad-Flow consensus engine operates in hostile environments where pull request code, model provider behavior, local execution hooks, and network transports may be malicious, compromised, or faulty.

### 7.1 Threat Vectors

| Threat ID | Threat Vector | Mechanism | Impact | Architectural Mitigation in RFC-027-02 |
|---|---|---|---|---|
| **T-01** | Majority Vote Vulnerability Erasure | Two LLMs suffer common-mode hallucination or miss a subtle RCE; naive 2-of-3 voting dismisses the 3rd model's valid finding. | Vulnerable code merged to `main`. | **Solitary Blocking Authority**: Any single sentry reporting an authentic Critical or High finding triggers a gate `block`. |
| **T-02** | Synthetic Approval via Provider Outage | Provider C times out or crashes; system defaults to assuming Provider C found 0 defects. | Erroneous consensus calculation; weakened review rigor. | **Fail-Closed Degradation**: Unhealthy sentries are marked `UNAVAILABLE` and omitted. They never contribute synthetic clean reports. |
| **T-03** | Windows CVE-2024-27980 Exploitation | Spawning `.cmd` files triggers argument injection vulnerabilities or crashes Node.js with `EINVAL`. | Arbitrary command execution or complete CI denial-of-service. | **Native Binary Resolution**: Bypasses `cmd.exe` entirely by executing `codex.exe` or `node codex.js` directly with `shell: false`. |
| **T-04** | CLI Output Injection & Hook Contamination | Hostile code in diff or local git hooks emits crafted ANSI or fake JSON to stdout during review. | Aggregator parses attacker-controlled payload as reviewer findings. | **Side-Channel Isolation**: Prompt passes via stdin; final JSON is read exclusively from private temporary file `-o <tempFile>`. |
| **T-05** | Hostile Argument Override | Pull request configuration or command-line args attempt to pass `--dangerously-bypass-approvals-and-sandbox`. | Reviewer executes with sandbox disabled, modifying workspace. | **Mandatory Flag Enforcement**: `assembleProviderArgs` strips conflicting flags and prepends immutable safety flags. |
| **T-06** | In-Process Capability Forgery | Adversary creates a mock consensus object `{ verdict: 'approve', quorumReached: true }`. | CI Gate approves without actual consensus or evidence. | **Module-Private WeakSet**: `assertTrustedConsensus` validates reference identity against unexposed `WeakSet`. |
| **T-07** | Sybil Inflation Attack | Malicious adapter submits multiple identical reports under different IDs to simulate multi-vendor quorum. | Single model family claims heterogeneous consensus. | **Sybil & Diversity Checking**: Quorum evaluator verifies unique report IDs and distinct canonical vendor families (`google`, `anthropic`, `openai`). |
| **T-08** | Incomplete Coverage Bypass | Model truncates review and omits files from review payload (`omittedFiles: [...]`). | Unreviewed code merged without gate scrutiny. | **Coverage Verification**: Any non-empty `omittedFiles` triggers status `incomplete` and Gate `block`. |

---

## 8. Architecture

Triad-Flow v2.7 structures review execution into four discrete, decoupled architectural planes:
1. **Transport & Execution Plane**: Manages native child process lifecycles, sandbox boundaries, and side-channel file I/O.
2. **Sentry Validation Plane**: Enforces Default-Deny schema normalization and strips forged capabilities.
3. **Quorum Consensus Plane**: Evaluates sentry health, resolves vendor heterogeneity, performs evidence-aware finding deduplication, and mints trusted consensus capabilities.
4. **CI/CD Gate Plane**: Computes final merge authority from the trusted consensus capability and produces auditable receipts.

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                     TRIAD-FLOW CORE HARNESS                                      │
├──────────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                                  │
│   ┌──────────────────────────────────────────────────────────────────────────────────────────┐   │
│   │                                1. ROUTER & SCALE EVALUATOR                               │   │
│   │  Evaluates changeset scale, file types, and sensitivity (Tier 1 vs Tier 2/3).            │   │
│   └─────────────────────────────────────────────┬────────────────────────────────────────────┘   │
│                                                 │                                                │
│                                                 ▼                                                │
│   ┌──────────────────────────────────────────────────────────────────────────────────────────┐   │
│   │                              2. HETEROGENEOUS REVIEW QUORUM                              │   │
│   │                                                                                          │   │
│   │   ┌──────────────────────┐    ┌──────────────────────┐    ┌──────────────────────────┐   │   │
│   │   │    Google Sentry     │    │   Anthropic Sentry   │    │      OpenAI Sentry       │   │   │
│   │   │        (agy)         │    │       (claude)       │    │         (codex)          │   │   │
│   │   │   gemini-3.8-flash   │    │   claude-5.5-sonnet  │    │       gpt-6.1-sol        │   │   │
│   │   ├──────────────────────┤    ├──────────────────────┤    ├──────────────────────────┤   │   │
│   │   │ • Native agy.exe     │    │ • Native claude.exe  │    │ • Native codex.exe       │   │   │
│   │   │ • --mode=plan        │    │ • -p --tools=        │    │ • exec --sandbox=read-only│   │  │
│   │   │ • Argv input channel │    │ • Stdin stream       │    │ • Stdin prompt stream    │   │   │
│   │   │ • Stdout JSON        │    │ • Stdout JSON        │    │ • -o <tmpFile> Isolation │   │   │
│   │   └──────────┬───────────┘    └──────────┬───────────┘    └────────────┬─────────────┘   │   │
│   │              │                           │                             │                 │   │
│   └──────────────┼───────────────────────────┼─────────────────────────────┼─────────────────┘   │
│                  │                           │                             │                     │
│                  ▼                           ▼                             ▼                     │
│   ┌──────────────────────────────────────────────────────────────────────────────────────────┐   │
│   │                             3. SENTRY VALIDATION & NORMALIZATION                         │   │
│   │  • Validates provider output against canonical schema. Strips forged capability nonces.  │   │
│   │  • Checks diff coverage (omittedFiles). Classifies transport errors (TIMEOUT, AUTH, etc).│   │
│   └─────────────────────────────────────────────┬────────────────────────────────────────────┘   │
│                                                 │                                                │
│                                                 ▼                                                │
│   ┌──────────────────────────────────────────────────────────────────────────────────────────┐   │
│   │                          4. TRI-PARTY QUORUM POLICY EVALUATION                           │   │
│   │  • Evaluates provider health: 3/3 Nominal, 2/3 Degraded, or 1/3 Single Sentry.           │   │
│   │  • Enforces Vendor Family Diversity (google != anthropic != openai).                     │   │
│   │  • Rejects Sybil inflation (pairwise object ref checks & unique report IDs).              │   │
│   └─────────────────────────────────────────────┬────────────────────────────────────────────┘   │
│                                                 │                                                │
│                                                 ▼                                                │
│   ┌──────────────────────────────────────────────────────────────────────────────────────────┐   │
│   │                        5. CONSENSUS & EVIDENCE-AWARE DEDUPLICATION                       │   │
│   │  • 3-Tuple Matching: <CanonicalPath, LineOverlap(±5), DefectIdentity>.                  │   │
│   │  • DefectIdentity mandates structured 'cwe' / 'type' tags with numeric normalization.    │   │
│   │  • Calculates Corroborations: count of independent reporting vendors (1, 2, or 3).       │   │
│   │  • Severity Preservation: consensusSeverity = max(severities). Never downgrades.         │   │
│   │  • Solitary Blocker Invariant: Single Critical/High finding forces verdict = 'needs-attn'│   │
│   │  • Mints unforgeable In-Process Trusted Capability in module-private WeakSet.            │   │
│   │  • Writes Tri-Party Disagreement Ledger recording divergences and solitary blockers.     │   │
│   └─────────────────────────────────────────────┬────────────────────────────────────────────┘   │
│                                                 │                                                │
│                                                 ▼                                                │
│   ┌──────────────────────────────────────────────────────────────────────────────────────────┐   │
│   │                                  6. CI/CD GATE EVALUATION                                │   │
│   │  • assertTrustedConsensus(consensus) -> Verify in WeakSet.                               │   │
│   │  • evaluateGateDecision(consensus, strict) -> APPROVE or BLOCK.                          │   │
│   │  • Emits cryptographically verifiable audit receipt (audit-receipt.json).                │   │
│   └──────────────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                                  │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 8.1 Consensus Pipeline Operational Specification

#### Step 1 (Stage 4): Pairwise Object Reference Equality & Sybil Defense
To eliminate cross-key object aliasing Sybil vulnerabilities, `aggregateConsensus` enforces exhaustive **pairwise object reference equality checks** across all entries in `rawReports` prior to ID assignment:
$$\forall k_1, k_2 \in \text{keys}(\text{rawReports}), \quad k_1 \ne k_2 \implies \text{rawReports}[k_1] \not\equiv \text{rawReports}[k_2]$$
If any two provider slots reference the identical object instance (e.g. `rawReports.agy === rawReports.codex`), consensus aborts immediately with a `Sybil inflation rejected` error and the gate blocks. Furthermore, all minted report IDs must satisfy Set cardinality: `selectedUniqueIds.size === selectedReportIds.length`.

#### Step 5 (Stage 5): Structured DefectIdentity & Bare Numeric CWE Normalization
To prevent finding deduplication fragility where equivalent vulnerabilities across heterogeneous models fail to corroborate due to differing free-text titles (e.g. `"SQL Injection in query"` vs `"SQLi via parameter concatenation"`):
1. **Mandatory Taxonomy Tags**: Reviewer prompt contracts (RFC-027-01) strictly enforce structured `cwe` (e.g. `cwe-89`) and `type` enum tags in provider schemas.
2. **Taxonomy Normalization**: The sentry normalization layer standardizes all raw CWE inputs using `/^(?:CWE[-_]?)?(\d+)$/i` to canonical `"cwe-$1"`, handling bare numeric strings (`"89"`, `"1321"`) and casing variants.
3. **DefectIdentity Binding**: The 3-tuple deduplication mechanism `<CanonicalPath, LineOverlap(±5), DefectIdentity>` binds `DefectIdentity` to this normalized CWE/type token, ensuring that equivalent findings from distinct sentries reliably corroborate ($k \ge 2$) rather than splitting into spurious solitary dissent.

---

## 9. Data Schemas

All data contracts in Triad-Flow are strictly typed, immutable (`deepFreeze`), and validated under Default-Deny.

### 9.1 Canonical Codex Provider Profile Schema
```javascript
export const CodexProfileSchema = Object.freeze({
  id: "codex",
  command: "codex",
  family: "openai",
  model: "gpt-6.1-sol",
  reviewProfileReady: true,
  profileStatus: "canonical",
  baseArgs: Object.freeze(["exec", "--ephemeral", "--color", "never"]),
  mandatorySafetyArgs: Object.freeze(["--sandbox=read-only"]),
  args: Object.freeze(["exec", "--sandbox=read-only", "--ephemeral", "--color", "never"]),
  readOnlyFlags: Object.freeze(["--sandbox=read-only"]),
  inputChannel: "stdin",
  supportsStdin: true,
  outputChannel: "file",
  outputFileFlag: "-o",
  envAllowlist: Object.freeze([
    "PATH", "SYSTEMROOT", "TEMP", "TMP", "USERPROFILE",
    "HOME", "APPDATA", "LOCALAPPDATA", "OPENAI_API_KEY", "CODEX_HOME"
  ])
});
```

### 9.2 Provider Execution & Readiness Schema
```typescript
interface ProviderReadinessReport {
  provider: "agy" | "claude" | "codex";
  family: "google" | "anthropic" | "openai" | "unknown";
  ready: boolean;
  points: {
    binaryDetected: boolean;      // Point 1: Executable found on system PATH or binary resolution path
    versionParsed: boolean;        // Point 2: Version matches semver / CLI standard
    canonicalMatched: boolean;     // Point 3: Matches canonical profile definition
    safetyArgsVerified: boolean;   // Point 4: Mandatory safety args cannot be overridden
    liveProbeSucceeded: boolean;   // Point 5: Non-interactive benign execution passes
    readOnlyGuaranteed: boolean;   // Point 6: Enforces filesystem read-only sandbox
    cleanOutputVerified: boolean;  // Point 7: Pure JSON extractable without log contamination
  };
  nativeResolution?: {
    resolvedPath: string;
    isNativeExecutable: boolean;
    bypassedBatchWrapper: boolean;
  };
  summary: string;
  errors: string[];
}
```

### 9.3 Deduplicated Finding Schema with Multi-Party Corroboration
```typescript
interface TriPartyConsensusFinding {
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  file: string;                   // Normalized POSIX-style relative path
  line_start: number;
  line_end: number;
  ruleId?: string;
  cwe?: string;
  type?: string;
  recommendation?: string;
  sources: Array<"agy" | "claude" | "codex" | string>;
  corroborations: number;         // Count of independent reporting providers (1, 2, or 3)
  authority: "solitary" | "corroborated" | "unanimous";
  locators: Array<{
    provider: string;
    line_start: number;
    line_end: number;
  }>;
}
```

*DefectIdentity Normalization Specification*: In accordance with the consensus deduplication contract, all findings must declare structured `cwe` (e.g. `"cwe-89"`) or `type` enum tags. Raw model outputs containing bare numeric strings (`"89"`, `"1321"`) or formatting variations (`"CWE-89"`, `"cwe_89"`) are strictly normalized by the sentry adapter via `/^(?:CWE[-_]?)?(\d+)$/i` to canonical `"cwe-$1"`. The deduplication engine binds `DefectIdentity` to this normalized taxonomy token, guaranteeing that heterogeneous models detecting the same underlying defect corroborate reliably rather than diverging due to free-text title variance.

### 9.4 Trusted Consensus Capability Schema
```typescript
interface TriPartyConsensusCapability {
  verdict: "approve" | "warning" | "needs-attention" | "error";
  quorumReached: boolean;
  quorumTopology: "3_OF_3_NOMINAL" | "2_OF_3_DEGRADED" | "1_OF_3_SINGLE_SENTRY" | "QUORUM_FAILED";
  participatingProviders: Array<"google" | "anthropic" | "openai">;
  totalFindings: number;
  blockingFindingsCount: number;  // Count of Critical and High findings
  findings: TriPartyConsensusFinding[];
  selectedReportIds: string[];
  consensusProof: string;
  timestamp: string;
}
```

### 9.5 Tri-Party Disagreement Ledger Schema
```typescript
interface TriPartyDisagreementLedgerDocument {
  schemaVersion: "2.7.0";
  runId: string;
  commitSha: string;
  quorumStatus: {
    topology: "3_OF_3" | "2_OF_3" | "1_OF_3";
    activeFamilies: string[];
    unavailableProviders: Array<{
      provider: string;
      reason: "TIMEOUT" | "AUTH_FAILURE" | "MALFORMED_OUTPUT" | "EXECUTION_ERROR";
    }>;
  };
  summary: {
    totalFindingsEvaluated: number;
    unanimousFindingsCount: number;
    corroboratedFindingsCount: number;
    solitaryBlockersCount: number;
    divergentSeveritiesCount: number;
  };
  entries: Array<{
    findingId: string;
    canonicalKey: string;
    disposition: "UNANIMOUS" | "CORROBORATED_2_OF_3" | "SOLITARY_BLOCKER" | "SEVERITY_DIVERGENCE";
    highestSeverity: "critical" | "high" | "medium" | "low" | "info";
    reportingProviders: string[];
    dissentingProviders: string[];
    details: {
      providerSeverities: Record<string, string>;
      reportedLocators: Record<string, { line_start: number; line_end: number }>;
    };
  }>;
}
```

---

## 10. CLI / Configuration Contract

### 10.1 Environment Variables
Triad-Flow strictly audits environment variables passed to reviewer child processes. The Codex provider environment is scrubbed under Default-Deny:

| Variable | Scope | Action | Rationale |
|---|---|---|---|
| `PATH`, `SYSTEMROOT` | System | Allowed | Essential for OS dynamic linking and binary discovery. |
| `TEMP`, `TMP` | System | Allowed | Required for `-o <tempFile>` temporary output capture. |
| `USERPROFILE`, `HOME`, `APPDATA`, `LOCALAPPDATA` | User | Allowed | Required for local CLI configuration and model cache discovery. |
| `OPENAI_API_KEY` | Provider | Allowed | Required for OpenAI model authentication. |
| `CODEX_HOME` | Provider | Allowed | Configuration root for Codex CLI. |
| `ANTHROPIC_API_KEY`, `GEMINI_API_KEY` | Provider | **STRIPPED** | Prevents cross-provider secret leakage to OpenAI child process. |
| `GITHUB_TOKEN`, `GH_TOKEN` | Repository | **STRIPPED** | Prevents pull-request token exfiltration. |
| `AWS_SECRET_ACCESS_KEY`, `AZURE_*` | Cloud | **STRIPPED** | Prevents cloud credential exfiltration. |
| `NODE_OPTIONS`, `LD_PRELOAD`, `DYLD_*` | Runtime | **STRIPPED** | Prevents child process hijack or runtime hook injection. |

### 10.2 Windows Native Binary Resolution Protocol
To resolve the Windows `codex.cmd` execution hazard (Node.js CVE-2024-27980 `EINVAL` and `DEP0190`), `resolveProviderProfile("codex")` must execute the following deterministic algorithm:

```
Algorithm 1: Native Windows Binary Resolution for Codex
Input: commandOrName string ("codex")
Output: Resolved executable path and spawn configuration

1. If process.platform !== "win32", return { command: commandOrName, useShell: false }.
2. Check known native binary installation paths:
   a. Local package binary:
      path.join(workspaceRoot, "node_modules/@openai/codex/node_modules/@openai/codex-win32-x64/vendor/x86_64-pc-windows-msvc/bin/codex.exe")
   b. Global npm binary:
      path.join(process.env.APPDATA, "npm/node_modules/@openai/codex/node_modules/@openai/codex-win32-x64/vendor/x86_64-pc-windows-msvc/bin/codex.exe")
   c. User home binary:
      path.join(process.env.USERPROFILE, ".codex/bin/codex.exe")
3. For each candidatePath:
   If fs.existsSync(candidatePath) and fs.statSync(candidatePath).isFile():
      Return { command: candidatePath, useShell: false, resolvedType: "NATIVE_EXE" }.
4. If native codex.exe is not found:
   Check if codex.js entry point exists:
      jsEntry = path.join(process.env.APPDATA, "npm/node_modules/@openai/codex/bin/codex.js")
   If fs.existsSync(jsEntry):
      Return { command: process.execPath, prefixArgs: [jsEntry], useShell: false, resolvedType: "NODE_SCRIPT" }.
5. Fallback:
   If only codex.cmd exists on PATH:
      Throw ConfigurationError: "Codex Windows wrapper requires native binary resolution. Found only 'codex.cmd' which violates CVE-2024-27980 security invariants under shell:false. Please install @openai/codex-win32-x64 or compile codex.exe."
```

### 10.3 Codex Output Isolation Protocol via `-o <tempFile>`
To ensure 100% clean JSON output extraction without stdout banner contamination:
1. Before spawning `codex`, the adapter creates an isolated temporary file:
   `const tempOutFile = path.join(os.tmpdir(), \`tf-codex-out-\${crypto.randomUUID()}.json\`);`
2. Arguments are assembled using `assembleProviderArgs`:
   `args = ["exec", "--sandbox=read-only", "--ephemeral", "--color", "never", "-o", tempOutFile, "-"]`
3. Prompt is written to child stdin and ended:
   `child.stdin.end(promptPayload, "utf8");`
4. Upon child process exit (code 0):
   - Adapter reads `tempOutFile` via `fs.promises.readFile(tempOutFile, "utf8")`.
   - Temporary file is deleted immediately in a `finally` block.
   - Parsed content is normalized through `validateProviderOutput`.

---

## 11. State / Transition Model

### 11.1 Quorum Lifecycle State Machine
```
                       ┌────────────────────────┐
                       │     INIT_PIPELINE      │
                       └───────────┬────────────┘
                                   │
                                   ▼
                       ┌────────────────────────┐
                       │    PROBE_PROVIDERS     │
                       │ (agy, claude, codex)   │
                       └───────────┬────────────┘
                                   │
             ┌─────────────────────┼─────────────────────┐
             ▼                     ▼                     ▼
      [All 3 Healthy]       [2 of 3 Healthy]      [<= 1 Healthy]
             │                     │                     │
             ▼                     ▼                     ▼
     ┌──────────────┐      ┌──────────────┐      ┌──────────────┐
     │ 3/3 NOMINAL  │      │ 2/3 DEGRADED │      │ EVALUATE TIER│
     │ QUORUM READY │      │ QUORUM READY │      └───────┬──────┘
     └───────┬──────┘      └───────┬──────┘              │
             │                     │          ┌──────────┴──────────┐
             │                     │          ▼                     ▼
             │                     │     [Tier 1 High-Risk]   [Tier 2/3 Low-Risk]
             │                     │     Security OR >=50L    Non-sec AND <50L
             │                     │          │                     │
             │                     │          ▼                     ▼
             │                     │     ┌───────────┐        ┌───────────┐
             │                     │     │QUORUM FAIL│        │1/3 SINGLE │
             │                     │     │GATE: BLOCK│        │SENTRY PATH│
             │                     │     └───────────┘        └─────┬─────┘
             │                     │                                │
             └─────────────────────┼────────────────────────────────┘
                                   │
                                   ▼
                       ┌────────────────────────┐
                       │    DISPATCH REVIEWS    │
                       │ (Parallel CLI Review)  │
                       └───────────┬────────────┘
                                   │
                                   ▼
                       ┌────────────────────────┐
                       │   VALIDATE RESPONSES   │
                       │ (Coverage & Integrity) │
                       └───────────┬────────────┘
                                   │
                                   ▼
                       ┌────────────────────────┐
                       │  CONSENSUS AGGREGATION │
                       │ (Deduplication, Max-   │
                       │  Severity, Blockers)   │
                       └───────────┬────────────┘
                                   │
                                   ▼
                       ┌────────────────────────┐
                       │  MINT TRUSTED CAPABILITY│
                       │   (Module WeakSet)     │
                       └───────────┬────────────┘
                                   │
                                   ▼
                       ┌────────────────────────┐
                       │   EVALUATE CI GATE     │
                       │  (APPROVE or BLOCK)    │
                       └────────────────────────┘
```

---

### 11.2 Complete Quorum Formation Truth Table

The following truth table defines quorum validity and degradation across all permutations of provider operational health.

| State ID | Google (`agy`) | Anthropic (`claude`) | OpenAI (`codex`) | Changeset Scale / Risk Tier | Resolved Topology | Quorum Status | Gate Authority Permitted | Fallback / Action Rationale |
|:---|:---|:---|:---|:---|:---|:---:|:---:|:---|
| **Q-01** | Healthy | Healthy | Healthy | Any (Tier 1, 2, or 3) | `3_OF_3_NOMINAL` | **TRUE** | Full Tri-Party Quorum | Full heterogeneous review across all three vendor families. |
| **Q-02** | Healthy | Healthy | Error / Timeout | Any (Tier 1, 2, or 3) | `2_OF_3_DEGRADED` | **TRUE** | Dual-Sentry Quorum | Graceful degradation to Google + Anthropic. Codex marked `UNAVAILABLE`. |
| **Q-03** | Healthy | Error / Timeout | Healthy | Any (Tier 1, 2, or 3) | `2_OF_3_DEGRADED` | **TRUE** | Dual-Sentry Quorum | Graceful degradation to Google + OpenAI. Claude marked `UNAVAILABLE`. |
| **Q-04** | Error / Timeout | Healthy | Healthy | Any (Tier 1, 2, or 3) | `2_OF_3_DEGRADED` | **TRUE** | Dual-Sentry Quorum | Graceful degradation to Anthropic + OpenAI. Google marked `UNAVAILABLE`. |
| **Q-05A** | Healthy | Error / Timeout | Error / Timeout | **Tier 1 (High-Risk: Security-sensitive files OR $\ge 50$ lines)** | `QUORUM_FAILED` | **FALSE** | **GATE: BLOCK** | **FAIL-CLOSED**: High-risk diff cannot be evaluated by single sentry. |
| **Q-05B** | Healthy | Error / Timeout | Error / Timeout | **Tier 2/3 (Low-Risk: Non-security AND $< 50$ lines)** | `1_OF_3_SINGLE_SENTRY`| **TRUE** | Single-Sentry Authority | Fast-path single sentry permitted for minor, non-security changes. |
| **Q-06A** | Error / Timeout | Healthy | Error / Timeout | **Tier 1 (High-Risk: Security-sensitive files OR $\ge 50$ lines)** | `QUORUM_FAILED` | **FALSE** | **GATE: BLOCK** | **FAIL-CLOSED**: High-risk diff cannot be evaluated by single sentry. |
| **Q-06B** | Error / Timeout | Healthy | Error / Timeout | **Tier 2/3 (Low-Risk: Non-security AND $< 50$ lines)** | `1_OF_3_SINGLE_SENTRY`| **TRUE** | Single-Sentry Authority | Fast-path single sentry permitted for minor, non-security changes. |
| **Q-07A** | Error / Timeout | Error / Timeout | Healthy | **Tier 1 (High-Risk: Security-sensitive files OR $\ge 50$ lines)** | `QUORUM_FAILED` | **FALSE** | **GATE: BLOCK** | **FAIL-CLOSED**: High-risk diff cannot be evaluated by single sentry. |
| **Q-07B** | Error / Timeout | Error / Timeout | Healthy | **Tier 2/3 (Low-Risk: Non-security AND $< 50$ lines)** | `1_OF_3_SINGLE_SENTRY`| **TRUE** | Single-Sentry Authority | Fast-path single sentry permitted for minor, non-security changes. |
| **Q-08** | Error / Timeout | Error / Timeout | Error / Timeout | Any (Tier 1, 2, or 3) | `QUORUM_FAILED` | **FALSE** | **GATE: BLOCK** | Complete outage. Zero providers available. Pipeline halts. |

*Tier 1 Scope and Fail-Closed Invariant*: Changeset classification treats any modification touching security-sensitive files (authentication, cryptography, sandbox enforcement, CI/CD workflows, repository permissions, secret management) as **Tier 1 High-Risk**, regardless of line count (even a 1-line change). Changesets qualify for Tier 2/3 single-sentry fallback **only** if they touch strictly non-security files AND total changed lines are $< 50$. Any Tier 1 diff strictly fails closed (`GATE: BLOCK`) if fewer than 2 healthy heterogeneous providers remain.

---

### 11.3 Tri-Party Finding Evaluation & Gate Decision Truth Table (3/3 Nominal)

The following truth table maps provider finding distributions to consensus verdicts, gate decisions, and Disagreement Ledger classifications when all three sentries participate.

| Case ID | Google (`agy`) Report | Anthropic (`claude`) Report | OpenAI (`codex`) Report | Deduplicated Findings | Corroboration Count | Highest Severity | Consensus Verdict | Gate (Normal) | Gate (Strict) | Disagreement Ledger Classification |
|:---|:---|:---|:---|:---|:---:|:---:|:---:|:---:|:---:|:---|
| **V-01** | Clean (0 findings) | Clean (0 findings) | Clean (0 findings) | 0 findings | 3 (Unanimous) | None | `approve` | **APPROVE** | **APPROVE** | `UNANIMOUS_CLEAN_PASS` |
| **V-02** | Clean (0 findings) | Clean (0 findings) | **1 Critical (RCE)** | 1 Critical | 1 (Solitary) | Critical | `needs-attention` | **BLOCK** | **BLOCK** | `SOLITARY_HIGH_RISK` (Codex Blocker) |
| **V-03** | **1 High (SQLi)** | Clean (0 findings) | Clean (0 findings) | 1 High | 1 (Solitary) | High | `needs-attention` | **BLOCK** | **BLOCK** | `SOLITARY_HIGH_RISK` (Google Blocker) |
| **V-04** | Clean (0 findings) | **1 Critical (SSRF)**| Clean (0 findings) | 1 Critical | 1 (Solitary) | Critical | `needs-attention` | **BLOCK** | **BLOCK** | `SOLITARY_HIGH_RISK` (Claude Blocker) |
| **V-05** | **1 High (SQLi)** | **1 High (SQLi)** | Clean (0 findings) | 1 High | 2 (Corroborated) | High | `needs-attention` | **BLOCK** | **BLOCK** | `CORROBORATED_BLOCKER` (Google + Claude) |
| **V-06** | **1 Critical (RCE)**| **1 Critical (RCE)**| **1 Critical (RCE)**| 1 Critical | 3 (Unanimous) | Critical | `needs-attention` | **BLOCK** | **BLOCK** | `UNANIMOUS_BLOCKER` (3 of 3) |
| **V-07** | 1 Medium (XSS) | 1 Critical (RCE) | 1 High (AuthBypass) | 3 distinct issues | 1 each | Critical | `needs-attention` | **BLOCK** | **BLOCK** | `MULTI_SOLITARY_BLOCKERS` (3 issues) |
| **V-08** | 1 Low (Style) | Clean (0 findings) | Clean (0 findings) | 1 Low | 1 (Solitary) | Low | `warning` | **APPROVE** | **BLOCK** | `SOLITARY_LOW_ADVISORY` |
| **V-09** | 1 Medium (DoS) | 1 Medium (DoS) | Clean (0 findings) | 1 Medium | 2 (Corroborated) | Medium | `warning` | **APPROVE** | **BLOCK** | `CORROBORATED_MEDIUM_ADVISORY` |
| **V-10** | 1 Medium (DoS) | 1 High (DoS) | 1 Low (DoS) | 1 defect (merged) | 3 (Corroborated) | **High (Preserved)**| `needs-attention` | **BLOCK** | **BLOCK** | `SEVERITY_DIVERGENCE_UPGRADED_TO_HIGH`|

---

## 12. Failure Modes

Triad-Flow enforces explicit, deterministic failure classifications for all reviewer interactions:

| Failure Mode | Trigger Condition | Detection Mechanism | Immediate Action | Gate Disposition |
|---|---|---|---|---|
| `AUTH_FAILURE` | Provider CLI exits non-zero with invalid API key, expired token, or 401/403 status. | Exit code inspection + stderr regex `/(auth\|unauthorized\|api[ _-]?key\|login)/i`. | Provider marked `UNAVAILABLE`. Triggers 2/3 fallback. | Fails closed on Tier 1 if $<2$ healthy providers remain. |
| `TIMEOUT` | Reviewer process exceeds configured timeout (default 90s). | Child process lifecycle monitor triggers `SIGTERM`, then `SIGKILL` after 2s grace. | Child process terminated. Status marked `TIMEOUT`. | Triggers fallback degradation. |
| `MALFORMED_OUTPUT` | Provider stdout or `-o` file fails JSON parsing or schema validation. | `validateProviderOutput` returns `ok: false`. | Execution marked `MALFORMED_OUTPUT`. | Unhealthy provider excluded from quorum. |
| `PAYLOAD_TOO_LARGE` | Provider payload exceeds `SAFE_ARGV_THRESHOLD_BYTES` on argv-only provider (`agy`). | Pre-flight byte size assertion in `CliReviewAdapter`. | Fails closed immediately without executing child process. | Marked `PAYLOAD_TOO_LARGE`. Gate blocks. |
| `INCOMPLETE_COVERAGE` | Sentry review report declares `omittedFiles.length > 0`. | Review orchestrator inspects `coverage.omittedFiles`. | Execution marked `INCOMPLETE_COVERAGE`. | Gate **BLOCKS** unconditionally (`status: incomplete`). |
| `CAPABILITY_FORGERY` | Object presented to gate was not minted into `trustedConsensusRegistry`. | `assertTrustedConsensus` fails WeakSet lookup. | Throws `UNTRUSTED_CONSENSUS` error. | Gate **BLOCKS** unconditionally. |
| `SYBIL_DUPLICATION` | Quorum result contains duplicate report IDs or references identical objects. | Aggregator checks `selectedUniqueIds.size !== selectedReportIds.length` and performs pairwise reference equality check ($\forall k_1 \ne k_2, \text{rawReports}[k_1] \not\equiv \text{rawReports}[k_2]$). | Consensus aborted with `Sybil inflation rejected`. | Gate **BLOCKS** unconditionally. |
| `HETEROGENEITY_COLLISION`| Two sentries resolve to identical canonical vendor family (e.g. `google === google`). | `QuorumPolicies` checks family uniqueness. | Quorum declared reached = false. | Gate **BLOCKS** unconditionally. |

---

## 13. Fail-Closed Semantics

A foundational requirement of Triad-Flow is that adding a third provider must never weaken existing fail-closed guarantees. We now provide formal mathematical and logical proof.

### 13.1 Formal Mathematical Proof of Invariant Fail-Closed Security

#### Definitions:
Let $\mathcal{D}$ represent a candidate code changeset (diff).  
Let $\mathcal{P} = \{ P_{\text{google}}, P_{\text{anthropic}}, P_{\text{openai}} \}$ represent the set of heterogeneous review providers.  
Let $\mathcal{F}(P_i, \mathcal{D})$ denote the set of security findings emitted by provider $P_i$ on diff $\mathcal{D}$.  
Each finding $f \in \mathcal{F}$ has a severity $\text{sev}(f) \in \{ \text{critical}, \text{high}, \text{medium}, \text{low}, \text{info} \}$.  
Let $\mathcal{B}(P_i, \mathcal{D})$ be the blocking indicator for provider $P_i$:
$$\mathcal{B}(P_i, \mathcal{D}) = \begin{cases} 
1 & \text{if } \exists f \in \mathcal{F}(P_i, \mathcal{D}) \text{ such that } \text{sev}(f) \in \{ \text{critical}, \text{high} \} \\
0 & \text{otherwise}
\end{cases}$$

Let $\mathcal{H}(P_i)$ be the health predicate of provider $P_i$, where $\mathcal{H}(P_i) = 1$ if $P_i$ executed cleanly, within timeout, without auth failure, and with 100% diff coverage ($\text{omittedFiles} = \emptyset$); otherwise $\mathcal{H}(P_i) = 0$.

#### Two-Party Baseline Gate Policy ($G_2$):
Under the v2.6 two-party baseline ($P_1 = P_{\text{google}}, P_2 = P_{\text{anthropic}}$), the Gate Decision $G_2(\mathcal{D}) \in \{ \text{APPROVE}, \text{BLOCK} \}$ is defined as:
$$G_2(\mathcal{D}) = \text{APPROVE} \iff \Big( \mathcal{H}(P_1) = 1 \land \mathcal{H}(P_2) = 1 \land \mathcal{B}(P_1, \mathcal{D}) = 0 \land \mathcal{B}(P_2, \mathcal{D}) = 0 \Big)$$
Equivalently, the blocking predicate $\text{Block}_2(\mathcal{D})$ is:
$$\text{Block}_2(\mathcal{D}) \iff \Big( \neg \mathcal{H}(P_1) \lor \neg \mathcal{H}(P_2) \lor \mathcal{B}(P_1, \mathcal{D}) = 1 \lor \mathcal{B}(P_2, \mathcal{D}) = 1 \Big)$$

#### Tri-Party Gate Policy ($G_3$):
Under the RFC-027-02 tri-party specification with providers $\{ P_1, P_2, P_3 \}$, the Gate Decision $G_3(\mathcal{D})$ for nominal $3/3$ operation is defined as:
$$G_3(\mathcal{D}) = \text{APPROVE} \iff \left( \bigwedge_{i=1}^3 \mathcal{H}(P_i) = 1 \right) \land \left( \bigwedge_{i=1}^3 \mathcal{B}(P_i, \mathcal{D}) = 0 \right)$$
That is:
$$\text{Block}_3(\mathcal{D}) \iff \left( \exists i \in \{1, 2, 3\}, \neg \mathcal{H}(P_i) \right) \lor \left( \exists i \in \{1, 2, 3\}, \mathcal{B}(P_i, \mathcal{D}) = 1 \right)$$

#### Proof of Monotonicity (Non-Weakening):
1. **Case 1: Finding Detection Monotonicity**.  
   Suppose a diff $\mathcal{D}$ triggered a block under $G_2$ due to an authentic blocking finding: $\mathcal{B}(P_1, \mathcal{D}) = 1 \lor \mathcal{B}(P_2, \mathcal{D}) = 1$.  
   Under $G_3$, because blocking authority is **solitary** (any single provider reporting a blocker sets $\text{Block}_3 = 1$):
   $$\left( \mathcal{B}(P_1, \mathcal{D}) = 1 \lor \mathcal{B}(P_2, \mathcal{D}) = 1 \right) \implies \left( \exists i \in \{1, 2, 3\}, \mathcal{B}(P_i, \mathcal{D}) = 1 \right) \implies \text{Block}_3(\mathcal{D}) = \text{TRUE}$$
   Therefore, no vulnerability detected by $P_1$ or $P_2$ can ever be unblocked by $P_3$, even if $P_3$ reports zero findings.

2. **Case 2: Novel Vulnerability Detection by Provider 3**.  
   Suppose $P_1$ and $P_2$ both fail to detect a critical flaw ($\mathcal{B}(P_1, \mathcal{D}) = 0, \mathcal{B}(P_2, \mathcal{D}) = 0$), but $P_3$ (OpenAI Codex) identifies it ($\mathcal{B}(P_3, \mathcal{D}) = 1$).  
   Under $G_2$, this diff would have erroneously passed ($G_2 = \text{APPROVE}$).  
   Under $G_3$, because $\mathcal{B}(P_3, \mathcal{D}) = 1$, $\text{Block}_3(\mathcal{D}) = \text{TRUE}$.  
   Hence:
   $$\{ \mathcal{D} \mid \text{Block}_2(\mathcal{D}) \} \subset \{ \mathcal{D} \mid \text{Block}_3(\mathcal{D}) \}$$
   The set of blocked vulnerable diffs is strictly monotonically increasing.

3. **Case 3: Missing Provider Non-Fabrication**.  
   If $P_3$ is unavailable ($\mathcal{H}(P_3) = 0$), $P_3$ is marked `UNAVAILABLE`. It contributes zero synthetic approvals. Under nominal $3/3$ policy, $\neg \mathcal{H}(P_3)$ forces immediate transition to the degraded $2/3$ policy ($Q_2, Q_3, Q_4$). Under degraded $2/3$, the gate reduces exactly to the two available healthy providers $\{ P_a, P_b \}$, which obeys identical fail-closed guarantees to $G_2$:
   $$G_{2/3}(\mathcal{D}) = \text{APPROVE} \iff \Big( \mathcal{H}(P_a) = 1 \land \mathcal{H}(P_b) = 1 \land \mathcal{B}(P_a, \mathcal{D}) = 0 \land \mathcal{B}(P_b, \mathcal{D}) = 0 \Big)$$
   Under no condition does $\neg \mathcal{H}(P_3)$ permit an approval that would have been blocked under two providers.

**Conclusion**: The addition of OpenAI Codex into a tri-party quorum strictly preserves or enhances fail-closed security. It is mathematically impossible for the tri-party quorum to grant approval to code that the two-party engine would have blocked. $\blacksquare$

---

## 14. Security Considerations

1. **Windows Command Injection Immunity (CVE-2024-27980)**:
   By resolving `codex.exe` directly or invoking `node codex.js` with `shell: false`, Triad-Flow completely avoids passing arguments through `cmd.exe`. This eliminates command injection risks associated with Windows batch file parsing.
2. **Deterministic Sandboxing (`--sandbox=read-only`)**:
   Codex execution is strictly constrained. The flag `--sandbox=read-only` is injected into `mandatorySafetyArgs`. The `assembleProviderArgs` function neutralizes any user attempts to pass `--dangerously-bypass-approvals-and-sandbox` or write permissions (`-s workspace-write`).
3. **Secret Scrubbing in Process Environment**:
   Cross-vendor API keys (`ANTHROPIC_API_KEY`, `GEMINI_API_KEY`) and repository tokens (`GITHUB_TOKEN`) are explicitly stripped from child process environments. This ensures an OpenAI subprocess cannot read Anthropic or Google credentials even if it attempts environment inspection.
4. **Side-Channel Output Isolation**:
   Passing `-o <tempFile>` prevents stdout injection attacks where malicious files in the diff attempt to print fake JSON payloads to terminal output.
5. **In-Process WeakSet Capability Isolation**:
   Because `trustedConsensusRegistry` is scoped as a module-private `WeakSet` within `src/core/consensus-state.mjs`, external scripts or malicious plugins cannot manipulate the set, forge capabilities, or inspect registered objects.

---

## 15. Compatibility

1. **Two-Party Backward Compatibility**:
   Existing configurations specifying `policy: "STRICT_HETEROGENEOUS"` continue to execute Google + Anthropic dual sentries with zero changes. The new `QuorumPolicies.TRI_PARTY_HETEROGENEOUS` policy is additive and non-breaking.
2. **Single-Sentry Fast-Path Compatibility**:
   Tier 2/3 changesets ($< 50$ lines of non-security code) retain access to the `SINGLE_SENTRY` fast path, allowing rapid approvals when multi-vendor quorum is not warranted.
3. **Interoperability with RFC-027-01**:
   The prompt schemas, AST context blocks, and diff chunking structures defined in RFC-027-01 feed transparently into Codex via standard input (`stdin: true`), matching the transport expectations of `CliReviewAdapter`.
4. **Interoperability with RFC-027-03**:
   Consensus capabilities minted under tri-party quorum emit audit receipts conforming to `audit-receipt.json`, which RFC-027-03 binds into cryptographic release attestations and SBOM metadata.

---

## 16. Migration Plan

The transition to Tri-Party Quorum follows a phased, zero-risk rollout:

| Phase | Milestone | Scope of Work | Acceptance Verification Gate |
|---|---|---|---|
| **Phase 1** | v2.7-Alpha | Implement `CodexProviderProfile` and Native Binary Resolution in `src/adapters/provider-profiles.mjs`. | All 7 points of Provider Readiness Contract pass for Codex in `doctor` check. |
| **Phase 2** | v2.7-Beta1 | Implement `-o <tempFile>` output isolation in `CliReviewAdapter`. Add offline mock tests in `tests/provider-codex.test.mjs`. | 100% clean JSON extraction verified without stdout log contamination. |
| **Phase 3** | v2.7-Beta2 | Implement `QuorumPolicies.TRI_PARTY_HETEROGENEOUS` in `src/core/loop.mjs`. Add unit test suite `tests/quorum-tri-party.test.mjs`. | Full truth tables (Q-01..Q-08 and V-01..V-10) pass contract testing. |
| **Phase 4** | v2.7-RC | Enable Tri-Party Quorum as default policy for Tier 1 changesets when 3 providers pass readiness. | Live trial on non-corpus changesets verifies 0 false gate approvals. |
| **Phase 5** | v2.7.0 | Final release. Promote `tri-party` as the standard production review engine. | Milestone closure and branch protection integration. |

---

## 17. Rollback Plan

If unexpected regressions, model API deprecations, or platform incompatibilities arise during deployment:
1. **Immediate CLI Flag Override**: Users can immediately force two-party mode by supplying `--quorum=strict-heterogeneous` or `--providers=agy,claude`.
2. **Configuration File Pinning**: Pinning `quorumPolicy: "STRICT_HETEROGENEOUS"` in `triad-flow.config.mjs` disables Codex dispatch at the router level without requiring software downgrades.
3. **Automatic Fallback Degradation**: If Codex CLI is uninstalled or its API key is revoked, the state machine automatically triggers State Q-02 (`2_OF_3_DEGRADED`), seamlessly routing reviews through Google and Anthropic dual sentries without pipeline interruption.

---

## 18. Test Contracts

All future implementations of RFC-027-02 must be validated against the following concrete, additive test contracts:

### 18.1 Provider Profile & Binary Resolution Tests (`tests/provider-codex.test.mjs`)
1. `test_codex_profile_canonical_definition`: Asserts `PROVIDER_PROFILES.codex` contains `family: "openai"`, `model: "gpt-6.1-sol"`, `supportsStdin: true`, and mandatory `--sandbox=read-only`.
2. `test_codex_native_binary_resolution_windows`: Simulates Windows environment and asserts that `resolveProviderProfile("codex")` resolves to `codex.exe` without invoking `.cmd` wrappers.
3. `test_codex_mandatory_arg_neutralization`: Asserts that passing hostile args (e.g. `["--dangerously-bypass-approvals-and-sandbox", "-s", "workspace-write"]`) via user args is stripped and neutralized.
4. `test_codex_tempfile_isolation`: Executes mock CLI emitting noisy stdout banners and verifies that `CliReviewAdapter` reads pure JSON exclusively from `-o <tempFile>`.

### 18.2 Tri-Party Quorum & Consensus Tests (`tests/quorum-tri-party.test.mjs`)
1. `test_tri_party_quorum_formation_truth_table`: Executes test cases Q-01 through Q-08 from Section 11.2, verifying expected `quorumReached` and topology.
2. `test_tri_party_solitary_blocker_veto`: Executes test cases V-02, V-03, V-04 where a single provider reports Critical/High; asserts that verdict is `needs-attention` and gate decision is `block`.
3. `test_tri_party_corroboration_accumulation`: Executes test case V-05 and V-06; asserts that `corroborations` is accurately set to 2 and 3 respectively.
4. `test_tri_party_severity_preservation`: Executes test case V-10 where providers report Medium, High, and Low for the same defect; asserts that consensus severity is preserved at `high`.
5. `test_tri_party_fallback_degradation_tier1_rejects_single_sentry`: Asserts that states Q-05A, Q-06A, Q-07A on Tier 1 changesets abort with `quorumReached: false` and gate `block`.
6. `test_tri_party_fallback_degradation_tier2_permits_single_sentry`: Asserts that states Q-05B, Q-06B, Q-07B on Tier 2/3 changesets successfully permit single sentry evaluation.

### 18.3 In-Process Capability & Tamper Resistance Tests (`tests/capability-tri-party.test.mjs`)
1. `test_trusted_consensus_weakset_isolation`: Asserts that forged consensus objects return `isTrustedConsensus(obj) === false` and trigger gate `block`.
2. `test_sybil_report_id_rejection`: Asserts that submitting duplicate report IDs under tri-party quorum aborts with Sybil inflation error.
3. `test_disagreement_ledger_generation`: Asserts that solitary blockers and severity divergences generate structured Disagreement Ledger entries with full locator accounting.

---

## 19. Evidence & Audit Requirements

Every execution under Tri-Party Quorum must persist auditable, cryptographically verifiable records:
1. **Audit Receipt (`audit-receipt.json`)**:
   - Contains SHA-256 digests of all input diffs, provider prompt packages, and raw provider outputs.
   - Encodes participating provider families, model versions (`gemini-3.8-flash`, `claude-5.5-sonnet`, `gpt-6.1-sol`), and quorum topology.
   - Records the invocation nonce generated by the consensus engine.
2. **Disagreement Ledger (`disagreement-ledger.json`)**:
   - Persists all dissenting evaluations, solitary blockers, and locator variances across sentries.
3. **Non-Interference with Frozen Corpus Baseline**:
   - All evaluation runs are written to segregated run directories (`evidence-runs/TF-EVIDENCE-0007+`).
   - The authoritative v2.6 baseline `TF-EVIDENCE-0006` and frozen benchmark `TF-OSS-v1` remain byte-for-byte immutable.

---

## 20. Acceptance Criteria

An implementation of RFC-027-02 is accepted if and only if all of the following criteria are satisfied:

- [ ] **Codex Provider Profile**: `PROVIDER_PROFILES.codex` is frozen, canonical, and specifies `model: "gpt-6.1-sol"`, `supportsStdin: true`, and `mandatorySafetyArgs: ["--sandbox=read-only"]`.
- [ ] **Native Resolution**: Windows binary resolution identifies `codex.exe` and executes with `{ shell: false }`, completely eliminating Node.js CVE-2024-27980 `EINVAL` errors and `DEP0190` warnings.
- [ ] **Output Isolation**: Codex CLI adapter extracts pure JSON via `-o <tempFile>`, achieving 0 parse failures due to CLI banner or hook log contamination.
- [ ] **Truth Table Conformance**: All 8 quorum formation states (Q-01..Q-08) and 10 finding evaluation states (V-01..V-10) pass deterministic contract tests.
- [ ] **Solitary Blocking Invariant**: Any single sentry reporting an authentic Critical or High finding forces verdict `needs-attention` and gate `block`.
- [ ] **Severity Preservation**: Finding deduplication assigns $\max(\text{severity})$ across reporting sentries.
- [ ] **Degradation Bounds**: 2/3 fallback preserves vendor diversity; 1/3 fallback is strictly forbidden on Tier 1 high-risk changesets.
- [ ] **Zero Runtime Dependencies**: `package.json` contains zero new entries under `dependencies`.
- [ ] **Regression Invariance**: Existing 404 test baseline passes without modification, deletion, or skip conversion.
- [ ] **Corpus Immutability**: `TF-OSS-v1` corpus digest matches exactly:
  `sha256:47ed3ce44878b77572005358a16511e3f0900dda11d14443e6a2a84baf501625`.

---

## 21. Open Questions

1. **Dynamic Timeout Scaling for Multi-Turn Verifier Passes**:
   When all three providers participate in multi-pass reviews, should the timeout budget be uniform (e.g. 90s per provider in parallel) or dynamically adjusted based on changeset line count?
2. **Streaming Diff Ingestion for Large Changesets in agy**:
   While `claude` and `codex` support stdin streaming, `agy` currently requires argv input (`supportsStdin: false`). In Phase 3, should Triad-Flow propose an upstream patch or wrapper for `agy` to accept diffs via stdin or a temporary file to bypass Windows 32KB argv limits?
3. **Disagreement Ledger Weighting in Automated Remediation**:
   When solitary blockers occur (1 provider blocks, 2 approve), should automated remediation workflows prioritize patches for solitary blockers with equal urgency to unanimous blockers, or should they require an interactive developer confirmation step?
