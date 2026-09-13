<p align="center">
  <img src="assets/banner.jpg" alt="Triad-Flow Banner" width="800">
</p>

# Triad-Flow ⚡

> **Adaptive Multi-Agent Closed-Loop Control Architecture**  
> *A deterministic safety core, scale-adaptive topology routing, and fail-closed consensus gate for multi-model code review and OODA control loops.*

---

## 🌐 What is Triad-Flow?

Triad-Flow replaces prompt-bloated, schema-heavy agent processes with an industrial-grade **Graph + Loop + Harness Engineering Triad**:

1. **🌐 Graph Engineering (拓撲路由)**:
   - Automatically evaluates Diff complexity, lockfile changes, and file risk tiers.
   - Small edits (<50 lines) route to a **Single-Agent Fast Path** (zero token waste).
   - High-risk security changes (including security-sensitive tests) or large PRs fan out into **Parallel Subagent Swarms**.
2. **🔄 Loop Engineering (控制閉環)**:
   - Heterogeneous review consensus interface: **Claude (Master Driver)** + **Gemini (Macro Radar)** + **OpenAI Codex (Micro Arbiter)** *(Target architecture / pluggable provider adapters)*.
   - Enforces **Strict Heterogeneous Quorum** (both sentries must be healthy) with Severity Escalation Deduplication.
   - **OODA Loop Controller Primitive**: Jaccard semantic stagnation & patch cycle circuit breaking *(Remediator synthesis fails closed pending adapter configuration)*.
3. **🛡️ Harness Engineering (安全夾具)**:
   - Provides tested redaction and path-safety primitives: multi-pattern secret redaction, symlink-aware filesystem traversal boundary checks, Quorum-enforced Fail-Closed gates, and SARIF 2.1.0 report generation.

---

## ⚡ Quickstart

```bash
# 1. Run test suite (including 18+ adversarial regression tests)
npm test

# 2. Check environment & capability health
npm run doctor

# 3. Run deterministic local simulation
npm run demo

# 4. Run scale-adaptive review on real Git diff
npm run review

# 5. Advanced review options
triad-flow review --base=origin/main --head=HEAD   # Review committed PR range
triad-flow review --staged                         # Review staged changes only
triad-flow review --format=sarif                   # Emit OASIS SARIF 2.1.0
triad-flow review --format=json --report=run.json  # Emit auditable review-run.json

# 6. Real benchmark evaluation (TF-RBC-v0)
npm run bench:real                                 # Run 15-case offline benchmark evaluation
npm run bench:real -- --limit=3                    # Evaluate subset of cases
npm run bench:real -- --live                       # Run against live local AI CLI (e.g. agy)
```

---

## 🚀 How to Adopt in Your Projects

### A. Existing Projects (3-Minute Zero-Friction Setup)

1. **Add `CLAUDE.md` to your project root:**
   ```markdown
   # Autonomous Sentry Protocol
   1. **Pre-flight Check**: Execute `!triad-flow review` before finalizing code.
   2. **Auto-Remediation (OODA)**: On `needs-attention`, apply counter-example patches and re-test until green.
   3. **Macro Delegation**: Use Gemini 2M Context for whole-repo (>10 files) caller audits.
   ```
2. **Run baseline review:**
   ```bash
   npx @arcobaleno64/triad-flow review
   ```

---

## 🤖 Tri-Agent Consensus Matrix (Target Architecture)

| Role | Provider / Engine | Superpower | Focus Area |
|---|---|---|---|
| **Master Driver** | **Anthropic Claude Code** | Code Generation & OODA Self-Healing | Implementation, Patch synthesis, CLI driver |
| **Macro Sentry** | **Google Gemini** | 2M Context Whole-Repo Radar | Cross-module interface drift, CI/CD skew, call-chain impact |
| **Micro Arbiter** | **OpenAI Codex / o3** | Deep Test-Time Compute (CoT) | Concurrency race conditions, boundary fuzzing, formal counter-examples |

---

## 📊 30-Second Engineering ROI Comparison (Design Matrix)

| Dimension | Single Model (`claude --review`) | Static Linters (Sonar / ESLint) | **Triad-Flow Closed-Loop** |
|---|---|---|---|
| **Macro Call-Chain** | Blind to distant caller regressions (>10 files) | AST-only, zero architectural comprehension | **Gemini 2M Context Radar**: Whole-repo multi-file audit and CI/CD drift analysis *(Planned)* |
| **Deep Concurrency** | Glances over complex state-machine races | Cannot simulate multi-thread runtime interleaving | **OpenAI o3/Codex CoT**: Deep test-time verification & formal counter-examples *(Planned)* |
| **Token Efficiency** | Flat high token cost on all diffs | Zero token, but high false alarms & no fixes | **Scale-Adaptive Graph**: Small diffs (<50 lines) route to single-agent fast path (0 overhead) |
| **Closed-Loop Fix** | Verbal suggestions requiring human edits | Reports errors only without auto-healing | **OODA Loop Controller**: Generates SARIF 2.1.0 & manages remediation stagnation circuit breaking |

---

## 🛡️ Cybersecurity & AI Safety Architecture

- **Network Egress & OS Privileges**: Triad-Flow core performs no direct network egress and no repository code mutation. External CLI child processes (`CliReviewAdapter`) run under caller OS privileges (read-only protocol via prompts and flags, not an OS-level kernel sandbox) and may contact their configured provider endpoints.
- **SARIF 2.1.0**: Standardized JSON report generation with deduplicated driver rules and URI-safe artifact locations.
- **OWASP Top 10 for LLM**:
  - `LLM02: Sensitive Info Disclosure` — Multi-pattern redaction (Google, OpenAI, Anthropic, GitHub, AWS, JWT, PEM keys).
  - `LLM06: Excessive Agency` — `OodaLoopController` 3-iteration livelock, Jaccard semantic stagnation detection, and patch cycle circuit breaker.
- **NIST SSDF (SP 800-218) & OpenSSF**: Physical symlink and sibling path traversal defense with Quorum-enforced Fail-Closed gates.
- **IEEE 352 / N-Version**: Heterogeneous multi-model consensus defense against Common-Mode Failures.

---

## 🏛️ Core Architecture & Capability Matrix

### Core Pillars (Active Safety Core)

| Pillar | Implementation File | Key Mechanism | Status |
|---|---|---|---|
| 🛡️ **Harness Engineering** | [`src/core/harness.mjs`](src/core/harness.mjs) | Fail-closed gate, SARIF 2.1.0 validation, secret redaction primitives | **Active Core** |
| 🌐 **Graph Engineering** | [`src/core/graph-router.mjs`](src/core/graph-router.mjs) | Scale-adaptive routing, multi-tier risk classification, binary change escalation | **Active Core** |
| 🔄 **Loop Engineering** | [`src/core/loop.mjs`](src/core/loop.mjs) | Quorum verification, distinct-source corroboration, severity escalation deduplication | **Active Core** |

### Supporting Modules

| Module | Implementation File | Role | Status |
|---|---|---|---|
| 📁 **Git Collector** | [`src/core/git-collector.mjs`](src/core/git-collector.mjs) | Canonical ChangeSet, sha256 digest, revision-range (`--base`/`--head`) & staged capture | Wired to CLI |
| 🔌 **Review Adapters** | [`src/adapters/cli-transport.mjs`](src/adapters/cli-transport.mjs), [`src/adapters/provider-profiles.mjs`](src/adapters/provider-profiles.mjs), [`src/adapters/provider-contract.mjs`](src/adapters/provider-contract.mjs) | Read-only CLI transport (`CliReviewAdapter`), canonical provider profiles (agy, claude), Default-Deny & high-risk dual sentry gate | Wired to CLI |
| 🩺 **Capability Doctor** | [`src/core/doctor.mjs`](src/core/doctor.mjs) | Probes local AI CLI binaries (agy, claude, codex), evaluates Heterogeneous Quorum readiness, emits text or JSON | Wired to CLI |
| 📝 **Run Auditing** | [`src/core/review-run-report.mjs`](src/core/review-run-report.mjs) | Canonical `review-run.json` audit schema, 6 unambiguous run statuses, CI exit code preservation | Wired to CLI |
| 🎯 **Eval & Benchmark** | [`src/core/scoring.mjs`](src/core/scoring.mjs), [`src/core/benchmark-pilot.mjs`](src/core/benchmark-pilot.mjs), [`src/core/real-benchmark-runner.mjs`](src/core/real-benchmark-runner.mjs) | 1-to-1 instance matching, TF-RBC-v0 15-case real benchmark corpus & runner, 3-way Pareto comparison | Active Framework |
| 🔭 **Telemetry** | [`src/core/telemetry.mjs`](src/core/telemetry.mjs) | Lean in-process span tracer and latency profiler | Demo / Simulation |
| 🏭 **Autonomous Factory** | [`src/core/factory.mjs`](src/core/factory.mjs) | Autonomous remediation pipeline pre-flight & fail-closed gate | Execution Skeleton (Frozen) |

---

## 📄 License

Apache-2.0 © arcobaleno64
