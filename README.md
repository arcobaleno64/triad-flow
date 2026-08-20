<p align="center">
  <img src="assets/banner.jpg" alt="Triad-Flow Banner" width="800">
</p>

# Triad-Flow ⚡

> **Adaptive Multi-Agent Closed-Loop Control Architecture**  
> *A lean, high-velocity, zero-bureaucracy agentic workflow for resilient software delivery across Claude, Gemini, and OpenAI Codex.*

---

## 🌐 What is Triad-Flow?

Triad-Flow replaces prompt-bloated, schema-heavy agent processes with an industrial-grade **Graph + Loop + Harness Engineering Triad**:

1. **🌐 Graph Engineering (拓撲路由)**:
   - Automatically evaluates Diff complexity and file risk tiers.
   - Small edits (<50 lines) route to a **Single-Agent Fast Path** (zero token waste).
   - High-risk security changes or large PRs fan out into **Parallel Subagent Swarms**.
2. **🔄 Loop Engineering (控制閉環)**:
   - Orchestrates multi-model heterogeneous consensus: **Claude (Master Driver)** ➔ **Gemini (Macro Radar)** ➔ **OpenAI Codex (Micro Arbiter)**.
   - Injects formal counter-examples directly into the prompt to drive **automated self-healing remediation (OODA Loop)** with SHA-256 state-hash livelock prevention.
3. **🛡️ Harness Engineering (安全夾具)**:
   - Enforces deterministic security scaffolding: 9-pattern secret redaction, sibling path traversal sandboxing, Quorum-enforced Fail-Closed gates, and OASIS SARIF 2.1.0 compliance.

---

## ⚡ Quickstart

```bash
# 1. Install dependencies
npm install

# 2. Run test suite (15 unit tests)
npm test

# 3. Check environment health
npm run doctor

# 4. Run scale-adaptive review
npm run review

# 5. Run end-to-end autonomous software factory pipeline
node src/cli.mjs factory
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
   npx triad-flow review
   ```
3. **(Optional) Install Git Pre-Commit Hook:**
   ```bash
   echo "npx triad-flow review" > .git/hooks/pre-commit
   ```

### B. Brand New Projects (1-Minute Bootstrap)

```bash
mkdir my-new-project && cd my-new-project
git init
# Copy the CLAUDE.md template above and start coding with Claude Code
claude
```

---

## 🤖 Tri-Agent Consensus Matrix

| Role | Provider / Engine | Superpower | Focus Area |
|---|---|---|---|
| **Master Driver** | **Anthropic Claude Code** | Code Generation & OODA Self-Healing | Implementation, Patch synthesis, CLI driver |
| **Macro Sentry** | **Google Gemini 3.7 / 4** | 2M Context Whole-Repo Radar | Cross-module interface drift, CI/CD skew, call-chain impact |
| **Micro Arbiter** | **OpenAI Codex / o3-pro** | Deep Test-Time Compute (CoT) | Concurrency race conditions, boundary fuzzing, formal counter-examples |

---

## 📊 30-Second Engineering ROI Comparison

| Dimension | Single Model (`claude --review`) | Static Linters (Sonar / ESLint) | **Triad-Flow Closed-Loop** |
|---|---|---|---|
| **Macro Call-Chain** | Blind to distant caller regressions (>10 files) | AST-only, zero architectural comprehension | **Gemini 2M Context Radar**: Scans 50+ callers and CI/CD drift |
| **Deep Concurrency** | Glances over complex state-machine races | Cannot simulate multi-thread runtime interleaving | **OpenAI o3/Codex CoT**: Generates executable counter-examples |
| **Token Efficiency** | Flat high token cost on all diffs | Zero token, but high false alarms & no fixes | **Scale-Adaptive Graph**: 80% small PRs stay single-agent (0 overhead) |
| **Closed-Loop Fix** | Verbal suggestions requiring human edits | Reports errors only without auto-healing | **OODA Loop Controller**: Generates verified patches & SARIF 2.1.0 |

---

## 🛡️ Cybersecurity & AI Safety Compliance

- **OASIS SARIF 2.1.0**: Native compliance, seamlessly ingested by GitHub Advanced Security & SonarQube.
- **OWASP Top 10 for LLM (2025/2026)**:
  - `LLM01: Prompt Injection` — XML Nonce sandbox isolation & JSON schema constraints.
  - `LLM02: Sensitive Info Disclosure` — 9-pattern redaction (OpenAI `sk-proj-`, GitHub `github_pat_`, JWT, PEM keys).
  - `LLM06: Excessive Agency` — `OodaLoopController` 3-iteration livelock circuit breaker.
- **NIST SSDF (SP 800-218) & OpenSSF**: Zero-trust sibling directory path isolation & Quorum-enforced Fail-Closed gates.
- **IEEE 352 / N-Version**: Heterogeneous multi-model consensus defense against Common-Mode Failures.

---

## 🏛️ The 8 Engineering Pillars Matrix

| Pillar | Implementation File | Key Mechanism |
|---|---|---|
| 🛡️ **1. Guardrail & Harness** | [`src/core/harness.mjs`](src/core/harness.mjs) | 9 Secret patterns, Sibling sandbox, Quorum gate, SARIF 2.1.0 |
| 🌐 **2. Graph Engineering** | [`src/core/router.mjs`](src/core/router.mjs) | Scale-adaptive routing, test file auto-downgrade (saves 80% tokens) |
| 🔄 **3. Loop Engineering** | [`src/core/loop.mjs`](src/core/loop.mjs) | Severity Escalation Merge, OODA Controller, SHA-256 state-hash circuit breaker |
| 🔭 **4. Observability** | [`src/core/telemetry.mjs`](src/core/telemetry.mjs) | Ultra-lean (35 lines) OpenTelemetry distributed trace & span tracking |
| 🎯 **5. Eval & Benchmark** | [`src/core/eval.mjs`](src/core/eval.mjs) | Mutation score verification & held-out golden CVE recall testing |
| 🧠 **6. Context Budgeting** | [`src/core/router.mjs`](src/core/router.mjs) | 3-Tier risk allocation (0% truncation on Auth/CI files) |
| 📦 **7. Sandbox Isolation** | [`src/core/harness.mjs`](src/core/harness.mjs) | Zero-trust workspace root confinement |
| ⚖️ **8. Constitutional** | [`CLAUDE.md`](CLAUDE.md) | Lean, non-negotiable invariant rules (<50 lines) |

---

## 📄 License

Apache-2.0 © arcobaleno64
