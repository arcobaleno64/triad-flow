# Triad-Flow ⚡

> **Adaptive Multi-Agent Closed-Loop Control Architecture**  
> *A lean, high-velocity, zero-bureaucracy agentic workflow for resilient software delivery across Claude, Gemini, and OpenAI Codex.*

---

## What is Triad-Flow?

Triad-Flow replaces prompt-bloated, schema-heavy agent processes with a modern **Graph + Loop + Harness Engineering Triad**:

1. **🌐 Graph Engineering (拓撲路由)**:
   - Evaluates Diff complexity and security risk automatically.
   - Small edits (<50 lines) route to a **Single-Agent Fast Path** (zero token waste).
   - Large refactors or Auth/CI changes fan out into **Parallel Subagent Swarms**.
2. **🔄 Loop Engineering (控制閉環)**:
   - Orchestrates multi-model heterogeneous consensus: **Claude (Master Driver)** ➔ **Gemini (Macro Radar)** ➔ **OpenAI Codex (Micro Arbiter)**.
   - Injects formal counter-examples directly into the prompt to drive **automated self-healing remediation**.
3. **🛡️ Harness Engineering (安全夾具)**:
   - Enforces deterministic security scaffolding: Secret Redaction, Fail-Open/Closed Gates, and OASIS SARIF 2.1.0 output for CI/CD integration.

---

## Quickstart

```bash
# 1. Install dependencies
npm install

# 2. Run test suite
npm test

# 3. Check environment health
npm run doctor

# 4. Run scale-adaptive review
npm run review
```

---

## Tri-Agent Consensus Matrix

| Role | Provider / Engine | Superpower | Focus Area |
|---|---|---|---|
| **Master Driver** | **Anthropic Claude Code** | Code Generation & OODA Self-Healing | Implementation, Patch synthesis, CLI driver |
| **Macro Sentry** | **Google Gemini 3.7 / 4** | 2M Context Whole-Repo Radar | Cross-module interface drift, CI/CD skew, call-chain impact |
| **Micro Arbiter** | **OpenAI Codex / o3-pro** | Deep Test-Time Compute (CoT) | Concurrency race conditions, boundary fuzzing, formal counter-examples |

---

## License

Apache-2.0
