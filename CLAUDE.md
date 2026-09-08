# Triad-Flow

Adaptive Multi-Agent Closed-Loop Control Architecture for resilient code generation, heterogeneous adversarial review, and automated self-healing.

## 1. Core Principles (Engineering Triad)

1. **Graph Engineering (拓撲路由)**:
   - Dynamic scale-adaptive routing: small diffs (<50 lines) route directly to single-agent fast path; large PRs, lockfiles, or Auth/CI changes fan out to specialized subagents.
2. **Loop Engineering (控制閉環)**:
   - Heterogeneous Sentry Quorum: requires both Macro Sentry (Gemini) and Micro Arbiter (OpenAI) to be healthy.
   - OODA remediation control with semantic stagnation/livelock circuit breaker.
3. **Harness Engineering (安全夾具)**:
   - Fail-closed quorum gate, multi-pattern secret redaction, symlink-aware filesystem sandbox, and SARIF 2.1.0 report generation.

## 2. Guardrails (Occam's Razor & Truthfulness)

- **Zero Fabricated Claims**: Production review never injects fake findings, mock diffs, or unperformed merges. Simulations belong strictly in `triad-flow demo`.
- **Strict Fail-Closed Quorum**: Single-sentry error or timeout triggers quorum failure and gate block.
- **Evidence First**: Verify before proposing changes. Always run `npm test` before declaring completion.
- **Token Efficiency**: Context is reserved for business logic and adversarial review, not process boilerplate.

## 3. Common Commands

```bash
# Run test suite
npm test

# Run deterministic local simulation
npm run demo

# Run scale-adaptive review on real Git diff
npm run review

# Run environment & capability doctor
npm run doctor
```
