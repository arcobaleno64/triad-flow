# Council-Forge 2.0 (Lean Architecture)

Adaptive Multi-Agent Closed-Loop Control Architecture for resilient code generation and adversarial review.

## 1. Core Principles (Engineering Triad)

1. **Graph Engineering (拓撲路由)**:
   - Dynamic scale-adaptive routing: small diffs (<50 lines) route directly to single-agent fast path; large PRs or Auth/CI changes fan out to specialized subagents.
2. **Loop Engineering (控制閉環)**:
   - Closed-loop OODA self-healing: Master Driver (Claude) ➔ Macro Sentry (Gemini) ➔ Micro Arbiter (OpenAI) ➔ Auto-remediation patch ➔ Green gate exit.
3. **Harness Engineering (安全夾具)**:
   - Fail-Open/Closed dual-mode gate, secret masking (`secrets`), path traversal sandboxing, and OASIS SARIF 2.1.0 compliance.

## 2. Guardrails (Occam's Razor & Chesterton's Fence)

- **Zero Schema Bureaucracy**: Do NOT create manual Markdown schemas or state machines. Trust Git commits, tests, and SARIF output.
- **Evidence First**: Verify before proposing changes. Always run `npm test` before declaring completion.
- **Token Efficiency**: 90% of context must be reserved for business logic and adversarial review, not process boilerplate.

## 3. Common Commands

```bash
# Run test suite
npm test

# Run scale-adaptive review
npm run review

# Run environment health check
npm run doctor
```
