# Progress: long-task skill

Task: Adapt the seven-layer harness prompt (@beamnxw) into the project skill `long-task`; CLAUDE.md gets a pointer only (user chose skill over a full CLAUDE.md merge, 2026-10-08).

Outputs:
- `.claude/skills/long-task/SKILL.md`
- `CLAUDE.md` (Guardrails → **Long Tasks**, 1 line)
- `.claude/tasks/long-task-skill/{task.md,checks.md,progress.md}`

Completed:
- Baseline at `9886cb8` (Node v22.22.0): `npm test` → 679 tests, 676 pass, 0 fail, 3 skipped.
- Skill written; second-pass review against the prompt image fixed 3 coverage gaps and 1 inaccurate frozen-file claim (see `checks.md`).
- After change: `npm test` → 679 tests, 676 pass, 0 fail, 3 skipped. C1–C9 pass, C10 unresolved.

Decisions:
- Skill, not CLAUDE.md merge → CLAUDE.md Token Efficiency guardrail; skill body loads only on invocation.
- State dir `.claude/tasks/<slug>/`, committed on the working branch → cloud containers are ephemeral; `.agents/` and `scratch/` are git-ignored so they would not survive.
- Model invocation left enabled (no `disable-model-invocation`) → the CLAUDE.md pointer tells agents to use it for long tasks.
- Wording adapted rather than copied verbatim, with attribution → prompt is @beamnxw's original wording.
- Not changed: `src/`, `tests/`, `docs/`, README, CHANGELOG (out of Scope; `.claude/` is not in the npm `files` list).

Open issues:
- C10: skill discovery not yet observed in a fresh session.
- Footer links ([1], [2]) were copied from the image and not opened.
- Whether `.claude/tasks/long-task-skill/` should remain after merge to `main` is the user's call.

Next action: open a new session on `claude/new-session-u9cjqn`, type `/long-task`, and confirm the skill appears and loads; record the result in C10.
