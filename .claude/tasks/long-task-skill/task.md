# Task: long-task skill

- **Task**: Adapt the seven-layer long-task harness prompt (@beamnxw) into a triad-flow project skill; add a one-line pointer in CLAUDE.md.
- **Output**: `.claude/skills/long-task/SKILL.md`, `CLAUDE.md` (pointer only), this directory (`task.md`, `checks.md`, `progress.md`).
- **Checks**: see `checks.md` (written before the first edit).
- **Sources**:
  - Harness prompt image supplied by the user in session (2026-10-08). Credits: prompt by @beamnxw; inspired by https://github.com/karpathy/autoresearch; seven-layer adaptation from https://x.com/beamnxw/status/2107522996046905797. States "Not written or endorsed by Andrej Karpathy." Links not opened; taken from the image footer.
  - Skill frontmatter format: https://code.claude.com/docs/en/skills (checked 2026-10-08): `.claude/skills/<name>/SKILL.md`, `description` recommended, `argument-hint` supported, `$ARGUMENTS` substituted.
  - Repo facts: `CLAUDE.md`, `package.json`, `.gitignore`, `src/cli.mjs` (review fails closed without sentry commands), `src/core/doctor.mjs`, `scripts/record-cycle.mjs`, `docs/roadmap/v2.7-milestone-roadmap.md` (frozen `TF-OSS-v1`), `docs/rfc/RFC-027-01-*.md` (frozen evidence).
- **Scope**: `.claude/skills/long-task/`, `.claude/tasks/long-task-skill/`, `CLAUDE.md`. No `src/`, `tests/`, `docs/`, README, or CHANGELOG edits.
- **Limit**: this session; one commit on `claude/new-session-u9cjqn`.
- **Decision (user, 2026-10-08)**: skill, not a full CLAUDE.md merge, to respect the CLAUDE.md Token Efficiency guardrail.
