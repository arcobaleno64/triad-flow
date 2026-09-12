# Security Policy & Trust Model

Triad-Flow is a local, dependency-free CLI. It reads a repository's git working
state, runs a consensus gate over sentry reports, and emits SARIF. The core engine
performs no direct network egress, no remote scanning, and no code mutation. However,
external CLI child processes invoked via adapters (e.g. `CliReviewAdapter`) execute with the caller's
OS privileges and may egress to their respective provider APIs. Triad-Flow enforces a strict read-only
protocol and prompt constraints, but does not provide an OS-level sandbox.

## 1. What this tool guarantees

### 1.1 Fail-closed gate
`evaluateGateDecision` (`src/core/harness.mjs:261`) returns `block` — never
`approve` — whenever any of the following holds:

- the consensus object fails the trusted-capability check (`UNTRUSTED_CONSENSUS`);
- quorum was not reached, or the verdict is `error`;
- one or more findings are `critical` or `high` severity;
- `--strict` is set and any finding at all remains.

A block maps to exit code `1` (`GATE_BLOCKED`, `src/cli.mjs:14`). There is no
flag that converts a block into a pass.

### 1.2 Quorum cannot be forged
`validateConsensusSemantics` (`src/core/consensus-state.mjs`) rejects a report
whose `verdict` is `approve` while `quorumReached` is `false` (C-07), and one
whose `verdict` is `error` while claiming a clean quorum with no error reason
(C-08). `quorumReached` must be a boolean; a truthy string will not pass (C-01).
The quorum policies themselves (`src/core/loop.mjs`) require healthy sentries:
`STRICT_HETEROGENEOUS` needs both a macro and a micro sentry healthy,
`SINGLE_SENTRY` needs the designated role, `K_OF_N` needs `requiredCount`.

### 1.3 The autonomous factory never runs unconfigured
`runFactoryPipeline` (`src/core/factory.mjs`) halts without mutating code unless
`remediator`, `macroSentry` and `microSentry` adapters are all supplied. No
execution path for configured adapters exists yet, so the pipeline currently
halts in every case. It reports the halt rather than reporting a successful run.

## 2. What this tool does NOT guarantee

- **No OS-level sandbox.** Triad-Flow does not isolate the repository or child processes
  with OS containerization. It runs git commands and external CLI tools against the working
  tree with the caller's own OS privileges and environment; a hostile `.git/config`
  (`diff.external`, textconv, hooks) is not neutralised. Do not point it at an untrusted repository.
- **Tested redaction and path-safety primitives.** Triad-Flow provides tested redaction
  and path-safety primitives in its harness, but findings, SARIF output and console output
  are emitted based on sentry responses. Sentry child processes inspect diff content under
  caller permissions.
- **No supply-chain attestation.** There is no signed release artifact and no
  integrity manifest.
- **Sentry quality is out of scope.** The gate decides on the reports it is
  given. It cannot detect a sentry that reports nothing because it looked at
  nothing; `quorumReached` attests liveness, not coverage.

## 3. Reporting a vulnerability

Do **not** open a public GitHub issue.

- **Preferred**: [GitHub Security Advisories](https://github.com/arcobaleno64/triad-flow/security/advisories/new).
- **Email**: <arcobaleno830623@gmail.com>. Monitored by one maintainer, not a team inbox.

### Response expectations
- Initial response: within 48 hours.
- Status update: within 7 business days.
- Fix: released in a patch release.

## 4. Supported versions

Only the current MINOR line is supported. Update this table on every MINOR bump.

| Version | Supported |
|---|---|
| 2.0.x | :white_check_mark: |
| < 2.0.0 | :x: |
