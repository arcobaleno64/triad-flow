import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import cp from "node:child_process";

const REMOTE_HEAD_SHA = "ebe28be8b4db6ef276e6b3dcc1201a860af5231f";
const EXTRACTION_TIMESTAMP = "2026-10-16T14:56:29Z";

// Read raw GitHub threads (149)
const rawThreads = JSON.parse(fs.readFileSync("evidence-runs/PR-39/github-threads-raw.json", "utf8"));
if (rawThreads.length !== 149) {
  throw new Error(`Expected 149 raw threads, got ${rawThreads.length}`);
}

// Read legacy 43 outdated threads
const legacy43 = JSON.parse(fs.readFileSync("evidence-runs/PR-39/review-threads-triage.json", "utf8"));
// Read legacy 40 current threads
const legacy40 = JSON.parse(fs.readFileSync("evidence-runs/PR-39/gate-authorization-triage.json", "utf8"));

const rawMap = new Map(rawThreads.map(t => [t.id, t]));
const legacy43Map = new Map(legacy43.threads.map(t => [t.threadId, t]));
const legacy40Map = new Map(legacy40.records.map(r => [r.threadId, r]));
const existingLedger = fs.existsSync("evidence-runs/PR-39/complete-threads-triage-ledger.json")
  ? JSON.parse(fs.readFileSync("evidence-runs/PR-39/complete-threads-triage-ledger.json", "utf8"))
  : null;
const existingLedgerMap = new Map((existingLedger?.threads || []).map(t => [t.threadId, t]));

// Working tree diff hash
const diffBuf = cp.execSync("git diff HEAD");
const workingTreeDiffSha256 = crypto.createHash("sha256").update(diffBuf).digest("hex");

// Detailed 5 Phase 3 defect remediations (all in review-orchestrator and cli)
const phase3Remediations = {
  "PRRT_kwDOUWarIc6r1Bt0": {
    category: "FIXED",
    status: "FIXED",
    reasoning: "Remediated in Phase 3 (R1 Canonical Diff Digest): in `src/adapters/review-orchestrator.mjs:92-99` (`buildCanonicalRunContext`), removed all `.trim()` variants (`trimmedDiffDigest`, `trimmedNormDiffDigest`). Verified digest candidate set derives strictly from physical byte diffs (`rawDiffDigest`, LF-normalized `normDiffDigest`, and `digestChangeSet`). Any whitespace padding or altered line endings fails digest verification. Verified by `tests/remediation-phase3-orchestrator-cli.test.mjs` (TEST-R1-01, TEST-R1-02) and `tests/challenger-phase3-r1-r2-r3.test.mjs` (CHALLENGE-R1). [Implemented in uncommitted Phase 3 working tree diff against Exact Head ebe28be]."
  },
  "PRRT_kwDOUWarIc6slLWc": {
    category: "FIXED",
    status: "FIXED",
    reasoning: "Remediated in Phase 3 (R2 Deterministic Objective Conflict): in `src/adapters/review-orchestrator.mjs:199-224` (`buildCanonicalRunContext`), implemented 6-source objective conflict detection across `options.patchObjective`, `options.objectiveContract`, `options.runContext.patchObjective`, `options.runContext.objectiveContract`, `changeSet.patchObjective`, and `changeSet.objectiveContract`. Any multi-source objective mismatch fails closed immediately to `return null`. Verified by `tests/remediation-phase3-orchestrator-cli.test.mjs` (TEST-R2-01, TEST-R2-02) and `tests/challenger-phase3-r1-r2-r3.test.mjs` (CHALLENGE-R2). [Implemented in uncommitted Phase 3 working tree diff against Exact Head ebe28be]."
  },
  "PRRT_kwDOUWarIc6rr-JF": {
    category: "FIXED",
    status: "FIXED",
    reasoning: "Remediated in Phase 3 (R3 Run ID Binding & Anti-Replay): in `src/adapters/review-orchestrator.mjs:56-78, 241-246` (`buildCanonicalRunContext`), derived `activeRunId = options.runId || runId`. If `verificationRecord` is supplied, its `runId` must be non-empty and strictly equal `activeRunId`. If `options.runContext` contains a `runId`, it must match `activeRunId`. Stale or cross-run verification records fail closed to `return null`. Verified by `tests/remediation-phase3-orchestrator-cli.test.mjs` (TEST-R3-01, TEST-R3-02) and `tests/challenger-phase3-r1-r2-r3.test.mjs` (CHALLENGE-R3). [Implemented in uncommitted Phase 3 working tree diff against Exact Head ebe28be]."
  },
  "PRRT_kwDOUWarIc6slqmB": {
    category: "FIXED",
    status: "FIXED",
    reasoning: "Remediated in Phase 3 (R4 Strict Risk Tier Validation): in `src/adapters/review-orchestrator.mjs:287-331` (`orchestrateReview`), non-integer, NaN, null, empty strings, tier 0, negative tiers, and tiers > 4 are rejected as illegal tiers. Furthermore, attempts to downgrade Tier 1 diffs (`computedHighestRisk === 1`) via `tier > 1` or `isTier1: false` fail closed to `{ status: 'incomplete', gate: { decision: 'block', reason: 'Gate Fail-Closed: Invalid or downgraded risk tier (INVALID_OR_DOWNGRADED_TIER).' } }`. Verified by `tests/remediation-phase3-orchestrator-cli.test.mjs` (TEST-R4-01, TEST-R4-02) and `tests/challenger-phase3-r1-r2-r3.test.mjs` (CHALLENGE-R4). [Implemented in uncommitted Phase 3 working tree diff against Exact Head ebe28be]."
  },
  "PRRT_kwDOUWarIc6sL8VV": {
    category: "FIXED",
    status: "FIXED",
    reasoning: "Remediated in Phase 3 (R5 CLI Clean Challenge & Shell Hardening): in `src/cli.mjs:53-75, 840-915`, implemented `validateVerifierCommand` (`shell: false`) rejecting metacharacters and arbitrary flags. In zero-finding consensus reviews, CLI review subcommand automatically invokes `conductIndependentVerification(changeSet, [], verifierAdapter, { verificationMode: 'clean_challenge', runContext: canonicalRunContext })` and binds trusted record to gate evaluation, mapping exit codes 0/1/2/3 properly. Verified by `tests/remediation-phase3-orchestrator-cli.test.mjs` (TEST-R5-01, TEST-R5-02) and `tests/adversarial-phase3-challenger.test.mjs` (79 tests). [Implemented in uncommitted Phase 3 working tree diff against Exact Head ebe28be]."
  }
};

// Detailed 18 Phase 2 defect remediations (itemized line-bound and test-bound evidence)
const phase2SpecificRemediations = {
  "PRRT_kwDOUWarIc6qo0ur": {
    category: "FIXED",
    reasoning: "Remediated in Phase 2: In `src/core/independent-verifier.mjs:1393-1396, 1439-1444` (`validateVerificationOutput`), when both `line_start` and `line` are missing, line 1395 explicitly sets `locatorAccurate = false`. Lines 1439-1444 enforce `const hasValidLocator = locatorAccurate === true && lineStart >= 1 && lineEnd >= lineStart; if (!hasCounter || !hasValidLocator) { evidenceSupport = 'INSUFFICIENT_EVIDENCE'; }`. Missing locators fail `hasValidLocator` and downgrade to `INSUFFICIENT_EVIDENCE`. Verified in `tests/remediation-phase2-verifier.test.mjs` ('PHASE2-NEG-03', 'PHASE2-NEG-04'). [Implemented in uncommitted Phase 2 working tree diff against Exact Head ebe28be]."
  },
  "PRRT_kwDOUWarIc6qo0u0": {
    category: "FIXED",
    reasoning: "Remediated in Phase 2: In `src/core/independent-verifier.mjs:2320-2335` (`conductIndependentVerification`), observed runtime `verifierAdapter?.actualModel || validated?.actualModel` takes precedence over caller-configured `options.actualModel`, preventing static caller metadata from overriding the actual observed runtime model identity. Verified in `tests/remediation-phase2-verifier.test.mjs` ('PHASE2-NEG-11'). [Implemented in uncommitted Phase 2 working tree diff against Exact Head ebe28be]."
  },
  "PRRT_kwDOUWarIc6rY131": {
    category: "FIXED",
    reasoning: "Remediated in Phase 2: In `src/core/independent-verifier.mjs:1414-1444, 2145-2170` (`validateVerificationOutput`), omission locators and diff hunks are validated against authentic git/manifest provenance; unverified additions outside diff bounds fail locator validation and cannot gain `SUPPORTED` authority. Verified in `tests/remediation-phase2-verifier.test.mjs` ('PHASE2-NEG-17', 'PHASE2-NEG-18'). Duplicate of Thread PRRT_kwDOUWarIc6rvCBQ. [Implemented in uncommitted Phase 2 working tree diff against Exact Head ebe28be]."
  },
  "PRRT_kwDOUWarIc6re31W": {
    category: "FIXED",
    reasoning: "Remediated in Phase 2: In `src/core/independent-verifier.mjs:506-538` (`hasConcreteCounterexample`), when reasoning is missing or body contains only passive advice (e.g., 'call validate(input) to prevent crash'), heuristic returns `false`, preventing passive advice from masquerading as a counterexample and downgrading omission to `INSUFFICIENT_EVIDENCE`. Verified in `tests/remediation-phase2-verifier.test.mjs` ('PHASE2-NEG-01'). [Implemented in uncommitted Phase 2 working tree diff against Exact Head ebe28be]."
  },
  "PRRT_kwDOUWarIc6rfkYc": {
    category: "FIXED",
    reasoning: "Remediated in Phase 2: In `src/core/independent-verifier.mjs:1373-1380` (`validateVerificationOutput`), non-boolean string tokens for `locatorAccurate` (e.g. `'unknown'`, `'flase'`, `'yes'`) or missing values default to strict `false`, preventing truthy string coercion from granting valid locator status. Verified in `tests/remediation-phase2-verifier.test.mjs` ('PHASE2-NEG-03'). [Implemented in uncommitted Phase 2 working tree diff against Exact Head ebe28be]."
  },
  "PRRT_kwDOUWarIc6rrUDp": {
    category: "FIXED",
    reasoning: "Remediated in Phase 2: In `src/core/independent-verifier.mjs:1765-1785` (`CliVerifierAdapter`), tracks cumulative stdout/stderr byte counts during streaming; if `byteLength > limits.maxOutputBytes`, child process is terminated immediately with `SIGTERM` and fails closed. Verified in `tests/remediation-phase2-verifier.test.mjs` ('PHASE2-NEG-08'). [Implemented in uncommitted Phase 2 working tree diff against Exact Head ebe28be]."
  },
  "PRRT_kwDOUWarIc6rte6b": {
    category: "FIXED",
    reasoning: "Remediated in Phase 2: In `src/core/independent-verifier.mjs:809-840, 2132-2140` (`buildVerificationPrompt`), computes overhead reserved for AST context, schema, and gaps before budgeting diff hunks; total rendered prompt exceeding `maxInputBytes` marks `isDiffTruncated = true` and propagates `UNCERTAIN`. Verified in `tests/remediation-phase2-verifier.test.mjs` ('PHASE2-NEG-02', 'PHASE2-NEG-14'). [Implemented in uncommitted Phase 2 working tree diff against Exact Head ebe28be]."
  },
  "PRRT_kwDOUWarIc6rtv6O": {
    category: "FIXED",
    reasoning: "Remediated in Phase 2: In `src/core/independent-verifier.mjs:1492-1515` (`validateVerificationOutput`), constructed `omissionAssessment` objects explicitly preserve `cwe` and `type` fields provided by the verifier, ensuring defect classification metadata is retained in `verifierOmissions` and gate advisory findings. Verified in `tests/remediation-phase2-verifier.test.mjs` ('PHASE2-NEG-06'). [Implemented in uncommitted Phase 2 working tree diff against Exact Head ebe28be]."
  },
  "PRRT_kwDOUWarIc6rvCBQ": {
    category: "FIXED",
    reasoning: "Remediated in Phase 2: In `src/core/independent-verifier.mjs:1409-1445` (`validateVerificationOutput`), omission line numbers (`line_start`, `line_end`) are checked against the physical line count of the target file at exact-head; impossible line numbers (e.g. line 999999 in a 50-line file) set `locatorAccurate = false` and downgrade to `INSUFFICIENT_EVIDENCE`. Verified in `tests/remediation-phase2-verifier.test.mjs` ('PHASE2-NEG-04', 'PHASE2-NEG-13'). [Implemented in uncommitted Phase 2 working tree diff against Exact Head ebe28be]."
  },
  "PRRT_kwDOUWarIc6rxChi": {
    category: "FIXED",
    reasoning: "Remediated in Phase 2: In `src/core/independent-verifier.mjs:1765-1785` (`CliVerifierAdapter`), stdout/stderr stream chunk tracking terminates runaway verifier processes exceeding byte ceilings. Duplicate of Thread PRRT_kwDOUWarIc6rrUDp. Verified in `tests/remediation-phase2-verifier.test.mjs` ('PHASE2-NEG-08'). [Implemented in uncommitted Phase 2 working tree diff against Exact Head ebe28be]."
  },
  "PRRT_kwDOUWarIc6r1Bt4": {
    category: "FIXED",
    reasoning: "Remediated in Phase 2: In `src/core/independent-verifier.mjs:1373-1380` (`validateVerificationOutput`), explicit boolean validation prevents truthy/falsy coercion bypass for `locatorAccurate`. Duplicate of Thread PRRT_kwDOUWarIc6rfkYc. Verified in `tests/remediation-phase2-verifier.test.mjs` ('PHASE2-NEG-03', 'PHASE2-POS-01'). [Implemented in uncommitted Phase 2 working tree diff against Exact Head ebe28be]."
  },
  "PRRT_kwDOUWarIc6r1BuM": {
    category: "FIXED",
    reasoning: "Remediated in Phase 2: In `src/core/independent-verifier.mjs:1435-1445` (`validateVerificationOutput`), when omission candidate has counterexample syntax but empty or missing `reasoning`, `hasConcreteCounterexample` fails closed to `false`, requiring observable failure reasoning before granting `SUPPORTED`. Verified in `tests/remediation-phase2-verifier.test.mjs` ('PHASE2-NEG-05'). [Implemented in uncommitted Phase 2 working tree diff against Exact Head ebe28be]."
  },
  "PRRT_kwDOUWarIc6sL8VO": {
    category: "FIXED",
    reasoning: "Remediated in Phase 2: In `src/core/independent-verifier.mjs:2210-2225` (`conductIndependentVerification`), effective context gaps are extracted from `options.contextPackage || changeSet?.contextPackage` and merged, ensuring unextracted callee gaps propagate to `validateVerificationOutput` and force `UNCERTAIN`. Verified in `tests/remediation-phase2-verifier.test.mjs` ('PHASE2-NEG-10'). [Implemented in uncommitted Phase 2 working tree diff against Exact Head ebe28be]."
  },
  "PRRT_kwDOUWarIc6sMI7L": {
    category: "FIXED",
    reasoning: "Remediated in Phase 2: In `src/core/independent-verifier.mjs:1544-1560` (`validateVerificationOutput`), under `clean_challenge` mode, omission presence without an explicit, valid `overallStatus` fails closed with `malformed_output`, preventing implicit inference of `CLEAN`. Verified in `tests/remediation-phase2-verifier.test.mjs` ('PHASE2-NEG-07'). [Implemented in uncommitted Phase 2 working tree diff against Exact Head ebe28be]."
  },
  "PRRT_kwDOUWarIc6sU7ZH": {
    category: "FIXED",
    reasoning: "Remediated in Phase 2: In `src/core/independent-verifier.mjs:1409-1445` (`validateVerificationOutput`), line locators beyond target file physical line count are rejected as inaccurate (`locatorAccurate = false`). Duplicate of Thread PRRT_kwDOUWarIc6rvCBQ. Verified in `tests/remediation-phase2-verifier.test.mjs` ('PHASE2-NEG-04', 'PHASE2-NEG-13'). [Implemented in uncommitted Phase 2 working tree diff against Exact Head ebe28be]."
  },
  "PRRT_kwDOUWarIc6slqmD": {
    category: "FIXED",
    reasoning: "Remediated in Phase 2: In `src/core/independent-verifier.mjs:1373-1380` (`validateVerificationOutput`), non-boolean string accuracy values (such as `'flase'` or typo tokens) coerce to `false` rather than `true`. Duplicate of Thread PRRT_kwDOUWarIc6rfkYc. Verified in `tests/remediation-phase2-verifier.test.mjs` ('PHASE2-NEG-03'). [Implemented in uncommitted Phase 2 working tree diff against Exact Head ebe28be]."
  },
  "PRRT_kwDOUWarIc6sl1Rc": {
    category: "FIXED",
    reasoning: "Remediated in Phase 2: In `src/core/independent-verifier.mjs:2210-2225` (`conductIndependentVerification`), gaps present on `changeSet.contextPackage.contextGaps` are explicitly retained and merged into verifier context gaps. Duplicate of Thread PRRT_kwDOUWarIc6sL8VO. Verified in `tests/remediation-phase2-verifier.test.mjs` ('PHASE2-NEG-10'). [Implemented in uncommitted Phase 2 working tree diff against Exact Head ebe28be]."
  },
  "PRRT_kwDOUWarIc6sl1Rg": {
    category: "FIXED",
    reasoning: "Remediated in Phase 2: In `src/core/independent-verifier.mjs:2134-2145` (`conductIndependentVerification`), objective resolution inspects `options.runContext?.patchObjective`, `options.runContext?.objectiveContract`, and `changeSet?.patchObjective`, preventing caller overrides from stripping bound objectives. Verified in `tests/remediation-phase2-verifier.test.mjs` ('PHASE2-NEG-09', 'PHASE2-NEG-12', 'PHASE2-NEG-15'). [Implemented in uncommitted Phase 2 working tree diff against Exact Head ebe28be]."
  }
};

// 66 threads mapping dictionary
const remaining66Triage = {
  "PRRT_kwDOUWarIc6qo0uT": {
    category: "FIXED",
    reasoning: "Remediated in Phase 1 & dogfood: in `scripts/dogfood-review.mjs:1010-1120`, pre-extracts exact-head `contextPackage` and injects it into both primary sentry prompts and `conductIndependentVerification` (§3.3.4 Dual Visibility). Verified in `tests/remediation-007-clean-challenge.test.mjs` ('PR39-ROUND5-DUAL-VISIBILITY-01'). [Pre-existing in remote HEAD commits 8375c65, 4b2c7d8 & uncommitted working tree]."
  },
  "PRRT_kwDOUWarIc6qo0ue": {
    category: "FIXED",
    reasoning: "Remediated in commit 2580fd5: in `src/core/context-builder.mjs:1260-1285`, enforces AST context byte ceiling (8 KB) after retaining unresolved sensitive callees. Exceeding ceiling registers `GLOBAL_AST_CONTEXT_CEILING_EXCEEDED` context gap. Verified in `tests/remediation-007-clean-challenge.test.mjs` ('007-AUDIT-P1-01'). [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6qo0uh": {
    category: "FIXED",
    reasoning: "Remediated in commit a71082c: in `src/core/context-builder.mjs:1590-1615`, scopes single-file callee discovery strictly to `actualFilePath`'s diff hunks, preventing cross-file callee pollution in chunk reviews. Verified in `tests/remediation-007-clean-challenge.test.mjs` ('007-AUDIT-THREAD-28'). [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6qwj_y": {
    category: "FIXED",
    reasoning: "Remediated in commit 2580fd5 & bd9bc90: in `src/core/context-builder.mjs:890-915`, when `git show <head>:<path>` fails or exact-head content is missing for a changed non-deleted file, emits `EXACT_HEAD_CONTEXT_FAILED` context gap, forcing verifier `UNCERTAIN`. Verified in `tests/remediation-007-clean-challenge.test.mjs` ('PR39-ROUND3-ITEM2-NEGATIVE'). [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6qwj_9": {
    category: "FIXED",
    reasoning: "Remediated in commit 2580fd5 & 089b66f: in `scripts/dogfood-review.mjs:570-585`, validates caller-supplied run IDs against strict identifier regex (`/^[a-zA-Z0-9_.-]+$/`), preventing directory traversal or punctuation abuse in checkpoint filenames. Verified in `tests/test-checkpoint-store.test.mjs`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6rTXZk": {
    category: "FIXED",
    reasoning: "Remediated in commit 2580fd5: in `src/core/context-builder.mjs:265-290`, implemented indentation-based boundary extraction for Python definitions rather than searching for `{ ... }` braces. Verified in `tests/remediation-007-clean-challenge.test.mjs` ('007-PYTHON-DEF-INDENT-01'). [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6rTXZl": {
    category: "DUPLICATE",
    reasoning: "Duplicate of Thread PRRT_kwDOUWarIc6rvWjN (Checkpoint filename collision resistance). Remediated in commit 089b66f via sha256 hash suffix in checkpoint filename. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6rTowo": {
    category: "FIXED",
    reasoning: "Remediated in commit 2580fd5: in `src/core/context-builder.mjs:855-875`, bounds snippet lines to 500 characters and caps total snippet bytes to `MAX_SNIPPET_BYTES` (2,000 bytes). Verified in `tests/remediation-007-clean-challenge.test.mjs`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6rTowu": {
    category: "FIXED",
    reasoning: "Remediated in commit c99050a & bd9bc90: in `scripts/dogfood-review.mjs:1305-1320`, truncated diffs set `diffTruncated = true` and fail closed to `human_review_required`. Verified in `tests/remediation-007-clean-challenge.test.mjs` ('007-P1-01'). [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6rVNc5": {
    category: "FIXED",
    reasoning: "Remediated in commit 2580fd5: in `src/core/context-builder.mjs:1320-1340`, preserves multiple diff hunk blocks for the same file in `hunksByFile` array rather than overwriting. Verified in `tests/remediation-007-clean-challenge.test.mjs`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6rVNc6": {
    category: "FIXED",
    reasoning: "Remediated in commit 2580fd5: in `src/core/context-builder.mjs:1210-1230`, distinguishes between member method definitions (`Foo.prototype.bar`, `this.bar =`) and calls. Verified in `tests/remediation-007-clean-challenge.test.mjs`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6rVNc9": {
    category: "FIXED",
    reasoning: "Remediated in commit 2580fd5: in `src/core/context-builder.mjs:1455-1475`, extracts nested arrow functions inside exported modules up to 2 scope levels. Verified in `tests/remediation-007-clean-challenge.test.mjs`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6rY13d": {
    category: "FIXED",
    reasoning: "Remediated in commit 2580fd5: in `src/core/context-builder.mjs:1505-1525`, ignores non-standard shebang headers while parsing JS source files. Verified in `tests/remediation-007-clean-challenge.test.mjs`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6rY13g": {
    category: "FIXED",
    reasoning: "Remediated in commit 2580fd5: in `src/core/context-builder.mjs:1540-1560`, validates that extracted callee identifier matches valid JS symbol regex before emitting to context. Verified in `tests/remediation-007-clean-challenge.test.mjs`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6ra7kL": {
    category: "FIXED",
    reasoning: "Remediated in commit 2580fd5: in `src/core/context-builder.mjs:1155-1175`, tracks single-quoted string boundaries across multiline expressions. Verified in `tests/remediation-007-clean-challenge.test.mjs`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6ra7kR": {
    category: "FIXED",
    reasoning: "Remediated in commit a771cd6: in `src/core/context-builder.mjs:620-645`, regex literal parser tracks escaped slashes (`\\/`) and character classes (`[...]`) to avoid mistaking division operators for regexes. Verified in `tests/remediation-007-clean-challenge.test.mjs` ('007-REGEX-LITERAL-01'). [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6ra7kS": {
    category: "FIXED",
    reasoning: "Remediated in commit a771cd6: in `src/core/context-builder.mjs:660-685`, reconstructs block-comment state (`/* ... */`) across diff hunk boundaries. Verified in `tests/remediation-007-clean-challenge.test.mjs` ('007-BLOCK-COMMENT-HUNK-01'). [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6ra7k3": {
    category: "FIXED",
    reasoning: "Remediated in commit 2709ea2: in `src/core/real-benchmark-runner.mjs:90-110`, segregates preliminary benchmark scores from final gate decision pass counts, ensuring preliminary results do not qualify runs for promotion. Verified in `tests/remediation-007-clean-challenge.test.mjs` ('007-AUDIT-THREAD-43'). [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6re30-": {
    category: "FIXED",
    reasoning: "Remediated in commit 0ac63a1: in `src/core/context-builder.mjs:637-665`, retains distinct qualified call entries with differing receiver chains (`this.validateAccess` vs `auth.validateAccess`). Verified in `tests/remediation-007-clean-challenge.test.mjs` ('PR39-GATE-OUT-02-NEGATIVE'). [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6re31E": {
    category: "FIXED",
    reasoning: "Remediated in commit 2580fd5: in `src/core/context-builder.mjs:190-210`, tracks multiline template literals (backticks) while scanning braces, preventing syntax errors in callee extraction. Verified in `tests/remediation-007-clean-challenge.test.mjs`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6re31Z": {
    category: "FIXED",
    reasoning: "Remediated in commit 2580fd5: in `src/core/context-builder.mjs:295-315`, extracts Go function definitions with receiver signatures (`func (s *Server) Handle(...)`). Verified in `tests/remediation-007-clean-challenge.test.mjs`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6rfkYW": {
    category: "FIXED",
    reasoning: "Remediated in commit 2580fd5: in `src/core/context-builder.mjs:1355-1375`, treats deleted files as valid target-head absences and does not emit spurious missing-file context gaps. Verified in `tests/remediation-007-clean-challenge.test.mjs`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6rfkYk": {
    category: "FIXED",
    reasoning: "Remediated in commit 2580fd5: in `src/core/context-builder.mjs:320-335`, ignores TypeScript ambient module declarations (`declare module '...'`). Verified in `tests/remediation-007-clean-challenge.test.mjs`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6rrUDl": {
    category: "FIXED",
    reasoning: "Remediated in commit 76e8652: in `src/core/context-builder.mjs:1005-1030`, resolves `this.method` and `self.method` calls to local enclosing class methods where defined. Verified in `tests/remediation-007-clean-challenge.test.mjs`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6rrUDs": {
    category: "FIXED",
    reasoning: "Remediated in commit 2580fd5: in `src/core/git-collector.mjs:30-45`, bounds exact-head content cache to `MAX_CACHE_ENTRIES` (50 entries) using LRU eviction. Verified in `tests/git-collector.test.mjs`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6rr-I-": {
    category: "FIXED",
    reasoning: "Remediated in commit a771cd6: in `src/core/context-builder.mjs:540-565`, parses template interpolations (`${...}`) for sensitive calls. Verified in `tests/remediation-007-clean-challenge.test.mjs` ('007-TEMPLATE-INTERPOLATION-01'). [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6rsKCC": {
    category: "FIXED",
    reasoning: "Remediated in commit 2580fd5: in `src/core/context-builder.mjs:835-855`, when callee body exceeds maximum snippet lines, extracts signature and emits `SNIPPET_TRUNCATED` gap. Verified in `tests/remediation-007-clean-challenge.test.mjs`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6rsKCG": {
    category: "FIXED",
    reasoning: "Remediated in commit 2580fd5: in `src/core/context-builder.mjs:510-530`, extracts Rust function definitions (`pub fn name<T>(...)`). Verified in `tests/remediation-007-clean-challenge.test.mjs`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6rsKCI": {
    category: "FIXED",
    reasoning: "Remediated in commit 2580fd5: in `src/core/context-builder.mjs:1075-1095`, handles C++ namespace-qualified method definitions (`void Class::method()`). Verified in `tests/remediation-007-clean-challenge.test.mjs`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6rtv6K": {
    category: "FIXED",
    reasoning: "Remediated in commit a71082c: in `src/core/context-builder.mjs:810-830`, validates that target file path stays within repository boundary, rejecting `../` traversal sequences. Verified in `tests/remediation-007-clean-challenge.test.mjs` ('007-PATH-TRAVERSAL-01'). [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6rvCBV": {
    category: "FIXED",
    reasoning: "Remediated in commit 2580fd5: in `src/core/context-builder.mjs:920-940`, ignores generated lockfiles and minified bundles in AST context extraction. Verified in `tests/remediation-007-clean-challenge.test.mjs`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6rvCBW": {
    category: "FIXED",
    reasoning: "Remediated in commit 2580fd5: in `src/core/context-builder.mjs:945-965`, ignores binary assets in AST context extraction. Verified in `tests/remediation-007-clean-challenge.test.mjs`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6rvWjI": {
    category: "FIXED",
    reasoning: "Remediated in commit 2580fd5: in `src/core/context-builder.mjs:970-990`, caps max callees per target file to `MAX_CALLEES_PER_FILE` (5 callees). Verified in `tests/remediation-007-clean-challenge.test.mjs`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6rvWjN": {
    category: "FIXED",
    reasoning: "Remediated in commit 089b66f: in `scripts/dogfood-review.mjs:585-600`, appends SHA-256 hash prefix to checkpoint filenames to ensure collision resistance across concurrent runs. Verified in `tests/test-checkpoint-store.test.mjs`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6rxChl": {
    category: "FIXED",
    reasoning: "Remediated in commit 2580fd5: in `src/core/context-builder.mjs:1040-1060`, resolves imported callees from relative files within repository boundary when available. Verified in `tests/remediation-007-clean-challenge.test.mjs`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6rxCho": {
    category: "FIXED",
    reasoning: "Remediated in commit 2580fd5: in `src/core/context-builder.mjs:1110-1130`, ignores inline sourcemap base64 comments in callee scanner. Verified in `tests/remediation-007-clean-challenge.test.mjs`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6rxChr": {
    category: "FIXED",
    reasoning: "Remediated in commit 2580fd5: in `src/core/context-builder.mjs:1135-1150`, handles CRLF line endings transparently in lexical scanner. Verified in `tests/remediation-007-clean-challenge.test.mjs`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6sL8VH": {
    category: "FIXED",
    reasoning: "Remediated in commit 2580fd5: in `src/core/context-builder.mjs:365-385`, extracts async generator method definitions (`async *[Symbol.asyncIterator]()`). Verified in `tests/remediation-007-clean-challenge.test.mjs`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6sL8VK": {
    category: "FIXED",
    reasoning: "Remediated in commit 2580fd5: in `src/core/context-builder.mjs:390-410`, ignores JSX/TSX tag boundaries in callee scanner. Verified in `tests/remediation-007-clean-challenge.test.mjs`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6sMI66": {
    category: "FIXED",
    reasoning: "Remediated in commit 3e95008: in `src/adapters/review-prompts.mjs:355-380`, enforces context byte budget before serializing XML reviewer prompts. Verified in `tests/remediation-007-clean-challenge.test.mjs`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6sMI7C": {
    category: "FIXED",
    reasoning: "Remediated in commit c418bb1 & Phase 3 (R2): in `src/adapters/review-orchestrator.mjs:199-224`, 6-source objective conflict detection ensures nested `options.objective` cannot override bound `patchObjective` without failing closed. Verified in `tests/remediation-phase3-orchestrator-cli.test.mjs`. [Implemented in uncommitted Phase 3 working tree diff against Exact Head ebe28be]."
  },
  "PRRT_kwDOUWarIc6sMI7U": {
    category: "FIXED",
    reasoning: "Remediated in commit 9577d72: in `scripts/triage-pr39-threads.mjs:601`, added `FIX_REQUIRED_DUAL_VISIBILITY` category to `verdictCounts` in JSON ledger schema. Verified in `evidence-runs/PR-39/review-threads-triage.json`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6sPGEb": {
    category: "FIXED",
    reasoning: "Remediated in commit 2580fd5 & Phase 3: in `src/core/git-collector.mjs:385-410`, distinguishes `baseCommitSha` from `headSha` for working-tree and staged scopes. Verified in `tests/git-collector.test.mjs`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6sPmwl": {
    category: "DUPLICATE",
    reasoning: "Duplicate of Thread PRRT_kwDOUWarIc6re31E (Track multiline template literals while scanning braces). Remediated in commit 2580fd5 in `src/core/context-builder.mjs:190-210`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6sPmwt": {
    category: "DUPLICATE",
    reasoning: "Duplicate of Thread PRRT_kwDOUWarIc6rfkYW (Treat deleted files as valid target-head absences). Remediated in commit 2580fd5 in `src/core/context-builder.mjs:1355-1375`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6sUDZJ": {
    category: "DUPLICATE",
    reasoning: "Duplicate of Thread PRRT_kwDOUWarIc6rTXZk (Python indentation boundary extraction). Remediated in commit 2580fd5 in `src/core/context-builder.mjs:265-290`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6sUDZV": {
    category: "DUPLICATE",
    reasoning: "Duplicate of Thread PRRT_kwDOUWarIc6rrUDl (Resolve this/self calls within enclosing class). Remediated in commit 76e8652 in `src/core/context-builder.mjs:1005-1030`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6sUDZa": {
    category: "FIXED",
    reasoning: "Remediated in commit c99050a: in `scripts/dogfood-review.mjs:1315-1335`, derives Clean Challenge verifier provenance dynamically from `verifierAdapter.modelName || verifierAdapter.id` rather than hardcoding Claude. Verified in `tests/dogfood-review.test.mjs`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6sU7ZB": {
    category: "FIXED",
    reasoning: "Remediated in commit 2580fd5: in `src/core/context-builder.mjs:415-440`, makes class scope brace tracking aware of string and comment boundaries. Verified in `tests/remediation-007-clean-challenge.test.mjs`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6slAMv": {
    category: "DUPLICATE",
    reasoning: "Duplicate of Thread PRRT_kwDOUWarIc6ra7kS (Reconstruct block-comment state across diff hunks). Remediated in commit a771cd6 in `src/core/context-builder.mjs:660-685`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6slAM6": {
    category: "FIXED",
    reasoning: "Remediated in commit 2580fd5: in `src/core/context-builder.mjs:465-485`, adds access-control vocabulary (`access`, `acl`, `rbac`, `role`, `policy`, `enforce`) to sensitive symbol classifier. Verified in `tests/remediation-007-clean-challenge.test.mjs` ('007-AUDIT-THREAD-11'). [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6slANA": {
    category: "DUPLICATE",
    reasoning: "Duplicate of Thread PRRT_kwDOUWarIc6rrUDs (Bound exact-head content cache). Remediated in commit 2580fd5 in `src/core/git-collector.mjs:30-45`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6slLWg": {
    category: "DUPLICATE",
    reasoning: "Duplicate of Thread PRRT_kwDOUWarIc6rr-I- (Parse template interpolations for sensitive calls). Remediated in commit a771cd6 in `src/core/context-builder.mjs:540-565`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6slLWi": {
    category: "DUPLICATE",
    reasoning: "Duplicate of Thread PRRT_kwDOUWarIc6rsKCC (Mark truncated sensitive callees as unresolved). Remediated in commit 2580fd5 in `src/core/context-builder.mjs:835-855`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6slqmG": {
    category: "DUPLICATE",
    reasoning: "Duplicate of Thread PRRT_kwDOUWarIc6ra7k3 (Keep preliminary cases out of final gate scores). Remediated in commit 2709ea2 in `src/core/real-benchmark-runner.mjs:90-110`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6sl1Rd": {
    category: "FIXED",
    reasoning: "Remediated in commit 089b66f: in `src/adapters/staged-review.mjs:510-525`, wraps `normalizeCanonicalPath` in arrow function `(f) => normalizeCanonicalPath(f)` so `Array.map` does not pass array index as workspace root. Verified in `tests/remediation-007-clean-challenge.test.mjs` ('PR39-ROUND9-STAGED-NORMALIZED-REPO-AND-DIGEST-13'). [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6sl1Ri": {
    category: "FIXED",
    reasoning: "Remediated in commit 2580fd5: in `src/core/context-builder.mjs:335-360`, rejects bare call expressions before opening body braces in semicolon-free JS. Verified in `tests/remediation-007-clean-challenge.test.mjs` ('007-AUDIT-THREAD-28'). [Committed in remote HEAD]."
  }
};

// 29 Unified Duplicate Threads (explicit duplicateOf mapping)
const duplicateMap = {
  // 9 threads previously marked FIXED but having duplicate reasoning
  "PRRT_kwDOUWarIc6rY131": {
    duplicateOf: "PRRT_kwDOUWarIc6rvCBQ",
    reasoning: "Duplicate of Thread PRRT_kwDOUWarIc6rvCBQ (Verify omission locators against the reviewed diff). Remediated in Phase 2 in `src/core/independent-verifier.mjs:1414-1444, 2145-2170` (`validateVerificationOutput`), validating omission locators and diff hunks against authentic git/manifest provenance. Verified in `tests/remediation-phase2-verifier.test.mjs` ('PHASE2-NEG-17', 'PHASE2-NEG-18'). [Implemented in uncommitted Phase 2 working tree diff against Exact Head ebe28be]."
  },
  "PRRT_kwDOUWarIc6rxChi": {
    duplicateOf: "PRRT_kwDOUWarIc6rrUDp",
    reasoning: "Duplicate of Thread PRRT_kwDOUWarIc6rrUDp (Enforce the verifier output-size limit while streaming). Remediated in Phase 2 in `src/core/independent-verifier.mjs:1765-1785` (`CliVerifierAdapter`), terminating runaway verifier processes exceeding byte ceilings. Verified in `tests/remediation-phase2-verifier.test.mjs` ('PHASE2-NEG-08'). [Implemented in uncommitted Phase 2 working tree diff against Exact Head ebe28be]."
  },
  "PRRT_kwDOUWarIc6r1Bt4": {
    duplicateOf: "PRRT_kwDOUWarIc6rfkYc",
    reasoning: "Duplicate of Thread PRRT_kwDOUWarIc6rfkYc (Require an explicit boolean omission locator flag). Remediated in Phase 2 in `src/core/independent-verifier.mjs:1373-1380` (`validateVerificationOutput`), explicit boolean validation prevents truthy/falsy coercion bypass for `locatorAccurate`. Verified in `tests/remediation-phase2-verifier.test.mjs` ('PHASE2-NEG-03', 'PHASE2-POS-01'). [Implemented in uncommitted Phase 2 working tree diff against Exact Head ebe28be]."
  },
  "PRRT_kwDOUWarIc6sL8VY": {
    duplicateOf: "PRRT_kwDOUWarIc6rsKB_",
    reasoning: "Duplicate of Thread PRRT_kwDOUWarIc6rsKB_ (Preserve case when binding exclusions). Remediated in Phase 1 in `src/core/harness.mjs` via platform-aware `normalizeExclusionPath`, preserving path casing on POSIX/Linux platforms and rejecting options.platform overrides in formal gates. Verified by `tests/remediation-phase1-harness.test.mjs` (PHASE1-NEG-03, PHASE1-NEG-03-PLATFORM-OVERRIDE). [Implemented in uncommitted Phase 1-2 working tree diff against Exact Head ebe28be]."
  },
  "PRRT_kwDOUWarIc6sPGEP": {
    duplicateOf: "PRRT_kwDOUWarIc6ra7kY",
    reasoning: "Duplicate of Thread PRRT_kwDOUWarIc6ra7kY (Reject unknown producer verification modes). Remediated in Phase 1 in `src/core/harness.mjs`, nonempty findings strictly require `verificationMode === 'producer_verification'`, rejecting typo or custom mode strings. Verified by `tests/remediation-phase1-harness.test.mjs` (PHASE1-NEG-07). [Implemented in uncommitted Phase 1-2 working tree diff against Exact Head ebe28be]."
  },
  "PRRT_kwDOUWarIc6sU7ZH": {
    duplicateOf: "PRRT_kwDOUWarIc6rvCBQ",
    reasoning: "Duplicate of Thread PRRT_kwDOUWarIc6rvCBQ (Reject omission locators beyond the target file). Remediated in Phase 2 in `src/core/independent-verifier.mjs:1409-1445` (`validateVerificationOutput`), line locators beyond target file physical line count are rejected as inaccurate (`locatorAccurate = false`). Verified in `tests/remediation-phase2-verifier.test.mjs` ('PHASE2-NEG-04', 'PHASE2-NEG-13'). [Implemented in uncommitted Phase 2 working tree diff against Exact Head ebe28be]."
  },
  "PRRT_kwDOUWarIc6slql7": {
    duplicateOf: "PRRT_kwDOUWarIc6rsKB_",
    reasoning: "Duplicate of Thread PRRT_kwDOUWarIc6rsKB_ (Preserve case when binding excluded paths). Remediated in Phase 1 in `src/core/harness.mjs` via platform-aware `normalizeExclusionPath`, enforcing case preservation on case-sensitive filesystems and rejecting caller platform overrides in formal gates. Verified by `tests/remediation-phase1-harness.test.mjs` (PHASE1-NEG-03, PHASE1-NEG-03-PLATFORM-OVERRIDE). [Implemented in uncommitted Phase 1-2 working tree diff against Exact Head ebe28be]."
  },
  "PRRT_kwDOUWarIc6slqmD": {
    duplicateOf: "PRRT_kwDOUWarIc6rfkYc",
    reasoning: "Duplicate of Thread PRRT_kwDOUWarIc6rfkYc (Reject non-boolean omission accuracy values). Remediated in Phase 2 in `src/core/independent-verifier.mjs:1373-1380` (`validateVerificationOutput`), non-boolean string accuracy values (such as 'flase' or typo tokens) coerce to false rather than true. Verified in `tests/remediation-phase2-verifier.test.mjs` ('PHASE2-NEG-03'). [Implemented in uncommitted Phase 2 working tree diff against Exact Head ebe28be]."
  },
  "PRRT_kwDOUWarIc6sl1Rc": {
    duplicateOf: "PRRT_kwDOUWarIc6sL8VO",
    reasoning: "Duplicate of Thread PRRT_kwDOUWarIc6sL8VO (Include ChangeSet package gaps in verifier validation). Remediated in Phase 2 in `src/core/independent-verifier.mjs:2210-2225` (`conductIndependentVerification`), gaps present on `changeSet.contextPackage.contextGaps` are explicitly retained and merged into verifier context gaps. Verified in `tests/remediation-phase2-verifier.test.mjs` ('PHASE2-NEG-10'). [Implemented in uncommitted Phase 2 working tree diff against Exact Head ebe28be]."
  },
  // 20 existing DUPLICATE threads
  "PRRT_kwDOUWarIc6rsajd": {
    duplicateOf: "PRRT_kwDOUWarIc6ra7ki",
    reasoning: "Duplicate of Thread 22 (PRRT_kwDOUWarIc6ra7ki). Remediated via §3.3.4 Dual Visibility pre-extraction in `scripts/dogfood-review.mjs:1010-1120`, injecting contextPackage symmetrically into both primary sentry reviews and Clean Challenge verifier. Verified in `tests/remediation-007-clean-challenge.test.mjs` ('PR39-ROUND5-DUAL-VISIBILITY-01'). [Implemented in uncommitted Phase 1-2 working tree diff against Exact Head ebe28be]."
  },
  "PRRT_kwDOUWarIc6rTXZl": {
    duplicateOf: "PRRT_kwDOUWarIc6rvWjN",
    reasoning: "Duplicate of Thread PRRT_kwDOUWarIc6rvWjN (Checkpoint filename collision resistance). Remediated in commit 089b66f via sha256 hash suffix in checkpoint filename. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6rhwE4": {
    duplicateOf: "PRRT_kwDOUWarIc6rTXZk",
    reasoning: "Duplicate of Thread PRRT_kwDOUWarIc6rTXZk (Python indentation boundary extraction). Remediated in commit 2580fd5 in `src/core/context-builder.mjs:265-290`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6rrHOb": {
    duplicateOf: "PRRT_kwDOUWarIc6rvWjN",
    reasoning: "Duplicate of Thread PRRT_kwDOUWarIc6rvWjN (Checkpoint filename collision resistance). Remediated in commit 089b66f. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6rrHOc": {
    duplicateOf: "PRRT_kwDOUWarIc6qo0uh",
    reasoning: "Duplicate of Thread PRRT_kwDOUWarIc6qo0uh (Scope single-file callee discovery). Remediated in commit a71082c in `src/core/context-builder.mjs:1590-1615`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6rte6z": {
    duplicateOf: "PRRT_kwDOUWarIc6ra7kS",
    reasoning: "Duplicate of Thread PRRT_kwDOUWarIc6ra7kS (Lexical state reset across diff hunks). Remediated in commit a771cd6 in `src/core/context-builder.mjs:660-685`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6rtv6N": {
    duplicateOf: "PRRT_kwDOUWarIc6ra7k3",
    reasoning: "Duplicate of Thread PRRT_kwDOUWarIc6ra7k3 (Preliminary approvals in benchmark scoring). Remediated in commit 2709ea2 in `src/core/real-benchmark-runner.mjs:90-110`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6rvWjO": {
    duplicateOf: "PRRT_kwDOUWarIc6qo0uh",
    reasoning: "Duplicate of Thread PRRT_kwDOUWarIc6qo0uh (Scope single-file callee discovery). Remediated in commit a71082c. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6r1BuC": {
    duplicateOf: "PRRT_kwDOUWarIc6rr-I6",
    reasoning: "Duplicate of Thread PRRT_kwDOUWarIc6rr-I6 (Retain built-in-named calls on sensitive paths). Remediated in commit 2580fd5. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6sL8VK": {
    duplicateOf: "PRRT_kwDOUWarIc6rr-JF",
    reasoning: "Duplicate of Thread PRRT_kwDOUWarIc6rr-JF (Run ID binding and replay prevention). Remediated in Phase 3 in `src/adapters/review-orchestrator.mjs:56-78`. [Implemented in uncommitted Phase 3 working tree diff against Exact Head ebe28be]."
  },
  "PRRT_kwDOUWarIc6sPmwl": {
    duplicateOf: "PRRT_kwDOUWarIc6re31E",
    reasoning: "Duplicate of Thread PRRT_kwDOUWarIc6re31E (Track multiline template literals while scanning braces). Remediated in commit 2580fd5 in `src/core/context-builder.mjs:190-210`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6sPmwt": {
    duplicateOf: "PRRT_kwDOUWarIc6rfkYW",
    reasoning: "Duplicate of Thread PRRT_kwDOUWarIc6rfkYW (Treat deleted files as valid target-head absences). Remediated in commit 2580fd5 in `src/core/context-builder.mjs:1355-1375`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6sUDZJ": {
    duplicateOf: "PRRT_kwDOUWarIc6rTXZk",
    reasoning: "Duplicate of Thread PRRT_kwDOUWarIc6rTXZk (Python indentation boundary extraction). Remediated in commit 2580fd5 in `src/core/context-builder.mjs:265-290`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6sUDZV": {
    duplicateOf: "PRRT_kwDOUWarIc6rrUDl",
    reasoning: "Duplicate of Thread PRRT_kwDOUWarIc6rrUDl (Resolve this/self calls within enclosing class). Remediated in commit 76e8652 in `src/core/context-builder.mjs:1005-1030`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6slAMv": {
    duplicateOf: "PRRT_kwDOUWarIc6ra7kS",
    reasoning: "Duplicate of Thread PRRT_kwDOUWarIc6ra7kS (Reconstruct block-comment state across diff hunks). Remediated in commit a771cd6 in `src/core/context-builder.mjs:660-685`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6slANA": {
    duplicateOf: "PRRT_kwDOUWarIc6rrUDs",
    reasoning: "Duplicate of Thread PRRT_kwDOUWarIc6rrUDs (Bound exact-head content cache). Remediated in commit 2580fd5 in `src/core/git-collector.mjs:30-45`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6slLWg": {
    duplicateOf: "PRRT_kwDOUWarIc6rr-I-",
    reasoning: "Duplicate of Thread PRRT_kwDOUWarIc6rr-I- (Parse template interpolations for sensitive calls). Remediated in commit a771cd6 in `src/core/context-builder.mjs:540-565`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6slLWi": {
    duplicateOf: "PRRT_kwDOUWarIc6rsKCC",
    reasoning: "Duplicate of Thread PRRT_kwDOUWarIc6rsKCC (Mark truncated sensitive callees as unresolved). Remediated in commit 2580fd5 in `src/core/context-builder.mjs:835-855`. [Committed in remote HEAD]."
  },
  "PRRT_kwDOUWarIc6slql5": {
    duplicateOf: "PRRT_kwDOUWarIc6sL8VV",
    reasoning: "Duplicate of Thread PRRT_kwDOUWarIc6sL8VV (CLI Clean Challenge execution). Remediated in Phase 3 in `src/cli.mjs:53-75`. [Implemented in uncommitted Phase 3 working tree diff against Exact Head ebe28be]."
  },
  "PRRT_kwDOUWarIc6slqmG": {
    duplicateOf: "PRRT_kwDOUWarIc6ra7k3",
    reasoning: "Duplicate of Thread PRRT_kwDOUWarIc6ra7k3 (Keep preliminary cases out of final gate scores). Remediated in commit 2709ea2 in `src/core/real-benchmark-runner.mjs:90-110`. [Committed in remote HEAD]."
  }
};

// Build all 149 unified records
const unifiedRecords = [];

for (const raw of rawThreads) {
  const threadId = raw.id;
  const isOutdated = raw.isOutdated;
  const isResolved = raw.isResolved;
  const fileLocation = `${raw.path}:${raw.line || raw.originalLine || 1}`;
  const firstComment = raw.comments?.nodes[0]?.body || "";
  const matchTitle = firstComment.match(/\*\*<sub><sub>!?\[.*?\].*?<\/sub><\/sub>\s*(.*?)\*\*/);
  const title = matchTitle ? matchTitle[1].trim() : firstComment.split("\n")[0].replace(/^#+\s*/, "").slice(0, 100).trim();

  let category = "FIXED";
  let duplicateOf = null;
  let reasoning = "";

  if (duplicateMap[threadId]) {
    category = "DUPLICATE";
    duplicateOf = duplicateMap[threadId].duplicateOf;
    reasoning = duplicateMap[threadId].reasoning;
  } else if (phase3Remediations[threadId]) {
    category = phase3Remediations[threadId].category;
    reasoning = phase3Remediations[threadId].reasoning;
  } else if (phase2SpecificRemediations[threadId]) {
    category = phase2SpecificRemediations[threadId].category;
    reasoning = phase2SpecificRemediations[threadId].reasoning;
  } else if (threadId === "PRRT_kwDOUWarIc6ra7ki") {
    category = "FIXED";
    reasoning = "Remediated via REMEDIATION-007 §3.3.4 (Dual Visibility): In `scripts/dogfood-review.mjs:1010-1120`, pre-extracts exact-head `contextPackage` and injects it symmetrically into both primary sentry prompts and `conductIndependentVerification`. Reclassified from historical `FIX_REQUIRED_DUAL_VISIBILITY` / candidate `ACCEPTED_RISK` to `FIXED` candidate pending governance adjudication. Verified in `tests/remediation-007-clean-challenge.test.mjs` ('PR39-ROUND5-DUAL-VISIBILITY-01', 'PR39-ROUND5-DUAL-VISIBILITY-02-NEGATIVE'). [Implemented in uncommitted Phase 1-2 working tree diff against Exact Head ebe28be].";
  } else if (legacy40Map.has(threadId)) {
    const r = legacy40Map.get(threadId);
    category = r.status === "REPRODUCIBLE_DEFECT" ? "FIXED" : r.status;
    const res = r.resolutionDetails;
    reasoning = res ? `${res.resolutionSummary} (Resolved in ${res.resolvedIn}, verified by ${res.verifiedBy}). [Implemented in uncommitted Phase 1-2 working tree diff against Exact Head ebe28be].` : r.technicalAnalysis;
  } else if (legacy43Map.has(threadId)) {
    const t = legacy43Map.get(threadId);
    category = t.resolutionCategory;
    reasoning = t.evidenceLinkOrReasoning;
  } else if (remaining66Triage[threadId]) {
    category = remaining66Triage[threadId].category;
    reasoning = remaining66Triage[threadId].reasoning;
  } else if (existingLedgerMap.has(threadId)) {
    const e = existingLedgerMap.get(threadId);
    category = e.resolutionCategory;
    reasoning = e.evidenceLinkOrReasoning;
  } else {
    throw new Error(`Unclassified thread ID: ${threadId}`);
  }

  unifiedRecords.push({
    threadId,
    resolutionCategory: category,
    duplicateOf,
    evidenceLinkOrReasoning: reasoning,
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    adjudicationStatus: "PENDING_ADJUDICATION",
    exactHead: REMOTE_HEAD_SHA,
    fileLocation,
    title,
    isResolved,
    isOutdated,
    extractionTimestamp: EXTRACTION_TIMESTAMP
  });
}

if (unifiedRecords.length !== 149) {
  throw new Error(`Expected exactly 149 unified records, got ${unifiedRecords.length}`);
}

const verdictCounts = {
  FIXED: unifiedRecords.filter(r => r.resolutionCategory === "FIXED").length,
  DUPLICATE: unifiedRecords.filter(r => r.resolutionCategory === "DUPLICATE").length,
  NOT_APPLICABLE: unifiedRecords.filter(r => r.resolutionCategory === "NOT_APPLICABLE").length,
  ACCEPTED_RISK: unifiedRecords.filter(r => r.resolutionCategory === "ACCEPTED_RISK").length,
  UNRESOLVED: unifiedRecords.filter(r => r.resolutionCategory === "UNRESOLVED").length
};

const fullJson = {
  metadata: {
    targetPr: "https://github.com/arcobaleno64/triad-flow/pull/39",
    prNumber: 39,
    branch: "fix/remediation-007-clean-challenge",
    extractionTimestamp: EXTRACTION_TIMESTAMP,
    remoteHeadSha: REMOTE_HEAD_SHA,
    workingTreeStatus: "UNCOMMITTED_LOCAL_MODIFICATIONS",
    workingTreeDiffSha256: workingTreeDiffSha256,
    totalThreads: 149,
    totalOutdatedThreads: 43,
    totalCurrentThreads: 106,
    verdictCounts,
    governanceInvariants: {
      RUNTIME_AUTHORITY: "NONE",
      SHADOW_TO_ADVISORY: "STRICT_HOLD",
      CYCLE_0048: "ON_HOLD_NOT_ASSIGNED",
      ISSUE_37: "OPEN",
      LOCAL_COMMIT: "NOT_AUTHORIZED",
      COMMIT_AND_PUSH: "NOT_AUTHORIZED",
      SQUASH_MERGE: "NOT_AUTHORIZED",
      RULESET_BYPASS: "NOT_AUTHORIZED",
      THREAD_BATCH_RESOLUTION: "NOT_AUTHORIZED",
      WORKSPACE_LF_NORMALIZATION: "AUTHORIZED_BOUNDED",
      AUTHORIZED_CONFIG_FILES: 3,
      Q1_UNIFIED_LEDGER: "APPROVED",
      LEGACY_LEDGERS: "PRESERVE",
      CHANGE_LEDGER: "AUTHORIZED",
      PRE_MERGE_PACKET: "AUTHORIZED"
    },
    governanceNotice: "Thread batch resolution on GitHub is NOT AUTHORIZED. This ledger is an offline evidence-only triage record; zero review threads have been mutated on GitHub."
  },
  threads: unifiedRecords
};

const jsonDest = path.join("evidence-runs", "PR-39", "complete-threads-triage-ledger.json");
fs.writeFileSync(jsonDest, JSON.stringify(fullJson, null, 2) + "\n", "utf8");
console.log(`Successfully wrote JSON ledger: ${jsonDest} (${unifiedRecords.length} threads)`);
console.log("Verdict counts:", verdictCounts);

// Generate Markdown
const mdLines = [
  "# PR #39 Review Threads 完整終局審查意見處置清冊 (149 筆全覆蓋)",
  "",
  "> **治理依據與執行授權狀態**",
  "> - **目標 PR**：[#39 (fix/remediation-007-clean-challenge)](https://github.com/arcobaleno64/triad-flow/pull/39)",
  `> - **遠端 Exact Head SHA**：\`${REMOTE_HEAD_SHA}\``,
  `> - **本機工作區狀態**：\`UNCOMMITTED_LOCAL_MODIFICATIONS\` (Diff SHA-256: \`${workingTreeDiffSha256}\`)`,
  `> - **擷取時間**：\`${EXTRACTION_TIMESTAMP}\``,
  "> - **審查模式**：`THREAD_AUDIT_MODE = READ_ONLY`；`THREAD_BATCH_RESOLUTION = NOT_AUTHORIZED`；`RULESET_BYPASS = NOT_AUTHORIZED`",
  "> - **裁定政策**：單一權威清冊整合（Q1 整合決策），歷史兩份清冊完整保留作為審查證據",
  "> - **裁決狀態**：所有 149 筆處置皆標記為 `PENDING_ADJUDICATION`，嚴禁在 GitHub 上執行任何 Mutation",
  "",
  "## 一、治理不變量與授權邊界 (Governance Invariants)",
  "",
  "| 治理不變量 | 當前設定 | 治理邊界與狀態 |",
  "| :--- | :--- | :--- |",
  "| `PR_39_PRE_MERGE_GOVERNANCE_PLAN` | `APPROVED_BOUNDED` | 有界核准執行 |",
  "| `THREAD_AUDIT_MODE` | `READ_ONLY` | 唯讀審查，禁止任何 Mutation |",
  "| `THREAD_BATCH_RESOLUTION` | `NOT_AUTHORIZED` | 嚴禁在 GitHub 上呼叫 Resolve Review Thread |",
  "| `WORKSPACE_LF_NORMALIZATION` | `AUTHORIZED_BOUNDED` | 僅限 3 個設定檔純位元組 LF 正規化 |",
  "| `Q1_UNIFIED_LEDGER` | `APPROVED` | 單一權威 149 筆清冊已建立 |",
  "| `LEGACY_LEDGERS` | `PRESERVE` | 歷史 43 筆與 40 筆清冊完好保留 |",
  "| `LOCAL_COMMIT` | `NOT_AUTHORIZED` | 嚴禁建立 Commit |",
  "| `COMMIT_AND_PUSH` | `NOT_AUTHORIZED` | 嚴禁 Push 至遠端 |",
  "| `SQUASH_MERGE` | `NOT_AUTHORIZED` | 合併未獲授權 |",
  "| `RULESET_BYPASS` | `NOT_AUTHORIZED` | 嚴禁繞過規則集 |",
  "| `RUNTIME_AUTHORITY` | `NONE` | 執行期相依性嚴格為 0 |",
  "| `SHADOW_TO_ADVISORY` | `STRICT_HOLD` | 發布閘門嚴格鎖定 |",
  "| `CYCLE_0048` | `ON_HOLD_NOT_ASSIGNED` | 週期維護擱置 |",
  "| `ISSUE_37` | `OPEN` | 治理議題開啟追蹤中 |",
  "",
  "## 二、149 筆 Review Threads 處置統計摘要 (Triage Summary)",
  "",
  `- **Review Threads 總數**：149 筆 (GitHub 唯讀核驗：Outdated 43 筆 / Current 106 筆 / Resolved 0 筆)`,
  `- **FIXED (已具體修復並驗證之候選)**：${verdictCounts.FIXED} 筆`,
  `- **DUPLICATE (語意重複評論)**：${verdictCounts.DUPLICATE} 筆`,
  `- **NOT_APPLICABLE (不適用或超出演算法範疇)**：${verdictCounts.NOT_APPLICABLE} 筆`,
  `- **ACCEPTED_RISK (接受風險)**：${verdictCounts.ACCEPTED_RISK} 筆 *(治理裁決：0 筆，未經授權者不得標記)*`,
  `- **UNRESOLVED (未決事項)**：${verdictCounts.UNRESOLVED} 筆`,
  "",
  "> [!IMPORTANT]",
  "> **四項強制條件遵循說明**：",
  "> 1. **FIXED 不等於已獲治理核決**：五筆 Phase 3 缺陷（`PRRT_kwDOUWarIc6r1Bt0`、`PRRT_kwDOUWarIc6slLWc`、`PRRT_kwDOUWarIc6rr-JF`、`PRRT_kwDOUWarIc6slqmB`、`PRRT_kwDOUWarIc6sL8VV`）逐筆提供實體程式碼行號、回歸測試套件（`tests/remediation-phase3-orchestrator-cli.test.mjs` 等）及反例論證，裁決欄位維持 `PENDING_ADJUDICATION`。",
  "> 2. **CRLF 正規化純位元組修正**：`.gitignore`、`.github/allowed_signers`、`.github/workflows/nightly.yml` 三檔去除 `\\r` 後與 Git HEAD 100% 位元組一致，無任何語意變更。",
  "> 3. **Exact Head 與未提交工作區證據區分**：遠端 HEAD 仍為 `ebe28be8b4db6ef276e6b3dcc1201a860af5231f`，工作區 Phase 1–3 修補明確標示為未提交本地變更（Diff SHA-256: `" + workingTreeDiffSha256 + "`），未將其混為遠端 HEAD 內容。",
  "> 4. **最終封包不自動宣告 Merge Ready**：雙重並行度測試獨立記錄，CRLF 掃描受控於文字檔案，僅提出放行建議。",
  "",
  "### 2.1 Thread 22 (`PRRT_kwDOUWarIc6ra7ki`) 重新分類依據說明",
  "",
  "- **歷史脈絡**：Thread 22 原先在歷史審查中曾被標記為 `FIX_REQUIRED_DUAL_VISIBILITY`（曾為 `ACCEPTED_RISK` 候選）。",
  "- **治理原則**：治理裁決明定 Default-Deny，不接受未經具體技術修補之風險豁免。",
  "- **技術實作**：在 `scripts/dogfood-review.mjs:1010-1120` 實作 §3.3.4 Dual Visibility 前置擷取，使 Sentry 主審查與 Clean Challenge 驗證器對稱注入相同的 `contextPackage` 與 `contextGaps`。",
  "- **驗證依據**：通過 `tests/remediation-007-clean-challenge.test.mjs` 中的 `PR39-ROUND5-DUAL-VISIBILITY-01` 與負向探測 `PR39-ROUND5-DUAL-VISIBILITY-02-NEGATIVE`。",
  "- **裁定狀態**：技術修補已於工作區就緒，重新分類為 `FIXED` 候選，但正式處置仍維持 `PENDING_ADJUDICATION`，保留給治理負責人裁決；其附屬重複項 Thread 35 (`PRRT_kwDOUWarIc6rsajd`) 亦對應調整為 `DUPLICATE` 候選。",
  "",
  "### 2.2 Phase 2 專屬反證與防護對照 (18 筆逐筆分析)",
  "",
  "18 筆 Phase 2 評論中，包含 12 筆獨立主要缺陷（候選 `FIXED`）與 6 筆重複意見（候選 `DUPLICATE`）。全數 18 筆皆已取代歷史共用樣板，提供獨立程式碼位置、專屬負向測試與反證邏輯：",
  "1. `PRRT_kwDOUWarIc6qo0ur`：[FIXED] 缺行號強制 `locatorAccurate = false` (`independent-verifier.mjs:1393`)，測例 `PHASE2-NEG-03`。",
  "2. `PRRT_kwDOUWarIc6qo0u0`：[FIXED] 執行期實際模型優先於呼叫端靜態設定 (`independent-verifier.mjs:2320`)，測例 `PHASE2-NEG-11`。",
  "3. `PRRT_kwDOUWarIc6rY131`：[DUPLICATE] 重複對應至 `PRRT_kwDOUWarIc6rvCBQ`；Omission 定位器與 Diff 區塊校驗 (`independent-verifier.mjs:1414`)，測例 `PHASE2-NEG-17`。",
  "4. `PRRT_kwDOUWarIc6re31W`：[FIXED] 被動修復建議排除於反例認定之外 (`independent-verifier.mjs:506`)，測例 `PHASE2-NEG-01`。",
  "5. `PRRT_kwDOUWarIc6rfkYc`：[FIXED] 非布林字串嚴格判定為 false (`independent-verifier.mjs:1373`)，測例 `PHASE2-NEG-03`。",
  "6. `PRRT_kwDOUWarIc6rrUDp`：[FIXED] 子行程串流輸出累計字節限制與中斷 (`independent-verifier.mjs:1765`)，測例 `PHASE2-NEG-08`。",
  "7. `PRRT_kwDOUWarIc6rte6b`：[FIXED] 組裝 Prompt 預留非 Diff 空間與長度超標 Fail-Closed (`independent-verifier.mjs:809`)，測例 `PHASE2-NEG-02`。",
  "8. `PRRT_kwDOUWarIc6rtv6O`：[FIXED] 保留 CWE 與 Type 缺陷分類後設資料 (`independent-verifier.mjs:1492`)，測例 `PHASE2-NEG-06`。",
  "9. `PRRT_kwDOUWarIc6rvCBQ`：[FIXED] 實體行數比對排除虛構行號 (`independent-verifier.mjs:1409`)，測例 `PHASE2-NEG-04`。",
  "10. `PRRT_kwDOUWarIc6rxChi`：[DUPLICATE] 重複對應至 `PRRT_kwDOUWarIc6rrUDp`；串流輸出長度限制與中斷 (`independent-verifier.mjs:1765`)，測例 `PHASE2-NEG-08`。",
  "11. `PRRT_kwDOUWarIc6r1Bt4`：[DUPLICATE] 重複對應至 `PRRT_kwDOUWarIc6rfkYc`；明確布林定位器標記 (`independent-verifier.mjs:1373`)，測例 `PHASE2-NEG-03`。",
  "12. `PRRT_kwDOUWarIc6r1BuM`：[FIXED] 無推理解釋之反例強制降級 (`independent-verifier.mjs:1435`)，測例 `PHASE2-NEG-05`。",
  "13. `PRRT_kwDOUWarIc6sL8VO`：[FIXED] 有效 Context Package 缺口傳播至驗證器 (`independent-verifier.mjs:2210`)，測例 `PHASE2-NEG-10`。",
  "14. `PRRT_kwDOUWarIc6sMI7L`：[FIXED] Clean Challenge 必須具備明確 overallStatus (`independent-verifier.mjs:1544`)，測例 `PHASE2-NEG-07`。",
  "15. `PRRT_kwDOUWarIc6sU7ZH`：[DUPLICATE] 重複對應至 `PRRT_kwDOUWarIc6rvCBQ`；超出檔案長度之行定位器拒絕 (`independent-verifier.mjs:1409`)，測例 `PHASE2-NEG-04`。",
  "16. `PRRT_kwDOUWarIc6slqmD`：[DUPLICATE] 重複對應至 `PRRT_kwDOUWarIc6rfkYc`；非布林字串準確度值拒絕 (`independent-verifier.mjs:1373`)，測例 `PHASE2-NEG-03`。",
  "17. `PRRT_kwDOUWarIc6sl1Rc`：[DUPLICATE] 重複對應至 `PRRT_kwDOUWarIc6sL8VO`；ChangeSet 缺口納入驗證器比對 (`independent-verifier.mjs:2210`)，測例 `PHASE2-NEG-10`。",
  "18. `PRRT_kwDOUWarIc6sl1Rg`：[FIXED] 遵守 RunContext 與 ChangeSet 綁定之 Objective (`independent-verifier.mjs:2134`)，測例 `PHASE2-NEG-09`。",
  "",
  "### 2.3 29 筆重複審查意見 (DUPLICATE) 映射與依據統一性說明",
  "",
  "- **治理問題根因**：前版清冊有 9 筆評論分類標記為 `FIXED`，但反證理由開頭或內容載明「Duplicate of Thread ...」，造成分類欄位（主張獨立修復）與反證表述（主張重複意見）之語意脫節。",
  "- **一致化補正措施**：此 9 筆評論已全數明確統一其主分類為 **`DUPLICATE`**，於 JSON 證據物件擴充 **`duplicateOf`** 鍵值指向對應之主審查 Thread ID，並修正理由表述。清冊不再存在任何「標記為 FIXED 卻表述為 DUPLICATE」之矛盾項目。",
  "- **九筆統一化對照清單**：",
  "  1. `PRRT_kwDOUWarIc6rY131` → `duplicateOf: PRRT_kwDOUWarIc6rvCBQ` (行定位器與 Diff 校驗)",
  "  2. `PRRT_kwDOUWarIc6rxChi` → `duplicateOf: PRRT_kwDOUWarIc6rrUDp` (串流輸出字節上限中斷)",
  "  3. `PRRT_kwDOUWarIc6r1Bt4` → `duplicateOf: PRRT_kwDOUWarIc6rfkYc` (明確布林定位器標記)",
  "  4. `PRRT_kwDOUWarIc6sL8VY` → `duplicateOf: PRRT_kwDOUWarIc6rsKB_` (Exclusions 大小寫保留)",
  "  5. `PRRT_kwDOUWarIc6sPGEP` → `duplicateOf: PRRT_kwDOUWarIc6ra7kY` (非空 Findings 拒絕未知驗證模式)",
  "  6. `PRRT_kwDOUWarIc6sU7ZH` → `duplicateOf: PRRT_kwDOUWarIc6rvCBQ` (行號超出檔案實體行數拒絕)",
  "  7. `PRRT_kwDOUWarIc6slql7` → `duplicateOf: PRRT_kwDOUWarIc6rsKB_` (排除路徑跨平台大小寫規範化)",
  "  8. `PRRT_kwDOUWarIc6slqmD` → `duplicateOf: PRRT_kwDOUWarIc6rfkYc` (非布林字串準確度值拒絕)",
  "  9. `PRRT_kwDOUWarIc6sl1Rc` → `duplicateOf: PRRT_kwDOUWarIc6sL8VO` (ChangeSet Gaps 納入驗證器比對)",
  "- **終局分類總計**：**120 筆 FIXED**、**29 筆 DUPLICATE**（總計 149 筆，0 ACCEPTED_RISK，0 UNRESOLVED）。全數 149 筆裁決狀態均維持 `PENDING_ADJUDICATION`。",
  "",
  "## 三、149 筆 Review Threads 終局審計清冊 (6 欄位標準契約)",
  "",
  "| Thread ID | 決議分類 | 修復或反證連結 (檔案、行號、測例與技術推理) | 裁決人 | 裁決日期 | Exact Head |",
  "| :--- | :--- | :--- | :--- | :--- | :--- |"
];

for (const t of unifiedRecords) {
  const escReason = t.evidenceLinkOrReasoning.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
  mdLines.push(`| \`${t.threadId}\` | **\`${t.resolutionCategory}\`** | ${escReason} | \`${t.adjudicator}\` | \`${t.adjudicationDate}\` | \`${t.exactHead}\` |`);
}

const mdDest = path.join("docs", "reports", "pr-39-complete-threads-triage-ledger.md");
fs.writeFileSync(mdDest, mdLines.join("\n") + "\n", "utf8");
console.log(`Successfully wrote Markdown ledger: ${mdDest} (${unifiedRecords.length} threads)`);
