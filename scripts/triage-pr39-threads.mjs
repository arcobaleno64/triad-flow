import fs from "node:fs";
import path from "node:path";

const BASELINE_HEAD_SHA = "bd9bc9001ee4cfee34671d6563d97deb793ff1ae";
const EXTRACTION_TIMESTAMP = "2026-10-13T09:55:54Z";

const triageRecords = [
  {
    threadId: "PRRT_kwDOUWarIc6qo0uL",
    path: "src/core/harness.mjs",
    line: 372,
    title: "Require clean verification in the default gate path",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commit 2709ea2; locator src/core/harness.mjs:458-477. Zero-finding gate requires authentic independent verification record and fails closed to 'block' unless explicitly called with options.preliminary = true. Tested in tests/remediation-007-clean-challenge.test.mjs ('007-DELTA-01').",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: BASELINE_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6qo0uP",
    path: "src/core/independent-verifier.mjs",
    line: 244,
    title: "Keep verification capability minting private",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commit 2580fd5; locator src/core/independent-verifier.mjs:252. trustedVerificationRegistry is an unexported module-private WeakSet; capability minting is strictly contained within conductIndependentVerification upon valid completion. Tested in capability security suite.",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: BASELINE_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6qo0uZ",
    path: "src/core/independent-verifier.mjs",
    line: 317,
    title: "Validate counterexample content before granting support",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commits 0b90fcb, 6e2f120, e7f1527; locator src/core/independent-verifier.mjs:489-560, 1438-1460. hasConcreteCounterexample validates failure path syntax, reproduction mechanics, and non-vacuous reasoning before granting SUPPORTED status. Tested in tests/remediation-007-clean-challenge.test.mjs ('007-P1-04').",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: BASELINE_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6qo0uk",
    path: "src/core/harness.mjs",
    line: 345,
    title: "Bind objective exclusions when validating the run context",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commits 3e95008, c418bb1; locator src/core/harness.mjs:403-429. _evaluateGateDecisionCore executes bidirectional comparison of normalized exclusions between RunContext and verificationRecord. Mismatches fail closed with FORGED_OR_STALE_RECORD ('block'). Tested in tests/remediation-007-clean-challenge.test.mjs ('007-AUDIT-THREAD-37-NEGATIVE').",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: BASELINE_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6qo0un",
    path: "src/core/harness.mjs",
    line: 361,
    title: "Require clean-challenge mode for zero-finding records",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commits 23a82a2, 2580fd5; locator src/core/harness.mjs:433-440. Enforces that zero-finding consensus strictly requires verificationMode === 'clean_challenge'. Records produced with producer_verification fail closed to 'block'. Tested in tests/remediation-007-clean-challenge.test.mjs ('007-P1-03-DELTA').",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: BASELINE_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6qo0uv",
    path: "src/core/context-builder.mjs",
    line: 343,
    title: "Detect sensitive terms inside camelCase symbols",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commit 2580fd5; locator src/core/context-builder.mjs:461. classifySensitiveCategory normalizes camelCase transitions ([a-z0-9])([A-Z]) -> $1_$2 before regex evaluation, correctly classifying symbols like handleError, hasPermission, and getDefaultFallback. Tested in tests/remediation-007-clean-challenge.test.mjs ('007-AUDIT-THREAD-11').",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: BASELINE_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6qwj_j",
    path: "src/core/context-builder.mjs",
    line: 560,
    title: "Preserve sensitive gaps after reaching the callee limit",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commit 2580fd5; locator src/core/context-builder.mjs:969-982. When fileCalleesCount >= MAX_CALLEES_PER_FILE, extraction loop continues scanning remaining candidates and registers EXTRACTION_QUOTA_EXCEEDED context gaps for unextracted sensitive callees instead of breaking early. Tested in tests/remediation-007-clean-challenge.test.mjs ('007-P1-03').",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: BASELINE_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6qwj_p",
    path: "src/core/independent-verifier.mjs",
    line: 1060,
    title: "Reject verification responses without a valid overall status",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commit c99050a; locator src/core/independent-verifier.mjs:1543-1577. In Clean Challenge mode, missing or invalid overallStatus fails closed with MALFORMED_OUTPUT error rather than normalizing to null. Tested in tests/remediation-007-clean-challenge.test.mjs ('007-P1-01').",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: BASELINE_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6qwj_t",
    path: "scripts/dogfood-review.mjs",
    line: 729,
    title: "Keep the verifier real when live reviewers are injected",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commit c99050a; locator scripts/dogfood-review.mjs:796-809. Verifier adapter selection decouples from reviewer adapters; when isLive === true, live CliVerifierAdapter is instantiated by default regardless of injected reviewAdapters. Tested in benchmark CLI integration.",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: BASELINE_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6qwj_0",
    path: "src/core/context-builder.mjs",
    line: 412,
    title: "Exclude comments and string literals from callee discovery",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commits 2580fd5, a771cd6; locator src/core/context-builder.mjs:495-560, 684. stripCommentsAndStrings strips block comments, line comments, string literals, and regex literals before extracting call symbols, preventing comment text from triggering spurious context gaps. Tested in regex hardening test suite.",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: BASELINE_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6rTXZd",
    path: "src/core/context-builder.mjs",
    line: 295,
    title: "Skip parameter braces when locating function bodies",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commit 2580fd5; locator src/core/context-builder.mjs:309-328. findFunctionDefinitions tracks parenthesis nesting depth (parenDepth) and begins searching for the function body opening brace '{' only after parameter list closing paren ')' (parenDepth <= 0).",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: BASELINE_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6rTXZh",
    path: "src/core/context-builder.mjs",
    line: 798,
    title: "Record uncertainty when byte-budget eviction drops callees",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commit 2580fd5; locator src/core/context-builder.mjs:1486-1498, 1626-1638. When Layer 1 byte budgeting evicts sensitive definitions exceeding the 8 KB AST ceiling, GLOBAL_AST_CONTEXT_CEILING_EXCEEDED context gaps are recorded, propagating to verifier UNCERTAIN. Tested in tests/remediation-007-clean-challenge.test.mjs ('007-AUDIT-P1-01').",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: BASELINE_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6rTXZn",
    path: "src/core/independent-verifier.mjs",
    line: 991,
    title: "Reject omissions that lack an evidence-support verdict",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commit 05fb0fa; locator src/core/independent-verifier.mjs:1417-1420. Under Default-Deny, omissions missing both evidenceSupport and verdict default to INSUFFICIENT_EVIDENCE instead of SUPPORTED. Tested in tests/remediation-007-clean-challenge.test.mjs ('007-AUDIT-THREAD-23').",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: BASELINE_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6rTowe",
    path: "src/core/independent-verifier.mjs",
    line: 261,
    title: "Keep the remaining verification issuer private",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commit 2580fd5; locator src/core/independent-verifier.mjs:440. issueVerificationRecordFromOutput registers minted records into segregatedSyntheticRegistry. evaluateGateDecision strictly rejects synthetic records in production gates (UNTRUSTED_VERIFICATION_RECORD). Tested in tests/remediation-007-clean-challenge.test.mjs ('007-P1-01-DELTA').",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: BASELINE_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6rTowi",
    path: "src/core/context-builder.mjs",
    line: 888,
    title: "Distinguish an empty blob from a failed exact-head lookup",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commit 2580fd5; locator src/core/context-builder.mjs:1358-1365. Uses nullish check fileContent === null rather than falsiness check, allowing legitimately empty files '' at exact HEAD to be processed without triggering exactHeadUnavailable.",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: BASELINE_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6rTowl",
    path: "src/core/independent-verifier.mjs",
    line: 1853,
    title: "Preserve verifier uncertainty over caller overrides",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commit 2580fd5; locator src/core/independent-verifier.mjs:385-388, 2346-2349. Defensive check guarantees that options.overallStatus cannot downgrade validated UNCERTAIN or DEFECTS_FOUND to CLEAN. Tested in tests/remediation-007-clean-challenge.test.mjs ('007-AUDIT-P1-02').",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: BASELINE_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6rTowq",
    path: "src/core/context-builder.mjs",
    line: 266,
    title: "Reject call sites when locating callee definitions",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commit 2580fd5; locator src/core/context-builder.mjs:274-292. findFunctionDefinitions rejects call expressions, statement keywords (if, while, return), and property declarations, ensuring semicolon-free call expressions are not mistaken for function definitions. Tested in tests/remediation-007-clean-challenge.test.mjs ('007-AUDIT-THREAD-28').",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: BASELINE_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6rVNc1",
    path: "src/core/independent-verifier.mjs",
    line: 1288,
    title: "Propagate every sensitive context gap to uncertainty",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commit 2580fd5; locator src/core/independent-verifier.mjs:1594-1602. All unresolved sensitive contextGaps (including UNRESOLVED_SYMBOL, EXTRACTION_QUOTA_EXCEEDED, GLOBAL_AST_CONTEXT_CEILING_EXCEEDED) force overallStatus = 'UNCERTAIN'. Tested in tests/remediation-007-clean-challenge.test.mjs ('007-AUDIT-P1-01').",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: BASELINE_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6rY13u",
    path: "src/core/independent-verifier.mjs",
    line: 1886,
    title: "Keep recorded exclusions identical to verifier scope",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commit 3e95008; locator src/core/independent-verifier.mjs:2143-2155, 2361. Canonical normContract.exclusions derives both prompt text and verification record exclusions, preventing discrepancies between verifier scope and gate binding.",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: BASELINE_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6rY139",
    path: "src/core/independent-verifier.mjs",
    line: 1241,
    title: "Reject Clean Challenge evaluations without producer findings",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commit 23a82a2; locator src/core/independent-verifier.mjs:1531-1541. In clean_challenge mode (reviewing 0 producer findings), returning a non-empty evaluations array fails closed with MALFORMED_OUTPUT. Tested in tests/remediation-007-clean-challenge.test.mjs ('007-AUDIT-THREAD-35').",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: BASELINE_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6ra7kH",
    path: "src/adapters/review-orchestrator.mjs",
    line: 238,
    title: "Bind supplied records to the current ChangeSet",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commits c418bb1, 0ac63a1; locator src/adapters/review-orchestrator.mjs:51-95, 345-360. buildCanonicalRunContext derives and binds authoritative RunContext from current changeSet content digests before gate evaluation. Tested in tests/remediation-007-clean-challenge.test.mjs ('007-AUDIT-THREAD-37').",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: BASELINE_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6ra7ki",
    path: "scripts/dogfood-review.mjs",
    line: 972,
    title: "Build callee context before invoking primary reviewers",
    resolutionCategory: "ACCEPTED_RISK",
    evidenceLinkOrReasoning: "REQUIRES EXPLICIT USER GOVERNANCE AUTHORIZATION. Architectural Decision: In Track D1 Shadow Dogfood Review, primary sentries (agy, claude, codex) intentionally perform zero-knowledge diff review to preserve independent multi-party consensus and benchmark reproducibility without prompt bias; context package extraction is strictly reserved for the 4th-party sentry Clean Challenge verifier (claude-5.5-sonnet).",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: BASELINE_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6ra7kt",
    path: "src/adapters/review-prompts.mjs",
    line: 222,
    title: "Escape callee source before embedding prompt markup",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commit 3e95008; locator src/adapters/review-prompts.mjs:163-260. Callee definitions and XML attributes are escaped via escapeXmlText and escapeXmlAttribute before XML prompt assembly. Tested in tests/remediation-007-clean-challenge.test.mjs ('007-AUDIT-THREAD-42').",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: BASELINE_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6re305",
    path: "src/adapters/review-orchestrator.mjs",
    line: 78,
    title: "Derive the binding digest from ChangeSet contents",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commit 0ac63a1; locator src/adapters/review-orchestrator.mjs:51-95. buildCanonicalRunContext strictly recomputes digest from diffHunks and verifies declared digests against recomputed values. Tested in tests/remediation-007-clean-challenge.test.mjs ('007-DELTA-P1-01-NEGATIVE').",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: BASELINE_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6re31A",
    path: "src/core/context-builder.mjs",
    line: 528,
    title: "Track qualified sensitive calls during callee discovery",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commits 2580fd5, 76e8652; locator src/core/context-builder.mjs:700-740. Qualified calls (auth.validateAccess, this.verifyToken) are extracted with qualifiers and classified for sensitivity. Tested in tests/remediation-007-clean-challenge.test.mjs ('007-DELTA-P1-03').",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: BASELINE_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6re31P",
    path: "src/core/harness.mjs",
    line: 686,
    title: "Reject unexplained DEFECTS_FOUND statuses",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commit c99050a; locator src/core/harness.mjs:843-863. Verifier DEFECTS_FOUND without SUPPORTED omission flags 'Verifier Status Inconsistent' and sets hasHumanReview = true (human_review_required). Tested in tests/remediation-007-clean-challenge.test.mjs ('007-DELTA-P1-04').",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: BASELINE_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6rfkYK",
    path: "scripts/dogfood-review.mjs",
    line: 970,
    title: "Fail closed when supplied changesets lack repository roots",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commits cc1de22, bd9bc90; locator scripts/dogfood-review.mjs:976-989. Absence of trusted repository root sets contextExtractionFailed = true and records EXACT_HEAD_CONTEXT_FAILED, failing closed to UNCERTAIN / human_review_required. Negative test: tests/remediation-007-clean-challenge.test.mjs ('PR39-ROUND3-ITEM2-NEGATIVE').",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: BASELINE_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6rhwEx",
    path: "src/core/context-builder.mjs",
    line: 866,
    title: "Resolve newly added local definitions before declaring a gap",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commit 2580fd5; locator src/core/context-builder.mjs:1358-1365, src/core/git-collector.mjs:44-67. Exact-head retrieval via getExactHeadFileContent(repoRoot, headSha, path) inspects the exact commit tree containing the applied patch.",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: BASELINE_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6riPTp",
    path: "src/core/context-builder.mjs",
    line: 637,
    title: "Preserve receiver identity when deduplicating callees",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commit 76e8652; locator src/core/context-builder.mjs:735-755. Callee candidate deduplication key includes qualifier (${qualifier ? `${qualifier}.` : ''}${sym}), preserving distinct receiver identities. Tested in tests/remediation-007-clean-challenge.test.mjs ('PR39-GATE-OUT-02-NEGATIVE').",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: BASELINE_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6riPT0",
    path: "scripts/dogfood-review.mjs",
    line: 969,
    title: "Bind supplied context packages to the reviewed ChangeSet",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commit 1c33d99; locator scripts/dogfood-review.mjs:991-1120. Validates headSha, repositoryRoot, contentDigest, and fileCoverageManifest against current ChangeSet before accepting external context package. Tested in tests/remediation-007-clean-challenge.test.mjs ('PR39-GATE-OUT-01-NEGATIVE').",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: BASELINE_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6rrHOT",
    path: "src/core/harness.mjs",
    line: 550,
    title: "Compare the complete finding when binding records",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commits 0b90fcb, 6e2f120; locator src/core/harness.mjs:260-280. getFindingSignature incorporates title, file, line, line_end, type, cwe, severity, and recommendation for comprehensive tampering protection. Tested in tests/remediation-007-clean-challenge.test.mjs ('PR39-DELTA-P1-04-NEGATIVE').",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: BASELINE_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6rr-JA",
    path: "src/core/independent-verifier.mjs",
    line: 1932,
    title: "Preserve package gaps when explicit gaps are empty",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commit 0b90fcb; locator src/core/independent-verifier.mjs:687-730. mergeContextGaps unions caller gaps and package gaps, ensuring empty caller arrays cannot wipe out package gaps. Tested in tests/remediation-007-clean-challenge.test.mjs ('PR39-DELTA-P1-03-NEGATIVE').",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: BASELINE_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6rsKB6",
    path: "scripts/dogfood-review.mjs",
    line: 1024,
    title: "Verify package digests only against recomputed diff hashes",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commit 0b90fcb; locator scripts/dogfood-review.mjs:1033-1078. Declared digests validated against recomputed diff hashes before validating package digest. Tested in tests/remediation-007-clean-challenge.test.mjs ('PR39-DELTA-P1-01-NEGATIVE').",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: BASELINE_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6rsajd",
    path: "scripts/dogfood-review.mjs",
    line: 970,
    title: "Build exact-head context before invoking primary sentries",
    resolutionCategory: "DUPLICATE",
    evidenceLinkOrReasoning: "Duplicate of Thread 22 (PRRT_kwDOUWarIc6ra7ki). Both raise exact-head callee context availability before primary reviewer invocation in runDogfoodReview.",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: BASELINE_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6rtv6E",
    path: "scripts/dogfood-review.mjs",
    line: 976,
    title: "Treat an omitted repository root as extraction failure",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commits cc1de22, bd9bc90; locator scripts/dogfood-review.mjs:976-989. Omitted repository or object missing root fails closed to contextExtractionFailed = true with EXACT_HEAD_CONTEXT_FAILED. Negative test: tests/remediation-007-clean-challenge.test.mjs ('PR39-ROUND3-ITEM2-NEGATIVE').",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: BASELINE_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6rtv6M",
    path: "scripts/dogfood-review.mjs",
    line: 1084,
    title: "Reject manifests that lack exact-head coverage",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commits cf6be07, eda22b9, e7f1527; locator scripts/dogfood-review.mjs:1091-1100. Reject manifests where exactHeadAvailable === false or exactHeadUnavailable === true, setting pkgInvalid = true and failing closed. Tested in tests/remediation-007-clean-challenge.test.mjs ('PR39-ROUND2-ITEM2-NEGATIVE').",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: BASELINE_HEAD_SHA
  }
];

// 1. Build JSON Ledger
const jsonLedger = {
  metadata: {
    targetPr: "https://github.com/arcobaleno64/triad-flow/pull/39",
    prNumber: 39,
    branch: "fix/remediation-007-clean-challenge",
    extractionTimestamp: EXTRACTION_TIMESTAMP,
    baselineHeadSha: BASELINE_HEAD_SHA,
    totalOutdatedThreads: triageRecords.length,
    verdictCounts: {
      FIXED: triageRecords.filter(r => r.resolutionCategory === "FIXED").length,
      ACCEPTED_RISK: triageRecords.filter(r => r.resolutionCategory === "ACCEPTED_RISK").length,
      DUPLICATE: triageRecords.filter(r => r.resolutionCategory === "DUPLICATE").length,
      NOT_APPLICABLE: triageRecords.filter(r => r.resolutionCategory === "NOT_APPLICABLE").length,
      UNRESOLVED: triageRecords.filter(r => r.resolutionCategory === "UNRESOLVED").length
    },
    governanceInvariants: {
      RUNTIME_AUTHORITY: "NONE",
      SHADOW_TO_ADVISORY: "STRICT_HOLD",
      CYCLE_0048: "ON_HOLD_NOT_ASSIGNED",
      ISSUE_37: "OPEN",
      SQUASH_MERGE: "NOT_AUTHORIZED",
      GITHUB_RULESET_BYPASS: "NOT_AUTHORIZED",
      THREAD_BATCH_RESOLUTION: "NOT_AUTHORIZED",
      THREAD_TRIAGE: "AUTHORIZED_AS_POLICY"
    },
    governanceNotice: "Thread batch resolution on GitHub is NOT AUTHORIZED. This ledger is an evidence-only triage record; zero review threads have been mutated on GitHub."
  },
  threads: triageRecords.map(r => ({
    threadId: r.threadId,
    resolutionCategory: r.resolutionCategory,
    evidenceLinkOrReasoning: r.evidenceLinkOrReasoning,
    adjudicator: r.adjudicator,
    adjudicationDate: r.adjudicationDate,
    exactHead: r.exactHead,
    fileLocation: `${r.path}:${r.line}`,
    title: r.title
  }))
};

const jsonDir = path.resolve("evidence-runs", "PR-39");
fs.mkdirSync(jsonDir, { recursive: true });
const jsonPath = path.join(jsonDir, "review-threads-triage.json");
fs.writeFileSync(jsonPath, JSON.stringify(jsonLedger, null, 2) + "\n", "utf8");
console.log(`Wrote JSON ledger: ${jsonPath}`);

// 2. Build Markdown Report
const mdLines = [
  "# Triad-Flow PR #39 Outdated Review Threads Evidence Triage Ledger",
  "",
  "> **Governance Notice & Execution Boundaries**",
  "> - **Target PR**: [#39 (fix/remediation-007-clean-challenge)](https://github.com/arcobaleno64/triad-flow/pull/39)",
  `> - **Extraction Timestamp**: \`${EXTRACTION_TIMESTAMP}\``,
  `> - **Baseline Extraction Head SHA**: \`${BASELINE_HEAD_SHA}\``,
  "> - **Mutation Policy**: Zero GitHub mutations performed. `THREAD_BATCH_RESOLUTION = NOT_AUTHORIZED`; `GITHUB_RULESET_BYPASS = NOT_AUTHORIZED`; `SQUASH_MERGE = NOT_AUTHORIZED`.",
  "> - **Adjudication State**: All candidate records marked `PENDING_ADJUDICATION` under Default-Deny.",
  "",
  "## Governance Invariants & Policy Holds",
  "",
  "| Invariant | Setting | Authority / Status |",
  "| :--- | :--- | :--- |",
  "| `RUNTIME_AUTHORITY` | `NONE` | Strict Advisory Mode |",
  "| `SHADOW_TO_ADVISORY` | `STRICT_HOLD` | Release Gate Locked |",
  "| `CYCLE_0048` | `ON_HOLD_NOT_ASSIGNED` | Policy Hold |",
  "| `ISSUE_37` | `OPEN` | Governance Tracking Open |",
  "| `SQUASH_MERGE` | `NOT_AUTHORIZED` | Merge Invariant |",
  "| `GITHUB_RULESET_BYPASS` | `NOT_AUTHORIZED` | Merge Invariant |",
  "| `THREAD_BATCH_RESOLUTION` | `NOT_AUTHORIZED` | Dry-run Evidence Ledger Only |",
  "| `THREAD_TRIAGE` | `AUTHORIZED_AS_POLICY` | Evidence Ledger Authorized |",
  "",
  "## Summary of Candidate Classifications",
  "",
  `- **Total Outdated Threads**: ${triageRecords.length}`,
  `- **FIXED**: ${triageRecords.filter(r => r.resolutionCategory === "FIXED").length}`,
  `- **ACCEPTED_RISK**: ${triageRecords.filter(r => r.resolutionCategory === "ACCEPTED_RISK").length} *(Flags: Thread 22 / \`PRRT_kwDOUWarIc6ra7ki\` requires explicit user governance authorization)*`,
  `- **DUPLICATE**: ${triageRecords.filter(r => r.resolutionCategory === "DUPLICATE").length} *(Thread 34 duplicate of Thread 22)*`,
  `- **NOT_APPLICABLE**: ${triageRecords.filter(r => r.resolutionCategory === "NOT_APPLICABLE").length}`,
  `- **UNRESOLVED**: ${triageRecords.filter(r => r.resolutionCategory === "UNRESOLVED").length}`,
  "",
  "## ⚠️ Explicit Governance Authorization Flag (ACCEPTED_RISK)",
  "",
  "> [!WARNING]",
  "> **Candidate ACCEPTED_RISK Flagged for User Governance Authorization**:",
  "> - **Thread ID**: `PRRT_kwDOUWarIc6ra7ki` (and Duplicate `PRRT_kwDOUWarIc6rsajd`)",
  "> - **Location**: `scripts/dogfood-review.mjs:972`",
  "> - **Issue**: Suggests extracting and passing exact-head callee context package to primary sentries (agy, claude, codex) before initial tri-party review.",
  "> - **Technical Rationale**: In Track D1 Shadow Dogfood Review, primary sentries intentionally perform zero-knowledge diff review to preserve independent multi-party consensus and benchmark reproducibility without prompt bias. Callee context extraction is strictly bounded to the 4th-party sentry Clean Challenge verifier (claude-5.5-sonnet).",
  "> - **Governance Requirement**: Marking this thread as resolved under `ACCEPTED_RISK` requires explicit user governance authorization.",
  "",
  "## Auditable 6-Field Evidence Triage Table",
  "",
  "| # | Thread ID | 決議分類 | 修復或反證連結 | 裁決人 | 裁決日期 | Exact Head |",
  "| :---: | :--- | :--- | :--- | :--- | :--- | :--- |"
];

for (let i = 0; i < triageRecords.length; i++) {
  const r = triageRecords[i];
  const escapedReasoning = r.evidenceLinkOrReasoning.replace(/\|/g, "\\|");
  mdLines.push(`| ${i + 1} | \`${r.threadId}\` | **${r.resolutionCategory}** | ${escapedReasoning} | \`${r.adjudicator}\` | \`${r.adjudicationDate}\` | \`${r.exactHead.slice(0, 12)}...\` |`);
}

mdLines.push(
  "",
  "## Head SHA Provenance Distinction",
  "",
  `- **Triage Baseline Extraction Head**: \`${BASELINE_HEAD_SHA}\``,
  "- **Triage Baseline Status**: 100 unresolved threads (36 outdated, 64 current) on PR #39.",
  "- **Post-Remediation Push Head**: Distinct commit generated on `origin/fix/remediation-007-clean-challenge` incorporating technical boundary remediations P1-A, P1-B, and evidence ledger artifacts."
);

const mdDir = path.resolve("docs", "reports");
fs.mkdirSync(mdDir, { recursive: true });
const mdPath = path.join(mdDir, "pr-39-review-threads-triage.md");
fs.writeFileSync(mdPath, mdLines.join("\n") + "\n", "utf8");
console.log(`Wrote Markdown report: ${mdPath}`);
