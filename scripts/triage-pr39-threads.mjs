import fs from "node:fs";
import path from "node:path";

const BASELINE_HEAD_SHA = "bd9bc9001ee4cfee34671d6563d97deb793ff1ae";
const CURRENT_HEAD_SHA = "089b66fb166888baf7ad47fae76081586ad2fa38";
const EXTRACTION_TIMESTAMP = "2026-10-15T01:42:00Z";

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
    resolutionCategory: "FIX_REQUIRED_DUAL_VISIBILITY",
    evidenceLinkOrReasoning: "Per governance ruling, ACCEPTED_RISK is NOT approved. Spec baseline: REMEDIATION-007 §3.3.4 (Dual Visibility requires contextPackage injected simultaneously into both Sentry primary review and Clean Challenge verifier). Implementation fix in scripts/dogfood-review.mjs approved under Option B; GitHub thread remains UNRESOLVED until verified.",
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
    threadId: "PRRT_kwDOUWarIc6re31K",
    path: "scripts/dogfood-review.mjs",
    line: 984,
    title: "Fail closed when context-package extraction throws",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commit 8375c65 / 02be43c; locator scripts/dogfood-review.mjs:1013-1028. Extraction failures register EXACT_HEAD_CONTEXT_FAILED in effectiveContextGaps, causing downstream gate evaluation to fail closed to human_review_required. Tested in tests/remediation-007-clean-challenge.test.mjs ('PR39-ROUND5-DUAL-VISIBILITY-02-NEGATIVE').",
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
    evidenceLinkOrReasoning: "Duplicate of Thread 22 (PRRT_kwDOUWarIc6ra7ki). Disposition subordinate to Thread 22 (FIX_REQUIRED_DUAL_VISIBILITY under REMEDIATION-007 §3.3.4). GitHub thread remains UNRESOLVED.",
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
  },
  {
    threadId: "PRRT_kwDOUWarIc6sMI7c",
    path: "src/adapters/staged-review.mjs",
    line: 622,
    title: "Preserve context gaps in staged fallback prompts",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commits a71082c, HEAD; locator src/adapters/staged-review.mjs:610-630. Preserves and merges caller-provided contextGaps with chunk-level contextPkg gaps, injecting effectiveChunkContextGaps into buildEvidenceReviewPrompt and adapter.executeReview. Tested in tests/remediation-007-clean-challenge.test.mjs ('PR39-ROUND6-STAGED-DUAL-VISIBILITY-01', 'PR39-ROUND6-STAGED-DUAL-VISIBILITY-02-NEGATIVE').",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: CURRENT_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6sPGEl",
    path: "src/adapters/staged-review.mjs",
    line: 385,
    title: "Re-extract exact-head contextPackage when options.contextPackage is null or empty",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commits 187a878, d621bd9, HEAD; locator src/adapters/staged-review.mjs:385-480. When callerContextPackage is null, undefined, or vacuous ({}, { layers: {} }), staged review invokes buildContextPackage with repositoryRoot fallback. If unavailable, fails closed with EXACT_HEAD_CONTEXT_FAILED. Tested in tests/remediation-007-clean-challenge.test.mjs ('PR39-ROUND7-STAGED-NULL-CONTEXT-REEXTRACTION-01', 'PR39-ROUND7-STAGED-NULL-CONTEXT-FAIL-CLOSED-02-NEGATIVE', 'PR39-ROUND7-STAGED-VACUOUS-OBJECT-REEXTRACTION-05', 'PR39-ROUND8-STAGED-VACUOUS-LAYERS-REEXTRACTION-06', 'PR39-ROUND8-STAGED-VACUOUS-LAYERS-FAIL-CLOSED-07-NEGATIVE').",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: CURRENT_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6sPmwz",
    path: "scripts/dogfood-review.mjs",
    line: 1400,
    title: "Attribute stagedFallbackUsed and staged review telemetry per provider",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commits 187a878, d621bd9, HEAD; locator scripts/dogfood-review.mjs:1040-1175, 1400-1465. Provider telemetry individually tracks agyStagedFallbackUsed, claudeStagedFallbackUsed, and codexStagedFallbackUsed alongside per-provider chunk counts and timeout metrics. Tested in tests/remediation-007-clean-challenge.test.mjs ('PR39-ROUND7-STAGED-PROVIDER-TELEMETRY-ATTRIBUTION-02', 'PR39-ROUND8-STAGED-MULTI-PROVIDER-TELEMETRY-08').",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: CURRENT_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6slAMk",
    path: "src/adapters/staged-review.mjs",
    line: 422,
    title: "Bind caller context packages to the reviewed change set",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commit 089b66f; locator src/adapters/staged-review.mjs:406-490. Recomputes candidate diff contentDigests and enforces strict identity, contentDigest, repositoryRoot, and file coverage scope binding between callerContextPackage and changeSet. Unbound, mismatched, or cross-changeset packages fail closed with EXACT_HEAD_CONTEXT_FAILED and are not forwarded to chunks. Tested in tests/remediation-007-clean-challenge.test.mjs ('PR39-ROUND9-STAGED-UNBOUND-CONTEXT-FAIL-CLOSED-11-NEGATIVE', 'PR39-ROUND9-STAGED-NORMALIZED-REPO-AND-DIGEST-13').",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: CURRENT_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6slAMq",
    path: "src/adapters/staged-review.mjs",
    line: 323,
    title: "Merge change-set gaps with explicitly supplied staged gaps",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commit 089b66f; locator src/adapters/staged-review.mjs:322-325. callerContextGaps now merges options.contextGaps and changeSet.contextGaps via mergeContextGaps, ensuring explicitly passing options.contextGaps = [] cannot clear pre-existing gaps such as EXACT_HEAD_CONTEXT_FAILED. Tested in tests/remediation-007-clean-challenge.test.mjs ('PR39-ROUND9-STAGED-MERGE-CALLER-CONTEXT-GAPS-12-NEGATIVE').",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: CURRENT_HEAD_SHA
  },
  {
    threadId: "PRRT_kwDOUWarIc6slAMz",
    path: "scripts/triage-pr39-threads.mjs",
    line: 5,
    title: "Point the evidence ledger at a commit containing its fixes",
    resolutionCategory: "FIXED",
    evidenceLinkOrReasoning: "Commits 089b66f, 9a59e90, HEAD; locator scripts/triage-pr39-threads.mjs:4-6. Synchronized CURRENT_HEAD_SHA to a commit containing the complete fixes (P1-DV-03, P2-TELEMETRY-02, P1-CONTEXT-BINDING-01, P1-CONTEXT-GAPS-01), ensuring consumers can reproduce every stated remediation and cited location from the recorded exact head.",
    adjudicator: "PENDING_ADJUDICATION",
    adjudicationDate: "PENDING_ADJUDICATION",
    exactHead: CURRENT_HEAD_SHA
  }
];

const deltaFindings = [
  {
    id: "P1-DV-01",
    severity: "P1",
    status: "REMEDIATED",
    title: "Staged Review 未沿用已驗證的 Context (§3.3.4 Dual Visibility)",
    locations: [
      "scripts/dogfood-review.mjs:1059-1077",
      "src/adapters/staged-review.mjs:516-572"
    ],
    issue: "Staged fallback (executeStagedReview / executeChunk) was rebuilding context independently rather than forwarding caller-provided exact-head contextPackage and contextGaps, breaking §3.3.4 Dual Visibility identical contextual enclosure invariant.",
    remediation: "executeStagedReview and executeChunk now forward caller-provided contextPackage and effectiveContextGaps through to prompt assembly and chunk adapter calls, ensuring identical enclosures between primary sentries and Clean Challenge verifier. Fail-closed behavior enforced on context absence or inconsistency."
  },
  {
    id: "P1-DV-02",
    severity: "P1",
    status: "REMEDIATED",
    title: "executeStagedReview 在 contextPackage 為 null/falsy 時繞過重新擷取 (§3.3.4 Dual Visibility)",
    locations: [
      "src/adapters/staged-review.mjs:380-480",
      "src/adapters/staged-review.mjs:690-705"
    ],
    issue: "staged-review.mjs 以 callerContextPackage !== undefined 判斷是否沿用外部 Context，當明確傳入 null 且無 EXACT_HEAD_CONTEXT_FAILED 時略過 buildContextPackage 重新擷取，導致缺少必要 Context 與不確定性提示即進入 Chunk Review。",
    remediation: "executeStagedReview 強化 callerContextPackage 驗證，僅在有效非空物件時直接沿用；若為 null/undefined 且無 extraction gap 則強制呼叫 buildContextPackage 重新擷取有效 exact-head contextPackage。若擷取失敗或 exact-head 不可用，則傳播 EXACT_HEAD_CONTEXT_FAILED 不確定性 gap 並阻止 Clean Approval。"
  },
  {
    id: "P1-DV-03",
    severity: "P1",
    status: "REMEDIATED",
    title: "executeStagedReview 在部分空白 Context ({ layers: {} } 或無 Head/Digest) 時繞過重新擷取",
    locations: [
      "src/adapters/staged-review.mjs:385-420"
    ],
    issue: "staged-review.mjs 原以 !callerContextPackage.layers 判斷 contextPackage 是否 vacuous，當傳入 { layers: {} }、[{}] 空 manifest、缺少 Head SHA / Digest 或包含 throwing getters 時，繞過 buildContextPackage 重新擷取或造成未處理例外，導致無效或損毀 Context 進入 Chunk Review。",
    remediation: "強化 isCallerContextVacuous 與 Context 驗證，要求 contextPackage 必須具備非空層級 (substantive layers) 或具備具體檔案標識的非空 File Coverage Manifest，且必須包含有效 Head SHA 或 Content Digest；並加入安全屬性讀取以防範 throwing getters 與代理攻擊；否則視為 vacuous 強制呼叫 buildContextPackage 重新擷取，若擷取失敗或物件異常則 fail-closed 注入 EXACT_HEAD_CONTEXT_FAILED。"
  },
  {
    id: "P2-TELEMETRY-01",
    severity: "P2",
    status: "REMEDIATED",
    title: "三方 Staged 遙測歸屬錯誤 (dogfood-review.mjs providerTelemetry)",
    locations: [
      "scripts/dogfood-review.mjs:1400-1402"
    ],
    issue: "dogfood-review.mjs 將全域 stagedFallbackUsed 寫給 agy，並將 claude、codex 固定為 false，導致單一 Provider (如 Claude) 觸發 Staged Fallback 時遙測歸屬錯誤。",
    remediation: "分別追蹤 agyStagedFallbackUsed, claudeStagedFallbackUsed, codexStagedFallbackUsed，並如實填入 providerTelemetry[provider].stagedFallbackUsed。"
  },
  {
    id: "P2-TELEMETRY-02",
    severity: "P2",
    status: "REMEDIATED",
    title: "多 Provider 同時觸發 Staged Fallback 時遙測彙總與 Chunk 統計覆蓋 (dogfood-review.mjs)",
    locations: [
      "scripts/dogfood-review.mjs:1040-1175",
      "scripts/dogfood-review.mjs:1425-1490"
    ],
    issue: "dogfood-review.mjs 之 stagedTelemetry 與 stagedChunkCount 使用共用變數，多 Provider 同時觸發 Staged Fallback 時僅保留單一 Provider 遙測，造成其他 Provider 的 Chunk 數、Timeout 數與預算統計被覆蓋。",
    remediation: "dogfood-review.mjs 獨立追蹤各 Provider 之 stagedTelemetry、stagedChunkCount 與 stagedTimeoutCount，於 providerTelemetry 中提供各 Provider 細部數據，並在全域 telemetryMetrics 與 phaseMetrics.byProvider 準確彙總，避免多 Provider 同時 Staged 時數據遺失。"
  },
  {
    id: "P1-CONTEXT-BINDING-01",
    severity: "P1",
    status: "REMEDIATED",
    title: "外部 Context 未完整綁定 ChangeSet (staged-review.mjs)",
    locations: [
      "src/adapters/staged-review.mjs:406-490"
    ],
    issue: "在 staged-review.mjs 中，hasHeadOrDigest 只要求存在非空的 headSha、contentDigest 或 digest 其中之一，未比對 contentDigest 與實際 changeSet.diffHunks。一份具有非空 Layers、有效形式 Manifest、但只有過期 Digest 而沒有 Head SHA 的 Context 存在被當成有效輸入的路徑。",
    remediation: "重新計算 diff contentDigest，嚴格比對 caller contextPackage 之 headSha、contentDigest、repositoryRoot 及檔案涵蓋範圍。非空 Context 必須具備與目前 ChangeSet 一致的 Head SHA 或 Content Digest 綁定，驗證失敗即 Fail-Closed 注入 EXACT_HEAD_CONTEXT_FAILED 並阻斷 Clean Approval。"
  },
  {
    id: "P1-CONTEXT-GAPS-01",
    severity: "P1",
    status: "REMEDIATED",
    title: "明確傳入空陣列可能遮蔽既有 Gap (staged-review.mjs options.contextGaps)",
    locations: [
      "src/adapters/staged-review.mjs:321-325"
    ],
    issue: "staged-review.mjs 原以 options.contextGaps !== undefined 優先選取 callerContextGaps，當呼叫端傳入空陣列 options.contextGaps: [] 時，changeSet.contextGaps 中的既有 Gap (如 EXACT_HEAD_CONTEXT_FAILED) 會被捨棄，導致後續無法傳播不確定性。",
    remediation: "以 mergeContextGaps(options.contextGaps, changeSet?.contextGaps) 合併兩者，確保傳入空陣列無法清除既有 contextGaps。"
  },
  {
    id: "P1-CONTEXT-BINDING-02",
    severity: "P1",
    status: "REMEDIATED",
    title: "未驗證之宣告 Digest 與 Trimmed Diff 雜湊混入候選集合 (staged-review.mjs changeSetDigestCandidates)",
    locations: [
      "src/adapters/staged-review.mjs:410-440"
    ],
    issue: "在 staged-review.mjs 中，changeSetDigestCandidates 盲目將未驗證之宣告 digest (changeSet.contentDigest 與 changeSet.changeSetDigest) 以及 diffHunks.trim() 加入候選集合。當呼叫端傳入之 contextPackage.contentDigest 與 changeSet.contentDigest 一致、但兩者皆與 physical diffHunks 雜湊衝突時，hasMatchingDigest 仍判定為 true，導致未受真實 diff 錨定之 contextPackage 被錯誤信任。",
    remediation: "changeSetDigestCandidates 僅能由 physical diffHunks 之原始雜湊、正規化 LF 雜湊及獨立重算之 digestChangeSet 產生，移除 diffHunks.trim()。未驗證之 changeSet.contentDigest 與 changeSet.changeSetDigest 不得直接加入可信集合，且若其與重算之 diff digest 衝突時立即標記衝突並 Fail-Closed 阻斷 Clean Approval。"
  },
  {
    id: "P2-LEDGER-HEAD-01",
    severity: "P2",
    status: "REMEDIATED",
    title: "證據清冊之 CURRENT_HEAD_SHA 指向早於修補完成之 Commit (scripts/triage-pr39-threads.mjs)",
    locations: [
      "scripts/triage-pr39-threads.mjs:4-6"
    ],
    issue: "先前清冊之 currentHeadSha 指向歷史 commit (d621bd9)，早於 P2-TELEMETRY-02 等修復提交，導致依該 SHA 無法重現所宣稱之 locator 與修復內容。",
    remediation: "將 currentHeadSha 更新至包含完整修復之 Commit SHA，確保所有修補聲明與證據引用皆可在記錄之 Exact Head 完整重現與檢驗。"
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
    currentHeadSha: CURRENT_HEAD_SHA,
    totalOutdatedThreads: triageRecords.length,
    verdictCounts: {
      FIXED: triageRecords.filter(r => r.resolutionCategory === "FIXED").length,
      FIX_REQUIRED_DUAL_VISIBILITY: triageRecords.filter(r => r.resolutionCategory === "FIX_REQUIRED_DUAL_VISIBILITY").length,
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
  deltaFindings,
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
  `- **FIX_REQUIRED_DUAL_VISIBILITY**: ${triageRecords.filter(r => r.resolutionCategory === "FIX_REQUIRED_DUAL_VISIBILITY").length} *(Thread 22 / \`PRRT_kwDOUWarIc6ra7ki\`: ACCEPTED_RISK rejected; spec baseline §3.3.4 Dual Visibility enforced)*`,
  `- **DUPLICATE**: ${triageRecords.filter(r => r.resolutionCategory === "DUPLICATE").length} *(Thread 34 duplicate of Thread 22; disposition subordinate to Thread 22)*`,
  `- **ACCEPTED_RISK**: ${triageRecords.filter(r => r.resolutionCategory === "ACCEPTED_RISK").length} *(0 formally approved; rejected by governance ruling)*`,
  `- **NOT_APPLICABLE**: ${triageRecords.filter(r => r.resolutionCategory === "NOT_APPLICABLE").length}`,
  `- **UNRESOLVED**: ${triageRecords.filter(r => r.resolutionCategory === "UNRESOLVED").length}`,
  "",
  "## ⚠️ Active Delta Review Findings",
  "",
  "> [!IMPORTANT]",
  "> **P1-DV-01: Staged Review 未沿用已驗證的 Context (§3.3.4 Dual Visibility)**:",
  "> - **Severity**: `P1`",
  "> - **Status**: `REMEDIATED` (Tested & verified)",
  "> - **Locations**:",
  ">   - `scripts/dogfood-review.mjs:1059-1077`",
  ">   - `src/adapters/staged-review.mjs:516-572`",
  "> - **Issue**: Staged fallback (`executeStagedReview` / `executeChunk`) was rebuilding context independently rather than forwarding caller-provided exact-head `contextPackage` and `contextGaps`, breaking §3.3.4 Dual Visibility identical contextual enclosure invariant.",
  "> - **Remediation**: `executeStagedReview` and `executeChunk` now forward caller-provided `contextPackage` and `effectiveContextGaps` through to prompt assembly and chunk adapter calls, ensuring identical enclosures between primary sentries and Clean Challenge verifier. Fail-closed behavior enforced on context absence or inconsistency.",
  "> - **Verification Evidence**: `tests/remediation-007-clean-challenge.test.mjs` (`PR39-ROUND6-STAGED-DUAL-VISIBILITY-01`, `PR39-ROUND6-STAGED-DUAL-VISIBILITY-02-NEGATIVE`, `PR39-ROUND6-STAGED-DUAL-VISIBILITY-03-NEGATIVE`).",
  "",
  "> [!IMPORTANT]",
  "> **P1-DV-02: executeStagedReview 在 contextPackage 為 null/falsy 時繞過重新擷取 (§3.3.4 Dual Visibility)**:",
  "> - **Severity**: `P1`",
  "> - **Status**: `REMEDIATED` (Tested & verified)",
  "> - **Locations**:",
  ">   - `src/adapters/staged-review.mjs:380-480`",
  ">   - `src/adapters/staged-review.mjs:690-705`",
  "> - **Issue**: `staged-review.mjs` 以 `callerContextPackage !== undefined` 判斷是否沿用外部 Context，當明確傳入 null 且無 EXACT_HEAD_CONTEXT_FAILED 時略過 `buildContextPackage` 重新擷取，導致缺少必要 Context 與不確定性提示即進入 Chunk Review。",
  "> - **Remediation**: `executeStagedReview` 強化 `callerContextPackage` 驗證，僅在有效非空物件時直接沿用；若為 null/undefined 且無 extraction gap 則強制呼叫 `buildContextPackage` 重新擷取有效 exact-head contextPackage。若擷取失敗或 exact-head 不可用，則傳播 `EXACT_HEAD_CONTEXT_FAILED` 不確定性 gap 並阻止 Clean Approval。",
  "> - **Verification Evidence**: `tests/remediation-007-clean-challenge.test.mjs` (`PR39-ROUND7-STAGED-NULL-CONTEXT-REEXTRACTION-01`, `PR39-ROUND7-STAGED-NULL-CONTEXT-FAIL-CLOSED-02-NEGATIVE`, `PR39-ROUND7-STAGED-REPOSITORY-ROOT-FALLBACK-03`, `PR39-ROUND7-STAGED-CORRUPTED-CONTEXT-FAIL-CLOSED-04-NEGATIVE`, `PR39-ROUND7-STAGED-VACUOUS-OBJECT-REEXTRACTION-05`).",
  "",
  "> [!IMPORTANT]",
  "> **P2-TELEMETRY-01: 三方 Staged 遙測歸屬錯誤 (dogfood-review.mjs providerTelemetry)**:",
  "> - **Severity**: `P2`",
  "> - **Status**: `REMEDIATED` (Tested & verified)",
  "> - **Locations**:",
  ">   - `scripts/dogfood-review.mjs:1400-1402`",
  "> - **Issue**: `dogfood-review.mjs` 將全域 `stagedFallbackUsed` 寫給 agy，並將 claude、codex 固定為 false，導致單一 Provider (如 Claude 或 Codex) 觸發 Staged Fallback 時遙測歸屬錯誤。",
  "> - **Remediation**: 分別追蹤 `agyStagedFallbackUsed`, `claudeStagedFallbackUsed`, `codexStagedFallbackUsed`，並如實填入 `providerTelemetry[provider].stagedFallbackUsed`。",
  "> - **Verification Evidence**: `tests/remediation-007-clean-challenge.test.mjs` (`PR39-ROUND7-PROVIDER-TELEMETRY-ATTRIBUTION-01`).",
  "",
  "> [!IMPORTANT]",
  "> **P1-DV-03: executeStagedReview 在部分空白 Context ({ layers: {} } 或無 Head/Digest) 時繞過重新擷取**:",
  "> - **Severity**: `P1`",
  "> - **Status**: `REMEDIATED` (Tested & verified)",
  "> - **Locations**:",
  ">   - `src/adapters/staged-review.mjs:385-420`",
  "> - **Issue**: `staged-review.mjs` 原以 `!callerContextPackage.layers` 判斷 contextPackage 是否 vacuous，當傳入 `{ layers: {} }`、`[{}]` 空 manifest、缺少 Head SHA / Digest 或包含 throwing getters 時，繞過 `buildContextPackage` 重新擷取或造成未處理例外，造成無效 Context 進入 Chunk Review。",
  "> - **Remediation**: 強化 `isCallerContextVacuous` 與 Context 驗證，要求 contextPackage 必須具備非空層級 (substantive layers) 或具備具體檔案標識的非空 File Coverage Manifest，且必須包含有效 Head SHA 或 Content Digest；並加入安全屬性讀取防範 throwing getters 與代理攻擊；否則視為 vacuous 強制呼叫 `buildContextPackage` 重新擷取，若擷取失敗則 fail-closed 注入 `EXACT_HEAD_CONTEXT_FAILED`。",
  "> - **Verification Evidence**: `tests/remediation-007-clean-challenge.test.mjs` (`PR39-ROUND8-STAGED-VACUOUS-LAYERS-REEXTRACTION-06`, `PR39-ROUND8-STAGED-VACUOUS-LAYERS-FAIL-CLOSED-07-NEGATIVE`, `PR39-ROUND8-STAGED-VACUOUS-MANIFEST-EMPTY-OBJECT-09-NEGATIVE`, `PR39-ROUND8-STAGED-THROWING-GETTER-CONTEXT-10-NEGATIVE`).",
  "",
  "> [!IMPORTANT]",
  "> **P2-TELEMETRY-02: 多 Provider 同時觸發 Staged Fallback 時遙測彙總與 Chunk 統計覆蓋 (dogfood-review.mjs)**:",
  "> - **Severity**: `P2`",
  "> - **Status**: `REMEDIATED` (Tested & verified)",
  "> - **Locations**:",
  ">   - `scripts/dogfood-review.mjs:1040-1175`",
  ">   - `scripts/dogfood-review.mjs:1425-1490`",
  "> - **Issue**: `dogfood-review.mjs` 之 `stagedTelemetry` 與 `stagedChunkCount` 使用共用變數，多 Provider 同時觸發 Staged Fallback 時僅保留單一 Provider 遙測，造成其他 Provider 的 Chunk 數、Timeout 數與預算統計被覆蓋。",
  "> - **Remediation**: `dogfood-review.mjs` 獨立追蹤各 Provider 之 `stagedTelemetry`、`stagedChunkCount` 與 `stagedTimeoutCount`，於 `providerTelemetry` 中提供各 Provider 細部數據，並在全域 `telemetryMetrics` 與 `phaseMetrics.byProvider` 準確彙總，避免多 Provider 同時 Staged 時數據遺失。",
  "> - **Verification Evidence**: `tests/remediation-007-clean-challenge.test.mjs` (`PR39-ROUND8-STAGED-MULTI-PROVIDER-TELEMETRY-08`).",
  "",
  "> [!IMPORTANT]",
  "> **P1-CONTEXT-BINDING-01: 外部 Context 未完整綁定 ChangeSet (staged-review.mjs)**:",
  "> - **Severity**: `P1`",
  "> - **Status**: `REMEDIATED` (Tested & verified)",
  "> - **Locations**:",
  ">   - `src/adapters/staged-review.mjs:406-490`",
  "> - **Issue**: 在 `staged-review.mjs` 中，`hasHeadOrDigest` 只要求存在非空的 `headSha`、`contentDigest` 或 `digest` 其中之一，未比對 `contentDigest` 與實際 `changeSet.diffHunks`。一份具有非空 Layers、有效形式 Manifest、但只有過期 Digest 而沒有 Head SHA 的 Context 存在被當成有效輸入的路徑。",
  "> - **Remediation**: 重新計算 diff `contentDigest`，嚴格比對 caller `contextPackage` 之 `headSha`、`contentDigest`、`repositoryRoot` 及檔案涵蓋範圍。非空 Context 必須具備與目前 ChangeSet 一致的 Head SHA 或 Content Digest 綁定，驗證失敗即 Fail-Closed 注入 `EXACT_HEAD_CONTEXT_FAILED` 並阻斷 Clean Approval。",
  "> - **Verification Evidence**: `tests/remediation-007-clean-challenge.test.mjs` (`PR39-ROUND9-STAGED-UNBOUND-CONTEXT-FAIL-CLOSED-11-NEGATIVE`).",
  "",
  "> [!IMPORTANT]",
  "> **P1-CONTEXT-GAPS-01: 明確傳入空陣列可能遮蔽既有 Gap (staged-review.mjs options.contextGaps)**:",
  "> - **Severity**: `P1`",
  "> - **Status**: `REMEDIATED` (Tested & verified)",
  "> - **Locations**:",
  ">   - `src/adapters/staged-review.mjs:321-325`",
  "> - **Issue**: `staged-review.mjs` 原以 `options.contextGaps !== undefined` 優先選取 `callerContextGaps`，當呼叫端傳入空陣列 `options.contextGaps: []` 時，`changeSet.contextGaps` 中的既有 Gap (如 `EXACT_HEAD_CONTEXT_FAILED`) 會被捨棄，導致後續無法傳播不確定性。",
  "> - **Remediation**: 以 `mergeContextGaps(options.contextGaps, changeSet?.contextGaps)` 合併兩者，確保傳入空陣列無法清除既有 `contextGaps`。",
  "> - **Verification Evidence**: `tests/remediation-007-clean-challenge.test.mjs` (`PR39-ROUND9-STAGED-MERGE-CALLER-CONTEXT-GAPS-12-NEGATIVE`).",
  "",
  "> [!IMPORTANT]",
  "> **P1-CONTEXT-BINDING-02: 未驗證之宣告 Digest 與 Trimmed Diff 雜湊混入候選集合 (staged-review.mjs changeSetDigestCandidates)**:",
  "> - **Severity**: `P1`",
  "> - **Status**: `REMEDIATED` (Tested & verified)",
  "> - **Locations**:",
  ">   - `src/adapters/staged-review.mjs:410-440`",
  "> - **Issue**: 在 `staged-review.mjs` 中，`changeSetDigestCandidates` 盲目將未驗證之宣告 digest (`changeSet.contentDigest` 與 `changeSet.changeSetDigest`) 以及 `diffHunks.trim()` 加入候選集合。當呼叫端傳入之 `contextPackage.contentDigest` 與 `changeSet.contentDigest` 一致、但兩者皆與 physical `diffHunks` 雜湊衝突時，`hasMatchingDigest` 仍判定為 true，導致未受真實 diff 錨定之 contextPackage 被錯誤信任。",
  "> - **Remediation**: `changeSetDigestCandidates` 僅能由 physical `diffHunks` 之原始雜湊、正規化 LF 雜湊及獨立重算之 `digestChangeSet` 產生，移除 `diffHunks.trim()`。未驗證之 `changeSet.contentDigest` 與 `changeSet.changeSetDigest` 不得直接加入可信集合，且若其與重算之 diff digest 衝突時立即標記衝突並 Fail-Closed 阻斷 Clean Approval。",
  "> - **Verification Evidence**: `tests/remediation-007-clean-challenge.test.mjs` (`PR39-ROUND10-STAGED-UNVERIFIED-DECLARED-DIGEST-FAIL-CLOSED-14-NEGATIVE`).",
  "",
  "> [!IMPORTANT]",
  "> **P2-LEDGER-HEAD-01: 證據清冊之 CURRENT_HEAD_SHA 指向早於修補完成之 Commit (scripts/triage-pr39-threads.mjs)**:",
  "> - **Severity**: `P2`",
  "> - **Status**: `REMEDIATED` (Tested & verified)",
  "> - **Locations**:",
  ">   - `scripts/triage-pr39-threads.mjs:4-6`",
  "> - **Issue**: 先前清冊之 `currentHeadSha` 指向歷史 commit (`d621bd9`)，早於 `P2-TELEMETRY-02` 等修復提交，導致依該 SHA 無法重現所宣稱之 locator 與修復內容。",
  "> - **Remediation**: 將 `currentHeadSha` 更新至包含完整修復之 Commit SHA，確保所有修補聲明與證據引用皆可在記錄之 Exact Head 完整重現與檢驗。",
  "> - **Verification Evidence**: `scripts/triage-pr39-threads.mjs`, `evidence-runs/PR-39/review-threads-triage.json`, `docs/reports/pr-39-review-threads-triage.md` (`43_SYNCHRONIZED`).",
  "",
  "## ⚠️ Governance Status: FIX_REQUIRED_DUAL_VISIBILITY (Spec §3.3.4 Enforced)",
  "",
  "> [!IMPORTANT]",
  "> **ACCEPTED_RISK Rejected — Implementation Fix Required per REMEDIATION-007 §3.3.4**:",
  "> - **Thread ID**: `PRRT_kwDOUWarIc6ra7ki` (and Duplicate `PRRT_kwDOUWarIc6rsajd`)",
  "> - **Location**: `scripts/dogfood-review.mjs:972`",
  "> - **Issue**: Suggests extracting and passing exact-head callee context package to primary sentries (agy, claude, codex) before initial tri-party review.",
  "> - **Governance Ruling**: User has explicitly **rejected** `ACCEPTED_RISK` and approved **Option B** (fix implementation in `scripts/dogfood-review.mjs` to inject `contextPackage` into primary review prompts as well as Clean Challenge verifier).",
  "> - **Normative Spec Baseline**: `REMEDIATION-007 §3.3.4 Dual Visibility` (\"The generated contextPackage MUST be injected simultaneously into: 1. Sentry review prompts... 2. Clean Challenge verifier prompts...\").",
  "> - **Status**: Marked as `FIX_REQUIRED_DUAL_VISIBILITY`. GitHub thread remains **UNRESOLVED**.",
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
  `- **Current Verified Head**: \`${CURRENT_HEAD_SHA}\``,
  "- **Triage Status**: 140 review threads (43 outdated, 97 current) on PR #39.",
  "- **Post-Remediation Push Head**: Distinct commit generated on `origin/fix/remediation-007-clean-challenge` incorporating technical boundary remediations P1-DV-01, P1-DV-02, P1-DV-03, P2-TELEMETRY-01, P2-TELEMETRY-02, P1-CONTEXT-BINDING-01, P1-CONTEXT-GAPS-01, P1-CONTEXT-BINDING-02, P2-LEDGER-HEAD-01, and evidence ledger artifacts."
);

const mdDir = path.resolve("docs", "reports");
fs.mkdirSync(mdDir, { recursive: true });
const mdPath = path.join(mdDir, "pr-39-review-threads-triage.md");
fs.writeFileSync(mdPath, mdLines.join("\n") + "\n", "utf8");
console.log(`Wrote Markdown report: ${mdPath}`);
