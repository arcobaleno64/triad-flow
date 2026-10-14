# Triad-Flow PR #39 Outdated Review Threads Evidence Triage Ledger

> **Governance Notice & Execution Boundaries**
> - **Target PR**: [#39 (fix/remediation-007-clean-challenge)](https://github.com/arcobaleno64/triad-flow/pull/39)
> - **Extraction Timestamp**: `2026-10-14T11:41:22Z`
> - **Baseline Extraction Head SHA**: `bd9bc9001ee4cfee34671d6563d97deb793ff1ae`
> - **Mutation Policy**: Zero GitHub mutations performed. `THREAD_BATCH_RESOLUTION = NOT_AUTHORIZED`; `GITHUB_RULESET_BYPASS = NOT_AUTHORIZED`; `SQUASH_MERGE = NOT_AUTHORIZED`.
> - **Adjudication State**: All candidate records marked `PENDING_ADJUDICATION` under Default-Deny.

## Governance Invariants & Policy Holds

| Invariant | Setting | Authority / Status |
| :--- | :--- | :--- |
| `RUNTIME_AUTHORITY` | `NONE` | Strict Advisory Mode |
| `SHADOW_TO_ADVISORY` | `STRICT_HOLD` | Release Gate Locked |
| `CYCLE_0048` | `ON_HOLD_NOT_ASSIGNED` | Policy Hold |
| `ISSUE_37` | `OPEN` | Governance Tracking Open |
| `SQUASH_MERGE` | `NOT_AUTHORIZED` | Merge Invariant |
| `GITHUB_RULESET_BYPASS` | `NOT_AUTHORIZED` | Merge Invariant |
| `THREAD_BATCH_RESOLUTION` | `NOT_AUTHORIZED` | Dry-run Evidence Ledger Only |
| `THREAD_TRIAGE` | `AUTHORIZED_AS_POLICY` | Evidence Ledger Authorized |

## Summary of Candidate Classifications

- **Total Outdated Threads**: 38
- **FIXED**: 36
- **FIX_REQUIRED_DUAL_VISIBILITY**: 1 *(Thread 22 / `PRRT_kwDOUWarIc6ra7ki`: ACCEPTED_RISK rejected; spec baseline §3.3.4 Dual Visibility enforced)*
- **DUPLICATE**: 1 *(Thread 34 duplicate of Thread 22; disposition subordinate to Thread 22)*
- **ACCEPTED_RISK**: 0 *(0 formally approved; rejected by governance ruling)*
- **NOT_APPLICABLE**: 0
- **UNRESOLVED**: 0

## ⚠️ Active Delta Review Findings

> [!IMPORTANT]
> **P1-DV-01: Staged Review 未沿用已驗證的 Context (§3.3.4 Dual Visibility)**:
> - **Severity**: `P1`
> - **Status**: `REMEDIATED` (Tested & verified)
> - **Locations**:
>   - `scripts/dogfood-review.mjs:1059-1077`
>   - `src/adapters/staged-review.mjs:516-572`
> - **Issue**: Staged fallback (`executeStagedReview` / `executeChunk`) was rebuilding context independently rather than forwarding caller-provided exact-head `contextPackage` and `contextGaps`, breaking §3.3.4 Dual Visibility identical contextual enclosure invariant.
> - **Remediation**: `executeStagedReview` and `executeChunk` now forward caller-provided `contextPackage` and `effectiveContextGaps` through to prompt assembly and chunk adapter calls, ensuring identical enclosures between primary sentries and Clean Challenge verifier. Fail-closed behavior enforced on context absence or inconsistency.
> - **Verification Evidence**: `tests/remediation-007-clean-challenge.test.mjs` (`PR39-ROUND6-STAGED-DUAL-VISIBILITY-01`, `PR39-ROUND6-STAGED-DUAL-VISIBILITY-02-NEGATIVE`, `PR39-ROUND6-STAGED-DUAL-VISIBILITY-03-NEGATIVE`).

> [!IMPORTANT]
> **P1-DV-02: executeStagedReview 在 contextPackage 為 null/falsy 時繞過重新擷取 (§3.3.4 Dual Visibility)**:
> - **Severity**: `P1`
> - **Status**: `REMEDIATED` (Tested & verified)
> - **Locations**:
>   - `src/adapters/staged-review.mjs:592-645`
> - **Issue**: `staged-review.mjs` 以 `callerContextPackage !== undefined` 判斷是否沿用外部 Context，當明確傳入 null 且無 EXACT_HEAD_CONTEXT_FAILED 時略過 `buildContextPackage` 重新擷取，導致缺少必要 Context 與不確定性提示即進入 Chunk Review。
> - **Remediation**: `executeStagedReview` 強化 `callerContextPackage` 驗證，僅在有效非空物件時直接沿用；若為 null/undefined 且無 extraction gap 則強制呼叫 `buildContextPackage` 重新擷取有效 exact-head contextPackage。若擷取失敗或 exact-head 不可用，則傳播 `EXACT_HEAD_CONTEXT_FAILED` 不確定性 gap 並阻止 Clean Approval。
> - **Verification Evidence**: `tests/remediation-007-clean-challenge.test.mjs` (`PR39-ROUND7-STAGED-NULL-CONTEXT-REEXTRACTION-01`, `PR39-ROUND7-STAGED-NULL-CONTEXT-FAIL-CLOSED-02-NEGATIVE`).

> [!IMPORTANT]
> **P2-TELEMETRY-01: 三方 Staged 遙測歸屬錯誤 (dogfood-review.mjs providerTelemetry)**:
> - **Severity**: `P2`
> - **Status**: `REMEDIATED` (Tested & verified)
> - **Locations**:
>   - `scripts/dogfood-review.mjs:1400-1402`
> - **Issue**: `dogfood-review.mjs` 將全域 `stagedFallbackUsed` 寫給 agy，並將 claude、codex 固定為 false，導致單一 Provider (如 Claude 或 Codex) 觸發 Staged Fallback 時遙測歸屬錯誤。
> - **Remediation**: 分別追蹤 `agyStagedFallbackUsed`, `claudeStagedFallbackUsed`, `codexStagedFallbackUsed`，並如實填入 `providerTelemetry[provider].stagedFallbackUsed`。
> - **Verification Evidence**: `tests/remediation-007-clean-challenge.test.mjs` (`PR39-ROUND7-PROVIDER-TELEMETRY-ATTRIBUTION-01`).

## ⚠️ Governance Status: FIX_REQUIRED_DUAL_VISIBILITY (Spec §3.3.4 Enforced)

> [!IMPORTANT]
> **ACCEPTED_RISK Rejected — Implementation Fix Required per REMEDIATION-007 §3.3.4**:
> - **Thread ID**: `PRRT_kwDOUWarIc6ra7ki` (and Duplicate `PRRT_kwDOUWarIc6rsajd`)
> - **Location**: `scripts/dogfood-review.mjs:972`
> - **Issue**: Suggests extracting and passing exact-head callee context package to primary sentries (agy, claude, codex) before initial tri-party review.
> - **Governance Ruling**: User has explicitly **rejected** `ACCEPTED_RISK` and approved **Option B** (fix implementation in `scripts/dogfood-review.mjs` to inject `contextPackage` into primary review prompts as well as Clean Challenge verifier).
> - **Normative Spec Baseline**: `REMEDIATION-007 §3.3.4 Dual Visibility` ("The generated contextPackage MUST be injected simultaneously into: 1. Sentry review prompts... 2. Clean Challenge verifier prompts...").
> - **Status**: Marked as `FIX_REQUIRED_DUAL_VISIBILITY`. GitHub thread remains **UNRESOLVED**.

## Auditable 6-Field Evidence Triage Table

| # | Thread ID | 決議分類 | 修復或反證連結 | 裁決人 | 裁決日期 | Exact Head |
| :---: | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `PRRT_kwDOUWarIc6qo0uL` | **FIXED** | Commit 2709ea2; locator src/core/harness.mjs:458-477. Zero-finding gate requires authentic independent verification record and fails closed to 'block' unless explicitly called with options.preliminary = true. Tested in tests/remediation-007-clean-challenge.test.mjs ('007-DELTA-01'). | `PENDING_ADJUDICATION` | `PENDING_ADJUDICATION` | `bd9bc9001ee4...` |
| 2 | `PRRT_kwDOUWarIc6qo0uP` | **FIXED** | Commit 2580fd5; locator src/core/independent-verifier.mjs:252. trustedVerificationRegistry is an unexported module-private WeakSet; capability minting is strictly contained within conductIndependentVerification upon valid completion. Tested in capability security suite. | `PENDING_ADJUDICATION` | `PENDING_ADJUDICATION` | `bd9bc9001ee4...` |
| 3 | `PRRT_kwDOUWarIc6qo0uZ` | **FIXED** | Commits 0b90fcb, 6e2f120, e7f1527; locator src/core/independent-verifier.mjs:489-560, 1438-1460. hasConcreteCounterexample validates failure path syntax, reproduction mechanics, and non-vacuous reasoning before granting SUPPORTED status. Tested in tests/remediation-007-clean-challenge.test.mjs ('007-P1-04'). | `PENDING_ADJUDICATION` | `PENDING_ADJUDICATION` | `bd9bc9001ee4...` |
| 4 | `PRRT_kwDOUWarIc6qo0uk` | **FIXED** | Commits 3e95008, c418bb1; locator src/core/harness.mjs:403-429. _evaluateGateDecisionCore executes bidirectional comparison of normalized exclusions between RunContext and verificationRecord. Mismatches fail closed with FORGED_OR_STALE_RECORD ('block'). Tested in tests/remediation-007-clean-challenge.test.mjs ('007-AUDIT-THREAD-37-NEGATIVE'). | `PENDING_ADJUDICATION` | `PENDING_ADJUDICATION` | `bd9bc9001ee4...` |
| 5 | `PRRT_kwDOUWarIc6qo0un` | **FIXED** | Commits 23a82a2, 2580fd5; locator src/core/harness.mjs:433-440. Enforces that zero-finding consensus strictly requires verificationMode === 'clean_challenge'. Records produced with producer_verification fail closed to 'block'. Tested in tests/remediation-007-clean-challenge.test.mjs ('007-P1-03-DELTA'). | `PENDING_ADJUDICATION` | `PENDING_ADJUDICATION` | `bd9bc9001ee4...` |
| 6 | `PRRT_kwDOUWarIc6qo0uv` | **FIXED** | Commit 2580fd5; locator src/core/context-builder.mjs:461. classifySensitiveCategory normalizes camelCase transitions ([a-z0-9])([A-Z]) -> $1_$2 before regex evaluation, correctly classifying symbols like handleError, hasPermission, and getDefaultFallback. Tested in tests/remediation-007-clean-challenge.test.mjs ('007-AUDIT-THREAD-11'). | `PENDING_ADJUDICATION` | `PENDING_ADJUDICATION` | `bd9bc9001ee4...` |
| 7 | `PRRT_kwDOUWarIc6qwj_j` | **FIXED** | Commit 2580fd5; locator src/core/context-builder.mjs:969-982. When fileCalleesCount >= MAX_CALLEES_PER_FILE, extraction loop continues scanning remaining candidates and registers EXTRACTION_QUOTA_EXCEEDED context gaps for unextracted sensitive callees instead of breaking early. Tested in tests/remediation-007-clean-challenge.test.mjs ('007-P1-03'). | `PENDING_ADJUDICATION` | `PENDING_ADJUDICATION` | `bd9bc9001ee4...` |
| 8 | `PRRT_kwDOUWarIc6qwj_p` | **FIXED** | Commit c99050a; locator src/core/independent-verifier.mjs:1543-1577. In Clean Challenge mode, missing or invalid overallStatus fails closed with MALFORMED_OUTPUT error rather than normalizing to null. Tested in tests/remediation-007-clean-challenge.test.mjs ('007-P1-01'). | `PENDING_ADJUDICATION` | `PENDING_ADJUDICATION` | `bd9bc9001ee4...` |
| 9 | `PRRT_kwDOUWarIc6qwj_t` | **FIXED** | Commit c99050a; locator scripts/dogfood-review.mjs:796-809. Verifier adapter selection decouples from reviewer adapters; when isLive === true, live CliVerifierAdapter is instantiated by default regardless of injected reviewAdapters. Tested in benchmark CLI integration. | `PENDING_ADJUDICATION` | `PENDING_ADJUDICATION` | `bd9bc9001ee4...` |
| 10 | `PRRT_kwDOUWarIc6qwj_0` | **FIXED** | Commits 2580fd5, a771cd6; locator src/core/context-builder.mjs:495-560, 684. stripCommentsAndStrings strips block comments, line comments, string literals, and regex literals before extracting call symbols, preventing comment text from triggering spurious context gaps. Tested in regex hardening test suite. | `PENDING_ADJUDICATION` | `PENDING_ADJUDICATION` | `bd9bc9001ee4...` |
| 11 | `PRRT_kwDOUWarIc6rTXZd` | **FIXED** | Commit 2580fd5; locator src/core/context-builder.mjs:309-328. findFunctionDefinitions tracks parenthesis nesting depth (parenDepth) and begins searching for the function body opening brace '{' only after parameter list closing paren ')' (parenDepth <= 0). | `PENDING_ADJUDICATION` | `PENDING_ADJUDICATION` | `bd9bc9001ee4...` |
| 12 | `PRRT_kwDOUWarIc6rTXZh` | **FIXED** | Commit 2580fd5; locator src/core/context-builder.mjs:1486-1498, 1626-1638. When Layer 1 byte budgeting evicts sensitive definitions exceeding the 8 KB AST ceiling, GLOBAL_AST_CONTEXT_CEILING_EXCEEDED context gaps are recorded, propagating to verifier UNCERTAIN. Tested in tests/remediation-007-clean-challenge.test.mjs ('007-AUDIT-P1-01'). | `PENDING_ADJUDICATION` | `PENDING_ADJUDICATION` | `bd9bc9001ee4...` |
| 13 | `PRRT_kwDOUWarIc6rTXZn` | **FIXED** | Commit 05fb0fa; locator src/core/independent-verifier.mjs:1417-1420. Under Default-Deny, omissions missing both evidenceSupport and verdict default to INSUFFICIENT_EVIDENCE instead of SUPPORTED. Tested in tests/remediation-007-clean-challenge.test.mjs ('007-AUDIT-THREAD-23'). | `PENDING_ADJUDICATION` | `PENDING_ADJUDICATION` | `bd9bc9001ee4...` |
| 14 | `PRRT_kwDOUWarIc6rTowe` | **FIXED** | Commit 2580fd5; locator src/core/independent-verifier.mjs:440. issueVerificationRecordFromOutput registers minted records into segregatedSyntheticRegistry. evaluateGateDecision strictly rejects synthetic records in production gates (UNTRUSTED_VERIFICATION_RECORD). Tested in tests/remediation-007-clean-challenge.test.mjs ('007-P1-01-DELTA'). | `PENDING_ADJUDICATION` | `PENDING_ADJUDICATION` | `bd9bc9001ee4...` |
| 15 | `PRRT_kwDOUWarIc6rTowi` | **FIXED** | Commit 2580fd5; locator src/core/context-builder.mjs:1358-1365. Uses nullish check fileContent === null rather than falsiness check, allowing legitimately empty files '' at exact HEAD to be processed without triggering exactHeadUnavailable. | `PENDING_ADJUDICATION` | `PENDING_ADJUDICATION` | `bd9bc9001ee4...` |
| 16 | `PRRT_kwDOUWarIc6rTowl` | **FIXED** | Commit 2580fd5; locator src/core/independent-verifier.mjs:385-388, 2346-2349. Defensive check guarantees that options.overallStatus cannot downgrade validated UNCERTAIN or DEFECTS_FOUND to CLEAN. Tested in tests/remediation-007-clean-challenge.test.mjs ('007-AUDIT-P1-02'). | `PENDING_ADJUDICATION` | `PENDING_ADJUDICATION` | `bd9bc9001ee4...` |
| 17 | `PRRT_kwDOUWarIc6rTowq` | **FIXED** | Commit 2580fd5; locator src/core/context-builder.mjs:274-292. findFunctionDefinitions rejects call expressions, statement keywords (if, while, return), and property declarations, ensuring semicolon-free call expressions are not mistaken for function definitions. Tested in tests/remediation-007-clean-challenge.test.mjs ('007-AUDIT-THREAD-28'). | `PENDING_ADJUDICATION` | `PENDING_ADJUDICATION` | `bd9bc9001ee4...` |
| 18 | `PRRT_kwDOUWarIc6rVNc1` | **FIXED** | Commit 2580fd5; locator src/core/independent-verifier.mjs:1594-1602. All unresolved sensitive contextGaps (including UNRESOLVED_SYMBOL, EXTRACTION_QUOTA_EXCEEDED, GLOBAL_AST_CONTEXT_CEILING_EXCEEDED) force overallStatus = 'UNCERTAIN'. Tested in tests/remediation-007-clean-challenge.test.mjs ('007-AUDIT-P1-01'). | `PENDING_ADJUDICATION` | `PENDING_ADJUDICATION` | `bd9bc9001ee4...` |
| 19 | `PRRT_kwDOUWarIc6rY13u` | **FIXED** | Commit 3e95008; locator src/core/independent-verifier.mjs:2143-2155, 2361. Canonical normContract.exclusions derives both prompt text and verification record exclusions, preventing discrepancies between verifier scope and gate binding. | `PENDING_ADJUDICATION` | `PENDING_ADJUDICATION` | `bd9bc9001ee4...` |
| 20 | `PRRT_kwDOUWarIc6rY139` | **FIXED** | Commit 23a82a2; locator src/core/independent-verifier.mjs:1531-1541. In clean_challenge mode (reviewing 0 producer findings), returning a non-empty evaluations array fails closed with MALFORMED_OUTPUT. Tested in tests/remediation-007-clean-challenge.test.mjs ('007-AUDIT-THREAD-35'). | `PENDING_ADJUDICATION` | `PENDING_ADJUDICATION` | `bd9bc9001ee4...` |
| 21 | `PRRT_kwDOUWarIc6ra7kH` | **FIXED** | Commits c418bb1, 0ac63a1; locator src/adapters/review-orchestrator.mjs:51-95, 345-360. buildCanonicalRunContext derives and binds authoritative RunContext from current changeSet content digests before gate evaluation. Tested in tests/remediation-007-clean-challenge.test.mjs ('007-AUDIT-THREAD-37'). | `PENDING_ADJUDICATION` | `PENDING_ADJUDICATION` | `bd9bc9001ee4...` |
| 22 | `PRRT_kwDOUWarIc6ra7ki` | **FIX_REQUIRED_DUAL_VISIBILITY** | Per governance ruling, ACCEPTED_RISK is NOT approved. Spec baseline: REMEDIATION-007 §3.3.4 (Dual Visibility requires contextPackage injected simultaneously into both Sentry primary review and Clean Challenge verifier). Implementation fix in scripts/dogfood-review.mjs approved under Option B; GitHub thread remains UNRESOLVED until verified. | `PENDING_ADJUDICATION` | `PENDING_ADJUDICATION` | `bd9bc9001ee4...` |
| 23 | `PRRT_kwDOUWarIc6ra7kt` | **FIXED** | Commit 3e95008; locator src/adapters/review-prompts.mjs:163-260. Callee definitions and XML attributes are escaped via escapeXmlText and escapeXmlAttribute before XML prompt assembly. Tested in tests/remediation-007-clean-challenge.test.mjs ('007-AUDIT-THREAD-42'). | `PENDING_ADJUDICATION` | `PENDING_ADJUDICATION` | `bd9bc9001ee4...` |
| 24 | `PRRT_kwDOUWarIc6re305` | **FIXED** | Commit 0ac63a1; locator src/adapters/review-orchestrator.mjs:51-95. buildCanonicalRunContext strictly recomputes digest from diffHunks and verifies declared digests against recomputed values. Tested in tests/remediation-007-clean-challenge.test.mjs ('007-DELTA-P1-01-NEGATIVE'). | `PENDING_ADJUDICATION` | `PENDING_ADJUDICATION` | `bd9bc9001ee4...` |
| 25 | `PRRT_kwDOUWarIc6re31A` | **FIXED** | Commits 2580fd5, 76e8652; locator src/core/context-builder.mjs:700-740. Qualified calls (auth.validateAccess, this.verifyToken) are extracted with qualifiers and classified for sensitivity. Tested in tests/remediation-007-clean-challenge.test.mjs ('007-DELTA-P1-03'). | `PENDING_ADJUDICATION` | `PENDING_ADJUDICATION` | `bd9bc9001ee4...` |
| 26 | `PRRT_kwDOUWarIc6re31K` | **FIXED** | Commit 8375c65 / 02be43c; locator scripts/dogfood-review.mjs:1013-1028. Extraction failures register EXACT_HEAD_CONTEXT_FAILED in effectiveContextGaps, causing downstream gate evaluation to fail closed to human_review_required. Tested in tests/remediation-007-clean-challenge.test.mjs ('PR39-ROUND5-DUAL-VISIBILITY-02-NEGATIVE'). | `PENDING_ADJUDICATION` | `PENDING_ADJUDICATION` | `bd9bc9001ee4...` |
| 27 | `PRRT_kwDOUWarIc6re31P` | **FIXED** | Commit c99050a; locator src/core/harness.mjs:843-863. Verifier DEFECTS_FOUND without SUPPORTED omission flags 'Verifier Status Inconsistent' and sets hasHumanReview = true (human_review_required). Tested in tests/remediation-007-clean-challenge.test.mjs ('007-DELTA-P1-04'). | `PENDING_ADJUDICATION` | `PENDING_ADJUDICATION` | `bd9bc9001ee4...` |
| 28 | `PRRT_kwDOUWarIc6rfkYK` | **FIXED** | Commits cc1de22, bd9bc90; locator scripts/dogfood-review.mjs:976-989. Absence of trusted repository root sets contextExtractionFailed = true and records EXACT_HEAD_CONTEXT_FAILED, failing closed to UNCERTAIN / human_review_required. Negative test: tests/remediation-007-clean-challenge.test.mjs ('PR39-ROUND3-ITEM2-NEGATIVE'). | `PENDING_ADJUDICATION` | `PENDING_ADJUDICATION` | `bd9bc9001ee4...` |
| 29 | `PRRT_kwDOUWarIc6rhwEx` | **FIXED** | Commit 2580fd5; locator src/core/context-builder.mjs:1358-1365, src/core/git-collector.mjs:44-67. Exact-head retrieval via getExactHeadFileContent(repoRoot, headSha, path) inspects the exact commit tree containing the applied patch. | `PENDING_ADJUDICATION` | `PENDING_ADJUDICATION` | `bd9bc9001ee4...` |
| 30 | `PRRT_kwDOUWarIc6riPTp` | **FIXED** | Commit 76e8652; locator src/core/context-builder.mjs:735-755. Callee candidate deduplication key includes qualifier (${qualifier ? `${qualifier}.` : ''}${sym}), preserving distinct receiver identities. Tested in tests/remediation-007-clean-challenge.test.mjs ('PR39-GATE-OUT-02-NEGATIVE'). | `PENDING_ADJUDICATION` | `PENDING_ADJUDICATION` | `bd9bc9001ee4...` |
| 31 | `PRRT_kwDOUWarIc6riPT0` | **FIXED** | Commit 1c33d99; locator scripts/dogfood-review.mjs:991-1120. Validates headSha, repositoryRoot, contentDigest, and fileCoverageManifest against current ChangeSet before accepting external context package. Tested in tests/remediation-007-clean-challenge.test.mjs ('PR39-GATE-OUT-01-NEGATIVE'). | `PENDING_ADJUDICATION` | `PENDING_ADJUDICATION` | `bd9bc9001ee4...` |
| 32 | `PRRT_kwDOUWarIc6rrHOT` | **FIXED** | Commits 0b90fcb, 6e2f120; locator src/core/harness.mjs:260-280. getFindingSignature incorporates title, file, line, line_end, type, cwe, severity, and recommendation for comprehensive tampering protection. Tested in tests/remediation-007-clean-challenge.test.mjs ('PR39-DELTA-P1-04-NEGATIVE'). | `PENDING_ADJUDICATION` | `PENDING_ADJUDICATION` | `bd9bc9001ee4...` |
| 33 | `PRRT_kwDOUWarIc6rr-JA` | **FIXED** | Commit 0b90fcb; locator src/core/independent-verifier.mjs:687-730. mergeContextGaps unions caller gaps and package gaps, ensuring empty caller arrays cannot wipe out package gaps. Tested in tests/remediation-007-clean-challenge.test.mjs ('PR39-DELTA-P1-03-NEGATIVE'). | `PENDING_ADJUDICATION` | `PENDING_ADJUDICATION` | `bd9bc9001ee4...` |
| 34 | `PRRT_kwDOUWarIc6rsKB6` | **FIXED** | Commit 0b90fcb; locator scripts/dogfood-review.mjs:1033-1078. Declared digests validated against recomputed diff hashes before validating package digest. Tested in tests/remediation-007-clean-challenge.test.mjs ('PR39-DELTA-P1-01-NEGATIVE'). | `PENDING_ADJUDICATION` | `PENDING_ADJUDICATION` | `bd9bc9001ee4...` |
| 35 | `PRRT_kwDOUWarIc6rsajd` | **DUPLICATE** | Duplicate of Thread 22 (PRRT_kwDOUWarIc6ra7ki). Disposition subordinate to Thread 22 (FIX_REQUIRED_DUAL_VISIBILITY under REMEDIATION-007 §3.3.4). GitHub thread remains UNRESOLVED. | `PENDING_ADJUDICATION` | `PENDING_ADJUDICATION` | `bd9bc9001ee4...` |
| 36 | `PRRT_kwDOUWarIc6rtv6E` | **FIXED** | Commits cc1de22, bd9bc90; locator scripts/dogfood-review.mjs:976-989. Omitted repository or object missing root fails closed to contextExtractionFailed = true with EXACT_HEAD_CONTEXT_FAILED. Negative test: tests/remediation-007-clean-challenge.test.mjs ('PR39-ROUND3-ITEM2-NEGATIVE'). | `PENDING_ADJUDICATION` | `PENDING_ADJUDICATION` | `bd9bc9001ee4...` |
| 37 | `PRRT_kwDOUWarIc6rtv6M` | **FIXED** | Commits cf6be07, eda22b9, e7f1527; locator scripts/dogfood-review.mjs:1091-1100. Reject manifests where exactHeadAvailable === false or exactHeadUnavailable === true, setting pkgInvalid = true and failing closed. Tested in tests/remediation-007-clean-challenge.test.mjs ('PR39-ROUND2-ITEM2-NEGATIVE'). | `PENDING_ADJUDICATION` | `PENDING_ADJUDICATION` | `bd9bc9001ee4...` |
| 38 | `PRRT_kwDOUWarIc6sMI7c` | **FIXED** | Commits a71082c, HEAD; locator src/adapters/staged-review.mjs:610-630. Preserves and merges caller-provided contextGaps with chunk-level contextPkg gaps, injecting effectiveChunkContextGaps into buildEvidenceReviewPrompt and adapter.executeReview. Tested in tests/remediation-007-clean-challenge.test.mjs ('PR39-ROUND6-STAGED-DUAL-VISIBILITY-01', 'PR39-ROUND6-STAGED-DUAL-VISIBILITY-02-NEGATIVE'). | `PENDING_ADJUDICATION` | `PENDING_ADJUDICATION` | `a71082c7b2bc...` |

## Head SHA Provenance Distinction

- **Triage Baseline Extraction Head**: `bd9bc9001ee4cfee34671d6563d97deb793ff1ae`
- **Current Verified Head**: `a71082c7b2bc4d29f17cee60c5c0f7abe7fe45d0`
- **Triage Status**: 125 review threads (38 outdated, 87 current) on PR #39.
- **Post-Remediation Push Head**: Distinct commit generated on `origin/fix/remediation-007-clean-challenge` incorporating technical boundary remediations P1-DV-01, P1-DV-02, P2-TELEMETRY-01, and evidence ledger artifacts.
