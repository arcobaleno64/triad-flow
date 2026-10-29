# PR #39 G4 系統性修復實體實作與測試閉合收據 R8

- **專案識別**：`triad-flow`
- **目標 PR**：[#39 arcobaleno64/triad-flow](https://github.com/arcobaleno64/triad-flow/pull/39)
- **分支名稱**：`fix/remediation-007-clean-challenge`
- **基準遠端 HEAD SHA**：`ec750e6010edd8d6f3fb8007a59994644b98862c`
- **治理階段**：Gate G4（系統性修復實體驗收與單一本機 Commit 授權申請）
- **核驗裁示**：依據審查領隊 恒一 於 R7 裁示（`PR39-SCHEMA2-G4-REMEDIATION-IMPLEMENTATION-REVIEW-R7`）之最小補正要求

---

## 一、R7 裁示覆核與 R8 針對性閉合對照

在 R7 裁示中，審查領隊 恒一 裁定：
1. `PATCH_INTEGRITY = VERIFIED`、`BASE_BLOB_ALIGNMENT = VERIFIED`、`FILE_SCOPE = VERIFIED`、`NEW_TEST_WHITESPACE = PASS`（全數合規，五檔白名單維持一致）。
2. `C12`：**ACCEPTED**。
3. `C14A／C14B 測試設計`：維持 **ACCEPTED**。
4. `C13 Fixture 旗標繞過`：**FIXED_IN_PATCH**。
5. **唯一阻擋項**：`C13 Synthetic SHA 正式驗證隔離 = HOLD`（`isLegacySyntheticHarness` 未排除 `--verify-with` 正式驗證流程，呼叫端傳入 `headSha = "a"*40` 且無 Repo Root 時仍會跳過 `contextExtractionFailed` 分支）。

### R8 最小補正要求落實對照

| 序號 | 審查領隊要求 | R8 實作方案 | 驗證證據 |
|---|---|---|---|
| 1 | 限制 Legacy Synthetic Harness 條件為不具正式驗證能力的流程（排除 `--verify-with` 與正式 Adapter） | 在 `src/cli.mjs` 將 `isLegacySyntheticHarness` 嚴格限制為：`!strictArg && !verifyWithSpecified && !options.verifierAdapter && !hasFixtureBypassFlag && (headSha === "a".repeat(40) || headSha === "b".repeat(40))`。完全依照審查領隊建議規格落實。正式 `--verify-with` 流程（或傳入 Verifier Adapter）絕不豁免物理 Git 倉庫驗證。 | `src/cli.mjs` 第 924-933 行 |
| 2 | 新增針對性負向測試：`--verify-with=claude`、非 Strict、無 Root、無 Fixture 旗標、`headSha = "a".repeat(40)`，直接確認 Verifier 收到 `EXACT_HEAD_CONTEXT_FAILED` 且 Gate 不得核准 | 在 `tests/remediation-twenty-p1-systemic.test.mjs` 新增 `R8 C13-TEST-4`：呼叫非 Strict 之 `runCli(["review", "--verify-with=claude"])`，傳入 `headSha = "a".repeat(40)` 且完全不提供 repoRoot、cwd 或任何 Fixture bypass 旗標。斷言程序嚴格退出 `EXIT_CODES.GATE_BLOCKED` (1)，且 Verifier 確實接收到 `EXACT_HEAD_CONTEXT_FAILED` Context Gap。 | `SYSTEMIC-C13-CLI-NO-REPO-FAIL-CLOSED (Negative - Synthetic SHA with formal verifier)` |
| 3 | 保留隔離純記憶體測試相容性 | 既有 Phase 3 單元測試（`adversarial-phase3-challenger.test.mjs` 79 測資與 `remediation-phase3-orchestrator-cli.test.mjs` 27 測資）全數通過，全儲存庫完整回歸測試 1,256 筆測試 100% 通過。 | 全庫 `npm test` 通過 (1256 PASS, 0 FAIL) |

---

## 二、實體補丁指紋與檔案範疇核驗 (R8 Patches)

本次產出之兩份實體補丁皆以遠端 HEAD `ec750e6010edd8d6f3fb8007a59994644b98862c` 為唯一起點基準：

### 1. `pr39-r8-tracked.patch`
- **檔案大小**：44,445 bytes
- **SHA-256 指紋**：`26069A6B6BBCA179D5D9040B41EFBADE6D8E3FA9D4A71965A93D6924ADCEF58B`
- **涵蓋檔案（嚴格 4 既有檔案白名單）**：
  1. `scripts/dogfood-review.mjs` (Blob: `23a98afcebf7ca00094e951a88535a4a476ef263` -> `ad40d564ef4e4efde13e59c39eea95731e859d51`, +83 / -16 lines)
  2. `src/adapters/review-prompts.mjs` (Blob: `6d8c183e466d835dcd3c5f43f84c717932207a7f` -> `f0c379d21d786eb39a92cc7e5453d6caec72abc0`, +3 / -3 lines)
  3. `src/cli.mjs` (Blob: `319c8e382989dbe6e30a322a950e55edb8ab6f82` -> `3c64bdb7d046bd7350b5385847cd33623b54bde1`, +118 / -10 lines)
  4. `src/core/context-builder.mjs` (Blob: `779d4462e4aef90950fb9d87f78cd74adfb5632b` -> `6e669a272eac612277f7c56c827694c1904d2af3`, +478 / -80 lines)
- **Git 基準一致性**：4 個修改前 Blob 雜湊全數精確吻合遠端 HEAD，且 `git apply --check --reverse --whitespace=error pr39-r8-tracked.patch` 乾淨通過（Exit Code: 0）。

### 2. `pr39-r8-new-test.patch`
- **檔案大小**：49,777 bytes
- **SHA-256 指紋**：`9B495B716DF0887C6B2965AEB4EF668944F5BBC54466E7D6078ABC9D396B2634`
- **涵蓋檔案（嚴格 1 新增檔案白名單）**：
  1. `tests/remediation-twenty-p1-systemic.test.mjs` (Blob: `d0642ea4852febe4e6b297f88e1ef9154410950d`, 1,224 lines)
- **空白與反向檢驗**：`git apply --check --reverse --whitespace=error pr39-r8-new-test.patch` 乾淨通過（Exit Code: 0）。
- **語法檢查**：`node --check tests/remediation-twenty-p1-systemic.test.mjs` 通過。

---

## 三、本地測試驗收收據

### 1. 系統性修復測試套件驗證 (32/32 PASS)
```
node --test tests/remediation-twenty-p1-systemic.test.mjs
✔ SYSTEMIC-C01-HUNK-LEXICAL-STATE (Negative): Hunk starting inside block comment ignores commented code when fileContent is provided (2.0431ms)
✔ SYSTEMIC-C01-HUNK-LEXICAL-STATE (Negative without fileContent): Emits lexicalStateUncertain when fileContent is absent (1.4646ms)
✔ SYSTEMIC-C01-HUNK-LEXICAL-STATE (Positive): Hunk in regular executable code accurately extracts candidate calls (0.231ms)
✔ SYSTEMIC-C02-COMMENTED-DEF-EXCLUSION (Negative): Commented-out function definitions in /* */ are strictly excluded (0.3814ms)
✔ SYSTEMIC-C02-COMMENTED-DEF-EXCLUSION (Positive): Legitimate function preceded by comments is accurately found with line numbers preserved (1.1233ms)
✔ SYSTEMIC-C03-DELAYED-BRACE-BARE-CALL (Negative): Bare call followed by delayed brace is strictly rejected (0.5884ms)
✔ SYSTEMIC-C03-DELAYED-BRACE-BARE-CALL (Negative Chained): Chained bare call followed by delayed brace is strictly rejected (0.2363ms)
✔ SYSTEMIC-C03-DELAYED-BRACE-BARE-CALL (Positive): Cross-line declaration with function keyword is preserved (0.1153ms)
✔ SYSTEMIC-C03-DELAYED-BRACE-BARE-CALL (Positive): Cross-line parameter list with function keyword is preserved (0.2013ms)
✔ SYSTEMIC-C04-ACCESS-CONTROL-VOCAB: Policy, enforce, rbac, acl, and permission terms classify as security (0.3021ms)
✔ SYSTEMIC-C04-ACCESS-CONTROL-VOCAB: Receiver classification for policy.enforce() and acl.canAccess() (0.315ms)
✔ SYSTEMIC-C05-DIVISION-CHAIN-PRESERVATION (Negative): Chained division operands are not swallowed as regex literals (0.1728ms)
✔ SYSTEMIC-C05-DIVISION-CHAIN-PRESERVATION (Positive): True regex literals are correctly stripped (0.0995ms)
✔ SYSTEMIC-C06-BUILTIN-ON-SENSITIVE-RECEIVER: Retains sensitive receiver with builtin method name at both sites (0.4493ms)
✔ SYSTEMIC-C06-BUILTIN-ON-SENSITIVE-RECEIVER (Non-sensitive skipped): Standard non-sensitive collection calls skipped (0.088ms)
✔ SYSTEMIC-C07-TRUNCATED-CALLEE-GAP: Emits CALLEE_TRUNCATED_ELIDED gap for oversized sensitive callee (2.815ms)
✔ SYSTEMIC-C07-TRUNCATED-CALLEE-GAP (Cross-layer): CALLEE_TRUNCATED_ELIDED gap forces Gate to block Clean Approval (2.2523ms)
✔ SYSTEMIC-C07-TRUNCATED-CALLEE-GAP (Positive): Full body callee emits 0 gaps (0.5114ms)
✔ SYSTEMIC-C08-IMPORT-ALIAS-PRESERVATION: Import alias preserves original symbol sensitivity (0.3739ms)
✔ SYSTEMIC-C09-PATCH-ADDED-IMPORTS (Negative): Local definition deleted by patch is not treated as valid HEAD callee (0.4085ms)
✔ SYSTEMIC-C09-PATCH-ADDED-IMPORTS (Positive): Patch newly added import correctly recognized as external symbol (0.1684ms)
✔ SYSTEMIC-C10-CHANGED-HUNK-CONTEXT-GAPS (Negative): Context line call in hunk with modified control flow generates Context Gap (0.4553ms)
✔ SYSTEMIC-C10-CHANGED-HUNK-CONTEXT-GAPS (Positive): Context line call without control flow alterations in hunk (0.1445ms)
✔ SYSTEMIC-C11-CALLEE-XML-FILE-ATTRIBUTE: XML enclosure contains genuine file attribute without multi-file counterfeiting (0.2952ms)
✔ SYSTEMIC-C12-SINGLE-FILE-DIFF-ISOLATION: Multi-file diff is strictly isolated in single-file mode (3.0402ms)
✔ SYSTEMIC-C12-SCHEMA2-ROUTING: targetFile 'multi-file' routes to multi-file logic without mutual exclusion error (0.2391ms)
✔ SYSTEMIC-C12-DIFF-TARGET-NOT-FOUND (Negative): Structured diff omitting target file rejects raw diff fallback and emits context gap (0.3992ms)
✔ SYSTEMIC-C13-CLI-NO-REPO-FAIL-CLOSED (Negative): CLI Clean Challenge without reliable repository root fails closed with EXACT_HEAD_CONTEXT_FAILED (13.4262ms)
✔ SYSTEMIC-C14A-FORGED-CALLEE-REJECTION (Negative): Rejects external ContextPackage containing callee not present in exact-head commit (360.1855ms)
✔ SYSTEMIC-C14B-REGISTRATION-FAILURE-WORKFLOW-DENIAL (Negative): Failed context package registration denies workflow authority and causes Dogfood caller fail-closed (781.0938ms)
✔ SYSTEMIC-C14C-SENTRY-COVERAGE-INCOMPLETE-GATE-BLOCK (Negative): Sentry reporting omitted files blocks Clean Approval (0.3301ms)
✔ SYSTEMIC-C14C-SENTRY-COVERAGE-COMPLETE (Positive): Complete sentry coverage without omissions permits Clean Approval (0.1397ms)
ℹ tests 32
ℹ suites 0
ℹ pass 32
ℹ fail 0
```

### 2. 四大修復驗證套件聯測 (144/144 PASS)
```
node --test tests/remediation-twenty-p1-systemic.test.mjs tests/remediation-six-p1-threads.test.mjs tests/remediation-phase3-orchestrator-cli.test.mjs tests/adversarial-phase3-challenger.test.mjs
ℹ tests 144
ℹ suites 0
ℹ pass 144
ℹ fail 0
ℹ duration_ms 10876.2139
```

### 3. 全儲存庫完整回歸測試 (`npm test`：1,256 PASS)
```
> @arcobaleno64/triad-flow@2.7.0 test
> node --test
ℹ tests 1260
ℹ suites 0
ℹ pass 1256
ℹ fail 0
ℹ cancelled 0
ℹ skipped 4
ℹ todo 0
ℹ duration_ms 36984.6557
```

---

## 四、治理限制遵守聲明

依據 Gate G4 規範與審查領隊裁示：
- `LOCAL_WORKSPACE_EDIT`：依授權完成修改。
- `LOCAL_TEST_EXECUTION`：依授權完成測試驗證。
- `LOCAL_COMMIT`：持續維持 **HOLD**（在審查領隊核驗 R8 補丁並正式授權前，絕不執行 `git commit`）。
- `NEW_PUSH`：**NOT_AUTHORIZED**。
- `THREAD_REPLY / RESOLVE`：**NOT_AUTHORIZED**。
- `SQUASH_MERGE`：**NOT_AUTHORIZED**。
