# PR #39 G4 系統性修復實體實作與測試閉合收據 R7

- **專案識別**：`triad-flow`
- **目標 PR**：[#39 arcobaleno64/triad-flow](https://github.com/arcobaleno64/triad-flow/pull/39)
- **分支名稱**：`fix/remediation-007-clean-challenge`
- **基準遠端 HEAD SHA**：`ec750e6010edd8d6f3fb8007a59994644b98862c`
- **治理階段**：Gate G4（系統性修復實體驗收與單一本機 Commit 授權申請）
- **核驗裁示**：依據審查領隊 恒一 於 R6 裁示（`PR39-SCHEMA2-G4-REMEDIATION-IMPLEMENTATION-REVIEW-R6`）之最小補正要求

---

## 一、R6 裁示覆核與 R7 針對性閉合對照

在 R6 裁示中，審查領隊 恒一 裁定：
1. `PATCH_INTEGRITY = VERIFIED`、`五檔白名單 = VERIFIED`、`父節點 Blob 一致性 = VERIFIED`、`C12 = ACCEPTED`、`C14A/C14B = MAINTAINED_ACCEPTED`。
2. **阻擋項 1（C13 Fixture 隔離）**：正式 `--verify-with` Clean Challenge 不得以 `allowMissingRepo`、`testFixture`、`isMock` 或 Adapter 名稱豁免可信 Repository Root 驗證。須補上正式驗證與上述 Fixture 旗標同時存在時的負向測試，直接檢查 Context Gap 與最終 Gate。
3. **阻擋項 2（新測試 Patch 末尾空白行）**：修正新測試 Patch 末尾多餘空白行（`new blank line at EOF`），確保 `git apply --check --whitespace=error` 嚴格通過。

### R7 最小補正要求落實對照

| 序號 | 審查領隊要求 | R7 實作方案 | 驗證證據 |
|---|---|---|---|
| 1 | 封閉 C13 正式驗證與 Fixture 的混用路徑；不得以 `allowMissingRepo`、`testFixture`、`isMock` 等豁免可信 Repo Root | 在 `src/cli.mjs` 定義 `hasFixtureBypassFlag`（涵蓋 `options.allowMissingRepo`、`options.testFixture`、`options.inMemoryFixture`、`options.mockFixture`、`options.isMock`、`options.verifierAdapter?.isMock`）。將非 Strict 虛擬 Harness 嚴格邊界收斂至無任何 Fixture 旁路旗標且明確匹配合成 dummy SHA（`'a'*40` 或 `'b'*40`）。正式 `--verify-with` 流程在缺少合法 Repo Root 時，即使呼叫端提供各類 bypass 旗標，一律 Fail-Closed 發射 `EXACT_HEAD_CONTEXT_FAILED`。 | `src/cli.mjs` 第 912-925 行 |
| 2 | 補上正式驗證與 Fixture 旗標同時存在的負向測試 | 在 `tests/remediation-twenty-p1-systemic.test.mjs` 新增針對性負向測試：呼叫非 Strict 之 `runCli(["review", "--verify-with=claude"])`，同時注入 `allowMissingRepo: true`、`testFixture: true`、`inMemoryFixture: true`、`isMock: true` 且不提供 repoRoot。斷言程序嚴格退出 `EXIT_CODES.GATE_BLOCKED` (1)，並發射 `EXACT_HEAD_CONTEXT_FAILED` Context Gap。 | `SYSTEMIC-C13-CLI-NO-REPO-FAIL-CLOSED (Negative - Fixture bypass flags with formal verifier)` |
| 3 | 修正新測試 Patch 末尾空白行，通過嚴格空白檢查 | 廢除手工字串拼接 Patch 流程，改採 Git 原生意圖追蹤（`git add -N`）與原生二進位 Diff（`git diff --binary --output=...`）產出 Patch。已執行 `git apply --check --reverse --whitespace=error pr39-r7-new-test.patch` 驗證完全零錯誤、零警告通過。 | `git apply --check --reverse --whitespace=error` Exit Code: 0 |
| 4 | 純記憶體測試與既有測試套件相容性 | 既有 Phase 3 Challenger 測試維持綠燈，全儲存庫完整回歸測試 1,256 筆測試 100% 通過。 | 全庫 `npm test` 通過 (1256 PASS, 0 FAIL) |

---

## 二、實體補丁指紋與檔案範疇核驗 (R7 Patches)

本次產出之兩份實體補丁皆以遠端 HEAD `ec750e6010edd8d6f3fb8007a59994644b98862c` 為唯一起點基準：

### 1. `pr39-r7-tracked.patch`
- **檔案大小**：44,004 bytes
- **SHA-256 指紋**：`5A43B55D9BDB3E9757A80638AD84B574204B49B18300678B99F4E2007CB8BFA3`
- **涵蓋檔案（嚴格 4 既有檔案白名單）**：
  1. `scripts/dogfood-review.mjs` (Blob: `23a98afcebf7ca00094e951a88535a4a476ef263` -> `ad40d564ef4e4efde13e59c39eea95731e859d51`, +83 / -16 lines)
  2. `src/adapters/review-prompts.mjs` (Blob: `6d8c183e466d835dcd3c5f43f84c717932207a7f` -> `f0c379d21d786eb39a92cc7e5453d6caec72abc0`, +3 / -3 lines)
  3. `src/cli.mjs` (Blob: `319c8e382989dbe6e30a322a950e55edb8ab6f82` -> `adff2c65a2b84d0768aa2880f6641fd4cc8272c4`, +110 / -10 lines)
  4. `src/core/context-builder.mjs` (Blob: `779d4462e4aef90950fb9d87f78cd74adfb5632b` -> `6e669a272eac612277f7c56c827694c1904d2af3`, +478 / -80 lines)
- **Git 基準一致性**：4 個修改前 Blob 雜湊全數精確吻合遠端 HEAD，且 `git apply --check --reverse --whitespace=error pr39-r7-tracked.patch` 乾淨通過（Exit Code: 0）。

### 2. `pr39-r7-new-test.patch`
- **檔案大小**：47,759 bytes
- **SHA-256 指紋**：`07BE4FF98347BEE3418D3DFE5F0DAACAE3C62CD75800B6B828920E5F13430191`
- **涵蓋檔案（嚴格 1 新增檔案白名單）**：
  1. `tests/remediation-twenty-p1-systemic.test.mjs` (Blob: `779998f9530765d726909c41eced97fb9737375f`, 1,177 lines)
- **空白與反向檢驗**：`git apply --check --reverse --whitespace=error pr39-r7-new-test.patch` 乾淨通過（Exit Code: 0）。
- **語法檢查**：`node --check tests/remediation-twenty-p1-systemic.test.mjs` 通過。

---

## 三、本地測試驗收收據

### 1. 系統性修復測試套件驗證 (32/32 PASS)
```
node --test tests/remediation-twenty-p1-systemic.test.mjs
✔ SYSTEMIC-C01-HUNK-LEXICAL-STATE (Negative): Hunk starting inside block comment ignores commented code when fileContent is provided (2.2823ms)
✔ SYSTEMIC-C01-HUNK-LEXICAL-STATE (Negative without fileContent): Emits lexicalStateUncertain when fileContent is absent (2.3186ms)
✔ SYSTEMIC-C01-HUNK-LEXICAL-STATE (Positive): Hunk in regular executable code accurately extracts candidate calls (0.4251ms)
✔ SYSTEMIC-C02-COMMENTED-DEF-EXCLUSION (Negative): Commented-out function definitions in /* */ are strictly excluded (0.6149ms)
✔ SYSTEMIC-C02-COMMENTED-DEF-EXCLUSION (Positive): Legitimate function preceded by comments is accurately found with line numbers preserved (2.2762ms)
✔ SYSTEMIC-C03-DELAYED-BRACE-BARE-CALL (Negative): Bare call followed by delayed brace is strictly rejected (0.6171ms)
✔ SYSTEMIC-C03-DELAYED-BRACE-BARE-CALL (Negative Chained): Chained bare call followed by delayed brace is strictly rejected (0.2476ms)
✔ SYSTEMIC-C03-DELAYED-BRACE-BARE-CALL (Positive): Cross-line declaration with function keyword is preserved (0.1355ms)
✔ SYSTEMIC-C03-DELAYED-BRACE-BARE-CALL (Positive): Cross-line parameter list with function keyword is preserved (0.1235ms)
✔ SYSTEMIC-C04-ACCESS-CONTROL-VOCAB: Policy, enforce, rbac, acl, and permission terms classify as security (0.2735ms)
✔ SYSTEMIC-C04-ACCESS-CONTROL-VOCAB: Receiver classification for policy.enforce() and acl.canAccess() (0.2716ms)
✔ SYSTEMIC-C05-DIVISION-CHAIN-PRESERVATION (Negative): Chained division operands are not swallowed as regex literals (0.156ms)
✔ SYSTEMIC-C05-DIVISION-CHAIN-PRESERVATION (Positive): True regex literals are correctly stripped (0.0897ms)
✔ SYSTEMIC-C06-BUILTIN-ON-SENSITIVE-RECEIVER: Retains sensitive receiver with builtin method name at both sites (0.4214ms)
✔ SYSTEMIC-C06-BUILTIN-ON-SENSITIVE-RECEIVER (Non-sensitive skipped): Standard non-sensitive collection calls skipped (0.0835ms)
✔ SYSTEMIC-C07-UNCONFIRMED-EXTERNAL-EMPTY-GAPS: Empty external callee emits 0 gaps (0.6068ms)
✔ SYSTEMIC-C08-IMPORT-ALIAS-PRESERVATION: Import alias preserves original symbol sensitivity (0.4796ms)
✔ SYSTEMIC-C09-PATCH-ADDED-IMPORTS (Negative): Local definition deleted by patch is not treated as valid HEAD callee (0.4773ms)
✔ SYSTEMIC-C09-PATCH-ADDED-IMPORTS (Positive): Patch newly added import correctly recognized as external symbol (0.1942ms)
✔ SYSTEMIC-C10-CHANGED-HUNK-CONTEXT-GAPS (Negative): Context line call in hunk with modified control flow generates Context Gap (0.4852ms)
✔ SYSTEMIC-C10-CHANGED-HUNK-CONTEXT-GAPS (Positive): Context line call without control flow alterations in hunk (0.156ms)
✔ SYSTEMIC-C11-CALLEE-XML-FILE-ATTRIBUTE: XML enclosure contains genuine file attribute without multi-file counterfeiting (0.3908ms)
✔ SYSTEMIC-C12-SINGLE-FILE-DIFF-ISOLATION: Multi-file diff is strictly isolated in single-file mode (3.7787ms)
✔ SYSTEMIC-C12-SCHEMA2-ROUTING: targetFile 'multi-file' routes to multi-file logic without mutual exclusion error (0.3088ms)
✔ SYSTEMIC-C12-DIFF-TARGET-NOT-FOUND (Negative): Structured diff omitting target file rejects raw diff fallback and emits context gap (0.504ms)
✔ SYSTEMIC-C13-CLI-NO-REPO-FAIL-CLOSED (Negative): CLI Clean Challenge without reliable repository root fails closed with EXACT_HEAD_CONTEXT_FAILED (13.4382ms)
✔ SYSTEMIC-C14A-FORGED-CALLEE-REJECTION (Negative): Rejects external ContextPackage containing callee not present in exact-head commit (649.4518ms)
✔ SYSTEMIC-C14B-REGISTRATION-FAILURE-WORKFLOW-DENIAL (Negative): Failed context package registration denies workflow authority and causes Dogfood caller fail-closed (864.1824ms)
✔ SYSTEMIC-C14C-SENTRY-COVERAGE-INCOMPLETE-GATE-BLOCK (Negative): Sentry reporting omitted files blocks Clean Approval (0.4018ms)
✔ SYSTEMIC-C14C-SENTRY-COVERAGE-COMPLETE (Positive): Complete sentry coverage without omissions permits Clean Approval (0.1496ms)
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
ℹ duration_ms 11624.8192
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
ℹ duration_ms 43312.8712
```

---

## 四、治理限制遵守聲明

依據 Gate G4 規範與審查領隊裁示：
- `LOCAL_WORKSPACE_EDIT`：依授權完成修改。
- `LOCAL_TEST_EXECUTION`：依授權完成測試驗證。
- `LOCAL_COMMIT`：持續維持 **HOLD**（在審查領隊核驗 R7 補丁並正式授權前，絕不執行 `git commit`）。
- `NEW_PUSH`：**NOT_AUTHORIZED**。
- `THREAD_REPLY / RESOLVE`：**NOT_AUTHORIZED**。
- `SQUASH_MERGE`：**NOT_AUTHORIZED**。
