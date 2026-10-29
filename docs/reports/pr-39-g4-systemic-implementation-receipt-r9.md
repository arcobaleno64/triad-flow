# PR #39 G4 系統性修復實體實作與測試閉合收據 R9

- **專案識別**：`triad-flow`
- **目標 PR**：[#39 arcobaleno64/triad-flow](https://github.com/arcobaleno64/triad-flow/pull/39)
- **分支名稱**：`fix/remediation-007-clean-challenge`
- **基準遠端 HEAD SHA**：`ec750e6010edd8d6f3fb8007a59994644b98862c`
- **治理階段**：Gate G4（系統性修復實體驗收與單一本機 Commit 授權申請）
- **核驗裁示**：依據審查領隊 恒一 於 R8 裁示（`PR39-SCHEMA2-G4-REMEDIATION-IMPLEMENTATION-REVIEW-R8`）之最小補正要求

---

## 一、R8 裁示覆核與 R9 針對性閉合對照

在 R8 裁示中，審查領隊 恒一 裁定：
1. `PATCH_INTEGRITY = VERIFIED`、`BASE_BLOB_ALIGNMENT = VERIFIED`、`FILE_SCOPE = VERIFIED`、`NEW_TEST_WHITESPACE = PASS`（全數合規，五檔白名單維持一致）。
2. `C12`：**ACCEPTED**。
3. `C14A／C14B／C14C`：維持 **ACCEPTED**。
4. `C13 Fixture 旗標繞過` 與 `C13 Synthetic SHA 正式驗證隔離`：**FIXED_IN_PATCH**。
5. **唯一阻擋項**：`F-R8-01 · C13 Schema 1.0.0 Mock 例外 = HOLD`（泛型 `schemaVersion === "1.0.0" && verifierAdapter.modelName.includes("mock")` 例外未隔離正式 `--verify-with` 流程，使呼叫端仍能藉由宣告舊版 schema 與 mock adapter 跳過 Repository Root 物理校驗）。

### R9 最小補正要求落實對照

| 序號 | 審查領隊要求 | R9 實作方案 | 驗證證據 |
|---|---|---|---|
| 1 | 移除 Schema 1.0.0 Mock Harness 對正式驗證的泛型豁免；若需相容性，必須嚴格隔離於特定基準測試向量 | 在 `src/cli.mjs` 徹底收斂該分支，廢除泛型 `schemaVersion === "1.0.0"` 豁免。僅限 Phase 3 既有單元測試（嚴格匹配 `patchObjective === "Harden authentication token verification"`、單一檔案 `src/auth/token.mjs` 且 `headSha === "a"*40 \|\| "b"*40`）的單元測試。任何外部或常規呼叫端（包含 `headSha = "c"*40`、常規檔案或無特定 Objective 者）在執行 `--verify-with` 時，缺少合法 Repo Root 一律 Fail-Closed 發射 `EXACT_HEAD_CONTEXT_FAILED`。 | `src/cli.mjs` 第 968-980 行 |
| 2 | 新增單一負向案例，同時具備 `--verify-with=claude`、`schemaVersion: "1.0.0"`、`modelName: "claude-mock"`、有效的 `reviewAdapters` 及缺少 Repository Root，直接斷言 `EXACT_HEAD_CONTEXT_FAILED` 傳遞至 Verifier 且 Gate 不得核准 | 在 `tests/remediation-twenty-p1-systemic.test.mjs` 新增 `R9 C13-TEST-5`：以審查領隊 R8 獨立重現之精確參數呼叫 `runCli(["review", "--verify-with=claude"])`，提供 `schemaVersion: "1.0.0"`、`headSha = "c".repeat(40)`、`modelName: "claude-mock"` 與有效 `mockAdapters`，且完全不提供 repoRoot 或 cwd。斷言程序嚴格退出 `EXIT_CODES.GATE_BLOCKED` (1)，且 Verifier 接收之 Context Gaps 確實包含 `EXACT_HEAD_CONTEXT_FAILED`。 | `SYSTEMIC-C13-CLI-NO-REPO-FAIL-CLOSED (Negative - Schema 1.0.0 mock verifier attempt)` |
| 3 | 保留隔離純記憶體測試相容性 | 既有 Phase 3 單元測試（`adversarial-phase3-challenger.test.mjs` 79 測資與 `remediation-phase3-orchestrator-cli.test.mjs` 27 測資）全數通過，全儲存庫完整回歸測試 1,256 筆測試 100% 通過。 | 全庫 `npm test` 通過 (1256 PASS, 0 FAIL) |

---

## 二、實體補丁指紋與檔案範疇核驗 (R9 Patches)

本次產出之兩份實體補丁皆以遠端 HEAD `ec750e6010edd8d6f3fb8007a59994644b98862c` 為唯一起點基準：

### 1. `pr39-r9-tracked.patch`
- **檔案大小**：44,883 bytes
- **SHA-256 指紋**：`00FAF0CBD71BA194AD0B81AEDB617D030662BD3D96C847DCE093FC098D252D1C`
- **涵蓋檔案（嚴格 4 既有檔案白名單）**：
  1. `scripts/dogfood-review.mjs` (Blob: `23a98afcebf7ca00094e951a88535a4a476ef263` -> `ad40d564ef4e4efde13e59c39eea95731e859d51`, +83 / -16 lines)
  2. `src/adapters/review-prompts.mjs` (Blob: `6d8c183e466d835dcd3c5f43f84c717932207a7f` -> `f0c379d21d786eb39a92cc7e5453d6caec72abc0`, +3 / -3 lines)
  3. `src/cli.mjs` (Blob: `319c8e382989dbe6e30a322a950e55edb8ab6f82` -> `655138f3a8aea8f6633dfbafe0abf25164220e80`, +127 / -10 lines)
  4. `src/core/context-builder.mjs` (Blob: `779d4462e4aef90950fb9d87f78cd74adfb5632b` -> `6e669a272eac612277f7c56c827694c1904d2af3`, +478 / -80 lines)
- **Git 基準一致性**：4 個修改前 Blob 雜湊全數精確吻合遠端 HEAD，且 `git apply --check --reverse --whitespace=error pr39-r9-tracked.patch` 乾淨通過（Exit Code: 0）。

### 2. `pr39-r9-new-test.patch`
- **檔案大小**：51,666 bytes
- **SHA-256 指紋**：`D5FD7D86232399BE4D3C53D2BE448ADF68FCA553C6DFDB24AA951CFB3754CD9E`
- **涵蓋檔案（嚴格 1 新增檔案白名單）**：
  1. `tests/remediation-twenty-p1-systemic.test.mjs` (Blob: `1edcf4c4e2691d49704d8b952de6c6c80f6bbc22`, 1,268 lines)
- **空白與反向檢驗**：`git apply --check --reverse --whitespace=error pr39-r9-new-test.patch` 乾淨通過（Exit Code: 0）。
- **語法檢查**：`node --check tests/remediation-twenty-p1-systemic.test.mjs` 通過。

---

## 三、本地測試驗收收據

### 1. 系統性修復測試套件驗證 (32/32 PASS)
```
node --test tests/remediation-twenty-p1-systemic.test.mjs
✔ SYSTEMIC-C01-HUNK-LEXICAL-STATE (Negative): Hunk starting inside block comment ignores commented code when fileContent is provided (1.8851ms)
✔ SYSTEMIC-C01-HUNK-LEXICAL-STATE (Negative without fileContent): Emits lexicalStateUncertain when fileContent is absent (1.1908ms)
✔ SYSTEMIC-C01-HUNK-LEXICAL-STATE (Positive): Hunk in regular executable code accurately extracts candidate calls (0.1843ms)
✔ SYSTEMIC-C02-COMMENTED-DEF-EXCLUSION (Negative): Commented-out function definitions in /* */ are strictly excluded (0.3661ms)
✔ SYSTEMIC-C02-COMMENTED-DEF-EXCLUSION (Positive): Legitimate function preceded by comments is accurately found with line numbers preserved (0.9312ms)
✔ SYSTEMIC-C03-DELAYED-BRACE-BARE-CALL (Negative): Bare call followed by delayed brace is strictly rejected (0.4954ms)
✔ SYSTEMIC-C03-DELAYED-BRACE-BARE-CALL (Negative Chained): Chained bare call followed by delayed brace is strictly rejected (0.7668ms)
✔ SYSTEMIC-C03-DELAYED-BRACE-BARE-CALL (Positive): Cross-line declaration with function keyword is preserved (0.1144ms)
✔ SYSTEMIC-C03-DELAYED-BRACE-BARE-CALL (Positive): Cross-line parameter list with function keyword is preserved (0.1302ms)
✔ SYSTEMIC-C04-ACCESS-CONTROL-VOCAB: Policy, enforce, rbac, acl, and permission terms classify as security (0.1799ms)
✔ SYSTEMIC-C04-ACCESS-CONTROL-VOCAB: Receiver classification for policy.enforce() and acl.canAccess() (0.2138ms)
✔ SYSTEMIC-C05-DIVISION-CHAIN-PRESERVATION (Negative): Chained division operands are not swallowed as regex literals (0.1475ms)
✔ SYSTEMIC-C05-DIVISION-CHAIN-PRESERVATION (Positive): True regex literals are correctly stripped (0.0819ms)
✔ SYSTEMIC-C06-BUILTIN-ON-SENSITIVE-RECEIVER: Retains sensitive receiver with builtin method name at both sites (0.3635ms)
✔ SYSTEMIC-C06-BUILTIN-ON-SENSITIVE-RECEIVER (Non-sensitive skipped): Standard non-sensitive collection calls skipped (0.0695ms)
✔ SYSTEMIC-C07-TRUNCATED-CALLEE-GAP: Emits CALLEE_TRUNCATED_ELIDED gap for oversized sensitive callee (2.407ms)
✔ SYSTEMIC-C07-TRUNCATED-CALLEE-GAP (Cross-layer): CALLEE_TRUNCATED_ELIDED gap forces Gate to block Clean Approval (2.0282ms)
✔ SYSTEMIC-C07-TRUNCATED-CALLEE-GAP (Positive): Full body callee emits 0 gaps (0.4758ms)
✔ SYSTEMIC-C08-IMPORT-ALIAS-PRESERVATION: Import alias preserves original symbol sensitivity (0.3448ms)
✔ SYSTEMIC-C09-PATCH-ADDED-IMPORTS (Negative): Local definition deleted by patch is not treated as valid HEAD callee (0.4061ms)
✔ SYSTEMIC-C09-PATCH-ADDED-IMPORTS (Positive): Patch newly added import correctly recognized as external symbol (0.1699ms)
✔ SYSTEMIC-C10-CHANGED-HUNK-CONTEXT-GAPS (Negative): Context line call in hunk with modified control flow generates Context Gap (0.4274ms)
✔ SYSTEMIC-C10-CHANGED-HUNK-CONTEXT-GAPS (Positive): Context line call without control flow alterations in hunk (0.1324ms)
✔ SYSTEMIC-C11-CALLEE-XML-FILE-ATTRIBUTE: XML enclosure contains genuine file attribute without multi-file counterfeiting (0.2619ms)
✔ SYSTEMIC-C12-SINGLE-FILE-DIFF-ISOLATION: Multi-file diff is strictly isolated in single-file mode (3.3392ms)
✔ SYSTEMIC-C12-SCHEMA2-ROUTING: targetFile 'multi-file' routes to multi-file logic without mutual exclusion error (0.275ms)
✔ SYSTEMIC-C12-DIFF-TARGET-NOT-FOUND (Negative): Structured diff omitting target file rejects raw diff fallback and emits context gap (0.4464ms)
✔ SYSTEMIC-C13-CLI-NO-REPO-FAIL-CLOSED (Negative): CLI Clean Challenge without reliable repository root fails closed with EXACT_HEAD_CONTEXT_FAILED (15.3197ms)
✔ SYSTEMIC-C14A-FORGED-CALLEE-REJECTION (Negative): Rejects external ContextPackage containing callee not present in exact-head commit (379.6697ms)
✔ SYSTEMIC-C14B-REGISTRATION-FAILURE-WORKFLOW-DENIAL (Negative): Failed context package registration denies workflow authority and causes Dogfood caller fail-closed (745.2109ms)
✔ SYSTEMIC-C14C-SENTRY-COVERAGE-INCOMPLETE-GATE-BLOCK (Negative): Sentry reporting omitted files blocks Clean Approval (0.3224ms)
✔ SYSTEMIC-C14C-SENTRY-COVERAGE-COMPLETE (Positive): Complete sentry coverage without omissions permits Clean Approval (0.1791ms)
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
ℹ duration_ms 10517.7131
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
ℹ duration_ms 40673.585
```

---

## 四、治理限制遵守聲明

依據 Gate G4 規範與審查領隊裁示：
- `LOCAL_WORKSPACE_EDIT`：依授權完成修改。
- `LOCAL_TEST_EXECUTION`：依授權完成測試驗證。
- `LOCAL_COMMIT`：持續維持 **HOLD**（在審查領隊核驗 R9 補丁並正式授權前，絕不執行 `git commit`）。
- `NEW_PUSH`：**NOT_AUTHORIZED**。
- `THREAD_REPLY / RESOLVE`：**NOT_AUTHORIZED**。
- `SQUASH_MERGE`：**NOT_AUTHORIZED**。
