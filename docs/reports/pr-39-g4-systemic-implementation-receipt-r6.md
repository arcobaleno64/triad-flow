# PR #39 G4 系統性修復實體實作與測試閉合收據 R6

- **專案識別**：`triad-flow`
- **目標 PR**：[#39 arcobaleno64/triad-flow](https://github.com/arcobaleno64/triad-flow/pull/39)
- **分支名稱**：`fix/remediation-007-clean-challenge`
- **基準遠端 HEAD SHA**：`ec750e6010edd8d6f3fb8007a59994644b98862c`
- **治理階段**：Gate G4（系統性修復實體驗收與單一本機 Commit 授權申請）
- **核驗裁示**：依據審查領隊 恒一 於 R5 裁示（`PR39-SCHEMA2-G4-REMEDIATION-IMPLEMENTATION-REVIEW-R5`）之最小補正要求

---

## 一、R5 裁示覆核與 R6 針對性閉合對照

在 R5 裁示中，審查領隊 恒一 裁定：
1. `PATCH_INTEGRITY = VERIFIED`、`BASE_BLOB_ALIGNMENT = VERIFIED`、`FILE_SCOPE = VERIFIED`（全數合規，五檔白名單維持一致）。
2. `C12 單檔 Diff 隔離`：正式 **ACCEPTED**。
3. `C14A 偽造 Callee 來源驗證` 與 `C14B Registry 失敗傳播`：**ACCEPTED_FOR_TEST_DESIGN**（設計完全接受，不再要求修改）。
4. `C13 argv --strict 路徑`：**ACCEPTED**。
5. **唯一阻擋項**：`C13 完整來源邊界`（非 Strict 模式下程式介面注入 Verifier Adapter 推定為 Fixture 存在旁路，且預先提供 `options.contextPackage` 需補全來源校驗）。

### R6 最小補正要求落實對照

| 序號 | 審查領隊要求 | R6 實作方案 | 驗證證據 |
|---|---|---|---|
| 1 | 將 Repository Root 不可信判斷與 Fixture 辨識分開；不得單靠 Adapter 注入推定安全測試模式 | 徹底廢除 `options.verifierAdapter && !strictArg` 的泛型推定。建立嚴格之 `isExplicitInMemoryFixture`，僅當明確傳入 `options.inMemoryFixture === true` 等顯式旗標，或 Adapter 之 `modelName`/`providerName` 具備明確 `mock` 標識（如 `createMockVerifierAdapter` 產物）時才視為 Fixture。正式 Adapter（如 `claude-5.5-sonnet`）絕不豁免。 | `src/cli.mjs` 第 910-920 行 |
| 2 | 對正式 `--verify-with` 流程，無論是否 `--strict`，缺少可靠 Exact-Head Repository Root 都必須 Fail-Closed | 當 `isExplicitInMemoryFixture` 為 false 時，無論命令列是否帶 `--strict`，只要缺少 `targetRepo` 或 `isGitRepo(targetRepo)` 為 false，嚴格觸發 `contextExtractionFailed = true` 並注入 `EXACT_HEAD_CONTEXT_FAILED` Gap，阻擋 Clean Approval。 | `src/cli.mjs` 第 955-965 行；負向測試驗證通過 |
| 3 | 對預先提供 `options.contextPackage` 的情境，確認其不能繞過必要來源驗證 | 新增前置授信檢驗：若呼叫端傳入 `options.contextPackage`，首先檢查 `isTrustedContextPackage(effectiveContextPackage)`。若未獲授信，則強制要求 `targetRepo` 存在且通過真實 Git 來源註冊（`registerTrustedContextPackage`）；若無合法 Repo 或註冊失敗，強制清除 `effectiveContextPackage = null`，設定 `contextExtractionFailed = true` 並發射 `EXACT_HEAD_CONTEXT_FAILED`。 | `src/cli.mjs` 第 922-953 行 |
| 4 | 新增非 Strict、無 Root、注入 Adapter 負向測試 | 在 `tests/remediation-twenty-p1-systemic.test.mjs` 新增測試：呼叫 `runCli(["review", "--verify-with=claude"])`（無 `--strict`、無 repoRoot），注入正式 Adapter（`modelName: "claude-5.5-sonnet"`），斷言退出碼為 `EXIT_CODES.GATE_BLOCKED` (1)，且 Verifier 確實收到 `EXACT_HEAD_CONTEXT_FAILED` Gap。 | `SYSTEMIC-C13-CLI-NO-REPO-FAIL-CLOSED` |
| 5 | 新增 Strict、無 Root、預先提供 Package 負向測試 | 在 `tests/remediation-twenty-p1-systemic.test.mjs` 新增測試：呼叫 `runCli(["review", "--strict", "--verify-with=claude"])`，傳入未受信之候選 `contextPackage`，且完全不提供 repoRoot。斷言退出碼為 `EXIT_CODES.GATE_BLOCKED` (1)，Verifier 接收之 `contextPackage` 嚴格被清除為 `null`，且收到 `EXACT_HEAD_CONTEXT_FAILED` Gap。 | `SYSTEMIC-C13-CLI-NO-REPO-FAIL-CLOSED` |
| 6 | 允許保留獨立純記憶體測試模式，但明確標識隔離，不影響既有測試套件 | 既有 Phase 3 單元測試（`adversarial-phase3-challenger.test.mjs` 與 `remediation-phase3-orchestrator-cli.test.mjs`）使用標準 `createMockVerifierAdapter("claude")`，其 `modelName` 為 `claude-mock`，安全隔離於正式審查流程，全庫 1,256 筆測試持續 100% 通過。 | 全庫 `npm test` 通過 (1256 PASS, 0 FAIL) |

---

## 二、實體補丁指紋與檔案範疇核驗 (R6 Patches)

本次產出之兩份實體補丁皆以遠端 HEAD `ec750e6010edd8d6f3fb8007a59994644b98862c` 為唯一起點基準：

### 1. `pr39-r6-tracked.patch`
- **檔案大小**：43,540 bytes
- **SHA-256 指紋**：`29CBBE24F717DF04FB7C35E615D49A3BC5BD9F5A8A120E1FB597BF176FF02362`
- **涵蓋檔案（嚴格 4 既有檔案白名單）**：
  1. `scripts/dogfood-review.mjs` (Blob: `23a98af` -> `ad40d56`, +83 / -16 lines)
  2. `src/adapters/review-prompts.mjs` (Blob: `6d8c183` -> `f0c379d`, +3 / -3 lines)
  3. `src/cli.mjs` (Blob: `319c8e3` -> `1876cba`, +99 / -10 lines)
  4. `src/core/context-builder.mjs` (Blob: `779d446` -> `6e669a2`, +478 / -80 lines)
- **Git 基準一致性**：4 個修改前 Blob 雜湊全數精確吻合遠端 HEAD，且 `git apply --check --reverse pr39-r6-tracked.patch` 乾淨通過。

### 2. `pr39-r6-new-test.patch`
- **檔案大小**：46,016 bytes
- **SHA-256 指紋**：`ABCD069AB113177703E13E9CCE0015DB0414EEEAF712097F79AF8DA1ED9AACAB`
- **涵蓋檔案（嚴格 1 新增檔案白名單）**：
  1. `tests/remediation-twenty-p1-systemic.test.mjs` (Blob: `e4ed664f17d130958a2b501d7cb780968c16c952`, 1,136 lines)
- **語法檢查**：`node --check tests/remediation-twenty-p1-systemic.test.mjs` 通過。

---

## 三、本地測試驗收收據

### 1. 系統性修復測試套件驗證
```
node --test tests/remediation-twenty-p1-systemic.test.mjs
✔ SYSTEMIC-C01-HUNK-LEXICAL-STATE ...
...
✔ SYSTEMIC-C13-CLI-NO-REPO-FAIL-CLOSED (Negative): CLI Clean Challenge without reliable repository root fails closed with EXACT_HEAD_CONTEXT_FAILED (14.2718ms)
✔ SYSTEMIC-C14A-FORGED-CALLEE-REJECTION (Negative): Rejects external ContextPackage containing callee not present in exact-head commit (476.9138ms)
✔ SYSTEMIC-C14B-REGISTRATION-FAILURE-WORKFLOW-DENIAL (Negative): Failed context package registration denies workflow authority and causes Dogfood caller fail-closed (741.6949ms)
✔ SYSTEMIC-C14C-SENTRY-COVERAGE-INCOMPLETE-GATE-BLOCK ...
ℹ tests 32
ℹ suites 0
ℹ pass 32
ℹ fail 0
ℹ duration_ms 1388.4268
```
**結果：32/32 PASS (100%)**

### 2. 四大修復驗證套件聯測
```
node --test tests/remediation-twenty-p1-systemic.test.mjs tests/remediation-six-p1-threads.test.mjs tests/remediation-phase3-orchestrator-cli.test.mjs tests/adversarial-phase3-challenger.test.mjs
ℹ tests 144
ℹ suites 0
ℹ pass 144
ℹ fail 0
ℹ duration_ms 11354.0196
```
**結果：144/144 PASS (100%)**

### 3. 全儲存庫完整回歸測試 (`npm test`)
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
ℹ duration_ms 44819.7695
```
**結果：1,256 PASS、0 FAIL、4 SKIPPED (100%)**

---

## 四、治理限制遵守聲明

依據 Gate G4 規範與審查領隊裁示：
- `LOCAL_WORKSPACE_EDIT`：依授權完成修改。
- `LOCAL_TEST_EXECUTION`：依授權完成測試驗證。
- `LOCAL_COMMIT`：持續維持 **HOLD**（在審查領隊核驗 R6 補丁並正式授權前，絕不執行 `git commit`）。
- `NEW_PUSH`：**NOT_AUTHORIZED**。
- `THREAD_REPLY / RESOLVE`：**NOT_AUTHORIZED**。
- `SQUASH_MERGE`：**NOT_AUTHORIZED**。
