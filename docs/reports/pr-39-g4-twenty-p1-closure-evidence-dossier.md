# PR #39 G4 20 筆 Current P1 討論串結案證據卷宗（14 聚類一對一閉合對帳）

- **卷宗識別碼**：`PR39-SCHEMA2-G4-THREAD-CLOSURE-EVIDENCE-DOSSIER-R1`
- **對應審查階段**：`PR39-SCHEMA2-G4-THREAD-CLOSURE-EVIDENCE-REVIEW-R1`
- **對應 CI 裁示**：`PR39-SCHEMA2-G4-CROSS-PLATFORM-CI-ACCEPTANCE-R1`（`CROSS_PLATFORM CI = ACCEPTED`）
- **核驗 Commit**：`0fec4f97f46c892a8f5eee1d606660e07d130d54`（Parent: `ec750e6010edd8d6f3fb8007a59994644b98862c`）
- **目標 PR**：[arcobaleno64/triad-flow#39](https://github.com/arcobaleno64/triad-flow/pull/39)
- **當前治理狀態**：`LOCAL_COMMIT = DONE`、`NEW_PUSH = DONE`、`CROSS_PLATFORM_CI = ACCEPTED`、`THREAD_REPLY / RESOLVE = HOLD`（等待本卷宗核審授權）

---

## 一、CI-OBS-01 測試計數差異對帳說明

在 R1 跨平台 CI 驗收裁示中，領隊 恒一 標註觀察項 `CI-OBS-01`：
> 「本地收據為 1,257 PASS、4 SKIPPED；GitHub CI 則為 1,254 PASS、4 SKIPPED，存在 3 項測試的計數差異。」

### 精確對帳結果
1. **差異來源**：本地工作區包含 `scratch/` 目錄，內含 3 個臨時驗證腳本：
   - `scratch/debug-challenger-test.mjs` (1 test)
   - `scratch/test-attach.mjs` (1 test)
   - `scratch/test-route1.mjs` (1 test)
2. **Node 測試執行器機制**：本地執行 `npm test`（即 `node --test`）時，Node.js 預設會遞迴掃描工作區所有匹配 `**/*.test.*` 或 `**/test-*.*` 之檔案。因此本地總計為：
   `1,254（官方儲存庫測試）+ 3（scratch 暫存腳本）= 1,257 PASS`。
3. **CI 乾淨環境**：在 GitHub Actions 中，`scratch/` 屬於本地未追蹤目錄，未提交至 Git。因此三平台 CI 執行的是純淨儲存庫官方測試，嚴格為 **1,254 PASS、0 FAIL、4 SKIPPED**。
4. **結論**：正式官方測試套件在本地與 GitHub CI 三大平台之測試計數與通過率 **100% 完全一致**。

---

## 二、20 筆 Current P1 討論串 1 對 1 閉合對帳表

本表嚴格依據 PR #39 的 20 則尚未解決之 Current P1 Review Threads，逐筆對應 14 個缺陷聚類、修復程式碼位置、新測試檔契約及 CI 驗證收據：

| # | Thread Node ID | Short ID | 聚類 | 核心檔案與行號 (Commit `0fec4f9`) | 缺陷本質與修復動作 | 專屬確定性測試契約 | CI 驗證 |
| :---: | :--- | :---: | :---: | :--- | :--- | :--- | :---: |
| 1 | `PRRT_kwDOUWarIc6rte6z` | `rte6z` | **C1** | `src/core/context-builder.mjs:1683` | 跨 Hunk 區塊註解詞法狀態遺失。引入目標檔案 `fileContent` 結合行號區間準確判定 Hunk 起始行是否處於多行註解中。 | `SYSTEMIC-C01-HUNK-LEXICAL-STATE` (Negative/Positive) | PASS |
| 2 | `PRRT_kwDOUWarIc6slAMv` | `slAMv` | **C1** | `src/core/context-builder.mjs:1683` | （同上 C1 聚類）未提供 `fileContent` 時保守發射 `lexicalStateUncertain`，避免註解代碼偽裝成呼叫。 | `SYSTEMIC-C01-HUNK-LEXICAL-STATE` (Negative without fileContent) | PASS |
| 3 | `PRRT_kwDOUWarIc6rvCBT` | `rvCBT` | **C2** | `src/core/context-builder.mjs:490` | `findFunctionDefinitions` 缺少塊級註解追蹤。引入區塊註解狀態機，排查 `/* ... */` 內被註解掉之函式定義。 | `SYSTEMIC-C02-COMMENTED-DEF-EXCLUSION` (Negative/Positive) | PASS |
| 4 | `PRRT_kwDOUWarIc6sl1Ri` | `sl1Ri` | **C3** | `src/core/context-builder.mjs:510` | 延遲大括號搜尋未嚴格排除裸呼叫表達式。嚴格限定延遲 `{` 僅能接續於合法宣告式簽章（`function`, `class`, `export` 等）。 | `SYSTEMIC-C03-DELAYED-BRACE-BARE-CALL` (Negative/Positive) | PASS |
| 5 | `PRRT_kwDOUWarIc6slAM6` | `slAM6` | **C4** | `src/core/context-builder.mjs:1346` | 存取控制正則詞彙不足。在 `security` 敏感正則補全 `policy`, `enforce`, `rbac`, `acl`, `permission`, `access` 權限關鍵詞。 | `SYSTEMIC-C04-ACCESS-CONTROL-VOCAB` | PASS |
| 6 | `PRRT_kwDOUWarIc6r1BuI` | `r1BuI` | **C5** | `src/core/context-builder.mjs:1473` | 連續除法鏈 `/` 被誤判為 Regex 字面量開頭。修正前向運算元識別，若 `/` 前為運算元（識別字、`)`、`]`、數字）則判定為除法運算子。 | `SYSTEMIC-C05-DIVISION-CHAIN-PRESERVATION` (Negative/Positive) | PASS |
| 7 | `PRRT_kwDOUWarIc6rr-I6` | `rr-I6` | **C6** | `src/core/context-builder.mjs:1729` | 內建方法名過濾早於 Receiver 敏感性判定。調整順序：Receiver 屬敏感實體時（如 `permissions.has`），即使方法名為內建亦保留。 | `SYSTEMIC-C06-BUILTIN-ON-SENSITIVE-RECEIVER` | PASS |
| 8 | `PRRT_kwDOUWarIc6r1BuC` | `r1BuC` | **C6** | `src/core/context-builder.mjs:1843` | （同上 C6 聚類）在第二處符號提取點同步調整 Receiver 敏感性優先判定。 | `SYSTEMIC-C06-BUILTIN-ON-SENSITIVE-RECEIVER` (Non-sensitive skipped) | PASS |
| 9 | `PRRT_kwDOUWarIc6rsKCC` | `rsKCC` | **C7** | `src/core/context-builder.mjs:2396` | 敏感函式體被截斷省略未發出 Context Gap。當被呼叫者非 `full_body` 時，對敏感路徑強制發出 `CALLEE_TRUNCATED_ELIDED` gap。 | `SYSTEMIC-C07-TRUNCATED-CALLEE-GAP` (Negative/Cross-layer) | PASS |
| 10 | `PRRT_kwDOUWarIc6slLWi` | `slLWi` | **C7** | `src/core/context-builder.mjs:2410` | （同上 C7 聚類）截斷 Gap 強制使 Gate 阻斷 Clean Approval。 | `SYSTEMIC-C07-TRUNCATED-CALLEE-GAP` (Cross-layer Gate Block) | PASS |
| 11 | `PRRT_kwDOUWarIc6rsajc` | `rsajc` | **C8** | `src/core/context-builder.mjs:2221` | Import 別名（Alias）遺失原始符號敏感身分。建立 `importAliases` Map 溯源別名原始名稱。 | `SYSTEMIC-C08-IMPORT-ALIAS-PRESERVATION` | PASS |
| 12 | `PRRT_kwDOUWarIc6rte6o` | `rte6o` | **C9** | `src/core/context-builder.mjs:2235` | 模組匯入 Set 未解析 Patch Diff 中新增的 import。除 pre-image 外額外掃描 diffHunks 中 `+` 新增的 import 與 require 宣告。 | `SYSTEMIC-C09-PATCH-ADDED-IMPORTS` (Negative/Positive) | PASS |
| 13 | `PRRT_kwDOUWarIc6rr-JC` | `rr-JC` | **C10** | `src/core/context-builder.mjs:2364` | 僅記錄 `isAdded: true` 遺漏周邊控制流變更的呼叫。對變更 Hunk 範圍內且周邊控制流實質異動的未解析敏感呼叫發出 Gap。 | `SYSTEMIC-C10-CHANGED-HUNK-CONTEXT-GAPS` (Negative/Positive) | PASS |
| 14 | `PRRT_kwDOUWarIc6rfkYi` | `rfkYi` | **C11** | `src/adapters/review-prompts.mjs:260` | Callee XML Enclosure 標籤缺少 `file` 屬性。在 `<callee>` XML 節點渲染中加入 `file="${escapeXmlAttribute(c.file || targetFileAttr)}"`。 | `SYSTEMIC-C11-CALLEE-XML-FILE-ATTRIBUTE` | PASS |
| 15 | `PRRT_kwDOUWarIc6rrHOc` | `rrHOc` | **C12** | `src/core/context-builder.mjs:3125` | 單檔模式處理多檔 ChangeSet 時之 Diff 隔離邊界。強制透過 `splitDiffByFiles` 提取該單檔自身之 diffHunks，杜絕多檔混雜。 | `SYSTEMIC-C12-SINGLE-FILE-DIFF-ISOLATION` | PASS |
| 16 | `PRRT_kwDOUWarIc6rvWjO` | `rvWjO` | **C12** | `src/core/context-builder.mjs:3080` | （同上 C12 聚類）多檔路由與結構化 Diff 遺漏單檔之負向安全防護。 | `SYSTEMIC-C12-SCHEMA2-ROUTING` / `DIFF-TARGET-NOT-FOUND` | PASS |
| 17 | `PRRT_kwDOUWarIc6tdsmP` | `tdsmP` | **C13** | `src/cli.mjs:907-986` | CLI Clean Challenge 缺少可靠 Repository Root 未 Fail-Closed。完全刪除 Mock 豁免，凡缺少合法實體 Git 根目錄無條件發射 `EXACT_HEAD_CONTEXT_FAILED` 退出碼 1。 | `SYSTEMIC-C13-CLI-NO-REPO-FAIL-CLOSED` (含 R9 TEST-5, R10 TEST-6) | PASS |
| 18 | `PRRT_kwDOUWarIc6tdsmT` | `tdsmT` | **C14A** | `scripts/dogfood-review.mjs:1104` | 偽造 Callee 或篡改 ContextPackage 注入。引入實體 Git 真實性校驗（`validateContextPackageAuthenticity`），未經驗證者拒絕註冊並 Fail-Closed。 | `SYSTEMIC-C14A-FORGED-CALLEE-REJECTION` | PASS |
| 19 | `PRRT_kwDOUWarIc6rxCha` | `rxCha` | **C14B** | `scripts/dogfood-review.mjs:1115` | 未經註冊之 ContextPackage 繞過流程。校驗失敗時剝離 Package 並注入 `EXACT_HEAD_CONTEXT_FAILED` 阻斷 Clean Approval。 | `SYSTEMIC-C14B-REGISTRATION-FAILURE-WORKFLOW-DENIAL` | PASS |
| 20 | `PRRT_kwDOUWarIc6rvCBW` | `rvCBW` | **C14C** | `scripts/dogfood-review.mjs:1439` | Sentry 覆蓋不全（有遺漏檔案）卻通關 Clean Challenge。嚴格斷言所有 Sentry 無遺漏檔案（`coverage.omittedFiles.length === 0`）始得核准。 | `SYSTEMIC-C14C-SENTRY-COVERAGE-INCOMPLETE-GATE-BLOCK` | PASS |

---

## 三、治理回覆草案（供 THREAD_REPLY 授權核准）

實施團隊建議對上述 20 則 Review Threads 發布之標準化回覆範本：

> **PR #39 G4 系統性修復驗收回覆**：
> 本缺陷已於 G4 系統性修復 Commit `0fec4f97f46c892a8f5eee1d606660e07d130d54` 徹底修復，修復內容遵循審查領隊 恒一 之授權命令 `PR39-SCHEMA2-G4-LOCAL-COMMIT-AUTH-R1`。
> 專屬針對性測試已納入 `tests/remediation-twenty-p1-systemic.test.mjs`，且已於 GitHub Actions 跨平台 CI（Run ID: 40521711216，macOS / Ubuntu / Windows 三平台）驗證 100% 通過。
> 治理收據：`docs/reports/pr-39-g4-twenty-p1-closure-evidence-dossier.md`。

---

## 四、治理授權請求

依據審查領隊 恒一 於 CI 驗收裁示第四節指示：
> 「該階段應將 20 筆 Current P1 Review Threads 逐筆對應修復程式、負向測試及 CI 證據，先核發回覆授權，再依實際確認結果決定是否允許 Resolve。不得僅以「CI 全綠」作為 20 筆討論串全部結案的證據。」

實施團隊謹請審查領隊核驗本卷宗之 20 筆 1 對 1 映射與對帳證據，並核發：
1. **`THREAD_REPLY = AUTHORIZED`**：授權實施團隊將上述標準化收據回覆至該 20 則 Review Threads。
2. **`THREAD_RESOLVE` 評估裁示**：由領隊核實回覆後裁決是否授權標記解決。
