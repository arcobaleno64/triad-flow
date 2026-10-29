# PR #39 G4 Current P1 系統性根因修復規範與變更申請書 (Remediation Specification)

**文件日期**: 2026-10-27  
**專案儲存庫**: `arcobaleno64/triad-flow`  
**目標 PR**: [PR #39 (`fix/remediation-007-clean-challenge`)](https://github.com/arcobaleno64/triad-flow/pull/39)  
**目標 Commit HEAD**: `ec750e6010edd8d6f3fb8007a59994644b98862c`  
**參照指導裁示**: `PR39-SCHEMA2-G4-BATCH4-REVIEW-R1` 第六節戰略指示  
> *「完成 Batch 4 後，建議將工作重心由逐筆關閉轉向 20 筆 Current P1 的根因合併、最小修復方案與新 Commit 授權審查。同一個缺陷反覆以不同 Thread ID 出現，不應讓修復工作也跟著重複二十次。」*

---

## 一、母體狀態與執行背景

在完成 Pilot Five（5 則）、Six P1s（6 則）、Pilot Five Current P1s（5 則）、Batch 2（4 則）、Batch 3（3 則）及 Batch 4（2 則）累計 **25 則 Review Threads** 之交易式閉合後，PR #39 全部 42 則 Current P1 討論串已 **100% 盤點定性完畢**：
- **已解決 (Resolved)**: **22 則 Current P1**（全域累計 25 則 Resolved，佔比 13.89%）
- **維持凍結 (STRICT_HOLD)**: **20 則 Current P1**（全域未解決 155 則，佔比 86.11%）
  * Outdated P1 (88 則) 與 P2 (47 則) 繼續維持 `STRICT_HOLD`。

本規範依據非通關推定（Default-Deny）與最小手術式變更原則（Occam's Razor / Surgical Change），將此 20 則凍結討論串合併為 **14 組核心缺陷聚類**，擬定精確修復方案與測試矩陣，正式向審查員申請 `NEW_COMMIT` 授權。

---

## 二、20 筆 Current P1 缺陷聚類與根因映射表

| 聚類編號 | 涵蓋討論串 (Thread Short IDs) | 缺陷本質與核心模組 | 涉及檔案與行號錨點 | 最小修復動作 |
| :--- | :--- | :--- | :--- | :--- |
| **C1** | `rte6z`, `slAMv` | 跨 Hunk 區塊註解詞法狀態還原 | `src/core/context-builder.mjs:1683-1698` | 在 Hunk 邊界結合目標檔案內容（`fileContent`），準確判定 Hunk 起始行是否處於多行區塊註解內，避免省略區段註解導致代碼誤判。 |
| **C2** | `rvCBT` | `findFunctionDefinitions` 缺少塊級註解追蹤 | `src/core/context-builder.mjs:490-550` | 在函式定義掃描行迴圈中引入區塊註解狀態機，排查 `/* ... */` 內的註解代碼，防止偽函式圍欄。 |
| **C3** | `sl1Ri` | 延遲大括號搜尋未嚴格排除裸呼叫表達式 | `src/core/context-builder.mjs:494-594` | 嚴格要求延遲大括號 `{` 僅能接續於合法宣告式簽章（包含 `function`, `class`, `export`, `def`, `=>` 等），裸呼叫接換行括號一律拒絕。 |
| **C4** | `slAM6` | 存取控制關鍵字正則詞彙不足 | `src/core/context-builder.mjs:1346-1365` | 在 `classifySensitiveCategory` 的 `security` 正則中補全 `policy`, `enforce`, `rbac`, `acl`, `permission`, `access` 權限關鍵詞。 |
| **C5** | `r1BuI` | 連續除法鏈 `/` 被誤判為 Regex 字面量開頭 | `src/core/context-builder.mjs:1473` | 正規表達式啟發式判定修正：若 `/` 前之最後有效非空白字元為運算元（識別字、`)`、`]`、數字），則判定為除法運算子而非 Regex 開頭。 |
| **C6** | `rr-I6`, `r1BuC` | 內建方法名過濾早於 Receiver 敏感性判定 | `src/core/context-builder.mjs:1729, 1843` | 調整過濾順序：若 Receiver 屬於敏感實體（如 `permissions.has(user)`），即使方法名屬於 `BUILTIN_OBJECT_METHODS` 亦保留為敏感呼叫。 |
| **C7** | `rsKCC`, `slLWi` | 敏感函式體被截斷省略未發出 Context Gap | `src/core/context-builder.mjs:2396-2415` | 當被呼叫者函式因長度超過上限被截斷為 `signature_and_guards` 或 `incomplete` 時，若屬敏感路徑，明確發出 `CALLEE_TRUNCATED_ELIDED` contextGap。 |
| **C8** | `rsajc` | Import 別名（Alias）遺失原始符號敏感身分 | `src/core/context-builder.mjs:2221-2232` | 建立 `importAliases` 映射表（`localAlias -> originalSymbol`），解析呼叫符號時溯源至原始名稱判定敏感類別。 |
| **C9** | `rte6o` | 模組匯入 Set 未解析 Patch Diff 中新增的 import | `src/core/context-builder.mjs:2221-2253` | 除了掃描 `fileContent`（pre-image）外，額外掃描 `diffHunks` 中以 `+` 新增的 `import` 與 `require` 宣告並納入 `importedSymbols`。 |
| **C10** | `rr-JC` | 僅記錄 `isAdded: true` 遺漏周邊控制流變更的呼叫 | `src/core/context-builder.mjs:2286, 2364` | 對於處於變更 Hunk 範圍內（含 Context 行）且其周邊控制流發生實質異動的未解析敏感呼叫，允許記錄為 Context Gap。 |
| **C11** | `rfkYi` | Callee XML Enclosure 標籤缺少 `file` 屬性 | `src/adapters/review-prompts.mjs:260` | 在 `<callee>` XML 節點渲染中加入 `file="${escapeXmlAttribute(c.file || targetFileAttr)}"` 屬性。 |
| **C12** | `rrHOc`, `rvWjO` | 單檔模式處理多檔 ChangeSet 時之 Diff 隔離邊界 | `src/core/context-builder.mjs:3125-3135` | 單檔模式下提取 Callee 時，強制透過 `splitDiffByFiles` 提取該單檔自身之 Diff Hunks，杜絕多檔混雜。 |
| **C13** | `tdsmP` | CLI Clean Challenge 缺少可靠 Repository Root 未 Fail-Closed | `src/cli.mjs:885-945` | 在 CLI 執行 `--verify-with` 時，若無法解析可靠 Repository Root 或 Exact-Head Context 構建失敗，強制 Fail-Closed 發出 `EXACT_HEAD_CONTEXT_FAILED`。 |
| **C14** | `rvCBW`, `rxCha`, `tdsmT` | `scripts/dogfood-review.mjs` 覆蓋驗證與外部 Package 授信邊界 | `scripts/dogfood-review.mjs:1104-1117, 1439` | 引入物理 Git 真實性校驗後始得註冊，並在零 Findings 進入 Clean Challenge 前嚴格核驗所有 Sentry 之檔案覆蓋完整性（`coverage.omittedFiles.length === 0`）。 |

---

## 三、各模組最小手術式修改藍圖 (Surgical Code Changes)

### 1. `src/core/context-builder.mjs`（聚焦 C1～C10、C12）
- **C1 & C5 (`extractCandidateCallSymbols`)**:
  * 引入前向運算元識別，精準區分 `/` 為除法還是 Regex：
    ```javascript
    const isPrecededByOperand = i > 0 && /[a-zA-Z0-9_$)\]]/.test(lastNonWhitespaceChar);
    if (ch === "/" && !isPrecededByOperand && (i === 0 || /[\s=,(:!&|?{;]/.test(line[i - 1]))) { ... }
    ```
  * 結合檔案行號區間校驗 Hunk 起始詞法狀態。
- **C2 & C3 (`findFunctionDefinitions`)**:
  * 加入區塊註解狀態機 `inBlockComment`，跳過所有註解行。
  * 延遲大括號 `{` 僅允許接續於函式/方法宣告標頭，排除裸呼叫表達式。
- **C4 (`classifySensitiveCategory`)**:
  * 擴充 `security` 正則模式：
    ```javascript
    { category: "security", regex: /(?:^|_|\b)(?:auth|permit|permiss|allow|deny|token|secret|privilege|guard|secure|policy|enforce|rbac|acl|role|access)\w*/gi }
    ```
- **C6 (`extractCandidateCallSymbols` & `extractLocalCalleeContext`)**:
  * 調整 `BUILTIN_OBJECT_METHODS` 檢查：先提取 Receiver 並檢驗 Receiver 敏感性，若 Receiver 具備敏感類別則保留呼叫。
- **C7 (`extractLocalCalleeContext`)**:
  * 檢查 `snippet.extractionMode !== "full_body"`，對敏感被呼叫者發出 `CALLEE_TRUNCATED_ELIDED` contextGap。
- **C8 & C9 (`extractLocalCalleeContext`)**:
  * 建立 `importAliases` Map 溯源別名原始名稱。
  * 掃描 `diffHunks` 中新增的 import 宣告加入 `importedSymbols`。
- **C12 (`buildContextPackage`)**:
  * 單檔模式使用 `splitDiffByFiles` 嚴格限制提取該單檔自身之 diffHunks。

### 2. `src/adapters/review-prompts.mjs`（聚焦 C11）
- 行 260：
  ```javascript
  const fileAttr = c.file ? ` file="${escapeXmlAttribute(c.file)}"` : (targetFileAttr ? ` file="${targetFileAttr}"` : "");
  lines.push(`      <callee${fileAttr} symbol="${symAttr}"${lineAttr} bytes="${bytesAttr}">`);
  ```

### 3. `src/cli.mjs`（聚焦 C13）
- 在 `runCli` 之 Clean Challenge 執行路徑中，若 `targetRepo` 不存在或 exact-head context 提取異常，不再靜默忽略，強制注入 `EXACT_HEAD_CONTEXT_FAILED` 阻斷 Gate 誤通關。

### 4. `scripts/dogfood-review.mjs`（聚焦 C14）
- 行 1104：呼叫 `validateContextPackageAuthenticity` 核對 Git 實體後始得建立信任。
- 行 1439：在呼叫 `conductIndependentVerification` 前，增加 `consensus.coverageComplete === true` 斷言。

---

## 四、自動化驗證測試套件藍圖

新增專屬測試檔案 `tests/remediation-twenty-p1-systemic.test.mjs`，包含 14 組一對一針對性確定性回歸測試：
1. `SYSTEMIC-C01-HUNK-LEXICAL-STATE`: 驗證跨 Hunk 區塊註解狀態正確還原。
2. `SYSTEMIC-C02-COMMENTED-DEF-EXCLUSION`: 驗證 `/* function validateAccess() */` 不被誤判為合法定義。
3. `SYSTEMIC-C03-DELAYED-BRACE-BARE-CALL`: 驗證 4 行裸呼叫接換行括號嚴格回傳 0 definitions。
4. `SYSTEMIC-C04-ACCESS-CONTROL-VOCAB`: 驗證 `policyCheck`, `enforceAccess`, `rbacRole` 分類為 `security`。
5. `SYSTEMIC-C05-DIVISION-CHAIN-PRESERVATION`: 驗證 `total / parseLimit(input) / scale` 不被除法符號截斷。
6. `SYSTEMIC-C06-BUILTIN-ON-SENSITIVE-RECEIVER`: 驗證 `permissions.has(user)` 被識別為敏感呼叫。
7. `SYSTEMIC-C07-TRUNCATED-CALLEE-GAP`: 驗證被截斷省略之敏感函式產生 `CALLEE_TRUNCATED_ELIDED` gap。
8. `SYSTEMIC-C08-IMPORT-ALIAS-PRESERVATION`: 驗證 `import { validateAccess as run }` 保留敏感身分。
9. `SYSTEMIC-C09-PATCH-ADDED-IMPORTS`: 驗證 Patch 新增之 import 被納入符號集合。
10. `SYSTEMIC-C10-CHANGED-HUNK-CONTEXT-GAPS`: 驗證修改控制流周圍之敏感未解析呼叫產出 Context Gap。
11. `SYSTEMIC-C11-CALLEE-XML-FILE-ATTRIBUTE`: 驗證 `<callee>` 標籤包含 `file` 屬性。
12. `SYSTEMIC-C12-SINGLE-FILE-DIFF-ISOLATION`: 驗證單檔模式多檔 ChangeSet 徹底隔離 Diff。
13. `SYSTEMIC-C13-CLI-NO-REPO-FAIL-CLOSED`: 驗證 CLI 無可靠 Repository Root 時 Fail-Closed。
14. `SYSTEMIC-C14-DOGFOOD-PRODUCER-COVERAGE`: 驗證 Dogfood 缺少 sentry coverage 阻斷 Clean Challenge。

---

## 五、申請授權事項請求 (NEW_COMMIT Authorization Request)

特此向審查員正式申請核發授權：
1. **代碼修改授權 (NEW_COMMIT)**:
   - 准予依本規範對 `src/core/context-builder.mjs`、`src/adapters/review-prompts.mjs`、`src/cli.mjs`、`scripts/dogfood-review.mjs` 實施最小手術式修復。
   - 准予新增測試套件 `tests/remediation-twenty-p1-systemic.test.mjs`。
2. **提交與推播約束**:
   - 本地變更完成後，必須 100% 通過全域測試套件（`npm test`）及新增之 14 組回歸測試。
   - 於提交本地 Commit 前，提交包含完整 Git Diff 之離線執行收據供審查員核可。
   - `PUSH` 與 `SQUASH_MERGE` 仍維持 `NOT_AUTHORIZED`，直至全域測試與新 Commit 獲審查員核可。

敬請審查員核准本系統性修復藍圖並核發 `NEW_COMMIT` 授權！
