# PR #39 G4 系統性修復實作驗收提報收據 R4 (針對性三項修復閉合)

**提報日期**：2026-10-27  
**審查目標**：PR #39 (`arcobaleno64/triad-flow`)  
**審查基準 HEAD**：`ec750e6010edd8d6f3fb8007a59994644b98862c`  
**呼叫治理裁示**：`PR39-SCHEMA2-G4-REMEDIATION-IMPLEMENTATION-REVIEW-R4`  
**審查領隊**：恒一 (`6adf3e84-1770-83ee-9374-e18b6834e5d9`)  

---

## 一、物理交付文件與父節點驗收清單

依據審查領隊 恒一 於 R3 裁示（`PR39-SCHEMA2-G4-REMEDIATION-IMPLEMENTATION-REVIEW-R3`）之驗收結論：
1. **補丁父節點 Blob 一致性**：已正式確認 VERIFIED，`PATCH_BASE_BLOB_MISMATCH` 永久解除。
2. **五檔修改白名單**：已正式確認 VERIFIED。
3. **20 筆 P1 映射矩陣**：已正式確認 ACCEPTED。
4. **R4 驗收範圍**：嚴格限定於審查領隊指名之三項針對性修復（F-R3-01 / C14B、F-R3-02 / C12、F-R3-03 / C13）與兩項測試契約加強（C14A 完整封裝結構、C14B 呼叫端端到端測試）。

本次提報交付之兩份最新實體 Patch：

| 補丁檔案名稱 | 檔案大小 (Bytes) | SHA-256 雜湊值 | 涵蓋檔案 |
|---|---|---|---|
| `pr39-r4-tracked.patch` | 41,635 bytes | `021592C95F8F1BFB34A2B5389CECF54A07A6C389C14B5B774DC62C1C6E67F2E3` | 4 個 Tracked 檔案 |
| `pr39-r4-new-test.patch` | 35,404 bytes | `C6D6A5240D22410BF28679F33403F51E45E7E250F6CC8356E50E38C39856BE3E` | 1 個全新測試檔案 |

### 父節點 Blob 一致性核驗

| 檔案路徑 | 原始 HEAD Blob (ec750e60) | 修復後 Blob | 變更統計 |
|---|---|---|---|
| `scripts/dogfood-review.mjs` | `23a98af` | `ad40d56` | +83 / -13 |
| `src/adapters/review-prompts.mjs` | `6d8c183` | `f0c379d` | +5 / -1 |
| `src/cli.mjs` | `319c8e3` | `5f66cdb` | +38 / -21 |
| `src/core/context-builder.mjs` | `779d446` | `6e669a2` | +389 / -76 |
| `tests/remediation-twenty-p1-systemic.test.mjs` | *(新檔案)* | `09e32a8` | +874 |

`git diff --check` 核驗結果：Exit code 0，零語法與空白格式錯誤。

---

## 二、R4 三項針對性修復實施細節

### 1. F-R3-01 (C14B)：可信註冊判定與 Dogfood 呼叫端 Fail-Closed

- **問題根因**：原判定式 `registrationSucceeded = regResult !== false && (!regResult || regResult.ok !== false);` 在 `regResult === null`（`registerTrustedContextPackage` 之失敗回傳值）時誤判為 `true`。
- **程式修正**（[`scripts/dogfood-review.mjs`](file:///C:/Users/arcobaleno/Documents/Code/triad-flow/scripts/dogfood-review.mjs#L1119-L1125)）：
  ```javascript
  registrationSucceeded = Boolean(
    regResult &&
    typeof regResult === "object" &&
    regResult.ok !== false &&
    regResult !== null
  );
  ```
  嚴格要求回傳值必須為真實非空物件且 `ok !== false`，`null`、`undefined`、`false` 一律判定為註冊失敗。
- **呼叫端負向測試**：
  在 [`tests/remediation-twenty-p1-systemic.test.mjs`](file:///C:/Users/arcobaleno/Documents/Code/triad-flow/tests/remediation-twenty-p1-systemic.test.mjs) 中實施 `SYSTEMIC-C14B-REGISTRATION-FAILURE-WORKFLOW-DENIAL`：
  直接呼叫 `runDogfoodReview()`，驗證當 `registerTrustedContextPackage()` 回傳 `null` 時，流程嚴格 Fail-Closed，`status: "ERROR"` 且 `contextPackage: null`，外部套件權限被拒絕。

### 2. F-R3-02 (C12)：單檔 Diff 隔離缺席目標檔案拒絕 Raw Diff 回退

- **問題根因**：當 Diff 包含多檔案邊界但找不到請求之單一目標檔案時，原程式直接保留 `rawDiffHunks`，導致外檔 Diff 滲漏進入單檔 ContextPackage。
- **程式修正**（[`src/core/context-builder.mjs`](file:///C:/Users/arcobaleno/Documents/Code/triad-flow/src/core/context-builder.mjs#L3456-L3475) & [L3590-L3600](file:///C:/Users/arcobaleno/Documents/Code/triad-flow/src/core/context-builder.mjs#L3590-L3600)）：
  ```javascript
  let diffHunks = rawDiffHunks;
  let diffFileMismatch = false;
  if (rawDiffHunks && actualFilePath) {
    const fileDiffMap = splitDiffByFiles(rawDiffHunks, [normTarget]);
    const isolated = fileDiffMap.get(normTarget);
    if (isolated !== undefined) {
      diffHunks = isolated;
    } else {
      const hasFileBoundaries = fileDiffMap.size > 0 ||
        /^(?:diff --git |--- [ab]\/|\+\+\+ [ab]\/)/m.test(rawDiffHunks);
      if (hasFileBoundaries) {
        diffHunks = "";
        diffFileMismatch = true;
      }
    }
  }
  ```
  當包含結構化邊界但未包含目標檔案時，`diffHunks` 清空為 `""`，並發射 `DIFF_TARGET_FILE_NOT_FOUND` Context Gap。
- **負向測試**：
  `SYSTEMIC-C12-DIFF-TARGET-NOT-FOUND (Negative)` 驗證包含 `src/unrelated.mjs` 之多檔 Diff 在建構 `src/target.mjs` 時，`rawHunks` 為空字串，且 `contextGaps` 明確包含 `DIFF_TARGET_FILE_NOT_FOUND`。

### 3. F-R3-03 (C13)：移除 Repository Root 檢查例外與加強負向測試

- **問題根因**：原 `isCustomChangeSetTest` 在 `options.repoRoot` 與 `options.cwd` 同時未提供時豁免 Exact-Head 檢查，形成安全繞過漏洞。
- **程式修正**（[`src/cli.mjs`](file:///C:/Users/arcobaleno/Documents/Code/triad-flow/src/cli.mjs#L905-L925)）：
  徹底移除 `isCustomChangeSetTest`。正式 CLI 呼叫與 `--strict` Clean Challenge 在缺少有效 Git Repo Root 時，嚴格 Fail-Closed，發射 `EXACT_HEAD_CONTEXT_FAILED` 並退出 Exit Code 1 (`GATE_BLOCKED`)。
- **負向測試**：
  `SYSTEMIC-C13-CLI-NO-REPO-FAIL-CLOSED (Negative)` 測試兩種邊界：
  - 情境 A：`repoRoot: null, cwd: null` -> 退出 1，發射 `EXACT_HEAD_CONTEXT_FAILED`。
  - 情境 B：完全未提供 `repoRoot` 與 `cwd` -> 退出 1，發射 `EXACT_HEAD_CONTEXT_FAILED`。

### 4. C14A 測試契約加強：完整封裝結構下的 Git 實體 Callee 防偽

- 在 `SYSTEMIC-C14A-FORGED-CALLEE-REJECTION` 中注入結構完整的 Package：
  包含 `schemaVersion: "2.0.0"`、合法之 `budgetAccounting`、有效之 `layer0Diff`、`layer2ModuleScope`，僅在 `layer1Callees` 注入偽造之 `fabricatedSymbol`。
- 驗證結果：Package 成功通過第一層結構驗證，精確於 Git HEAD 實體原始碼比對防線被攔截，發射 `CONTEXT_INTEGRITY_TAMPERED`，阻斷 Clean Approval。

---

## 三、完整驗證收據

### 1. 專屬系統性修復測試套件
- **指令**：`node --test tests/remediation-twenty-p1-systemic.test.mjs`
- **結果**：**32 / 32 PASS (100%)**，耗時 821ms。

### 2. 四大修復與對抗性驗證套件
- **指令**：`node --test tests/remediation-twenty-p1-systemic.test.mjs tests/remediation-six-p1-threads.test.mjs tests/adversarial-phase3-challenger.test.mjs tests/rfc-027-01-schema-v2.test.mjs`
- **結果**：**117 / 117 PASS (100%)**，零失敗。

### 3. 全套儲存庫迴歸測試 (Full Regression)
- **指令**：`npm test`
- **結果**：
  ```text
  ℹ tests 1260
  ℹ suites 0
  ℹ pass 1256
  ℹ fail 0
  ℹ cancelled 0
  ℹ skipped 4
  ℹ todo 0
  ℹ duration_ms 47698.2478
  ```
  **1,256 PASS、0 FAIL、4 SKIPPED**，全專案無任何回退。

---

## 四、治理狀態與申請事項

- **五檔白名單遵循**：嚴格遵守，未觸碰白名單以外任何檔案。
- **目前治理狀態**：
  - `LOCAL_WORKSPACE_EDIT = COMPLETED`
  - `LOCAL_TEST_EXECUTION = 100% PASS`
  - `LOCAL_COMMIT = HOLD`
  - `NEW_PUSH = NOT_AUTHORIZED`
  - `THREAD_REPLY / RESOLVE = NOT_AUTHORIZED`
  - `SQUASH_MERGE = NOT_AUTHORIZED`

**申請授權**：  
請審查領隊 恒一 覆核 R4 兩份實體補丁（`pr39-r4-tracked.patch`、`pr39-r4-new-test.patch`）與三項針對性修復閉合收據。若符合 Default-Deny 與安全規範，請求核發 `LOCAL_COMMIT = AUTHORIZED` 單一本地 Commit 授權。
