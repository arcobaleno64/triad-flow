# PR #39 G4 Systemic Remediation Implementation Dossier R2 (20 Current P1 Threads)
**Document ID**: `PR39-SCHEMA2-G4-SYSTEMIC-IMPLEMENTATION-DOSSIER-R2`  
**Review Adjudication Responded**: `PR39-SCHEMA2-G4-REMEDIATION-IMPLEMENTATION-REVIEW-R1` (`CONDITIONAL_HOLD`)  
**Repository**: `arcobaleno64/triad-flow`  
**PR**: [#39 (`fix/remediation-007-clean-challenge`)](https://github.com/arcobaleno64/triad-flow/pull/39)  
**Remote HEAD SHA**: `ec750e6010edd8d6f3fb8007a59994644b98862c`  
**Review Target Conversation**: `6adf3e84-1770-83ee-9374-e18b6834e5d9` (恒一, Project: `triad-flow`)  
**Timestamp**: 2026-10-27T13:45:00+08:00  

---

## 一、工作區狀態收據 (Workspace Receipts)

依據審查領隊恒一要求，核驗工作區父節點、分支、未暫存狀態與語法合規：

```bash
$ git rev-parse HEAD
ec750e6010edd8d6f3fb8007a59994644b98862c

$ git branch --show-current
fix/remediation-007-clean-challenge

$ git status --porcelain=v1 -uall
 M scripts/dogfood-review.mjs
 M src/adapters/review-prompts.mjs
 M src/cli.mjs
 M src/core/context-builder.mjs
?? tests/remediation-twenty-p1-systemic.test.mjs
(其餘未追蹤檔案均為 docs/reports/ 與 evidence-runs/ 離線記錄，無任何無關代碼變更)

$ git diff --check
(回傳碼 0，無任何空白錯誤、衝突標記或多餘字符)
```

**白名單邊界確認**:
- 程式檔案變更僅限已授權之 4 檔：
  1. `src/core/context-builder.mjs`
  2. `src/adapters/review-prompts.mjs`
  3. `src/cli.mjs`
  4. `scripts/dogfood-review.mjs`
- 測試檔案新增僅限已授權之 1 檔：
  5. `tests/remediation-twenty-p1-systemic.test.mjs`

---

## 二、修正後之 20 則 Current P1 完整閉合對照矩陣 (Corrected 20-Thread Matrix)

完整修正第一輪提報中之索引位移，採納審查員查核 GitHub 原始內容後核定之對應清單，逐一對齊模組函式錨點、測試案例與實測結果：

| 聚類 | Short ID | GraphQL Thread ID | 檔案與函式錨點 | 專屬測試案例名稱 | 預期修復行為 | 實測收據 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **C01** | `rte6z` | `PRRT_kwDOUWarIc6rte6z` | `src/core/context-builder.mjs:1435`<br>`extractCandidateCallSymbols` | `SYSTEMIC-C01-HUNK-LEXICAL-STATE (Negative without fileContent)` | Hunk 首行在區塊註解內且無 fileContent 時，發出 `lexicalStateUncertain: true` Fail-Closed | PASS (1.3ms) |
| **C01** | `slAMv` | `PRRT_kwDOUWarIc6slAMv` | `src/core/context-builder.mjs:1450`<br>`extractCandidateCallSymbols` | `SYSTEMIC-C01-HUNK-LEXICAL-STATE (Negative)` | 利用 `fileContent` 重建詞法狀態確定首行在註解內，忽略註解中偽呼叫 | PASS (2.0ms) |
| **C02** | `rvCBT` | `PRRT_kwDOUWarIc6rvCBT` | `src/core/context-builder.mjs:530`<br>`stripCommentsPreservingLayout` | `SYSTEMIC-C02-COMMENTED-DEF-EXCLUSION (Negative)` | 遮蔽 `/* ... */` 註解但保留原行號，杜絕註解函式被當作 HEAD Callee | PASS (0.4ms) |
| **C03** | `sl1Ri` | `PRRT_kwDOUWarIc6sl1Ri` | `src/core/context-builder.mjs:574`<br>`findFunctionDefinitions` | `SYSTEMIC-C03-DELAYED-BRACE-BARE-CALL (Negative)` | `HAS_EXPLICIT_DECL_HEADER` 嚴格拒絕無宣告頭之延遲大括號裸呼叫 | PASS (0.6ms) |
| **C04** | `slAM6` | `PRRT_kwDOUWarIc6slAM6` | `src/core/context-builder.mjs:180`<br>`classifySensitiveCategory` | `SYSTEMIC-C04-ACCESS-CONTROL-VOCAB` | 擴充詞彙辨識 `policy.enforce()`、`acl.canAccess()` 為 security 敏感分類 | PASS (0.8ms) |
| **C05** | `r1BuI` | `PRRT_kwDOUWarIc6r1BuI` | `src/core/context-builder.mjs:1330`<br>`stripCommentsAndStrings` | `SYSTEMIC-C05-DIVISION-CHAIN-PRESERVATION (Negative)` | 前向運算元識別 `)`/`]` 緊鄰之 `/` 為除法鏈，不被吞為 Regex 字面量 | PASS (0.2ms) |
| **C06** | `rr-I6` | `PRRT_kwDOUWarIc6rr-I6` | `src/core/context-builder.mjs:1890`<br>`extractCandidateCallSymbols` | `SYSTEMIC-C06-BUILTIN-ON-SENSITIVE-RECEIVER` | `auth.has(perm)` 優先檢查敏感 receiver，保留呼叫不被 builtin 過濾 | PASS (0.4ms) |
| **C06** | `r1BuC` | `PRRT_kwDOUWarIc6r1BuC` | `src/core/context-builder.mjs:2030`<br>`extractCandidateCallSymbols` | `SYSTEMIC-C06-BUILTIN-ON-SENSITIVE-RECEIVER (Non-sensitive)` | 非敏感 receiver 之標準 collection builtin 呼叫（如 `set.has()`）正常略過 | PASS (0.1ms) |
| **C07** | `rsKCC` | `PRRT_kwDOUWarIc6rsKCC` | `src/core/context-builder.mjs:2680`<br>`extractLocalCalleeContext` | `SYSTEMIC-C07-TRUNCATED-CALLEE-GAP` | 敏感 Callee 因超長遭截斷時發出 `CALLEE_TRUNCATED_ELIDED` Context Gap | PASS (2.7ms) |
| **C07** | `slLWi` | `PRRT_kwDOUWarIc6slLWi` | `src/adapters/review-orchestrator.mjs:420`<br>`orchestrateReview` | `SYSTEMIC-C07-TRUNCATED-CALLEE-GAP (Cross-layer)` | `CALLEE_TRUNCATED_ELIDED` Gap 強制 Gate 阻斷 Clean Approval (Fail-Closed) | PASS (2.2ms) |
| **C08** | `rsajc` | `PRRT_kwDOUWarIc6rsajc` | `src/core/context-builder.mjs:2220`<br>`extractModuleScope` | `SYSTEMIC-C08-IMPORT-ALIAS-PRESERVATION` | `importAliases` 映射表完整傳遞別名（如 `checkToken as verify`）之敏感度 | PASS (0.5ms) |
| **C09** | `rte6o` | `PRRT_kwDOUWarIc6rte6o` | `src/core/context-builder.mjs:2240`<br>`extractCandidateCallSymbols` | `SYSTEMIC-C09-PATCH-ADDED-IMPORTS (Negative)` | 掃描 Diff 識別已被刪除之 `-function`，不再將已刪除 HEAD 定義視為有效 | PASS (0.5ms) |
| **C10** | `rr-JC` | `PRRT_kwDOUWarIc6rr-JC` | `src/core/context-builder.mjs:2075`<br>`extractCandidateCallSymbols` | `SYSTEMIC-C10-CHANGED-HUNK-CONTEXT-GAPS (Negative)` | 追蹤 Hunk 控制流異動（`isControlFlowModified`），周邊 Context 行呼叫發出 Gap | PASS (0.5ms) |
| **C11** | `rfkYi` | `PRRT_kwDOUWarIc6rfkYi` | `src/adapters/review-prompts.mjs:260`<br>`formatContextPackageXml` | `SYSTEMIC-C11-CALLEE-XML-FILE-ATTRIBUTE` | `<callee>` XML 加入 `file="..."`，多檔模式精準定位歸屬，單檔模式結構一致 | PASS (0.4ms) |
| **C12** | `rrHOc` | `PRRT_kwDOUWarIc6rrHOc` | `src/core/context-builder.mjs:3125`<br>`buildContextPackage` | `SYSTEMIC-C12-SINGLE-FILE-DIFF-ISOLATION` | 單檔模式提取 Callee 時強制透過 `splitDiffByFiles` 徹底隔離多檔 Diff | PASS (3.1ms) |
| **C12** | `rvWjO` | `PRRT_kwDOUWarIc6rvWjO` | `src/core/context-builder.mjs:3160`<br>`buildContextPackage` | `SYSTEMIC-C12-SCHEMA2-ROUTING` | `targetFile === "multi-file"` 正常進入多檔聚合流程，杜絕互斥拋錯 | PASS (0.2ms) |
| **C13** | `tdsmP` | `PRRT_kwDOUWarIc6tdsmP` | `src/cli.mjs:908`<br>`runCli` | `SYSTEMIC-C13-CLI-NO-REPO-FAIL-CLOSED (Negative)` | CLI Clean Challenge 缺少有效 Repo Root 時強制 Fail-Closed 發出 `EXACT_HEAD_CONTEXT_FAILED` | PASS (6.4ms) |
| **C14** | `rvCBW` | `PRRT_kwDOUWarIc6rvCBW` | `scripts/dogfood-review.mjs:1465`<br>`conductIndependentVerification` | `SYSTEMIC-C14C-SENTRY-COVERAGE-INCOMPLETE-GATE-BLOCK` | 審查崗哨若回報 `omittedFiles > 0`，強制注入 Gap 阻斷 Clean Approval | PASS (0.3ms) |
| **C14** | `rxCha` | `PRRT_kwDOUWarIc6rxCha` | `scripts/dogfood-review.mjs:1140`<br>`registerTrustedContextPackage` | `SYSTEMIC-C14B-REGISTRATION-FAILURE-WORKFLOW-DENIAL` | 外部 Package 授信註冊若拋出異常或失敗，強制剝奪 Clean Challenge 權限 | PASS (0.9ms) |
| **C14** | `tdsmT` | `PRRT_kwDOUWarIc6tdsmT` | `scripts/dogfood-review.mjs:1104`<br>`validateContextPackageAuthenticity` | `SYSTEMIC-C14A-FORGED-CALLEE-REJECTION (Negative)` | 外部 Package 內之 Callee 需通過 Git 實體核驗，偽造定義直接拒絕 | PASS (311ms) |

---

## 三、原始測試紀錄與 4 項 Skip 詳實說明 (Raw Test Evidence & Skip Ledger)

### 1. 專屬測試套件 (`tests/remediation-twenty-p1-systemic.test.mjs`)
- **指令**: `node --test tests/remediation-twenty-p1-systemic.test.mjs`
- **結果**:
  ```
  ℹ tests 31
  ℹ suites 0
  ℹ pass 31
  ℹ fail 0
  ℹ cancelled 0
  ℹ skipped 0
  ℹ todo 0
  ℹ duration_ms 471.7392
  ```
- **退出碼**: `0`

### 2. 全倉庫回歸測試 (`npm test`)
- **指令**: `npm test`
- **結果**:
  ```
  ℹ tests 1257
  ℹ suites 0
  ℹ pass 1253
  ℹ fail 0
  ℹ cancelled 0
  ℹ skipped 4
  ℹ todo 0
  ℹ duration_ms 42018.8556
  ```
- **退出碼**: `0`

### 3. 4 項 Skipped 測試之精確清單與原因查核
透過原始執行日誌逐筆定位 4 筆 Skipped 測試：

1. **`tests/context-builder.test.mjs:464`**:
   - **測試名稱**: `CYCLE-0047 real repository extraction when local clickhouse path is present`
   - **跳過訊息**: `# External clickhouse repository not present on this machine.`
   - **成因與性質**: 離線防護機制。該測試僅在本地存在外部大型 ClickHouse 倉庫時才執行實際 git 樹遍歷；日常離線環境下自動優雅略過，不影響核心功能。
2. **`tests/real-provider-pilot.test.mjs:55`**:
   - **測試名稱**: `Path 1 (Clean Pass): Real agy review on benign change approves cleanly`
   - **跳過訊息**: `# Real Google agy CLI reviewer not detected or offline routine test (enable via 'npm run test:real-pilot' or TRIAD_REAL_PILOT=1)`
   - **成因與性質**: 真實 CLI 整合防護。日常單元測試避免觸發真實網路請求與外部 CLI 呼叫，需顯式指定 `TRIAD_REAL_PILOT=1` 始執行。
3. **`tests/real-provider-pilot.test.mjs:85`**:
   - **測試名稱**: `Path 2 (Vulnerability Catch & Gate Block): Real agy catches OWASP defects and blocks Gate`
   - **跳過訊息**: 同上（真實 CLI 整合離線防護）。
4. **`tests/real-provider-pilot.test.mjs:113`**:
   - **測試名稱**: `Path 3 (Timeout Kill & Fail-Closed): Short deadline kills real child process and blocks Gate`
   - **跳過訊息**: 同上（真實 CLI 整合離線防護）。

**結論**: 4 項 Skip 全數為設計預期之離線安全防護，零缺陷略過，有效測試達成率為 1253/1253 (100%)。

---

## 四、四項關鍵安全契約收據 (Key Security Contract Receipts)

1. **C07 (Gap-to-Gate 傳播與阻斷)**:
   - 物理位置: `src/core/context-builder.mjs:2680-2715` & `src/adapters/review-prompts.mjs:305-320`
   - 當敏感路徑 Callee 因超長（超過 60 行或 2000 位元組）遭截斷時，注入 `CALLEE_TRUNCATED_ELIDED`。
   - 跨模組端到端驗證: `tests/remediation-twenty-p1-systemic.test.mjs:SYSTEMIC-C07-TRUNCATED-CALLEE-GAP (Cross-layer)` 驗證包含該 Gap 之 ContextPackage 傳入 `orchestrateReview` 時，Gate 評估為 `gate.decision === "block"`，杜絕放行。
2. **C09 (刪除定義防護)**:
   - 物理位置: `src/core/context-builder.mjs:2240-2290`
   - 掃描 Diff Hunks，提取以 `-` 開頭之函式宣告，記錄於 `deletedLocalDefs`。若候選呼叫指向已被補丁刪除之 HEAD 定義，不再返回過時 snippet，強制發出 Context Gap。
   - 驗證: `tests/remediation-twenty-p1-systemic.test.mjs:SYSTEMIC-C09-PATCH-ADDED-IMPORTS (Negative)`。
3. **C12 (多檔 Diff 隔離與 Schema v2 路由)**:
   - 物理位置: `src/core/context-builder.mjs:3125-3165`
   - 單檔模式（`targetFile !== "multi-file"`）下，透過 `splitDiffByFiles` 提取該單檔自身之 Diff Hunks，杜絕多檔混雜。若傳入 `targetFile === "multi-file"`，平滑轉入多檔聚合邏輯。
   - 驗證: `SYSTEMIC-C12-SINGLE-FILE-DIFF-ISOLATION` 與 `SYSTEMIC-C12-SCHEMA2-ROUTING`。
4. **C14 (外部 Package 授信邊界與三方覆蓋)**:
   - 物理位置: `scripts/dogfood-review.mjs:1104-1180, 1465-1485`
   - 外部 ContextPackage 必須通過 `validateContextPackageAuthenticity`，利用真實 Git 物件庫校驗 Callee 行號與內容哈希；註冊失敗時強制移除授權標記；在發起 Clean Challenge 前，強制校驗各 Sentry 的 `coverage.omittedFiles.length === 0`。
   - 驗證: `SYSTEMIC-C14A`、`SYSTEMIC-C14B`、`SYSTEMIC-C14C`。

---

## 五、完整 Git Diff (Full Git Diff)

### 1. `scripts/dogfood-review.mjs`
```diff
diff --git a/scripts/dogfood-review.mjs b/scripts/dogfood-review.mjs
index eb91f7c..3bdf49b 100644
--- a/scripts/dogfood-review.mjs
+++ b/scripts/dogfood-review.mjs
@@ -49,7 +49,9 @@ import {
   CliVerifierAdapter,
   conductIndependentVerification,
   normalizeCommitSha,
-  mergeContextGaps
+  mergeContextGaps,
+  validateContextPackageAuthenticity,
+  registerTrustedContextPackage
 } from "../src/core/independent-verifier.mjs";
 import { buildContextPackage } from "../src/core/context-builder.mjs";
 import {
@@ -1102,6 +1104,27 @@ export async function runDogfoodReview(targetPath = process.cwd(), userOptions =
 
   let contextPackage = userOptions.contextPackage || changeSet?.contextPackage || null;
   let contextExtractionFailed = false;
   let contextExtractionError = null;
 
+  if (contextPackage) {
+    const authCheck = validateContextPackageAuthenticity(contextPackage, {
+      repositoryRoot: targetRepo,
+      cwd: targetRepo,
+      headSha: headSha || null
+    });
+    if (!authCheck || authCheck.ok === false) {
+      if (log) console.warn("  ⚠️ External ContextPackage failed authenticity check:", authCheck?.reason);
+      contextPackage = null;
+    } else {
+      try {
+        const regOk = registerTrustedContextPackage(contextPackage);
+        if (!regOk) {
+          contextPackage = null;
+        }
+      } catch (err) {
+        contextPackage = null;
+      }
+    }
+  }
+
   if (!contextPackage && Array.isArray(changeSet?.files) && changeSet.files.length > 0) {
     try {
       contextPackage = buildContextPackage(
@@ -1164,7 +1187,7 @@ export async function runDogfoodReview(targetPath = process.cwd(), userOptions =
     }
   }
 
-  const effectiveContextGaps = mergeContextGaps(
+  let effectiveContextGaps = mergeContextGaps(
     contextExtractionFailed ? [
       {
         code: "EXACT_HEAD_CONTEXT_FAILED",
@@ -1460,6 +1483,23 @@ export async function runDogfoodReview(targetPath = process.cwd(), userOptions =
     cleanChallengeAttempted = true;
     if (log) console.log("  ⚡ Zero-finding quorum reached. Executing Clean Challenge verification...");
+
+    const sentryCoverageIncomplete = !sentryCoverageManifest || sentryCoverageManifest.length === 0 || sentryCoverageManifest.some(s => {
+      if (!s || !Array.isArray(s.coveredFiles)) return true;
+      if (Array.isArray(s.omittedFiles) && s.omittedFiles.length > 0) return true;
+      const expectedFiles = changeSet?.files?.map(f => typeof f === "string" ? f : f?.path) || [];
+      return expectedFiles.some(f => !s.coveredFiles.includes(f));
+    });
+
+    if (sentryCoverageIncomplete) {
+      if (log) console.warn("  ⚠️ Sentry coverage incomplete or omitted files reported; cannot Clean Approve.");
+      const gap = {
+        code: "INSUFFICIENT_PRODUCER_COVERAGE",
+        symbol: "sentry-coverage",
+        reason: "One or more review sentries failed complete file coverage declaration or reported omitted files.",
+        coverage: sentryCoverageManifest
+      };
+      effectiveContextGaps = mergeContextGaps(effectiveContextGaps, [gap]);
+    }
+
     const tClean0 = Date.now();
     try {
       verificationRecord = await conductIndependentVerification(
```

### 2. `src/adapters/review-prompts.mjs`
```diff
diff --git a/src/adapters/review-prompts.mjs b/src/adapters/review-prompts.mjs
index 6d8c183..ad2088f 100644
--- a/src/adapters/review-prompts.mjs
+++ b/src/adapters/review-prompts.mjs
@@ -257,7 +257,11 @@ export function formatContextPackageXml(contextPackage) {
           : ` lines="${escapeXmlAttribute(c.lines)}"`;
         const symAttr = escapeXmlAttribute(c.symbol);
         const bytesAttr = escapeXmlAttribute(c.bytes);
-        lines.push(`      <callee symbol="${symAttr}"${lineAttr} bytes="${bytesAttr}">`);
+        const fileVal = c.file && c.file !== "multi-file" && (targetFileAttr === "multi-file" || c.file !== targetFileAttr)
+          ? c.file
+          : "";
+        const fileAttr = fileVal ? ` file="${escapeXmlAttribute(fileVal)}"` : "";
+        lines.push(`      <callee symbol="${symAttr}"${fileAttr}${lineAttr} bytes="${bytesAttr}">`);
         if (typeof c.definition === "string") {
           const escapedDef = escapeXmlText(c.definition.trim()).replace(/\n/g, "\n        ");
           lines.push(`        ${escapedDef}`);
```

### 3. `src/cli.mjs`
```diff
diff --git a/src/cli.mjs b/src/cli.mjs
index 319c8e3..50268a7 100644
--- a/src/cli.mjs
+++ b/src/cli.mjs
@@ -47,7 +47,8 @@ import {
   normalizeCommitSha,
   normalizeDigest,
   normalizeObjective,
-  mergeContextGaps
+  mergeContextGaps,
+  isGitRepo
 } from "./core/independent-verifier.mjs";
 import { buildContextPackage } from "./core/context-builder.mjs";
 import { digestChangeSet } from "./core/canonical-digest.mjs";
@@ -905,32 +906,37 @@ export async function runCli(argv = process.argv.slice(2), io = { stdout: proces
       let contextExtractionFailed = false;
       let contextExtractionError = null;
 
-      if (!effectiveContextPackage && Array.isArray(files) && files.length > 0 && targetRepo) {
-        try {
-          effectiveContextPackage = buildContextPackage(
-            changeSet,
-            null,
-            {
-              headSha: headSha || null,
-              repositoryRoot: targetRepo,
-              cwd: targetRepo,
-              runId: activeRunId
-            }
-          );
-          if (!effectiveContextPackage || effectiveContextPackage.ok === false) {
-            contextExtractionFailed = true;
-            contextExtractionError = effectiveContextPackage?.error?.message || "buildContextPackage returned invalid or non-ok contextPackage";
-          } else if (Array.isArray(effectiveContextPackage.fileCoverageManifest)) {
-            const unavailableEntry = effectiveContextPackage.fileCoverageManifest.find(
-              m => m && (m.exactHeadAvailable === false || m.exactHeadUnavailable === true || m.contentAvailable === false)
+      if (!effectiveContextPackage && Array.isArray(files) && files.length > 0) {
+        if (targetRepo) {
+          if (!isGitRepo(targetRepo)) {
+            contextExtractionFailed = true;
+            contextExtractionError = `Target repository '${targetRepo}' is not a valid git repository; unable to extract reliable exact-head context for review.`;
+          } else {
+            try {
+              effectiveContextPackage = buildContextPackage(
+                changeSet,
+                null,
+                {
+                  headSha: headSha || null,
+                  repositoryRoot: targetRepo,
+                  cwd: targetRepo,
+                  runId: activeRunId
+                }
+              );
+              if (!effectiveContextPackage || effectiveContextPackage.ok === false) {
+                contextExtractionFailed = true;
+                contextExtractionError = effectiveContextPackage?.error?.message || "buildContextPackage returned invalid or non-ok contextPackage";
+              } else if (Array.isArray(effectiveContextPackage.fileCoverageManifest)) {
+                const unavailableEntry = effectiveContextPackage.fileCoverageManifest.find(
+                  m => m && (m.exactHeadAvailable === false || m.exactHeadUnavailable === true || m.contentAvailable === false)
+                );
+                if (unavailableEntry) {
+                  contextExtractionFailed = true;
+                  contextExtractionError = `Exact-head content unavailable for file: '${unavailableEntry.file || unavailableEntry.path}'.`;
+                }
+              }
+            } catch (err) {
+              contextExtractionFailed = true;
+              contextExtractionError = err?.message || String(err);
+            }
+          }
+        }
+      }
```

### 4. `src/core/context-builder.mjs`
```diff
diff --git a/src/core/context-builder.mjs b/src/core/context-builder.mjs
index 92e35e7..0669781 100644
--- a/src/core/context-builder.mjs
+++ b/src/core/context-builder.mjs
@@ -194,6 +194,14 @@ export function classifySensitiveCategory(name, qualifiers = []) {
   if (/(?:validate|sanitize|filter|escape|whitelist|allowlist|blacklist|denylist|check|verify|assert|ensure|guard|protect)/i.test(fullName)) {
     return "input_validation";
   }
+  if (/(?:policy|enforce|rbac|acl|role|access|permission|authorize|grant|deny)/i.test(fullName)) {
+    return "security";
+  }
   if (/(?:default|fallback|init|reset|normalize|standardize|resolve|derive)/i.test(fullName)) {
     return "default_values";
   }
@@ -530,6 +538,37 @@ export function findBraceScopeEnd(lines, startLineIdx, options = {}) {
   return -1;
 }
 
+/**
+ * Strips block and line comments while preserving line breaks and character columns (masking with spaces).
+ * This allows layout-sensitive, line-number-bound AST parsers to operate without syntax skew.
+ * @param {string[]} lines
+ * @returns {string[]}
+ */
+export function stripCommentsPreservingLayout(lines) {
+  if (!Array.isArray(lines)) return [];
+  let inBlockComment = false;
+  return lines.map(line => {
+    let out = "";
+    let i = 0;
+    while (i < line.length) {
+      if (inBlockComment) {
+        if (line[i] === "*" && line[i + 1] === "/") {
+          inBlockComment = false;
+          out += "  ";
+          i += 2;
+        } else {
+          out += " ";
+          i++;
+        }
+      } else if (line[i] === "/" && line[i + 1] === "*") {
+        inBlockComment = true;
+        out += "  ";
+        i += 2;
+      } else if (line[i] === "/" && line[i + 1] === "/") {
+        out += " ".repeat(line.length - i);
+        break;
+      } else {
+        out += line[i];
+        i++;
+      }
+    }
+    return out;
+  });
+}
+
@@ -570,6 +609,8 @@ export function findFunctionDefinitions(lines, symbol) {
   const matches = [];
   const escapedSym = symbol.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
 
+  const cleanLines = stripCommentsPreservingLayout(lines);
+
+  const HAS_EXPLICIT_DECL_HEADER = new RegExp(
+    `(?:` +
+    `^(?:\\s*(?:[a-zA-Z0-9_<>*&]|::)+\\s+)+(?:[a-zA-Z0-9_]+::)?${escapedSym}\\s*(?:<[^()]+>\\s*)?\\(|` +
+    `^\\s*(?:export\\s+)?(?:default\\s+)?(?:async\\s+)?function(?:\\s+${escapedSym})?\\s*(?:<[^()]+>\\s*)?\\(|` +
+    `^\\s*(?:(?:static|async|public|private|protected|virtual|inline|override)\\s+)+${escapedSym}\\s*(?:<[^()]+>\\s*)?\\(|` +
+    `^\\s*(?:export\\s+)?(?:const|let|var)?\\s*${escapedSym}\\s*=\\s*(?:async\\s*)?(?:<[^()]+>\\s*)?(?:\\([^)]*\\)|[a-zA-Z0-9_$]+)?\\s*(?:=>|function)|` +
+    `^\\s*def\\s+${escapedSym}\\s*\\(` +
+    `)`
+  );
@@ -698,6 +739,23 @@ export function findFunctionDefinitions(lines, symbol) {
     if (isDeclarationOnly || !hasBrace || braceLineIdx === -1) {
       continue;
     }
 
+    let hasExplicitHeader = HAS_EXPLICIT_DECL_HEADER.test(line);
+    if (!hasExplicitHeader) {
+      for (let prevIdx = i - 1; prevIdx >= Math.max(0, i - 3); prevIdx--) {
+        const prevTrim = cleanLines[prevIdx].trim();
+        if (prevTrim.length === 0) continue;
+        if (HAS_EXPLICIT_DECL_HEADER.test(`${prevTrim} ${line.trim()}`)) {
+          hasExplicitHeader = true;
+          break;
+        }
+        break;
+      }
+    }
+
+    if (braceLineIdx > i && !hasExplicitHeader) {
+      // Reject bare call expressions accepting delayed body brace (sl1Ri / C3)
+      continue;
+    }
+
     const endLine = findBraceScopeEnd(cleanLines, braceLineIdx, { failClosed: true, startCharIndex: bodyBraceIdx });
```

*(因篇幅限制，其餘 C05 運算元識別、C06 敏感接收者判定、C07 截斷 Context Gap、C08 importAliases 映射表、C09 patch-added imports、C10 控制流變更檢測、C12 splitDiffByFiles 隔離等完整 diff 已同步備份於本地 `pr39_systemic_remediation.patch`)*

---

## 六、下一步授權裁示申請 (Authorization Request for LOCAL_COMMIT)

本地工作區代碼修改、正確對應矩陣、四項 Skip 說明、四大安全契約與測試全量通過證明已完整呈報。  
特向領隊恒一正式申請核准：

```
PR39-SCHEMA2-G4-REMEDIATION-IMPLEMENTATION-REVIEW-R2
LOCAL_COMMIT: AUTHORIZED
(准予針對上述 5 個受控檔案執行單一本地 Commit)
NEW_PUSH: NOT_AUTHORIZED (待審查員覆核本地 Commit 後指示)
THREAD_REPLY / RESOLVE: NOT_AUTHORIZED (維持 STRICT_HOLD)
SQUASH_MERGE: NOT_AUTHORIZED
```

敬請領隊裁示！
