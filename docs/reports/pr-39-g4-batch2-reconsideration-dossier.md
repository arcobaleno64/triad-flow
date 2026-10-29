# PR-39 G4 Batch 2 解鎖覆核卷宗 (Reconsideration Dossier)

- **目標 PR**: [arcobaleno64/triad-flow#39](https://github.com/arcobaleno64/triad-flow/pull/39)
- **基準 Commit HEAD**: `ec750e6010edd8d6f3fb8007a59994644b98862c`
- **參照裁定**: `PR39-SCHEMA2-G4-BATCH2-REVIEW-R1`
- **治理狀態**:
  - `ra7kM`: **已完成交易式關閉**（Comment ID: `PRRC_kwDOUWarIc8AAAABBU03VA` / DB ID `4383913812`，`isResolved: true`）
  - `rfkYi`、`rr-I6`: **維持 STRICT_HOLD**（確認為實質開源缺陷，不在此次申請解鎖）
  - `rVNc6`、`rrHOc`、`tgXSH`、`tgXSI`: **依審查員第六節解鎖條件提交精準反證與受控測試證據**

---

## 一、審查員解鎖條件逐項對照與受控驗證結果

### 1. Thread `rVNc6` (GraphQL ID: `PRRT_kwDOUWarIc6rVNc6`)
- **檔案位置**: `src/core/context-builder.mjs:1767`
- **問題本質**: 首次呼叫非敏感，隨後在安全敏感條件中重複呼叫時，敏感屬性升級。
- **審查員解鎖條件**:
  > 「補測首次非敏感的 `helper()`，隨後在安全敏感條件中再次呼叫，證明 `isSensitive` 從 `false` 升為 `true`。」
- **物理程式碼錨點**: `src/core/context-builder.mjs:1808-1811`
  ```javascript
  if (isSensitive && !existing.isSensitive) {
    existing.isSensitive = true;
    existing.category = symCategory;
  }
  ```
- **受控測試與反證結果**:
  - **基準驗證 (1A)**: 當只有 `const normal = helper(data);` 時，`helper` 不含敏感關鍵字：
    * `isSensitive`: `false`
    * `category`: `null`
  - **升級驗證 (1B)**: 當緊隨其後出現 `if (!helper(data)) throw new Error("security check failed");` 防衛行：
    * `isSensitive`: 從 `false` 升級為 `true`
    * `category`: 從 `null` 升級為 `"input_validation"`
  - **結論**: 程式碼在 HEAD `ec750e60...` 物理具備且正確執行該升級邏輯。

---

### 2. Thread `rrHOc` (GraphQL ID: `PRRT_kwDOUWarIc6rrHOc`)
- **檔案位置**: `src/core/context-builder.mjs:3020` (HEAD: 2782-2788, 3125-3134)
- **問題本質**: Single-file 模式收到 multi-file ChangeSet 時的 Diff 與 Callee 污染防護。
- **審查員解鎖條件**:
  > 「以多檔 ChangeSet 呼叫 single-file 模式，證明其他檔案的呼叫不會污染目標檔案；或者證明該輸出必定被後續授信閘門拒絕。」
- **物理程式碼與授信閘門雙重防線**:
  - **防線 1 (Producer Gate, Schema v2 規範 §2.4)**: `src/core/context-builder.mjs:2782-2788`
    ```javascript
    } else if (normalizedFiles.length > 1) {
      if (targetFile !== "multi-file") {
        const err = new Error(`Mutual exclusion violation: multi-file ChangeSet requires targetFile: 'multi-file', got '${targetFile}'`);
        err.code = "MUTUAL_EXCLUSION_VIOLATION";
        throw err;
      }
    }
    ```
    當 ChangeSet 為多檔時，若以單檔呼叫 `buildContextPackage`，直接拋出 `MUTUAL_EXCLUSION_VIOLATION`，物理阻斷單檔模式在多檔變更下的產出。
  - **防線 2 (Verifier Gate, 互斥性嚴格核驗)**: `src/core/independent-verifier.mjs:407-426` (`evaluateContextPackageBinding`)
    若向獨立驗證器提供單檔 ContextPackage 配對多檔 ChangeSet，驗證器即刻拒絕：
    * `bound`: `false`
    * `reason`: `"MUTUAL_EXCLUSION_VIOLATION"`
  - **防線 3 (Registry Gate, 註冊拒絕)**: `registerTrustedContextPackage` 收到上述綁定失敗，即刻回傳 `null`，阻斷所有下游利用。
  - **結論**: 多檔 Diff 污染單檔模式之路徑已被 Schema v2 互斥規範自來源與下游閘門徹底封死。

---

### 3. Thread `tgXSH` (GraphQL ID: `PRRT_kwDOUWarIc6tgXSH`)
- **檔案位置**: `src/adapters/staged-review.mjs:600` (HEAD: 592-613)
- **問題本質**: Staged Review 在接收外部傳入的 ContextPackage 時，必須核驗實體來源物理背書，拒絕偽造 Callee。
- **審查員解鎖條件**:
  > 「建立 HEAD、Digest、Manifest 均匹配，但 Callee 定義偽造的負向測試，確認 staged review 不接受未經物理來源核驗的 ContextPackage。」
- **物理程式碼錨點**:
  - `src/core/independent-verifier.mjs:990-1045`: `validateContextPackageAuthenticity` 逐一提取 Git 實體物件內容核對 Callee 程式碼片段與行號範疇。
  - `src/adapters/staged-review.mjs:592-613`:
    ```javascript
    let isCallerContextTrusted = isCallerContextObject && isTrustedContextPackage(callerContextPackage);
    if (!isCallerContextTrusted && isCallerContextObject && !isCallerContextPoisoned && !isCallerContextBindingMismatch) {
      try {
        const verified = registerTrustedContextPackage(callerContextPackage, { ... });
        if (verified) isCallerContextTrusted = true;
      } catch {}
    }
    const hasValidCallerContext = ... && isCallerContextTrusted;
    ```
- **受控測試與反證結果**:
  - 構造 HEAD、Digest、Manifest 全數合法匹配之 ContextPackage，但在 `layer1AstEnclosure.callees` 中注入偽造函式宣告 `function forgedFunction() { evilBackdoorPayload(); }`。
  - **註冊閘門**: `registerTrustedContextPackage` 核對真實 Git 物件後判定代碼片段不存在，拒絕授信回傳 `null`；`isTrustedContextPackage(forgedPkg)` 保持 `false`。
  - **Staged Review 閘門**: `executeStagedReview` 執行時，檢驗 `isCallerContextTrusted === false`，徹底拒絕採用該 Package（`resolvedContextPackage !== forgedPkg`），成功阻斷未經物理來源核驗之 ContextPackage 重用。

---

### 4. Thread `tgXSI` (GraphQL ID: `PRRT_kwDOUWarIc6tgXSI`)
- **檔案位置**: `src/core/independent-verifier.mjs:801` (HEAD: 735-772)
- **問題本質**: 獨立驗證器必須對 Callee 及 Enclosure 實施 Manifest 全域覆蓋校驗，拒絕 Manifest 外注入。
- **審查員解鎖條件**:
  > 「建立 Manifest 外 Callee／Enclosure 偽造案例，證明 `registerTrustedContextPackage` 拒絕註責，且下游 Verifier 無法取得偽造內容。」
- **物理程式碼錨點**: `src/core/independent-verifier.mjs:735-772`
  ```javascript
  // tgXSI: Manifest Global Coverage Verification
  const manifestMap = new Map();
  for (const entry of pkg.fileCoverageManifest) {
    manifestMap.set(normalizeCanonicalPath(entry.file), entry);
  }
  // All callees, enclosing functions, and scope fragments in layer1AstEnclosure
  // must map to a manifest entry that physically exists with exactHeadAvailable === true.
  for (const callee of layer1.callees) {
    const calleeFile = getEnclosureFile(callee);
    if (!calleeFile) return false;
    const manifestEntry = manifestMap.get(calleeFile);
    if (!manifestEntry || manifestEntry.exactHeadAvailable !== true || manifestEntry.exactHeadUnavailable === true) {
      return false;
    }
  }
  ```
- **受控測試與反證結果**:
  - 構造 Manifest 合法，但在 `callees` 中包含未列於 Manifest 之外部檔案 `src/secret/admin.mjs`。
  - **真實性核驗**: `validateContextPackageAuthenticity` 觸發 Manifest 映射失敗，回傳 `false`。
  - **註冊授權**: `registerTrustedContextPackage` 拒絕註冊回傳 `null`；`isTrustedContextPackage` 回傳 `false`。
  - **下游阻斷**: 任何要求授信 ContextPackage 之驗證流程皆無法取得或採用此偽造內容。

---

## 二、受控驗證測試執行記錄 (Test Runner Execution Receipt)

執行指令：
```bash
node scratch/test_batch2_unlock.mjs
```

完整終端輸出：
```text
================================================================================
PR-39 G4 BATCH 2 UNLOCK VERIFICATION RUNNER
Commit HEAD: ec750e6010edd8d6f3fb8007a59994644b98862c
Repository Root: C:\Users\arcobaleno\Documents\Code\triad-flow
================================================================================

>>> [1/4] Thread rVNc6: Sensitivity Upgrade on Repeated Added Call Site
  [1A Baseline] helper(data) initially non-sensitive: isSensitive = false, category = null (CONFIRMED)
  [1B Upgrade] Repeated helper(data) on guard line: isSensitive = true, category = 'input_validation' (CONFIRMED)
  [1C Code Invariant] src/core/context-builder.mjs:1808-1811 correctly upgrades existing.isSensitive

>>> [2/4] Thread rrHOc: Single-File Mode Isolation and Gate Rejection
  [2A Producer Gate] buildContextPackage threw: MUTUAL_EXCLUSION_VIOLATION (Mutual exclusion violation: multi-file ChangeSet requires targetFile: 'multi-file', got 'src/fileA.mjs') (CONFIRMED)
  [2B Verifier Gate] evaluateContextPackageBinding returned: bound=false, reason='MUTUAL_EXCLUSION_VIOLATION' (CONFIRMED)
  [2C Registry Gate] registerTrustedContextPackage returned: null (Registration Refused) (CONFIRMED)

>>> [3/4] Thread tgXSH: Staged Review Rejection of Forged Callee Snippet
  [3A Direct Registration] registerTrustedContextPackage returned: null (CONFIRMED)
  [3B Staged Review Gate] executeStagedReview resolvedContextPackage !== forgedPkg (Reused Refused) (CONFIRMED)

>>> [4/4] Thread tgXSI: Rejection of Out-of-Manifest Callee / Enclosure
  [4A Authenticity Gate] validateContextPackageAuthenticity returned: false (CONFIRMED)
  [4B Registry Gate] registerTrustedContextPackage returned: null (Registration Refused) (CONFIRMED)
  [4C Verifier Invariant] Downstream verifiers unable to obtain or trust forged out-of-manifest content (CONFIRMED)

================================================================================
ALL 4 UNLOCK CONDITIONS RIGOROUSLY VERIFIED UNDER HEAD ec750e6010edd8d6f3fb8007a59994644b98862c
================================================================================
```

---

## 三、申請授權標的與預擬回覆內容

在此正式向審查員申請解鎖覆核裁定（`PR39-SCHEMA2-G4-BATCH2-REVIEW-R2`）：

| Thread | shortId | 當前狀態 | 申請授權 | 備註 |
|---|---|---|---|---|
| `PRRT_kwDOUWarIc6rVNc6` | `rVNc6` | HOLD | AUTHORIZED | 解鎖條件 1 驗證通過 |
| `PRRT_kwDOUWarIc6rrHOc` | `rrHOc` | HOLD | AUTHORIZED | 解鎖條件 2 驗證通過 |
| `PRRT_kwDOUWarIc6tgXSH` | `tgXSH` | HOLD | AUTHORIZED | 解鎖條件 3 驗證通過 |
| `PRRT_kwDOUWarIc6tgXSI` | `tgXSI` | HOLD | AUTHORIZED | 解鎖條件 4 驗證通過 |
| `PRRT_kwDOUWarIc6rfkYi` | `rfkYi` | HOLD | STRICT_HOLD (不申請) | 維持 OPEN_DEFECT |
| `PRRT_kwDOUWarIc6rr-I6` | `rr-I6` | HOLD | STRICT_HOLD (不申請) | 維持 OPEN_DEFECT |

### 預擬回覆文字

#### 1. `rVNc6` (`PRRT_kwDOUWarIc6rVNc6`)
```markdown
Addressed in `src/core/context-builder.mjs:1808-1811`, present in HEAD `ec750e6010edd8d6f3fb8007a59994644b98862c`.

Repeated candidate call symbols encountering subsequent sensitive or guard contexts upgrade `existing.isSensitive = true` and adopt the sensitive category (`input_validation`).

Verified under controlled test: baseline call `helper(data)` initially registers with `isSensitive: false`, and subsequent appearance on `if (!helper(data)) throw ...` correctly upgrades the candidate to `isSensitive: true` with category `"input_validation"`.
```

#### 2. `rrHOc` (`PRRT_kwDOUWarIc6rrHOc`)
```markdown
Addressed under Schema v2 targetFile mutual exclusion (§2.4) in `src/core/context-builder.mjs:2782-2788` and `src/core/independent-verifier.mjs:407-426`, present in HEAD `ec750e6010edd8d6f3fb8007a59994644b98862c`.

Multi-file diff cross-contamination into single-file extraction is structurally blocked:
1. `buildContextPackage` in Schema v2 throws `MUTUAL_EXCLUSION_VIOLATION` if single-file mode is invoked on a multi-file ChangeSet.
2. Downstream verifier `evaluateContextPackageBinding` rejects single-file packages paired with multi-file ChangeSets (`bound: false`, `reason: 'MUTUAL_EXCLUSION_VIOLATION'`), and `registerTrustedContextPackage` returns `null`.
3. In multi-file mode, `splitDiffByFiles` strictly isolates diff hunks per file (`src/core/context-builder.mjs:2809, 2833-2835`).
```

#### 3. `tgXSH` (`PRRT_kwDOUWarIc6tgXSH`)
```markdown
Addressed in `src/adapters/staged-review.mjs:592-613` and `src/core/independent-verifier.mjs:990-1045`, present in HEAD `ec750e6010edd8d6f3fb8007a59994644b98862c`.

Caller context packages supplied to staged review must establish authentic provenance via `isTrustedContextPackage` or successful registration through `registerTrustedContextPackage`.

Negative test verified: packages declaring valid headSha, source digests, and manifests with forged callee snippets are rejected by `validateContextPackageAuthenticity` against authentic Git objects, return `null` from `registerTrustedContextPackage`, and `executeStagedReview` refuses reuse (`resolvedContextPackage !== forgedPkg`).
```

#### 4. `tgXSI` (`PRRT_kwDOUWarIc6tgXSI`)
```markdown
Addressed in `src/core/independent-verifier.mjs:735-772`, present in HEAD `ec750e6010edd8d6f3fb8007a59994644b98862c`.

Schema v2 enforces global manifest coverage across all callees and AST enclosures. Every callee, enclosing function, and class in `layer1AstEnclosure` must resolve to an entry in `fileCoverageManifest` with `exactHeadAvailable === true`.

Negative test verified: context packages containing out-of-manifest callees or enclosures fail `validateContextPackageAuthenticity`, `registerTrustedContextPackage` returns `null`, and downstream verifiers cannot verify or trust the package.
```
