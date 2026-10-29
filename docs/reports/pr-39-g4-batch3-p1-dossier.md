# PR #39 G4 Batch 3 P1 審查卷宗與技術核驗 (Batch 3 P1 Dossier)

**審查日期**: 2026-10-27  
**專案儲存庫**: `arcobaleno64/triad-flow`  
**目標 PR**: [PR #39 (`fix/remediation-007-clean-challenge`)](https://github.com/arcobaleno64/triad-flow/pull/39)  
**目標 Commit HEAD**: `ec750e6010edd8d6f3fb8007a59994644b98862c`  
**治理基準**:
- `PR39-SCHEMA2-G4-PILOT-FIVE-REVIEW-R1` (已執行完成)
- `PR39-SCHEMA2-G4-BATCH2-REVIEW-R1` (已裁定)
- `PR39-SCHEMA2-G4-BATCH2-REVIEW-R2` (已裁定並完成交易式關閉)
**治理進程**: G1 (PASS) $\to$ G2 (PASS) $\to$ G3 (PASS) $\to$ G4 (Batch 1: 5 已關閉；Batch 2: 4 已關閉；目前累計 20 則已關閉)

---

## 一、執行摘要與母體狀態 (Population State)

依據專案治理守則、非通關推定（Default-Deny / Presumption of Non-Pass）以及異議義務（Obligation of Dissent），本批次對 PR #39 當前（Current）P1 討論串進行物理代碼與測試驗證。

### 母體統計現況 (母體總數：180 則)
- **已關閉 (Resolved)**: **20 則** (11.11%)
  * Pilot Five 初始 (5 則): `qo0uf`, `qo0uL`, `qwj-8`, `rTow7`, `rVNcE`
  * Six P1s (6 則): `qo0uA`, `qo0uB`, `qwj_u`, `rTowz`, `rVNc4`, `ra7kN`
  * Pilot Five 當前 P1 (5 則): `qo0uT`, `qo0uc`, `qwj_y`, `rTowu`, `rVNc5`
  * Batch 2 (4 則): `ra7kM` (R1), `rVNc6` (R2), `tgXSH` (R2), `tgXSI` (R2)
- **未關閉 (Unresolved)**: **160 則** (88.89%)
  * **P1 討論串 (113 則)**:
    - **Current (當前有效, 25 則)**:
      * **本批次驗證修復候選 (5 則)**: `rr-I-`, `sl1Ri`, `rte6j`, `slqmB`, `tdsmP`（申請 G4-B 授權）
      * **實質開源缺陷維持 STRICT_HOLD (7 則)**: `rrHOc` (待後續多檔實體驗證), `rfkYi` (開源缺陷), `rr-I6` (開源缺陷), `rsKCC` (開源缺陷), `rsajc` (開源缺陷), `r1BuI` (開源缺陷), `slAM6` (開源缺陷)
      * **待後續分批審查 Current P1 (13 則)**: `rr-JC`, `rte6o`, `rte6z`, `rvCBT`, `rvCBW`, `rvWjO`, `rxCha`, `r1BuC`, `slAMv`, `slLWg`, `slLWi`, `tdsmT`, `tm8Kn`
    - **Outdated (歷史過期, 88 則)**: 維持 `STRICT_HOLD`
  * **P2 討論串 (47 則)**:
    - **Current (26 則)**: 維持 `STRICT_HOLD`
    - **Outdated (21 則)**: 維持 `STRICT_HOLD`

---

## 二、Batch 3 候選討論串物理代碼審查與測試驗證 (申請關閉)

本批次針對 5 則已在 Commit HEAD `ec750e6010edd8d6f3fb8007a59994644b98862c` 具備物理修復與單元測試之 Current P1 討論串提出關閉申請：

### Batch 3 申請核准對照表

| 序號 | Short ID | Thread ID (GraphQL) | 嚴重度 | 檔案位置 | 物理審查狀態 | 申請裁定 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `rr-I-` | `PRRT_kwDOUWarIc6rr-I-` | P1 | `src/core/context-builder.mjs:1428` | **FIXED_VERIFIED** | **REQUEST_AUTHORIZATION** |
| 2 | `sl1Ri` | `PRRT_kwDOUWarIc6sl1Ri` | P1 | `src/core/context-builder.mjs:551` | **FIXED_VERIFIED** | **REQUEST_AUTHORIZATION** |
| 3 | `rte6j` | `PRRT_kwDOUWarIc6rte6j` | P1 | `src/core/harness.mjs:1249` | **FIXED_VERIFIED** | **REQUEST_AUTHORIZATION** |
| 4 | `slqmB` | `PRRT_kwDOUWarIc6slqmB` | P1 | `src/adapters/review-orchestrator.mjs:495` | **FIXED_VERIFIED** | **REQUEST_AUTHORIZATION** |
| 5 | `tdsmP` | `PRRT_kwDOUWarIc6tdsmP` | P1 | `src/cli.mjs:1090` | **FIXED_VERIFIED** | **REQUEST_AUTHORIZATION** |

---

### 詳細技術分析與驗證證據

#### 1. Thread `rr-I-` (`PRRT_kwDOUWarIc6rr-I-`)
- **審查員關注點**: Template literals (`${...}`) 內部的表達式未被掃描。例如在 `const label = `${validateAccess(user)}`;` 中，`validateAccess` 呼叫未被識別為 candidate call symbol，導致敏感呼叫漏失。
- **物理代碼錨點**: `src/core/context-builder.mjs:1427-1455`
  ```javascript
  // Extract expressions within template literal interpolation `${...}`
  const templateInterpolationRegex = /\$\{([^}]+)\}/g;
  let tplMatch;
  while ((tplMatch = templateInterpolationRegex.exec(cleanLine)) !== null) {
    const expr = tplMatch[1];
    // Recursively extract call symbols within interpolation expressions
    const exprSymbols = extractCallSymbolsFromExpression(expr, lineNum, isAdded);
    for (const sym of exprSymbols) {
      candidates.push(sym);
    }
  }
  ```
- **確定性測試佐證**:
  - `tests/remediation-four-threads-tm8.test.mjs`
  - `scratch/test_batch3_verification.mjs:18-29`:
    輸入 `+ const label = \`\${validateAccess(user)}\`;`，成功提取 `symbol: "validateAccess"`，確認 `isSensitive: true`，`category: "input_validation"`。
- **裁定請求**: 授權回覆並標記關閉。

---

#### 2. Thread `sl1Ri` (`PRRT_kwDOUWarIc6sl1Ri`)
- **審查員關注點**: `findFunctionDefinitions` 在遇到換行的函式定義時，若遇到非函式宣告的裸呼叫表達式後接換行的大括號 `{`，會誤將該括號視為該呼叫的函式主體，形成偽函式圍欄。
- **物理代碼錨點**: `src/core/context-builder.mjs:577-606`
  ```javascript
  // Validate delayed body brace: only genuine function/method headers can accept delayed brace
  if (pendingDelayedBrace) {
    const isHeaderValid = FUNCTION_DECL_PATTERNS.some(p => p.test(pendingDelayedBrace.headerLine));
    if (!isHeaderValid || isBareCallExpression(pendingDelayedBrace.headerLine)) {
      pendingDelayedBrace = null; // Strictly reject bare call expressions preceding delayed brace
    }
  }
  ```
- **確定性測試佐證**:
  - `tests/remediation-007-clean-challenge.test.mjs:1740-1790` (`007-AUDIT-THREAD-28`)
  - `scratch/test_batch3_verification.mjs:34-55`:
    輸入 `validateAccess(user)\nchainedCallback()\n{\n fakeBody();\n}`，嚴格返回 0 definitions（拒絕偽函式）；輸入合法宣告 `function validateAccess(user)\n{\n return user.isAdmin;\n}`，正常返回 1 definition。
- **裁定請求**: 授權回覆並標記關閉。

---

#### 3. Thread `rte6j` (`PRRT_kwDOUWarIc6rte6j`)
- **審查員關注點**: 獨立驗證器回報遺漏項時，若提出 `evidenceSupport: "CONTESTED"` 但未提供實質根據（ungrounded reasoning），可能導致安全審查被空泛辯解繞過。
- **物理代碼錨點**: `src/core/harness.mjs:1246-1265` & `src/core/independent-verifier.mjs:2530-2548`
  ```javascript
  if (omission.evidenceSupport === "CONTESTED") {
    const isGrounded = hasSubstantiveReasoning(omission.reasoning, omission.file, changeSet);
    if (!isGrounded) {
      // Ungrounded CONTESTED omissions automatically downgrade to INSUFFICIENT_EVIDENCE
      omission.evidenceSupport = "INSUFFICIENT_EVIDENCE";
    }
  }
  ```
- **確定性測試佐證**:
  - `tests/remediation-phase3-orchestrator-cli.test.mjs` (`PR39-GATE-OUT-07-NEGATIVE` / `PR39-ROUND2-ITEM4-NEGATIVE`)
  - `scratch/test_batch3_verification.mjs:60-97`:
    當 CONTESTED 遺漏項給出非實質理由（"The parameter is safe."）時，`validateVerificationOutput` 自動將其降級為 `INSUFFICIENT_EVIDENCE`，阻斷無實體依據之抗辯。
- **裁定請求**: 授權回覆並標記關閉。

---

#### 4. Thread `slqmB` (`PRRT_kwDOUWarIc6slqmB`)
- **審查員關注點**: `orchestrateReview` 曾允許外部傳入 `tier: null`、`tier: 0` 或 `isTier1: false` 覆蓋實體檢測到的 Tier 1 風險，規避雙崗哨 Quorum 及審查要求。
- **物理代碼錨點**: `src/adapters/review-orchestrator.mjs:470-488`
  ```javascript
  // Downgrade check: if diff is Tier 1, cannot downgrade to > 1 or override isTier1: false
  const isDowngraded = (authoritativeScale.highestRisk === 1 && (
    (parsedTier !== undefined && parsedTier > 1) ||
    options.isTier1 === false ||
    parsedTier === 0 ||
    parsedTier === null
  )) || isPlanConflict;

  if (isIllegalTier || isDowngraded) {
    return {
      runId,
      status: "incomplete",
      plan,
      consensus: null,
      gate: {
        decision: "block",
        reason: "Gate Fail-Closed: Invalid or downgraded risk tier (INVALID_OR_DOWNGRADED_TIER)."
      },
      reports: {}
    };
  }
  ```
- **確定性測試佐證**:
  - `tests/remediation-phase3-orchestrator-cli.test.mjs:180-250` (`PHASE3-NEG-04-01..06`)
  - `scratch/test_batch3_verification.mjs:102-127`:
    對 Tier 1 ChangeSet 傳入 `tier: null`，`orchestrateReview` 立即 Fail-Closed：`gate.decision: "block"`，`reason: "...INVALID_OR_DOWNGRADED_TIER"`, `status: "incomplete"`。
- **裁定請求**: 授權回覆並標記關閉。

---

#### 5. Thread `tdsmP` (`PRRT_kwDOUWarIc6tdsmP`)
- **審查員關注點**: CLI 在執行 Clean Challenge 初步審查前，未先綁定 exact-head 建立授信 `contextPackage`，可能導致初步審查與後續驗證採用不一致的上下文。
- **物理代碼錨點**: `src/cli.mjs:885-956, 1087-1106`
  ```javascript
  // Establish authoritative contextPackage and contextGaps prior to preliminary review (tdsmP)
  const activeRunId = options.runId || crypto.randomUUID();
  const headSha = normalizeCommitSha(...);
  let effectiveContextPackage = options.contextPackage || changeSet?.contextPackage || null;

  if (!effectiveContextPackage && Array.isArray(files) && files.length > 0 && targetRepo) {
    effectiveContextPackage = buildContextPackage(changeSet, null, {
      headSha: headSha || null,
      repositoryRoot: targetRepo,
      cwd: targetRepo,
      runId: activeRunId
    });
  }
  // Passed directly into orchestrateReview before preliminary review execution
  ```
- **確定性測試佐證**:
  - `tests/remediation-phase3-orchestrator-cli.test.mjs:550-644` (`PHASE3-POS-01-01..03`)
  - `scratch/test_batch3_verification.mjs:132-165`:
    CLI 執行時，在 Preliminary Review 啟動前即建立綁定 `headSha: "ec750e6010edd8d6f3fb8007a59994644b98862c"` 之 `contextPackage` 並注入執行參數。
- **裁定請求**: 授權回覆並標記關閉。

---

## 三、實質開源缺陷揭露與異議（Dissent Obligation -> STRICT_HOLD）

依據異議義務與 Default-Deny 原則，審查過程中發現以下 4 則 Current P1 討論串在 HEAD `ec750e60...` 仍存在未修復的技術缺陷，**主動維持 `STRICT_HOLD`，嚴禁擅自回覆或關閉**：

### 實質開源缺陷清單 (STRICT_HOLD)

| Short ID | Thread ID (GraphQL) | 嚴重度 | 檔案位置 | 實質技術缺陷描述 | 處置動作 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `rsKCC` | `PRRT_kwDOUWarIc6rsKCC` | P1 | `src/core/context-builder.mjs:2396-2410` | 敏感被呼叫者函式體遭省略（`signature_and_guards`）時，直接放入 `callees`，未標記為 `unresolvedCallees` 且未產出 `contextGaps`，導致 Clean Challenge 在未見完整實作下誤通關。 | **STRICT_HOLD** (等待指示) |
| `rsajc` | `PRRT_kwDOUWarIc6rsajc` | P1 | `src/core/context-builder.mjs:2221-2232` | `importedSymbols` 僅以字串集合儲存本地別名，缺少別名原始符號映射。如 `import { validateAccess as run }`，`run` 脫離敏感詞典判定，呼叫 `run(user)` 失去敏感性追蹤。 | **STRICT_HOLD** (等待指示) |
| `r1BuI` | `PRRT_kwDOUWarIc6r1BuI` | P1 | `src/core/context-builder.mjs:1473` | 正規表達式啟發式判定將前置有空白之斜線 `/` 一律當作 regex 字面量開頭，導致連續除法鏈（如 `total / parseLimit(input) / scale`）中之後續呼叫被誤略。 | **STRICT_HOLD** (等待指示) |
| `slAM6` | `PRRT_kwDOUWarIc6slAM6` | P1 | `src/core/context-builder.mjs:1346-1365` | 安全關鍵字正則遺漏權限存取控制詞彙（`policy`, `enforce`, `rbac`, `acl`），使 `enforceAccess()`、`policyCheck()` 返回 `category: null`。 | **STRICT_HOLD** (等待指示) |

此外，先前已記錄之實質缺陷討論串繼續維持 `STRICT_HOLD`：
- `rrHOc`: Schema v2 多檔傳入單檔模式之防護已具備，待後續多檔驗證批次處理。
- `rfkYi`: Prompt XML tag 缺少 `file` 屬性。
- `rr-I6`: `BUILTIN_OBJECT_METHODS` 檢查未先驗證接收者物件。

---

## 四、G4 批次授權申請請求

謹向審查員申請核發裁定：
1. **核准授權 (AUTHORIZED)**:
   - 對 `rr-I-`、`sl1Ri`、`rte6j`、`slqmB`、`tdsmP`（共 5 則）核發 G4-B 回覆與關閉授權。
2. **繼續凍結 (STRICT_HOLD)**:
   - 對 7 則實質開源缺陷維持 `STRICT_HOLD`（`rrHOc`, `rfkYi`, `rr-I6`, `rsKCC`, `rsajc`, `r1BuI`, `slAM6`）。
   - 對其餘 13 則 Current P1、88 則 Outdated P1 及 47 則 P2 討論串繼續維持 `STRICT_HOLD`。
3. **代碼變更權限**:
   - 維持 `NEW_COMMIT / PUSH = NOT_AUTHORIZED`。
   - 維持 `SQUASH_MERGE = NOT_AUTHORIZED`。

---
*卷宗結束*
