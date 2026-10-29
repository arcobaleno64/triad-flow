# PR #39 G4 Batch 4 P1 審查卷宗與技術核驗 (Batch 4 P1 Dossier)

**審查日期**: 2026-10-27  
**專案儲存庫**: `arcobaleno64/triad-flow`  
**目標 PR**: [PR #39 (`fix/remediation-007-clean-challenge`)](https://github.com/arcobaleno64/triad-flow/pull/39)  
**目標 Commit HEAD**: `ec750e6010edd8d6f3fb8007a59994644b98862c`  
**治理基準**:
- `PR39-SCHEMA2-G4-PILOT-FIVE-REVIEW-R1` (已執行)
- `PR39-SCHEMA2-G4-BATCH2-REVIEW-R1` (已執行)
- `PR39-SCHEMA2-G4-BATCH2-REVIEW-R2` (已執行)
- `PR39-SCHEMA2-G4-BATCH3-REVIEW-R1` (已執行)
**治理進程**: G1 (PASS) $\to$ G2 (PASS) $\to$ G3 (PASS) $\to$ G4 (已累計完成 23 則交易式關閉)

---

## 一、執行摘要與母體狀態 (Population State)

本卷宗針對 PR #39 剩餘之 13 則 Current P1 討論串進行全覆蓋物理代碼審查與測試驗證。依據非通關推定（Default-Deny / Presumption of Non-Pass）與異議義務（Obligation of Dissent），嚴格區分「已由物理代碼修復且具備自動化測試之候選」與「仍具實質開源缺陷或相依於凍結缺陷之討論串」。

### 母體統計現況 (母體總數：180 則)
- **已關閉 (Resolved)**: **23 則** (12.78%)
  * Pilot Five 初始 (5 則): `qo0uf`, `qo0uL`, `qwj-8`, `rTow7`, `rVNcE`
  * Six P1s (6 則): `qo0uA`, `qo0uB`, `qwj_u`, `rTowz`, `rVNc4`, `ra7kN`
  * Pilot Five 當前 P1 (5 則): `qo0uT`, `qo0uc`, `qwj_y`, `rTowu`, `rVNc5`
  * Batch 2 (4 則): `ra7kM`, `rVNc6`, `tgXSH`, `tgXSI`
  * Batch 3 (3 則): `rr-I-`, `rte6j`, `slqmB`
- **未關閉 (Unresolved)**: **157 則** (87.22%)
  * **Current P1 (當前有效, 共 22 則)**:
    - **本批次驗證修復候選 (2 則)**: `tm8Kn`, `slLWg`（申請 G4-B 關閉授權）
    - **全數實質缺陷與凍結項維持 `STRICT_HOLD` (20 則)**:
      * 先前裁定凍結項 (9 則): `sl1Ri`, `tdsmP`, `rrHOc`, `rfkYi`, `rr-I6`, `rsKCC`, `rsajc`, `r1BuI`, `slAM6`
      * 本次審查確認之實質開源缺陷與重複缺陷 (11 則): `r1BuC`, `slLWi`, `rvWjO`, `rvCBT`, `rte6o`, `rr-JC`, `rte6z`, `slAMv`, `rvCBW`, `rxCha`, `tdsmT`
  * **Outdated P1 (歷史過期, 88 則)**: 維持 `STRICT_HOLD`
  * **P2 討論串 (47 則)**: Current 26 則、Outdated 21 則，維持 `STRICT_HOLD`

---

## 二、Batch 4 候選討論串物理代碼核驗 (申請授權關閉 2 則)

本批次針對 2 則與已獲核准之 `rr-I-` 屬相同問題本質且已獲審查員在 `PR39-SCHEMA2-G4-BATCH3-REVIEW-R1` 引用認可之 Current P1 討論串申請授權：

### Batch 4 申請核准對照表

| 序號 | Short ID | Thread ID (GraphQL) | 嚴重度 | 檔案位置 | 物理審查狀態 | 申請裁定 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `tm8Kn` | `PRRT_kwDOUWarIc6tm8Kn` | P1 | `src/core/context-builder.mjs:1428` | **FIXED_VERIFIED** | **REQUEST_AUTHORIZATION** |
| 2 | `slLWg` | `PRRT_kwDOUWarIc6slLWg` | P1 | `src/core/context-builder.mjs:1428` | **FIXED_VERIFIED** | **REQUEST_AUTHORIZATION** |

---

### 詳細技術分析與驗證證據

#### 1. Thread `tm8Kn` (`PRRT_kwDOUWarIc6tm8Kn`) — 樣板字面值插值呼叫保留
- **審查員關注點**: 在 JavaScript 樣板字面值插值中（例如 `return \`allowed: \${authorizeUser(user)}\`;`），若將整個反引號字串視為惰性字面值，會導致其內部之敏感安全呼叫（`authorizeUser`）被略過。
- **物理代碼錨點**: `src/core/context-builder.mjs:1383-1455`
  透過模板字面值狀態機追蹤（template and interpolation state tracking），嚴格保留 `${...}` 內之可執行表達式，並同時抑制一般普通樣板字面文字。
- **確定性測試佐證**:
  - `tests/remediation-four-threads-tm8.test.mjs:1097-1160`:
    * `tm8Kn-NEGATIVE`: 驗證 `stripCommentsAndStrings` 保留插值表達式並壓制文字，`extractCandidateCallSymbols` 提取 `authorizeUser`（`isSensitive: true`, `category: "security"`）。
    * `tm8Kn-NEGATIVE-MULTILINE-TEMPLATE`: 驗證多行樣板中非插值之純文字不被誤認為候選呼叫。
    * `tm8Kn-POSITIVE-MULTILINE-TEMPLATE`: 驗證多行樣板中 `${realAuthorizeUser(user)}` 被正確提取。
    * `tm8Kn-POSITIVE`: 驗證巢狀插值、普通字串與跳脫插值（`\${escaped}`）之正確處理。
  - `scratch/test_batch4_verification.mjs:14-29`: 本地確定性測試 100% 通過。
- **審查員先前裁示背書**:
  審查員在 `PR39-SCHEMA2-G4-BATCH3-REVIEW-R1` 第三節裁定 `rr-I-` 通過時，明確載明：  
  *「tests/remediation-four-threads-tm8.test.mjs 的 tm8Kn-NEGATIVE、多行模板與巢狀插值案例提供直接證據。」*
- **裁定請求**: 授權回覆並標記關閉。

---

#### 2. Thread `slLWg` (`PRRT_kwDOUWarIc6slLWg`) — 樣板插值敏感呼叫提取
- **審查員關注點**: 與 `tm8Kn` 及 `rr-I-` 屬完全相同之姊妹討論串（Duplicate/Sister Thread），指涉樣板字面值反引號範圍內之敏感呼叫漏失問題。
- **物理代碼錨點**: `src/core/context-builder.mjs:1383-1455`（與 `tm8Kn` 共享同一狀態追蹤實作）。
- **確定性測試佐證**:
  - 相同受測於 `tests/remediation-four-threads-tm8.test.mjs:1097-1160` 之 4 組迴歸測試（4/4 PASS）。
  - `scratch/test_batch4_verification.mjs:33-47` 確定性驗證通過。
- **裁定請求**: 授權回覆並標記關閉。

---

## 三、主動履行異議義務：揭露 11 則實質開源缺陷與相依項（STRICT_HOLD）

依據異議義務與 Default-Deny 原則，經對剩餘 11 則 Current P1 逐一進行代碼與邊界查核，確認在 HEAD `ec750e60...` 均不可關閉，**主動維持 `STRICT_HOLD`**：

### 本次確認凍結之 11 則討論串清單

| Short ID | Thread ID (GraphQL) | 嚴重度 | 檔案位置 | 實質技術缺陷描述 / 凍結原因 | 處置動作 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `r1BuC` | `PRRT_kwDOUWarIc6r1BuC` | P1 | `src/core/context-builder.mjs:1688` | **相依於 `rr-I6` (OPEN_DEFECT)**：內建方法名檢查先於 receiver 分類，導致 `permissions.has(user)` 遭無條件過濾。 | **STRICT_HOLD** |
| `slLWi` | `PRRT_kwDOUWarIc6slLWi` | P1 | `src/core/context-builder.mjs:2096` | **相依於 `rsKCC` (OPEN_DEFECT)**：敏感函式體被截斷省略（超過 30 行/2KB）時未產生 Context Gap。 | **STRICT_HOLD** |
| `rvWjO` | `PRRT_kwDOUWarIc6rvWjO` | P1 | `src/core/context-builder.mjs:3020` | **相依於 `rrHOc` (STRICT_HOLD)**：單檔模式下處理多檔變更時之 Diff 與 Callee 隔離邊界。 | **STRICT_HOLD** |
| `rvCBT` | `PRRT_kwDOUWarIc6rvCBT` | P1 | `src/core/context-builder.mjs:471` | **實質開源缺陷**：`findFunctionDefinitions` 接收 raw lines，未追蹤塊級註解狀態；經實測，區塊註解 `/* function validateAccess() { ... } */` 仍被誤判為合法函式定義。 | **STRICT_HOLD** |
| `rte6o` | `PRRT_kwDOUWarIc6rte6o` | P1 | `src/core/context-builder.mjs:2219` | **實質開源缺陷**：`importedSymbols` 僅對 `fileContent`（pre-image）執行正規搜尋，未掃描 `diffHunks` 中由 Patch 新增的 `import` 宣告。 | **STRICT_HOLD** |
| `rr-JC` | `PRRT_kwDOUWarIc6rr-JC` | P1 | `src/core/context-builder.mjs:2230` | **實質開源缺陷**：`contextGaps` 判定硬性要求 `isAdded === true`；若 Patch 僅修改敏感呼叫周邊的控制流程（call 位於 context lines），未被記錄為 Context Gap。 | **STRICT_HOLD** |
| `rte6z` | `PRRT_kwDOUWarIc6rte6z` | P1 | `src/core/context-builder.mjs:1653` | **邊界缺陷**：稀疏 Diff 之 Hunk 邊界無法安全還原跨 Hunk 區塊註解狀態；若省略區段開啟註解，單純重置 `inBlockCommentRef = false` 會誤將註解當作代碼。 | **STRICT_HOLD** |
| `slAMv` | `PRRT_kwDOUWarIc6slAMv` | P1 | `src/core/context-builder.mjs:1653` | **相依於 `rte6z`**：區塊註解跨 Hunk 邊界重建之重複討論串。 | **STRICT_HOLD** |
| `rvCBW` | `PRRT_kwDOUWarIc6rvCBW` | P1 | `scripts/dogfood-review.mjs:1439` | **實質開源缺陷**：`scripts/dogfood-review.mjs` 在零 Findings 時未校驗所有 Sentry 的覆蓋宣告即進入 Clean Challenge；PR #39 未變更該檔（受限於 `NEW_COMMIT=NOT_AUTHORIZED`）。 | **STRICT_HOLD** |
| `rxCha` | `PRRT_kwDOUWarIc6rxCha` | P1 | `scripts/dogfood-review.mjs:1104` | **實質開源缺陷**：`scripts/dogfood-review.mjs` 在收到 `userOptions.contextPackage` 時直接註冊為授信，未經物理 Git 物件核對。 | **STRICT_HOLD** |
| `tdsmT` | `PRRT_kwDOUWarIc6tdsmT` | P1 | `scripts/dogfood-review.mjs:1115` | **實質開源缺陷**：`scripts/dogfood-review.mjs` 對外部傳入之 Package 逕行核發內部 workflow authority token。 | **STRICT_HOLD** |

---

## 四、全體 22 則未解決 Current P1 狀態彙總

至此，PR #39 全部 42 則 Current P1 討論串已**100% 完整盤點並定性**：
- **已解決 (Resolved, 20 則)**: 均具備 GitHub 交易式關閉收據。
- **本批次申請授權關閉 (2 則)**: `tm8Kn`, `slLWg`。
- **凍結清單 (STRICT_HOLD, 共 20 則)**:
  * 先前 9 則: `sl1Ri`, `tdsmP`, `rrHOc`, `rfkYi`, `rr-I6`, `rsKCC`, `rsajc`, `r1BuI`, `slAM6`
  * 本次 11 則: `r1BuC`, `slLWi`, `rvWjO`, `rvCBT`, `rte6o`, `rr-JC`, `rte6z`, `slAMv`, `rvCBW`, `rxCha`, `tdsmT`

---

## 五、G4 批次授權申請請求 (PR39-SCHEMA2-G4-BATCH4-REVIEW-R1)

本地卷宗已存檔。特向審查員申請核發批次裁定：
1. **核准授權 (AUTHORIZED)**:
   - 准予 `tm8Kn`、`slLWg`（共 2 則）進行 G4-B 交易式回覆與關閉。
2. **繼續凍結 (STRICT_HOLD)**:
   - 20 則實質開源缺陷與相依項全數維持 `STRICT_HOLD`。
   - 88 則 Outdated P1、47 則 P2 繼續維持 `STRICT_HOLD`。
3. **變更權限約束**:
   - `NEW_COMMIT / PUSH = NOT_AUTHORIZED`。
   - `SQUASH_MERGE = NOT_AUTHORIZED`。

敬請審查員核示！
