# PR #39 G4 系統性修復實施收據（R10：徹底刪除 Schema 1.0.0 豁免與既有測試權限分離提報）

- **實施識別碼**：`PR39-SCHEMA2-G4-REMEDIATION-IMPLEMENTATION-RECEIPT-R10`
- **對應審查裁示**：`PR39-SCHEMA2-G4-REMEDIATION-IMPLEMENTATION-REVIEW-R9`（`HOLD_FOR_LEGACY_TEST_AUTHORITY_SEPARATION`）
- **基準 Commit**：`ec750e6010edd8d6f3fb8007a59994644b98862c`
- **治理狀態**：`LOCAL_COMMIT = HOLD`（等待 R10 裁定）、`NEW_PUSH = NOT_AUTHORIZED`、`THREAD_REPLY / RESOLVE = NOT_AUTHORIZED`

---

## 一、R10 核心修復與 F-R8-01 徹底閉合

依據審查領隊 恒一 於 R9 裁示中指出之關鍵根因：
> 「這揭示了真正的相容性衝突：舊測試要求沒有實體來源證據的 Mock Clean Challenge 得到正式核准結果，而現行 C13 安全契約要求它不得取得正式核准。繼續縮小檔名、Objective 或 SHA 條件，無法解決這個衝突。那些都是可重現的測試資料，不是不可偽造的安全授權... 實施團隊應另行提報這個必要的測試遷移範圍，而不是為了維持舊測試全綠而保留正式流程的安全豁免。」

實施團隊在本輪做出如下決定性變更：

### 1. `src/cli.mjs` 徹底刪除所有 Schema 1.0.0 Mock Harness 豁免
在 `src/cli.mjs` 中完全移除了任何針對 Schema 1.0.0 或 Phase 3 測試向量的豁免分支。
- 正式 `--verify-with` 或注入 `verifierAdapter` 的呼叫端，只要缺少合法、可信之實體 Git 儲存庫根目錄（`targetRepo`），一律無條件進入 Fail-Closed 分支：
  - `contextExtractionFailed = true`
  - 發射 `EXACT_HEAD_CONTEXT_FAILED`
  - 封裝為 `effectiveContextGaps`
  - 阻擋 Clean Approval，退出碼嚴格為 `EXIT_CODES.GATE_BLOCKED` (1)。

### 2. `tests/remediation-twenty-p1-systemic.test.mjs` 新增原 Phase 3 基準向量精確負向測試
在白名單新測試檔中新增 `R10 C13-TEST-6`，精確使用原 Phase 3 基準測試向量：
- `schemaVersion: "1.0.0"`
- `patchObjective: "Harden authentication token verification"`
- `headSha: "a".repeat(40)`
- `files: [{ path: "src/auth/token.mjs", additions: 15, deletions: 2, riskTier: 1 }]`
- `modelName: "claude-mock"`
- 執行 `runCli(["review", "--verify-with=claude"])`，完全不提供 `repoRoot` 與 `cwd`。
- **斷言驗證**：
  - `exitCode === EXIT_CODES.GATE_BLOCKED` (1)
  - `verifierPkg === null`
  - `verifierGaps` 必定包含 `EXACT_HEAD_CONTEXT_FAILED`。
  - 測試於 16ms 內精確通過。

---

## 二、既有 Phase 3 測試遷移範圍提報（遵循領隊裁示第四節第二項）

依據領隊指示：「實施團隊應另行提報這個必要的測試遷移範圍，而不是為了維持舊測試全綠而保留正式流程的安全豁免。」

### 1. 受影響的既有測試盤點
在刪除安全豁免後，全儲存庫僅有以下兩檔案共 5 項測試轉紅：
1. `tests/remediation-phase3-orchestrator-cli.test.mjs`（2 筆）：
   - `PHASE3-POS-01-02`: CLI level text format: `--verify-with=claude` with clean consensus evaluates to reviewed-clean (exit code 0)
   - `PHASE3-POS-01-03`: CLI level json format: `--verify-with=claude --format=json` outputs approved report with exit code 0
2. `tests/adversarial-phase3-challenger.test.mjs`（3 筆）：
   - `R5-LIFECYCLE-02`: Clean review on changed code WITH verifier (CLEAN) exits with code 0 (SUCCESS)（包含 text、json、space-separated 三子項）

### 2. 衝突性質說明
此 5 項測試誕生於 Phase 3（PR #39 早期階段），其當時的設計假設為「在純記憶體 Mock 環境下，以虛擬 SHA (`"a"*40`) 執行 `--verify-with=claude` 即可取得 Gate APPROVE 與 exit code 0」。
然而，C13（Default-Deny 實體來源防偽契約）明確規定：**凡正式 `--verify-with` 流程，若缺少實體 Git 儲存庫與真實 Exact-Head commit 證據，絕不准取得正式 Clean Approval**。
因此，這 5 項舊測試所預期的行為已與現行安全標準直接衝突。

### 3. 治理處置提案（請領隊裁決）
目前該兩測試檔案嚴格位於「五檔白名單」之外，實施團隊堅守治理紀律，未曾亦不得擅自修改該兩檔。謹提請領隊裁示採行下列何者：
- **方案 A（授權擴大白名單進行遷移）**：領隊正式授權將 `tests/remediation-phase3-orchestrator-cli.test.mjs` 與 `tests/adversarial-phase3-challenger.test.mjs` 納入修復白名單，實施團隊將其調整為明確驗證「缺少實體來源時拒絕核准並退出碼 1」，或遷移為帶有實體暫存 Git 庫之正向整合測試。
- **方案 B（當前五檔驗收通過，舊測試遷移列為後續授權追蹤）**：認可當前五檔核心修復補丁之完整性與 C13 安全邊界之絕對閉合，賜予本輪五檔之單一本機 Commit 授權（`LOCAL_COMMIT = AUTHORIZED`），舊測試遷移作為下一個獨立 PR 或獨立授權階段處置。

---

## 三、R10 實體補丁指紋與驗證數據

### 1. 補丁檔案指紋
- `pr39-r10-tracked.patch`:
  - 大小：44,223 bytes
  - SHA-256：`1815887089AC870E83CAA0404D6A5AB4B655696BFFCB1AA721F2160D02461A1F`
  - 涵蓋 4 檔：
    - `scripts/dogfood-review.mjs` (`23a98afcebf7ca00094e951a88535a4a476ef263` -> `ad40d564ef4e4efde13e59c39eea95731e859d51`)
    - `src/adapters/review-prompts.mjs` (`6d8c183e466d835dcd3c5f43f84c717932207a7f` -> `f0c379d21d786eb39a92cc7e5453d6caec72abc0`)
    - `src/cli.mjs` (`319c8e382989dbe6e30a322a950e55edb8ab6f82` -> `48498b888d2836d6412e509661d1163ee4c60cd2`)
    - `src/core/context-builder.mjs` (`779d4462e4aef90950fb9d87f78cd74adfb5632b` -> `6e669a272eac612277f7c56c827694c1904d2af3`)
- `pr39-r10-new-test.patch`:
  - 大小：54,298 bytes
  - SHA-256：`6C9144645DA65CF07C9A0CF0F84018037D5EE872AC8CFBDECD3107A52CFB479F`
  - 新增檔：`tests/remediation-twenty-p1-systemic.test.mjs`（1,327 行，Git Blob: `8d1f4d4f54d38177358bd0baedb973bfbf57491c`）

### 2. 測試與格式驗證收據
- `tests/remediation-twenty-p1-systemic.test.mjs`：**32/32 PASS (100%)**
- 四套修復套件聯測（`remediation-five-p1`, `remediation-six-p1`, `remediation-three-p1`, `remediation-twenty-p1`）：**62/62 PASS (100%)**
- `git apply --check --reverse --whitespace=error`：代碼 0（無任何空白或行尾警告）
- `git diff --check`：代碼 0
- `node --check`：PASS
