# PR #39 G4 系統性修復實施收據（R11：七檔整合驗收與 Phase 3 舊測試路線一遷移完成）

- **實施識別碼**：`PR39-SCHEMA2-G4-REMEDIATION-IMPLEMENTATION-RECEIPT-R11`
- **對應審查裁示**：`PR39-SCHEMA2-G4-REMEDIATION-IMPLEMENTATION-REVIEW-R10`（授權令：`PR39-SCHEMA2-G4-LEGACY-PHASE3-TEST-MIGRATION-AUTH-R1`）
- **基準 Commit**：`ec750e6010edd8d6f3fb8007a59994644b98862c`
- **治理狀態**：`LOCAL_COMMIT = HOLD`（等待 R11 最終授權）、`NEW_PUSH = NOT_AUTHORIZED`、`THREAD_REPLY / RESOLVE = NOT_AUTHORIZED`

---

## 一、方案 A 遷移落實說明（採納路線一：保留正向測試契約）

依據審查領隊 恒一 於 R10 裁示正式授權之「方案 A」與第四節「遷移驗收契約」：
> 「路線一：保留正向測試。在隔離暫存 Git Repository 中建立真正的 Commit、ChangeSet 與可信來源 ContextPackage，讓 Clean Challenge 的核准來自真實且可驗證的上下文。如此才能保留原本測試 APPROVE 的預期... 避免把所有測試都改成只會拒絕，最後連正常核准路徑也沒人測試。」

實施團隊嚴格在授權範圍內，對被授權的 2 個舊測試檔案落實受控遷移，完全未觸動已凍結之五檔核心修復程式碼：

### 1. `tests/adversarial-phase3-challenger.test.mjs` 遷移
- **受影響測試**：`R5-LIFECYCLE-02`（三項子測試：Text mode、JSON mode、Space-separated argument `--verify-with claude`）。
- **遷移實作**：
  - 引入隔離輔助函式 `createTempGitRepository()`，在系統暫存目錄建立乾淨 Git 庫，建立真實 commit 與真實 HEAD SHA。
  - 將 `repo.headSha`、`repo.tmpDir` 作為 `changeSet`、`repoRoot`、`cwd` 傳入 `runCliHelper`。
  - 三項子測試均由真實 Git 上下文取得 Exact-Head 驗證，成功達成 Clean Challenge 核准。
- **執行結果**：全套 **79/79 PASS (100%)**。

### 2. `tests/remediation-phase3-orchestrator-cli.test.mjs` 遷移
- **受影響測試**：`PHASE3-POS-01-02`（CLI level text format）與 `PHASE3-POS-01-03`（CLI level json format）。
- **遷移實作**：
  - 同樣引入隔離輔助函式 `createTempGitRepository()`，建立真實實體 commit，傳入真實合法之 `repo.headSha` 與 `repoRoot: repo.tmpDir`。
  - 保留原本對 exit code 0、Gate Decision APPROVE、status reviewed-clean 的正向斷言。
- **執行結果**：全套 **27/27 PASS (100%)**。

### 3. 負向防偽契約對照保障
在正向測試保留的同時，白名單新測試檔 `tests/remediation-twenty-p1-systemic.test.mjs` 依然嚴格保留 `R9 C13-TEST-5` 與 `R10 C13-TEST-6`，保證「任何缺少實體來源之正式 `--verify-with` 一律強制 Fail-Closed 發射 `EXACT_HEAD_CONTEXT_FAILED` 並退出碼 1」。正負向兩條契約互為鏡像，完全閉合。

---

## 二、七檔白名單補丁檔案指紋與基準對齊

本次交付嚴格遵守領隊授權之七檔白名單（6 個修改前 Tracked 檔 + 1 個新增測試檔），完全無任何範圍外更動。

### 1. Tracked 補丁指紋 (`pr39-r11-tracked.patch`)
- **大小**：58,871 bytes
- **SHA-256**：`D9C113E341FF7F6C6865F2E7D8339A33F0C5A78FD49F5EA8779F4D07EEAA4652`
- **6 個修改前 Git Blob（基準 `ec750e6010edd8d6f3fb8007a59994644b98862c`）**：
  1. `scripts/dogfood-review.mjs`: `23a98afcebf7ca00094e951a88535a4a476ef263` -> `ad40d564ef4e4efde13e59c39eea95731e859d51`（凍結）
  2. `src/adapters/review-prompts.mjs`: `6d8c183e466d835dcd3c5f43f84c717932207a7f` -> `f0c379d21d786eb39a92cc7e5453d6caec72abc0`（凍結）
  3. `src/cli.mjs`: `319c8e382989dbe6e30a322a950e55edb8ab6f82` -> `48498b888d2836d6412e509661d1163ee4c60cd2`（凍結）
  4. `src/core/context-builder.mjs`: `779d4462e4aef90950fb9d87f78cd74adfb5632b` -> `6e669a272eac612277f7c56c827694c1904d2af3`（凍結）
  5. `tests/adversarial-phase3-challenger.test.mjs`: `fffbd1db0a0708ad574c70526b707f3b1c16951d` -> `33eadc0804e7dc1ed523e0cea7e7e2670c2b1de2`（方案 A 遷移）
  6. `tests/remediation-phase3-orchestrator-cli.test.mjs`: `6f554814e59c4cad3ef577279f1b73e5accaa588` -> `5ed7006539ca789290723931ff79571cfed6c48d`（方案 A 遷移）

### 2. New Test 補丁指紋 (`pr39-r11-new-test.patch`)
- **大小**：54,298 bytes
- **SHA-256**：`6C9144645DA65CF07C9A0CF0F84018037D5EE872AC8CFBDECD3107A52CFB479F`
- **新增檔**：`tests/remediation-twenty-p1-systemic.test.mjs`
  - 行數：1,327 行
  - 測試案例：32 項
  - Git Blob：`8d1f4d4f54d38177358bd0baedb973bfbf57491c`（完全對齊 R10 已驗證 Blob，無任何變動）

---

## 三、完整回歸測試收據

- **受影響 Phase 3 測試套件**：
  - `tests/adversarial-phase3-challenger.test.mjs`：**79/79 PASS (100%)**
  - `tests/remediation-phase3-orchestrator-cli.test.mjs`：**27/27 PASS (100%)**
- **專屬系統性修復測試套件**：
  - `tests/remediation-twenty-p1-systemic.test.mjs`：**32/32 PASS (100%)**
- **四套修復聯測**：**62/62 PASS (100%)**
- **全庫回歸測試 (`npm test`)**：
  - **1,257 PASS, 0 FAIL, 4 SKIPPED (100%)**（耗時 41.8s）
  - 原有 4 項合理 SKIP 完全維持，未新增任何跳過。
- **補丁格式與空白檢查**：
  - `git diff --check`：代碼 0
  - `git apply --check --reverse --whitespace=error`：代碼 0（兩份補丁均反向套用無誤）
  - `node --check`：全數 PASS

---

## 四、請求單一本機 Commit 授權

七檔修復與遷移已徹底消除所有回歸衝突，全庫 1,257 測試全綠，補丁範圍嚴格受控於七檔。
請審查領隊 恒一 核發單一本機 Commit 授權（`LOCAL_COMMIT = AUTHORIZED`）。
實施團隊將在收到授權後，立即執行單一本機 Commit，並維持 `NEW_PUSH = NOT_AUTHORIZED` 與 `THREAD_REPLY / RESOLVE = NOT_AUTHORIZED` 直至進一步裁示。
