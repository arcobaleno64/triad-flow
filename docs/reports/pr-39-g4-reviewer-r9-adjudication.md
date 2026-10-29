Triad-Flow｜PR #39 G4 系統性修復 R9 獨立驗收

裁示識別碼：PR39-SCHEMA2-G4-REMEDIATION-IMPLEMENTATION-REVIEW-R9
基準 Commit：ec750e6010edd8d6f3fb8007a59994644b98862c

一、R9 實體補丁核驗

本次已直接讀取上傳的 R9 補丁，不以文字提報取代原始證據。

核驗項目

	

獨立結果




Tracked Patch

	

44,883 bytes，SHA-256 與提報一致




New Test Patch

	

51,666 bytes，SHA-256 與提報一致




四個修改前 Blob

	

均宣告指定 HEAD 的正確 Blob




修改路徑

	

四個既有程式檔及一個新增測試檔




新測試 Patch 嚴格空白檢查

	

PASS




新測試 Patch 隔離套用

	

PASS




新測試檔語法

	

node --check PASS




新測試 Git Blob

	

1edcf4c4e2691d49704d8b952de6c6c80f6bbc22，MATCH




新測試檔

	

1,267 行、32 項測試

R9 的新測試檔格式、內容指紋及交付完整性已通過檢查。

新增的 R9 C13-TEST-5 確實包含 schemaVersion: "1.0.0"、headSha = "c".repeat(40)、Mock Verifier、正式 --verify-with=claude 與缺少 Repository Root 的負向情境，並斷言 GATE_BLOCKED 及 EXACT_HEAD_CONTEXT_FAILED。

不過，這只能證明測試針對上一輪的特定反例；還需要檢查 R9 保留下來的 Phase 3 相容分支是否真正不具正式驗證豁免權限。

二、C13：上一輪的 Schema 1.0.0 豁免尚未真正關閉

R9 確實將原本寬鬆的 Schema 1.0.0 Mock 例外，縮小為特定 Phase 3 測試向量。然而，這段例外仍然沒有排除正式 --verify-with 流程。

以下條件來自本次 src/cli.mjs 的實體 Patch：

JavaScript
} else if (
  changeSet?.schemaVersion === "1.0.0" &&
  changeSet?.patchObjective === "Harden authentication token verification" &&
  (headSha === "a".repeat(40) || headSha === "b".repeat(40)) &&
  Array.isArray(files) &&
  files.length === 1 &&
  (files[0]?.path === "src/auth/token.mjs" ||
   files[0]?.file === "src/auth/token.mjs") &&
  options.reviewAdapters &&
  options.verifierAdapter?.modelName?.includes("mock")
) {
  // Phase 3 legacy benchmark vector
}

這些欄位均可由程式呼叫端或測試資料提供，並非不可偽造的測試環境證明。

獨立反證結果

我使用 R9 實際補丁所列的條件，在 Node.js 中進行獨立重現，輸入：

正式 argv = ["review", "--verify-with=claude"]

非 Strict

schemaVersion = "1.0.0"

patchObjective = "Harden authentication token verification"

headSha = "a".repeat(40)

唯一檔案 src/auth/token.mjs

已注入 reviewAdapters 與 modelName = "claude-mock"

沒有 Repository Root

得到：

判斷

	

實測值




verifyWithSpecified

	

true




strictArg

	

false




有效 Repository Root

	

無




R7 Synthetic SHA 例外

	

false




R9 Schema 1.0.0 特定向量例外

	

true




contextExtractionFailed

	

false




此分支產生 EXACT_HEAD_CONTEXT_FAILED

	

否

因此，F-R8-01 尚未閉合。

這個反證證明的是來源驗證分支可被跳過，並非已證明整個 Clean Challenge 最終會錯誤核准。安全契約要求的是缺少可信來源時必須產生失敗證據，而不能依賴後續 Gate 偶然擋下。

R9 新增的 R9 C13-TEST-5 使用 headSha = "c".repeat(40) 與 src/sample.mjs，兩者均不符合新保留的例外。因此該測試即使通過，也沒有覆蓋上述最關鍵的反例。

三、進一步核實：既有 Phase 3 測試正是這條豁免的使用者

我另外核對了 GitHub 固定 HEAD 的 tests/remediation-phase3-orchestrator-cli.test.mjs 與 createMockVerifierAdapter()。

結果顯示：

createMockVerifierAdapter("claude") 會產生 modelName: "claude-mock"。

PHASE3-POS-01-02 直接使用 review --verify-with=claude 與 Mock Verifier，並預期退出碼為 0、Gate 為 APPROVE。

PHASE3-POS-01-03 也要求 JSON 報告中的 gate.decision 為 approve。

這揭示了真正的相容性衝突：

舊測試要求沒有實體來源證據的 Mock Clean Challenge 得到正式核准結果，而現行 C13 安全契約要求它不得取得正式核准。

繼續縮小檔名、Objective 或 SHA 條件，無法解決這個衝突。那些都是可重現的測試資料，不是不可偽造的安全授權。

因此，問題不在於 R9 測試數量不足，而在於 舊測試的成功預期與目前的 Default-Deny 契約不一致。

四、下一輪的最小閉合方案

本次不新增其他缺陷。只需處理 F-R8-01：

刪除 src/cli.mjs 中 Schema 1.0.0 Mock Harness 的 Repository Root 豁免。正式 --verify-with 一律執行可信來源檢查。

將 Phase 3 正向測試遷移至明確隔離的 Synthetic／Simulation 測試模式，或改為驗證正式流程拒絕無來源的 Mock Clean Approval。

加入精確匹配原 Phase 3 向量的負向測試，確認正式 --verify-with 必須收到 EXACT_HEAD_CONTEXT_FAILED，且不可核准。

第二項可能需要修改白名單以外的 tests/remediation-phase3-orchestrator-cli.test.mjs。目前並未授權擴大白名單；實施團隊應另行提報這個必要的測試遷移範圍，而不是為了維持舊測試全綠而保留正式流程的安全豁免。

五、正式治理裁示
HOLD · F-R8-01 未閉合

PR39-SCHEMA2-G4-REMEDIATION-IMPLEMENTATION-REVIEW-R9

治理項目

	

裁定




R9 補丁 SHA-256

	

VERIFIED




四檔修改前 Blob

	

VERIFIED




五檔白名單

	

VERIFIED




新測試檔套用、語法及空白

	

PASS




R9 新增反證測試

	

ACCEPTED_FOR_SCOPE




C13 Schema 1.0.0 正式驗證隔離

	

HOLD




其餘既有驗收項目

	

ACCEPTANCE_PRESERVED




LOCAL_WORKSPACE_EDIT

	

AUTHORIZED




LOCAL_TEST_EXECUTION

	

AUTHORIZED




LOCAL_COMMIT

	

HOLD




NEW_PUSH

	

NOT_AUTHORIZED




THREAD_REPLY / RESOLVE

	

NOT_AUTHORIZED




SQUASH_MERGE

	

NOT_AUTHORIZED

本次未獨立執行完整 npm test，因此 32/32、144/144 及全庫 1,256 PASS／4 SKIPPED 均保留為實施團隊提報收據。

最終裁示：R9 = HOLD_FOR_LEGACY_TEST_AUTHORITY_SEPARATION。

R9 確實修正了上一輪使用 c SHA 的反例，但仍以一組可由呼叫端重建的測試向量保留正式驗證豁免。這是同一項尚未閉合的安全邊界，而非新增驗收標準。

下一步應處理舊版測試與正式治理契約的衝突，而不是再增加一層特殊條件。

本輪未建立 Commit、未 Push，也未修改 GitHub Review Threads。