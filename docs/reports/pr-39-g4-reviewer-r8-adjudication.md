Triad-Flow｜PR #39 G4 系統性修復 R8 獨立驗收

裁示識別碼：PR39-SCHEMA2-G4-REMEDIATION-IMPLEMENTATION-REVIEW-R8
基準 Commit：ec750e6010edd8d6f3fb8007a59994644b98862c

一、R8 實體補丁核驗結果

本次已直接檢查上傳的 R8 Tracked Patch 與 New Test Patch，並核對 GitHub PR #39 的固定 HEAD。PR 仍為 OPEN、未合併，基準 SHA 未變。

驗收項目

	

獨立核驗




Tracked Patch

	

44,445 bytes，SHA-256 完全一致




New Test Patch

	

49,777 bytes，SHA-256 完全一致




4 個修改前 Git Blob

	

全數與遠端 HEAD 一致




五檔修改白名單

	

PASS




新測試檔嚴格空白檢查

	

PASS




新測試檔隔離套用

	

PASS




新測試檔 Git Blob

	

d0642ea4852febe4e6b297f88e1ef9154410950d，MATCH




新測試檔語法

	

node --check PASS




測試案例宣告

	

32 項

R8 的 Synthetic SHA 修補本身已符合上一輪要求：

JavaScript
const isLegacySyntheticHarness =
  !strictArg &&
  !verifyWithSpecified &&
  !options.verifierAdapter &&
  !hasFixtureBypassFlag &&
  (
    headSha === "a".repeat(40) ||
    headSha === "b".repeat(40)
  );

這段判斷已能阻止正式 --verify-with 或注入 Verifier Adapter 的呼叫利用 Synthetic SHA 取得豁免。

新增的 R8 C13-TEST-4 也具備對應的負向輸入，並直接斷言 GATE_BLOCKED 與 EXACT_HEAD_CONTEXT_FAILED。

裁定：C13_SYNTHETIC_SHA_BOUNDARY = FIXED_IN_PATCH。

不過，完整 C13 來源驗證邊界仍有另一條例外需要確認。

二、仍存在的阻擋項：Schema 1.0.0 Mock Harness 豁免
F-R8-01 · C13 來源驗證未完全閉合

在 R8 的 src/cli.mjs 補丁中，Synthetic SHA 判斷之後還保留另一條例外：

JavaScript
} else if (
  changeSet?.schemaVersion === "1.0.0" &&
  options.reviewAdapters &&
  options.verifierAdapter?.modelName?.includes("mock")
) {
  // Segregated legacy Phase 3 Schema 1.0.0 synthetic mock harness
}

這條分支沒有檢查 verifyWithSpecified 或 strictArg。

它雖然是為了相容舊版測試而保留，但 schemaVersion 和 Adapter 名稱都能由程式呼叫端提供，因此不能直接視為可信的隔離測試證據。

獨立反證

以下輸入會觸發該例外：

JavaScript
await runCli(
  ["review", "--verify-with=claude"],
  io,
  {
    getChangeSet: () => ({
      ok: true,
      schemaVersion: "1.0.0",
      headSha: "c".repeat(40),
      files: [{ path: "src/auth.mjs" }],
      diffHunks: "@@ -1 +1 @@\n+const x = 1;"
    }),
    reviewAdapters: mockAdapters,
    verifierAdapter: {
      modelName: "claude-mock",
      executeVerification: async () => ({
        ok: true,
        executionStatus: "SUCCESS",
        overallStatus: "CLEAN",
        evaluations: [],
        omissions: []
      })
    }
  }
);

對補丁中的分支條件進行 Node.js 獨立重現：

判斷項目

	

結果




verifyWithSpecified

	

true




strictArg

	

false




isLegacySyntheticHarness

	

false




Schema 1.0.0 Mock 例外

	

true




可信 Repository Root

	

不存在




contextExtractionFailed

	

維持 false




由此分支產生 EXACT_HEAD_CONTEXT_FAILED

	

否

這證明正式 --verify-with 流程仍可透過另一條 Legacy Mock 例外跳過指定的 Context Extraction Failure 分支。

須區分的是：本次重現確認了來源檢查的分支繞過，尚未證明完整流程最後一定會錯誤核准 Clean Approval。因此缺陷範圍明確限定在 C13 的 Fail-Closed 來源驗證契約，不擴大宣稱 Gate 已遭突破。

為什麼 R8 的 32 項測試沒有發現？

R8 新增測試使用的是 Synthetic SHA 加正式 --verify-with，其 changeSet 未設定 schemaVersion: "1.0.0"。

而先前的 Mock Adapter 負向測試，也未同時設定 Schema 1.0.0。

因此沒有測試命中這條 Legacy Phase 3 例外。

裁定：F-R8-01 = OPEN。

三、R9 最小修補指令

無須重新審查 C01～C12、C14A～C14C，也不必重作所有測試設計。

本次只要求：

移除 Schema 1.0.0 Mock Harness 對正式驗證的豁免。最直接的方案是刪除該 else if，讓無可信 Repository Root 的請求進入既有 Fail-Closed 分支。若確實需要維持相容性，則必須將舊版 Fixture 隔離在不具正式 Clean Approval 權限的測試入口。

新增單一負向案例，同時具備 --verify-with=claude、schemaVersion: "1.0.0"、modelName: "claude-mock"、有效的 reviewAdapters 及缺少 Repository Root。直接斷言 EXACT_HEAD_CONTEXT_FAILED 傳遞至 Verifier，且最終不得核准。

重新產出兩份完整 Patch，保留父節點與五檔白名單，附更新後的 Git Blob、SHA-256 及測試收據。

四、R8 正式治理裁定

PR39-SCHEMA2-G4-REMEDIATION-IMPLEMENTATION-REVIEW-R8

HOLD_FOR_SCHEMA1_MOCK_BOUNDARY

治理項目

	

裁定




R8 Patch 指紋

	

VERIFIED




父節點 Blob

	

VERIFIED




五檔白名單

	

VERIFIED




新測試 Patch 格式、語法與空白

	

PASS




C13 Synthetic SHA 正式驗證隔離

	

FIXED_IN_PATCH




C13 Fixture 旗標繞過

	

FIXED_IN_PATCH




C13 Schema 1.0.0 Mock 例外

	

HOLD




其餘已接受項目

	

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

本輪沒有獨立執行完整 npm test，因此提報的 32/32、144/144、1,256 PASS／4 SKIPPED 保持為 REPORTED_PASS，不冒充實際重跑結果。

最終裁定：R8 = CONDITIONAL_HOLD。

R8 已完成前輪指名的 Synthetic SHA 修補。尚未閉合的是同一 C13 安全契約內、原本就存在的 Legacy Schema 1.0.0 Mock 分支，並非新增一套驗收要求。

下一輪限定於這一條分支的修正與反證。完成之前，不授權單一本地 Commit；其餘治理權限維持原狀。

本次未建立 Commit、未 Push、未回覆或關閉任何 GitHub Review Thread。