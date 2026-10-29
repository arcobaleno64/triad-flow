Triad-Flow｜PR #39 G4 系統性修復 R7 獨立驗收

裁示識別碼：PR39-SCHEMA2-G4-REMEDIATION-IMPLEMENTATION-REVIEW-R7
基準 Commit：ec750e6010edd8d6f3fb8007a59994644b98862c

CONDITIONAL_HOLD

R7 已修正上一輪指出的 Fixture 旗標繞過問題，也排除了新測試 Patch 的空白錯誤；但本輪仍發現一條未受正式驗證模式限制的 Synthetic SHA 豁免路徑。因此暫不核發 LOCAL_COMMIT 授權。

一、實體補丁核驗

已直接讀取本次上傳的兩份 Patch，使用 Git、Node.js 與 SHA-256 進行獨立檢查。

驗收項目

	

結果




Tracked Patch

	

44,004 bytes，SHA-256 與提報完全一致




New Test Patch

	

47,759 bytes，SHA-256 與提報完全一致




修改範圍

	

四個既有程式檔、一個新增測試檔




四個舊 Blob

	

全數與 GitHub 指定 HEAD 一致




新測試檔 Git Blob

	

779998f9530765d726909c41eced97fb9737375f，MATCH




新測試檔行數

	

1,177 行




新測試 Patch 嚴格空白檢查

	

PASS




新測試 Patch 隔離套用

	

PASS




新測試檔 node --check

	

PASS




測試案例宣告數

	

32




PR #39

	

OPEN、未合併，HEAD 未變

R7 的修改規模為四個追蹤檔案約 +564／−109 行，以及新增測試檔 1,177 行。

正式接受：PATCH_INTEGRITY = VERIFIED、BASE_BLOB_ALIGNMENT = VERIFIED、FILE_SCOPE = VERIFIED、NEW_TEST_WHITESPACE = PASS。

前輪 R6 的末尾空白問題，本次確實已解除。

二、C13：Fixture 旗標繞過已修正，但 Synthetic SHA 仍可豁免正式驗證

R7 的 src/cli.mjs 使用：

JavaScript
const isLegacySyntheticHarness = !strictArg &&
  !hasFixtureBypassFlag &&
  (headSha === "a".repeat(40) || headSha === "b".repeat(40));

這段邏輯存在一個尚未封閉的條件：沒有排除 --verify-with 正式驗證流程。

我已核對固定 HEAD 的 runCli() 實作：

verifyWithSpecified 會辨識 --verify-with=claude。

headSha 可以由呼叫端提供的 changeSet.headSha 取得。

R7 新增的 isLegacySyntheticHarness 不檢查 verifyWithSpecified。

當 isLegacySyntheticHarness 成立時，缺少 Repository Root 不會被標記為 contextExtractionFailed。

獨立條件重現

測試輸入如下：

JavaScript
argv = ["review", "--verify-with=claude"];

changeSet = {
  ok: true,
  headSha: "a".repeat(40),
  files: [{ path: "src/auth.mjs" }],
  diffHunks: "@@ -1 +1 @@\n+const x = 1;"
};

// 沒有 repoRoot、cwd 或任何 Fixture 旗標

使用 Node.js 執行與補丁相同的判斷，得到：

條件

	

實測




正式 --verify-with

	

true




strictArg

	

false




hasFixtureBypassFlag

	

false




isLegacySyntheticHarness

	

true




有效 Repository Root

	

false




contextExtractionFailed

	

false

這是已驗證的分支繞過，但不表示已證明最終 Gate 會核准。核心問題是正式驗證仍可能缺少預期的 EXACT_HEAD_CONTEXT_FAILED 證據。

R7 新增測試為何未攔截

新增 R7 C13-TEST-3 使用 headSha = "3".repeat(40)，並同時設定多個 Fixture 旗標。

這確實會令 hasFixtureBypassFlag === true，因此新增修補正常進入失敗分支。

但它沒有測試無 Fixture 旗標、使用 a 或 b Synthetic SHA、同時要求正式 --verify-with 的情境。

裁定：C13 = PARTIALLY_FIXED。R6 的旗標繞過已關閉，R7 的 Synthetic SHA 豁免仍需收斂。

三、R8 僅需一項最終補正

不需要重做其他已接受的修復。

建議將 Legacy Synthetic Harness 條件限制為不具正式驗證能力的流程，例如：

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

並新增一項負向測試：--verify-with=claude、非 Strict、無 Root、無 Fixture 旗標、headSha = "a".repeat(40)，直接確認 Verifier 收到 EXACT_HEAD_CONTEXT_FAILED 且 Gate 不得核准。

這樣可保留真正隔離的 Legacy Synthetic 測試，同時不讓特殊 SHA 成為正式驗證的來源信任豁免。

四、正式治理裁定

PR39-SCHEMA2-G4-REMEDIATION-IMPLEMENTATION-REVIEW-R7

HOLD_FOR_SYNTHETIC_SHA_BOUNDARY

治理項目

	

裁定




R7 Patch 指紋

	

VERIFIED




四個舊 Blob

	

VERIFIED




五檔白名單

	

VERIFIED




Patch 嚴格空白修正

	

ACCEPTED




C12

	

ACCEPTED




C14A／C14B 測試設計

	

維持 ACCEPTED




C13 Fixture 旗標繞過

	

FIXED_IN_PATCH




C13 Synthetic SHA 正式驗證隔離

	

HOLD




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

本次獨立完成了 Patch 指紋、Git Blob 基準、新測試套用、語法、空白檢查與 C13 條件重現；未重跑完整 npm test。提報的 32/32、144/144 及全庫 1,256 PASS／4 SKIPPED，仍登錄為實施團隊測試收據。

最終裁定：R7 = HOLD。

下一輪只審查 Synthetic SHA 與正式驗證的隔離修正，不再重開 C12、C14A、C14B 或其他已接受事項。修復範圍限定 src/cli.mjs 與既有新增測試檔，不需重新進行整套治理設計。

在這項來源驗證邊界閉合之前，LOCAL_COMMIT 維持 HOLD；Push、Thread Resolution 與 Merge 仍禁止。