Triad-Flow｜PR #39 G4 系統性修復 R6 再覆核裁示

裁示識別碼：PR39-SCHEMA2-G4-REMEDIATION-IMPLEMENTATION-REVIEW-R6
基準 Commit：ec750e6010edd8d6f3fb8007a59994644b98862c

HOLD · 原裁定維持

裁示結論：本次不核發 LOCAL_COMMIT 授權。

本次重新上傳的兩份 R6 補丁，經 SHA-256 與逐位元組比對，確認與上一輪已審查的 R6 補丁完全相同。因此，前次指出的 C13 Fixture 隔離問題尚未獲得新的程式修復。

一、實體補丁獨立核驗

項目

	

核驗結果




Tracked Patch SHA-256

	

29cbbe24…76ff02362，MATCH




New Test Patch SHA-256

	

abcd069a…9aacab，MATCH




與上一輪 R6 補丁比較

	

兩檔均完全相同




修改檔案

	

4 個既有程式檔＋1 個新測試檔




五檔白名單

	

PASS




四個修改前 Blob

	

與 GitHub 指定 HEAD 一致




新測試案例

	

32 項




新測試檔語法

	

PASS




PR #39

	

OPEN、未合併

二、仍未解除的 C13 阻擋

R6 的 src/cli.mjs 仍允許下列條件宣告 Fixture：

JavaScript
options.allowMissingRepo === true

以及透過 options.verifierAdapter.isMock、modelName 或 providerName 包含 mock 進行辨識。

當正式 --verify-with 流程未指定 --strict，但呼叫端設定上述旗標時，仍可能進入：

JavaScript
if (isExplicitInMemoryFixture && !strictArg) {
  // 跳過 Repository Root 失敗標記
}

這表示呼叫端控制的測試旗標仍可使正式驗證流程跳過 EXACT_HEAD_CONTEXT_FAILED 的產生分支。

C13 的完整安全契約尚未成立。 現有測試證明一般正式 Adapter 在無 Root 時會受阻，但沒有覆蓋正式驗證與 Fixture 旗標同時存在的衝突情境。

三、新測試 Patch 的空白問題已確認原因

本次另外獨立核對了所提報的測試 Blob：

Patch 宣告新 Blob：e4ed664f17d130958a2b501d7cb780968c16c952

一般 git apply 後的實際 Blob：1cc5c9ec7b88cab5b7241a0a9420e44675dd90a6

使用 git apply --whitespace=fix 後：與宣告的 e4ed664… 一致

原因是 Patch 末尾多了一個空白行。嚴格檢查：

Bash
git apply --check --whitespace=error pr39-r6-new-test.patch

仍會回報 new blank line at EOF。

這也解釋了為何本地 git diff --check 可能顯示正常：它預設不檢查尚未追蹤的新測試檔。

此項屬於交付品質問題，並非新的安全缺陷。

四、R7 最小補正指令

本輪不重新開啟已驗收的 C12、C14A、C14B。

只須處理兩件事：

封閉 C13 正式驗證與 Fixture 的混用路徑。 只要執行正式 --verify-with Clean Challenge，即不得以 allowMissingRepo、testFixture、isMock 或 Adapter 名稱豁免可信 Repository Root 驗證。補上正式驗證與上述 Fixture 旗標同時存在時的負向測試，直接檢查 Context Gap 與最終 Gate。

修正新測試 Patch 的末尾空白行。 重新產生完整 Patch、更新 SHA-256 與 Git Blob 收據，確保嚴格空白檢查通過。

純記憶體 Fixture 可以保留，但必須與正式驗證權限隔離，不能藉由標記自己是 Fixture 而取得正式 Clean Approval。

五、正式治理決議

PR39-SCHEMA2-G4-REMEDIATION-IMPLEMENTATION-REVIEW-R6

治理項目

	

裁定




Patch 指紋與來源

	

VERIFIED




五檔修改白名單

	

VERIFIED




父節點 Blob 一致性

	

VERIFIED




C12

	

ACCEPTED




C14A／C14B

	

維持前次接受狀態




C13 Fixture 隔離

	

HOLD




新測試 Patch 空白檢查

	

CORRECTION_REQUIRED




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

本次未獨立執行全庫 npm test，因此提報的測試數量仍屬實施團隊收據，未升格為獨立重現結果。

最終裁定：R6 = HOLD_FOR_C13_FIXTURE_BOUNDARY。

下一輪直接進入 R7 針對性驗收。由於這次兩份補丁與已審查的 R6 完全相同，無須再次提交相同材料；只需提供真正修正 C13 邊界及 Patch 空白問題的新版本。

本次未建立 Commit、未 Push，也未回覆或關閉任何 GitHub Review Thread。