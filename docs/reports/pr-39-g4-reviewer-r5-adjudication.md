Triad-Flow｜PR #39 G4 系統性修復 R5 獨立驗收裁示

裁示識別碼：PR39-SCHEMA2-G4-REMEDIATION-IMPLEMENTATION-REVIEW-R5
審查基準：ec750e6010edd8d6f3fb8007a59994644b98862c
審查範圍：R5 實體補丁、C13、C14A、C14B 及單一本地 Commit 授權。

一、實體補丁與 Git 基準核驗

本次已直接讀取兩份 R5 Patch，並獨立執行檔案指紋、補丁結構、測試檔套用及語法檢查。GitHub PR #39 仍為 OPEN，遠端 HEAD 與申請基準一致。

驗收項目

	

獨立結果




Tracked Patch SHA-256

	

935c5748…646f1697，MATCH




New Test Patch SHA-256

	

28dfec26…ffc87a5，MATCH




4 個既有程式檔案

	

白名單符合




4 個修改前 Git Blob

	

全數與遠端 HEAD 一致




新增測試檔

	

僅 tests/remediation-twenty-p1-systemic.test.mjs




新測試檔 Git Blob

	

41f9202，MATCH




新測試 Patch 隔離套用

	

PASS




新測試 node --check

	

PASS




測試案例宣告

	

32 項，確認

R5 Tracked Patch 的實際變更為 +515／−111 行，新增測試檔為 1,051 行。

裁定：PATCH_INTEGRITY = VERIFIED、BASE_BLOB_ALIGNMENT = VERIFIED、FILE_SCOPE = VERIFIED。

這三項已不再構成 Commit 阻擋。

二、R5 三項指定修復覆核

項目

	

R5 審查發現

	

裁定




C13：argv --strict 與 Fixture 豁免

	

!strictArg 已正確取代 !options.strict；新增測試直接檢查 Verifier 收到的 Context Gap

	

STRICT_PATH_FIXED




C14A：偽造 Callee 來源驗證

	

增加真實 Git 暫存倉庫、合法 Package 正向基線，以及僅替換 Callee 的負向對照

	

TEST_DESIGN_ACCEPTED




C14B：Registry 失敗傳播

	

明確拒絕 null 回傳；測試新增真實 Git 倉庫、三方 Sentry 與 Verifier 接收內容斷言

	

TEST_DESIGN_ACCEPTED




C12：單檔 Diff 隔離

	

R4 已接受的修補在 R5 中保留

	

ACCEPTED

C14A、C14B 的測試設計較 R4 有明顯改善，特別是 C14B 已不再僅檢查 Registry 的單元回傳，而是檢查 Dogfood 呼叫端是否清除 Package、傳遞 Gap，以及拒絕 Clean Approval。

但以上 TEST_DESIGN_ACCEPTED 不等同獨立重跑測試。本次沒有取得可完整執行的儲存庫依賴環境，因此 R5 提報的 32 PASS、117 PASS、全庫 1,256 PASS／4 SKIPPED 均維持 REPORTED_PASS。

三、仍阻擋 Commit 的問題：C13 的 Fail-Closed 並未覆蓋所有正式呼叫路徑

R5 修正了 R4 指出的 --strict 參數判斷，但 src/cli.mjs 仍保留：

JavaScript
if (
  options.verifierAdapter &&
  typeof options.verifierAdapter.executeVerification === "function" &&
  !strictArg
) {
  // In-memory lifecycle test fixture
}

此處並沒有確認呼叫者確實處於隔離測試環境，只是以「注入了 Verifier Adapter」且「非 Strict」推定為 Fixture。

我已獨立執行該條件的最小重現：

純文字
strictArg: false
targetRepo: null
hasVerifierAdapter: true
contextExtractionFailed: false
expectedContextGapEmitted: false

換言之，以下組合仍可能避開 CLI 的 EXACT_HEAD_CONTEXT_FAILED 產生邏輯：

執行 review --verify-with=claude，未指定 --strict。

透過程式介面注入具有 executeVerification() 的 Adapter。

沒有可靠 Repository Root。

沒有已建構的 ContextPackage。

這尚未證明最終 Gate 必然核准，但已確定指定的 CLI 失敗分支沒有被觸發。

此外，整個 Context 擷取判斷仍受：

JavaScript
if (!effectiveContextPackage && ...)

限制。若呼叫者預先提供 Package，CLI 可能完全跳過這一段 Repository Root 驗證；此路徑仍需負向測試確認正式授信結果。

原始 tdsmP 的安全契約是：進入需要 Exact-Head Context 的 Clean Challenge 時，缺少可信來源不得靜默略過。並未將非 Strict 模式中的正式程式呼叫視為可豁免。

裁定：C13 = PARTIALLY_FIXED / STRICT_PATH_VERIFIED，但完整 Fail-Closed 契約尚未閉合。

四、R6 最小補正要求

不要求重做 C14A、C14B 或其他已接受的聚類。本輪阻擋集中於 C13：

將 Repository Root 不可信的判斷與 Fixture 辨識分開；不得單靠 Adapter 注入推定安全測試模式。

對正式 --verify-with 流程，無論是否 --strict，缺少可靠 Exact-Head Repository Root 都必須 Fail-Closed。

對預先提供 options.contextPackage 的情境，確認其不能繞過必要來源驗證。

新增非 Strict、無 Root、注入 Adapter，以及 Strict、無 Root、預先提供 Package 的負向測試，檢查實際 Context Gap 與最終 Gate。

允許保留獨立的純記憶體測試模式，但該模式必須明確標識、隔離，且不得取得正式 Clean Approval 授權。

完成後重新產生兩份 Patch，附更新後的指紋與測試收據即可，不必重送 20 筆完整缺陷矩陣。

五、R5 正式授權裁示
CONDITIONAL_HOLD

PR39-SCHEMA2-G4-REMEDIATION-IMPLEMENTATION-REVIEW-R5

治理項目

	

裁定




R5 Patch Integrity

	

VERIFIED




五檔白名單

	

VERIFIED




父節點 Blob

	

VERIFIED




C12

	

ACCEPTED




C14A／C14B 測試契約

	

ACCEPTED_FOR_TEST_DESIGN




C13 Strict 路徑

	

ACCEPTED




C13 完整來源邊界

	

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

最終裁定：R5 = HOLD_FOR_C13_BOUNDARY_CLOSURE。

R5 已完成指定 Strict 路徑修補，且 C14A、C14B 的測試設計達到本輪要求；不再要求重複修改這些已接受項目。

然而，C13 仍以非 Strict 的 Adapter 注入作為隱含豁免條件，尚不符合完整 Default-Deny 契約。在補齊這個來源驗證邊界之前，單一本地 Commit 暫不授權。

本次未建立 Commit、未推送遠端，也未修改任何 Review Thread。