Triad-Flow｜PR #39 系統性修復 R4 獨立驗收

裁示識別碼：PR39-SCHEMA2-G4-REMEDIATION-IMPLEMENTATION-REVIEW-R4
審查基準：ec750e6010edd8d6f3fb8007a59994644b98862c

一、實體補丁核驗結果

本次已直接讀取 R4 的兩份原始 Patch，並進行檔案指紋、修改範圍與新增測試檔驗證。

驗收項目

	

核驗結果




Tracked Patch SHA-256

	

與提報 021592c9…e67f2e3 一致




New Test Patch SHA-256

	

與提報 c6d6a524…856be3e 一致




四個既有程式檔案

	

均在授權白名單內




修改前 Blob

	

均與指定 GitHub HEAD 一致




新增測試檔

	

僅一檔，位於授權路徑




新測試檔 Git Blob

	

09e32a8，與提報一致




新測試檔隔離套用

	

PASS




node --check

	

PASS

R3 的實體補丁交付、檔案範圍與 Blob 基準問題可繼續維持 VERIFIED，不必重新審查。

不過，R4 仍存在安全測試沒有真正到達所宣稱驗證路徑的問題。程式存在防護條件，與測試已證明該防護條件有效，是兩件不同的事。

二、C14B：程式判斷已修正，但端到端測試尚未證明修復閉合

R4 將註冊結果判定改為：

JavaScript
registrationSucceeded = Boolean(
  regResult &&
  typeof regResult === "object" &&
  regResult.ok !== false &&
  regResult !== null
);

這次已能正確拒絕 null、undefined 與 false。原先 R3 指出的 null 被誤判成功問題，在此程式分支已修正。

但新增 SYSTEMIC-C14B 測試存在證據缺口。

測試先直接呼叫 Registry，確認無效 Package 被拒絕；隨後雖然執行 runDogfoodReview()，傳入的外部 Package 卻缺少基本必填欄位，包括 schemaVersion、budgetAccounting 等。

這個 Package 在進入可信註冊之前，就可能被原有的結構驗證擋下。

因此，即使測試結果是 Clean Approval 被阻止，也不能據此證明 Dogfood 呼叫端確實處理了 Registry 回傳 null 的情境。

目前裁定：

C14B 程式判斷：FIXED_IN_PATCH

C14B 呼叫端閉合證據：INSUFFICIENT_EVIDENCE

Thread rxCha：維持未解決

三、C13：新增測試仍漏掉 --strict 命令列參數

R4 的 CLI 修復保留了這項例外：

JavaScript
if (
  options.verifierAdapter &&
  typeof options.verifierAdapter.executeVerification === "function" &&
  !options.strict
) {
  // In-memory lifecycle test fixture
}

但是 runCli() 實際使用的 Strict 判斷是：

JavaScript
const strictArg =
  argv.includes("--strict") || Boolean(options.strict);

因此，下列呼叫會產生衝突：

JavaScript
runCli(
  ["review", "--verify-with=claude", "--strict"],
  io,
  {
    getChangeSet: () => changeSet,
    verifierAdapter: mockVerifier
    // 沒有提供 options.strict
    // 也沒有提供可靠 repoRoot
  }
);

在這個情境下：

strictArg === true，正式流程已進入 Strict。

!options.strict === true，新增的 Fixture 例外卻仍成立。

缺少 Repository Root 不會在該分支被標記為 contextExtractionFailed。

我已使用 Node.js 獨立重現這組條件判斷。這是明確的安全檢查豁免漏洞，不是單純的文件問題。

裁定：C13 = PARTIALLY_FIXED。 需要讓 Fixture 例外不得在 strictArg 成立時生效，並新增僅透過 argv 指定 --strict 的負向測試，直接斷言產生 EXACT_HEAD_CONTEXT_FAILED，不能只檢查最終退出碼。

四、C14A：偽造 Package 測試仍提前失敗

R4 的 SYSTEMIC-C14A-FORGED-CALLEE-REJECTION 已加入 schemaVersion、budgetAccounting，較 R3 完整。

但實際測試資料中的 fileCoverageManifest 項目仍缺少：

JavaScript
inspected: true,
calleesExtracted: []

指定 HEAD 的 validateContextPackageAuthenticity() 明確要求這兩個欄位。缺少時會在 Manifest 結構驗證階段直接回傳 false。

因此，該測試即使產生 EXACT_HEAD_CONTEXT_FAILED，也不能證明執行到了 Git 原始碼中的偽造 Callee 比對。

此外，測試實際斷言的是 EXACT_HEAD_CONTEXT_FAILED，並非 R4 提報聲稱的 CONTEXT_INTEGRITY_TAMPERED。

裁定：C14A = TEST_ORACLE_INSUFFICIENT。 必須使用通過所有前置結構檢查的 Package，再針對偽造 Callee 驗證真正的物理來源防線。

五、C14B 呼叫端測試的實際阻擋路徑

進一步追查 runDogfoodReview() 的執行條件後，確認 C14B 測試並未覆蓋所聲稱的路徑。

R4 測試傳入的 changeSet 沒有 repository.root，而現有 Dogfood 程式在處理外部 Package 前，先執行：

JavaScript
if (!isRepoValidObject) {
  contextExtractionFailed = true;
} else if (contextPackage) {
  // External Package validation and trusted registration
}

因此，該測試會先進入 Missing trusted repository root 的錯誤分支，無法用來證明可信註冊回傳 null 後的呼叫端處置。

R4 提報聲稱的 status: "ERROR"、contextPackage: null 也沒有出現在該測試的實際斷言中。測試主要檢查 Gate 不為 approve，以及存在 EXACT_HEAD_CONTEXT_FAILED。

這足以證明某條 Fail-Closed 路徑有效，卻不足以證明目標缺陷 C14B 已閉合。

六、R4 三項指定修復的分別裁定

R3 缺陷

	

R4 結果

	

裁定




C14B：註冊失敗被當成成功

	

成功條件已修正，測試未真正執行註冊失敗的呼叫端路徑

	

FIXED_PENDING_VERIFY




C12：缺席目標檔案時回退 Raw Diff

	

已明確設為空 Diff、產生 DIFF_TARGET_FILE_NOT_FOUND，並新增直接負向測試

	

FIXED_VERIFIED_IN_PATCH




C13：Repository Root 驗證豁免

	

已改善一般缺少 Root 情境，但 argv --strict 與 options.strict 不一致仍可繞過檢查

	

PARTIALLY_FIXED




C14A：偽造 Callee 測試契約

	

新增部分必填欄位，但測試仍可能在 Manifest 結構層提前失敗

	

TEST_CORRECTION_REQUIRED

R5 的最小修正範圍

本次可以明確縮小為三項工作：

**C13：**將 Fixture 例外與有效的 strictArg 綁定，確保 --strict 不會因 options.strict 未提供而跳過 Repository Root 檢查。新增對應負向案例。

**C14B：**建立可通過前置 Repository Root、ContextPackage 結構與 Metadata 檢查的測試情境，確實觸發 Registry 失敗，並驗證呼叫端清除不可信 Package、產生 Gap、拒絕 Clean Approval。

**C14A：**補全 fileCoverageManifest 的必要欄位，先證明測試資料通過結構檢查，再驗證偽造 Callee 被 Git 實體來源核對拒絕。

C12 暫無須重寫；只需在下一次回歸中保留其正反測試。

七、正式治理決議
PARTIAL_ACCEPTANCE · LOCAL_COMMIT HOLD

PR39-SCHEMA2-G4-REMEDIATION-IMPLEMENTATION-REVIEW-R4

治理項目

	

裁定




R4 Patch SHA-256

	

VERIFIED




五檔白名單

	

VERIFIED




父節點 Blob

	

VERIFIED




C12 指定修復

	

ACCEPTED




C13 完整修復

	

HOLD




C14B 端到端閉合

	

HOLD




C14A 測試契約

	

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

GitHub PR #39 已再次核實仍為 OPEN、未合併，HEAD 未變；目前 180 筆 Threads 中有 25 筆 Resolved，20 筆 Current P1 仍未解決。

R4 提報的 32/32 專屬測試、117/117 重點測試，以及全庫 1,256 PASS／4 SKIPPED 均登錄為 REPORTED_PASS。本次獨立執行了補丁檔案檢查、新測試檔隔離套用、Node 語法檢查與 C13 分支條件重現，但未能重跑完整儲存庫測試。

最終裁定：R4 = HOLD_FOR_TARGETED_VERIFICATION_AND_FIX。

R4 已實質解除 C12 的指定阻擋；C14B 的程式修正方向亦已接受。下一輪僅需針對上述三項補強，不必重新開啟已驗收的其餘聚類。

在證明 C13 不存在 Strict 豁免，且 C14A／C14B 測試確實命中預期安全防線之前，單一本地 Commit 仍不得執行。