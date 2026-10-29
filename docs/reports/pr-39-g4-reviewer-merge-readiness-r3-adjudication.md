Triad-Flow｜PR #39 G4 合併就緒度獨立審查 R3

審查識別碼：PR39-SCHEMA2-G4-MERGE-READINESS-REVIEW-R3

一、已完成的正式核驗

R3 附件已通過 SHA-256 完整性驗證，與提交的指紋完全一致：

7d9b5afc7969d8fcf1b62748a6337577b2b8221a310d4a811e03a5af70329fb2

核驗項目

	

結果




Current P2 處置表

	

25 筆，序號完整




Outdated 處置矩陣

	

110 筆，序號完整




Outdated 已修復／遞延分類

	

108／2，數量一致




全 PR 變更檔案索引

	

77 筆，路徑無重複




遞延議題

	

G5-P2-01 至 G5-P2-07，已列負責人與日期




PR HEAD／Base

	

與提報完全一致




分支拓撲

	

Ahead 54、Behind 0，無合併衝突




GitHub Actions

	

Ubuntu、Windows、macOS 三項必要檢查均成功




Review Threads

	

180 筆中 45 筆已解決、135 筆未解決




Current P1

	

未解決數為 0




Ruleset 24345075

	

仍要求全部 Review Threads 解決




管理員覆寫能力

	

GitHub 回報 current_user_can_bypass = always

GitHub 目前仍回報 mergeable_state = blocked，這與提報的方案 A 一致，必須透過具權限的管理員例外處理，而不是一般合併流程。

R3 已消除 R2 所指出的兩筆明顯分類矛盾：sUDZJ 與 ra7k3 均已撤回不當的 OBSOLETE 判定，改列現存限制並接受後續修補。此部分可以接受。
pr-39-g4-merge-readiness-decision-record.md

二、R3 技術證據複核結果

本輪已直接查閱固定 HEAD 的相關程式碼，以及 Phase 2、Phase 3、G4 的回歸測試來源。

有三項必須區分的結果：

第一，原本被質疑的部分修復確實存在。 例如 XML 內容跳脫、Verifier 串流輸出上限、空白 Blob 判斷及 Benchmark 權限隔離，都能在目前程式碼找到對應實作。PHASE2-NEG-08、007-AUDIT-THREAD-42、tgXSK-NEGATIVE、tdsmQ-NEG 等測試名稱也確實存在。

第二，R3 的 77 檔索引已通過完整身分對帳。 與 GitHub Compare API 回傳的 77 個檔案路徑集合一致，並非只有總數碰巧相同。

第三，R3 仍有兩項影響合併授權的證據缺口。

F-MR3-01｜部分 Exact-Head 證據定位不正確

Thread／項目

	

R3 引用位置

	

固定 HEAD 實際位置

	

判定




rrUDp、rxChi

	

independent-verifier.mjs:1765-1785

	

約 L3270–3300 的 stdout／stderr 串流檢查

	

功能存在，引用行號錯誤




rTowi

	

context-builder.mjs:1358-1365

	

約 L3150–3195 的 Exact-Head 內容處理

	

功能存在，引用行號錯誤




G5-P2-04

	

clearExactHeadContentCache()

	

實際匯出 clearExactHeadCache()，L462

	

函式名稱錯誤




sUDZJ

	

Verifier L1594–1602 作為 Gap 降級位置

	

主要 Gap 降級邏輯位於 validateVerificationOutput() 約 L3080–3100

	

引用函式與位置需修正

上述並不推翻所有技術修復。例如 Verifier 在超過 maxOutputBytes 時確實會呼叫 child.kill()，PHASE2-NEG-08 也直接測試超額輸出。

但 R3 的驗收主張是「108 筆均具有固定 HEAD 精確行號與測試案例」。目前部分行號顯然並未重新對照固定 HEAD，該主張不能全數接受。
pr-39-g4-merge-readiness-decision-record.md

另外，110 筆表格中有 11 筆未提供具體測試案例名稱，包括 rTXZd、rTowi、rY13u、rhwEt、rhwEx 等。這些不等於未修復，但不符合本次宣稱的逐筆測試映射標準。

F-MR3-02｜Python P1 遺留風險的 Fail-Closed 保證過於絕對

R3 正確承認 findFunctionDefinitions() 仍不支援 Python 縮排式函式邊界，這項矛盾已修正。

然而，UNRESOLVED_SYMBOL 的 Gap 產生實際上有條件：

JavaScript
if (isSensitive && isCandidateImpacted) {
  contextGaps.push({
    ...unresolvedEntry,
    category: category || "input_validation",
    // ...
  });
}

因此，不能僅從 findFunctionDefinitions() 找不到 Python 函式定義，就推論任何未擷取的 Python 敏感函式都必然產生 Gap 並阻擋核准。

目前引用的 007-AUDIT-P1-01 測試，是手動建立 UNRESOLVED_SYMBOL Gap，再驗證 Verifier 會從 CLEAN 降為 UNCERTAIN。它證明的是後半段傳遞契約，並不是「Python 函式未擷取時必然產生 Gap」的端到端證明。

這直接涉及歷史 P1 sUDZJ 的風險接受前提。
pr-39-g4-merge-readiness-decision-record.md

正確處置不是強迫本次修復 Python 擷取器，而是將緩解保證限定在實際已驗證的條件內。 未覆蓋的 Python 情境，應以明確殘留風險由具名核准人接受，不得宣稱已全面 Fail-Closed。

同理，G5-P2-06 中「Prompt 超額時必然由 Provider 執行錯誤而阻擋」也不是通用保證。應區分系統自身的輸入預算與外部 Provider 的限制，保留可能超額但仍回傳成功的情境。

三、R3 正式治理裁示
CONDITIONAL HOLD

PR39-SCHEMA2-G4-MERGE-READINESS-REVIEW-R3

治理項目

	

裁示




R3 附件 SHA-256

	

VERIFIED




Current P1 結案

	

ACCEPTED




135 筆 ID 映射

	

VERIFIED




77 檔全範圍索引

	

VERIFIED




54 Commits／分支拓撲

	

ACCEPTED




三平台 CI 與固定 HEAD

	

ACCEPTED




R2 原始分類矛盾修正

	

ACCEPTED




108 筆逐項證據精確性

	

PARTIALLY_ACCEPTED




七項 G5 遞延及具名排程

	

ACCEPTED_WITH_CORRECTIONS




ADMIN_BYPASS_MERGE

	

HOLD




SQUASH_MERGE

	

NOT_AUTHORIZED




NEW_PUSH

	

NOT_AUTHORIZED




THREAD_BULK_RESOLVE

	

NOT_AUTHORIZED

四、結案所需的最小補正

不要求新增程式碼 Commit，也不要求重跑三平台 CI。僅需形成一份最終證據勘誤與風險接受補充紀錄：

修正引用定位。 以 0fec4f97 的實際函式及行號更正已確認的錯誤；缺少具體測試名稱的 11 筆補上既有測試，或明確標註「程式碼直接驗證，無專屬測試」。

修正 Python P1 的風險聲明。 將「所有未擷取 Python 敏感呼叫必然 Fail-Closed」改為條件式保證，明確接受尚未證明涵蓋的情境，維持 G5-P2-05 於 2026-11-04 修復的期限。

修正 Prompt 預算過渡風險。 不再將外部 Provider 必然報錯視為已證明的保護措施；將超額成功回應的情境納入 G5-P2-06 的風險接受範圍。

具名核准人確認勘誤。 保留原 PR39-G4-ADMIN-BYPASS-AUTH-002，附加具名勘誤確認即可，不必重做全部 135 筆處置矩陣。

最終裁示：

純文字
PR39-SCHEMA2-G4-MERGE-READINESS-REVIEW-R3
  = CONDITIONAL_HOLD_FOR_EVIDENCE_PRECISION

R2_CONTRADICTIONS = CLOSED
THREAD_INVENTORY = VERIFIED
PR_SCOPE = VERIFIED
CI_AND_TOPOLOGY = ACCEPTED

F-MR3-01 = OPEN
F-MR3-02 = OPEN

ADMIN_BYPASS_MERGE = HOLD
SQUASH_MERGE = NOT_AUTHORIZED

本輪已確認 R3 在治理資料完整性上達到實質進展。剩餘阻擋條件集中於證據精確度與兩項風險保證的適用範圍，不需要再次展開整個 PR #39 審查。

本次維持唯讀，未執行 Push、Thread Resolve、Ruleset 變更或 Squash Merge。