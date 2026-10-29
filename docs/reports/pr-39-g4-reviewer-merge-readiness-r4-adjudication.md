Triad-Flow｜PR #39 G4 合併就緒最終審查 R4

審查識別碼：PR39-SCHEMA2-G4-MERGE-READINESS-REVIEW-R4

一、文件完整性與遠端狀態核驗

R4 附件的 SHA-256 驗證通過，與提報值完全一致：

f0b642c8819f82894cfa78891bf287820a0ec417e93321e82c414f1cb85adfa8

但附件實際大小為 147,050 bytes，不是提報的 129,116 bytes。這是文件中繼資料的勘誤事項；內容雜湊一致，故不影響附件身分確認。

核驗項目

	

結果




固定 HEAD

	

0fec4f97f46c892a8f5eee1d606660e07d130d54，吻合




固定 Base／目前 main

	

93a63e30a039239212d54db501ce2b0655f3bd49，吻合




PR 狀態

	

OPEN，尚未合併




分支拓撲

	

Ahead 54、Behind 0，無合併衝突




全範圍索引

	

77 筆，序號完整、路徑無重複




Current P2

	

25 筆：10 已修復、1 已緩解、14 遞延




Outdated Threads

	

110 筆：108 已列修復、2 列 G5 遞延




GitHub 未解決討論串

	

135 筆，其中 Current P1 為 0




三平台必要 CI

	

Ubuntu、Windows、macOS 均 SUCCESS




Ruleset 24345075

	

仍要求所有 Review Threads 解決




管理員覆寫能力

	

GitHub 回報 current_user_can_bypass = always

因此，R3 已接受的 PR 範圍、分類數量、CI 與分支拓撲結論，於 R4 核驗時仍有效。GitHub 目前的 mergeable_state 仍為 blocked，原因尚不能直接等同於所有規則皆已滿足；一般合併與管理員覆寫必須明確區分。

二、R4 補正內容的獨立複核

R4 已經實質修正 Python 風險聲明，但測試證據與 Prompt 超額範圍仍有可重現的不一致。

F-MR3-01｜尚未完全關閉

以下為直接對照固定 HEAD 原始碼與測試檔案得到的結果。

R4 證據

	

固定 HEAD 核驗結果

	

裁定




rrUDp／rxChi：CliVerifierAdapter.verify

	

實際方法為 CliVerifierAdapter.executeVerification()，約 L3158；串流限制實作在 L3270–3305

	

行號修正正確，方法名稱仍錯




#66 sL8VK：TEST-R3-01、TEST-R3-02、CHALLENGE-R3

	

這些測試識別碼不存在；實際為 PHASE3-NEG-03-01 等及 ADV-R3-01 等

	

測試名稱未通過




#89 slql5：TEST-R5-01、TEST-R5-02

	

兩個識別碼不存在；實際有 PHASE3-NEG-05-01、PHASE3-NEG-05-02 等

	

測試名稱未通過




#77 sPmwl：SYSTEMIC-C02-MULTILINE-STRING-BRACE

	

不存在；固定 HEAD 的 C02 實際為 SYSTEMIC-C02-COMMENTED-DEF-EXCLUSION

	

證據錯配




#81 sUDZV：SYSTEMIC-C05-THIS-RECEIVER-ENCLOSING-CLASS

	

不存在；固定 HEAD 的 C05 實際為 SYSTEMIC-C05-DIVISION-CHAIN-PRESERVATION

	

證據錯配




#17 rTowi：兩項既有測試

	

測試確實存在，但前者檢查空白內容處理，後者檢查空白檔案的 Omission 行號，不是完整的 Git Exact-Head 空 Blob 查找測試

	

可列相關測試，不宜宣稱直接證明

這表示 R4 確實補上了測試欄位，但「106 筆均有精確對應的既有測試案例」仍不能作為全數驗證通過的結論。尤其 C02、C05 是引用真實存在的測試檔案，卻填入不存在且測試主題不同的案例名稱，不能視為純粹的排版誤差。
pr-39-g4-merge-readiness-decision-record.md

F-MR3-02｜Python 部分可關閉，Prompt 部分仍需修正

Python sUDZJ／G5-P2-05：接受關閉。

R4 明確承認，只有 isSensitive && isCandidateImpacted 成立時才會產生對應 Gap；未偵測或未判定受影響的 Python 呼叫可能不被阻擋。並且正確區分手動注入 Gap 的測試與端到端擷取測試。風險接受人及 2026-11-04 的期限也已記錄。這符合 R3 的補正要求。
pr-39-g4-merge-readiness-decision-record.md

Prompt G5-P2-06：風險方向已修正，但上界宣稱仍不成立。

R4 已承認內部 maxBytes 超限時，外部 Provider 仍可能成功回應，這部分正確。

然而，附件繼續宣稱「最多超額約 35–40 KB」。固定 HEAD 的 buildEvidenceReviewPrompt() 會附加 fileList、contextGapsBlock、patchObjective 等內容，並未在完整組裝後執行總位元組硬上限檢查。其中 formatContextGaps() 會展開輸入的 Gap 陣列，沒有可據此證明 35–40 KB 最大超額的通用限制。

因此，35–40 KB 只能列為特定輸入條件下的估計，不可列為最壞情況上界。同時，「外部 Provider 不會報錯」應修正為「外部 Provider 可能成功回應」，不應把外部服務的行為寫成確定事實。
pr-39-g4-merge-readiness-decision-record.md

三、R4 正式裁示
CONDITIONAL HOLD

PR39-SCHEMA2-G4-MERGE-READINESS-REVIEW-R4

治理項目

	

裁示




R4 附件雜湊

	

VERIFIED




25／110／77 筆結構對帳

	

VERIFIED




固定 SHA 與三平台 CI

	

ACCEPTED




F-MR3-01

	

PARTIALLY_REMEDIATED_OPEN




F-MR3-02 Python

	

CLOSED




F-MR3-02 Prompt

	

PARTIALLY_REMEDIATED_OPEN




R4 具名風險接受聲明

	

RECORDED




ADMIN_BYPASS_MERGE

	

HOLD




SQUASH_MERGE

	

NOT_AUTHORIZED

最小結案要求

不要求重新修改程式碼、不要求重新執行 CI，也不要求重審 54 個 Commits。僅需在既有 R4 決策記錄附加一份短版勘誤：

更正上述不存在或錯配的測試名稱，並將缺乏直接回歸測試者明確標註為「程式碼直接驗證」或「相關測試，非直接證明」。

將 CliVerifierAdapter.verify 修正為 CliVerifierAdapter.executeVerification，並更正其他受影響的索引。

撤回 Prompt 超額「最多 35–40 KB」的通用上界宣稱，具名接受尚無完整硬上限的實際殘留風險。

更新 PR39-G4-ADMIN-BYPASS-AUTH-002-ERRATA-R4 的勘誤確認，使最終授權依據與修正後的證據一致。

最終治理決議
純文字
PR39-SCHEMA2-G4-MERGE-READINESS-REVIEW-R4
  = CONDITIONAL_HOLD_FOR_EVIDENCE_MAPPING

F-MR3-01 = OPEN
F-MR3-02-PYTHON = CLOSED
F-MR3-02-PROMPT = OPEN

PR_HEAD_AND_BASE = VERIFIED
CI_AND_TOPOLOGY = ACCEPTED
G5_RISK_REGISTER = ACCEPTED_WITH_ERRATA

NEW_PUSH = NOT_REQUIRED
CI_RERUN = NOT_REQUIRED

ADMIN_BYPASS_MERGE = HOLD
SQUASH_MERGE = NOT_AUTHORIZED

目前真正阻擋合併的不是程式碼測試或 Git 分支狀態，而是最終審計紀錄仍有錯誤證據映射及未獲證實的風險上界。 這些修正均屬文件層級，無須另行開展技術修復輪次。

本輪未執行 Push、Thread Resolve、Ruleset 變更或 Squash Merge。