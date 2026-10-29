Triad-Flow｜PR #39 G4 合併就緒度獨立審查 R1

裁示識別碼：PR39-SCHEMA2-G4-MERGE-READINESS-REVIEW-R1
審查目標：arcobaleno64/triad-flow PR #39

一、即時驗證結果

已直接查詢 GitHub 的 PR、180 筆 Review Threads、主分支 Ruleset 24345075、Review 紀錄與三平台 CI。

20/20

指定 Current P1 已解決

3/3

跨平台 CI 成功

135

其餘未解決 Thread

審查項目

	

GitHub 實際結果

	

裁定




PR 狀態

	

OPEN，非 Draft，未合併

	

VERIFIED




HEAD

	

0fec4f97f46c892a8f5eee1d606660e07d130d54

	

VERIFIED




Base

	

main，SHA 93a63e30a039239212d54db501ce2b0655f3bd49

	

VERIFIED




GitHub mergeable

	

true

	

PASS




GitHub mergeable_state

	

blocked

	

BLOCKED




20 筆指定 Current P1

	

20/20 Resolved

	

PASS




全部 Review Threads

	

45 Resolved／135 Unresolved

	

VERIFIED




三平台必要 CI

	

Ubuntu、Windows、macOS 全部 SUCCESS

	

PASS




Ruleset

	

Active，包含 required_review_thread_resolution

	

VERIFIED

重要區別：mergeable = true 只表示 Git 可合併，不代表符合主分支保護政策。

目前 GitHub 明確回傳 mergeable_state = blocked，因此尚不能核發一般 Squash Merge 授權。

二、剩餘 135 筆分類完全吻合

這部分我沒有採信卷宗數字，而是重新統計全部 180 筆 Thread 的原始 P1／P2 標記與 isOutdated、isResolved 狀態。

未解決 Thread 分類

	

數量

	

獨立核驗




Outdated P1

	

88

	

MATCH




Outdated P2

	

22

	

MATCH




Current P2

	

25

	

MATCH




Current P1

	

0

	

MATCH




合計

	

135

	

MATCH

因此，「20 筆指定 Current P1 全數結案」及「目前不存在未解決的非 Outdated P1」兩項結論成立。

但 Outdated 是 GitHub 的 Diff 位置狀態，不是「缺陷已修復」的技術證明。同樣，P2 代表較低優先級，不代表可無條件接受風險。

這兩者是接下來合併授權的主要治理問題。

三、Ruleset 與合併拓撲核驗

已取得 Ruleset 24345075 的完整設定，確認：

required_linear_history 已啟用。

required_review_thread_resolution = true。

三個必要 CI Context 與成功的 Job 名稱一致。

strict_required_status_checks_policy = true。

required_approving_review_count = 0。

當前 GitHub 使用者的 current_user_can_bypass = always。

另外，透過 GitHub Commit Compare API 確認：

分支拓撲

	

結果




main HEAD

	

93a63e30a039239212d54db501ce2b0655f3bd49




Merge Base

	

與 main HEAD 相同




Ahead

	

54 commits




Behind

	

0 commits




PR 全部變更檔案

	

77 檔

這裡還有一項不能忽略的範圍差異：

G4 完成驗收的是七檔修復與 20 筆指定 Thread；正式 Squash Merge 對象則是整個包含 54 個 Commit、77 個變更檔案的 PR #39。

G4 驗收成功，不會自動取代整個 PR 的交付範圍與剩餘風險驗收。

管理員覆寫在權限設定上確實可用，但這只證明能夠覆寫，尚不足以證明應當覆寫。

四、發現兩項合併治理缺口
F-MR1-01：剩餘 P2 並非全屬風格或無影響建議

我進一步檢查了 25 筆 Current P2 的原始內容，並抽查固定 HEAD 的相關程式碼。

其中至少有下列實質風險值得正式處置：

原始議題

	

程式碼核驗

	

可能影響




Checkpoint 名稱碰撞

	

staged-review.mjs 將不同的特殊字元統一替換為 _

	

不同執行可能共用 Checkpoint，影響恢復狀態




Verifier Advisory 遺失

	

review-run-report.mjs 的報告摘要取自 Consensus Findings，沒有完整保存 Gate Advisory

	

稽核報告可能遺漏非阻擋的驗證器發現




模型身分與實際執行不一致

	

dogfood-review.mjs 的 Clean Challenge actualModel 固定填入 Claude 資訊

	

使用自訂 Verifier Adapter 時可能產生錯誤的執行溯源




Exact-Head Cache 無界增長

	

git-collector.mjs 使用模組層級 Map，未見容量淘汰機制

	

長時間執行可能增加記憶體負擔

這些並不必然都需要在 G4 修復，但不能直接歸類為「只有程式風格問題」。

另一方面，也不是每則 P2 都仍然成立。例如部分 Thread 指稱 Run ID 可以穿越 Checkpoint 目錄，但目前 CheckpointStore.getCheckpointPath() 已有安全字元轉換與路徑邊界檢查。該原始反例至少不能不經重新驗證就當成已確認缺陷。

裁定：P2_DEFERRAL_RISK_ACCEPTANCE = INSUFFICIENT_EVIDENCE。

F-MR1-02：110 筆 Outdated Thread 尚無可審計的失效證明

目前可以直接確認的是 110 筆 isOutdated = true，其中 88 筆為 P1。

但提報中的「全數已被後續重構取代，技術上失效」，尚缺少逐筆或同根因聚類的對應修復證據。

即使 GitHub 不再將某條留言附著於現行 Diff，原始缺陷也可能移至其他函式、其他檔案，或在重構後仍然存在。

因此，這 110 筆不可僅以 Outdated 狀態作為批次 Resolve 或管理員覆寫的完整理由。

裁定：HISTORICAL_THREAD_RISK_DISPOSITION = PENDING。

五、方案 A／B 裁決

方案 A：受控管理員覆寫

CONDITIONAL PATH

允許作為後續合併路徑，但目前不授權執行。必須先完成剩餘風險的獨立審查、明確豁免及整個 PR 的合併範圍確認。

方案 B：135 筆批次 Resolve

NOT AUTHORIZED

不接受僅因 Outdated 或 P2 標記就直接結案。這會讓 GitHub 呈現 180/180 全綠，卻無法證明 135 筆缺陷已得到真正處置。

正式選擇方案 A 作為優先候選，但暫緩管理員覆寫與 Squash Merge 授權。

這不是要再重新審查已結案的 20 筆 Current P1，而是將尚未取得證據的 135 筆轉成可追溯的接受、修補、駁回或遞延決策。

六、下一輪唯一需要補齊的證據

授權進入：

PR39-SCHEMA2-G4-MERGE-READINESS-REVIEW-R2

下一輪只需提交一份整合的 Merge Readiness Decision Record，包含：

110 筆 Outdated Thread 處置矩陣： Thread ID、原缺陷、目前程式碼位置、修復或失效證據、審查結論。允許依相同根因聚類，但仍須保留每筆身分映射。

25 筆 Current P2 風險登記： 確認有效性、影響、是否接受遞延、後續 G5／PR 或 Issue、責任歸屬與處理期限。對涉及權限、資料完整性、稽核溯源的項目，須明確給出接受理由。

PR 全範圍確認： 對 54 個 Commit、77 個變更檔案的合併內容建立範圍收據，確認不存在尚未裁決的重大交付問題。

覆寫例外核准： 由有權負責人具名接受剩餘風險，明確記錄覆寫的是 required_review_thread_resolution，以及為何本次例外合理。

在此之前，不必增加程式 Commit，也不要求無目的地重跑既有三平台 CI。

七、正式治理狀態

治理項目

	

R1 裁定




20 筆指定 Current P1

	

CLOSED · 20/20




Git 合併拓撲

	

MERGEABLE




三平台 CI

	

ACCEPTED




Ruleset 24345075

	

VERIFIED




PR Merge State

	

BLOCKED




110 筆 Outdated 處置

	

PENDING




25 筆 Current P2 風險接受

	

PENDING




整個 PR 合併範圍

	

REVIEW_REQUIRED




管理員覆寫候選方案

	

A · CONDITIONALLY_SELECTED




THREAD_BULK_RESOLVE

	

NOT_AUTHORIZED




SQUASH_MERGE

	

HOLD




ADMIN_BYPASS_MERGE

	

NOT_AUTHORIZED

最終裁示：PR39-SCHEMA2-G4-MERGE-READINESS-REVIEW-R1 = CONDITIONAL_HOLD。

G4 的指定 Current P1 修復與結案工作已通過驗收。現在阻擋合併的，不是 CI 或程式衝突，而是整個 PR 的剩餘風險尚未完成正式處置，以及主分支明確要求所有 Review Threads 必須解決。

下一輪若能證明剩餘項目已合理處置，便可評估一次性、限定 HEAD／Base SHA、具完整風險接受紀錄的管理員覆寫授權；不必為了追求 GitHub 畫面全綠而製造 135 筆缺乏依據的結案紀錄。

本輪僅執行唯讀審查，未 Resolve、Push、覆寫 Ruleset 或 Merge。