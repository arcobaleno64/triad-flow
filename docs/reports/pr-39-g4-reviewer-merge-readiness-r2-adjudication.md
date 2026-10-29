Triad-Flow｜PR #39 G4 合併就緒度獨立審查 R2

審查識別碼：PR39-SCHEMA2-G4-MERGE-READINESS-REVIEW-R2
審查基準 HEAD：0fec4f97f46c892a8f5eee1d606660e07d130d54
目標 Base：93a63e30a039239212d54db501ce2b0655f3bd49

一、正式附件與 GitHub 狀態核驗

已讀取本次兩份完整附件，並以 GitHub 的 PR、Ruleset、Review Threads 與 CI 原始紀錄交叉核對。

項目

	

獨立驗證結果




Merge Readiness Decision Record

	

完整讀取，含 25 筆與 110 筆處置表




135 筆 Thread JSON Inventory

	

135 筆，無重複 ID




JSON 與 Markdown 明細

	

25／110 筆數一致




JSON 與 GitHub 未解決 Thread 身分集合

	

135/135 完全一致




指定 Current P1

	

20/20 Resolved




其餘未解決

	

88 Outdated P1、22 Outdated P2、25 Current P2




PR HEAD／Base

	

與提報完全一致




分支拓撲

	

Ahead 54、Behind 0、77 檔變更




三平台必要 CI

	

3/3 SUCCESS




GitHub mergeable

	

true




GitHub mergeable_state

	

blocked




Ruleset 24345075

	

Active，要求全部 Review Threads 解決




管理員覆寫權限

	

current_user_can_bypass = always

兩份附件的 SHA-256 也已計算，可作為後續審查版本錨點：

Decision Record：e26dea99a75f351a3a764845c94935959e3164e5b7352602a1feb7921aaf873f

Inventory JSON：bb2df2f71b17aa5aeca43841c360dae8144b694470ba51c4d5869520876a10f0

結論：本次已完成真實的 135 筆身分對帳，不再存在清單缺漏問題。 但身分對帳成功，仍須與每筆缺陷的技術處置是否成立分開判定。

二、阻擋管理員覆寫的實質發現

本輪的主要問題已不是附件缺漏，而是部分處置結論與固定 HEAD 的實際程式碼互相矛盾。

F-MR2-01｜Outdated P1 與 G5 遞延項目存在直接衝突
BLOCKING

Thread

	

原始問題

	

R2 處置

	

獨立審查




sUDZJ，Outdated P1

	

Python 函式應以縮排辨識區塊

	

OBSOLETE_REPLACED_BY_C01_C12

	

與現行程式碼矛盾




rTXZk，Current P2

	

Python 函式縮排辨識

	

ACCEPT_DEFERRAL，G5-P2-05

	

同一根因仍存在




rhwE4，Current P2

	

Python 函式定義不能依賴大括號

	

ACCEPT_DEFERRAL，G5-P2-05

	

同一根因仍存在

固定 HEAD 的 src/core/context-builder.mjs 仍存在：

JavaScript
if (isDeclarationOnly || !hasBrace || braceLineIdx === -1) {
  continue;
}

因此，未含大括號的 Python def 函式仍不能正常依縮排擷取。

同一個技術限制不能在 Current P2 表中承認尚未修復，卻在 Outdated P1 表中宣稱已被 C1–C12 完全消除。

這不代表必須立即完成 Python 支援，但必須將 sUDZJ 改為現存限制的正式風險接受或修復項目，而非 OBSOLETE。其原始 P1 嚴重度也不能因 GitHub 顯示 Outdated 就自動降級。

F-MR2-02｜歷史 P1 的 Benchmark 問題並未由 C13 修復證明
BLOCKING

Thread

	

原始問題

	

R2 處置




ra7k3，Outdated P1

	

不得把 Preliminary Approval 計為 Final Gate PASS

	

宣稱已被 C13、Schema 2.0.0 取代




rtv6N，Current P2

	

Final Gate 應依觀察到的 Findings 判定

	

G5-P2-07 遞延




slqmG，Current P2

	

Preliminary Case 不應納入 Final Gate 成績

	

G5-P2-07 遞延

目前 src/core/real-benchmark-runner.mjs 仍使用：

JavaScript
const finalGateDecision =
  isClean ? "block" : actualGateDecision;

const finalGatePolicyPass =
  finalGateDecision === caseDef.expectedGateDecision;

const finalGatePassed = Boolean(
  detectionPass &&
  finalGatePolicyPass &&
  executionComplete
);

雖然後續設定 promotionEligible = false，可以防止該結果直接用於 Promotion，但並沒有消除 Final Gate 統計欄位可能誤計未驗證案例的問題。

C13 的 CLI Repo Root Fail-Closed 測試，也不是這個 Benchmark 計分問題的直接反證。

裁定：ra7k3 目前不具備 OBSOLETE_REPLACED_BY_C13_SCHEMA2 的充分證據，應併入 G5-P2-07 重新評估與正式接受。

F-MR2-03｜110 筆 Outdated 的證據仍有過度概括

卷宗確實列出了 110 筆、九欄的處置矩陣；但其中的修復或失效證據，大量重複同一組聚類文字：

聚類

	

Thread 數

	

修復／失效證據的實際情況




OUT-C1

	

31

	

共用一套 C1–C12 概括描述




OUT-C2

	

43

	

共用一套 C14A/B 概括描述




OUT-C3

	

11

	

共用一套 C14A/B/C 概括描述




OUT-C4

	

17

	

共用一套重構與路徑防護描述




OUT-C5

	

8

	

共用一套 C13、Schema 2.0.0 描述

同根因聚類本身可以接受，但不同原始缺陷仍須由適用的修復證據支持。例如：

ra7kt 要求 Prompt Markup Escape，C13 的 Repo Root 驗證不能單獨證明它已修復。

rrUDp 要求 Verifier Streaming Output Size Limit，C14A/B 的 ContextPackage 授信驗證不是直接的輸出長度反證。

rTowi 要求區分空白 Blob 與 Exact-Head Lookup 失敗，不能只靠 C1–C12 的廣泛名稱證明已修復。

這些不一定都是尚存缺陷，但目前提交的處置證據不足以獨立確認它們全數失效。
pr-39-g4-merge-readiness-decision-record.md

裁定：OUTDATED_110_CLOSURE_EVIDENCE = PARTIALLY_SUPPORTED，不得核發 110/110 全數技術失效的認定。

三、25 筆 Current P2 風險接受審查

對於 25 筆 Current P2，本次的工作已有實質進展。10 筆 FIXED_IN_HEAD 中，例如 AST 上限截斷、Repo 隔離快取鍵、SARIF Null Guard，都能找到直接程式碼依據。

但部分 ACCEPT_DEFERRAL 理由需要修正。

G5 項目

	

審查意見

	

裁定




G5-P2-01 Checkpoint 碰撞

	

目錄穿越已防護，但不同自訂 Run ID 仍可映射同一檔名

	

遞延可考慮，須保留資料覆寫風險




G5-P2-02 Advisory 匯出

	

不影響核心 Gate 判定，但會影響下游稽核資訊完整性

	

可接受受控遞延




G5-P2-03 模型溯源

	

影響執行證據的模型身分正確性

	

可接受受控遞延，不宜宣稱沒有稽核風險




G5-P2-04 Cache

	

模組層級 Map 無容量上限，且失敗結果快取為 null

	

需修正風險估計




G5-P2-05 Python

	

現存功能限制，與歷史 P1 同根因

	

須補入 P1 遺留風險處置




G5-P2-06 Prompt Budget

	

32 KB ContextPackage 上限不等於整份 Prompt 的輸入上限

	

需補充完整輸入預算驗證




G5-P2-07 Benchmark

	

promotionEligible = false 可限制使用，但不使錯誤計分自動正確

	

須補入歷史 P1 遺留風險處置

其中兩項值得特別修正：

Cache 的記憶體風險估計。 getExactHeadFileContent() 每次 Git 擷取的 maxBuffer 為 10 MiB，且目前不存在 LRU 或項目數上限。因此不能依據 PR 有 77 個變更檔案，就推導快取必然小於數 MB。這項估計應改為基於實際使用模式的有界測量，而不是宣稱沒有 OOM 風險。

Prompt Budget 的安全邊界。 固定 HEAD 中，Context Block、Context Gaps 及 Response Schema 會附加至已產生的 Diff 內容。上游限制 ContextPackage 大小，並不等於 Verifier／Reviewer 的最終輸入整體不超過預算。若要接受 G5 遞延，應說明目前超額時的失敗處置，而不是把 32 KB Context 上限視為完整保證。

此外，卷宗已有 G5-P2-01 至 G5-P2-07 的內部追蹤編號、負責團隊及 Sprint，但沒有提供實際 GitHub Issue 連結或明確日期，因此目前可確認的是遞延計畫已登記於卷宗，尚非已驗證的 Issue 追蹤與完成期限。
pr-39-g4-merge-readiness-decision-record.md

四、管理員覆寫例外與全 PR 範圍

已確認附件存在由 Repository Owner arcobaleno64 具名的管理員覆寫核准宣告，明確限定 Ruleset、Base SHA 與 HEAD SHA。
pr-39-g4-merge-readiness-decision-record.md

這項具名風險接受的形式與授權範圍可接受，但其所依賴的「110 筆全部已失效、14 筆遞延均無重大風險」事實前提，尚未獲獨立驗證。

另外，GitHub 已證實 54 Commits／77 Changed Files 的拓撲及數量正確。然而，卷宗第三節以四大子系統進行總括確認，沒有提供 77 檔逐檔的最終差異處置結果，因此目前只能接受全範圍盤點，不能將其提升為全範圍已獨立完成重大缺陷排除的證明。
pr-39-g4-merge-readiness-decision-record.md

五、正式 R2 治理裁決
MERGE AUTHORIZATION · HOLD

PR39-SCHEMA2-G4-MERGE-READINESS-REVIEW-R2

治理項目

	

R2 裁定




135 筆 Thread ID 實體對帳

	

VERIFIED




Current P1 20/20 結案

	

VERIFIED




Git 合併拓撲

	

ACCEPTED




三平台必要 CI

	

ACCEPTED




25 筆 Current P2 風險登記

	

PARTIALLY_ACCEPTED




110 筆 Outdated 處置

	

HOLD_FOR_EVIDENCE_CORRECTION




管理員具名風險接受宣告

	

RECEIVED




管理員覆寫的技術前提

	

NOT_YET_ACCEPTED




THREAD_BULK_RESOLVE

	

NOT_AUTHORIZED




NEW_PUSH

	

NOT_AUTHORIZED




ADMIN_BYPASS_MERGE

	

HOLD




SQUASH_MERGE

	

NOT_AUTHORIZED

六、下一輪最小補正範圍

下一輪可進入：

PR39-SCHEMA2-G4-MERGE-READINESS-REVIEW-R3

不要求重新整理 135 筆 ID，也不要求重做 G4 的七檔修復與三平台 CI。僅需完成以下四項：

修正 Outdated 處置矛盾。 至少將 sUDZJ 與 ra7k3 從「已修復失效」改成有直接驗證依據的狀態，或提供新的可執行反證；並檢查其他同類錯誤映射。既有 P1 若要遞延，須明確記錄重新定級與具名風險接受理由。

補足真正缺陷對應的證據。 對 110 筆 Outdated 保留原 ID，聚類可以沿用，但應以實際缺陷、修復位置或測試案例為依據，不再用整個子系統的通用描述取代個別技術驗證。

修正 G5 風險接受理由。 特別是 Cache 容量、Prompt 預算，以及 Checkpoint 與稽核資料完整性的影響，補入可檢查的追蹤責任、期限與必要時的緩解措施。

更新覆寫簽署及全範圍收據。 將上述更正反映於新的具名核准聲明，並補上 77 檔的範圍索引與風險處置結果。原 Base／HEAD 不變時，不必重新建立 Commit。

R2 最終裁示：CONDITIONAL_HOLD_FOR_EVIDENCE_CONTRADICTIONS。

本輪接受 135/135 身分清單、完整處置表的交付、20 筆 Current P1 結案、三平台 CI、分支拓撲及管理員具名宣告的存在性。

但已找到至少兩組現行 G5 遞延項目與歷史 P1「已失效」裁定直接衝突的證據。對需要覆寫主分支治理規則的 Squash Merge 而言，這是必須先修正的實質缺口，不適合以「Outdated」或「管理員已簽署」取代驗證。

方案 A 繼續保留；本輪不核發 Admin Bypass 或 Squash Merge 授權。

本次僅進行唯讀核驗，未操作 Review Threads、未變更 Ruleset，也未執行 Merge。