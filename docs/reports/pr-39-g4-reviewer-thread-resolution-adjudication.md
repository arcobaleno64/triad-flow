Triad-Flow｜PR #39 G4 討論串 Resolve 授權審查 R1

裁示識別碼：PR39-SCHEMA2-G4-THREAD-RESOLUTION-AUTHORIZATION-REVIEW-R1
關聯 Commit：0fec4f97f46c892a8f5eee1d606660e07d130d54

一、20 筆回覆收據已獨立核實

已透過 GitHub 直接讀取 PR #39 全部 180 筆 Review Threads，逐筆比對提交的 Thread ID、GraphQL Comment ID、Database ID、建立時間及實際回覆內容。

20/20

回覆實際存在

20/20

ID 與時間戳一致

0/20

已執行 Resolve

獨立核驗結果：

20 筆指定 Thread 均有且只有一則新修復收據回覆，作者為 arcobaleno64。

20 組 GraphQL Comment ID、Database ID、建立時間均與提報完全一致。

20 則回覆皆包含正確的 Commit SHA、CI Run ID、修復檔案及回歸測試。

回覆發布後，這 20 筆 Thread 均無新增技術反駁或其他回覆。

其餘 160 筆 Thread 未發現同期新增回覆，原有的 25 筆已解決狀態保持不變。

PR #39 目前仍為 OPEN、未合併，HEAD 未變。

裁定：THREAD_REPLY_EXECUTION = VERIFIED_COMPLETE。

發表收據與完成技術結案是兩個不同的治理動作。下一步的重點不再是證明留言存在，而是確認每則留言所引用的修復證據，能否準確閉合原始缺陷。

二、原始缺陷與回覆內容的逐筆技術審查

GitHub 原始紀錄確認，關聯 Commit 仍為 PR #39 的 HEAD，三平台 CI 均為 completed / success。先前已驗收的修復程式與測試結果可繼續作為本輪結案證據。

但比對 20 則回覆與原始缺陷後，發現 6 則回覆需要修正證據描述或測試引用。這些問題不代表修復程式失效，而是目前的留言尚未完全符合上一輪訂定的逐筆結案證據契約。

Thread

	

審查發現

	

更正要求




slAMv（C1）

	

原問題是跨 Hunk 重建區塊註解狀態；回覆只引用缺少 fileContent 時的保守退化測試

	

補引 SYSTEMIC-C01-HUNK-LEXICAL-STATE (Negative)，說明以實際 fileContent 重建註解狀態




r1BuC（C6）

	

原問題是保留敏感 Receiver 的內建方法呼叫；回覆只引用非敏感 Receiver 應略過的測試

	

改引 SYSTEMIC-C06-BUILTIN-ON-SENSITIVE-RECEIVER，該測試直接驗證兩處敏感呼叫保留




rfkYi（C11）

	

回覆宣稱 XML 使用 c.file \|\| targetFileAttr，與實際程式碼不一致

	

改為描述條件式 fileVal／fileAttr，避免將 multi-file 當成 Callee 的來源檔案




rvWjO（C12）

	

原問題是單檔 Diff 隔離；回覆主要引用 Multi-file Routing 與 Target Missing 測試

	

補引 SYSTEMIC-C12-SINGLE-FILE-DIFF-ISOLATION 作為主要反證




tdsmT（C14）

	

原問題是未驗證外部 Package 不得取得 Workflow Authority；回覆只引用 C14A 偽造 Callee 測試

	

補引 SYSTEMIC-C14B-REGISTRATION-FAILURE-WORKFLOW-DENIAL，說明註冊失敗時撤銷授信




rxCha（C14）

	

原問題是比對外部 Callee 內容與 Exact-Head Git；回覆只引用 C14B 註冊失敗測試

	

改以 SYSTEMIC-C14A-FORGED-CALLEE-REJECTION 作為主要反證，說明實體來源比對

其中 rfkYi 的問題已直接由最新 Commit 的 src/adapters/review-prompts.mjs 確認。實際程式在多檔模式會尋找真正的來源路徑，在單檔模式則避免不必要地重複來源欄位，而不是無條件輸出 c.file || targetFileAttr。

C14 的兩則回覆則主要存在原始缺陷與主要測試引用錯位。相關的 C14A、C14B 測試都已通過 CI，毋須重做程式修補，只要正確對應各自的驗收目的。

三、依五項授權標準裁定

驗收標準

	

結果




1. 回覆存在與識別碼正確

	

20/20 PASS




2. 原始缺陷有對應修補

	

20/20 已有前輪程式驗收證據




3. 回歸測試與原問題精確對應

	

14 PASS、6 REQUIRE_CORRECTION




4. 無新增未處理異議

	

20/20 PASS




5. 證據可追溯

	

20/20 PASS

因此，本輪採逐筆差異化授權，不因 6 筆留言修正需求而阻擋其他 14 筆。

四、正式 THREAD_RESOLVE 授權
14 THREADS AUTHORIZED

正式核發：

PR39-SCHEMA2-G4-THREAD-RESOLVE-AUTH-R1

核准 Resolve 的 14 筆 Thread：

rte6z

rvCBT

sl1Ri

slAM6

r1BuI

rr-I6

rsKCC

slLWi

rsajc

rte6o

rr-JC

rrHOc

tdsmP

rvCBW

暫不授權 Resolve 的 6 筆 Thread：

slAMv

r1BuC

rfkYi

rvWjO

tdsmT

rxCha

對這 6 筆另行授予限定的 THREAD_COMMENT_EDIT = AUTHORIZED，只准更正本次核驗的既有修復回覆，不得修改原始審查留言或新增不相關回覆。維持原 GraphQL Comment ID，方便追溯前後版本。

完成更正後，只需提交這 6 筆更新後的內容，進行：

PR39-SCHEMA2-G4-THREAD-RESOLUTION-AUTHORIZATION-REVIEW-R2

不必重新審查另外 14 筆。

五、執行邊界與結案收據

治理項目

	

裁定




THREAD_REPLY_EXECUTION

	

VERIFIED，20/20




THREAD_RESOLVE

	

AUTHORIZED，限 14 筆




THREAD_COMMENT_EDIT

	

AUTHORIZED，限 6 筆




其餘未授權 Thread

	

NOT_AUTHORIZED




NEW_PUSH

	

NOT_AUTHORIZED




SQUASH_MERGE

	

NOT_AUTHORIZED

實施團隊執行 14 筆 Resolve 時，必須先重新確認 PR HEAD 仍為 0fec4f97f46c892a8f5eee1d606660e07d130d54、目標 Thread 尚未解決且沒有新增實質反駁。每次操作後應保存 GraphQL Thread ID、Mutation 結果與最終 isResolved 狀態。

最終裁定：PARTIAL_ACCEPTANCE_FOR_THREAD_RESOLUTION。

本輪確認 20/20 修復證據回覆確實發布成功，准予其中 14 筆進行 Resolve。另外 6 筆只需更正留言與測試證據的精確對應，不要求新的程式 Commit 或 CI。

本次僅核發治理授權，未實際呼叫任何 resolveReviewThread Mutation，也未執行 Merge。