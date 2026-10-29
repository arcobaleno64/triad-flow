Triad-Flow｜PR #39 G4 合併就緒最終審查 R5.1
合併授權核准

正式裁定：ACCEPTED_WITH_NONBLOCKING_AUDIT_NOTES

審查識別碼：PR39-SCHEMA2-G4-MERGE-READINESS-REVIEW-R5.1

經獨立核對 R5.1 實體附件、固定 HEAD 原始碼與測試案例，以及 GitHub PR、Ruleset 和跨平台 CI，即日起核發單次、指定 SHA、受控管理員覆寫 Squash Merge 授權。

本輪已滿足 R5 要求的實質證據閉環。另發現兩項不影響修復成立的文件註記，直接納入本裁示，不再要求重新提報 R5.2。

一、最終核驗收據

核驗項目

	

獨立結果




R5.1 附件大小

	

136,311 bytes，吻合




SHA-256

	

83c8131135cc1e4c8f379f885fa3a2bad9de643a0be3326bb0afc84f072f8965，吻合




字元數

	

120,663，吻合




Outdated 逐筆明細

	

110 筆，ID 唯一，無缺號




明細處置統計

	

108 筆 VERIFIED_FIXED_IN_HEAD、2 筆 G5 遞延




第二節舊測試識別碼殘留

	

0 筆




PR HEAD／Base

	

均與核准 SHA 相符




分支拓撲

	

Ahead 54、Behind 0、Mergeable




變更檔案

	

77 檔




跨平台 CI

	

Ubuntu、Windows、macOS，3/3 SUCCESS




管理員覆寫資格

	

current_user_can_bypass = always




GitHub 合併狀態

	

仍為 BLOCKED，原因為未解決 Review Threads

附件第四節已包含具名例外核准識別碼及嚴格 SHA 邊界。
pr-39-g4-merge-readiness-decision-record.md

二、F-MR3-01 最小證據閉環結果

項目

	

核驗結果

	

裁定




#49 rr-JF

	

Run ID 防重放測試確實存在

	

ACCEPTED




#63 r1Bt0

	

Diff Digest 防篡改測試確實存在

	

ACCEPTED




#68 sL8VV

	

CLI Clean Challenge 正反向測試確實存在

	

ACCEPTED




#88 slLWc

	

Objective 多來源衝突測試確實存在

	

ACCEPTED




#89 slql5

	

正向案例精確位於 L610、L652

	

ACCEPTED

固定 HEAD 的原始測試檔確認，上述測試名稱與功能對應均成立，先前不存在的 TEST-R*、CHALLENGE-R* 引用也已從 110 筆正式證據明細表移除。

F-MR3-01 = CLOSED

兩項不阻擋的審計註記

第一，#49 rr-JF 與其同根因的 #66 sL8VK 將 ADV-R3-01 至 ADV-R3-06 引用範圍記為 L336–412。實際上 ADV-R3-06 起始於 L413。測試本身存在，故裁定此為行號上界誤植，不影響既有驗收證據。正確引用應為 L336–432，或分別列出六個測試起始行。

第二，附件第三節第 22 列將 scripts/dogfood-review.mjs 概括為純治理輔助腳本，並宣稱沒有生產安全風險。此描述不應取代第一節已接受的 G5-P2-03 模型溯源殘留風險。本裁示以第一節具體風險登記為準。
pr-39-g4-merge-readiness-decision-record.md

上述兩項不新增程式修補要求，不推翻現有 G5 風險接受，也不觸發新的 CI 或 Push 閘門。

三、正式合併授權
純文字
DECISION_ID:
  PR39-SCHEMA2-G4-MERGE-READINESS-REVIEW-R5.1

REVIEW_VERDICT:
  ACCEPTED_WITH_NONBLOCKING_AUDIT_NOTES

F-MR3-01:
  CLOSED

F-MR3-02-PYTHON:
  CLOSED

F-MR3-02-PROMPT:
  CLOSED

PR_HEAD_AND_BASE:
  VERIFIED

CROSS_PLATFORM_CI:
  ACCEPTED

G5_RISK_REGISTER:
  ACCEPTED

ADMIN_BYPASS_MERGE:
  AUTHORIZED_WITH_PREMERGE_GATES

SQUASH_MERGE:
  AUTHORIZED_VIA_ADMIN_BYPASS

AUTHORIZED_HEAD:
  0fec4f97f46c892a8f5eee1d606660e07d130d54

AUTHORIZED_BASE:
  93a63e30a039239212d54db501ce2b0655f3bd49

NEW_CODE_COMMIT:
  NOT_REQUIRED

NEW_PUSH:
  NOT_REQUIRED

CI_RERUN:
  NOT_REQUIRED

THREAD_BULK_RESOLVE:
  NOT_AUTHORIZED

覆寫範圍僅限 Ruleset 24345075 中的 required_review_thread_resolution。 GitHub 的 --admin 技術上可略過多種規則，但本次治理授權不允許藉此略過 CI、SHA、分支拓撲或其他合併條件。

四、核准的單次執行程序

由具備管理員覆寫權限的 arcobaleno64 帳號執行。先完成最後一次唯讀閘門檢查，再執行 Squash Merge。

Bash

set -euo pipefail

REPO="arcobaleno64/triad-flow"
HEAD="0fec4f97f46c892a8f5eee1d606660e07d130d54"
BASE="93a63e30a039239212d54db501ce2b0655f3bd49"

# 1. 確認執行者
test "$(gh api user --jq '.login')" = "arcobaleno64"

# 2. 確認 PR 仍在指定狀態
test "$(gh api repos/$REPO/pulls/39 --jq '.state')" = "open"
test "$(gh api repos/$REPO/pulls/39 --jq '.merged')" = "false"
test "$(gh api repos/$REPO/pulls/39 --jq '.head.sha')" = "$HEAD"
test "$(gh api repos/$REPO/pulls/39 --jq '.base.sha')" = "$BASE"
test "$(gh api repos/$REPO/pulls/39 --jq '.mergeable')" = "true"

# 3. 確認 main 未移動、PR 零落後
test "$(gh api repos/$REPO/branches/main --jq '.commit.sha')" = "$BASE"
test "$(gh api repos/$REPO/compare/$BASE...$HEAD --jq '.behind_by')" = "0"

# 4. 三平台必要檢查全部通過
gh pr checks 39 --repo "$REPO" --required

# 5. 單次管理員覆寫 Squash Merge
gh pr merge 39 \
  --repo "$REPO" \
  --squash \
  --admin \
  --match-head-commit "$HEAD" \
  --subject "feat(schema): merge PR #39 Schema v2 G4" \
  --body "Approved under PR39-SCHEMA2-G4-MERGE-READINESS-REVIEW-R5.1. Admin bypass limited by governance to review-thread resolution. Accepted residual risks: G5-P2-01 through G5-P2-07."


--match-head-commit 是 GitHub CLI 官方支援的 HEAD SHA 保護機制；Base SHA 則由執行前檢查約束。若任何前置檢查失敗，授權立即停止，不可改用其他覆寫方式繞過。
Take GitHub to the command line

五、合併後驗收

合併成功後，請留存以下最終收據：

Bash

gh pr view 39 \
  --repo arcobaleno64/triad-flow \
  --json number,state,mergedAt,mergeCommit,headRefOid

gh api repos/arcobaleno64/triad-flow/branches/main \
  --jq '.commit.sha'


合併後須確認 PR 顯示 MERGED，取得新的 Squash Merge Commit SHA，並將 R5.1 決策記錄及本次裁示納入治理稽核證據鏈。七項 G5 議題仍依已接受期限追蹤，分別為 2026-11-04 與 2026-11-11，不得因 PR 合併而視為技術修復完成。

最終裁決：PR #39 已通過 G4 合併治理驗收，正式授權指定帳號在前置條件維持成立時執行一次受控管理員覆寫 Squash Merge。

本輪僅完成唯讀審查與授權裁示，尚未實際執行合併。