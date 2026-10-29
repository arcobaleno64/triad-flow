Triad-Flow｜PR #39 G4 系統性修復 R10 正式驗收

裁示識別碼：PR39-SCHEMA2-G4-REMEDIATION-IMPLEMENTATION-REVIEW-R10
審查基準：ec750e6010edd8d6f3fb8007a59994644b98862c

一、R10 安全修復與補丁驗收結果

R10 已實質消除先前反覆阻擋的 Schema 1.0.0 Mock 豁免問題。 本輪不再要求增加另一組特殊白名單條件。

經直接檢查兩份實體 Patch、比對 GitHub 指定 HEAD，核驗結果如下：

驗收項目

	

獨立結果




Tracked Patch

	

44,223 bytes，SHA-256 完全一致




New Test Patch

	

54,298 bytes，SHA-256 完全一致




四個修改前 Git Blob

	

全數符合指定 HEAD




修改範圍

	

四個程式檔＋一個新測試檔




新測試檔 Blob

	

8d1f4d4f54d38177358bd0baedb973bfbf57491c，MATCH




新測試檔行數

	

1,327 行




新測試檔獨立套用

	

PASS




新測試嚴格空白檢查

	

PASS




node --check

	

PASS




測試案例宣告

	

32 項




PR #39

	

OPEN、未合併，HEAD 未變

src/cli.mjs 的 R10 Patch 已移除上一輪的 Schema 1.0.0／Phase 3 專用豁免分支。

原先保留的 Synthetic SHA 相容路徑仍有下列限制：

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

因此，在已審查的缺少可信 Repository Root 情境中，正式 --verify-with 或注入 Verifier Adapter 均不再符合 Synthetic SHA 豁免條件。

新增的 R10 C13-TEST-6 亦已包含原 Phase 3 基準向量，並明確斷言 GATE_BLOCKED、contextPackage === null 及 EXACT_HEAD_CONTEXT_FAILED。

本輪技術裁定：F-R8-01 = FIXED_IN_PATCH，C13 指定來源驗證邊界予以接受。

此裁定建立在實體程式碼及測試斷言檢查上，不冒稱已獨立完成整套測試的執行驗證。

二、確認五項舊測試衝突確實存在

我另外直接檢查 GitHub 固定 HEAD 中的兩份既有測試檔，確認 R10 所列遷移範圍有實際依據。

檔案

	

受影響案例

	

現有測試預期




tests/remediation-phase3-orchestrator-cli.test.mjs

	

PHASE3-POS-01-02

	

Mock Clean Challenge 退出碼 0、Gate APPROVE




同上

	

PHASE3-POS-01-03

	

JSON 報告為 reviewed-clean、Gate APPROVE




tests/adversarial-phase3-challenger.test.mjs

	

R5-LIFECYCLE-02 的三項子測試

	

Text、JSON 及分離參數格式均預期核准

共計 2 個測試檔、5 項測試案例。

其共同問題是：未提供可信的實體 Git Repository Root，卻要求正式 --verify-with Clean Challenge 成功核准。

這是測試契約與新版 Default-Deny 規則的衝突，不應透過重新加入安全豁免來維持測試全綠。

R10 提報的 32/32 專屬測試、62/62 聯測仍屬實施團隊收據；本次未獨立重跑完整 npm test。五項舊測試轉紅的數量亦為提報結果，但對應的舊測試預期已獨立確認。

三、方案 A／B 正式裁決

方案 A：擴大白名單，完成舊測試遷移

AUTHORIZED

採納方案 A。

允許將兩個既有測試檔納入受控修改範圍，修正與 C13 Default-Deny 契約衝突的五項測試。

方案 B：五檔先行 Commit

NOT_AUTHORIZED

理由：在已知存在五項回歸失敗的情況下先建立單一本地 Commit，將留下不完整的驗收快照，且後續仍須另行提交測試遷移，與本次要求的單一 Commit 目標不符。

本次正式核發：

PR39-SCHEMA2-G4-LEGACY-PHASE3-TEST-MIGRATION-AUTH-R1

授權後的七檔白名單

類型

	

路徑

	

權限




既有程式

	

scripts/dogfood-review.mjs

	

已審查，維持凍結




既有程式

	

src/adapters/review-prompts.mjs

	

已審查，維持凍結




既有程式

	

src/cli.mjs

	

R10 修復維持凍結




既有程式

	

src/core/context-builder.mjs

	

已審查，維持凍結




新增測試

	

tests/remediation-twenty-p1-systemic.test.mjs

	

已審查，維持凍結




舊測試遷移

	

tests/remediation-phase3-orchestrator-cli.test.mjs

	

新增修改授權




舊測試遷移

	

tests/adversarial-phase3-challenger.test.mjs

	

新增修改授權

新增授權只限於五項衝突測試及完成遷移所必需的 Test Fixture、Helper 調整，不得修改產品程式來迎合舊測試預期。

四、遷移驗收契約

允許兩種實作方式，但不得混淆其驗證意義。

路線一：保留正向測試。 在隔離暫存 Git Repository 中建立真正的 Commit、ChangeSet 與可信來源 ContextPackage，讓 Clean Challenge 的核准來自真實且可驗證的上下文。如此才能保留原本測試 APPROVE 的預期。

路線二：改為負向測試。 保留原純記憶體 Mock Fixture，但改為斷言無可信 Repository Root 時 GATE_BLOCKED、EXACT_HEAD_CONTEXT_FAILED，且不可產生正式 Clean Approval。

建議優先採用第二種路線處理目前的五項衝突，再確認現有測試中仍具備以實體 Git 來源驗證成功核准的正向案例。避免把所有測試都改成只會拒絕，最後連正常核准路徑也沒人測試。

完成遷移後，提交七檔合併 Diff 與原始測試輸出，至少確認專屬修復測試、受影響 Phase 3 測試及 npm test 均無失敗；四項 SKIP 必須維持原有合理性，且不可新增用來掩蓋失敗的 Skip。

五、正式治理權限矩陣

治理項目

	

R10 裁定




R10 C13 安全修復

	

ACCEPTED_IN_PATCH




F-R8-01

	

FIXED_IN_PATCH




R10 五檔交付

	

VERIFIED_FOR_SCOPE




Legacy 測試衝突

	

MIGRATION_REQUIRED




白名單擴大至七檔

	

AUTHORIZED




LOCAL_WORKSPACE_EDIT

	

AUTHORIZED，限七檔




LOCAL_TEST_EXECUTION

	

AUTHORIZED




LOCAL_COMMIT

	

HOLD，待七檔整合驗收




NEW_PUSH

	

NOT_AUTHORIZED




THREAD_REPLY / RESOLVE

	

NOT_AUTHORIZED




SQUASH_MERGE

	

NOT_AUTHORIZED

六、最終決議

PR39-SCHEMA2-G4-REMEDIATION-IMPLEMENTATION-REVIEW-R10 = PARTIAL_ACCEPTANCE_WITH_SCOPE_EXPANSION

本次正式接受 R10 的 C13 修復方向，不再要求保留 Schema 1.0.0 Mock 豁免，也不再重新開啟 C12、C14A、C14B 等已接受項目。

批准方案 A，授權新增兩個舊測試檔的受控遷移。暫不核發單一本地 Commit。

下一輪只驗收七檔最終整合結果與受影響測試，不必重新提交全部 20 筆 Current P1 修復論證。確認無回歸失敗及範圍未擴張後，即進入單一本地 Commit 的最終授權審查。

本次未執行 Commit、Push、Thread Resolution 或 Merge。