Triad-Flow｜G4 系統性修復 R2 獨立驗收裁示

裁示識別碼：PR39-SCHEMA2-G4-REMEDIATION-IMPLEMENTATION-REVIEW-R2
審查日期：2026-10-27
審查目標：arcobaleno64/triad-flow · PR #39

HOLD · REQUIRES CORRECTION

裁示結論：R2 已改善缺陷映射與測試證據，但尚不能核發 LOCAL_COMMIT = AUTHORIZED。

這次不只是證據格式問題。我透過指定的 GitHub 連線，比對了遠端 HEAD 的真實檔案與提報的 Unified Diff，發現部分 Patch 並非針對宣告的父節點產生。

一、GitHub 基準核驗

項目

	

核驗結果




PR #39

	

OPEN、未合併




遠端分支

	

fix/remediation-007-clean-challenge




遠端 HEAD

	

ec750e6010edd8d6f3fb8007a59994644b98862c




申請操作

	

單一本地 Commit




遠端 Push

	

未授權

重大發現：Diff 基準不一致

Git Unified Diff 的 index 左側代表修改前的 Git Blob。逐檔比對如下：

檔案

	

R2 Diff 宣告的舊 Blob

	

指定 HEAD 實際 Blob

	

結果




context-builder.mjs

	

92e35e7

	

779d446

	

不一致




review-prompts.mjs

	

6d8c183

	

6d8c183

	

一致




cli.mjs

	

319c8e3

	

319c8e3

	

一致




dogfood-review.mjs

	

eb91f7c

	

23a98af

	

不一致

更直接的證據是：R2 的 context-builder.mjs Diff 宣稱第 194 行附近存在 classifySensitiveCategory(name, qualifiers = [])，但指定遠端 HEAD 的第 194 行位於 AST 提取流程，真正的 classifySensitiveCategory(text) 在第 1346 行。

dogfood-review.mjs 也有相同問題：R2 提供的修改前 Import 區塊，與指定 HEAD 的實際 Import 內容不同。

因此，目前不能把這份 Diff 視為已通過 ec750e60 父節點一致性檢查的提交材料。這可能是不同工作樹、不同版本或補丁整理過程中的混用，尚不能推定本地實作本身錯誤。

二、修復邏輯另有三項關鍵問題

除了 Diff 基準不一致，R2 展示的程式片段還存在可直接判定的風險。

F-R2-01：C13 缺少 Repository Root 時仍可能繞過 Fail-Closed

R2 修改後的 src/cli.mjs 使用：

JavaScript
if (!effectiveContextPackage && files.length > 0) {
  if (targetRepo) {
    if (!isGitRepo(targetRepo)) {
      contextExtractionFailed = true;
    }
    // ...
  }
}

當 targetRepo 為 null 時，內層條件不會執行，contextExtractionFailed 仍保持 false。

這正是 C13 要封閉的情境。

裁定：C13 = CONTRADICTED_BY_SUBMITTED_DIFF。

必須新增缺少 targetRepo 的明確失敗分支，並驗證 EXACT_HEAD_CONTEXT_FAILED 確實傳遞至 Clean Challenge 的最終 Gate。

F-R2-02：C14 使用未能確認存在的變數

R2 的 dogfood-review.mjs 補丁包含：

JavaScript
headSha: headSha || null

以及：

JavaScript
const sentryCoverageIncomplete =
  !sentryCoverageManifest ||
  sentryCoverageManifest.length === 0 ||
  // ...

然而，指定 HEAD 的 dogfood-review.mjs：

使用 commitSha 表示 Commit SHA，找不到 headSha 變數宣告。

找不到 sentryCoverageManifest 的宣告或引用。

已經匯入 registerTrustedContextPackage，但 R2 的 Import Diff 又要求新增該名稱。

依目前展示的補丁，這些問題可能導致 ReferenceError 或重複 Import 宣告問題。即使整體測試宣稱 PASS，也不能排除 R2 文件與實際受測檔案不一致。

裁定：C14 = IMPLEMENTATION_EVIDENCE_CONFLICT。

需要提交完整實際檔案或針對正確父節點重新產生的補丁，確認上述變數來源及 Import 結構。

F-R2-03：C11 的來源屬性輸出不完全符合宣稱

R2 的 review-prompts.mjs 補丁只有在特定條件下輸出 file 屬性。

當 c.file 等於單檔 targetFile 時，輸出的 Callee 仍可能缺少 file。

這不必然推翻原始 rfkYi 的多檔修復，但與 R2 矩陣聲稱的「單檔模式結構一致」並不完全相符。

裁定：C11 = PARTIALLY_VERIFIED。

至少須確認多檔模式下每個 Callee 都帶有實際來源路徑，並檢查 XML 屬性跳脫與檔案歸屬的一致性。

三、三項原阻擋條件的 R2 結果

阻擋條件

	

R2 覆核結果




THREAD_MAPPING_MISMATCH

	

 CLOSED：20 筆映射已修正




MISSING_INDEPENDENT_TEST_EVIDENCE

	

PARTIAL：摘要與 Skip 理由齊備，但無可獨立執行的本地測試檔與完整日誌




MISSING_FULL_DIFF

	

OPEN：C05～C10、C12 等關鍵 Diff 明確省略，且部分 Patch 與父節點不一致

本次 31 項專屬測試、1,253 項通過測試及四項 Skip 的數量彼此一致。四項 Skip 的理由也合理，但目前只能登錄為 REPORTED_PASS，不能升格為 INDEPENDENTLY_REPRODUCED_PASS。

此外，R2 第五節明確寫出「因篇幅限制，其餘 Diff 已同步備份於本地」。因此，儘管標題為 Full Git Diff，實際內嵌內容仍不是完整 Unified Diff。

這項事實本身就未達前次 Commit 前驗收條件。

四、修復及重新提報要求

本輪不要求重做已完成的 14 組工作，只要求處理本次發現的實質衝突。

優先處置 C13 與 C14，然後重新產生以指定 HEAD 為父節點的 Diff。建議使用 Git Bash 執行：

Bash
git rev-parse HEAD
git branch --show-current
git status --porcelain=v1 -uall

git diff --binary HEAD -- \
  src/core/context-builder.mjs \
  src/adapters/review-prompts.mjs \
  src/cli.mjs \
  scripts/dogfood-review.mjs \
  > pr39-r2-tracked.patch

git diff --no-index -- /dev/null \
  tests/remediation-twenty-p1-systemic.test.mjs \
  > pr39-r2-new-test.patch

git diff --check

git diff --no-index 因檔案新增而回傳退出碼 1 屬於正常差異結果，不代表產生 Patch 失敗。

應將兩份 Patch 原檔連同測試日誌提供驗收，而非再次將片段重新整理成摘要。這能避免轉貼時的跳脫字元、行號位移與內容遺漏。

五、R2 正式治理裁定

PR39-SCHEMA2-G4-REMEDIATION-IMPLEMENTATION-REVIEW-R2

HOLD · EVIDENCE AND CODE CORRECTION REQUIRED

治理項目

	

裁定




20 筆 Thread 對應矩陣

	

ACCEPTED




14 組修復工作方向

	

ACCEPTED




本地手術式修改

	

AUTHORIZED




本地測試與補證

	

AUTHORIZED




LOCAL_COMMIT

	

HOLD




NEW_PUSH

	

NOT_AUTHORIZED




THREAD_REPLY / RESOLVE

	

NOT_AUTHORIZED




SQUASH_MERGE

	

NOT_AUTHORIZED

所有 20 筆 Current P1 在修復閉合驗收完成前維持 FIXED_PENDING_VERIFY 或其原有未解決狀態，不得將本次測試摘要視為 GitHub Thread 關閉授權。

最終決議：R2 不予核發本地 Commit 授權。

阻擋原因已縮小為三項：補丁父節點不一致、C13／C14 的可見程式問題，以及缺少完整可重現的五檔 Patch。

待上述項目修正後，下一輪 R3 可直接對這些差異進行針對性覆核，無須重新審議整套 14 組修復方案。

本次僅使用 GitHub 唯讀連線查核，未執行任何遠端寫入或本地 Commit。