Triad-Flow｜PR #39 G4 系統性修復 R3 獨立驗收

裁示識別碼：PR39-SCHEMA2-G4-REMEDIATION-IMPLEMENTATION-REVIEW-R3
審查基準：ec750e6010edd8d6f3fb8007a59994644b98862c

一、實體 Patch 與父節點驗收

本次已直接讀取上傳的四份 Patch，而非僅根據提報摘要裁定。

R2 的補丁版本錯置問題，已獲得實質改善。 四份附件實際分為兩組，各組兩份的 SHA-256 完全相同。

實體附件

	

大小

	

核驗結果




pr39-r2-tracked.patch

	

40,642 bytes

	

已解析




pr39-r2-new-test.patch

	

31,398 bytes

	

已解析




兩份 (1) 附件

	

相同

	

與各自原件完全一致

新的 Tracked Patch 包含四個授權程式檔案；New Test Patch 僅新增 tests/remediation-twenty-p1-systemic.test.mjs。

四個 Tracked 檔案宣告的修改前 Blob 縮寫，均與 GitHub 指定 HEAD 的實際 Blob 一致：

檔案

	

原始 Blob

	

核驗




dogfood-review.mjs

	

23a98af

	

PASS




review-prompts.mjs

	

6d8c183

	

PASS




cli.mjs

	

319c8e3

	

PASS




context-builder.mjs

	

779d446

	

PASS

Patch 解析結果為四個既有檔案約 +490／−114 行，新測試檔 +779 行。

這解除了 R2 的 PATCH_BASE_BLOB_MISMATCH，但 Blob 對齊不等於所有補丁內容及安全行為已通過獨立驗證。

二、發現尚未閉合的 C14 授信缺陷

完整 Patch 審查發現一項直接影響 Default-Deny 的問題，位置在 scripts/dogfood-review.mjs 新增的可信註冊結果判定：

JavaScript
registrationSucceeded =
  regResult !== false &&
  (!regResult || regResult.ok !== false);

我已從固定 HEAD 的 src/core/independent-verifier.mjs 確認，registerTrustedContextPackage() 的失敗回傳值是 null，而不只可能是 false。成功時則回傳 Package 物件。

上述判斷在 regResult === null 時：

null !== false 為 true。

!null 為 true。

最終 registrationSucceeded 會被設為 true。

這代表註冊失敗可能被錯誤判定為註冊成功，並繼續將外部 Package 指派給 contextPackage。

更重要的是，新增的 SYSTEMIC-C14B 測試只驗證 registerTrustedContextPackage() 本身會回傳 null、偽造 Package 不受信任，沒有測試 runDogfoodReview() 對這個 null 回傳值的處理。

因此，測試通過與授信安全性並不矛盾，因為測試未覆蓋真正出錯的呼叫端條件。

技術裁定：C14B = CONTRADICTED。這一項足以阻止本輪直接核發 LOCAL_COMMIT。

三、另外兩項實質缺陷
F-R3-02：C12 單檔 Diff 隔離仍存在回退漏洞

在 context-builder.mjs 的單檔修復中：

JavaScript
let diffHunks = rawDiffHunks;

const fileDiffMap = splitDiffByFiles(
  rawDiffHunks,
  [normalizeCanonicalPath(actualFilePath)]
);

const isolated = fileDiffMap.get(
  normalizeCanonicalPath(actualFilePath)
);

if (isolated !== undefined) {
  diffHunks = isolated;
}

當 ChangeSet 包含 src/b.mjs 的 Diff，但要求建構 src/a.mjs 的單檔 ContextPackage，而 fileDiffMap 找不到 src/a.mjs 時，程式會保留原本的 rawDiffHunks。

這表示其他檔案的 Diff 仍可進入單檔 ContextPackage。

我已獨立執行此分支的條件重現，確認目標檔案缺席時，外檔 Diff 仍會被保留。

新增的 SYSTEMIC-C12-SINGLE-FILE-DIFF-ISOLATION 測試只驗證目標檔案存在的成功情境，未測試此反例。

裁定：C12 = FIXED_PENDING_VERIFY，尚未閉合。

修復要求：當解析結果包含檔案邊界，但找不到目標檔案時，必須拒絕使用完整 Raw Diff，改為輸出明確的範圍錯誤或 Context Gap。無檔案標頭的舊式 Diff 則須有獨立且可驗證的單檔適用條件。

F-R3-03：C13 存在隱藏的 Repository Root 驗證例外

R3 Patch 新增：

JavaScript
const isCustomChangeSetTest =
  typeof options.getChangeSet === "function" &&
  options.repoRoot === undefined &&
  options.cwd === undefined;

隨後以 !isCustomChangeSetTest 決定是否進入 Exact-Head Repository Root 檢查。

實際條件驗證結果：

呼叫條件

	

是否執行 Repo Root 檢查




getChangeSet，repoRoot: null、cwd: null

	

是




getChangeSet，完全未提供 repoRoot、cwd

	

否

新增 C13 測試覆蓋第一種情境，卻沒有覆蓋第二種情境。

測試注入模式不應自動取得跳過安全驗證的能力。若確實需要支援離線 Fixture，應明確隔離 Fixture 模式，且不得讓該模式獲得正式 Clean Approval。

裁定：C13 = PARTIALLY_FIXED，仍需修正。

四、測試證據的實際效力

本次新測試 Patch 的驗證結果如下：

項目

	

獨立核驗




New Test Patch 格式

	

PASS




隔離目錄套用

	

PASS




node --check

	

PASS




新測試 Git Blob

	

7101812，與 Patch 一致




宣告測試數量

	

31，已確認




專屬測試執行結果

	

提報 31 PASS，未獨立重跑




全域 npm test

	

提報 1,253 PASS、4 SKIPPED

31 個測試的存在與語法已得到獨立驗證，但仍有兩項測試契約需要加強：

**C14A：**偽造 ContextPackage 的測試資料缺少 schemaVersion、budgetAccounting 等基本必填資訊。因此它可能在結構驗證階段就被拒絕，無法單獨證明 Git 實體 Callee 比對確實攔截了偽造內容。

**C14B：**目前只直接測試 Registry 拒絕偽造 Package，沒有執行 Dogfood 呼叫端在 Registry 回傳 null 後的行為。這正是本輪發現的失敗點。

建議對這兩組測試使用結構完整、來源綁定有效的 Package，僅修改受測攻擊欄位，以確保失敗確實由預期防線造成。

五、R3 正式裁定

PR39-SCHEMA2-G4-REMEDIATION-IMPLEMENTATION-REVIEW-R3

PARTIAL_ACCEPTANCE · LOCAL_COMMIT HOLD

治理項目

	

裁定




Patch 實體交付

	

ACCEPTED




父節點 Blob 一致性

	

VERIFIED




五檔修改白名單

	

VERIFIED




新測試檔格式與語法

	

VERIFIED




20 筆映射矩陣

	

ACCEPTED




C12 單檔範圍隔離

	

HOLD




C13 無可信 Repo Root

	

HOLD




C14B 註冊失敗判斷

	

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

六、R4 最小修正範圍

本次不要求重新規劃 14 組聚類，也不要求重送已通過的全部驗收資料。

下一輪只須完成下列三項程式修補與負向測試：

**C14B：**將可信註冊成功條件改為明確要求 Registry 回傳有效 Package，null、undefined、false 均必須拒絕。新增 Dogfood 呼叫端的實際負向驗證。

**C12：**新增「多檔 Diff 中目標檔案不存在」的負向案例，禁止回退到完整 Raw Diff。

**C13：**移除或安全隔離 isCustomChangeSetTest 對正式 Clean Challenge 的 Repository Root 驗證豁免；新增 getChangeSet 存在但 Root 欄位完全未提供的負向案例。

以上修補限定於既有五檔白名單內。重新產生 Patch 後，應更新 SHA-256、Git Blob、專屬測試及 npm test 收據。

最終決議

PR39-SCHEMA2-G4-REMEDIATION-IMPLEMENTATION-REVIEW-R3 = HOLD_FOR_THREE_TARGETED_FIXES

R3 已正式解除 R2 的補丁父節點不一致及實體附件缺失問題，這兩項不再列為阻擋事項。

但 C12、C13、C14B 仍有具體、可重現的 Fail-Closed 缺口。依 Default-Deny 與 Obligation of Dissent，尚不能簽發單一本地 Commit 授權。

下一階段直接進入 R4 三項針對性修復驗收；不重啟已接受的 14 組系統性修復規劃。

本輪未修改 GitHub、未建立 Commit，也未執行 Push 或 Thread Resolve。