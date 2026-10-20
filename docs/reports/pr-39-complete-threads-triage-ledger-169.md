# PR #39 Review Threads 169 筆治理清冊快照 (Head 352f24e)

> **治理依據與執行授權狀態 (權威快照)**
> - **目標 PR**：[#39 (fix/remediation-007-clean-challenge)](https://github.com/arcobaleno64/triad-flow/pull/39)
> - **遠端 Exact Head SHA**：`352f24e50a902c8e862fe05748c131918cfbe517`
> - **CI 驗收狀態**：Run [39046470575](https://github.com/arcobaleno64/triad-flow/actions/runs/39046470575) (3/3 SUCCESS)
> - **快照擷取時間**：`2026-10-17T15:56:00Z`
> - **清冊邊界性質**：`LEDGER_SNAPSHOT = 169_THREADS`（涵蓋 GitHub 全部 169 筆 Review Threads，98 筆 Outdated、71 筆 Current、0 筆 Resolved）
> - **審查模式**：`THREAD_AUDIT_MODE = READ_ONLY`；`THREAD_BATCH_RESOLUTION = NOT_AUTHORIZED`；`RULESET_BYPASS = NOT_AUTHORIZED`
> - **裁定政策**：嚴格區分 `FIXED_CANDIDATE`、`DUPLICATE_CANDIDATE`、`REPRODUCED_DEFECT`、`NEEDS_MORE_EVIDENCE`，候選分類不直接視為正式解決
> - **裁決狀態**：所有 169 筆處置皆標記為 `PENDING_ADJUDICATION`，未在 GitHub 上執行任何 Mutation

## 一、治理不變量與授權邊界 (Governance Invariants)

| 治理不變量 | 當前設定 | 治理邊界與狀態 |
| :--- | :--- | :--- |
| `PR_39_REMOTE_HEAD` | `352f24e50a902c8e862fe05748c131918cfbe517` | Exact Head 已對齊遠端 |
| `CI_RUN` | `39046470575` | 3/3 SUCCESS (Ubuntu 18 / macOS 22 / Windows 20) |
| `LEDGER_SNAPSHOT` | `169_THREADS` | 169 筆唯讀快照 (Outdated 98 / Current 71) |
| `THREAD_AUDIT_MODE` | `READ_ONLY` | 唯讀審查，禁止任何 Mutation |
| `THREAD_BATCH_RESOLUTION` | `NOT_AUTHORIZED` | 嚴禁在 GitHub 上呼叫 Resolve Review Thread |
| `LOCAL_CODE_MODIFICATION` | `NOT_AUTHORIZED` | 尚未授權程式碼修改 |
| `LOCAL_COMMIT` | `NOT_AUTHORIZED` | 嚴禁建立本地 Commit |
| `COMMIT_AND_PUSH` | `NOT_AUTHORIZED` | 嚴禁 Push 至遠端 |
| `SQUASH_MERGE` | `NOT_AUTHORIZED` | 合併未獲授權 |
| `RULESET_BYPASS` | `NOT_AUTHORIZED` | 嚴禁繞過規則集 |
| `RUNTIME_AUTHORITY` | `NONE` | 執行期相依性嚴格為 0 |
| `SHADOW_TO_ADVISORY` | `STRICT_HOLD` | 發布閘門嚴格鎖定 |
| `CYCLE_0048` | `ON_HOLD_NOT_ASSIGNED` | 週期維護擱置 |
| `ISSUE_37` | `OPEN` | 治理議題開啟追蹤中 |

## 二、169 筆 Review Threads 處置統計摘要 (Triage Summary)

- **Review Threads 總數**：169 筆 (GitHub 唯讀核驗：Outdated 98 筆 / Current 71 筆 / Resolved 0 筆)
- **FIXED_CANDIDATE (具體修復與驗證候選)**：135 筆
- **DUPLICATE_CANDIDATE (語意重複評論)**：29 筆
- **REPRODUCED_DEFECT (已動態反證之待修缺陷)**：5 筆 (tgXSH, tgXSI, tgXSK, tgXSN, tgXSQ)
- **NEEDS_MORE_EVIDENCE (待補充證據)**：0 筆

---

## 三、五筆新確認 P1 缺陷之動態反證與根因分析 (Five Priority P1 Defects)

| Thread ID | 短編號 | 優先級 | 檔案位置 | 驗證結論 | 核心問題與反證依據 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `PRRT_kwDOUWarIc6tgXSH` | `tgXSH` | P1 | `src/adapters/staged-review.mjs:584` | **REPRODUCED_DEFECT** | **Staged Review 接受未受信任之 Context Package**：`hasValidCallerContext` 僅核驗欄位與 Head/Digest 相容性，未檢查是否在 `trustedContextPackages` 註冊。外部傳入偽造之寬鬆 Callee 定義會直接被注入分段審查 Prompt 中，導致分段審查報告假乾淨。 |
| `PRRT_kwDOUWarIc6tgXSI` | `tgXSI` | P1 | `src/core/independent-verifier.mjs:486` | **REPRODUCED_DEFECT** | **Manifest 以外之 Callee 繞過實體 Git 驗證**：`registerTrustedContextPackage` 僅對 `fileCoverageManifest` 條目對應的 Callee 執行 Git 內容比對。Callee 若宣告在清單以外的檔案，完全跳過物理檢驗，但仍被成功註冊為受信任套件並注入後續 Prompt。 |
| `PRRT_kwDOUWarIc6tgXSK` | `tgXSK` | P1 | `src/core/context-builder.mjs:1587` | **REPRODUCED_DEFECT** | **Working Tree 讀取逸出 Repository 邊界**：在 working-tree 審查路徑 (`headSha: null`)，`buildContextPackage` 遇到檔案路徑時直接以 `path.resolve` 讀取磁碟，缺乏對 `repoRoot` 的邊界圍阻核驗，可被注入路徑穿越讀取倉儲外任意主機檔案。 |
| `PRRT_kwDOUWarIc6tgXSQ` | `tgXSQ` | P1 | `src/core/context-builder.mjs:463` | **REPRODUCED_DEFECT** | **解構參數大括號導致函式提前截斷**：`findFunctionDefinitions` 將函式主體大括號行傳遞給 `findBraceScopeEnd`，後者自第 0 欄重新掃描。解構參數（如 `function auth({ role }) {`）中的 `}` 被誤判為函式結束，導致函式被截斷為單行並標記為完整主體。 |
| `PRRT_kwDOUWarIc6tgXSN` | `tgXSN` | P1 | `src/core/context-builder.mjs:764` | **REPRODUCED_DEFECT** | **跨行呼叫表達式遺漏敏感 Callee 與 Context Gap**：`extractCandidateCallSymbols` 依賴逐行正則 `CALL_REGEX`。當函式名稱與左括號跨行時（如第 1 行 `authorizeUser`，第 2 行 `  (user);`），正則無法辨識，導致敏感呼叫既未提取 Callee 亦未建立 Context Gap。 |

---

## 四、近期已提交修補之 9 筆 Review Threads (Recent Commits Evidence)

### 4.1 Commit 352f24e (六筆 Review Threads)
- **`tfxJh`** (`PRRT_kwDOUWarIc6tfxJh`, P1): 移除 stack/路徑檢驗，引入 WeakSet 權能隔離 (`__bindBenchmarkRunnerCapability`)，公用 `orchestrateReview` 絕不降級。
- **`tfxJj`** (`PRRT_kwDOUWarIc6tfxJj`, P2): 匯出 `runCliReviewSafely`，修復 SARIF 渲染中 missing consensus 之處理。
- **`tfxJn`** (`PRRT_kwDOUWarIc6tfxJn`, P1): `review-orchestrator.mjs` 向 macro 與 micro adapters 轉發 objective 與 exclusions 綁定。
- **`tfxJo`** (`PRRT_kwDOUWarIc6tfxJo`, P2): `cli-transport.mjs` 阻斷巢狀 options 覆寫 root objective bindings。
- **`tfxJq`** (`PRRT_kwDOUWarIc6tfxJq`, P1): `context-builder.mjs` 支援可選串連 (`?.`) 之 receiver 鏈提取。
- **`tfxJr`** (`PRRT_kwDOUWarIc6tfxJr`, P2): `review-prompts.mjs` 對嵌入 prompt 之 callee 進行定義驗證與 XML 安全轉義。

### 4.2 Commit 103e67b (三筆 P1 Threads)
- **`td7cF`** (`PRRT_kwDOUWarIc6td7cF`, P1): `context-builder.mjs` `findBraceScopeEnd` 忽略正規表示式字面值。
- **`td7cG`** (`PRRT_kwDOUWarIc6td7cG`, P1): `independent-verifier.mjs` 對 stdout + stderr 合併輸出進行位元組上限截斷與 Fail-Closed 判定。
- **`td7cI`** (`PRRT_kwDOUWarIc6td7cI`, P1): `harness.mjs` `getFindingSignature` 要求正整數行號並綁定佐證中繼資料。

---

## 五、169 筆完整處置明細清冊 (Full 169 Threads Ledger)

| 編號 | Thread ID | 嚴重性 | 狀態 | 檔案位置 | 處置分類 | 對應 Commit / 反證依據 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `qo0uL` | P1 | Outdated | `src/core/harness.mjs:null` | **FIXED_CANDIDATE** | 2709ea2; Commit 2709ea2; locator src/core/harness.mjs:458-477. Zero-finding gate requires authentic independe... |
| 2 | `qo0uP` | P1 | Outdated | `src/core/independent-verifier.mjs:null` | **FIXED_CANDIDATE** | 2580fd5; Commit 2580fd5; locator src/core/independent-verifier.mjs:252. trustedVerificationRegistry is an une... |
| 3 | `qo0uT` | P1 | Current | `scripts/dogfood-review.mjs:1460` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in Phase 1 & dogfood: in `scripts/dogfood-review.mjs:1010-1120`, pre-extracts exact-head ... |
| 4 | `qo0uZ` | P1 | Outdated | `src/core/independent-verifier.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Commits 0b90fcb, 6e2f120, e7f1527; locator src/core/independent-verifier.mjs:489-560, 1438-1460. has... |
| 5 | `qo0uc` | P1 | Current | `src/core/harness.mjs:934` | **FIXED_CANDIDATE** | HISTORICAL; Remediated prior to Phase 1: DEFECTS_FOUND without omissions fails closed with decision: 'block'. (R... |
| 6 | `qo0ue` | P2 | Current | `src/core/context-builder.mjs:1466` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 2580fd5: in `src/core/context-builder.mjs:1260-1285`, enforces AST context byte... |
| 7 | `qo0uh` | P2 | Current | `src/core/context-builder.mjs:1907` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit a71082c: in `src/core/context-builder.mjs:1590-1615`, scopes single-file callee... |
| 8 | `qo0uk` | P1 | Outdated | `src/core/harness.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Commits 3e95008, c418bb1; locator src/core/harness.mjs:403-429. _evaluateGateDecisionCore executes b... |
| 9 | `qo0un` | P1 | Outdated | `src/core/harness.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Commits 23a82a2, 2580fd5; locator src/core/harness.mjs:433-440. Enforces that zero-finding consensus... |
| 10 | `qo0ur` | P1 | Outdated | `src/core/independent-verifier.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in Phase 2: In `src/core/independent-verifier.mjs:1393-1396, 1439-1444` (`validateVerific... |
| 11 | `qo0uv` | P2 | Outdated | `src/core/context-builder.mjs:null` | **FIXED_CANDIDATE** | 2580fd5; Commit 2580fd5; locator src/core/context-builder.mjs:461. classifySensitiveCategory normalizes camel... |
| 12 | `qo0u0` | P2 | Outdated | `src/core/independent-verifier.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in Phase 2: In `src/core/independent-verifier.mjs:2320-2335` (`conductIndependentVerifica... |
| 13 | `qwj_j` | P1 | Outdated | `src/core/context-builder.mjs:null` | **FIXED_CANDIDATE** | 2580fd5; Commit 2580fd5; locator src/core/context-builder.mjs:969-982. When fileCalleesCount >= MAX_CALLEES_P... |
| 14 | `qwj_p` | P1 | Outdated | `src/core/independent-verifier.mjs:null` | **FIXED_CANDIDATE** | c99050a; Commit c99050a; locator src/core/independent-verifier.mjs:1543-1577. In Clean Challenge mode, missin... |
| 15 | `qwj_t` | P1 | Outdated | `scripts/dogfood-review.mjs:null` | **FIXED_CANDIDATE** | c99050a; Commit c99050a; locator scripts/dogfood-review.mjs:796-809. Verifier adapter selection decouples fro... |
| 16 | `qwj_y` | P1 | Current | `src/core/context-builder.mjs:1087` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 2580fd5 & bd9bc90: in `src/core/context-builder.mjs:890-915`, when `git show <h... |
| 17 | `qwj_0` | P2 | Outdated | `src/core/context-builder.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Commits 2580fd5, a771cd6; locator src/core/context-builder.mjs:495-560, 684. stripCommentsAndStrings... |
| 18 | `qwj_9` | P2 | Current | `scripts/dogfood-review.mjs:592` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 2580fd5 & 089b66f: in `scripts/dogfood-review.mjs:570-585`, validates caller-su... |
| 19 | `rTXZd` | P1 | Outdated | `src/core/context-builder.mjs:null` | **FIXED_CANDIDATE** | 2580fd5; Commit 2580fd5; locator src/core/context-builder.mjs:309-328. findFunctionDefinitions tracks parenth... |
| 20 | `rTXZh` | P1 | Outdated | `src/core/context-builder.mjs:null` | **FIXED_CANDIDATE** | 2580fd5; Commit 2580fd5; locator src/core/context-builder.mjs:1486-1498, 1626-1638. When Layer 1 byte budgeti... |
| 21 | `rTXZk` | P2 | Current | `src/core/context-builder.mjs:372` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 2580fd5: in `src/core/context-builder.mjs:265-290`, implemented indentation-bas... |
| 22 | `rTXZl` | P2 | Current | `src/adapters/staged-review.mjs:239` | **DUPLICATE_CANDIDATE** | HISTORICAL; Duplicate of Thread PRRT_kwDOUWarIc6rvWjN (Checkpoint filename collision resistance). Remediated in ... |
| 23 | `rTXZn` | P1 | Outdated | `src/core/independent-verifier.mjs:null` | **FIXED_CANDIDATE** | 05fb0fa; Commit 05fb0fa; locator src/core/independent-verifier.mjs:1417-1420. Under Default-Deny, omissions m... |
| 24 | `rTowe` | P1 | Outdated | `src/core/independent-verifier.mjs:null` | **FIXED_CANDIDATE** | 2580fd5; Commit 2580fd5; locator src/core/independent-verifier.mjs:440. issueVerificationRecordFromOutput reg... |
| 25 | `rTowi` | P2 | Outdated | `src/core/context-builder.mjs:null` | **FIXED_CANDIDATE** | 2580fd5; Commit 2580fd5; locator src/core/context-builder.mjs:1358-1365. Uses nullish check fileContent === n... |
| 26 | `rTowl` | P1 | Outdated | `src/core/independent-verifier.mjs:null` | **FIXED_CANDIDATE** | 2580fd5; Commit 2580fd5; locator src/core/independent-verifier.mjs:385-388, 2346-2349. Defensive check guaran... |
| 27 | `rTowo` | P2 | Current | `src/core/context-builder.mjs:1054` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 2580fd5: in `src/core/context-builder.mjs:855-875`, bounds snippet lines to 500... |
| 28 | `rTowq` | P1 | Outdated | `src/core/context-builder.mjs:null` | **FIXED_CANDIDATE** | 2580fd5; Commit 2580fd5; locator src/core/context-builder.mjs:274-292. findFunctionDefinitions rejects call e... |
| 29 | `rTowu` | P1 | Current | `scripts/dogfood-review.mjs:1441` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit c99050a & bd9bc90: in `scripts/dogfood-review.mjs:1305-1320`, truncated diffs s... |
| 30 | `rVNc1` | P1 | Outdated | `src/core/independent-verifier.mjs:null` | **FIXED_CANDIDATE** | 2580fd5; Commit 2580fd5; locator src/core/independent-verifier.mjs:1594-1602. All unresolved sensitive contex... |
| 31 | `rVNc5` | P1 | Current | `src/core/context-builder.mjs:1523` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 2580fd5: in `src/core/context-builder.mjs:1320-1340`, preserves multiple diff h... |
| 32 | `rVNc6` | P1 | Current | `src/core/context-builder.mjs:901` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 2580fd5: in `src/core/context-builder.mjs:1210-1230`, distinguishes between mem... |
| 33 | `rY13u` | P1 | Outdated | `src/core/independent-verifier.mjs:null` | **FIXED_CANDIDATE** | 3e95008; Commit 3e95008; locator src/core/independent-verifier.mjs:2143-2155, 2361. Canonical normContract.ex... |
| 34 | `rY131` | P2 | Outdated | `src/core/independent-verifier.mjs:null` | **DUPLICATE_CANDIDATE** | HISTORICAL; Duplicate of Thread PRRT_kwDOUWarIc6rvCBQ (Verify omission locators against the reviewed diff). Reme... |
| 35 | `rY139` | P1 | Outdated | `src/core/independent-verifier.mjs:null` | **FIXED_CANDIDATE** | 23a82a2; Commit 23a82a2; locator src/core/independent-verifier.mjs:1531-1541. In clean_challenge mode (review... |
| 36 | `rY14D` | P2 | Current | `src/core/git-collector.mjs:49` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 2580fd5: in `src/core/git-collector.mjs:45-60`, partitions exact-head cache key... |
| 37 | `ra7kH` | P1 | Outdated | `src/adapters/review-orchestrator.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Commits c418bb1, 0ac63a1; locator src/adapters/review-orchestrator.mjs:51-95, 345-360. buildCanonica... |
| 38 | `ra7kM` | P1 | Current | `src/core/context-builder.mjs:1158` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 2580fd5: in `src/core/context-builder.mjs:960-985`, unresolved imported sensiti... |
| 39 | `ra7kS` | P2 | Current | `src/core/context-builder.mjs:790` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit a771cd6: in `src/core/context-builder.mjs:660-685`, reconstructs block-comment ... |
| 40 | `ra7kY` | P1 | Current | `src/core/harness.mjs:621` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in Phase 1: in `_evaluateGateDecisionCore` and `_evaluatePostVerificationGateCore`, when ... |
| 41 | `ra7ki` | P2 | Outdated | `scripts/dogfood-review.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Remediated via REMEDIATION-007 §3.3.4 (Dual Visibility): In `scripts/dogfood-review.mjs:1010-1120`, ... |
| 42 | `ra7kt` | P1 | Outdated | `src/adapters/review-prompts.mjs:null` | **FIXED_CANDIDATE** | 3e95008; Commit 3e95008; locator src/adapters/review-prompts.mjs:163-260. Callee definitions and XML attribut... |
| 43 | `ra7k3` | P1 | Outdated | `src/core/real-benchmark-runner.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 2709ea2: in `src/core/real-benchmark-runner.mjs:90-110`, segregates preliminary... |
| 44 | `re305` | P1 | Outdated | `src/adapters/review-orchestrator.mjs:null` | **FIXED_CANDIDATE** | 0ac63a1; Commit 0ac63a1; locator src/adapters/review-orchestrator.mjs:51-95. buildCanonicalRunContext strictl... |
| 45 | `re31A` | P1 | Outdated | `src/core/context-builder.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Commits 2580fd5, 76e8652; locator src/core/context-builder.mjs:700-740. Qualified calls (auth.valida... |
| 46 | `re31E` | P1 | Outdated | `src/core/context-builder.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 2580fd5: in `src/core/context-builder.mjs:190-210`, tracks multiline template l... |
| 47 | `re31K` | P1 | Outdated | `scripts/dogfood-review.mjs:1388` | **FIXED_CANDIDATE** | 8375c65; Commit 8375c65 / 02be43c; locator scripts/dogfood-review.mjs:1013-1028. Extraction failures register... |
| 48 | `re31P` | P1 | Outdated | `src/core/harness.mjs:null` | **FIXED_CANDIDATE** | c99050a; Commit c99050a; locator src/core/harness.mjs:843-863. Verifier DEFECTS_FOUND without SUPPORTED omiss... |
| 49 | `re31W` | P1 | Outdated | `src/core/independent-verifier.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in Phase 2: In `src/core/independent-verifier.mjs:506-538` (`hasConcreteCounterexample`),... |
| 50 | `rfkYK` | P1 | Outdated | `scripts/dogfood-review.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Commits cc1de22, bd9bc90; locator scripts/dogfood-review.mjs:976-989. Absence of trusted repository ... |
| 51 | `rfkYW` | P2 | Outdated | `src/core/context-builder.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 2580fd5: in `src/core/context-builder.mjs:1355-1375`, treats deleted files as v... |
| 52 | `rfkYc` | P2 | Outdated | `src/core/independent-verifier.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in Phase 2: In `src/core/independent-verifier.mjs:1373-1380` (`validateVerificationOutput... |
| 53 | `rfkYi` | P1 | Current | `src/adapters/review-prompts.mjs:260` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 3e95008: in `src/adapters/review-prompts.mjs:245-265`, binds each extracted cal... |
| 54 | `rhwEt` | P1 | Outdated | `src/adapters/review-orchestrator.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; The review thread reported that orchestrateReview dropped diffTier when calling evaluateGateDecision... |
| 55 | `rhwEx` | P2 | Outdated | `src/core/context-builder.mjs:null` | **FIXED_CANDIDATE** | 2580fd5; Commit 2580fd5; locator src/core/context-builder.mjs:1358-1365, src/core/git-collector.mjs:44-67. Ex... |
| 56 | `rhwE0` | P2 | Current | `src/core/review-run-report.mjs:130` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 05fb0fa: in `src/core/review-run-report.mjs:125-145`, preserves verifier adviso... |
| 57 | `rhwE4` | P2 | Current | `src/core/context-builder.mjs:461` | **DUPLICATE_CANDIDATE** | HISTORICAL; Duplicate of Thread PRRT_kwDOUWarIc6rTXZk (Python indentation boundary extraction). Remediated in co... |
| 58 | `riPTk` | P1 | Outdated | `src/core/harness.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Remediated prior to Phase 1: enforces pairwise finding-set signature binding when boundProducerFindi... |
| 59 | `riPTp` | P1 | Outdated | `src/core/context-builder.mjs:null` | **FIXED_CANDIDATE** | 76e8652; Commit 76e8652; locator src/core/context-builder.mjs:735-755. Callee candidate deduplication key inc... |
| 60 | `riPTv` | P2 | Outdated | `src/core/harness.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in Phase 1: in `_evaluateGateDecisionCore` and `_evaluatePostVerificationGateCore`, insta... |
| 61 | `riPT0` | P1 | Outdated | `scripts/dogfood-review.mjs:null` | **FIXED_CANDIDATE** | 1c33d99; Commit 1c33d99; locator scripts/dogfood-review.mjs:991-1120. Validates headSha, repositoryRoot, cont... |
| 62 | `rrHOT` | P1 | Outdated | `src/core/harness.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Commits 0b90fcb, 6e2f120; locator src/core/harness.mjs:260-280. getFindingSignature incorporates tit... |
| 63 | `rrHOW` | P1 | Current | `src/core/context-builder.mjs:764` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 76e8652: in `src/core/context-builder.mjs:635-655`, recognizes optional chainin... |
| 64 | `rrHOY` | P2 | Outdated | `src/core/context-builder.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 2580fd5: in `src/core/context-builder.mjs:1355-1375`, reads renamed files from ... |
| 65 | `rrHOb` | P2 | Current | `src/adapters/staged-review.mjs:240` | **DUPLICATE_CANDIDATE** | HISTORICAL; Duplicate of Thread PRRT_kwDOUWarIc6rvWjN (Checkpoint filename collision resistance). Remediated in ... |
| 66 | `rrHOc` | P1 | Current | `src/core/context-builder.mjs:1907` | **DUPLICATE_CANDIDATE** | HISTORICAL; Duplicate of Thread PRRT_kwDOUWarIc6qo0uh (Scope single-file callee discovery). Remediated in commit... |
| 67 | `rrUDl` | P1 | Outdated | `src/core/context-builder.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 76e8652: in `src/core/context-builder.mjs:1005-1030`, resolves `this.method` an... |
| 68 | `rrUDp` | P1 | Outdated | `src/core/independent-verifier.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in Phase 2: In `src/core/independent-verifier.mjs:1765-1785` (`CliVerifierAdapter`), trac... |
| 69 | `rrUDs` | P2 | Current | `src/core/git-collector.mjs:32` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 2580fd5: in `src/core/git-collector.mjs:30-45`, bounds exact-head content cache... |
| 70 | `rr-I6` | P1 | Current | `src/core/context-builder.mjs:826` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 76e8652: in `src/core/context-builder.mjs:695-720`, classifies receiver securit... |
| 71 | `rr-I-` | P1 | Current | `src/core/context-builder.mjs:671` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit a771cd6: in `src/core/context-builder.mjs:540-565`, parses template interpolati... |
| 72 | `rr-JA` | P1 | Outdated | `src/core/independent-verifier.mjs:null` | **FIXED_CANDIDATE** | 0b90fcb; Commit 0b90fcb; locator src/core/independent-verifier.mjs:687-730. mergeContextGaps unions caller ga... |
| 73 | `rr-JC` | P1 | Current | `src/core/context-builder.mjs:1150` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 2580fd5: in `src/core/context-builder.mjs:950-975`, promotes unresolved sensiti... |
| 74 | `rr-JF` | P1 | Outdated | `src/adapters/review-orchestrator.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in Phase 3 (R3 Run ID Binding & Anti-Replay): in `src/adapters/review-orchestrator.mjs:56... |
| 75 | `rsKB4` | P1 | Current | `src/core/context-builder.mjs:764` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 76e8652: in `src/core/context-builder.mjs:635-655`, recognizes call expressions... |
| 76 | `rsKB6` | P1 | Outdated | `scripts/dogfood-review.mjs:null` | **FIXED_CANDIDATE** | 0b90fcb; Commit 0b90fcb; locator scripts/dogfood-review.mjs:1033-1078. Declared digests validated against rec... |
| 77 | `rsKB8` | P1 | Outdated | `src/core/harness.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in Phase 1: in `normalizeFinding`, provider-local finding IDs matching generic numeric pa... |
| 78 | `rsKB_` | P1 | Outdated | `src/core/harness.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in Phase 1 (including P1-HARNESS-EXCLUSION-PLATFORM-OVERRIDE-01): implemented and exporte... |
| 79 | `rsKCC` | P1 | Current | `src/core/context-builder.mjs:1035` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 2580fd5: in `src/core/context-builder.mjs:835-855`, when callee body exceeds ma... |
| 80 | `rsajY` | P1 | Outdated | `src/core/context-builder.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 76e8652: in `src/core/context-builder.mjs:690-715`, treats namespace-scoped cal... |
| 81 | `rsajc` | P1 | Current | `src/core/context-builder.mjs:1111` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 2580fd5: in `src/core/context-builder.mjs:910-935`, resolves import aliases to ... |
| 82 | `rsajd` | P2 | Outdated | `scripts/dogfood-review.mjs:null` | **DUPLICATE_CANDIDATE** | HISTORICAL; Duplicate of Thread 22 (PRRT_kwDOUWarIc6ra7ki). Remediated via §3.3.4 Dual Visibility pre-extraction... |
| 83 | `rte6b` | P2 | Current | `src/core/independent-verifier.mjs:1307` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in Phase 2: In `src/core/independent-verifier.mjs:809-840, 2132-2140` (`buildVerification... |
| 84 | `rte6j` | P1 | Current | `src/core/harness.mjs:1196` | **FIXED_CANDIDATE** | HISTORICAL; Remediated prior to Phase 1: ungrounded contested omissions without substantive counter-evidence fai... |
| 85 | `rte6o` | P1 | Current | `src/core/context-builder.mjs:1139` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 2580fd5: in `src/core/context-builder.mjs:940-965`, parses import statements ad... |
| 86 | `rte6t` | P1 | Current | `src/core/context-builder.mjs:764` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 76e8652: in `src/core/context-builder.mjs:635-655`, recognizes computed member ... |
| 87 | `rte6z` | P1 | Current | `src/core/context-builder.mjs:790` | **DUPLICATE_CANDIDATE** | HISTORICAL; Duplicate of Thread PRRT_kwDOUWarIc6ra7kS (Lexical state reset across diff hunks). Remediated in com... |
| 88 | `rtv6E` | P1 | Outdated | `scripts/dogfood-review.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Commits cc1de22, bd9bc90; locator scripts/dogfood-review.mjs:976-989. Omitted repository or object m... |
| 89 | `rtv6M` | P1 | Outdated | `scripts/dogfood-review.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Commits cf6be07, eda22b9, e7f1527; locator scripts/dogfood-review.mjs:1091-1100. Reject manifests wh... |
| 90 | `rtv6N` | P2 | Current | `src/core/real-benchmark-runner.mjs:210` | **DUPLICATE_CANDIDATE** | HISTORICAL; Duplicate of Thread PRRT_kwDOUWarIc6ra7k3 (Preliminary approvals in benchmark scoring). Remediated i... |
| 91 | `rtv6O` | P2 | Current | `src/core/independent-verifier.mjs:2072` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in Phase 2: In `src/core/independent-verifier.mjs:1492-1515` (`validateVerificationOutput... |
| 92 | `rvCBG` | P1 | Outdated | `src/core/harness.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in Phase 1: in `_evaluateGateDecisionCore` and `_evaluatePostVerificationGateCore`, raw h... |
| 93 | `rvCBL` | P1 | Outdated | `src/core/harness.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in Phase 1: in `src/core/harness.mjs`, `getFindingSignature` serializes finding fields as... |
| 94 | `rvCBQ` | P1 | Current | `src/core/independent-verifier.mjs:1787` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in Phase 2: In `src/core/independent-verifier.mjs:1409-1445` (`validateVerificationOutput... |
| 95 | `rvCBT` | P1 | Current | `src/core/context-builder.mjs:386` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 2580fd5 & a771cd6: in `src/core/context-builder.mjs:275-300`, strips comments a... |
| 96 | `rvCBW` | P1 | Current | `scripts/dogfood-review.mjs:1433` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 2580fd5: in `src/core/context-builder.mjs:945-965`, ignores binary assets in AS... |
| 97 | `rvWjN` | P2 | Current | `src/adapters/staged-review.mjs:238` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 089b66f: in `scripts/dogfood-review.mjs:585-600`, appends SHA-256 hash prefix t... |
| 98 | `rvWjO` | P1 | Current | `src/core/context-builder.mjs:1907` | **DUPLICATE_CANDIDATE** | HISTORICAL; Duplicate of Thread PRRT_kwDOUWarIc6qo0uh (Scope single-file callee discovery). Remediated in commit... |
| 99 | `rxCha` | P1 | Current | `scripts/dogfood-review.mjs:1104` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 089b66f & ebe28be: in `scripts/dogfood-review.mjs:980-1010` and `src/adapters/s... |
| 100 | `rxChi` | P2 | Outdated | `src/core/independent-verifier.mjs:null` | **DUPLICATE_CANDIDATE** | HISTORICAL; Duplicate of Thread PRRT_kwDOUWarIc6rrUDp (Enforce the verifier output-size limit while streaming). ... |
| 101 | `r0R6i` | P1 | Outdated | `src/core/context-builder.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 2580fd5: in `src/core/context-builder.mjs:355-375`, tokenizes regex literals be... |
| 102 | `r0R6m` | P2 | Current | `src/core/git-collector.mjs:65` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 2580fd5: in `src/core/git-collector.mjs:60-75`, failed exact-head lookups are n... |
| 103 | `r1Bt0` | P1 | Outdated | `src/adapters/review-orchestrator.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in Phase 3 (R1 Canonical Diff Digest): in `src/adapters/review-orchestrator.mjs:92-99` (`... |
| 104 | `r1Bt4` | P2 | Outdated | `src/core/independent-verifier.mjs:null` | **DUPLICATE_CANDIDATE** | HISTORICAL; Duplicate of Thread PRRT_kwDOUWarIc6rfkYc (Require an explicit boolean omission locator flag). Remed... |
| 105 | `r1Bt9` | P1 | Outdated | `src/core/context-builder.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 76e8652: in `src/core/context-builder.mjs:705-725`, preserves composite qualifi... |
| 106 | `r1BuC` | P1 | Current | `src/core/context-builder.mjs:826` | **DUPLICATE_CANDIDATE** | HISTORICAL; Duplicate of Thread PRRT_kwDOUWarIc6rr-I6 (Retain built-in-named calls on sensitive paths). Remediat... |
| 107 | `r1BuI` | P1 | Current | `src/core/context-builder.mjs:673` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit a771cd6: in `src/core/context-builder.mjs:545-565`, distinguishes division oper... |
| 108 | `r1BuM` | P2 | Current | `src/core/independent-verifier.mjs:2005` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in Phase 2: In `src/core/independent-verifier.mjs:1435-1445` (`validateVerificationOutput... |
| 109 | `sL8VK` | P1 | Outdated | `src/adapters/review-orchestrator.mjs:null` | **DUPLICATE_CANDIDATE** | HISTORICAL; Duplicate of Thread PRRT_kwDOUWarIc6rr-JF (Run ID binding and replay prevention). Remediated in Phas... |
| 110 | `sL8VO` | P1 | Outdated | `src/core/independent-verifier.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in Phase 2: In `src/core/independent-verifier.mjs:2210-2225` (`conductIndependentVerifica... |
| 111 | `sL8VV` | P1 | Outdated | `src/cli.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in Phase 3 (R5 CLI Clean Challenge & Shell Hardening): in `src/cli.mjs:53-75, 840-915`, i... |
| 112 | `sL8VY` | P1 | Outdated | `src/core/harness.mjs:null` | **DUPLICATE_CANDIDATE** | HISTORICAL; Duplicate of Thread PRRT_kwDOUWarIc6rsKB_ (Preserve case when binding exclusions). Remediated in Pha... |
| 113 | `sMI60` | P1 | Outdated | `src/core/context-builder.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit cf6be07 & eda22b9: in `src/core/context-builder.mjs:1570-1590`, missing `exactH... |
| 114 | `sMI66` | P2 | Current | `src/adapters/review-prompts.mjs:371` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 3e95008: in `src/adapters/review-prompts.mjs:355-380`, enforces context byte bu... |
| 115 | `sMI7C` | P1 | Outdated | `src/adapters/cli-transport.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit c418bb1 & Phase 3 (R2): in `src/adapters/review-orchestrator.mjs:199-224`, 6-so... |
| 116 | `sMI7L` | P1 | Outdated | `src/core/independent-verifier.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in Phase 2: In `src/core/independent-verifier.mjs:1544-1560` (`validateVerificationOutput... |
| 117 | `sMI7U` | P2 | Current | `scripts/triage-pr39-threads.mjs:605` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 9577d72: in `scripts/triage-pr39-threads.mjs:601`, added `FIX_REQUIRED_DUAL_VIS... |
| 118 | `sMI7c` | P1 | Outdated | `scripts/dogfood-review.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Commits a71082c, HEAD; locator src/adapters/staged-review.mjs:610-630. Preserves and merges caller-p... |
| 119 | `sPGEP` | P2 | Outdated | `src/core/harness.mjs:null` | **DUPLICATE_CANDIDATE** | HISTORICAL; Duplicate of Thread PRRT_kwDOUWarIc6ra7kY (Reject unknown producer verification modes). Remediated i... |
| 120 | `sPGEb` | P1 | Outdated | `src/core/git-collector.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 2580fd5 & Phase 3: in `src/core/git-collector.mjs:385-410`, distinguishes `base... |
| 121 | `sPGEl` | P1 | Outdated | `src/adapters/staged-review.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Commits 187a878, d621bd9, HEAD; locator src/adapters/staged-review.mjs:385-480. When callerContextPa... |
| 122 | `sPmwl` | P1 | Outdated | `src/core/context-builder.mjs:null` | **DUPLICATE_CANDIDATE** | HISTORICAL; Duplicate of Thread PRRT_kwDOUWarIc6re31E (Track multiline template literals while scanning braces).... |
| 123 | `sPmwt` | P2 | Outdated | `src/core/context-builder.mjs:null` | **DUPLICATE_CANDIDATE** | HISTORICAL; Duplicate of Thread PRRT_kwDOUWarIc6rfkYW (Treat deleted files as valid target-head absences). Remed... |
| 124 | `sPmwz` | P2 | Outdated | `scripts/dogfood-review.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Commits 187a878, d621bd9, HEAD; locator scripts/dogfood-review.mjs:1040-1175, 1400-1465. Provider te... |
| 125 | `sPmw9` | P1 | Current | `src/core/harness.mjs:608` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in Phase 1: in `_evaluatePostVerificationGateCore`, consensus capability validation (`isT... |
| 126 | `sUDZJ` | P1 | Current | `src/core/context-builder.mjs:424` | **DUPLICATE_CANDIDATE** | HISTORICAL; Duplicate of Thread PRRT_kwDOUWarIc6rTXZk (Python indentation boundary extraction). Remediated in co... |
| 127 | `sUDZV` | P1 | Outdated | `src/core/context-builder.mjs:null` | **DUPLICATE_CANDIDATE** | HISTORICAL; Duplicate of Thread PRRT_kwDOUWarIc6rrUDl (Resolve this/self calls within enclosing class). Remediat... |
| 128 | `sUDZa` | P2 | Current | `scripts/dogfood-review.mjs:1450` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit c99050a: in `scripts/dogfood-review.mjs:1315-1335`, derives Clean Challenge ver... |
| 129 | `sU7ZB` | P1 | Outdated | `src/core/context-builder.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 2580fd5: in `src/core/context-builder.mjs:415-440`, makes class scope brace tra... |
| 130 | `sU7ZH` | P2 | Outdated | `src/core/independent-verifier.mjs:null` | **DUPLICATE_CANDIDATE** | HISTORICAL; Duplicate of Thread PRRT_kwDOUWarIc6rvCBQ (Reject omission locators beyond the target file). Remedia... |
| 131 | `sU7ZN` | P1 | Outdated | `src/core/harness.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in Phase 1: in `_evaluateGateDecisionCore` and `_evaluatePostVerificationGateCore`, when ... |
| 132 | `slAMk` | P1 | Outdated | `src/adapters/staged-review.mjs:null` | **FIXED_CANDIDATE** | 089b66f; Commit 089b66f; locator src/adapters/staged-review.mjs:406-490. Recomputes candidate diff contentDig... |
| 133 | `slAMq` | P1 | Outdated | `src/adapters/staged-review.mjs:null` | **FIXED_CANDIDATE** | 089b66f; Commit 089b66f; locator src/adapters/staged-review.mjs:322-325. callerContextGaps now merges options... |
| 134 | `slAMv` | P1 | Current | `src/core/context-builder.mjs:790` | **DUPLICATE_CANDIDATE** | HISTORICAL; Duplicate of Thread PRRT_kwDOUWarIc6ra7kS (Reconstruct block-comment state across diff hunks). Remed... |
| 135 | `slAMz` | P2 | Outdated | `scripts/triage-pr39-threads.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Commits 089b66f, 9a59e90, HEAD; locator scripts/triage-pr39-threads.mjs:4-6. Synchronized CURRENT_HE... |
| 136 | `slAM6` | P1 | Current | `src/core/context-builder.mjs:593` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 2580fd5: in `src/core/context-builder.mjs:465-485`, adds access-control vocabul... |
| 137 | `slANA` | P2 | Current | `src/core/git-collector.mjs:32` | **DUPLICATE_CANDIDATE** | HISTORICAL; Duplicate of Thread PRRT_kwDOUWarIc6rrUDs (Bound exact-head content cache). Remediated in commit 258... |
| 138 | `slLWc` | P1 | Outdated | `src/adapters/review-orchestrator.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in Phase 3 (R2 Deterministic Objective Conflict): in `src/adapters/review-orchestrator.mj... |
| 139 | `slLWg` | P1 | Current | `src/core/context-builder.mjs:671` | **DUPLICATE_CANDIDATE** | HISTORICAL; Duplicate of Thread PRRT_kwDOUWarIc6rr-I- (Parse template interpolations for sensitive calls). Remed... |
| 140 | `slLWi` | P1 | Current | `src/core/context-builder.mjs:1035` | **DUPLICATE_CANDIDATE** | HISTORICAL; Duplicate of Thread PRRT_kwDOUWarIc6rsKCC (Mark truncated sensitive callees as unresolved). Remediat... |
| 141 | `slql5` | P1 | Outdated | `src/cli.mjs:null` | **DUPLICATE_CANDIDATE** | HISTORICAL; Duplicate of Thread PRRT_kwDOUWarIc6sL8VV (CLI Clean Challenge execution). Remediated in Phase 3 in ... |
| 142 | `slql7` | P1 | Outdated | `src/core/harness.mjs:null` | **DUPLICATE_CANDIDATE** | HISTORICAL; Duplicate of Thread PRRT_kwDOUWarIc6rsKB_ (Preserve case when binding excluded paths). Remediated in... |
| 143 | `slqmB` | P1 | Current | `src/adapters/review-orchestrator.mjs:495` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in Phase 3 (R4 Strict Risk Tier Validation): in `src/adapters/review-orchestrator.mjs:287... |
| 144 | `slqmD` | P2 | Outdated | `src/core/independent-verifier.mjs:null` | **DUPLICATE_CANDIDATE** | HISTORICAL; Duplicate of Thread PRRT_kwDOUWarIc6rfkYc (Reject non-boolean omission accuracy values). Remediated ... |
| 145 | `slqmG` | P2 | Current | `src/core/real-benchmark-runner.mjs:212` | **DUPLICATE_CANDIDATE** | HISTORICAL; Duplicate of Thread PRRT_kwDOUWarIc6ra7k3 (Keep preliminary cases out of final gate scores). Remedia... |
| 146 | `sl1Rc` | P1 | Outdated | `src/core/independent-verifier.mjs:null` | **DUPLICATE_CANDIDATE** | HISTORICAL; Duplicate of Thread PRRT_kwDOUWarIc6sL8VO (Include ChangeSet package gaps in verifier validation). R... |
| 147 | `sl1Rd` | P1 | Outdated | `src/adapters/staged-review.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 089b66f: in `src/adapters/staged-review.mjs:510-525`, wraps `normalizeCanonical... |
| 148 | `sl1Rg` | P1 | Outdated | `src/core/independent-verifier.mjs:null` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in Phase 2: In `src/core/independent-verifier.mjs:2134-2145` (`conductIndependentVerifica... |
| 149 | `sl1Ri` | P1 | Current | `src/core/context-builder.mjs:447` | **FIXED_CANDIDATE** | HISTORICAL; Remediated in commit 2580fd5: in `src/core/context-builder.mjs:335-360`, rejects bare call expressio... |
| 150 | `tdsmP` | P1 | Current | `src/cli.mjs:1066` | **FIXED_CANDIDATE** | c0c03e8ac45e279bec9978c1eb161f821578a23e; Commit c0c03e8; src/core/independent-verifier.mjs requires valid verificationRecord and fails closed... |
| 151 | `tdsmQ` | P1 | Outdated | `src/adapters/review-orchestrator.mjs:null` | **FIXED_CANDIDATE** | c0c03e8ac45e279bec9978c1eb161f821578a23e; Commit c0c03e8; src/adapters/review-orchestrator.mjs preserves preliminary status and never returns ... |
| 152 | `tdsmS` | P1 | Outdated | `src/adapters/staged-review.mjs:null` | **FIXED_CANDIDATE** | c0c03e8ac45e279bec9978c1eb161f821578a23e; Commit c0c03e8; src/core/harness.mjs evaluateGateDecision requires verificationMode === 'clean_chall... |
| 153 | `tdsmT` | P1 | Current | `scripts/dogfood-review.mjs:1115` | **FIXED_CANDIDATE** | c0c03e8ac45e279bec9978c1eb161f821578a23e; Commit c0c03e8; scripts/dogfood-review.mjs extracts exact-head source and diff across all changeSet.... |
| 154 | `tdsmV` | P1 | Outdated | `src/core/independent-verifier.mjs:null` | **FIXED_CANDIDATE** | c0c03e8ac45e279bec9978c1eb161f821578a23e; Commit c0c03e8; src/core/independent-verifier.mjs omission normalization downgrades missing evidence... |
| 155 | `tdsmY` | P1 | Outdated | `src/core/git-collector.mjs:null` | **FIXED_CANDIDATE** | c0c03e8ac45e279bec9978c1eb161f821578a23e; Commit c0c03e8; src/adapters/review-orchestrator.mjs enforces canonical RunContext for current chang... |
| 156 | `td7cF` | P1 | Current | `src/core/context-builder.mjs:320` | **FIXED_CANDIDATE** | 103e67b0fca12ed777a38ae50e5f135609b4bacd; Commit 103e67b; src/core/context-builder.mjs findBraceScopeEnd correctly skips regex literals (inclu... |
| 157 | `td7cG` | P1 | Current | `src/core/independent-verifier.mjs:2377` | **FIXED_CANDIDATE** | 103e67b0fca12ed777a38ae50e5f135609b4bacd; Commit 103e67b; src/core/independent-verifier.mjs tracks combined byte count across stdout and stder... |
| 158 | `td7cI` | P1 | Outdated | `src/core/harness.mjs:null` | **FIXED_CANDIDATE** | 103e67b0fca12ed777a38ae50e5f135609b4bacd; Commit 103e67b; src/core/harness.mjs getFindingSignature requires positive integer line numbers and ... |
| 159 | `tfxJh` | P1 | Outdated | `src/adapters/review-orchestrator.mjs:null` | **FIXED_CANDIDATE** | 352f24e50a902c8e862fe05748c131918cfbe517; Commit 352f24e; isolated benchmark execution via unforgeable WeakSet capability token (__bindBenchma... |
| 160 | `tfxJj` | P2 | Current | `src/cli.mjs:1157` | **FIXED_CANDIDATE** | 352f24e50a902c8e862fe05748c131918cfbe517; Commit 352f24e; src/cli.mjs exports runCliReviewSafely; formatSarifOutput handles null/missing conse... |
| 161 | `tfxJn` | P1 | Outdated | `src/adapters/review-orchestrator.mjs:null` | **FIXED_CANDIDATE** | 352f24e50a902c8e862fe05748c131918cfbe517; Commit 352f24e; src/adapters/review-orchestrator.mjs forwards runContext, patchObjective, and exclus... |
| 162 | `tfxJo` | P2 | Current | `src/adapters/cli-transport.mjs:269` | **FIXED_CANDIDATE** | 352f24e50a902c8e862fe05748c131918cfbe517; Commit 352f24e; src/adapters/cli-transport.mjs validates and enforces canonical objective bindings, ... |
| 163 | `tfxJq` | P1 | Outdated | `src/core/context-builder.mjs:null` | **FIXED_CANDIDATE** | 352f24e50a902c8e862fe05748c131918cfbe517; Commit 352f24e; src/core/context-builder.mjs extractCandidateCallSymbols recognizes optional-chainin... |
| 164 | `tfxJr` | P2 | Current | `src/adapters/review-prompts.mjs:263` | **FIXED_CANDIDATE** | 352f24e50a902c8e862fe05748c131918cfbe517; Commit 352f24e; src/adapters/review-prompts.mjs validates callee definitions and escapes/encodes XML... |
| 165 | `tgXSH` | P1 | Current | `src/adapters/staged-review.mjs:584` | **REPRODUCED_DEFECT** | PENDING_FIX; Dynamic reproduction confirmed in scratch/reproduce_5_p1.mjs: executeStagedReview accepts callerCont... |
| 166 | `tgXSI` | P1 | Current | `src/core/independent-verifier.mjs:486` | **REPRODUCED_DEFECT** | PENDING_FIX; Dynamic reproduction confirmed in scratch/reproduce_5_p1.mjs: registerTrustedContextPackage validate... |
| 167 | `tgXSK` | P1 | Current | `src/core/context-builder.mjs:1587` | **REPRODUCED_DEFECT** | PENDING_FIX; Dynamic reproduction confirmed in scratch/reproduce_5_p1.mjs: buildContextPackage in working-tree re... |
| 168 | `tgXSN` | P1 | Current | `src/core/context-builder.mjs:764` | **REPRODUCED_DEFECT** | PENDING_FIX; Dynamic reproduction confirmed in scratch/reproduce_5_p1.mjs: extractCandidateCallSymbols checks lin... |
| 169 | `tgXSQ` | P1 | Current | `src/core/context-builder.mjs:463` | **REPRODUCED_DEFECT** | PENDING_FIX; Dynamic reproduction confirmed in scratch/reproduce_5_p1.mjs: findFunctionDefinitions passes brace l... |
