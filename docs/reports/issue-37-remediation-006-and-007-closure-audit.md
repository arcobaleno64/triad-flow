# Triad-Flow｜Issue #37 與 REMEDIATION-006 系統性結案稽核記錄
## AGY Transport & Staged Timeout Reliability Governance Closure

- **提報識別碼**：`TF-AUDIT-ISSUE-37-REMEDIATION-006-CLOSURE`
- **關聯議題**：GitHub Issue #37（`LOOP2-SYSTEMIC-REMEDIATION-006: AGY transport and staged timeout reliability`）
- **規範依據**：[`docs/specs/loop2-systemic-remediation-006-spec.md`](file:///C:/Users/arcobaleno/Documents/Code/triad-flow/docs/specs/loop2-systemic-remediation-006-spec.md)
- **程式碼落地提交**：
  - PR #38（提交 [`b28afc0`](file:///C:/Users/arcobaleno/Documents/Code/triad-flow)）：REMEDIATION-006 核心傳輸與有界調度器
  - PR #39（提交 [`cc94fae`](file:///C:/Users/arcobaleno/Documents/Code/triad-flow)）：Schema v2 G4 零發現反向驗證與全量治理
  - PR #41 至 #47（提交 [`f216b70`](file:///C:/Users/arcobaleno/Documents/Code/triad-flow) 至 [`a72e0a7`](file:///C:/Users/arcobaleno/Documents/Code/triad-flow)）：Gate G5 遞延議題加固（Checkpoint 雜湊、Prompt 上限、LRU 快取）
- **稽核基線**：`main` 最新提交 [`a72e0a7`](file:///C:/Users/arcobaleno/Documents/Code/triad-flow)
- **權限模式**：`SHADOW_DOGFOOD`（運行權限：`NONE`，嚴禁自動晉升至 `ADVISORY`）

---

## 一、Issue #37 八大驗收條件逐項核驗矩陣

| 驗收條件 (Exit / Acceptance Gates) | 具體證據與實體對應 | 判定 |
|---|---|---|
| **1. 基準線與 CYCLE-0028 證據歧異排查** | `CYCLE-0028`（`netty#17475`）於 [`loop2-systemic-remediation-006-spec.md §2.1`](file:///C:/Users/arcobaleno/Documents/Code/triad-flow/docs/specs/loop2-systemic-remediation-006-spec.md) 正式釐清為單一提供者（`agy` 315s）頂層延遲耗盡，非 Staged 分塊超時。歷史記錄零篡改。 | **PASS** |
| **2. 傳輸能力與安全約束實體驗證** | `src/adapters/cli-transport.mjs` 實作 NDJSON stream-json 協議；`tests/loop2-systemic-remediation-006.test.mjs`（29 項測試全綠）驗證 >35KB 載荷在 Windows 繞過 argv 上限，且非 SUCCESS 或遺失 result 事件強制 Fail-Closed。 | **PASS** |
| **3. 有界並行與自適應調度合約** | `src/adapters/staged-review.mjs` 實作預算前檢（`minViableChunkBudgetMs = 10s`）、動態 Wave 調度、有界工作池（預設 `maxConcurrency = 2`），並依 `chunkIndex` 嚴格順序還原結果。 | **PASS** |
| **4. 防虛假覆蓋、防孤兒程序、防無效重試** | 測試 `AbortSignal cleanly aborts all concurrent workers` 與 `Tier-1 failure` 中止邏輯全數通過，無懸掛子行程；未執行分塊嚴格標記為 `TIMEOUT` 或 `FAILED`，禁止偽造覆蓋。 | **PASS** |
| **5. REMEDIATION-006 前瞻規範凍結** | 規格書 [`docs/specs/loop2-systemic-remediation-006-spec.md`](file:///C:/Users/arcobaleno/Documents/Code/triad-flow/docs/specs/loop2-systemic-remediation-006-spec.md) 於動工前完成凍結與簽署。 | **PASS** |
| **6. 獨立迴歸重放與多樣化實測** | 實測樣本橫跨 Kafka（Java）、Flink（Java）、Curl（C）、Node.js（JS/C++）、CPython（C/Python）與 ClickHouse（C++）；迴歸測試 [`adversarial-m4-2-challenge.test.mjs`](file:///C:/Users/arcobaleno/Documents/Code/triad-flow/tests/adversarial-m4-2-challenge.test.mjs) 重放通過。 | **PASS** |
| **7. 嚴格可靠性出閘（超時率 < 5.0%）** | 在 `CYCLE-0040` 至 `CYCLE-0047` 共 8 輪前瞻實況循環中，超時循環數為 **0 / 8 = 0.0%**（遠低於 5.0% 門檻；歷史 Phase 4.4 殘留超時問題徹底根除）。 | **PASS** |
| **8. 獨立人類治理審查先於權限變更** | 運行權限維持 `NONE`，嚴格遵守不自動賦權原則；後續 `ADVISORY` 晉升需待人類治理委員會審議。 | **PASS** |

---

## 二、實地評測（CYCLE-0040～0047）前瞻超時指標實證對照

| 循環編號 | 目標專案與 PR | 變更規模 | 歷史傳輸問題 | 落地後實測超時數 (`timeoutCount`) | 耗時 (ms) | 狀態 |
|---|---|---|---|---:|---:|---|
| **CYCLE-0040** | `apache/kafka#23712` | 3 檔 (+110/-20) | argv 易超限 | **0** | 57,561 | 通過 |
| **CYCLE-0041** | `apache/flink#29410` | 8 檔 (+170/-2) | argv 易超限 | **0** | 99,585 | 通過 |
| **CYCLE-0042** | `curl/curl#23196` | 9 檔 (+259/-15) | argv 易超限 | **0** | 159,661 | 通過 |
| **CYCLE-0043** | `apache/flink#29356` | 3 檔 (+173/-12) | argv 易超限 | **0** | 165,581 | 通過 |
| **CYCLE-0044** | `nodejs/node#66565` | 3 檔 (+16/-13) | 常規 | **0** | 27,223 | 通過 |
| **CYCLE-0045** | `apache/kafka#23659` | 3 檔 (+348/-27) | argv 易超限 | **0** | 79,295 | 通過 |
| **CYCLE-0046** | `python/cpython#158468` | 3 檔 (+48/-11) | 常規 | **0** | 203,066 | 通過 |
| **CYCLE-0047** | `ClickHouse/ClickHouse#123335` | 4 檔 (+367/-8) | 巨量 C++ | **0** | 54,527 | 通過 |

**實證結論**：前瞻 8 輪全數維持 `timeoutCount = 0`，證明 `streamJson` 與有界動態排程器已徹底消除 Windows 上傳輸截斷與均分飢餓導致的連鎖超時缺陷。

---

## 三、治理結論與 Issue #37 關閉判定

1. **技術結論**：`LOOP2-SYSTEMIC-REMEDIATION-006` 之所有工作流（006-A 遙測、006-B Stdin 串流、006-C 有界調度、006-D 契約測試）均已完成實作、驗收測試與多語言實戰驗證。
2. **Issue #37 判定**：**核准正式關閉（CLOSED as COMPLETED）**。
3. **後續接軌**：解除 `CYCLE-0048` 的掛起狀態，於 Issue #35 規範下啟動新一輪具備反向驗證能力（Schema v2 + Clean Challenge）的 Shadow Dogfood 循環。
