# RFC-028-02: Distributed Swarm Orchestrator

- **Document ID**: `TF-RFC-028-02`
- **Schema Version**: `1.0.0`
- **Author**: Triad-Flow Core Architecture Working Group (@orchestrator)
- **Target Milestone**: Triad-Flow v2.12
- **Canonical Baseline Commit**: `2875c4f5e7cd5d38a45a8c2e791731e922df0c80` (v2.11.0 Tagged Release)
- **Preceding Standards**: `TF-SPEC-RECEIPT-v1.0.0`, `TF-RFC-027-01` (Chunk Manager & Context Optimization), `TF-RFC-027-02` (Tri-Party Quorum Consensus), `RFC-028-01` (Container Sandbox Pool)
- **Status**: Proposed / Authoritative Architecture Specification
- **Integrity Level**: Strict Fail-Closed / Zero External Dependencies

---

## 1. 摘要與願景 (Executive Summary & Status)

本規格書定義 Triad-Flow v2.12 里程碑之核心支柱 2：**分散式異質審查協調器 (Distributed Swarm Orchestrator)** 的正式通訊協議、演算法細節與容錯合約。

在面臨千行級巨型拉取請求（PR）、跨檔案符號調用以及多程式語言混編 Monorepo 的審查場景時，單一 Worker 循序處理將面臨模型上下文超載、跨檔案函式邊界割裂、以及單點超時崩潰等架構瓶頸。分散式異質審查協調器透過四大關鍵機制解決此問題：

1. **依賴感知分塊派發 (Dependency-Aware Partitioning)**：基於 AST 與呼叫圖（Call-Graph）分析跨檔案符號定義與引用，透過 Union-Find 演算法將具備強耦合關聯的檔案聚類至同一審查單元，杜絕跨函式界限被機械式割裂。
2. **中間憑據防偽鏈 (Cryptographic Intermediate Receipts)**：各分散式 Worker 回傳之子模組審查報告嚴格綁定 SHA-256 前向雜湊鏈（Hash Chain）與時間戳憑證，中央協調器在匯總審查前逐一核驗簽章與覆蓋完整性，任何未經授權的修改、漏失或順序錯亂均引發嚴格阻斷。
3. **抗震盪降級斷路器 (Fail-Closed Circuit Breaker)**：具備 `CLOSED`、`OPEN` 與 `HALF_OPEN` 狀態機，支援逾時重試、連續失敗快速失敗與 `UNINSPECTED_CHUNK` 降級防線，嚴禁發放未經檢驗的合格權威。
4. **即時工作區清掃連動 (Workspace Scrubbing On-Break)**：採納交叉互審建議，當斷路器觸發熔斷或逾時拋錯時，協調器主動連動底層沙盒池銷毀臨時 Worktree 與清理掛載目錄，防止磁碟孤兒與容器插槽洩漏。

全規格嚴格遵守 **零外部 npm 依賴 (`"dependencies": {}`)** 與 Node.js 18+ 跨平台原生 API。

---

## 2. 背景與痛點分析 (Context & Problem Statement)

### 2.1 傳統單機與簡單分塊之缺陷

在 Triad-Flow v2.11 以前，變更集分塊（`chunk-manager.mjs`）主要依賴檔案風險分級（Tier 1/2/3）與行數預算（Windows 6000 bytes, POSIX 64KB）進行切分。然而，實務運行存在以下結構性瓶頸：

1. **依賴割裂 (Broken Call-Graph Context)**：
   若檔案 `auth/token.mjs` 定義了 `verifyToken()`，而檔案 `auth/guard.mjs` 新增了對 `verifyToken()` 的調用，舊版分塊器可能將兩者分配至不同 Chunk 甚至不同 Worker。這導致 Sentry Reviewer 在審查 `guard.mjs` 時因缺乏 `token.mjs` 實作細節而產生「上下文盲區（Context Blindness）」，嚴重遺漏高危弱點。
2. **缺乏不可篡改的中間狀態證明 (Lack of Cryptographic Provenance)**：
   在多節點分散式環境中，若某個 Worker 中間節點受到惡意竄改、網路丟包或中間代理緩存干擾，中央協調器無法數學證明各 Chunk 報告之原始真實性與順序完整性。
3. **假綠燈靜默風險 (Silent Swallowing on Worker Failure)**：
   當部分節點逾時或程序死鎖時，若協調器僅以「忽略該分塊」或「降級為無審查通過」結案，系統將直接違背 Triad-Flow 的核心不變量「Strict Fail-Closed」。

---

## 3. 規範性架構設計 (Normative Architecture Specification)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          ChangeSet Input Package                            │
│           (Files, Unified Diff Hunks, Symbol References, Risk Tiers)        │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│               Dependency-Aware Partitioning Engine (Union-Find)             │
│   - Multi-Language AST Symbol Definition Extraction (JS, Py, Go, C/C++)     │
│   - Import / Require / Include / Call-Graph Dependency Analysis             │
│   - Connected Components Clustering (Preserving Interdependent Functions)    │
│   - Priority Tier Inheritance & Byte-Ceiling Sub-Partitioning               │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                  ┌────────────────────┴────────────────────┐
                  │ Dispatch with Circuit Breakers & Pool   │
                  ▼                                         ▼
┌───────────────────────────────────┐     ┌───────────────────────────────────┐
│     Worker Partition Task 1       │     │     Worker Partition Task 2       │
│  ┌─────────────────────────────┐  │     │  ┌─────────────────────────────┐  │
│  │ CircuitBreaker (State/Retry)│  │     │  │ CircuitBreaker (State/Retry)│  │
│  └──────────────┬──────────────┘  │     │  └──────────────┬──────────────┘  │
│                 ▼                 │     │                 ▼                 │
│    Container Sandbox Execution    │     │    Container Sandbox Execution    │
│    (Workspace Scrub on Abort)     │     │    (Workspace Scrub on Abort)     │
└─────────────────┬─────────────────┘     └─────────────────┬─────────────────┘
                  │                                         │
                  └────────────────────┬────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│               Cryptographic Intermediate Receipt Hash Chain                 │
│                                                                             │
│   [Genesis Hash]                                                            │
│         │                                                                   │
│         ▼                                                                   │
│   [Receipt 1] ──SHA-256──> [Receipt 2] ──SHA-256──> [Receipt N (Root Hash)] │
│   (Partition 1)            (Partition 2)            (Partition N)           │
│                                                                             │
│   Anti-Tamper & Forward Continuity Verification: verifyReceiptChain()       │
│   Coverage Completeness Gate: verifyCoverageCompleteness()                  │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                     Central Consensus Synthesis Engine                      │
│   - Uninspected Chunk Detection (Immediate Fail-Closed `verdict: "error"`)   │
│   - Multi-Sentry Finding Deduplication & Severity Aggregation               │
│   - Root Receipt Hash & Audit Provenance Ledger Export                      │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. 模組詳細規格與通訊合約 (Module Contracts & Protocols)

### 4.1 依賴感知分塊引擎 (Dependency-Aware Partitioning)

#### 4.1.1 跨語言符號與依賴解析器 (`extractCrossFileDependencies`)
協調器解析 Unified Diff 與變更檔案，識別各檔案新增與修改之頂層符號：
- **JavaScript / TypeScript**：
  - 定義：`function <name>(`, `class <name>`, `const|let|var <name> = (async)? (...) =>`
  - 依賴：`import ... from '...'`, `require('...')`, `export ... from '...'`
- **Python**：
  - 定義：`def <name>(`, `class <name>:`
  - 依賴：`from <module> import <sym>`, `import <module>`
- **Go**：
  - 定義：`func <name>(`, `type <name>`
  - 依賴：`import "..."`
- **C / C++**：
  - 依賴：`#include "..."`, `#include <...>`

#### 4.1.2 互依聚類演算法 (`UnionFind`)
```javascript
// 對所有存在依賴邊 (from, to) 的節點進行連通元件聚類
const uf = new UnionFind(filePaths);
for (const edge of dependencyEdges) {
  if (filePaths.includes(edge.from) && filePaths.includes(edge.to)) {
    uf.union(edge.from, edge.to);
  }
}
const clusters = uf.getClusters();
```
- **優先級繼承規則**：若聚類中任一檔案屬於 `Tier 1 (Critical)`，整組聚類之優先級即提升為 `Tier 1`。
- **安全超限子分塊 (Safe Sub-Partitioning)**：若單一聚類的差異總位元組超出主機環境安全上限（`maxChunkBytes`），引擎在保留 `clusterId`、`clusterTotalSubChunks` 與相依邊中繼資料的前提下，將其劃分為連續子分塊，防止 Windows 平台 `ARG_MAX` 溢位。

### 4.2 前向 SHA-256 中間憑據防偽鏈 (Cryptographic Intermediate Receipts)

所有分散式節點在完成子任務或遭遇中斷時，均必須產出不可變的 `IntermediateReceipt`：

```typescript
interface IntermediateReceipt {
  receiptId: string;              // "rcpt-{runId}-{seq}"
  sequenceNumber: number;         // 1, 2, ... N (單調遞增)
  partitionId: string;            // 所屬分塊識別碼
  clusterId: string;              // 依賴聚類識別碼
  workerId: string;               // 執行節點識別碼
  status: "INSPECTED" | "UNINSPECTED_CHUNK";
  targetFiles: string[];          // 本分塊包含之標準化路徑 (排序)
  contentDigest: string;          // 分塊 Diff Hunk 之 SHA-256 ("sha256:...")
  resultDigest: string;           // 規範化審查輸出之 SHA-256
  previousReceiptHash: string;    // 前一項憑據之 receiptHash (首項為 GENESIS)
  receiptHash: string;            // 本憑據簽章 SHA-256
  timestamp: string;              // ISO-8601 UTC
  findings: Array<object>;        // 發現弱點清單
  coverage: {
    coveredFiles: string[];
    omittedFiles: Array<object>;
  };
  error: string | null;           // 錯誤訊息 (若執行失敗)
}
```

#### 4.2.1 創世憑據雜湊 (Genesis Hash)
```
GENESIS_RECEIPT_HASH = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
```

#### 4.2.2 雜湊鏈簽章公式
```
receiptHash = SHA-256(canonicalJsonStringify({
  contentDigest,
  partitionId,
  previousReceiptHash,
  receiptId,
  resultDigest,
  sequenceNumber,
  status,
  targetFiles,
  timestamp,
  workerId
}))
```

#### 4.2.3 防偽校驗與斷鏈判定 (`verifyReceiptChain`)
中央協調器在彙整結果前，必須逐項重算 `receiptHash`，並核驗 `receipt[i].previousReceiptHash === receipt[i-1].receiptHash`。若檢測出任何不一致、欄位篡改、順序跳躍或憑據遺漏，立即拋出 `ReceiptChainTamperedError` 並強制中斷流程。

### 4.3 抗震盪降級斷路器 (Fail-Closed Circuit Breaker)

各 Worker 綁定獨立的斷路器實例，具備以下三態轉換邏輯：

1. **CLOSED (正常運作)**：
   - 任務正常派發至 Worker。
   - 每次執行包裹於逾時控制計時器中（預設 `timeoutMs: 5000`）。
   - 支援有限次數自動重試（`maxRetries: 1`）。若重試成功，重設失敗計數。
   - 若連續失敗次數達閥值（預設 `failureThreshold: 3`），狀態立即轉換為 `OPEN`。
2. **OPEN (熔斷快拒)**：
   - 所有後續派發請求不呼叫 Worker，直接拋出 `CircuitBreakerOpenError` 實施快速失敗。
   - 記錄 `lastFailureTime`。當冷卻時間超過 `resetTimeoutMs`（預設 5000ms），自動過渡至 `HALF_OPEN`。
3. **HALF_OPEN (探針試探)**：
   - 僅允許單一試探性請求通過。
   - 若試探成功，將失敗計數歸零，狀態恢復為 `CLOSED`。
   - 若試探失敗，立即退回 `OPEN` 並刷新冷卻計時。

#### 4.3.1 嚴格 Fail-Closed 降級保障
當 Worker 逾時、崩潰或斷路器處於 `OPEN` 狀態時，協調器：
- **絕不靜默吞沒異常**。
- 將該 Partition 封裝為 `status: "UNINSPECTED_CHUNK"` 的中間憑據，並正確鏈入雜湊鏈。
- 在最終共識判定中，只要存在任何 `UNINSPECTED_CHUNK`，總結報告一律標記 `ok: false`，裁定為 `verdict: "error"`，並注入 `severity: "critical"` 的未審查分塊警報。

---

## 5. 跨支柱審查沉澱之架構強化 (Cross-Review Architecture Enhancements)

依據 2026-11-11 交叉互審（Cross-Worker Review）之決議，協調器實裝以下深化防禦：

### 5.1 逾時與熔斷時的即時 Workspace Scrubbing
在先前的原型中，當 Worker 逾時拋錯或斷路器快速失敗時，上層可能直接中斷流程，導致底層容器池中掛載的臨時 Worktree 未能徹底清除。
在本規範中，協調器在 `_invokeWorker` 執行環節導入強制清理與異常攔截：
```javascript
try {
  return await cb.execute(taskFn, { timeoutMs, maxRetries });
} catch (err) {
  // 觸發沙盒資源回收與工作目錄清掃
  if (typeof worker.cleanup === "function") {
    try { await worker.cleanup({ scrub: true, reason: err.message }); } catch {}
  }
  throw err;
}
```

### 5.2 搭配 AbortSignal 之協同中斷通道
協調器向 Worker 傳遞 `AbortSignal`。當 `SwarmTimeoutError` 被觸發時，計時器向 Worker 發送 abort 信號，通知容器池終止卡死行程（如死迴圈的測試腳本），防止容器槽位被永久佔據。

---

## 6. 品質閘門與驗收標準 (Quality Gates & Invariants)

| 檢驗指標 | 規範要求 | 驗收方式 |
|---|---|---|
| **執行時期依賴** | 嚴格 0 外部 npm 套件 (`"dependencies": {}`) | `node --test` 靜態掃描 package.json 與 import 語句 |
| **雜湊鏈不可篡改性** | 任何單一位元篡改 100% 觸發 `ReceiptChainTamperedError` | 單元測試模擬有效載荷篡改、順序倒置與斷鏈 |
| **覆蓋完整性契約** | 變更集檔案必須 100% 被 `INSPECTED` 或合法 `omitted` | `verifyCoverageCompleteness` 邊界測試 |
| **斷路器三態演進** | 達成閥值立即 `OPEN`，冷卻後試探 `HALF_OPEN`，成功即重設 | 時間加速模擬單元測試驗證狀態機轉換 |
| **Fail-Closed 絕對性** | 遭遇逾時或熔斷時，決不發放 `approve` 裁決 | 模擬故障節點，斷言 `ok === false` 且 `verdict === "error"` |
| **離線可測試性** | 離線環境 100% 通過全量測試 | `node --test tests/swarm-orchestrator.test.mjs` 零依賴通過 |

---

## 7. 結論與即刻實施計畫 (Next Steps)

本規範已透過原型實作 `src/core/swarm-orchestrator.mjs` 與合約測試 `tests/swarm-orchestrator.test.mjs`（19/19 通過）完成初步可行性驗證。下一階段將在 Phase 1 推進與 `ContainerSandboxPool`（RFC-028-01）及 `TaxonomyQuorumCalibrator`（RFC-028-04）之端到端協同整合。
