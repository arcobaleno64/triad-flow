# RFC-028-01: Hot-Reuse Container Sandbox Pool Architecture Specification

- **Document ID**: `TF-RFC-028-01`
- **Schema Version**: `1.0.0`
- **Author**: Triad-Flow Core Architecture Working Group (Worker `@pool`)
- **Target Milestone**: Triad-Flow v2.12 (Pillar 1)
- **Baseline Commit**: `2875c4f5e7cd5d38a45a8c2e791731e922df0c80` (v2.11.0 Tagged Release)
- **Preceding Standards**: RFC-024 (Pluggable Sandbox Drivers), RFC-027 (Review Prompts & Context)
- **Status**: `PROPOSED_FOR_CORE_IMPLEMENTATION` / `RATIFIED_SPECIFICATION`
- **Integrity Level**: Strict Fail-Closed / Zero External Runtime Dependencies (`"dependencies": {}`)
- **Date**: 2026-11-11

---

## 1. 執行摘要 (Executive Summary)

在 Triad-Flow v2.11 架構中，系統成功落地了基於 `ContainerDriver` 的 Patch Jail 容器隔離機制，達成了冷容器執行隔離與跨 7 大語言生態系的合約對齊。然而，在實務高併發審查、分散式 Swarm 分塊評估以及大量候選補丁批次修復情境下，每次調度皆啟動冷容器（Cold Container Spawn: `docker run --rm`）造成顯著的容器初始化、映象檔掛載與網路命名空間構建延遲（單次執行需 1.5 ~ 3 秒），在高負載時嚴重限制了審查吞吐量。

**RFC-028-01** 規範並定義了 Triad-Flow v2.12 核心支柱 1：**容器沙盒熱重載與工作區池化架構 (Hot-Reuse Container Sandbox Pool)**。透過預先啟動長駐守護行程池（Warm Container Daemons）、單元級工作區熱掛載、基於 `docker exec` / `podman exec` 的指令多工轉發、嚴格非特權降權隔離、任務釋放即時工作區清掃（Scrub-on-Release），以及程序級信號陷阱（Zero Orphan Containers），將單次容器執行延遲從秒級大幅降低至毫秒級（$< 150\text{ms}$，平均 $< 5\text{ms}$），同時維持絕對零外部 npm 依賴與 Node.js 18+ 跨平台標準。

---

## 2. 問題陳述與設計目標 (Problem Statement & Goals)

### 2.1 現存缺陷與瓶頸 (Forensic Bottlenecks)

1. **冷啟動延遲衝擊 (Cold Spawn Latency)**：
   每次修復試驗皆重新執行完整的容器啟動與銷毀生命週期，造成 Docker daemon 頻繁建立/清理 cgroup、命名空間與虛擬介面卡，在高頻率測試時導致磁碟 I/O 震盪與程序爭用。
2. **分散式分塊調度排隊 (Swarm Orchestrator Starvation)**：
   分散式協調器（Pillar 2）將大型變更集聚類分割為多個相依模組並行評估。若每個 Worker 均觸發冷容器啟動，高並發請求會迅速耗盡主機行程表與 Docker socket 連線池。
3. **工作區狀態污染風險 (Cross-Trial Contamination)**：
   熱重載池的核心風險在於跨任務殘留。若先前的試驗在檔案系統或暫存目錄中遺留產物（如快取、編譯產物、惡意檔案），將破壞後續試驗的決定性與純淨度。
4. **孤兒容器洩漏漏洞 (Orphan Container Leakage)**：
   長駐背景容器若在主控程序遭遇異常信號（`SIGINT`、`SIGTERM`、未捕獲異常）時未被同步終止，將殘留成為殭屍容器，持續佔用系統記憶體與 CPU 資源。

### 2.2 設計目標與不變量 (Normative Goals & Invariants)

- **I1: 零外部執行期依賴**：100% 使用 Node.js 原生 API（`node:child_process`, `node:fs`, `node:path`, `node:crypto`, `node:events`），維持 `"dependencies": {}`。
- **I2: 亞 150ms 熱調度延遲**：指令轉發至現存長駐容器之調度延遲強制小於 $150\text{ms}$。
- **I3: 嚴格隔離保證**：長駐容器具備硬性資源限制（記憶體 2GB、CPU 2.0 核心）、非特權降權（`--user 1000:1000`）、唯讀 rootfs、全權限剝離（`--cap-drop=ALL`）與主動離線隔離（`--network=none`）。
- **I4: 釋放即清掃 (Scrub-on-Release)**：容器釋放回池時，強制清除掛載工作區與揮發性 `/tmp` 內容，保證 100% 潔淨狀態。
- **I5: 零孤兒容器 (Zero Orphan Containers)**：註冊進程信號攔截器，保證主進程終止時池內所有容器 100% 同步回收。
- **I6: 向後相容驅動介面**：提供 `PoolContainerDriver` 類別，直接實現 `BaseSandboxDriver` 合約，無縫相容 `ControlledRemediationSession`。

---

## 3. 架構設計與介面契約 (Architecture & Interface Contracts)

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Triad-Flow Core Runtime                         │
│   (ControlledRemediationSession / DistributedSwarmOrchestrator)        │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │ acquireSync / acquire / execute
                                     ▼
┌────────────────────────────────────────────────────────────────────────┐
│               PoolContainerDriver (implements BaseSandboxDriver)       │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │ delegates
                                     ▼
┌────────────────────────────────────────────────────────────────────────┐
│                         ContainerSandboxPool                           │
│  ┌───────────────────┐  ┌────────────────────┐  ┌──────────────────┐  │
│  │   Acquire Queue   │  │   Reaper Timer     │  │  Signal Traps    │  │
│  │ (Capacity Guard)  │  │ (Idle Prune/Scrub) │  │ (Zero Orphans)   │  │
│  └───────────────────┘  └────────────────────┘  └──────────────────┘  │
│                                                                        │
│  daemons: Map<slotId, ContainerDaemon>                                 │
│  ├── [slot-01] Node.js Daemon   (IDLE)  --> /jail: hostWs-01           │
│  ├── [slot-02] Python Daemon    (BUSY)  --> /jail: hostWs-02           │
│  ├── [slot-03] Rust Daemon      (IDLE)  --> /jail: hostWs-03           │
│  └── [slot-04] Go Daemon        (IDLE)  --> /jail: hostWs-04           │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │ docker exec -w /jail <cmd>
                                     ▼
┌────────────────────────────────────────────────────────────────────────┐
│                    Container Runtime (Docker / Podman)                 │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ Container: tf-pool-<poolId>-node-<slotId>                        │  │
│  │ Flags: --network=none --read-only --memory=2g --cpus=2.0         │  │
│  │        --user=1000:1000 --cap-drop=ALL --tmpfs /tmp:...         │  │
│  │ Workdir: /jail (Mounted from hostWs-01:rw)                       │  │
│  │ Daemon Process: tail -f /dev/null                                │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

### 3.1 核心常數與狀態機

```javascript
export const POOL_CONTAINER_STATES = Object.freeze({
  STARTING: "starting",
  IDLE: "idle",
  BUSY: "busy",
  DRAINED: "drained",
  CRASHED: "crashed"
});

export const DEFAULT_RESOURCE_LIMITS = Object.freeze({
  memory: "2g",
  cpus: "2.0",
  user: "1000:1000"
});

export const DEFAULT_POOL_OPTIONS = Object.freeze({
  minWarm: 1,
  maxCapacity: 8,
  idleTimeoutMs: 120000,
  acquireTimeoutMs: 15000,
  runtime: "docker",
  containerPrefix: "tf-pool",
  reapIntervalMs: 30000,
  autoRegisterSignalHandlers: true,
  selinuxMount: false,
  scrubOnRelease: true,
  defaultLanguage: "javascript",
  resourceLimits: DEFAULT_RESOURCE_LIMITS
});
```

### 3.2 守護容器實體 (`ContainerDaemon`)

`ContainerDaemon` 代表長駐暖機池中的單一容器插槽：

| 屬性名稱 | 型別 | 描述 |
|---|---|---|
| `id` | `string` | 隨機生成的唯一插槽識別碼（hex 12 字元） |
| `containerName` | `string` | 實體容器名稱，格式為 `tf-pool-<poolId>-<lang>-<slotId>` |
| `language` | `string` | 容器所屬語言生態（`javascript`, `python`, `rust`, `go`, `c`） |
| `image` | `string` | 容器基礎映象檔識別（如 `node:20-slim`, `python:3.11-slim`） |
| `status` | `string` | 狀態機狀態（`STARTING`, `IDLE`, `BUSY`, `DRAINED`, `CRASHED`） |
| `hostWorkspaceDir` | `string` | 該插槽專用之宿主機工作目錄，掛載至容器 `/jail:rw` |
| `executionCount` | `number` | 該插槽累計執行的指令次數 |
| `totalDurationMs` | `number` | 該插槽累計指令執行耗時（毫秒） |
| `currentTaskId` | `string\|null` | 當前佔用該插槽的任務識別碼 |

---

## 4. 關鍵運作機制 (Key Operational Mechanisms)

### 4.1 長駐容器啟動與多語言預熱 (Warm Daemon Spawning)

長駐容器啟動時採用阻斷性長駐指令（`tail -f /dev/null` 或 `sleep infinity`），使容器保持運行狀態並隨時接受 `exec` 調用。啟動指令嚴格強制帶入全套安全防護標誌：

```bash
docker run -d \
  --name tf-pool-<poolId>-<lang>-<slotId> \
  --pull=never \
  --network=none \
  --read-only \
  --memory=2g \
  --cpus=2.0 \
  --user=1000:1000 \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --tmpfs /tmp/home:rw \
  -e HOME=/tmp/home \
  -e npm_config_cache=/tmp/npm-cache \
  -v <hostWorkspaceDir>:/jail:rw \
  -w /jail \
  <image> \
  tail -f /dev/null
```

### 4.2 微秒級指令轉發 (Execution Multiplexing)

每次呼叫 `execute(daemon, commandArgs, options)` 時，直接透過 `exec` 多工轉發至既有暖機容器，完全繞過冷容器建立流程：

```bash
docker exec \
  -w /jail/<cwd> \
  -e PATH=... -e NODE_ENV=... \
  <containerName> \
  <commandArgs...>
```

- **環境變數淨化 (Environment Sanitization)**：僅允許 `CONTAINER_ALLOWLIST_ENV_VARS`（`PATH`, `NODE_ENV`, `LANG`, `LC_ALL`, `CI`, `TERM`）與顯式傳入之 `options.env`。宿主機權杖（如 `GITHUB_TOKEN`, `ANTHROPIC_API_KEY`）一律強制剝離。
- **超時攔截與狀態映射**：支援 `timeout` 設定，若超過設定時間未完成，回傳 `status: 124`、`timedOut: true`。

### 4.3 工作區熱掛載與排程清掃 (Workspace Scrubbing)

為確保執行獨立性與防止跨試驗污染，工作區生命週期依循下列合約：
1. **熱掛載 (Hot-Mounting)**：每個插槽擁有獨立的宿主機目錄 `hostWorkspaceDir`，在建立時直接 bind-mount 映射至容器 `/jail`。任務開始前透過 `_syncDirectoryContents` 將目標 Worktree 或快照同步至該目錄。
2. **釋放清掃 (Scrub-on-Release)**：在 `releaseSync(daemon, { scrub: true })` 觸發時：
   - 宿主機端：遞迴刪除 `hostWorkspaceDir` 內所有檔案與子目錄，還原為空目錄。
   - 容器內部：同步執行 `exec rm -rf /tmp/* /tmp/.[!.]*` 清理揮發性 `/tmp` 快取與隱藏檔。
   - 若清掃失敗，該插槽立即標記為 `CRASHED` 並調用 `evict()` 強制剔除，隨後自動補位（Replenish）。

### 4.4 零孤兒容器保障 (Zero Orphan Containers)

透過在建構子中註冊進程結束信號處理器：
```javascript
process.once("exit", () => this._emergencyCleanupSync());
process.once("SIGINT", () => { this._emergencyCleanupSync(); process.exit(130); });
process.once("SIGTERM", () => { this._emergencyCleanupSync(); process.exit(143); });
```
在緊急同步清理函式中，遍歷 `this.daemons.values()`，以同步指令 `exec(runtime, ["rm", "-f", daemon.containerName])` 強制刪除所有容器，並清理宿主機暫存工作目錄。在呼叫 `drain()` 正常關閉時，主動解註冊信號監聽器以防止記憶體洩漏。

---

## 5. 跨審查架構共識與進階擴充 (Cross-Review Refinements)

結合 Swarm 交叉互審（Cross-Worker Review）之架構反饋，本規範納入以下兩項進階擴充規範：

### 5.1 非同步多工調度 (`executeAsync`)

- **背景**：既有 `execute()` 基於 `spawnSync` 實作。在高並發 Swarm 派發且測試腳本耗時較長的情境下，同步子行程可能短暫阻塞 Node.js 主事件循環。
- **規範**：
  - 增設 `executeAsync(daemon, commandArgs, options)` 方法，內部基於 `node:child_process` 的 `spawn` 實作非同步 Promise 流式封裝。
  - 支援串流讀取 `stdout` 與 `stderr`，並在超時時向子行程發送 `SIGTERM` / `SIGKILL`。
  - 同步與非同步雙軌支援：`execute()` 滿足一般單元測試與同步合約；`executeAsync()` 專供 `DistributedSwarmOrchestrator` 大量並發派發使用。

### 5.2 AbortSignal 容器插槽防洩漏與強制回收 (`forceReleaseByTaskId`)

- **背景**：當 `DistributedSwarmOrchestrator` 斷路器發生逾時中斷或熔斷跳脫時，若呼叫端未觸發 `jail.cleanup()`，背景中的容器可能被永久鎖定在 `BUSY` 狀態。
- **規範**：
  - `acquire({ taskId, signal })` 支援傳入 `AbortSignal`。若信號觸發 abort，立即中斷調度並將分配之插槽進行強制清掃回收。
  - `ContainerSandboxPool` 導出 `forceReleaseByTaskId(taskId, { scrub: true })` 介面，供協調器在偵測到 Worker 崩潰或超時時，精確以任務 ID 強制釋放對應的容器插槽。

---

## 6. 合約測試與驗證基準 (Contract Verification Matrix)

本規範之實作必須在離線環境下通過 [`tests/sandbox-pool.test.mjs`](file:///C:/Users/arcobaleno/.gemini/antigravity-cli/worktrees/62f33bce-a5d9-405b-8aee-f9a537111c04/swarm-pool-af914428/tests/sandbox-pool.test.mjs) 15 項合約測試：

| 合約識別碼 | 測試項目 | 驗收標準 |
|---|---|---|
| **Contract 1** | 初始化與預設配置 | 驗證 `minWarm: 1`, `maxCapacity: 8`, `memory: 2g`, `cpus: 2.0` |
| **Contract 2** | 探針失敗與嚴格 Fail-Closed | 當容器執行期或 daemon 不存在時拒絕啟動，禁止靜默降級 |
| **Contract 3** | 多語言暖機與安全隔離標誌 | 驗證 5 大語言生態與 `--read-only`, `--network=none`, `--user 1000:1000` |
| **Contract 4** | 指令轉發與亞 150ms 延遲 | 透過 `exec` 派發指令，實測派發延遲 $< 150\text{ms}$，cwd 正常轉發 |
| **Contract 5** | 執行逾時攔截 | 逾時指令正確終止，回傳 `status: 124` 與 `timedOut: true` |
| **Contract 6** | 工作區熱掛載與 Scrub-on-Release | 容器釋放後，宿主機工作目錄與 `/tmp` 殘留產物 100% 清空 |
| **Contract 7** | 容量限制與調度佇列 | 超出 `maxCapacity` 之請求進入佇列，前任務釋放後立即喚醒後續調度 |
| **Contract 8** | 調度等待逾時 | 佇列等待逾時拋出 `PoolAcquireTimeoutError` |
| **Contract 9** | 主動 Egress 阻擋探針 | 執行 active probe，確保非 loopback 網卡阻斷且回傳退出碼 42 |
| **Contract 10** | 健康檢查與崩潰自動補位 | ping 失敗時標記 `CRASHED`，主動剔除並補足至 `minWarm` |
| **Contract 11** | 閒置容器清理 (Reap Idle) | 超出 `idleTimeoutMs` 之插槽自動釋放，維持 `minWarm` 保底 |
| **Contract 12** | 零孤兒容器保障 | 調用 `drain()` 或行程中斷時，以 `rm -f` 銷毀池內全量容器 |
| **Contract 13** | `PoolContainerDriver` 合約實作 | 實現 `probe()`, `create()`, `capabilities()`，無縫整合 Jail |
| **Contract 14** | 真實審計憑據輸出 | `capabilities()` 正確記錄 `driver: "container-pool"`, `mode: "hot-reuse"` |
| **Contract 15** | ControlledRemediation 整合 | 於實際修復迴圈中執行 typed command runner 並產出完整 Receipt |

---

## 7. 結論與即刻實施計畫 (Next Steps)

1. **Phase 0**：本 RFC 規範已完成審訂並登錄至專案權威規範目錄。
2. **Phase 1 整合**：
   - 將 `ContainerSandboxPool` 與 `PoolContainerDriver` 與 `src/cli.mjs` 之 `--sandbox=pool` CLI 旗標對接。
   - 串聯 `DistributedSwarmOrchestrator`（支柱 2），以熱重載池作為多 Agent 並行審查與單元修復驗證之底層沙盒。
   - 啟用 `executeAsync` 與 `AbortSignal` 聯動，進一步優化整體審查管線吞吐量。
