# RFC-028-03: Active PoC Test Synthesizer & Differential Verification Engine

- **Document ID**: `TF-RFC-028-03`
- **Schema Version**: `1.0.0`
- **Title**: Active PoC Counterexample Synthesizer & Differential Verification Engine (Pillar 3)
- **Author**: Architectural Planning & Core Engineering Team (Worker `poc`)
- **Target Milestone**: Triad-Flow v2.12
- **Document Status**: `ADOPTED_IN_PROTOTYPE`
- **Working Directory**: `C:\Users\arcobaleno\Documents\Code\triad-flow`
- **Integrity Level**: `strict-fail-closed`
- **Dependency Invariant**: Strictly Zero External Runtime npm Dependencies (`"dependencies": {}`)
- **Date**: 2026-11-11

---

## 1. 執行摘要 (Executive Summary)

在 Triad-Flow 既有的審查流程中，安全審查主要仰賴靜態分析器（Static Analyzers）與異質大型語言模型（LLM Reviewers）進行文本語意推理。然而，純靜態推理具備兩大根本性缺陷：
1. **幻覺與偽陽性 (False Positives)**：模型經常提出語意推論上看似有理、但在實際執行期因為前置過濾、型別邊界或防禦深層設計而不可被觸發的「虛構漏洞」。
2. **缺乏實體反例 (Absence of Executable Counterexamples)**：傳統審查引擎僅能指出「這行代碼有問題」，卻無法提供可直接重現該問題的最小可執行測試腳本，導致審查者、自動修復迴圈（Controlled Remediation Session）與受審工程師無法即時檢驗修復有效性。

**RFC-028-03** 制定了 Triad-Flow v2.12 核心支柱 3——**主動式 PoC 反例合成器 (Active PoC Test Synthesizer)** 的架構標準。系統將待審查弱點（如 CWE-22 路徑穿越、CWE-89 SQL 注入、CWE-1321 原型污染、CWE-78 指令注入等）轉化為具備實體物理證明力的最小可執行重現測試（PoC Harness），並導入**修復前後雙向差異驗證 (Differential Verification)** 與**資產沉澱 (Asset Hardening)** 機制，徹底將靜態審查升級為物理事實驅動的精確驗證。

---

## 2. 核心架構契約 (Core Architectural Contracts)

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Vulnerability Finding                           │
│              (CWE-22 / CWE-89 / CWE-1321 / CWE-78 / ...)               │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                    ActivePoCSynthesizer.synthesize                     │
│    - Template Selection & Normalization (normalizeCwe)                 │
│    - Minimal Executable Script Generation                              │
│    - Canonical SHA-256 Digest Anchoring (computeSha256)                │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                         Produces: PoCHarness
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                    verifyDifferential (Two-Way Jail)                   │
│                                                                        │
│   Step 1: Execute against Pre-Patch Target                             │
│           Requirement: MUST FAIL (ExitCode != 0 / Red Light)           │
│           -> Proves vulnerability is physically reproducible.          │
│                                                                        │
│   Step 2: Execute against Post-Patch Target                            │
│           Requirement: MUST PASS (ExitCode == 0 / Green Light)         │
│           -> Proves patch successfully mitigates flaw without crash.   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                         Produces: Verified Receipt
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│               Asset Hardening (hardenToRegressionTest)                 │
│    - Converts ephemeral PoC into permanent node:test / pytest file     │
│    - Attaches advisory ID, cryptographic digest, and audit headers     │
│    - Writes directly into repository regression suite                  │
└────────────────────────────────────────────────────────────────────────┘
```

### 2.1 PoCHarness 不變量與介面

`PoCHarness` 是封裝動態反例測試的不可變核心物件（`Object.freeze`）：

```javascript
export class PoCHarness {
  constructor({
    id,                         // 唯一辨識碼: poc-<cwe>-<randomHex>
    cwe,                        // 標準化 CWE: CWE-1321, CWE-22, CWE-89, ...
    language = "javascript",    // 執行語言: javascript, python, shell
    targetModule = null,        // 目標模組相對/絕對路徑或名稱
    targetFunction = null,      // 目標函式識別碼
    payload,                    // 實體攻擊向量或邊界資料
    script,                     // 可獨立執行的測試腳本源碼
    expectedPrePatchFailure,    // 修復前預期失敗行為描述
    expectedPostPatchSuccess,   // 修復後預期通過行為描述
    metadata = {}               // 關聯 Advisory ID、嚴重度等審計標記
  });

  // 計算並凍結的 SHA-256 簽章
  readonly digest: string;

  // 轉換為標準永久迴歸測試套件源碼
  toRegressionTest(options: { testFramework?: string, advisoryId?: string }): string;

  // 序列化為安全 JSON
  toJSON(): object;
}
```

### 2.2 弱點分類與動態最小重現模板 (Taxonomy-Aware Templates)

系統內建四大常見弱點類別之精確最小重現模板，並提供動態擴充 API：

1. **CWE-1321 (Prototype Pollution - 原型污染)**：
   - **測試機制**：注入帶有 `__proto__` 或 `constructor.prototype` 之惡意屬性物件至目標深層合併或指派函式。
   - **驗證不變量**：修復前 `({}).polluted === markerVal` 成立（觸發退出碼 1）；修復後該屬性被防禦性略過或拋出異常，且 `Object.prototype` 維持乾淨無污染（退出碼 0）。
   - **隔離保證**：測試前後皆強制呼叫 `delete Object.prototype[markerKey]`，嚴禁殘留污染影響宿主行程。

2. **CWE-22 (Path Traversal - 路徑穿越)**：
   - **測試機制**：傳遞包含 `../../`、`..\\`、絕對路徑與 URL 編碼等逃逸序列至路徑解析器或資源載入器。
   - **驗證不變量**：修復前目標解析出脫離基礎沙盒目錄（`baseDir`）之非受限路徑；修復後目標強制約束路徑於 `baseDir` 內部，或拋出防禦性異常攔截存取。

3. **CWE-89 (SQL Injection - 資料庫注入)**：
   - **測試機制**：輸入經典單引號閉合、布林恆真式（`' OR '1'='1`）及註解終止符。
   - **驗證不變量**：修復前目標函式直接進行原始字串拼接，產生可操控語法；修復後目標強制轉化為參數化查詢物件（`values: [...]` 或 `parameters: [...]`）或對單引號執行嚴格跳脫。

4. **CWE-78 (OS Command Injection - 作業系統指令注入)**：
   - **測試機制**：輸入 shell 元字元（`; echo TF_PWNED`、`|`、`&`）。
   - **驗證不變量**：修復前指令字串包含未經跳脫之指令分隔符號；修復後使用離散 argv 陣列傳遞參數，或拋出異常拒絕執行。

5. **擴充介面 (`registerTemplate`)**：
   支援開發者或外掛註冊自訂 CWE 產生器：
   ```javascript
   synthesizer.registerTemplate("CWE-79", (spec) => new PoCHarness({ ... }));
   ```

---

## 3. 修復前後雙向差異驗證 (Differential Verification)

### 3.1 核心判決狀態機 (Verdicts)

雙向差異驗證嚴格落實**物理反例對照原則**：

| 狀態代碼 (`VERIFICATION_STATUS`) | Pre-Patch 執行結果 | Post-Patch 執行結果 | 最終判定 | 意義與處置 |
|---|---|---|---|---|
| `DIFFERENTIAL_VERIFIED` | **FAILED (Red / Exit != 0)** | **PASSED (Green / Exit == 0)** | **通過驗收 (Verified)** | 物理確證漏洞存在且修復完全有效。 |
| `REPRODUCTION_FAILED` | **PASSED (Green / Exit == 0)** | N/A (未執行或未採納) | **未重現 (Inconclusive)** | PoC 無法在修復前重現該漏洞，反例無效。 |
| `PATCH_INEFFECTIVE` | **FAILED (Red / Exit != 0)** | **FAILED (Red / Exit != 0)** | **修復失敗 (Ineffective)** | 修復未生效，攻擊載荷依然成功穿透防禦。 |
| `PATCH_REGRESSION` | **FAILED (Red / Exit != 0)** | **CRASHED (Unexpected Error)** | **功能倒退 (Regression)** | 修復代碼引發未捕捉之崩潰（如 TypeError）。 |
| `TIMEOUT` | 超出超時上限 (Timeout) | 超出超時上限 (Timeout) | **逾時熔斷 (Timeout)** | 執行超過時間上限，強制終止。 |

### 3.2 數位憑證與防偽檢驗 (`verifyReceiptDigest`)

驗證完成後產出不可篡改之憑證物件，具備時間戳與前向 SHA-256 數位簽章。

為滿足分散式協調器與仲裁器之自洽驗證需求，模組正式導出 `verifyReceiptDigest(receipt)` 輔助函式：

```javascript
export function verifyReceiptDigest(receipt) {
  if (!receipt || typeof receipt !== "object" || typeof receipt.digest !== "string") {
    return false;
  }
  const { digest, ...payload } = receipt;
  const expected = computeSha256(JSON.stringify(payload));
  return digest === expected;
}
```

任何對 `receipt` 內部狀態（如偽造 `status: "DIFFERENTIAL_VERIFIED"` 或竄改 `exitCode`）之篡改皆會導致 `verifyReceiptDigest` 判定 `false`，嚴格達成 Fail-Closed。

---

## 4. 資產沉澱機制 (Asset Hardening)

當一組動態 PoC 達成 `DIFFERENTIAL_VERIFIED` 後，系統支援將其固化為專案的標準迴歸測試，永續守護代碼庫防止該缺陷復發：

- **Node.js 標準測試 (`node:test`)**：
  生成具備 Advisory ID、CWE 標記、PoC Digest 與原生斷言（`assert.equal`、`assert.ok`）的 ES Module 測試檔案，並自動將 Windows 絕對路徑規格化為標準 `file://` ESM URL。
- **Python 標準測試 (`pytest`)**：
  生成包含 Advisory ID 與 `pytest` 標準定義的測試檔案。
- **直接磁碟寫入 (`writeRegressionTestFile`)**：
  具備自動建立父目錄與即時雜湊校驗功能。

---

## 5. 跨支柱協同與架構整合 (Cross-Pillar Synergy)

RFC-028-03 與 Triad-Flow v2.12 其他三大支柱形成高內聚、低耦合之閉環架構：

1. **與支柱 1 (Hot-Reuse Container Pool) 聯動**：
   - PoC 執行可直接委派予 `ContainerSandboxPool` 內的暖機容器（Warm Daemons），在嚴格 `--network=none`、`--user 1000:1000` 與唯讀磁碟邊界內運行，將 PoC 派發延遲壓至毫秒級，杜絕惡意載荷逃逸。
2. **與支柱 2 (Distributed Swarm Orchestrator) 聯動**：
   - 協調器在分塊派發（Dependency-Aware Partitioning）時，針對新增或缺乏測試覆蓋的代碼區塊，自動指派 PoCSynthesizer 生成專屬反例，並將 PoC 憑據雜湊鏈入不可篡改的中間數位憑據鏈。
3. **與支柱 4 (Taxonomy-Aware Quorum Calibration) 聯動（重大突破：物理證明凌駕機率推論）**：
   - 經交叉互審沉澱的關鍵架構共識：當 Finding 附帶通過 `verifyReceiptDigest` 的 `DIFFERENTIAL_VERIFIED` 實體憑據時，仲裁器（`TaxonomyQuorumCalibrator`）直接將其加權信心度（`weightedConfidence`）**強制錨定為 1.0**，並宣告 `isConfirmed: true`。
   - **實體物理事實擁有絕對否決權**，超越任何 LLM Sentry 的純文字推論。

---

## 6. 品質閘門與測試覆蓋 (Quality Gates)

| 規範項目 | 要求標準 | 驗收結果 |
|---|---|---|
| **執行時期依賴** | 嚴格 0 外部 npm 套件 (`"dependencies": {}`) | **100% 原生 Node.js API** |
| **測試通過率** | `node --test tests/poc-synthesizer.test.mjs` 離線全通 | **14 / 14 PASS (450ms)** |
| **全量迴歸測試** | 與 sandbox-driver / controlled-remediation 同步執行 | **61 / 61 PASS (14.3s)** |
| **交叉互審結果** | 經 @quorum 交叉審查 | **APPROVED (放行通過)** |
