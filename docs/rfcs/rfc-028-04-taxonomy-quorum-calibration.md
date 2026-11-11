# RFC-028-04: Taxonomy-Aware Heterogeneous Quorum Calibration & Physical Proof Override

- **Status**: PROPOSED
- **Author**: Triad-Flow Core Architecture Team (Worker @quorum)
- **Target Release**: Triad-Flow v2.12.0
- **Created**: 2026-11-11
- **Charter Reference**: [docs/roadmap/v2.12-milestone-roadmap.md](file:///C:/Users/arcobaleno/.gemini/antigravity-cli/worktrees/62f33bce-a5d9-405b-8aee-f9a537111c04/swarm-quorum-a5d2ea70/docs/roadmap/v2.12-milestone-roadmap.md) (Pillar 4: Taxonomy-Aware Quorum Calibration)
- **Normative References**: 
  - RFC-027-02 (Tri-Party Heterogeneous Quorum Consensus)
  - RFC-028-01 (Container Sandbox Pool)
  - RFC-028-02 (Distributed Swarm Orchestrator)
  - RFC-028-03 (Active PoC Counterexample Synthesizer)
  - NIST SP 800-218 (SSDF v1.1) Tasks PW.7, PW.8, RV.1; OWASP ASVS v5.0.0; CWE Top 25 (2025/2026).
- **Execution Invariants**: Strictly zero external runtime npm dependencies (`"dependencies": {}`), Node.js 18+ native standard library only, fail-closed security.

---

## 1. 摘要 (Abstract)

在 Triad-Flow v2.11 以前，多代理人共識機制（Consensus Engine）主要仰賴僵化的全等或 2/3 二元多數決投票（Binary Majority Voting），所有模型對各類漏洞的評審權重均等化。然而，不同底層大語言模型與靜態分析工具在特定安全領域具備顯著的認知專長非對稱性（Cognitive Asymmetry）：
1. **底層記憶體安全**（Buffer Overflow, UAF, Integer Overflow）依賴精準的指針語意與代碼語意分析；
2. **業務邏輯與並行競爭**（Race Condition, Livelock, State Machine Flaw）需要深度上下文推理與因果鏈追蹤；
3. **全域架構邊界與 Monorepo 依賴**（Cross-module boundary bypass, SSRF, UI Layering）則極度依賴百萬 token 級超長上下文關聯能力。

本 RFC 正式制定 **Triad-Flow v2.12 核心支柱 4：弱點分類感知的動態異質仲裁規範 (Taxonomy-Aware Quorum Calibration)**。
本規範引入：
- 弱點領域特化分類體系 (`classifyTaxonomyDomain`)；
- 異質模型專長加權矩陣 (`DEFAULT_DOMAIN_WEIGHTS`)；
- 高風險模組（Tier-1）動態風險係數加權與強制雙廠商異質門禁防線；
- **物理證明凌駕機率推論原則 (Physical Proof Override)**：當漏洞由主動式反例合成器（Active PoC Synthesizer）完成實體動態驗證時，其仲裁信心度強制錨定為 $1.0$（物理事實），徹底杜絕多數決推論抹殺真實漏洞的致命缺陷。

---

## 2. 背景與問題陳述 (Context & Problem Statement)

### 2.1 僵化投票機制的盲點 (The Flaw of Equal-Weighted Majority Voting)
傳統多模型共識將 OpenAI Codex、Anthropic Claude Code、Google Antigravity (AGY) 及 SAST 靜態分析器視為同質節點。在實務審查中經常出現以下系統性失效：
- **記憶體漏洞被推論模型稀釋**：OpenAI Codex 與靜態語意分析器精確指認 C/C++ 模組中之 `CWE-416` (Use-After-Free)，但兩名非專長語言模型因局部邏輯看似合理而投下 `approve`，導致極高危漏洞在 2/3 投票中被靜默放行；
- **動態競爭條件被靜態分析誤殺**：Anthropic Claude 辨識出高並發 async event queue 中的 `CWE-362` 競爭條件，但靜態分析器因語法無誤判定通過，缺乏專長加權時形成僵局。

### 2.2 純統計推論 vs 實體驗證反例的位階失衡 (Heuristic vs Physical Ground-Truth)
大語言模型之審查結論本質上是基於概率的符號推論（Statistical Text Heuristics）。即便三個模型一致給予 `approve`，只要程式碼實體存在可被物理觸發的反例（Counterexample），該變更即是不安全的。
在引入 Triad-Flow v2.12 支柱 3（主動式 PoC 反例合成器）後，系統具備了在 Patch Jail 容器中動態編譯執行反例的能力。仲裁引擎必須具備對實體物理證據（Executable PoC Receipts）的最高等級採信權威。

### 2.3 高風險模組（Tier-1）的共謀與同質性脆弱度 (Sybil & Vendor Collusion Risk)
在認證（Auth）、密碼學（Crypto）、CI/CD 流程等 Tier-1 核心模組中，若允許來自同一模型廠商（如使用多個 OpenAI 模型微調執行個體）組成法定仲裁人數，將喪失供應商架構多樣性（Provider-Family Diversity），容易受到同一組預訓練偏見或提示詞注入攻擊（Prompt Injection）的集體盲從。

---

## 3. 核心設計與演算法 (Architectural Design & Algorithm)

### 3.1 弱點分類感知領域模型 (Vulnerability Taxonomy Domains)

仲裁器將安全弱點精確劃分為四大領域（`VULNERABILITY_DOMAINS`）：

```
                     ┌──────────────────────────────────────────────┐
                     │          Vulnerability Taxonomy Domains      │
                     └──────────────────────┬───────────────────────┘
                                            │
         ┌──────────────────┬───────────────┴───────────────┬──────────────────┐
         │                  │                               │                  │
         ▼                  ▼                               ▼                  ▼
┌─────────────────┐┌─────────────────┐             ┌─────────────────┐┌─────────────────┐
│  MEMORY_SAFETY  ││CONCURRENCY_LOGIC│             │GLOBAL_ARCHITECT.││GENERAL_SECURITY │
│ (底層記憶體安全) ││(並行狀態與邏輯) │             │(全域架構與邊界) ││ (一般安全性規範) │
├─────────────────┤├─────────────────┤             ├─────────────────┤├─────────────────┤
│ CWE-119, 416,   ││ CWE-362, 835,   │             │ CWE-1021, 94,   ││ CWE-79, 89, 352 │
│ 190, 120, 787   ││ 755, 662, 1333  │             │ 693, 284, 22    ││ 預設常規弱點   │
└─────────────────┘└─────────────────┘             └─────────────────┘└─────────────────┘
```

1. **底層記憶體安全 (`MEMORY_SAFETY`)**：
   - 包含緩衝區溢位、釋放後使用、整數溢位、空指針解引用、記憶體洩漏等（`CWE-119`, `CWE-416`, `CWE-190`, `CWE-120`, `CWE-787`, `CWE-476`, `CWE-415`）。
   - 適用語言：C、C++、Rust、Go unsafe、底層系統驅動。
2. **業務邏輯與狀態競爭 (`CONCURRENCY_LOGIC`)**：
   - 包含多執行緒/非同步競爭條件、死結、活結、狀態機跳躍無效、未捕獲例外狀況、無限迴圈、正規表示式拒絕服務（`CWE-362`, `CWE-835`, `CWE-755`, `CWE-662`, `CWE-1333`）。
3. **全域架構與 Monorepo 邊界 (`GLOBAL_ARCHITECTURE`)**：
   - 包含跨模組邊界越權、程式碼注入越界、防護機制失效、路徑穿越、UI 點擊劫持、跨套件循環依賴（`CWE-1021`, `CWE-94`, `CWE-693`, `CWE-284`, `CWE-22`, `CWE-918`）。
4. **一般安全性 (`GENERAL_SECURITY`)**：
   - 跨站腳本攻擊 (XSS)、常規資料注入、弱雜湊演算法使用等通用防護漏洞。

### 3.2 領域特化動態加權矩陣 (Domain-Specialized Weight Matrix)

各模型依其底層架構特性獲得專業領域基準加權 $W_{\text{model}}(d)$：

| 模型 / 代理人家族 | 廠商家族 (`family`) | 記憶體安全 (`MEMORY_SAFETY`) | 並行與邏輯 (`CONCURRENCY_LOGIC`) | 全域架構 (`GLOBAL_ARCHITECTURE`) | 一般安全 (`GENERAL_SECURITY`) |
|---|---|---|---|---|---|
| **OpenAI Codex** (`codex`, `gpt-6.1`) | `openai` | **2.0** (優先權威) | 1.2 | 1.0 | 1.0 |
| **Static Analyzers** (`semgrep`, `sast`) | `static` | **1.8** (語意精確) | 0.8 (動態盲區) | 0.8 | 1.0 |
| **Anthropic Claude** (`claude-5.5`) | `anthropic` | 1.0 | **2.0** (推理權威) | 1.3 | 1.0 |
| **Google Antigravity** (`agy-2.0`) | `google` | 1.0 | 1.2 | **2.0** (1M 上下文權威) | 1.0 |
| **未驗證/外部模型** | `unknown` | 0.5 | 0.5 | 0.5 | 0.5 |

### 3.3 動態風險閾值演算法 (Dynamic Threshold Calculation)

動態共識閾值 $T_{\text{dyn}}$ 廢除固定的 $2/3$ 比例，公式定義如下：

$$T_{\text{dyn}} = \text{clamp}\left( T_{\text{base}}(\text{Tier}) \times \max_{d \in D_{\text{detected}}} (\mu_d) \times S_{\text{diff}}, \; 0.50, \; 0.95 \right)$$

其中：
1. **風險階層基準閾值 ($T_{\text{base}}$)**：
   - **Tier-1 Critical**（Auth, Crypto, JWT, CI/CD, Workflows, Dockerfiles）：$T_{\text{base}} = 0.80$
   - **Tier-2 Source**（核心業務邏輯、常規組件、測試）：$T_{\text{base}} = 0.65$
   - **Tier-3 Docs/Assets**（文件、靜態資源、說明）：$T_{\text{base}} = 0.50$
2. **領域風險係數 ($\mu_d$)**：
   - $\mu_{\text{MEMORY\_SAFETY}} = 1.15$
   - $\mu_{\text{CONCURRENCY\_LOGIC}} = 1.10$
   - $\mu_{\text{GLOBAL\_ARCHITECTURE}} = 1.05$
   - $\mu_{\text{GENERAL\_SECURITY}} = 1.00$
3. **規模膨脹懲罰係數 ($S_{\text{diff}}$)**：
   - 若變更檔案數 $> 5$ 或 總行數變更 $> 200$，則 $S_{\text{diff}} = 1.05$，否則為 $1.00$。
4. **邊界夾取**：嚴格限制在 $[0.50, 0.95]$ 範圍內。

---

## 4. 關鍵規範：物理證明凌駕機率推論 (Physical Proof Override)

這是 Triad-Flow v2.12 仲裁體系的核心突破：

```
                      ┌─────────────────────────────────────────┐
                      │    Finding Corroboration Pipeline       │
                      └────────────────────┬────────────────────┘
                                           │
                        Is Verified Physical PoC Present?
                        (Differential Verification Receipt)
                                           │
                    ┌──────────────────────┴──────────────────────┐
                    │ YES                                         │ NO
                    ▼                                             ▼
     ┌─────────────────────────────┐               ┌─────────────────────────────┐
     │   Physical Proof Override   │               │    Domain Weighted Scoring  │
     │ ─────────────────────────── │               │ ─────────────────────────── │
     │ • Confidence Anchor: 1.0    │               │ • Calculate weighted sum    │
     │ • Status: Confirmed Blocker │               │   across reporting sentries │
     │ • Veto Power: Overrules any │               │ • Threshold acceptance: 0.4 │
     │   LLM Approve votes         │               │ • Blocking if Critical/High │
     └─────────────────────────────┘               └─────────────────────────────┘
```

### 4.1 規範條款
1. **物理事實優先原則**：若待審弱點附帶由 `ActivePoCSynthesizer` 產出之可執行反例驗證憑證（`PoC Receipt`）：
   - 若 `receipt.status === "PATCH_INEFFECTIVE"`（Pre-Patch 確證引爆弱點，且 Post-Patch 仍然觸發失敗）：
     **該弱點之加權信心度（`weightedConfidence`）立即強制錨定為 $1.0$**，且自動標記為 `isConfirmed: true` 與 `isBlocking: true`。
   - 任何大語言模型所出具之「此處安全無虞」或「approve」結論在此物理反例面前均屬無效，仲裁引擎強制封鎖 `approve` 裁定。
2. **修復證偽原則**：若反例驗證狀態為 `receipt.status === "DIFFERENTIAL_VERIFIED"`（Pre-Patch 紅燈成功復現，Post-Patch 綠燈安全修復）：
   - 該弱點在修復評審中被判定為**物理驗證修復完畢**，不計入阻擋性弱點。
3. **防偽鏈校驗契約**：
   - 仲裁器在套用 Physical Proof Override 前，必須調用 `verifyReceiptDigest(receipt)` 校驗其 SHA-256 簽名，杜絕偽造或篡改的反例憑證注入。

---

## 5. Tier-1 安全閘門與反女巫防禦 (Tier-1 Heterogeneous Gate & Anti-Sybil Invariant)

在 Tier-1 關鍵模組（`RISK_TIERS.TIER_1_CRITICAL`）中，實施最嚴格的異質安全保障：

### 5.1 雙廠商異質強制約束 (Multi-Vendor Diversity Invariant)
$$\text{DistinctHealthyFamilies}(\text{Reports}) \ge 2 \quad (\text{where family} \in \{\text{google}, \text{anthropic}, \text{openai}, \text{static}\})$$

- **單一 Sentry 違規 (Single-Sentry Violation)**：
  若 Tier-1 變更僅有一家廠商的模型出具報告，即便該模型評分 100 分，仲裁引擎**嚴格以 Fail-Closed 原則判定失敗**：
  `quorumReached = false`，`verdict = "error"`，拒絕通行。
- **同廠商同質化違規 (Homogeneous Vendor Violation)**：
  若 Tier-1 變更由同一家廠商的兩個不同模型審查（如 `gpt-4o` 與 `codex`，兩者均屬 `openai` 家族），因欠缺跨架構獨立性，判定為違反異質防禦不變量，直接判定仲裁失敗。
- **合法法定仲裁成立條件**：
  必須至少存在 2 家不同家族且健康（`healthy: true`）的 Sentry 共同參與（如 `anthropic` + `google`，或 `openai` + `static`），且加權贊成得分滿足動態閾值：
  $$\text{weightedApprovalScore} \ge T_{\text{dyn}}$$

---

## 6. 介面契約與資料結構 (Interface Contract & Data Formats)

### 6.1 `TaxonomyQuorumCalibrator` 類別介面

```typescript
export interface CalibrateQuorumInput {
  reports: Array<ReviewerReport> | Map<string, ReviewerReport> | Record<string, ReviewerReport>;
  files?: Array<{ path: string; additions?: number; deletions?: number }>;
  riskTier?: number;
  policyOptions?: {
    tier?: number;
    risk?: "high" | "medium" | "low";
    errorOnBlockers?: boolean;
    files?: Array<any>;
  };
}

export interface CalibratedQuorumDecision {
  readonly quorumReached: boolean;
  readonly verdict: "approve" | "warning" | "needs-attention" | "error";
  readonly topology: string;
  readonly riskTier: number;
  readonly calibratedThreshold: number;
  readonly weightedApprovalScore: number;
  readonly dominantDomain: string;
  readonly selectedReportIds: ReadonlyArray<string>;
  readonly findings: ReadonlyArray<CalibratedFinding>;
  readonly blockingFindings: ReadonlyArray<CalibratedFinding>;
  readonly domainBreakdown: Record<string, number>;
  readonly reviewerVotes: ReadonlyArray<ReviewerVote>;
  readonly reason: string | null;
  readonly consensusProof: string; // SHA-256 Content-Addressable Proof Digest
}
```

### 6.2 與 `consensus-state.mjs` 整合保證
`TaxonomyQuorumCalibrator` 產出之決策物件可直接做為 `issueConsensusFromEvidence` 的輸入參數：
- 當 `verdict === "approve"` 時，保證 `quorumReached === true` 且 `blockingFindings.length === 0`（滿足 C-05, C-07 不變量）；
- 當存在阻擋性弱點（Critical/High）時，`verdict` 確定為 `"needs-attention"`，並提供詳盡的 `consensusProof`；
- 所有傳回之決策結構均經過 `deepFreeze` 遞迴凍結，防止執行期屬性篡改。

---

## 7. 向後相容性與升級路徑 (Backward Compatibility & Migration)

1. **對 Triad-Flow v2.11 QuorumPolicies 的相容性**：
   `TaxonomyQuorumCalibrator` 提供 `createQuorumPolicy()` 工廠方法，可直接替換或作為 `QuorumPolicies.TAXONOMY_AWARE_QUORUM` 注入至 `loop.mjs` 之 `aggregateConsensus()` 中，原有呼叫端無需變更簽名。
2. **零外部依賴不變量**：
   嚴格遵守 Node.js 原生 API 規範，僅使用 `node:crypto`、`node:path`、`node:assert`，確保在極簡容器與安全離線環境中 100% 獨立運行。

---

## 8. 安全考慮與威脅模型 (Security Considerations & Threat Modeling)

| 威脅向量 | 攻擊模式 | 仲裁引擎防禦機制 |
|---|---|---|
| **女巫模型偽裝 (Sybil Attack)** | 攻擊者部署同家族衍生模型試圖偽裝為多代理人共識 | `resolveProviderFamily` 強制將所有衍生名稱解析為規範家族，Tier-1 嚴格比對去重家族數量 $\ge 2$。 |
| **弱點機率洗白 (Probabilistic Whitewashing)** | 多個未受特化訓練之模型一致投下 `approve` 覆蓋嚴重弱點 | 1. 領域專長加權放大專長模型投票權重；<br>2. 實體反例（PoC）強制 Physical Proof Override（信心度 1.0），單一實體反例即擁有一票否決權。 |
| **記憶體/高危險路徑偷渡** | 在大型 PR 中夾帶底層 C 模組記憶體越界寫入 | 檔案路徑與 CWE 領域自動偵測觸發 `MEMORY_SAFETY` 領域，Codex/Static 權重自動提升至 2.0，動態閾值自動攀升至 0.92。 |
| **憑證偽造與竄改** | 攻擊者在記憶體中竄改決策物件的 `verdict` 或 `quorumReached` | 全面使用 `deepFreeze` 深度凍結，且最終閘門以 `trustedConsensusRegistry` (WeakSet) 進行內部能力校驗。 |

---

## 9. 驗收標準與測試矩陣 (Acceptance Criteria & Test Matrix)

本 RFC 之落地實作由 `tests/taxonomy-quorum.test.mjs` 提供 15 項全量合約驗證：
1. **依賴查核**：驗證 `package.json` 之 `"dependencies": {}`。
2. **領域分類矩陣**：涵蓋 `MEMORY_SAFETY`, `CONCURRENCY_LOGIC`, `GLOBAL_ARCHITECTURE`, `GENERAL_SECURITY` 映射。
3. **加權矩陣驗證**：OpenAI (Memory), Claude (Concurrency), AGY (Global) 各自於專長領域取得最高權重。
4. **Tier-1 異質防禦**：驗證單一 sentry 及同廠商雙 sentry 在 Tier-1 均觸發 Fail-Closed。
5. **歧異決定性仲裁**：驗證各領域在模型意見衝突時，專長模型之 blocker 判定不可被一般模型稀釋。
6. **能力憑證發行**：驗證產出可順利鑄造 `issueConsensusFromEvidence` 之受信任能力。
7. **異常韌性**：驗證 null、空陣列、損毀輸入在無例外拋出下優雅進入 Fail-Closed。
