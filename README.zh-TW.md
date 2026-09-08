<p align="center">
  <img src="assets/banner.jpg" alt="Triad-Flow Banner" width="800">
</p>

# Triad-Flow ⚡ (繁體中文版)

> **自適應多代理人閉環控制架構**  
> *提供確定性安全核心、規模自適應拓撲路由、以及嚴格 Fail-Closed 異質共識門禁，支援多模型審查與 OODA 控制閉環。*

---

## 🌐 什麼是 Triad-Flow？

Triad-Flow 用工業級的 **Graph + Loop + Harness（圖論 + 閉環 + 夾具）工程三位一體**，徹底取代落落長的提示詞與死板的狀態機：

1. **🌐 Graph Engineering (圖論拓撲路由)**：
   - 自動評估 Git 變更規模、Lockfile 與檔案風險等級。
   - 小型改動（<50 行）直接走 **單代理人極速通道**（零 Token 浪費）。
   - 高風險安全改動（含資安測試檔）或大型 PR 則動態平行派發至 **子代理人群 (Subagent Swarms)**。
2. **🔄 Loop Engineering (控制閉環工程)**：
   - 異質多模型共識審查介面：**Claude (主控生產端)** ➔ **Gemini (宏觀全庫雷達)** ➔ **OpenAI Codex (微觀反例仲裁)** *(目標架構 / 支援可抽換 Provider Adapters)*。
   - 實施 **嚴格異質雙哨兵 Quorum 門禁**（雙哨兵皆需健康）與最高嚴重度合併去重。
   - **OODA 閉環控制器原語**：內建 Jaccard 語意停滯檢測與補丁循環雜湊熔斷 *(Remediator 補丁合成在未配置 Adapter 時維持 Fail-Closed 門禁)*。
3. **🛡️ Harness Engineering (安全夾具工程)**：
   - 實施確定性安全邊界：多重機密遮蔽、符號連結 (Symlink) 與路徑穿越沙盒防禦、Quorum 嚴格 Fail-Closed 門禁、以及 SARIF 2.1.0 報表生成。

---

## ⚡ 快速開始

```bash
# 1. 執行測試套件（含 18+ 項對抗性回歸測試）
npm test

# 2. 執行環境與能力診斷
npm run doctor

# 3. 執行確定性本機模擬演練
npm run demo

# 4. 針對真實 Git Diff 執行自適應審查
npm run review
```

---

## 🚀 如何在專案中導入

### A. 現有專案（3 分鐘零摩擦導入）

1. **在專案根目錄新增 `CLAUDE.md`：**
   ```markdown
   # Autonomous Sentry Protocol
   1. **Pre-flight Check**: Execute `!triad-flow review` before finalizing code.
   2. **Auto-Remediation (OODA)**: On `needs-attention`, apply counter-example patches and re-test until green.
   3. **Macro Delegation**: Use Gemini 2M Context for whole-repo (>10 files) caller audits.
   ```
2. **執行基準審查：**
   ```bash
   npx triad-flow review
   ```

---

## 🤖 三代理人共識分工矩陣（目標架構）

| 角色 | 驅動引擎 | 核心超能力 | 專注範疇 |
|---|---|---|---|
| **Master Driver (主控驅動端)** | **Anthropic Claude Code** | 代碼生成與 OODA 自愈實作 | 代碼實裝、補丁合成、CLI 驅動 |
| **Macro Sentry (宏觀哨兵)** | **Google Gemini** | 2M 超大上下文全庫雷達 | 跨模組調用鏈破壞、CI/CD 漂移、架構影響面 |
| **Micro Arbiter (微觀仲裁員)** | **OpenAI Codex / o3** | 測試期深度計算 (CoT) | 並發競態模擬、邊界模糊測試、形式化反例構建 |

---

## 📊 30 秒工程投資回報 (ROI) 對照表（設計規格）

| 評估維度 | 單一模型 (`claude --review`) | 靜態代碼掃描 (Sonar / ESLint) | **Triad-Flow 閉環控制** |
|---|---|---|---|
| **宏觀跨檔案調用** | 盲區：無法感知 >10 個檔案外的調用破壞 | 僅限 AST 語法樹，完全無架構理解力 | **Gemini 2M 雷達**：全庫多檔案審計與 CI/CD 漂移分析 *(規劃中)* |
| **微觀深度並發** | 容易輕忽複雜的狀態機競態 | 無法模擬執行期的多執行緒交錯 | **OpenAI o3/Codex CoT**：深度測試期驗證與精確反例構建 *(規劃中)* |
| **Token 經濟學** | 所有 PR 不論大小均消耗高昂 Token | 零 Token，但誤報率高且無法自動修復 | **自適應圖路由**：小型改動 (<50 行) 走單代理人極速通道 (0 額外負擔) |
| **閉環修復能力** | 僅給出口頭建議，需人類手動修改 | 僅報錯，無自動化修復閉環 | **OODA 閉環控制器**：生成 SARIF 2.1.0 報表並管理修復停滯熔斷 |

---

## 🛡️ 資安與 AI 安全架構

- **SARIF 2.1.0**：標準化 JSON 報表生成，支援 Driver Rules 去重與 URI 安全路徑編碼。
- **OWASP Top 10 for LLM**：
  - `LLM02: Sensitive Info Disclosure` — 多重機密正則遮蔽（Google、OpenAI、Anthropic、GitHub、AWS、JWT、PEM 金鑰）。
  - `LLM06: Excessive Agency` — `OodaLoopController` 3 輪自愈上限、Jaccard 語意停滯檢測與補丁循環熔斷。
- **NIST SSDF (SP 800-218) & OpenSSF**：符號連結與同級路徑穿越沙盒防禦，嚴格 Quorum Fail-Closed 門禁。
- **IEEE 352 / N-Version**：異質多模型共識防禦，消除單一模型共模失效 (Common-Mode Failures)。

---

## 🏛️ 八大工程支柱矩陣

| 支柱 | 實作檔案 | 核心機制 |
|---|---|---|
| 🛡️ **1. Guardrail & Harness (防護與夾具)** | [`src/core/harness.mjs`](src/core/harness.mjs) | 機密正則遮蔽、Symlink 沙盒、Quorum 門禁、SARIF 2.1.0 |
| 🌐 **2. Graph Engineering (圖論拓撲)** | [`src/core/graph-router.mjs`](src/core/graph-router.mjs) | 規模自適應路由、Lockfile 規模納入、資安測試 Tier 1 審計 |
| 🔄 **3. Loop Engineering (閉環控制)** | [`src/core/loop.mjs`](src/core/loop.mjs) | 嚴重度升級合併、OODA 控制器、Jaccard 語意抗振盪熔斷 |
| 🔭 **4. Observability (可觀察性)** | [`src/core/telemetry.mjs`](src/core/telemetry.mjs) | 極簡進程內 Span 追蹤器與耗時分析 |
| 🎯 **5. Eval & Benchmark (評估基準)** | [`src/core/scoring.mjs`](src/core/scoring.mjs) | 嚴格變異分數驗證與 Held-Out 黃金 CVE 召回率測試 |
| 🧠 **6. Context Budgeting (上下文預算)** | [`src/core/graph-router.mjs`](src/core/graph-router.mjs) | 3-Tier 風險分層分配（Auth/CI 檔案 0% 截斷保證） |
| 📦 **7. Sandbox Isolation (沙盒隔離)** | [`src/core/harness.mjs`](src/core/harness.mjs) | 零信任實體檔案系統與 Symlink 邊界隔離 |
| ⚖️ **8. Constitutional (憲法邊界)** | [`CLAUDE.md`](CLAUDE.md) | 極簡、不可妥協的確定性規則（<50 行） |

---

## 📄 授權條款

Apache-2.0 © arcobaleno64
