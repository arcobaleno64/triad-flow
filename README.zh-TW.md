# Triad-Flow ⚡（繁體中文操作手冊）

> **自適應多代理人閉環控制架構**  
> *專為 Claude、Google Gemini 與 OpenAI Codex 打造的高效能、零官僚、工業級對抗性代碼審查與自動自愈系統。*

---

## 🌐 什麼是 Triad-Flow？

Triad-Flow 徹底拋棄傳統繁複的提示詞官僚與多餘文件，以現代 **Graph + Loop + Harness 工程三元組** 為核心：

1. **🌐 Graph Engineering（圖路由）**：
   - 自動評估 Git Diff 規模與資安風險等級。
   - 輕量修改（<50 行）走**單代理極速通道**（0 額外 Token 負擔）。
   - 涉及認證（Auth）或 CI/CD 高危變更自動喚醒**並行子代理群**。
2. **🔄 Loop Engineering（控制閉環）**：
   - 協同異質三模型共識：**Claude（主控生產）** ➔ **Gemini（宏觀雷達）** ➔ **OpenAI Codex（微觀黑客）**。
   - 自動生成反例修復向量，驅動 **OODA 閉環自愈**，內建 SHA-256 狀態環防範死鎖振盪。
3. **🛡️ Harness Engineering（安全夾具）**：
   - 確定性安全夾具：9 大機密正則遮蔽、路徑前綴隔離、Quorum 法定人數門禁、符合 OASIS SARIF 2.1.0 國際標準。

---

## ⚡ 快速起步

```bash
# 1. 安裝相依套件
npm install

# 2. 執行 15 項自動化單元測試
npm test

# 3. 檢查環境與金鑰健康度
npm run doctor

# 4. 執行自適應審查
npm run review

# 5. 執行全自動無人化工廠流水線
node src/cli.mjs factory
```

---

## 🚀 如何在您的專案中導入？

### A. 既有專案導入（零侵入、約 3 分鐘）

1. **在專案根目錄建立 `CLAUDE.md`：**
   ```markdown
   # 代理人自愈協定 (Triad-Flow Protocol)
   1. **交卷前自檢**：重大代碼修改後，主動執行 `!triad-flow review`。
   2. **遇錯自愈 (OODA)**：收到 `needs-attention` 時，依反例自動打補丁並重新測試，全綠方可交付。
   3. **宏觀分工**：涉及 10+ 檔案的架構重構，調用 Gemini 2M Context 進行全庫呼叫鏈掃描。
   ```
2. **執行基準掃描：**
   ```bash
   npx triad-flow review
   ```
3. **（選配）安裝 Git 提交守門員：**
   ```bash
   echo "npx triad-flow review" > .git/hooks/pre-commit
   ```

### B. 全新專案起步（約 1 分鐘）

```bash
mkdir my-new-project && cd my-new-project
git init
# 貼入上述 CLAUDE.md 範本，啟動 Claude Code
claude
```

---

## 🤖 三足鼎立共識矩陣 (Tri-Agent Matrix)

| 角色 | 模型 / 引擎 | 核心超能力 | 專精領域 |
|---|---|---|---|
| **Master Driver** | **Anthropic Claude Code** | 代碼生成與 OODA 自愈 | 業務邏輯實作、補丁合成、CLI 驅動 |
| **Macro Sentry** | **Google Gemini 3.7 / 4** | 2M Context 全庫雷達 | 跨模組介面漂移、CI/CD 影響、50+ 調用鏈掃描 |
| **Micro Arbiter** | **OpenAI Codex / o3-pro** | 深度測試期計算 (CoT) | 並發競爭條件、邊界模糊測試、形式化反例推導 |

---

## 🛡️ 國際資安標準符合性

- **OASIS SARIF 2.1.0**：原生符合標準，直接被 GitHub Advanced Security 與 SonarQube 讀取。
- **OWASP Top 10 for LLM (2025/2026)**：
  - `LLM01: 提示詞注入` — XML Nonce 隔離與嚴格 JSON 結構約束。
  - `LLM02: 敏感資料外洩` — 9 大機密正則自動遮蔽（API Key/JWT/私鑰）。
  - `LLM06: 過度自主權` — `OodaLoopController` 3 次迭代死鎖熔斷器。
- **NIST SSDF (SP 800-218) & OpenSSF**：零信任工作空間路徑隔離與 Quorum-Enforced Fail-Closed 門禁。
- **IEEE 352 / N-Version**：異質多模型交叉審計，杜絕單一模型共模故障。

---

## 🏛️ 8 大工程支柱架構總覽

| 工程支柱 | 實作模組檔案 | 核心機制 |
|---|---|---|
| 🛡️ **1. Guardrail & Harness** | [`src/core/harness.mjs`](src/core/harness.mjs) | 9 機密正則、前綴防護沙盒、Quorum 門禁、SARIF 2.1.0 報表 |
| 🌐 **2. Graph Engineering** | [`src/core/router.mjs`](src/core/router.mjs) | 規模自適應路由、測試檔自動降級保護（省 80% Token） |
| 🔄 **3. Loop Engineering** | [`src/core/loop.mjs`](src/core/loop.mjs) | 嚴重度升級防降級去重、OODA 狀態機、SHA-256 死鎖熔斷 |
| 🔭 **4. Observability** | [`src/core/telemetry.mjs`](src/core/telemetry.mjs) | 35 行超輕量 OpenTelemetry 分散式 Trace 與 Span 追蹤 |
| 🎯 **5. Eval & Benchmark** | [`src/core/eval.mjs`](src/core/eval.mjs) | 變異得分計算（Mutation Score）與盲測黃金漏洞召回率驗證 |
| 🧠 **6. Context Budgeting** | [`src/core/router.mjs`](src/core/router.mjs) | 3 級威脅加權分配，保證 Auth 與 CI/CD 0% 截斷 |
| 📦 **7. Sandbox Isolation** | [`src/core/harness.mjs`](src/core/harness.mjs) | 零信任工作空間邊界與瞬時隔離 |
| ⚖️ **8. Constitutional** | [`CLAUDE.md`](CLAUDE.md) | 不可違背憲法約束（精簡 <50 行） |

---

## 📄 授權條款

Apache-2.0 © arcobaleno64
