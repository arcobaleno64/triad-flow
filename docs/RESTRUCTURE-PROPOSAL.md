# Triad-Flow 整理提案（架構與命名）

規格基準：`agy-plugin-cc`、`agy-security-audit`（僅取兩者**交集**的慣例；兩者本身形狀不同，不可疊加）。
狀態：**已裁示並執行**（2026-09-08）。裁示＝維持 CLI、`factory` 升格。§1 命名與 §4 已落地；§3 repo 衛生尚未執行。

---

## 0. 先決問題（決定後續一半的工作）

Triad-Flow 要維持 **獨立 npm CLI**，還是改成 **plugin**？

- 目前跡證指向 CLI：`package.json` 有 `bin` / `files` / `engines`，README 教 `npx triad-flow review`。本提案**預設維持 CLI**，只吸收兩基準的 repo 衛生與命名紀律。
- 若要改 plugin，是另一件工作：`src/core/*.mjs` → `skills/<name>/scripts/`，外加 `plugin.json`（agy 形狀）或 `.claude-plugin/marketplace.json` + `plugins/<name>/{commands,agents,skills,hooks}`（cc 形狀），本提案的路徑對應表全部作廢。

---

## 1. 命名：三支柱與模組名的漂移

文件宣稱三支柱 **Graph / Loop / Harness**，但程式碼裡 `Graph` 只出現在一行 banner 字串（`src/cli.mjs:41`），對應的模組叫 `router.mjs`。其餘兩支柱名實相符。

| 支柱 | 文件用詞 | 現行模組 | 建議 | 理由 |
|---|---|---|---|---|
| 拓撲路由 | Graph Engineering | `src/core/router.mjs` | `src/core/graph-router.mjs` | 保留 router（它確實在做 routing），補上支柱詞，讓 grep 得到 |
| 控制閉環 | Loop Engineering | `src/core/loop.mjs` | 不動 | 名實相符 |
| 安全夾具 | Harness Engineering | `src/core/harness.mjs` | 不動 | 名實相符 |

角色詞彙已一致（`macro-sentry` / `micro-arbiter` 在 `src/cli.mjs:71,77` 與 `loop.mjs` 的 QuorumPolicies 內用法相同），**不需改動**。

### 命名缺陷（與支柱無關，但更嚴重）

| 檔案 | 問題 | 建議 |
|---|---|---|
| `tests/factory.test.mjs` | **名不符實**：檔內測的是 `SpanTracer`（telemetry）與 `eval.mjs`，完全沒測 factory | 拆成 `tests/telemetry.test.mjs` + `tests/eval.test.mjs` |
| `tests/probes-round5.test.mjs` | 「round5」是當初的 session 產物編號，對讀者無意義 | `tests/consensus-trust-probes.test.mjs` |
| `src/core/eval.mjs` | `eval` 是 JS 保留語意的字，且內容是「held-out baseline 驗收 + mutation score + CWE 比對」 | `src/core/scoring.mjs` |
| `src/core/git-collector.mjs` / `git-diff.mjs` | 切分是**真的**（前者收集 working state 並 re-export，後者純 numstat 解析），但兩個名字看不出上下關係 | `git-diff.mjs` → `git-numstat.mjs`（純解析器）；`git-collector.mjs` 不動 |
| `factory` 子命令 | `package.json` 有 `npm run factory`，但無對應模組，邏輯全在 `src/cli.mjs:141-147` 且只是印字的 fail-closed stub | 見 §4 |

---

## 2. 架構：目前層次是對的，缺的是一層邊界

現況 `bin/ → src/cli.mjs → src/core/*`，單向依賴、無循環，**這層不需要重構**。實際的架構缺口有二：

1. **無 provider adapter 層。** README 的 Gemini / Codex 全標 `(Planned)`，`src/cli.mjs:126` 直接 `No configured macro sentry provider`。兩基準都把外部引擎隔離成獨立契約（`agy-plugin-cc/docs/adapter-contract.md` + `scripts/verify-contracts.mjs`）。建議預留 `src/adapters/`，並補 `docs/adapter-contract.md`——**先寫契約，不寫實作**。
2. **`src/core/telemetry.mjs`（45 行，僅 `SpanTracer`）只被 demo 路徑用一次。** 它不是支柱，別給它架構地位；留在 core 即可，但不進 README 的架構圖。

---

## 3. Repo 衛生：兩基準一致、Triad-Flow 缺的

排序＝先做的在上。

| # | 缺口 | 兩基準的做法 | 代價 |
|---|---|---|---|
| 1 | **`.github/workflows/` 是空目錄** | 兩者皆有 `pull-request-ci.yml` + `release.yml`（security-audit 另有 `semgrep.yml`） | ~30 分 |
| 2 | 無 `SECURITY.md` | 兩者皆有 | ~15 分 |
| 3 | `package.json` 缺 `repository` / `homepage` / `bugs` | 兩者皆有 | ~5 分 |
| 4 | 無版本閘門 | 兩者皆有 `scripts/bump-version.mjs` + `bump-version` / `check-version` npm script | ~30 分 |
| 5 | 產 SARIF 卻無 schema | 兩者皆有 `schemas/*.schema.json`（security-audit 有 7 份） | ~1 小時 |

**已符合、不必動**：雙語 README 對照、kebab-case `.mjs`、`type: module`、`engines`。

**刻意不對齊**：套件名（Triad-Flow 為 bare `triad-flow`，兩基準為 `@arcobaleno64/…`）與授權（Apache-2.0 vs MIT）——這兩項是發佈決策，不是整理項目，除非指示否則維持。

---

## 4. 需要裁示的一項

`factory` 子命令目前是「印三行字然後 fail-closed」的空殼，但 `package.json`、CLI usage、README 都當它是正式命令。二選一：

- **(a) 降級**：從 `package.json` scripts 與 CLI usage 移除，README 標為 roadmap；
- **(b) 升格**：抽出 `src/core/factory.mjs`，即使內容仍是 fail-closed，至少有模組邊界與可測介面。

依 3.4 切斯特頓柵欄：它存在的理由是「宣示 pipeline 願景」，故我不逕行刪除。

---

## 5. 不做什麼（範圍界定）

不觸碰：`LICENSE`、`CLAUDE.md`、`assets/`、`README.md` / `README.zh-TW.md` 的內容、以及**所有 `src/core/*.mjs` 的函式主體**——本提案只涉及檔名與新增檔案，不改任何既有行為。
不變更：套件名、授權、`bin` 進入點名稱、CLI 既有子命令的輸出文字（Hyrum's Law：輸出被測試與使用者腳本觀察）。
不處理：README 中 `(Planned)` / `(Target architecture)` 標記的可信度問題（見 §6）。

---

## 6. 不確定清單

- **未讀**：`src/core/loop.mjs` 第 91-415 行（`aggregateConsensus` 主體、`OodaLoopController` 實作）、`harness.mjs` 全部主體、`git-collector.mjs` 全部主體。本提案的模組職責判斷來自 export 清單與行數，不是完整閱讀。
- **未讀**：兩基準的 `.github/workflows/*.yml` 內容，僅確認檔名存在；§3 的 CI 建議是「補上同名工作流」，不是「照抄內容」。
- **未測**：任何重新命名後的 import 修補；`npm test` 在本次工作中未執行。
- **推測**：`git-collector` / `git-diff` 的切分意圖（依 `git-collector.mjs:12` 的 re-export 推得，未查 commit 訊息）。
- **相鄰議題（僅提出，不執行）**：README 多處 `(Planned)`，而 `agy-plugin-cc` 以 `docs/evidence.md` + `docs/parity.md` + `PARITY_AUDIT*.md` 管理「宣稱 vs 實證」。這是可移植的紀律，但屬文件真實性，不屬架構與命名。
