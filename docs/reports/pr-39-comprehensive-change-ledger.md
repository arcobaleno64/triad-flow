# PR #39 全量變更清冊與架構防護矩陣 (Comprehensive Change Ledger)

> **治理邊界與環境狀態宣告**
> - **目標 PR**：[#39 (fix/remediation-007-clean-challenge)](https://github.com/arcobaleno64/triad-flow/pull/39)
> - **遠端 Exact Head SHA**：`ebe28be8b4db6ef276e6b3dcc1201a860af5231f`
> - **本機工作區狀態**：`UNCOMMITTED_LOCAL_MODIFICATIONS` (Diff SHA-256: `39097ac5e2103cd0344ed468ddd47926f3b9017a300ca501c54bdfad7fa6c728`, 120116 bytes)
> - **產出時間**：`2026-10-17T03:07:04.725Z`
> - **重要邊界聲明**：遠端 HEAD 仍為 `ebe28be8...`，Phase 1～3 之程式碼修復與新增測試套件均為本機工作區未提交變更。本清冊嚴格區分遠端 HEAD 基準與本機未提交 Diff，未將本機修復混淆為遠端 HEAD 已包含之內容。

## 一、架構防護矩陣 (7 個修改原始檔)

| 模組檔案 | 所屬階段 | 關閉之缺陷 / 向量 | 核心防護機制 | 驗證測試套件 | 檔案 SHA-256 (Disk / HEAD) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `src/core/harness.mjs` | **Phase 1** | P1-01~08, Delimiter Collision in Finding Signatures, Provider Finding ID Collisions, Consensus Tampering, Case Normalization Vulnerabilities | Strict RunContext binding; multi-pass provider finding ID namespacing (`${prefix}:${id}`); structured finding signature encoding using canonical JSON object serialization rather than delimiter concatenation; strict case and locator normalization. | `tests/remediation-phase1-harness.test.mjs` (10/10 PASS) | Disk: `dce609cfc077...`<br>HEAD: `92f62a96d3d1...` |
| `src/core/independent-verifier.mjs` | **Phase 2** | P2-CAP-01~08, Provenance Forgery, Token Minter Bypass, Missing Concrete Counterexample Path, Caller Override Downgrade | Private WeakMap capability registry (`trustedVerificationRegistry`); WeakMap snapshot content-hash verification; mandatory concrete reproduction counterexample path validation (`hasConcreteCounterexample`); rejection of self-proclaimed provenance strings; immutability enforcement preventing options overrides from downgrading UNCERTAIN or DEFECTS_FOUND. | `tests/remediation-phase2-verifier.test.mjs` (29/29 PASS) | Disk: `ac231d3dcaa5...`<br>HEAD: `ce072ae794cd...` |
| `src/core/context-builder.mjs` | **Phase 2** | P2-CAP-08, Receiver Deduplication Desync, AST Budget Exceeded Gaps, Imported Symbol Gaps, Indentation vs Brace Mismatch in Python | Deep freezing of context packages (`deepFreeze(pkg)`); receiver-aware call deduplication key (`${qualifier}.${sym}`); exact-head file content binding; propagation of unextracted sensitive callees to `UNRESOLVED_SYMBOL` and `GLOBAL_AST_CONTEXT_CEILING_EXCEEDED` context gaps; lexical tokenizer filtering comments and template strings. | `tests/remediation-phase2-verifier.test.mjs` (29/29 PASS)<br>`tests/remediation-007-clean-challenge.test.mjs` (102/102 PASS) | Disk: `b56bf26eb88d...`<br>HEAD: `95fc4637cf0d...` |
| `src/adapters/review-orchestrator.mjs` | **Phase 3** | R1 (Loose Diff Hashing / Trimmed Diff Digests), R2 (Objective Override Conflict), R3 (Run ID Binding & Anti-Replay), R4 (Illegal Risk Tier Overrides & Downgrades) | R1: Removal of `.trim()` diff digest variants; strict binding to physical byte diffs (`rawDiffDigest`, LF-normalized `normDiffDigest`). R2: Deterministic 6-source objective conflict detection failing closed on mismatch. R3: Authoritative `activeRunId` binding preventing replay of stale verification records across runs. R4: Strict validation rejecting NaN, null, negative, and tier 0 values, and failing closed against Tier 1 downgrades. | `tests/remediation-phase3-orchestrator-cli.test.mjs` (27/27 PASS)<br>`tests/challenger-phase3-r1-r2-r3.test.mjs` (21/21 PASS) | Disk: `287ed622b38c...`<br>HEAD: `ff164c9687c1...` |
| `src/cli.mjs` | **Phase 3** | R5 (CLI Clean Challenge & Verifier Bypass), Shell Injection via --verify-with, Exit Code Inconsistency | Strict verifier command validation (`validateVerifierCommand`) accepting only canonical provider profiles (`claude`, `agy`, `codex`) with `shell: false`; automatic Clean Challenge execution on zero-finding reviews; exit code contract mapping (0: approved, 1: defects found, 2: uncertain / usage error, 3: blocked). | `tests/remediation-phase3-orchestrator-cli.test.mjs` (27/27 PASS)<br>`tests/adversarial-phase3-challenger.test.mjs` (79/79 PASS) | Disk: `39f5c5f0d31a...`<br>HEAD: `93a25a530355...` |
| `scripts/dogfood-review.mjs` | **Phase 1~3** | Context Extraction Bypass, Dual Visibility Asymmetry (§3.3.4), Untrusted Repository Root Escalation | Pre-extraction of exact-head `contextPackage` with bidirectional injection into both primary sentry reviews and Clean Challenge verifier; fail-closed behavior on missing repository roots (`EXACT_HEAD_CONTEXT_FAILED`). | `tests/remediation-007-clean-challenge.test.mjs` (102/102 PASS) | Disk: `375eb4c3d2e4...`<br>HEAD: `b3f5046c2a95...` |
| `tests/remediation-007-clean-challenge.test.mjs` | **Invariant 6** | False Stale Record from Missing Run ID, Option A Bounded Fix Verification | Bounded remediation (lines 2268, 3161) binding valid active `runId` into test verification records, aligning legacy tests with Invariant 6 anti-stale protection without weakening test rigor. | `tests/remediation-007-clean-challenge.test.mjs` (102/102 PASS) | Disk: `6bd4154d1c3a...`<br>HEAD: `53854847f6f5...` |

## 二、工作區衛生正規化 (3 個設定檔)

| 設定檔案 | 正規化動作 | 驗證結果 | 檔案 SHA-256 (LF) |
| :--- | :--- | :--- | :--- |
| `.gitignore` | 移除 \r，正規化為純 LF | 100% 位元組比對與 Git HEAD 一致，公鑰與語意 0 變動 | `eb43ff82502abdb249757b047ec532530b4ce5dacb4723f63a478bb3c12287a5` |
| `.github/allowed_signers` | 移除 \r，正規化為純 LF | 100% 位元組比對與 Git HEAD 一致，公鑰與語意 0 變動 | `2214d608cd7773187fb2050acd96ff2b3fd421ab1a78039648950cae80d1f1ea` |
| `.github/workflows/nightly.yml` | 移除 \r，正規化為純 LF | 100% 位元組比對與 Git HEAD 一致，公鑰與語意 0 變動 | `fb9b9b5634cf367f9cbf03143549f91ff7eeca4fd12b5d1c1e7119434bb348ca` |

## 三、新增安全驗證測試套件 (5 個測試檔)

| 測試檔案 | 所屬階段 | 測例數量 | 涵蓋防護與對抗驗證重點 | 檔案 SHA-256 |
| :--- | :--- | :--- | :--- | :--- |
| `tests/remediation-phase1-harness.test.mjs` | **Phase 1 Verification** | **10 項** | Finding signature structured JSON serialization, finding ID namespacing, locator boundary normalization. | `1b01f07b50dcbcb0...` |
| `tests/remediation-phase2-verifier.test.mjs` | **Phase 2 Verification** | **29 項** | WeakMap registry capability security, WeakMap snapshot hash locking, concrete counterexample enforcement, AST gap propagation. | `a6f6a5ce891c981b...` |
| `tests/remediation-phase3-orchestrator-cli.test.mjs` | **Phase 3 Verification** | **27 項** | R1 Canonical diff digest, R2 Deterministic objective conflict, R3 Run ID anti-replay, R4 Risk tier validation, R5 CLI Clean Challenge execution. | `7e9fe9435f6a6e17...` |
| `tests/challenger-phase3-r1-r2-r3.test.mjs` | **Phase 3 Adversarial Challenge** | **21 項** | Adversarial challenges attacking R1 diff padding, R2 objective desynchronization, R3 replay token hijacking, and R4 tier downgrade bypass. | `02acedaf810b0c3d...` |
| `tests/adversarial-phase3-challenger.test.mjs` | **Phase 3 Adversarial Challenge** | **79 項** | Comprehensive fuzzing and adversarial inputs against CLI options, shell command injection, exit code mapping, and verifier adapters. | `63594a2be02e8c74...` |

## 四、全專案回歸測試數據與依賴純淨度

- **權威容器驗收基準 (`node --test --test-concurrency=4`)**：1,060 total · 1,056 PASS · 4 SKIP · 0 FAIL
- **測例跳過環境差異說明**：容器環境與本機環境之跳過數量差異（4 skips vs 1 skip）純屬選用外部測試固件（Optional External Fixtures）與憑證之有無，與 Node.js 執行並行度無關：
  1. `tests/clickhouse-repository.test.mjs`：因容器未預先檢出外部 ClickHouse 儲存庫而跳過 (1 skip)
  2. `tests/real-provider-pilot.test.mjs`：3 項 AGY Live Provider 測試因容器未注入即時付費 API 金鑰而跳過 (3 skips)
  - 當本機具備該儲存庫固件時，僅 1 項跳過（1,059 PASS / 1 SKIP / 0 FAIL）；在純淨隔離容器中則標準為 4 項跳過（1,056 PASS / 4 SKIP / 0 FAIL）。全數 1,060 測例皆具確定性判定，0 失敗。
- **執行期相依性 (`package.json`)**：`dependencies` 嚴格為空 (`{}`)，執行期相依性為 0
- **CRLF 掃描 (受控文字檔案集合 343 檔)**：0 CRLF，全文字檔案維持純 LF

## 五、治理約束狀態 (Invariants)

```text
LOCAL_COMMIT = NOT_AUTHORIZED
COMMIT_AND_PUSH = NOT_AUTHORIZED
SQUASH_MERGE = NOT_AUTHORIZED
RULESET_BYPASS = NOT_AUTHORIZED
THREAD_BATCH_RESOLUTION = NOT_AUTHORIZED
WORKSPACE_LF_NORMALIZATION = AUTHORIZED_BOUNDED
AUTHORIZED_CONFIG_FILES = 3
Q1_UNIFIED_LEDGER = APPROVED
LEGACY_LEDGERS = PRESERVE
RUNTIME_AUTHORITY = NONE
SHADOW_TO_ADVISORY = STRICT_HOLD
CYCLE_0048 = ON_HOLD_NOT_ASSIGNED
ISSUE_37 = OPEN
```
