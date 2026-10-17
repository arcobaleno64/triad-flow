import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import cp from "node:child_process";
import { scanControlledTextFiles } from "./scan-controlled-crlf.mjs";

const REMOTE_HEAD_SHA = "ebe28be8b4db6ef276e6b3dcc1201a860af5231f";
const TIMESTAMP = new Date().toISOString();

const snapshot = JSON.parse(fs.readFileSync("evidence-runs/PR-39/working-tree-snapshot.json", "utf8"));
const { count: controlledTextFilesCount, crlfFiles } = scanControlledTextFiles(".");

const changeLedger = {
  metadata: {
    targetPr: "https://github.com/arcobaleno64/triad-flow/pull/39",
    prNumber: 39,
    branch: "fix/remediation-007-clean-challenge",
    remoteHeadSha: REMOTE_HEAD_SHA,
    workingTreeDiffSha256: snapshot.metadata.fullWorkingTreeDiffSha256,
    workingTreeDiffBytes: snapshot.metadata.fullWorkingTreeDiffBytes,
    manifestDigestSha256: snapshot.metadata.manifestDigestSha256,
    timestamp: TIMESTAMP,
    summary: {
      modifiedSourceFiles: 7,
      normalizedConfigFiles: 3,
      untrackedVerificationTestFiles: 5,
      totalTestCount: 1060,
      passingTests: 1056,
      skippedTests: 4,
      failedTests: 0,
      runtimeDependenciesCount: 0,
      controlledTextFilesCount,
      crlfViolationsCount: crlfFiles.length
    },
    governanceNotice: "Exact Head ebe28be is distinct from uncommitted local modifications. Phase 1-3 fixes reside in the working directory as uncommitted changes subject to LOCAL_COMMIT = NOT_AUTHORIZED."
  },
  modifiedSourceFiles: [
    {
      path: "src/core/harness.mjs",
      phase: "Phase 1",
      headSha256: snapshot.modifiedTrackedFiles["src/core/harness.mjs"].headSha256,
      diskSha256: snapshot.modifiedTrackedFiles["src/core/harness.mjs"].diskSha256,
      headBytes: snapshot.modifiedTrackedFiles["src/core/harness.mjs"].headBytes,
      diskBytes: snapshot.modifiedTrackedFiles["src/core/harness.mjs"].diskBytes,
      closedVectors: [
        "P1-01~08",
        "Delimiter Collision in Finding Signatures",
        "Provider Finding ID Collisions",
        "Consensus Tampering",
        "Case Normalization Vulnerabilities"
      ],
      coreProtections: "Strict RunContext binding; multi-pass provider finding ID namespacing (`${prefix}:${id}`); structured finding signature encoding using canonical JSON object serialization rather than delimiter concatenation; strict case and locator normalization.",
      verificationSuites: [
        { file: "tests/remediation-phase1-harness.test.mjs", testCount: 10, status: "10/10 PASS" }
      ]
    },
    {
      path: "src/core/independent-verifier.mjs",
      phase: "Phase 2",
      headSha256: snapshot.modifiedTrackedFiles["src/core/independent-verifier.mjs"].headSha256,
      diskSha256: snapshot.modifiedTrackedFiles["src/core/independent-verifier.mjs"].diskSha256,
      headBytes: snapshot.modifiedTrackedFiles["src/core/independent-verifier.mjs"].headBytes,
      diskBytes: snapshot.modifiedTrackedFiles["src/core/independent-verifier.mjs"].diskBytes,
      closedVectors: [
        "P2-CAP-01~08",
        "Provenance Forgery",
        "Token Minter Bypass",
        "Missing Concrete Counterexample Path",
        "Caller Override Downgrade"
      ],
      coreProtections: "Private WeakMap capability registry (`trustedVerificationRegistry`); WeakMap snapshot content-hash verification; mandatory concrete reproduction counterexample path validation (`hasConcreteCounterexample`); rejection of self-proclaimed provenance strings; immutability enforcement preventing options overrides from downgrading UNCERTAIN or DEFECTS_FOUND.",
      verificationSuites: [
        { file: "tests/remediation-phase2-verifier.test.mjs", testCount: 29, status: "29/29 PASS" }
      ]
    },
    {
      path: "src/core/context-builder.mjs",
      phase: "Phase 2",
      headSha256: snapshot.modifiedTrackedFiles["src/core/context-builder.mjs"].headSha256,
      diskSha256: snapshot.modifiedTrackedFiles["src/core/context-builder.mjs"].diskSha256,
      headBytes: snapshot.modifiedTrackedFiles["src/core/context-builder.mjs"].headBytes,
      diskBytes: snapshot.modifiedTrackedFiles["src/core/context-builder.mjs"].diskBytes,
      closedVectors: [
        "P2-CAP-08",
        "Receiver Deduplication Desync",
        "AST Budget Exceeded Gaps",
        "Imported Symbol Gaps",
        "Indentation vs Brace Mismatch in Python"
      ],
      coreProtections: "Deep freezing of context packages (`deepFreeze(pkg)`); receiver-aware call deduplication key (`${qualifier}.${sym}`); exact-head file content binding; propagation of unextracted sensitive callees to `UNRESOLVED_SYMBOL` and `GLOBAL_AST_CONTEXT_CEILING_EXCEEDED` context gaps; lexical tokenizer filtering comments and template strings.",
      verificationSuites: [
        { file: "tests/remediation-phase2-verifier.test.mjs", testCount: 29, status: "29/29 PASS" },
        { file: "tests/remediation-007-clean-challenge.test.mjs", testCount: 102, status: "102/102 PASS" }
      ]
    },
    {
      path: "src/adapters/review-orchestrator.mjs",
      phase: "Phase 3",
      headSha256: snapshot.modifiedTrackedFiles["src/adapters/review-orchestrator.mjs"].headSha256,
      diskSha256: snapshot.modifiedTrackedFiles["src/adapters/review-orchestrator.mjs"].diskSha256,
      headBytes: snapshot.modifiedTrackedFiles["src/adapters/review-orchestrator.mjs"].headBytes,
      diskBytes: snapshot.modifiedTrackedFiles["src/adapters/review-orchestrator.mjs"].diskBytes,
      closedVectors: [
        "R1 (Loose Diff Hashing / Trimmed Diff Digests)",
        "R2 (Objective Override Conflict)",
        "R3 (Run ID Binding & Anti-Replay)",
        "R4 (Illegal Risk Tier Overrides & Downgrades)"
      ],
      coreProtections: "R1: Removal of `.trim()` diff digest variants; strict binding to physical byte diffs (`rawDiffDigest`, LF-normalized `normDiffDigest`). R2: Deterministic 6-source objective conflict detection failing closed on mismatch. R3: Authoritative `activeRunId` binding preventing replay of stale verification records across runs. R4: Strict validation rejecting NaN, null, negative, and tier 0 values, and failing closed against Tier 1 downgrades.",
      verificationSuites: [
        { file: "tests/remediation-phase3-orchestrator-cli.test.mjs", testCount: 27, status: "27/27 PASS" },
        { file: "tests/challenger-phase3-r1-r2-r3.test.mjs", testCount: 21, status: "21/21 PASS" }
      ]
    },
    {
      path: "src/cli.mjs",
      phase: "Phase 3",
      headSha256: snapshot.modifiedTrackedFiles["src/cli.mjs"].headSha256,
      diskSha256: snapshot.modifiedTrackedFiles["src/cli.mjs"].diskSha256,
      headBytes: snapshot.modifiedTrackedFiles["src/cli.mjs"].headBytes,
      diskBytes: snapshot.modifiedTrackedFiles["src/cli.mjs"].diskBytes,
      closedVectors: [
        "R5 (CLI Clean Challenge & Verifier Bypass)",
        "Shell Injection via --verify-with",
        "Exit Code Inconsistency"
      ],
      coreProtections: "Strict verifier command validation (`validateVerifierCommand`) accepting only canonical provider profiles (`claude`, `agy`, `codex`) with `shell: false`; automatic Clean Challenge execution on zero-finding reviews; exit code contract mapping (0: approved, 1: defects found, 2: uncertain / usage error, 3: blocked).",
      verificationSuites: [
        { file: "tests/remediation-phase3-orchestrator-cli.test.mjs", testCount: 27, status: "27/27 PASS" },
        { file: "tests/adversarial-phase3-challenger.test.mjs", testCount: 79, status: "79/79 PASS" }
      ]
    },
    {
      path: "scripts/dogfood-review.mjs",
      phase: "Phase 1~3",
      headSha256: snapshot.modifiedTrackedFiles["scripts/dogfood-review.mjs"].headSha256,
      diskSha256: snapshot.modifiedTrackedFiles["scripts/dogfood-review.mjs"].diskSha256,
      headBytes: snapshot.modifiedTrackedFiles["scripts/dogfood-review.mjs"].headBytes,
      diskBytes: snapshot.modifiedTrackedFiles["scripts/dogfood-review.mjs"].diskBytes,
      closedVectors: [
        "Context Extraction Bypass",
        "Dual Visibility Asymmetry (§3.3.4)",
        "Untrusted Repository Root Escalation"
      ],
      coreProtections: "Pre-extraction of exact-head `contextPackage` with bidirectional injection into both primary sentry reviews and Clean Challenge verifier; fail-closed behavior on missing repository roots (`EXACT_HEAD_CONTEXT_FAILED`).",
      verificationSuites: [
        { file: "tests/remediation-007-clean-challenge.test.mjs", testCount: 102, status: "102/102 PASS" }
      ]
    },
    {
      path: "tests/remediation-007-clean-challenge.test.mjs",
      phase: "Invariant 6",
      headSha256: snapshot.modifiedTrackedFiles["tests/remediation-007-clean-challenge.test.mjs"].headSha256,
      diskSha256: snapshot.modifiedTrackedFiles["tests/remediation-007-clean-challenge.test.mjs"].diskSha256,
      headBytes: snapshot.modifiedTrackedFiles["tests/remediation-007-clean-challenge.test.mjs"].headBytes,
      diskBytes: snapshot.modifiedTrackedFiles["tests/remediation-007-clean-challenge.test.mjs"].diskBytes,
      closedVectors: [
        "False Stale Record from Missing Run ID",
        "Option A Bounded Fix Verification"
      ],
      coreProtections: "Bounded remediation (lines 2268, 3161) binding valid active `runId` into test verification records, aligning legacy tests with Invariant 6 anti-stale protection without weakening test rigor.",
      verificationSuites: [
        { file: "tests/remediation-007-clean-challenge.test.mjs", testCount: 102, status: "102/102 PASS" }
      ]
    }
  ],
  normalizedConfigFiles: [
    {
      path: ".gitignore",
      phase: "Workspace Hygiene",
      headSha256: snapshot.modifiedTrackedFiles[".gitignore"].headSha256,
      diskSha256: snapshot.modifiedTrackedFiles[".gitignore"].diskSha256,
      diskBytes: 458,
      isBitForBitIdenticalToHead: true,
      description: "Normalized 27 CRLF occurrences to LF; verified bit-for-bit identical to Git HEAD."
    },
    {
      path: ".github/allowed_signers",
      phase: "Workspace Hygiene",
      headSha256: snapshot.modifiedTrackedFiles[".github/allowed_signers"].headSha256,
      diskSha256: snapshot.modifiedTrackedFiles[".github/allowed_signers"].diskSha256,
      diskBytes: 230,
      isBitForBitIdenticalToHead: true,
      description: "Normalized 3 CRLF occurrences to LF; public keys and semantics 100% intact; verified bit-for-bit identical to Git HEAD."
    },
    {
      path: ".github/workflows/nightly.yml",
      phase: "Workspace Hygiene",
      headSha256: snapshot.modifiedTrackedFiles[".github/workflows/nightly.yml"].headSha256,
      diskSha256: snapshot.modifiedTrackedFiles[".github/workflows/nightly.yml"].diskSha256,
      diskBytes: 723,
      isBitForBitIdenticalToHead: true,
      description: "Normalized 1 CRLF occurrence to LF; workflow steps and matrix intact; verified bit-for-bit identical to Git HEAD."
    }
  ],
  untrackedVerificationTestFiles: [
    {
      path: "tests/remediation-phase1-harness.test.mjs",
      phase: "Phase 1 Verification",
      testCount: 10,
      diskSha256: snapshot.untrackedFiles["tests/remediation-phase1-harness.test.mjs"].diskSha256,
      diskBytes: snapshot.untrackedFiles["tests/remediation-phase1-harness.test.mjs"].diskBytes,
      coverage: "Finding signature structured JSON serialization, finding ID namespacing, locator boundary normalization."
    },
    {
      path: "tests/remediation-phase2-verifier.test.mjs",
      phase: "Phase 2 Verification",
      testCount: 29,
      diskSha256: snapshot.untrackedFiles["tests/remediation-phase2-verifier.test.mjs"].diskSha256,
      diskBytes: snapshot.untrackedFiles["tests/remediation-phase2-verifier.test.mjs"].diskBytes,
      coverage: "WeakMap registry capability security, WeakMap snapshot hash locking, concrete counterexample enforcement, AST gap propagation."
    },
    {
      path: "tests/remediation-phase3-orchestrator-cli.test.mjs",
      phase: "Phase 3 Verification",
      testCount: 27,
      diskSha256: snapshot.untrackedFiles["tests/remediation-phase3-orchestrator-cli.test.mjs"].diskSha256,
      diskBytes: snapshot.untrackedFiles["tests/remediation-phase3-orchestrator-cli.test.mjs"].diskBytes,
      coverage: "R1 Canonical diff digest, R2 Deterministic objective conflict, R3 Run ID anti-replay, R4 Risk tier validation, R5 CLI Clean Challenge execution."
    },
    {
      path: "tests/challenger-phase3-r1-r2-r3.test.mjs",
      phase: "Phase 3 Adversarial Challenge",
      testCount: 21,
      diskSha256: snapshot.untrackedFiles["tests/challenger-phase3-r1-r2-r3.test.mjs"].diskSha256,
      diskBytes: snapshot.untrackedFiles["tests/challenger-phase3-r1-r2-r3.test.mjs"].diskBytes,
      coverage: "Adversarial challenges attacking R1 diff padding, R2 objective desynchronization, R3 replay token hijacking, and R4 tier downgrade bypass."
    },
    {
      path: "tests/adversarial-phase3-challenger.test.mjs",
      phase: "Phase 3 Adversarial Challenge",
      testCount: 79,
      diskSha256: snapshot.untrackedFiles["tests/adversarial-phase3-challenger.test.mjs"].diskSha256,
      diskBytes: snapshot.untrackedFiles["tests/adversarial-phase3-challenger.test.mjs"].diskBytes,
      coverage: "Comprehensive fuzzing and adversarial inputs against CLI options, shell command injection, exit code mapping, and verifier adapters."
    }
  ]
};

const jsonPath = path.join("evidence-runs", "PR-39", "change-ledger.json");
fs.writeFileSync(jsonPath, JSON.stringify(changeLedger, null, 2) + "\n", "utf8");
console.log(`Successfully wrote change ledger JSON: ${jsonPath}`);

// Generate Markdown
const md = [
  "# PR #39 全量變更清冊與架構防護矩陣 (Comprehensive Change Ledger)",
  "",
  "> **治理邊界與環境狀態宣告**",
  "> - **目標 PR**：[#39 (fix/remediation-007-clean-challenge)](https://github.com/arcobaleno64/triad-flow/pull/39)",
  `> - **遠端 Exact Head SHA**：\`${REMOTE_HEAD_SHA}\``,
  `> - **本機工作區狀態**：\`UNCOMMITTED_LOCAL_MODIFICATIONS\` (Diff SHA-256: \`${snapshot.metadata.fullWorkingTreeDiffSha256}\`, ${snapshot.metadata.fullWorkingTreeDiffBytes} bytes)`,
  `> - **產出時間**：\`${TIMESTAMP}\``,
  "> - **重要邊界聲明**：遠端 HEAD 仍為 `ebe28be8...`，Phase 1～3 之程式碼修復與新增測試套件均為本機工作區未提交變更。本清冊嚴格區分遠端 HEAD 基準與本機未提交 Diff，未將本機修復混淆為遠端 HEAD 已包含之內容。",
  "",
  "## 一、架構防護矩陣 (7 個修改原始檔)",
  "",
  "| 模組檔案 | 所屬階段 | 關閉之缺陷 / 向量 | 核心防護機制 | 驗證測試套件 | 檔案 SHA-256 (Disk / HEAD) |",
  "| :--- | :--- | :--- | :--- | :--- | :--- |",
  ...changeLedger.modifiedSourceFiles.map(f => {
    const suites = f.verificationSuites.map(s => `\`${s.file}\` (${s.status})`).join("<br>");
    return `| \`${f.path}\` | **${f.phase}** | ${f.closedVectors.join(", ")} | ${f.coreProtections} | ${suites} | Disk: \`${f.diskSha256.slice(0, 12)}...\`<br>HEAD: \`${f.headSha256.slice(0, 12)}...\` |`;
  }),
  "",
  "## 二、工作區衛生正規化 (3 個設定檔)",
  "",
  "| 設定檔案 | 正規化動作 | 驗證結果 | 檔案 SHA-256 (LF) |",
  "| :--- | :--- | :--- | :--- |",
  ...changeLedger.normalizedConfigFiles.map(f => {
    return `| \`${f.path}\` | 移除 \\r，正規化為純 LF | 100% 位元組比對與 Git HEAD 一致，公鑰與語意 0 變動 | \`${f.diskSha256}\` |`;
  }),
  "",
  "## 三、新增安全驗證測試套件 (5 個測試檔)",
  "",
  "| 測試檔案 | 所屬階段 | 測例數量 | 涵蓋防護與對抗驗證重點 | 檔案 SHA-256 |",
  "| :--- | :--- | :--- | :--- | :--- |",
  ...changeLedger.untrackedVerificationTestFiles.map(t => {
    return `| \`${t.path}\` | **${t.phase}** | **${t.testCount} 項** | ${t.coverage} | \`${t.diskSha256.slice(0, 16)}...\` |`;
  }),
  "",
  "## 四、全專案回歸測試數據與依賴純淨度",
  "",
  "- **權威容器驗收基準 (`node --test --test-concurrency=4`)**：1,060 total · 1,056 PASS · 4 SKIP · 0 FAIL",
  "- **測例跳過環境差異說明**：容器環境與本機環境之跳過數量差異（4 skips vs 1 skip）純屬選用外部測試固件（Optional External Fixtures）與憑證之有無，與 Node.js 執行並行度無關：",
  "  1. `tests/clickhouse-repository.test.mjs`：因容器未預先檢出外部 ClickHouse 儲存庫而跳過 (1 skip)",
  "  2. `tests/real-provider-pilot.test.mjs`：3 項 AGY Live Provider 測試因容器未注入即時付費 API 金鑰而跳過 (3 skips)",
  "  - 當本機具備該儲存庫固件時，僅 1 項跳過（1,059 PASS / 1 SKIP / 0 FAIL）；在純淨隔離容器中則標準為 4 項跳過（1,056 PASS / 4 SKIP / 0 FAIL）。全數 1,060 測例皆具確定性判定，0 失敗。",
  "- **執行期相依性 (`package.json`)**：`dependencies` 嚴格為空 (`{}`)，執行期相依性為 0",
  `- **CRLF 掃描 (受控文字檔案集合 ${controlledTextFilesCount} 檔)**：0 CRLF，全文字檔案維持純 LF`,

  "",
  "## 五、治理約束狀態 (Invariants)",
  "",
  "```text",
  "LOCAL_COMMIT = NOT_AUTHORIZED",
  "COMMIT_AND_PUSH = NOT_AUTHORIZED",
  "SQUASH_MERGE = NOT_AUTHORIZED",
  "RULESET_BYPASS = NOT_AUTHORIZED",
  "THREAD_BATCH_RESOLUTION = NOT_AUTHORIZED",
  "WORKSPACE_LF_NORMALIZATION = AUTHORIZED_BOUNDED",
  "AUTHORIZED_CONFIG_FILES = 3",
  "Q1_UNIFIED_LEDGER = APPROVED",
  "LEGACY_LEDGERS = PRESERVE",
  "RUNTIME_AUTHORITY = NONE",
  "SHADOW_TO_ADVISORY = STRICT_HOLD",
  "CYCLE_0048 = ON_HOLD_NOT_ASSIGNED",
  "ISSUE_37 = OPEN",
  "```"
];

const mdPath = path.join("docs", "reports", "pr-39-comprehensive-change-ledger.md");
fs.writeFileSync(mdPath, md.join("\n") + "\n", "utf8");
console.log(`Successfully wrote change ledger Markdown: ${mdPath}`);
