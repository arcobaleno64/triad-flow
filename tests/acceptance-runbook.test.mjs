import test from "node:test";
import assert from "node:assert/strict";
import {
  RUNBOOK_SCHEMA_VERSION,
  buildAcceptanceRunbook,
  formatRunbookMarkdown
} from "../src/core/acceptance-runbook.mjs";

test("AcceptanceRunbook: generates compliant schema and SHA-256 digest", () => {
  const runbook = buildAcceptanceRunbook({
    id: "RUNBOOK-TEST-001",
    targetFiles: ["src/core/sandbox-pool.mjs", "src/cli.mjs"],
    lifecycleStatus: "FIXED_PENDING_VERIFY",
    machineChecks: {
      flawReproduced: true,
      flawRemediated: true,
      prePatchExitCode: 1,
      postPatchExitCode: 0,
      signatureStatus: "VERIFIED",
      quorumScore: 0.95,
      quorumThreshold: 0.70,
      quorumPassed: true
    },
    reproductionSteps: [
      {
        title: "重現缺陷",
        description: "在 Patch 前執行 Active PoC，確認退出碼為 1",
        command: "node bin/triad-flow.mjs poc --cwe=CWE-89",
        expectedOutput: "Differential Status: DIFFERENTIAL_VERIFIED"
      }
    ],
    nonGoals: [
      "不修改既有 API 回應格式 (Hyrum's Law)",
      "不引入任何外部 npm 依賴"
    ],
    uncertainties: [
      "未測試真實 Podman rootless 環境 (已由 Docker 模擬驗證)"
    ]
  });

  assert.equal(runbook.schemaVersion, RUNBOOK_SCHEMA_VERSION);
  assert.equal(runbook.id, "RUNBOOK-TEST-001");
  assert.equal(runbook.lifecycleStatus, "FIXED_PENDING_VERIFY");
  assert.equal(runbook.targetFiles.length, 2);
  assert.equal(typeof runbook.digest, "string");
  assert.equal(runbook.digest.length, 64);

  const md = runbook.toMarkdown();
  assert.match(md, /RUNBOOK-TEST-001/);
  assert.match(md, /src\/core\/sandbox-pool\.mjs/);
  assert.match(md, /缺陷成功重現 \(必紅\)/);
  assert.match(md, /缺陷成功消除 \(轉綠\)/);
  assert.match(md, /node bin\/triad-flow\.mjs poc/);
  assert.match(md, /Hyrum's Law/);
  assert.match(md, /未測試真實 Podman rootless 環境/);
});

test("AcceptanceRunbook: handles fallback defaults gracefully", () => {
  const runbook = buildAcceptanceRunbook();
  assert.equal(runbook.schemaVersion, "1.0.0");
  assert.ok(runbook.id.startsWith("RUNBOOK-"));
  assert.equal(runbook.targetFiles.length, 0);

  const md = runbook.toMarkdown();
  assert.match(md, /npm test/);
  assert.match(md, /維持零外部執行期 npm 依賴/);
  assert.match(md, /暫無殘留不確定事項/);
});
