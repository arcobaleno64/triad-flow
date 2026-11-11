/**
 * End-to-End (E2E) Chained Integration Verification Test
 * Triad-Flow v2.12 Milestone: Four Pillars Pipeline
 *
 * Verifies seamless cross-module chaining across:
 * 1. Pillar 1: ContainerSandboxPool (Hot-Reuse Container Pool)
 * 2. Pillar 2: DistributedSwarmOrchestrator (Dependency-Aware Partitioning & Cryptographic Receipts)
 * 3. Pillar 3: ActivePoCSynthesizer (Dynamic PoC & Differential Verification)
 * 4. Pillar 4: TaxonomyQuorumCalibrator (Taxonomy-Aware Quorum & Physical Proof Override)
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { ContainerSandboxPool, PoolContainerDriver } from "../src/core/sandbox-pool.mjs";
import {
  DistributedSwarmOrchestrator,
  createIntermediateReceipt,
  verifyReceiptChain,
  ReceiptChainTamperedError,
  GENESIS_RECEIPT_HASH
} from "../src/core/swarm-orchestrator.mjs";
import {
  ActivePoCSynthesizer,
  VERIFICATION_STATUS,
  CWE_TAXONOMY,
  TEST_FRAMEWORKS
} from "../src/core/poc-synthesizer.mjs";
import {
  TaxonomyQuorumCalibrator,
  VULNERABILITY_DOMAINS,
  classifyTaxonomyDomain
} from "../src/core/taxonomy-quorum.mjs";

test("E2E Pipeline: Orchestrator -> Sandbox Pool -> PoC Synthesizer -> Quorum Calibrator", async () => {
  // 1. Setup Mock Container Sandbox Pool
  const executedCommands = [];
  const mockExecFn = (args) => {
    executedCommands.push(args);
    return {
      status: 0,
      stdout: "TAP version 13\nok 1 - test\n1..1\n# tests 1\n# pass 1\n",
      stderr: ""
    };
  };

  const pool = new ContainerSandboxPool({
    execFn: mockExecFn,
    autoRegisterSignalHandlers: false,
    reapIntervalMs: 0
  });

  // Pre-warm Node and Python daemons
  const warmed = pool.warmupSync(["node", "python"]);
  assert.equal(warmed.length, 2);

  // 2. Setup Orchestrator & Partition Interdependent ChangeSet
  const orchestrator = new DistributedSwarmOrchestrator({
    maxConcurrency: 2,
    failureThreshold: 2
  });

  const changeSet = {
    repoId: "arcobaleno64/triad-flow",
    baseSha: "v2.11.0",
    headSha: "HEAD",
    files: [
      {
        path: "src/utils/merge.js",
        status: "modified",
        additions: 15,
        deletions: 2
      },
      {
        path: "src/core/config-loader.js",
        status: "modified",
        additions: 10,
        deletions: 1
      },
      {
        path: "README.md",
        status: "modified",
        additions: 5,
        deletions: 0
      }
    ],
    diffHunks: [
      "diff --git a/src/utils/merge.js b/src/utils/merge.js\n+export function deepMerge(target, src) { for (let k in src) target[k] = src[k]; return target; }",
      "diff --git a/src/core/config-loader.js b/src/core/config-loader.js\n+import { deepMerge } from '../utils/merge.js';\n+export function loadConfig(user) { return deepMerge({}, user); }",
      "diff --git a/README.md b/README.md\n+# Documentation update"
    ].join("\n")
  };

  // Step 1: AST Dependency-Aware Partitioning
  const partitions = orchestrator.partition(changeSet);
  assert.ok(partitions.length >= 2, "Must partition into code and documentation clusters");

  const codePartition = partitions.find(p => p.targetFiles.includes("src/utils/merge.js"));
  assert.ok(codePartition, "Code partition must exist");
  assert.ok(
    codePartition.targetFiles.includes("src/core/config-loader.js"),
    "Interdependent merge.js and config-loader.js must be clustered together"
  );

  // Step 2: Dispatch through Sandbox Pool
  const driver = new PoolContainerDriver({}, pool);
  const probeRes = driver.probe();
  assert.equal(probeRes.available, true);

  const execRes = pool.execute(warmed[0], ["node", "--test", "tests/contract.test.mjs"]);
  assert.equal(execRes.exitCode, 0);
  assert.ok(execRes.durationMs < 1000, "Execution duration must be reasonable");

  // Step 3: PoC Synthesizer Differential Verification (CWE-1321 Prototype Pollution)
  const pocSynthesizer = new ActivePoCSynthesizer();
  const harness = pocSynthesizer.synthesize({
    cwe: CWE_TAXONOMY.CWE_1321,
    targetFunction: "deepMerge"
  });
  assert.ok(harness.script);
  assert.ok(harness.digest);

  // Vulnerable Pre-Patch Code (pollutes Object.prototype)
  const prePatchMerge = (target, src) => {
    for (const k of Object.keys(src)) {
      if (typeof src[k] === "object" && src[k] !== null) {
        if (!target[k]) target[k] = {};
        prePatchMerge(target[k], src[k]);
      } else {
        target[k] = src[k];
      }
    }
    return target;
  };

  // Fixed Post-Patch Code (guards __proto__ and prototype)
  const postPatchMerge = (target, src) => {
    for (const k of Object.keys(src)) {
      if (k === "__proto__" || k === "prototype" || k === "constructor") continue;
      if (typeof src[k] === "object" && src[k] !== null) {
        if (!target[k]) target[k] = {};
        postPatchMerge(target[k], src[k]);
      } else {
        target[k] = src[k];
      }
    }
    return target;
  };

  const differentialReceipt = await pocSynthesizer.verifyDifferential({
    harness: { cwe: CWE_TAXONOMY.CWE_1321, targetFunction: "deepMerge" },
    prePatch: prePatchMerge,
    postPatch: postPatchMerge
  });

  assert.equal(differentialReceipt.status, VERIFICATION_STATUS.DIFFERENTIAL_VERIFIED);
  assert.equal(differentialReceipt.verified, true);
  assert.equal(differentialReceipt.prePatch.passed, false);
  assert.equal(differentialReceipt.postPatch.passed, true);
  assert.ok(differentialReceipt.digest, "Receipt must contain cryptographic SHA-256 digest");

  // Step 4: Taxonomy Quorum Calibration with Physical Proof Override
  const calibrator = new TaxonomyQuorumCalibrator();

  const domainClassification = classifyTaxonomyDomain({
    cwe: "CWE-1321",
    title: "Prototype Pollution in deepMerge",
    file: "src/utils/merge.js"
  });
  assert.equal(domainClassification.domain, VULNERABILITY_DOMAINS.GENERAL_SECURITY);

  // Heterogeneous Reviews from Triad Reviewers
  const reports = [
    {
      id: "agy",
      provider: "agy",
      family: "google",
      status: "SUCCESS",
      healthy: true,
      findings: [
        {
          id: "FINDING-PP-01",
          cwe: "CWE-1321",
          title: "Prototype pollution in deepMerge",
          file: "src/utils/merge.js",
          severity: "high",
          sources: ["agy", "claude"]
        }
      ]
    },
    {
      id: "claude",
      provider: "claude",
      family: "anthropic",
      status: "SUCCESS",
      healthy: true,
      findings: [
        {
          id: "FINDING-PP-01",
          cwe: "CWE-1321",
          title: "Prototype pollution in deepMerge",
          file: "src/utils/merge.js",
          severity: "high",
          sources: ["agy", "claude"]
        }
      ]
    },
    {
      id: "codex",
      provider: "codex",
      family: "openai",
      status: "SUCCESS",
      healthy: true,
      findings: []
    }
  ];

  const quorumDecision = calibrator.calibrateQuorum({
    reports,
    files: [{ path: "src/utils/merge.js", additions: 15, deletions: 2 }],
    riskTier: 1
  });

  assert.equal(quorumDecision.quorumReached, true);
  assert.equal(quorumDecision.verdict, "needs-attention");
  assert.ok(quorumDecision.blockingFindings.length >= 1);
  assert.equal(quorumDecision.blockingFindings[0].cwe, "CWE-1321");
  assert.ok(quorumDecision.consensusProof, "Must emit tamper-proof consensusProof");
  assert.equal(typeof quorumDecision.consensusProof, "string");
  assert.equal(quorumDecision.consensusProof.length, 64);

  // Step 5: Asset Hardening into Persistent Regression File
  const tmpOutDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-e2e-reg-"));
  try {
    const regFilePath = path.join(tmpOutDir, "merge.regression.test.mjs");
    pocSynthesizer.writeRegressionTestFile(harness, regFilePath, {
      testFramework: TEST_FRAMEWORKS.NODE_TEST,
      advisoryId: "TF-ADV-2026-0033"
    });
    assert.ok(fs.existsSync(regFilePath), "Persistent regression test must be hardened to disk");
    const regContent = fs.readFileSync(regFilePath, "utf8");
    assert.match(regContent, /CWE-1321/);
    assert.match(regContent, /TF-ADV-2026-0033/);
  } finally {
    try { fs.rmSync(tmpOutDir, { recursive: true, force: true }); } catch {}
  }

  // Drain pool
  pool.drain();
});

test("E2E Invariant: Receipt Tampering in Orchestrator fails closed", () => {
  const partition1 = {
    runId: "test-run",
    targetFiles: ["src/a.js"],
    diffHunks: "+const a = 1;"
  };
  const partition2 = {
    runId: "test-run",
    targetFiles: ["src/b.js"],
    diffHunks: "+const b = 2;"
  };

  const r1 = createIntermediateReceipt({
    partition: partition1,
    workerId: "worker-1",
    sequenceNumber: 1,
    previousReceiptHash: GENESIS_RECEIPT_HASH,
    workerResult: {
      findings: [],
      coverage: { coveredFiles: ["src/a.js"], omittedFiles: [] }
    }
  });

  const r2 = createIntermediateReceipt({
    partition: partition2,
    workerId: "worker-2",
    sequenceNumber: 2,
    previousReceiptHash: r1.receiptHash,
    workerResult: {
      findings: [],
      coverage: { coveredFiles: ["src/b.js"], omittedFiles: [] }
    }
  });

  const receipts = [r1, r2];

  // Validate pristine chain
  const chainResult = verifyReceiptChain(receipts);
  assert.equal(chainResult.valid, true);

  // Tamper with first receipt payload
  const tamperedReceipts = [
    { ...receipts[0], status: "error" },
    receipts[1]
  ];

  assert.throws(
    () => verifyReceiptChain(tamperedReceipts),
    ReceiptChainTamperedError
  );
});
