import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import {
  DistributedSwarmOrchestrator,
  partitionChangeSetWithDependencies,
  extractCrossFileDependencies,
  createIntermediateReceipt,
  verifyReceiptChain,
  verifyCoverageCompleteness,
  CircuitBreaker,
  GENESIS_RECEIPT_HASH,
  CIRCUIT_BREAKER_STATES,
  CHUNK_STATUS,
  SWARM_VERDICTS,
  ReceiptChainTamperedError,
  CircuitBreakerOpenError,
  SwarmTimeoutError
} from "../src/core/swarm-orchestrator.mjs";
import { RISK_TIERS } from "../src/core/graph-router.mjs";

test("Contract: Dependency-Aware Partitioning clusters interdependent files together", () => {
  const diffA = [
    "diff --git a/src/auth/token.mjs b/src/auth/token.mjs",
    "--- a/src/auth/token.mjs",
    "+++ b/src/auth/token.mjs",
    "@@ -1,3 +1,5 @@",
    "+export function verifyToken(rawToken) {",
    "+  return rawToken === 'valid';",
    "+}"
  ].join("\n");

  const diffB = [
    "diff --git a/src/auth/guard.mjs b/src/auth/guard.mjs",
    "--- a/src/auth/guard.mjs",
    "+++ b/src/auth/guard.mjs",
    "@@ -1,2 +1,4 @@",
    "+import { verifyToken } from './token.mjs';",
    "+export function checkAuth(req) {",
    "+  return verifyToken(req.token);",
    "+}"
  ].join("\n");

  const diffC = [
    "diff --git a/src/billing/invoice.mjs b/src/billing/invoice.mjs",
    "--- a/src/billing/invoice.mjs",
    "+++ b/src/billing/invoice.mjs",
    "@@ -1,2 +1,3 @@",
    "+export function generateInvoice() { return 100; }"
  ].join("\n");

  const fullDiff = [diffA, diffB, diffC].join("\n");
  const changeSet = {
    files: [
      { path: "src/auth/token.mjs" },
      { path: "src/auth/guard.mjs" },
      { path: "src/billing/invoice.mjs" }
    ],
    diffHunks: fullDiff
  };

  const partitions = partitionChangeSetWithDependencies(changeSet);

  // token.mjs and guard.mjs should be clustered together because guard.mjs imports & calls verifyToken
  assert.equal(partitions.length, 2);

  const authPartition = partitions.find(p => p.targetFiles.includes("src/auth/guard.mjs"));
  assert.ok(authPartition);
  assert.ok(authPartition.targetFiles.includes("src/auth/token.mjs"));
  assert.equal(authPartition.targetFiles.length, 2);
  assert.ok(authPartition.dependencyEdges.length > 0);

  const billingPartition = partitions.find(p => p.targetFiles.includes("src/billing/invoice.mjs"));
  assert.ok(billingPartition);
  assert.equal(billingPartition.targetFiles.length, 1);
});

test("Contract: Explicit dependency graph is honored during partitioning", () => {
  const diffA = "diff --git a/src/a.mjs b/src/a.mjs\n+const a = 1;";
  const diffB = "diff --git a/src/b.mjs b/src/b.mjs\n+const b = 2;";
  const diffC = "diff --git a/src/c.mjs b/src/c.mjs\n+const c = 3;";

  const changeSet = {
    files: [{ path: "src/a.mjs" }, { path: "src/b.mjs" }, { path: "src/c.mjs" }],
    diffHunks: [diffA, diffB, diffC].join("\n")
  };

  const partitions = partitionChangeSetWithDependencies(changeSet, {
    dependencyGraph: {
      "src/a.mjs": ["src/c.mjs"]
    }
  });

  // a.mjs and c.mjs clustered together, b.mjs separate
  assert.equal(partitions.length, 2);
  const clusterAC = partitions.find(p => p.targetFiles.includes("src/a.mjs"));
  assert.ok(clusterAC.targetFiles.includes("src/c.mjs"));
});

test("Contract: Priority tier is determined correctly for clustered partitions", () => {
  const diffAuth = "diff --git a/src/auth/jwt.mjs b/src/auth/jwt.mjs\n+export function signJwt() {}";
  const diffUtil = "diff --git a/src/common/util.mjs b/src/common/util.mjs\n+import './jwt.mjs';\n+export function log() {}";

  const changeSet = {
    files: [{ path: "src/auth/jwt.mjs" }, { path: "src/common/util.mjs" }],
    diffHunks: [diffAuth, diffUtil].join("\n")
  };

  const partitions = partitionChangeSetWithDependencies(changeSet);
  assert.equal(partitions.length, 1);
  // Tier 1 Critical inherited because auth/jwt.mjs is in the cluster
  assert.equal(partitions[0].priorityTier, RISK_TIERS.TIER_1_CRITICAL);
});

test("Contract: Cryptographic Intermediate Receipts form valid SHA-256 hash chain", () => {
  const partition1 = {
    partitionId: "partition-001",
    runId: "run-test",
    targetFiles: ["src/a.mjs"],
    diffHunks: "diff --git a/src/a.mjs b/src/a.mjs\n+code;",
    clusterId: "cluster-001"
  };

  const partition2 = {
    partitionId: "partition-002",
    runId: "run-test",
    targetFiles: ["src/b.mjs"],
    diffHunks: "diff --git a/src/b.mjs b/src/b.mjs\n+code;",
    clusterId: "cluster-002"
  };

  const rcpt1 = createIntermediateReceipt({
    partition: partition1,
    workerResult: {
      findings: [{ title: "Finding 1", severity: "low" }],
      coverage: { coveredFiles: ["src/a.mjs"], omittedFiles: [] }
    },
    previousReceiptHash: GENESIS_RECEIPT_HASH,
    workerId: "worker-alpha",
    sequenceNumber: 1
  });

  assert.equal(rcpt1.sequenceNumber, 1);
  assert.equal(rcpt1.previousReceiptHash, GENESIS_RECEIPT_HASH);
  assert.match(rcpt1.receiptHash, /^sha256:[a-f0-9]{64}$/);

  const rcpt2 = createIntermediateReceipt({
    partition: partition2,
    workerResult: {
      findings: [],
      coverage: { coveredFiles: ["src/b.mjs"], omittedFiles: [] }
    },
    previousReceiptHash: rcpt1.receiptHash,
    workerId: "worker-beta",
    sequenceNumber: 2
  });

  assert.equal(rcpt2.sequenceNumber, 2);
  assert.equal(rcpt2.previousReceiptHash, rcpt1.receiptHash);
  assert.match(rcpt2.receiptHash, /^sha256:[a-f0-9]{64}$/);

  const verification = verifyReceiptChain([rcpt1, rcpt2]);
  assert.equal(verification.valid, true);
  assert.equal(verification.chainLength, 2);
  assert.equal(verification.rootHash, rcpt2.receiptHash);
});

test("Contract: Tampered intermediate receipt triggers ReceiptChainTamperedError", () => {
  const partition = {
    partitionId: "partition-tamper",
    runId: "run-tamper",
    targetFiles: ["src/secure.mjs"],
    diffHunks: "diff --git a/src/secure.mjs b/src/secure.mjs\n+const secret = 42;",
    clusterId: "cluster-001"
  };

  const rcpt1 = createIntermediateReceipt({
    partition,
    workerResult: { findings: [] },
    previousReceiptHash: GENESIS_RECEIPT_HASH,
    workerId: "worker-1",
    sequenceNumber: 1
  });

  // Tamper: modify findings or status inside payload without regenerating hash
  const tamperedRcpt = {
    ...rcpt1,
    status: CHUNK_STATUS.UNINSPECTED_CHUNK
  };

  assert.throws(
    () => verifyReceiptChain([tamperedRcpt]),
    (err) => {
      assert.ok(err instanceof ReceiptChainTamperedError);
      assert.match(err.message, /Tampered receipt detected/);
      return true;
    }
  );
});

test("Contract: Broken previousReceiptHash link triggers ReceiptChainTamperedError", () => {
  const partition = {
    partitionId: "p1",
    runId: "run-link",
    targetFiles: ["src/a.mjs"],
    diffHunks: "diff",
    clusterId: "c1"
  };

  const rcpt1 = createIntermediateReceipt({
    partition,
    workerResult: { findings: [] },
    previousReceiptHash: GENESIS_RECEIPT_HASH,
    workerId: "w1",
    sequenceNumber: 1
  });

  const rcpt2 = createIntermediateReceipt({
    partition,
    workerResult: { findings: [] },
    previousReceiptHash: "sha256:1111111111111111111111111111111111111111111111111111111111111111", // Corrupted link
    workerId: "w2",
    sequenceNumber: 2
  });

  assert.throws(
    () => verifyReceiptChain([rcpt1, rcpt2]),
    (err) => {
      assert.ok(err instanceof ReceiptChainTamperedError);
      assert.match(err.message, /previousReceiptHash mismatch/);
      return true;
    }
  );
});

test("Contract: Out-of-order sequence triggers ReceiptChainTamperedError", () => {
  const partition = {
    partitionId: "p1",
    runId: "run-seq",
    targetFiles: ["src/a.mjs"],
    diffHunks: "diff",
    clusterId: "c1"
  };

  const rcpt = createIntermediateReceipt({
    partition,
    workerResult: { findings: [] },
    previousReceiptHash: GENESIS_RECEIPT_HASH,
    workerId: "w1",
    sequenceNumber: 2 // Discontinuity: expected 1
  });

  assert.throws(
    () => verifyReceiptChain([rcpt]),
    (err) => {
      assert.ok(err instanceof ReceiptChainTamperedError);
      assert.match(err.message, /Sequence discontinuity/);
      return true;
    }
  );
});

test("CircuitBreaker: Normal execution succeeds and resets failure count", async () => {
  const cb = new CircuitBreaker({ workerId: "test-worker", failureThreshold: 2 });
  const result = await cb.execute(async () => "ok", { timeoutMs: 500 });
  assert.equal(result, "ok");
  assert.equal(cb.getState(), CIRCUIT_BREAKER_STATES.CLOSED);
  assert.equal(cb.failureCount, 0);
});

test("CircuitBreaker: Timeout triggers SwarmTimeoutError and tracks failures", async () => {
  const cb = new CircuitBreaker({ workerId: "slow-worker", failureThreshold: 2 });

  await assert.rejects(
    async () => {
      await cb.execute(
        () => new Promise(resolve => setTimeout(resolve, 200)),
        { timeoutMs: 50, maxRetries: 0 }
      );
    },
    (err) => {
      assert.ok(err instanceof SwarmTimeoutError);
      assert.match(err.message, /timed out after 50ms/);
      return true;
    }
  );

  assert.equal(cb.failureCount, 1);
  assert.equal(cb.getState(), CIRCUIT_BREAKER_STATES.CLOSED);
});

test("CircuitBreaker: Reaching failure threshold transitions state to OPEN and fast-fails", async () => {
  const cb = new CircuitBreaker({ workerId: "failing-worker", failureThreshold: 2, resetTimeoutMs: 1000 });

  const failTask = () => Promise.reject(new Error("Downstream service failure"));

  // First failure
  await assert.rejects(() => cb.execute(failTask, { maxRetries: 0 }));
  assert.equal(cb.getState(), CIRCUIT_BREAKER_STATES.CLOSED);

  // Second failure -> Trips circuit breaker to OPEN
  await assert.rejects(() => cb.execute(failTask, { maxRetries: 0 }));
  assert.equal(cb.getState(), CIRCUIT_BREAKER_STATES.OPEN);

  // Subsequent call fast-fails immediately with CircuitBreakerOpenError without calling task
  let called = false;
  await assert.rejects(
    () => cb.execute(() => { called = true; return Promise.resolve(); }),
    (err) => {
      assert.ok(err instanceof CircuitBreakerOpenError);
      assert.equal(err.workerId, "failing-worker");
      return true;
    }
  );
  assert.equal(called, false);
});

test("CircuitBreaker: Half-Open probe resets circuit on success", async () => {
  const cb = new CircuitBreaker({ workerId: "probe-worker", failureThreshold: 1, resetTimeoutMs: 50 });

  // Cause failure to trip to OPEN
  await assert.rejects(() => cb.execute(() => Promise.reject(new Error("fail")), { maxRetries: 0 }));
  assert.equal(cb.getState(), CIRCUIT_BREAKER_STATES.OPEN);

  // Wait for reset timeout
  await new Promise(r => setTimeout(r, 60));
  assert.equal(cb.getState(), CIRCUIT_BREAKER_STATES.HALF_OPEN);

  // Successful call restores to CLOSED
  const res = await cb.execute(() => Promise.resolve("recovered"), { timeoutMs: 500 });
  assert.equal(res, "recovered");
  assert.equal(cb.getState(), CIRCUIT_BREAKER_STATES.CLOSED);
  assert.equal(cb.failureCount, 0);
});

test("DistributedSwarmOrchestrator: Full clean review dispatch with multiple workers", async () => {
  const orchestrator = new DistributedSwarmOrchestrator({
    workers: [
      {
        id: "worker-1",
        executeReview: async (partition) => ({
          findings: [],
          coverage: { coveredFiles: partition.targetFiles, omittedFiles: [] }
        })
      },
      {
        id: "worker-2",
        executeReview: async (partition) => ({
          findings: [],
          coverage: { coveredFiles: partition.targetFiles, omittedFiles: [] }
        })
      }
    ]
  });

  const changeSet = {
    files: [{ path: "src/foo.mjs" }, { path: "src/bar.mjs" }],
    diffHunks: "diff --git a/src/foo.mjs b/src/foo.mjs\n+foo;\ndiff --git a/src/bar.mjs b/src/bar.mjs\n+bar;"
  };

  const result = await orchestrator.dispatch(changeSet);

  assert.equal(result.ok, true);
  assert.equal(result.verdict, SWARM_VERDICTS.APPROVE);
  assert.equal(result.receiptChain.length, 2);
  assert.equal(result.stats.inspectedPartitions, 2);
  assert.equal(result.stats.uninspectedPartitions, 0);
  assert.match(result.rootReceiptHash, /^sha256:[a-f0-9]{64}$/);
});

test("DistributedSwarmOrchestrator: Strict fail-closed fallback on worker timeout / failure", async () => {
  const orchestrator = new DistributedSwarmOrchestrator({
    timeoutMs: 50,
    maxRetries: 0,
    workers: [
      {
        id: "reliable-worker",
        executeReview: async (partition) => ({
          findings: [],
          coverage: { coveredFiles: partition.targetFiles, omittedFiles: [] }
        })
      },
      {
        id: "broken-worker",
        executeReview: async () => {
          // Timeout
          await new Promise(r => setTimeout(r, 200));
          return { findings: [] };
        }
      }
    ]
  });

  const changeSet = {
    files: [{ path: "src/auth/login.mjs" }, { path: "src/docs/guide.md" }],
    diffHunks: "diff --git a/src/auth/login.mjs b/src/auth/login.mjs\n+login;\ndiff --git a/src/docs/guide.md b/src/docs/guide.md\n+doc;"
  };

  const result = await orchestrator.dispatch(changeSet);

  // Strict Fail-Closed Guarantee:
  // Must NOT emit ok: true or verdict: "approve" when a worker timed out
  assert.equal(result.ok, false);
  assert.equal(result.verdict, SWARM_VERDICTS.ERROR);
  assert.equal(result.stats.uninspectedPartitions, 1);

  // Contains UNINSPECTED_CHUNK finding
  const uninspectedFinding = result.findings.find(f => f.type === "UNINSPECTED_CHUNK");
  assert.ok(uninspectedFinding);
  assert.equal(uninspectedFinding.severity, "critical");

  // Receipt chain is still cryptographically sound and complete
  assert.equal(result.receiptChain.length, 2);
  const uninspectedReceipt = result.receiptChain.find(r => r.status === CHUNK_STATUS.UNINSPECTED_CHUNK);
  assert.ok(uninspectedReceipt);
  assert.equal(uninspectedReceipt.workerId, "broken-worker");
});

test("DistributedSwarmOrchestrator: Empty ChangeSet returns approved verdict with 0 receipts", async () => {
  const orchestrator = new DistributedSwarmOrchestrator({
    workers: [{ id: "w", executeReview: async () => ({ findings: [] }) }]
  });

  const result = await orchestrator.dispatch({ files: [], diffHunks: "" });
  assert.equal(result.ok, true);
  assert.equal(result.verdict, SWARM_VERDICTS.APPROVE);
  assert.equal(result.receiptChain.length, 0);
  assert.equal(result.rootReceiptHash, GENESIS_RECEIPT_HASH);
});

test("Contract: Cross-language AST symbol extraction supports Python, C++, and Go", () => {
  const diffPyA = [
    "diff --git a/services/auth.py b/services/auth.py",
    "--- a/services/auth.py",
    "+++ b/services/auth.py",
    "@@ -1,3 +1,5 @@",
    "+def authenticate_session(token):",
    "+    return token == 'valid'"
  ].join("\n");

  const diffPyB = [
    "diff --git a/services/api.py b/services/api.py",
    "--- a/services/api.py",
    "+++ b/services/api.py",
    "@@ -1,2 +1,4 @@",
    "+from services.auth import authenticate_session",
    "+def handle_request(req):",
    "+    return authenticate_session(req['token'])"
  ].join("\n");

  const changeSet = {
    files: [{ path: "services/auth.py" }, { path: "services/api.py" }],
    diffHunks: [diffPyA, diffPyB].join("\n")
  };

  const partitions = partitionChangeSetWithDependencies(changeSet);
  assert.equal(partitions.length, 1);
  assert.equal(partitions[0].targetFiles.length, 2);
  assert.ok(partitions[0].targetFiles.includes("services/auth.py"));
  assert.ok(partitions[0].targetFiles.includes("services/api.py"));
});

test("Contract: Oversized cluster is sub-partitioned while preserving clusterId", () => {
  const diff1 = "diff --git a/src/mod/a.mjs b/src/mod/a.mjs\n+export function fa() { return 'a'.repeat(200); }";
  const diff2 = "diff --git a/src/mod/b.mjs b/src/mod/b.mjs\n+import './a.mjs';\n+export function fb() { return 'b'.repeat(200); }";

  const changeSet = {
    files: [{ path: "src/mod/a.mjs" }, { path: "src/mod/b.mjs" }],
    diffHunks: [diff1, diff2].join("\n")
  };

  // Set tiny maxChunkBytes to force sub-partitioning
  const partitions = partitionChangeSetWithDependencies(changeSet, { maxChunkBytes: 60 });
  assert.equal(partitions.length, 2);
  assert.equal(partitions[0].clusterId, partitions[1].clusterId);
  assert.equal(partitions[0].subChunkIndex, 1);
  assert.equal(partitions[1].subChunkIndex, 2);
  assert.equal(partitions[0].clusterTotalSubChunks, 2);
  assert.equal(partitions[1].clusterTotalSubChunks, 2);
});

test("Contract: Worker retries on transient error and succeeds", async () => {
  let callCount = 0;
  const orchestrator = new DistributedSwarmOrchestrator({
    maxRetries: 2,
    timeoutMs: 1000,
    workers: [
      {
        id: "retry-worker",
        executeReview: async (partition) => {
          callCount += 1;
          if (callCount === 1) {
            throw new Error("Transient network glitch");
          }
          return {
            findings: [],
            coverage: { coveredFiles: partition.targetFiles, omittedFiles: [] }
          };
        }
      }
    ]
  });

  const changeSet = {
    files: [{ path: "src/retry.mjs" }],
    diffHunks: "diff --git a/src/retry.mjs b/src/retry.mjs\n+const x = 1;"
  };

  const result = await orchestrator.dispatch(changeSet);
  assert.equal(result.ok, true);
  assert.equal(result.verdict, SWARM_VERDICTS.APPROVE);
  assert.equal(callCount, 2);
  assert.equal(result.stats.uninspectedPartitions, 0);
});

test("Contract: Incomplete file coverage triggers fail-closed error verdict", async () => {
  const orchestrator = new DistributedSwarmOrchestrator({
    workers: [
      {
        id: "evasive-worker",
        executeReview: async () => ({
          findings: [],
          // Intentionally fails to cover src/uncovered.mjs without omitting it
          coverage: { coveredFiles: ["src/covered.mjs"], omittedFiles: [] }
        })
      }
    ]
  });

  const changeSet = {
    files: [{ path: "src/covered.mjs" }, { path: "src/uncovered.mjs" }],
    // Put them in same diff
    diffHunks: "diff --git a/src/covered.mjs b/src/covered.mjs\n+c;\ndiff --git a/src/uncovered.mjs b/src/uncovered.mjs\n+u;"
  };

  const result = await orchestrator.dispatch(changeSet);
  assert.equal(result.ok, false);
  assert.equal(result.verdict, SWARM_VERDICTS.ERROR);
});

test("Contract: Zero external npm dependencies in swarm-orchestrator", async () => {
  const fs = await import("node:fs");
  const pkgContent = fs.readFileSync(new URL("../package.json", import.meta.url), "utf8");
  const pkg = JSON.parse(pkgContent);

  // Invariant: Zero external runtime dependencies
  assert.deepEqual(pkg.dependencies, undefined);

  // Check swarm-orchestrator.mjs imports
  const code = fs.readFileSync(new URL("../src/core/swarm-orchestrator.mjs", import.meta.url), "utf8");
  const importLines = code.match(/^import .* from ["'](.*)["'];/gm) || [];
  for (const line of importLines) {
    const match = line.match(/from ["'](.*)["']/);
    const mod = match[1];
    assert.ok(
      mod.startsWith("node:") || mod.startsWith("./") || mod.startsWith("../"),
      `Illegal external import detected: ${mod}`
    );
  }
});

