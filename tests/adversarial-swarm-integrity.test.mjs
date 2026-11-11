import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import {
  DistributedSwarmOrchestrator,
  createIntermediateReceipt,
  verifyReceiptChain,
  verifyCoverageCompleteness,
  GENESIS_RECEIPT_HASH,
  CHUNK_STATUS,
  SWARM_VERDICTS,
  ReceiptChainTamperedError
} from "../src/core/swarm-orchestrator.mjs";

test("Adversarial Contract 1: Receipt Chain Replay Attack Rejection (Cross-Run Forgery)", () => {
  const partitionA = {
    partitionId: "partition-run1-001",
    runId: "run-1",
    targetFiles: ["src/auth/token.mjs"],
    diffHunks: "+const token = 1;",
    contentDigest: "sha256:aaa"
  };

  const partitionB = {
    partitionId: "partition-run2-002",
    runId: "run-2",
    targetFiles: ["src/billing/pay.mjs"],
    diffHunks: "+const pay = 2;",
    contentDigest: "sha256:bbb"
  };

  const rcpt1 = createIntermediateReceipt({
    partition: partitionA,
    workerResult: { findings: [] },
    previousReceiptHash: GENESIS_RECEIPT_HASH,
    workerId: "worker-1",
    sequenceNumber: 1
  });

  // Legitimate receipt 1 passes
  assert.equal(verifyReceiptChain([rcpt1]).valid, true);

  // Attacker attempts to replay receipt from run-1 into run-2 as receipt 2
  const replayedRcpt = {
    ...rcpt1,
    sequenceNumber: 2, // Modified sequence number to bypass index check
    previousReceiptHash: rcpt1.receiptHash // Chained to itself
  };

  // Replay MUST fail closed because recomputing the payload hash invalidates receiptHash
  assert.throws(
    () => verifyReceiptChain([rcpt1, replayedRcpt]),
    (err) => {
      assert.ok(err instanceof ReceiptChainTamperedError);
      assert.match(err.message, /Tampered receipt detected/i);
      return true;
    }
  );
});

test("Adversarial Contract 2: Comprehensive Payload Tampering Invariant across All Fields", () => {
  const partition = {
    partitionId: "partition-sec-001",
    runId: "run-sec",
    targetFiles: ["src/kernel/crypto.mjs"],
    diffHunks: "+function encrypt() {}",
    contentDigest: "sha256:kernel-crypto"
  };

  const legitimateReceipt = createIntermediateReceipt({
    partition,
    workerResult: {
      findings: [{ id: "CWE-327", severity: "high", title: "Broken Crypto" }],
      coverage: { coveredFiles: ["src/kernel/crypto.mjs"], omittedFiles: [] }
    },
    previousReceiptHash: GENESIS_RECEIPT_HASH,
    workerId: "sec-auditor-1",
    sequenceNumber: 1
  });

  assert.equal(verifyReceiptChain([legitimateReceipt]).valid, true);

  // Fields to test tampering: modifying any single field while keeping receiptHash must fail closed
  const tamperCases = [
    { name: "workerId forgery", mod: { workerId: "impersonated-worker" } },
    { name: "status alteration", mod: { status: CHUNK_STATUS.UNINSPECTED_CHUNK } },
    { name: "targetFiles injection", mod: { targetFiles: ["src/kernel/crypto.mjs", "src/secret.key"] } },
    { name: "timestamp manipulation", mod: { timestamp: "1970-01-01T00:00:00.000Z" } },
    { name: "partitionId spoofing", mod: { partitionId: "partition-spoofed-999" } },
    { name: "contentDigest tampering", mod: { contentDigest: "sha256:forged-content" } },
    { name: "resultDigest tampering", mod: { resultDigest: "sha256:forged-result" } },
    { name: "sequenceNumber decrement", mod: { sequenceNumber: 0 } },
    { name: "previousReceiptHash overwrite", mod: { previousReceiptHash: "0".repeat(64) } }
  ];

  for (const { name, mod } of tamperCases) {
    const tampered = { ...legitimateReceipt, ...mod };
    assert.throws(
      () => verifyReceiptChain([tampered]),
      (err) => {
        assert.ok(err instanceof ReceiptChainTamperedError, `Expected ReceiptChainTamperedError on ${name}`);
        return true;
      },
      `Failed to catch tampering on ${name}`
    );
  }
});

test("Adversarial Contract 3: Cryptographic Signature Key Substitution & Forgery", () => {
  const { publicKey: pubKeyA, privateKey: privKeyA } = crypto.generateKeyPairSync("ed25519");
  const { publicKey: pubKeyB, privateKey: privKeyB } = crypto.generateKeyPairSync("ed25519");

  const partition = {
    partitionId: "partition-sig-001",
    runId: "run-sig",
    targetFiles: ["src/auth.mjs"],
    diffHunks: "+const auth = true;",
    contentDigest: "sha256:auth"
  };

  // 1. Signed with Key A
  const receiptA = createIntermediateReceipt({
    partition,
    workerResult: { findings: [] },
    previousReceiptHash: GENESIS_RECEIPT_HASH,
    workerId: "worker-sig",
    sequenceNumber: 1,
    privateKey: privKeyA
  });

  // Valid with Public Key A
  assert.equal(verifyReceiptChain([receiptA], { publicKey: pubKeyA }).valid, true);

  // Fails with Foreign Public Key B
  assert.throws(
    () => verifyReceiptChain([receiptA], { publicKey: pubKeyB }),
    /Ed25519 public key verification failed/i
  );

  // 2. HMAC Key Substitution
  const hmacSecret1 = "secret-key-alpha-999";
  const hmacSecret2 = "secret-key-beta-888";

  const hmacReceipt = createIntermediateReceipt({
    partition,
    workerResult: { findings: [] },
    previousReceiptHash: GENESIS_RECEIPT_HASH,
    workerId: "worker-hmac",
    sequenceNumber: 1,
    hmacKey: hmacSecret1
  });

  // Valid with secret 1
  assert.equal(verifyReceiptChain([hmacReceipt], { hmacKey: hmacSecret1 }).valid, true);

  // Fails with secret 2
  assert.throws(
    () => verifyReceiptChain([hmacReceipt], { hmacKey: hmacSecret2 }),
    /HMAC signature verification failed/i
  );

  // 3. Stripping signature when signature is required by verifier
  const strippedReceipt = { ...hmacReceipt, signature: null };
  assert.throws(
    () => verifyReceiptChain([strippedReceipt], { hmacKey: hmacSecret1 }),
    /Missing HMAC signature at receipt/i
  );
});

test("Adversarial Contract 4: Malformed, Null, and Prototype Pollution Resistance", () => {
  assert.throws(() => verifyReceiptChain("not-an-array"), /must be an array/i);
  assert.throws(() => verifyReceiptChain([null]), /Corrupted receipt at index 0/i);
  assert.throws(() => verifyReceiptChain([undefined]), /Corrupted receipt at index 0/i);
  assert.throws(() => verifyReceiptChain(["string-instead-of-object"]), /Corrupted receipt at index 0/i);

  // Sequence discontinuity
  const badSeq = {
    sequenceNumber: 2, // Should be 1
    previousReceiptHash: GENESIS_RECEIPT_HASH,
    receiptHash: "dummy"
  };
  assert.throws(() => verifyReceiptChain([badSeq]), /Sequence discontinuity at index 0/i);
});

test("Adversarial Contract 5: Path Normalization & Windows/POSIX Directory Traversal Evasion", () => {
  const changeSet = {
    files: [
      { path: "src/auth/token.mjs" },
      { path: "src/billing/invoice.mjs" }
    ]
  };

  // Worker attempts to report coverage using redundant dots, backslashes, or relative prefixes
  const receipts = [
    {
      status: CHUNK_STATUS.INSPECTED,
      targetFiles: ["src/auth/token.mjs"],
      coverage: {
        coveredFiles: [
          "./src/auth/token.mjs", // leading dot
          "src\\billing\\invoice.mjs" // Windows backslashes
        ],
        omittedFiles: []
      }
    }
  ];

  const evalResult = verifyCoverageCompleteness(changeSet, receipts);
  assert.equal(evalResult.complete, true);
  assert.equal(evalResult.missingFiles.length, 0);
  assert.equal(evalResult.uninspectedFiles.length, 0);
  assert.deepEqual(evalResult.coveredFiles, ["src/auth/token.mjs", "src/billing/invoice.mjs"]);
});

test("Adversarial Contract 6: Uninspected Chunk Strictly Overrides Fraudulent Coverage Claims", () => {
  const changeSet = {
    files: [
      { path: "src/kernel/driver.c" },
      { path: "src/kernel/main.c" }
    ]
  };

  // Worker 1 crashed and produced an UNINSPECTED_CHUNK receipt
  const receiptFailed = {
    status: CHUNK_STATUS.UNINSPECTED_CHUNK,
    targetFiles: ["src/kernel/driver.c"],
    coverage: { coveredFiles: [], omittedFiles: [] }
  };

  // Malicious/confused Worker 2 claims it covered driver.c
  const receiptFraudulent = {
    status: CHUNK_STATUS.INSPECTED,
    targetFiles: ["src/kernel/main.c"],
    coverage: {
      coveredFiles: ["src/kernel/driver.c", "src/kernel/main.c"],
      omittedFiles: []
    }
  };

  // Fail-closed invariant: uninspected chunk MUST mark complete = false and preserve uninspected file
  const evalResult = verifyCoverageCompleteness(changeSet, [receiptFailed, receiptFraudulent]);
  assert.equal(evalResult.complete, false);
  assert.ok(evalResult.uninspectedFiles.includes("src/kernel/driver.c"));
});

test("Adversarial Contract 7: Ghost / Missing File Stealth Omission Detection", () => {
  const changeSet = {
    files: [
      { path: "src/core/a.js" },
      { path: "src/core/b.js" },
      { path: "src/core/secret-backdoor.js" } // Completely omitted by workers
    ]
  };

  const receipts = [
    {
      status: CHUNK_STATUS.INSPECTED,
      targetFiles: ["src/core/a.js", "src/core/b.js"],
      coverage: {
        coveredFiles: ["src/core/a.js", "src/core/b.js"],
        omittedFiles: []
      }
    }
  ];

  const evalResult = verifyCoverageCompleteness(changeSet, receipts);
  assert.equal(evalResult.complete, false);
  assert.deepEqual(evalResult.missingFiles, ["src/core/secret-backdoor.js"]);
});

test("Adversarial Contract 8: DistributedSwarmOrchestrator Fails Closed on Receipt Tampering in Live Dispatch", async () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");

  // Worker returns tampered status
  const orchestrator = new DistributedSwarmOrchestrator({
    workers: [
      {
        id: "adversarial-worker",
        executeReview: async (partition) => ({
          findings: [],
          coverage: {
            coveredFiles: [], // Drops coverage
            omittedFiles: []
          }
        })
      }
    ]
  });

  const changeSet = {
    files: [{ path: "src/security.mjs" }],
    diffHunks: "diff --git a/src/security.mjs b/src/security.mjs\n+const sec = true;"
  };

  const result = await orchestrator.dispatch(changeSet, {
    privateKey,
    publicKey
  });

  // Coverage is incomplete, dispatch MUST fail closed with verdict: ERROR and ok: false
  assert.equal(result.ok, false);
  assert.equal(result.verdict, SWARM_VERDICTS.ERROR);
  assert.equal(result.coverage.complete, false);
  assert.ok(result.coverage.missingFiles.includes("src/security.mjs"));
});
