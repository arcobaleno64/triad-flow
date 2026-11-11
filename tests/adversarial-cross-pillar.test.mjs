import test from "node:test";
import assert from "node:assert/strict";

import {
  ContainerSandboxPool,
  POOL_CONTAINER_STATES,
  DANGEROUS_CONTAINER_ENV_VARS,
  PoolError,
  DaemonExecutionError
} from "../src/core/sandbox-pool.mjs";

import {
  ActivePoCSynthesizer,
  PoCHarness,
  CWE_TAXONOMY,
  HARNESS_LANGUAGES
} from "../src/core/poc-synthesizer.mjs";

import {
  TaxonomyQuorumCalibrator,
  VULNERABILITY_DOMAINS
} from "../src/core/taxonomy-quorum.mjs";
import { RISK_TIERS } from "../src/core/graph-router.mjs";

// =============================================================================
// Pillar 1: Container Sandbox Security & Injection Prevention
// =============================================================================

test("Pillar 1 Adversarial: Disallows dangerous environment variable injection in container exec", async () => {
  const pool = new ContainerSandboxPool({
    minWarm: 0,
    maxCapacity: 2,
    runtime: "docker",
    execFn: (cmd, args) => ({ status: 0, stdout: "ok" })
  });

  const daemon = pool._spawnDaemonSync({ language: "javascript" });

  const dangerousVars = [
    "LD_PRELOAD",
    "NODE_OPTIONS",
    "PYTHONSTARTUP",
    "BASH_ENV",
    "ENV",
    "PERL5OPT"
  ];

  for (const dangerousKey of dangerousVars) {
    // Synchronous execution must fail closed
    assert.throws(
      () => pool.execute(daemon, ["node", "-v"], { env: { [dangerousKey]: "/jail/evil.so" } }),
      (err) => {
        assert.ok(err instanceof DaemonExecutionError);
        assert.match(err.message, /dangerous environment variable.*disallowed/i);
        return true;
      },
      `Failed to reject dangerous env var: ${dangerousKey}`
    );

    // Asynchronous execution must fail closed
    await assert.rejects(
      async () => await pool.executeAsync(daemon, ["node", "-v"], { env: { [dangerousKey]: "/jail/evil.so" } }),
      (err) => {
        assert.ok(err instanceof DaemonExecutionError);
        assert.match(err.message, /dangerous environment variable.*disallowed/i);
        return true;
      }
    );
  }

  // Key with '=' or null byte must also be rejected
  assert.throws(
    () => pool.execute(daemon, ["node", "-v"], { env: { "FOO=BAR": "baz" } }),
    /Invalid environment variable key/i
  );

  await pool.drain();
});

test("Pillar 1 Adversarial: Rejects option-injection and malicious image identifiers", async () => {
  const pool = new ContainerSandboxPool({
    minWarm: 0,
    maxCapacity: 2,
    runtime: "docker",
    execFn: (cmd, args) => ({ status: 0, stdout: "ok" })
  });

  const maliciousImages = [
    "--privileged",
    "--volume=/etc:/host:rw",
    "-v /:/jail",
    "node:20-slim; rm -rf /",
    "node:20 slim"
  ];

  for (const badImg of maliciousImages) {
    assert.throws(
      () => pool._spawnDaemonSync({ image: badImg }),
      (err) => {
        assert.ok(err instanceof PoolError);
        assert.match(err.message, /Security violation: Invalid or dangerous container image/i);
        return true;
      },
      `Failed to reject malicious image identifier: ${badImg}`
    );
  }

  await pool.drain();
});

test("Pillar 1 Adversarial: Cwd path traversal attempts cannot escape /jail", () => {
  let capturedExecArgs = null;
  const pool = new ContainerSandboxPool({
    minWarm: 0,
    maxCapacity: 2,
    runtime: "docker",
    execFn: (cmd, args) => {
      capturedExecArgs = args;
      return { status: 0, stdout: "ok" };
    }
  });

  const daemon = pool._spawnDaemonSync({ language: "javascript" });

  // Attacker attempts relative directory traversal
  pool.execute(daemon, ["ls"], { cwd: "../../../etc" });
  assert.ok(capturedExecArgs);
  const wIdx = capturedExecArgs.indexOf("-w");
  assert.notEqual(wIdx, -1);
  // Must remain strictly /jail and not escape to /etc
  assert.equal(capturedExecArgs[wIdx + 1], "/jail");

  // Legitimate subdirectory within jail is preserved
  pool.execute(daemon, ["ls"], { cwd: "packages/core" });
  const wIdx2 = capturedExecArgs.indexOf("-w");
  assert.equal(capturedExecArgs[wIdx2 + 1], "/jail/packages/core");
});

// =============================================================================
// Pillar 2: Active PoC Synthesizer Hardening & Isolation
// =============================================================================

test("Pillar 2 Adversarial: Neutralizes code injection via targetFunction in regression generator", () => {
  const synthesizer = new ActivePoCSynthesizer();

  const maliciousHarness = new PoCHarness({
    cwe: CWE_TAXONOMY.CWE_1321,
    language: HARNESS_LANGUAGES.JAVASCRIPT,
    targetFunction: "safe; process.exit(1); //",
    payload: { __proto__: { polluted: "tf_compromised" } },
    script: "// dummy"
  });

  const generatedCode = synthesizer.hardenToRegressionTest(maliciousHarness, { runner: "node-test" });

  // Injected code must be safely enclosed in string bracket access, not evaluated as raw JS syntax
  assert.ok(generatedCode.includes('targetPkg["safe; process.exit(1); //"]'));
  assert.ok(!generatedCode.includes("const target = targetPkg.safe; process.exit(1);"));
});

test("Pillar 2 Adversarial: In-memory VM sandbox blocks unauthorized module require", () => {
  const synthesizer = new ActivePoCSynthesizer();

  const harness = new PoCHarness({
    cwe: CWE_TAXONOMY.CWE_89,
    language: HARNESS_LANGUAGES.JAVASCRIPT,
    targetFunction: "buildQuery",
    payload: "' OR '1'='1",
    script: `
      const target = globalThis.buildQuery;
      target("' OR '1'='1");
    `
  });

  // Malicious code string attempting to require child_process or fs in sandbox VM
  const maliciousCodeString = `
    const cp = require("child_process");
    globalThis.buildQuery = () => cp.execSync("whoami");
  `;

  const result = synthesizer.executeHarnessSync(harness, { code: maliciousCodeString });
  assert.equal(result.passed, false);
  assert.match(result.stderr, /Sandbox VM require disallowed for: child_process/i);
});

test("Pillar 2 Adversarial: Enforces execution timeout against CPU-bound infinite loops", () => {
  const synthesizer = new ActivePoCSynthesizer({ defaultTimeoutMs: 150 });

  const harness = new PoCHarness({
    cwe: CWE_TAXONOMY.CWE_20,
    language: HARNESS_LANGUAGES.JAVASCRIPT,
    targetFunction: "validate",
    payload: "input",
    script: "globalThis.validate('input');"
  });

  // Malicious target contains infinite loop
  const infiniteLoopCode = `
    globalThis.validate = () => { while(true) {} };
  `;

  const result = synthesizer.executeHarnessSync(harness, { code: infiniteLoopCode }, { timeoutMs: 100 });
  assert.equal(result.passed, false);
  assert.match(result.stderr, /timed out/i);
});

// =============================================================================
// Pillar 4: Taxonomy Quorum Arbitration & Physical Proof Override
// =============================================================================

test("Pillar 4 Adversarial: Physical Proof Override forces blocker status overruling 100% LLM Approve", () => {
  const calibrator = new TaxonomyQuorumCalibrator();

  // 3 LLM Reviewers from 3 distinct vendor families all claim APPROVE with 0 findings
  const reports = [
    { id: "sentry-google", provider: "agy", family: "google", verdict: "approve", findings: [] },
    { id: "sentry-anthropic", provider: "claude", family: "anthropic", verdict: "approve", findings: [] },
    { id: "sentry-openai", provider: "codex", family: "openai", verdict: "approve", findings: [] }
  ];

  const candidateFinding = {
    id: "TF-POLLUTION-01",
    cwe: "CWE-1321",
    severity: "high",
    title: "Prototype Pollution in object merge",
    file: "src/utils/merge.js"
  };

  // Sentries report candidate finding but LLMs downplay it as non-blocking
  const reportsWithCandidate = [
    { id: "sentry-google", provider: "agy", family: "google", findings: [candidateFinding] },
    { id: "sentry-anthropic", provider: "claude", family: "anthropic", verdict: "approve", findings: [] },
    { id: "sentry-openai", provider: "codex", family: "openai", verdict: "approve", findings: [] }
  ];

  // Active verified physical proof produced by ActivePoCSynthesizer
  const physicalProof = {
    verified: true,
    cwe: "CWE-1321",
    status: "PATCH_INEFFECTIVE",
    digest: "sha256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"
  };

  const decision = calibrator.calibrateQuorum({
    reports: reportsWithCandidate,
    files: [{ path: "src/utils/merge.js", additions: 20, deletions: 5 }],
    riskTier: RISK_TIERS.TIER_2_SOURCE,
    physicalProof
  });

  // Physical proof MUST enforce blocker status and override LLM approval
  assert.equal(decision.quorumReached, true);
  assert.equal(decision.verdict, "needs-attention");
  assert.equal(decision.blockingFindings.length, 1);
  const blocker = decision.blockingFindings[0];
  assert.equal(blocker.physicalProofOverride, true);
  assert.equal(blocker.weightedConfidence, 1.0);
  assert.equal(blocker.isConfirmed, true);
  assert.equal(blocker.isBlocking, true);
});

test("Pillar 4 Adversarial: Tier 1 multi-vendor diversity rejects homogeneous Sybil collusion", () => {
  const calibrator = new TaxonomyQuorumCalibrator();

  // 3 Reviewers from the SAME vendor family (openai) attempting to approve Tier 1 security files
  const homogeneousReports = [
    { id: "worker-1", provider: "codex", family: "openai", verdict: "approve", findings: [] },
    { id: "worker-2", provider: "gpt-4o", family: "openai", verdict: "approve", findings: [] },
    { id: "worker-3", provider: "o3-mini", family: "openai", verdict: "approve", findings: [] }
  ];

  const decision = calibrator.calibrateQuorum({
    reports: homogeneousReports,
    files: [{ path: "src/auth/jwt.mjs", additions: 15, deletions: 2 }],
    riskTier: RISK_TIERS.TIER_1_CRITICAL
  });

  // Must fail closed with verdict: error and topology: QUORUM_FAILED
  assert.equal(decision.quorumReached, false);
  assert.equal(decision.verdict, "error");
  assert.equal(decision.topology, "QUORUM_FAILED");
  assert.match(decision.reason, /require at least 2 healthy heterogeneous provider families/i);
});
