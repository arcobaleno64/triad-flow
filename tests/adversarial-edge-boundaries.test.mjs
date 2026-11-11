import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";

import {
  buildAcceptanceRunbook,
  formatRunbookMarkdown,
  RUNBOOK_SCHEMA_VERSION
} from "../src/core/acceptance-runbook.mjs";

import {
  executePostRemediationHook
} from "../scripts/post-remediation-hook.mjs";

import {
  REMEDIATION_STATES,
  validateRemediationTransition,
  validatePatchScope,
  scanAntiDegradationViolations,
  RemediationTransitionError,
  PatchJailSecurityError
} from "../src/core/controlled-remediation.mjs";

import {
  DistributedSwarmOrchestrator,
  SWARM_VERDICTS
} from "../src/core/swarm-orchestrator.mjs";

// =============================================================================
// 1. Acceptance Runbook Markdown Breakout & Fallback Invariants
// =============================================================================

test("Edge Boundary 1: Acceptance Runbook prevents Markdown Code Fence Breakout", () => {
  const maliciousCommand = "echo ```nested-breakout``` | sh -c '````rm -rf /````'";
  const runbook = buildAcceptanceRunbook({
    id: "TASK-ESCAPE-01",
    reproductionSteps: [
      {
        title: "Adversarial Code Injection Step",
        command: maliciousCommand,
        expectedOutput: "escaped"
      }
    ]
  });

  const md = runbook.toMarkdown();

  // Must use at least 5 backticks fence to encapsulate 4-backtick inner content
  assert.ok(md.includes("`````bash\n   " + maliciousCommand + "\n   `````"));
  // Ensure the fence is not a bare 3-backtick fence
  assert.equal(Boolean(md.match(/(?<!`)`{3}bash/)), false);
});

test("Edge Boundary 2: Acceptance Runbook handles null, empty, and corrupted check options", () => {
  const runbook = buildAcceptanceRunbook({
    id: null,
    machineChecks: null,
    reproductionSteps: null,
    nonGoals: null,
    uncertainties: null
  });

  assert.equal(runbook.schemaVersion, RUNBOOK_SCHEMA_VERSION);
  assert.ok(runbook.id.startsWith("RUNBOOK-"));
  assert.equal(runbook.machineChecks.prePatchExitCode, 1);
  assert.equal(runbook.machineChecks.postPatchExitCode, 0);
  assert.equal(typeof runbook.digest, "string");
  assert.equal(runbook.digest.length, 64);

  const md = runbook.toMarkdown();
  assert.ok(md.includes("## 2. 🤖 機器檢查證明"));
  assert.ok(md.includes("## 4. 🚫 不做事項與邊界約束"));
});

// =============================================================================
// 2. Post-Remediation Hook Subprocess Calling Contract Boundaries
// =============================================================================

test("Edge Boundary 3: Post-Remediation Hook handles malformed / truncated stdin JSON gracefully", async () => {
  let stderrOutput = "";
  const mockStderr = {
    write: (chunk) => { stderrOutput += chunk; }
  };
  const mockStdout = {
    write: () => {}
  };

  const tmpRunbook = path.join(os.tmpdir(), `test-runbook-${crypto.randomBytes(4).toString("hex")}.md`);
  // Malformed JSON piped to hook
  const exitCode = await executePostRemediationHook([`--runbook=${tmpRunbook}`, "--format=json"], {
    stdinData: "{ malformed: [ 123 ",
    stdout: mockStdout,
    stderr: mockStderr
  });

  // Must not throw uncaught exception, falls back to git/local defaults and exits 0
  assert.equal(exitCode, 0);
});

test("Edge Boundary 4: Post-Remediation Hook strict mode fails closed on ineffective remediation", async () => {
  let stderrOutput = "";
  const mockStderr = {
    write: (chunk) => { stderrOutput += chunk; }
  };
  const mockStdout = {
    write: () => {}
  };

  const ineffectiveReceipt = {
    id: "TASK-INEFFECTIVE",
    status: "REJECTED_FIX",
    deterministicChecks: {
      exitCode: 1, // Fix failed
      pocVerification: {
        prePatchExecution: { flawReproduced: true },
        postPatchExecution: { flawRemediated: false }
      }
    }
  };

  const tmpRunbook = path.join(os.tmpdir(), `test-runbook-${crypto.randomBytes(4).toString("hex")}.md`);
  const exitCode = await executePostRemediationHook([`--runbook=${tmpRunbook}`, "--strict"], {
    stdinData: JSON.stringify(ineffectiveReceipt),
    stdout: mockStdout,
    stderr: mockStderr
  });

  // Strict mode MUST fail closed with exit code 1
  assert.equal(exitCode, 1);
  assert.match(stderrOutput, /Gate blocked: Remediation checks did not pass cleanly/i);
});

// =============================================================================
// 3. Controlled Remediation Monotonic Defense & Patch Jail Boundary
// =============================================================================

test("Edge Boundary 5: Monotonic Defense blocks model/synthesizer self-authorization and self-closing", () => {
  // Model attempting to transition to PATCH_AUTHORIZED
  assert.throws(
    () => validateRemediationTransition(
      REMEDIATION_STATES.FIX_PROPOSED,
      REMEDIATION_STATES.PATCH_AUTHORIZED,
      { actorType: "model", isSelfVerification: true }
    ),
    (err) => {
      assert.ok(err instanceof RemediationTransitionError);
      assert.match(err.message, /Monotonic Defense violation/i);
      return true;
    }
  );

  // Synthesizer attempting to transition directly to CLOSED
  assert.throws(
    () => validateRemediationTransition(
      REMEDIATION_STATES.FIXED_PENDING_VERIFY,
      REMEDIATION_STATES.CLOSED,
      { actorType: "synthesizer" }
    ),
    (err) => {
      assert.ok(err instanceof RemediationTransitionError);
      assert.match(err.message, /Monotonic Defense violation/i);
      return true;
    }
  );
});

test("Edge Boundary 6: Patch Jail strictly blocks modification of CI/CD manifests and package configs", () => {
  const protectedDiff = [
    "diff --git a/.github/workflows/deploy.yml b/.github/workflows/deploy.yml",
    "--- a/.github/workflows/deploy.yml",
    "+++ b/.github/workflows/deploy.yml",
    "@@ -10,3 +10,4 @@",
    "+      run: npm run test:skip-all"
  ].join("\n");

  assert.throws(
    () => validatePatchScope(protectedDiff, ["src/app.mjs"]),
    (err) => {
      assert.ok(err instanceof PatchJailSecurityError);
      assert.match(err.message, /Security boundary violation/i);
      return true;
    }
  );
});

test("Edge Boundary 7: Anti-Degradation Evasion detection in Multi-Language Diffs (Python & C)", () => {
  // Python: deleting assertion
  const pythonDiff = [
    "diff --git a/src/auth.py b/src/auth.py",
    "--- a/src/auth.py",
    "+++ b/src/auth.py",
    "@@ -5,3 +5,1 @@",
    "-    assert token == 'valid', 'Invalid token'",
    "+    pass"
  ].join("\n");

  const pyViolations = scanAntiDegradationViolations(pythonDiff, { targetFiles: ["src/auth.py"] });
  assert.ok(pyViolations.length > 0);
  assert.ok(pyViolations.some(v => v.description.toLowerCase().includes("assert") || v.type.includes("ASSERTION")));

  // C: removing boundary check
  const cDiff = [
    "diff --git a/src/parser.c b/src/parser.c",
    "--- a/src/parser.c",
    "+++ b/src/parser.c",
    "@@ -12,3 +12,1 @@",
    "-    if (len >= MAX_BUFFER) return -1;",
    "+    /* removed check */"
  ].join("\n");

  const cViolations = scanAntiDegradationViolations(cDiff, { targetFiles: ["src/parser.c"] });
  assert.ok(cViolations.length > 0);
});

// =============================================================================
// 4. Swarm Orchestrator Boundary Invariants
// =============================================================================

test("Edge Boundary 8: DistributedSwarmOrchestrator safely handles empty changeSet without deadlock", async () => {
  const orchestrator = new DistributedSwarmOrchestrator({
    workers: [
      {
        id: "worker-1",
        executeReview: async () => ({ findings: [], coverage: { coveredFiles: [], omittedFiles: [] } })
      }
    ]
  });

  const emptyChangeSet = {
    files: [],
    diffHunks: ""
  };

  const result = await orchestrator.dispatch(emptyChangeSet);
  assert.equal(result.ok, true);
  assert.equal(result.verdict, SWARM_VERDICTS.APPROVE);
  assert.equal(result.findings.length, 0);
  assert.equal(result.receiptChain.length, 0);
});
