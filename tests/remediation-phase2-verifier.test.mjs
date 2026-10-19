/**
 * Phase 2 Remediation Acceptance Test Suite (PR #39)
 *
 * Implements authoritative negative regression contracts for all 11 reproducible root causes
 * in src/core/independent-verifier.mjs plus positive controls to guard against false holds.
 *
 * Test Matrix:
 *   PHASE2-NEG-01: (VERIFIER-RC-01 / PRRT_kwDOUWarIc6re31W) Passive remediation advice in recommendation/body does not count as concrete counterexample
 *   PHASE2-NEG-02: (VERIFIER-RC-02 / PRRT_kwDOUWarIc6rte6b) Prompt input budget reserves non-diff overhead, diff truncation flags isDiffTruncated and propagates UNCERTAIN
 *   PHASE2-NEG-03: (VERIFIER-RC-04 / PRRT_kwDOUWarIc6rfkYc, PRRT_kwDOUWarIc6r1Bt4, PRRT_kwDOUWarIc6slqmD) Non-boolean string locatorAccurate ('unknown', 'flase') fails closed
 *   PHASE2-NEG-04: (VERIFIER-RC-05 / PRRT_kwDOUWarIc6rvCBQ, PRRT_kwDOUWarIc6sU7ZH, PRRT_kwDOUWarIc6rY131) Impossible line number beyond physical file length marks locatorAccurate false
 *   PHASE2-NEG-05: (VERIFIER-RC-06 / PRRT_kwDOUWarIc6r1BuM) Omission with counterexample but empty reasoning downgrades to INSUFFICIENT_EVIDENCE
 *   PHASE2-NEG-06: (VERIFIER-RC-07 / PRRT_kwDOUWarIc6rtv6O) Omission assessment retains cwe and type metadata in verifierOmissions
 *   PHASE2-NEG-07: (VERIFIER-RC-08 / PRRT_kwDOUWarIc6sMI7L) Clean Challenge with contested omission but missing explicit overallStatus fails closed with malformed_output
 *   PHASE2-NEG-08: (VERIFIER-RC-09 / PRRT_kwDOUWarIc6rrUDp, PRRT_kwDOUWarIc6rxChi) CliVerifierAdapter terminates child process when output exceeds limits.maxOutputBytes
 *   PHASE2-NEG-09: (VERIFIER-RC-10 / PRRT_kwDOUWarIc6sl1Rg) conductIndependentVerification resolves objective from options.runContext or changeSet
 *   PHASE2-NEG-10: (VERIFIER-RC-11 / PRRT_kwDOUWarIc6sL8VO, PRRT_kwDOUWarIc6sl1Rc) Context gaps on changeSet.contextPackage propagate to validateVerificationOutput and force UNCERTAIN
 *   PHASE2-NEG-11: (VERIFIER-RC-12 / PRRT_kwDOUWarIc6qo0u0) Observed runtime verifierAdapter.actualModel takes precedence over caller-configured options.actualModel
 *   PHASE2-POS-01: Legitimate omission with valid file, valid lines within bounds, concrete counterexample and reasoning passes as SUPPORTED
 *   PHASE2-POS-02: Legitimate Clean Challenge with explicit CLEAN overallStatus and bound patchObjective succeeds without false hold
 *   PHASE2-NEG-18: (P2-LOC-06) Diff hunk provenance strictly verified against authentic Git/disk/manifest backing
 *   PHASE2-NEG-25: (P2-CAP-06) Public buildContextPackage in non-git environment with fabricated inputs cannot register authority or promote omissions to SUPPORTED
 *   PHASE2-NEG-26: (P2-CAP-07) Caller cannot provide tampered fileContents to override committed Git content in Exact-Head mode
 *   PHASE2-NEG-27: (P2-CAP-08) Context package in-memory mutation or cloning cannot retain Trusted Registry authority or promote unverified omissions
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { pathToFileURL } from "node:url";
import { execFileSync } from "node:child_process";

import {
  conductIndependentVerification,
  createMockVerifierAdapter,
  validateVerificationOutput,
  validateSyntheticVerificationOutput,
  registerTrustedContextPackage,
  isTrustedContextPackage,
  validateContextPackageAuthenticity,
  mintWorkflowAuthorityToken,
  isWorkflowAuthorityToken,
  hasConcreteCounterexample,
  buildVerificationPrompt,
  CliVerifierAdapter,
  RunContext,
  computeContextPackageSnapshotHash,
  deepFreeze
} from "../src/core/independent-verifier.mjs";
import { EXECUTION_STATUS } from "../src/adapters/provider-contract.mjs";
import { buildContextPackage } from "../src/core/context-builder.mjs";
import { getExactHeadFileContent } from "../src/core/git-collector.mjs";

// Helper: minimal valid changeset referencing an existing repo file
const currentRepoHeadSha = execFileSync(
  "git",
  ["-c", "core.fsmonitor=false", "rev-parse", "HEAD"],
  {
    cwd: process.cwd(),
    encoding: "utf8"
  }
).trim();

if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/i.test(currentRepoHeadSha)) {
  throw new Error("PHASE2 tests require a valid checked-out Git HEAD");
}

function createTestChangeSet(overrides = {}) {
  return {
    headSha: currentRepoHeadSha,
    contentDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    totalFiles: 1,
    files: [
      {
        path: "src/core/independent-verifier.mjs",
        additions: 10,
        deletions: 2,
        binary: false
      }
    ],
    diffHunks: `diff --git a/src/core/independent-verifier.mjs b/src/core/independent-verifier.mjs
index 1111111..2222222 100644
--- a/src/core/independent-verifier.mjs
+++ b/src/core/independent-verifier.mjs
@@ -100,6 +100,10 @@
+const testAdd = 1;
`,
    ...overrides
  };
}

// ============================================================================
// PHASE2-NEG-01: (VERIFIER-RC-01 / PRRT_kwDOUWarIc6re31W)
// ============================================================================
test("PHASE2-NEG-01: Passive remediation advice in recommendation/body without concrete failure reasoning returns false and downgrades to INSUFFICIENT_EVIDENCE", () => {
  const passiveAdviceCandidate = {
    title: "Missing input validation",
    file: "src/core/independent-verifier.mjs",
    line_start: 100,
    line_end: 105,
    locatorAccurate: true,
    severity: "high",
    evidenceSupport: "SUPPORTED",
    reasoning: "", // Empty reasoning!
    recommendation: "Call validate(input) when null is passed to prevent crash and avoid TypeError"
  };

  // 1. hasConcreteCounterexample must derive proof strictly from reasoning/counterexample
  assert.equal(hasConcreteCounterexample(passiveAdviceCandidate), false, "Passive remediation advice without reasoning must NOT count as concrete counterexample");

  // 2. validateVerificationOutput must downgrade the omission to INSUFFICIENT_EVIDENCE
  const changeSet = createTestChangeSet();
  const rawOutput = {
    overallStatus: "DEFECTS_FOUND",
    evaluations: [],
    verifierOmissions: [passiveAdviceCandidate]
  };

  const validated = validateVerificationOutput(rawOutput, { changeSet });
  assert.ok(validated.ok);
  assert.equal(validated.verifierOmissions.length, 1);
  assert.equal(validated.verifierOmissions[0].evidenceSupport, "INSUFFICIENT_EVIDENCE");
});

// ============================================================================
// PHASE2-NEG-02: (VERIFIER-RC-02 / PRRT_kwDOUWarIc6rte6b)
// ============================================================================
test("PHASE2-NEG-02: Prompt input budget reserves non-diff overhead, diff truncation sets isDiffTruncated and propagates UNCERTAIN", async () => {
  const maxInputBytes = 6000;
  // Large diff that fits within maxInputBytes alone (5500 bytes), but exceeds budget when overhead (contextPackage, schema, etc.) is added
  const largeDiff = "+\n".repeat(2700); // ~5400 bytes

  const changeSet = createTestChangeSet({
    diffHunks: largeDiff
  });

  const mockAdapter = createMockVerifierAdapter("claude", {
    executeVerification: async () => ({
      ok: true,
      overallStatus: "CLEAN",
      evaluations: [],
      verifierOmissions: []
    })
  });

  const record = await conductIndependentVerification(
    changeSet,
    [],
    mockAdapter,
    {
      verificationMode: "clean_challenge",
      limits: { maxInputBytes },
      contextPackage: {
        layers: {
          ast: { content: "function foo() { return 1; }" }
        }
      }
    }
  );

  // When prompt reserves overhead, large diff must be truncated and propagate UNCERTAIN
  assert.equal(record.diffTruncated, true, "record.diffTruncated must be true when diff exceeds reserved input budget");
  assert.equal(record.overallStatus, "UNCERTAIN", "overallStatus must be forced to UNCERTAIN when diff is truncated");
});

// ============================================================================
// PHASE2-NEG-03: (VERIFIER-RC-04 / PRRT_kwDOUWarIc6rfkYc, PRRT_kwDOUWarIc6r1Bt4, PRRT_kwDOUWarIc6slqmD)
// ============================================================================
test("PHASE2-NEG-03: Non-boolean string locatorAccurate ('unknown', 'flase') or omitted defaults to false and downgrades to INSUFFICIENT_EVIDENCE", () => {
  const changeSet = createTestChangeSet();

  const candidateUnknown = {
    title: "SQL Injection in query",
    file: "src/core/independent-verifier.mjs",
    line_start: 100,
    line_end: 105,
    locatorAccurate: "unknown", // Malformed non-boolean string
    severity: "critical",
    evidenceSupport: "SUPPORTED",
    reasoning: "query(userInput) directly concatenates string leading to SQL injection vulnerability",
    counterexample: "query('1 OR 1=1') -> returns all records"
  };

  const resUnknown = validateVerificationOutput(
    { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [candidateUnknown] },
    { changeSet }
  );
  assert.ok(resUnknown.ok);
  assert.equal(resUnknown.verifierOmissions[0].locatorAccurate, false);
  assert.equal(resUnknown.verifierOmissions[0].evidenceSupport, "INSUFFICIENT_EVIDENCE");

  const candidateFlase = {
    ...candidateUnknown,
    locatorAccurate: "flase" // Typo string
  };
  const resFlase = validateVerificationOutput(
    { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [candidateFlase] },
    { changeSet }
  );
  assert.ok(resFlase.ok);
  assert.equal(resFlase.verifierOmissions[0].locatorAccurate, false);
  assert.equal(resFlase.verifierOmissions[0].evidenceSupport, "INSUFFICIENT_EVIDENCE");

  const candidateMissing = {
    ...candidateUnknown,
    locatorAccurate: undefined // Omitted locatorAccurate
  };
  const resMissing = validateVerificationOutput(
    { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [candidateMissing] },
    { changeSet }
  );
  assert.ok(resMissing.ok);
  assert.equal(resMissing.verifierOmissions[0].locatorAccurate, false);
  assert.equal(resMissing.verifierOmissions[0].evidenceSupport, "INSUFFICIENT_EVIDENCE");
});

// ============================================================================
// PHASE2-NEG-04: (VERIFIER-RC-05 / PRRT_kwDOUWarIc6rvCBQ, PRRT_kwDOUWarIc6sU7ZH, PRRT_kwDOUWarIc6rY131)
// ============================================================================
test("PHASE2-NEG-04: Impossible line number beyond physical file length marks locatorAccurate false and downgrades to INSUFFICIENT_EVIDENCE", () => {
  const changeSet = createTestChangeSet();

  const outOfBoundsOmission = {
    title: "Buffer overflow on non-existent line",
    file: "src/core/independent-verifier.mjs",
    line_start: 999999, // Impossible line number!
    line_end: 1000005,
    locatorAccurate: true,
    severity: "critical",
    evidenceSupport: "SUPPORTED",
    reasoning: "Executing bufferCopy(dest, src, 1024) causes heap corruption crash",
    counterexample: "bufferCopy(ptr, input, 9999) -> SIGSEGV crash"
  };

  const validated = validateVerificationOutput(
    { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [outOfBoundsOmission] },
    { changeSet }
  );

  assert.ok(validated.ok);
  assert.equal(validated.verifierOmissions[0].locatorAccurate, false, "Line number beyond file length must set locatorAccurate to false");
  assert.equal(validated.verifierOmissions[0].evidenceSupport, "INSUFFICIENT_EVIDENCE", "Out-of-bounds locator must downgrade omission to INSUFFICIENT_EVIDENCE");
});

// ============================================================================
// PHASE2-NEG-05: (VERIFIER-RC-06 / PRRT_kwDOUWarIc6r1BuM)
// ============================================================================
test("PHASE2-NEG-05: Omission with counterexample but empty reasoning downgrades to INSUFFICIENT_EVIDENCE", () => {
  const changeSet = createTestChangeSet();

  const terseOmission = {
    title: "Null dereference in parser",
    file: "src/core/independent-verifier.mjs",
    line_start: 100,
    line_end: 105,
    locatorAccurate: true,
    severity: "high",
    evidenceSupport: "SUPPORTED",
    reasoning: "", // Empty reasoning!
    counterexample: "validate(null) -> TypeError crash"
  };

  const validated = validateVerificationOutput(
    { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [terseOmission] },
    { changeSet }
  );

  assert.ok(validated.ok);
  assert.equal(validated.verifierOmissions[0].evidenceSupport, "INSUFFICIENT_EVIDENCE", "Omission lacking substantive explanatory reasoning must be downgraded to INSUFFICIENT_EVIDENCE");
});

// ============================================================================
// PHASE2-NEG-06: (VERIFIER-RC-07 / PRRT_kwDOUWarIc6rtv6O)
// ============================================================================
test("PHASE2-NEG-06: Omission assessment retains cwe and type metadata in verifierOmissions", () => {
  const changeSet = createTestChangeSet();

  const richOmission = {
    title: "SQL Injection in query handler",
    file: "src/core/independent-verifier.mjs",
    line_start: 100,
    line_end: 105,
    locatorAccurate: true,
    severity: "critical",
    evidenceSupport: "SUPPORTED",
    cwe: "CWE-89",
    type: "SQL_INJECTION",
    reasoning: "Calling executeQuery(req.params.id) directly embeds raw unescaped input causing SQL injection",
    counterexample: "executeQuery(\"' OR '1'='1\") -> dumps entire users table"
  };

  const validated = validateVerificationOutput(
    { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [richOmission] },
    { changeSet }
  );

  assert.ok(validated.ok);
  assert.equal(validated.verifierOmissions[0].cwe, "CWE-89", "omissionAssessment must retain provided cwe");
  assert.equal(validated.verifierOmissions[0].type, "SQL_INJECTION", "omissionAssessment must retain provided type");
});

// ============================================================================
// PHASE2-NEG-07: (VERIFIER-RC-08 / PRRT_kwDOUWarIc6sMI7L)
// ============================================================================
test("PHASE2-NEG-07: Clean Challenge with contested omission but missing explicit overallStatus fails closed with malformed_output", () => {
  const changeSet = createTestChangeSet();

  const contestedOmission = {
    title: "Theoretical race condition",
    file: "src/core/independent-verifier.mjs",
    line_start: 100,
    line_end: 105,
    locatorAccurate: true,
    severity: "low",
    evidenceSupport: "CONTESTED",
    reasoning: "Thread mutex locks the resource synchronously, so concurrent access is impossible in current architecture."
  };

  // Verifier response in Clean Challenge mode omitting overallStatus
  const rawOutput = {
    evaluations: [],
    verifierOmissions: [contestedOmission]
    // overallStatus omitted!
  };

  const validated = validateVerificationOutput(rawOutput, {
    changeSet,
    verificationMode: "clean_challenge"
  });

  assert.equal(validated.ok, false, "Clean Challenge with missing overallStatus must fail closed");
  assert.equal(validated.executionStatus, EXECUTION_STATUS.MALFORMED_OUTPUT);
  assert.match(validated.error, /Clean Challenge verifier output missing or invalid required 'overallStatus'/i);
});

// ============================================================================
// PHASE2-NEG-08: (VERIFIER-RC-09 / PRRT_kwDOUWarIc6rrUDp, PRRT_kwDOUWarIc6rxChi)
// ============================================================================
test("PHASE2-NEG-08: CliVerifierAdapter terminates child process when output exceeds limits.maxOutputBytes", async () => {
  // Use node -e to emit 50 KB of stream data
  const adapter = new CliVerifierAdapter({
    command: process.execPath,
    args: ["-e", "process.stdout.write(Buffer.alloc(50000, 65));"]
  });

  const res = await adapter.executeVerification({
    prompt: "Evaluate diff",
    limits: {
      maxOutputBytes: 1024 // 1 KB ceiling
    }
  });

  assert.equal(res.ok, false, "Execution must fail when maxOutputBytes is exceeded");
  assert.match(res.error, /maxOutputBytes/i);
});

// ============================================================================
// PHASE2-NEG-09: (VERIFIER-RC-10 / PRRT_kwDOUWarIc6sl1Rg)
// ============================================================================
test("PHASE2-NEG-09: conductIndependentVerification resolves objective from options.runContext or changeSet", async () => {
  const changeSet = createTestChangeSet();

  let capturedPrompt = "";
  const mockAdapter = createMockVerifierAdapter("claude", {
    executeVerification: async (input) => {
      capturedPrompt = input.prompt;
      return {
        ok: true,
        overallStatus: "CLEAN",
        evaluations: [],
        verifierOmissions: []
      };
    }
  });

  const runContext = new RunContext({
    headSha: changeSet.headSha,
    contentDigest: changeSet.contentDigest,
    patchObjective: "Prevent privilege escalation in authorization token handler"
  });

  const record = await conductIndependentVerification(
    changeSet,
    [],
    mockAdapter,
    {
      verificationMode: "clean_challenge",
      runContext
      // Note: options.patchObjective is intentionally omitted!
    }
  );

  assert.equal(record.patchObjective, "Prevent privilege escalation in authorization token handler", "patchObjective must be resolved from runContext");
  assert.ok(capturedPrompt.includes("Prevent privilege escalation in authorization token handler"), "Constructed prompt must contain stated patch objective from runContext");
});

// ============================================================================
// PHASE2-NEG-10: (VERIFIER-RC-11 / PRRT_kwDOUWarIc6sL8VO, PRRT_kwDOUWarIc6sl1Rc)
// ============================================================================
test("PHASE2-NEG-10: Context gaps on changeSet.contextPackage propagate to validateVerificationOutput and force UNCERTAIN", async () => {
  const changeSetWithGaps = createTestChangeSet({
    contextPackage: {
      layers: {
        ast: { content: "function foo() {}" }
      },
      contextGaps: [
        { symbol: "auth.verifyToken", reason: "EXTERNAL_CALLEE_UNRESOLVED" }
      ]
    }
  });

  const mockAdapter = createMockVerifierAdapter("claude", {
    executeVerification: async () => ({
      ok: true,
      overallStatus: "CLEAN", // Verifier attempts to claim CLEAN despite gaps
      evaluations: [],
      verifierOmissions: []
    })
  });

  const record = await conductIndependentVerification(
    changeSetWithGaps,
    [],
    mockAdapter,
    {
      verificationMode: "clean_challenge"
      // Note: options.contextPackage is omitted; contextPackage lives on changeSet
    }
  );

  assert.equal(record.overallStatus, "UNCERTAIN", "Context gaps on changeSet.contextPackage must propagate and force overallStatus to UNCERTAIN");
});

// ============================================================================
// PHASE2-NEG-11: (VERIFIER-RC-12 / PRRT_kwDOUWarIc6qo0u0)
// ============================================================================
test("PHASE2-NEG-11: Observed runtime verifierAdapter.actualModel takes precedence over caller-configured options.actualModel", async () => {
  const changeSet = createTestChangeSet();

  const mockAdapter = createMockVerifierAdapter("claude", {
    executeVerification: async () => ({
      ok: true,
      overallStatus: "CLEAN",
      evaluations: [],
      verifierOmissions: []
    })
  });
  // Runtime adapter observed actualModel
  mockAdapter.actualModel = {
    value: "claude-3-5-sonnet-20241022",
    source: "observed"
  };

  const record = await conductIndependentVerification(
    changeSet,
    [],
    mockAdapter,
    {
      verificationMode: "clean_challenge",
      actualModel: {
        value: "claude-static-fallback",
        source: "configured"
      }
    }
  );

  assert.equal(
    record.verifier.actualModel.value,
    "claude-3-5-sonnet-20241022",
    "Observed verifier adapter actualModel must take precedence over caller-configured actualModel"
  );
});

// ============================================================================
// PHASE2-POS-01: Positive Control - Legitimate Omission Evaluation
// ============================================================================
test("PHASE2-POS-01: Legitimate omission with valid line numbers within file bounds, concrete counterexample and reasoning passes as SUPPORTED", () => {
  const changeSet = createTestChangeSet();

  const validOmission = {
    title: "SQL injection via unescaped identifier",
    file: "src/core/independent-verifier.mjs",
    line_start: 100,
    line_end: 110,
    locatorAccurate: true,
    severity: "high",
    evidenceSupport: "SUPPORTED",
    cwe: "CWE-89",
    type: "SQL_INJECTION",
    reasoning: "The identifier is concatenated directly into SQL without quoting, allowing table alteration when user input contains quotes.",
    counterexample: "alterTable('users; DROP TABLE users--') -> executes drop table command and causes database corruption"
  };

  const validated = validateVerificationOutput(
    { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [validOmission] },
    { changeSet }
  );

  assert.ok(validated.ok);
  assert.equal(validated.verifierOmissions.length, 1);
  assert.equal(validated.verifierOmissions[0].evidenceSupport, "SUPPORTED");
  assert.equal(validated.verifierOmissions[0].locatorAccurate, true);
  assert.equal(validated.verifierOmissions[0].cwe, "CWE-89");
  assert.equal(validated.verifierOmissions[0].type, "SQL_INJECTION");
});

// ============================================================================
// PHASE2-POS-02: Positive Control - Legitimate Clean Challenge
// ============================================================================
test("PHASE2-POS-02: Legitimate Clean Challenge with explicit CLEAN overallStatus and bound patchObjective succeeds without false hold", async () => {
  const changeSet = createTestChangeSet();

  const mockAdapter = createMockVerifierAdapter("claude", {
    executeVerification: async () => ({
      ok: true,
      overallStatus: "CLEAN",
      evaluations: [],
      verifierOmissions: []
    })
  });

  const record = await conductIndependentVerification(
    changeSet,
    [],
    mockAdapter,
    {
      verificationMode: "clean_challenge",
      patchObjective: "Harden input validation against path traversal",
      runContext: new RunContext({
        headSha: changeSet.headSha,
        contentDigest: changeSet.contentDigest,
        patchObjective: "Harden input validation against path traversal"
      })
    }
  );

  assert.ok(record.ok);
  assert.equal(record.overallStatus, "CLEAN");
  assert.equal(record.patchObjective, "Harden input validation against path traversal");
  assert.equal(record.verificationMode, "clean_challenge");
});

// ============================================================================
// PHASE2-NEG-12: Objective Binding Conflict Protection
// ============================================================================
test("PHASE2-NEG-12: Conflicting caller patchObjective cannot override authoritative RunContext objective", async () => {
  const changeSet = createTestChangeSet();

  const mockAdapter = createMockVerifierAdapter("claude", {
    executeVerification: async () => ({
      ok: true,
      overallStatus: "CLEAN",
      evaluations: [],
      verifierOmissions: []
    })
  });

  const runContext = new RunContext({
    headSha: changeSet.headSha,
    contentDigest: changeSet.contentDigest,
    patchObjective: "Prevent privilege escalation in authorization token handler"
  });

  // Caller provides a conflicting patchObjective
  const record = await conductIndependentVerification(
    changeSet,
    [],
    mockAdapter,
    {
      verificationMode: "clean_challenge",
      runContext,
      patchObjective: "Refactor harmless logging formatting"
    }
  );

  // Must fail closed with UNCERTAIN, ok: false, or OBJECTIVE_MISMATCH error
  assert.equal(record.ok, false, "Conflicting objective must fail verification record ok");
  assert.equal(record.overallStatus, "UNCERTAIN", "Conflicting objective must force overallStatus to UNCERTAIN");
  assert.match(record.error, /OBJECTIVE_MISMATCH|conflicts with authoritative RunContext/i);
});

// ============================================================================
// PHASE2-NEG-13: Locator Integrity on Inaccessible / Missing File
// ============================================================================
test("PHASE2-NEG-13: Missing or inaccessible target file cannot establish physical line count and must downgrade SUPPORTED omission to INSUFFICIENT_EVIDENCE", () => {
  // File is listed in changeSet files but cannot be read from disk / repo, leaving physicalLineCount === null
  const changeSet = createTestChangeSet({
    files: [{ path: "src/non-existent-missing-file.mjs" }]
  });

  const outOfBoundsOmission = {
    title: "Arbitrary code execution on line 9999999",
    file: "src/non-existent-missing-file.mjs",
    line_start: 9999999,
    line_end: 10000005,
    locatorAccurate: true,
    severity: "critical",
    evidenceSupport: "SUPPORTED",
    reasoning: "Executing bufferCopy on line 9999999 causes heap corruption crash",
    counterexample: "bufferCopy(ptr, input, 9999) -> SIGSEGV crash"
  };

  const validated = validateVerificationOutput(
    { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [outOfBoundsOmission] },
    { changeSet }
  );

  assert.ok(validated.ok);
  assert.equal(validated.verifierOmissions[0].locatorAccurate, false, "Inaccessible file must set locatorAccurate to false");
  assert.equal(validated.verifierOmissions[0].evidenceSupport, "INSUFFICIENT_EVIDENCE", "Unverifiable locator must downgrade SUPPORTED to INSUFFICIENT_EVIDENCE");
});

// ============================================================================
// PHASE2-NEG-14: Prompt Input Budget UTF-8 Limit Enforcement
// ============================================================================
test("PHASE2-NEG-14: Assembled prompt exceeding maxInputBytes budget forces UNCERTAIN and cannot return CLEAN", async () => {
  const maxInputBytes = 1500;
  const changeSet = createTestChangeSet({
    diffHunks: "+\n".repeat(250) // ~500 bytes diff
  });

  const mockAdapter = createMockVerifierAdapter("claude", {
    executeVerification: async () => ({
      ok: true,
      overallStatus: "CLEAN",
      evaluations: [],
      verifierOmissions: []
    })
  });

  // Extra large context package (~4500 bytes) pushing total assembled prompt to ~5800 bytes
  const largeContextPackage = {
    layers: {
      ast: {
        content: "function criticalSecurityHandler() {\n" + "  console.log('security checking execution context');\n".repeat(80) + "}"
      }
    }
  };

  const record = await conductIndependentVerification(
    changeSet,
    [],
    mockAdapter,
    {
      verificationMode: "clean_challenge",
      limits: { maxInputBytes },
      contextPackage: largeContextPackage
    }
  );

  assert.equal(record.diffTruncated, true, "Diff or prompt capacity must be marked truncated");
  assert.equal(record.overallStatus, "UNCERTAIN", "Oversized prompt must force UNCERTAIN status and never permit CLEAN");
});

// ============================================================================
// PHASE2-NEG-15: (P2-OBJ-03) Dual Objective Declaration Conflict Protection
// ============================================================================
test("PHASE2-NEG-15: Secondary objectiveContract conflicting with RunContext fails closed even when patchObjective matches", async () => {
  const changeSet = createTestChangeSet();

  const mockAdapter = createMockVerifierAdapter("claude", {
    executeVerification: async () => ({
      ok: true,
      overallStatus: "CLEAN",
      evaluations: [],
      verifierOmissions: []
    })
  });

  const runContext = new RunContext({
    headSha: changeSet.headSha,
    contentDigest: changeSet.contentDigest,
    patchObjective: "Protect authorization checks"
  });

  // options.patchObjective matches runContext, but options.objectiveContract conflicts!
  const record = await conductIndependentVerification(
    changeSet,
    [],
    mockAdapter,
    {
      verificationMode: "clean_challenge",
      runContext,
      patchObjective: "Protect authorization checks",
      objectiveContract: {
        objective: "Remove authorization checks"
      }
    }
  );

  assert.equal(record.ok, false, "Conflicting secondary objective must fail verification record ok");
  assert.equal(record.overallStatus, "UNCERTAIN", "Conflicting secondary objective must force overallStatus to UNCERTAIN");
  assert.match(record.error, /OBJECTIVE_MISMATCH|conflicts with authoritative RunContext/i);
});

// ============================================================================
// PHASE2-NEG-16: (P2-LOC-04) Exact-Head Failure Rejects Working Tree Fallback & Declared lineCount
// ============================================================================
test("PHASE2-NEG-16: Non-existent Exact Head rejects working tree fallback, and unverified declared lineCount cannot grant SUPPORTED", () => {
  // Scenario 1: Non-existent Head SHA cannot fall back to working tree lines
  const changeSetNonExistentHead = createTestChangeSet({
    headSha: "0000000000000000000000000000000000000001",
    files: [{ path: "src/core/independent-verifier.mjs", additions: 5, deletions: 0 }]
  });

  const omissionOnNonExistentHead = {
    title: "SQL injection on non-existent commit",
    file: "src/core/independent-verifier.mjs",
    line_start: 500, // Valid in working tree (~2900 lines), but commit does not exist!
    line_end: 510,
    locatorAccurate: true,
    severity: "high",
    evidenceSupport: "SUPPORTED",
    reasoning: "Executing query without parameterization causes database corruption",
    counterexample: "query('SELECT * FROM users WHERE id = ' + input) -> SQL injection"
  };

  const res1 = validateVerificationOutput(
    { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [omissionOnNonExistentHead] },
    { changeSet: changeSetNonExistentHead, headSha: changeSetNonExistentHead.headSha }
  );

  assert.ok(res1.ok);
  assert.equal(res1.verifierOmissions[0].locatorAccurate, false, "Non-existent headSha must not fall back to working tree");
  assert.equal(res1.verifierOmissions[0].evidenceSupport, "INSUFFICIENT_EVIDENCE", "Unverifiable headSha must downgrade SUPPORTED to INSUFFICIENT_EVIDENCE");

  // Scenario 2: Unverified declared lineCount on missing file cannot substantiate line 9,999,999
  const changeSetDeclaredLines = createTestChangeSet({
    files: [{ path: "src/unreadable-synthetic-file.mjs", lineCount: 10000000, additions: 2, deletions: 0 }]
  });

  const omissionOnDeclaredLines = {
    title: "Heap overflow on extreme line",
    file: "src/unreadable-synthetic-file.mjs",
    line_start: 9999999,
    line_end: 10000005,
    locatorAccurate: true,
    severity: "critical",
    evidenceSupport: "SUPPORTED",
    reasoning: "Executing bufferCopy on line 9999999 causes heap corruption crash",
    counterexample: "bufferCopy(null) -> SIGSEGV crash"
  };

  const res2 = validateVerificationOutput(
    { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [omissionOnDeclaredLines] },
    { changeSet: changeSetDeclaredLines }
  );

  assert.ok(res2.ok);
  assert.equal(res2.verifierOmissions[0].locatorAccurate, false, "Declared lineCount cannot verify lines outside physical evidence");
  assert.equal(res2.verifierOmissions[0].evidenceSupport, "INSUFFICIENT_EVIDENCE", "Unverified lineCount must downgrade SUPPORTED to INSUFFICIENT_EVIDENCE");
});

// ============================================================================
// PHASE2-NEG-17: (P2-LOC-05) Invalid Exact Head Cannot Use ChangeSet Additions or Hunks as Source Basis
// ============================================================================
test("PHASE2-NEG-17: Invalid Exact Head cannot use unverified ChangeSet additions or diff hunks to grant SUPPORTED", () => {
  // Scenario 1: Invalid Exact Head with declared additions=100000 targeting line 5000
  const changeSetDeclaredAdditions = createTestChangeSet({
    headSha: "0000000000000000000000000000000000000002",
    files: [{ path: "src/core/independent-verifier.mjs", additions: 100000, deletions: 0 }],
    diffHunks: "" // No hunks, only declared additions metadata
  });

  const omissionOnDeclaredAdditions = {
    title: "SQL injection with unverified additions on non-existent commit",
    file: "src/core/independent-verifier.mjs",
    line_start: 5000,
    line_end: 5010,
    locatorAccurate: true,
    severity: "high",
    evidenceSupport: "SUPPORTED",
    reasoning: "Executing query without parameterization causes database corruption",
    counterexample: "query('SELECT * FROM users WHERE id = ' + input) -> SQL injection"
  };

  const res1 = validateVerificationOutput(
    { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [omissionOnDeclaredAdditions] },
    { changeSet: changeSetDeclaredAdditions, headSha: changeSetDeclaredAdditions.headSha }
  );

  assert.ok(res1.ok);
  assert.equal(res1.verifierOmissions[0].locatorAccurate, false, "Invalid Exact Head must reject additions-based line verification");
  assert.equal(res1.verifierOmissions[0].evidenceSupport, "INSUFFICIENT_EVIDENCE", "Invalid Exact Head must downgrade additions-based omission to INSUFFICIENT_EVIDENCE");

  // Scenario 2: Invalid Exact Head with fabricated hunk @@ -1 +5000,2 @@ targeting line 5000
  const changeSetFabricatedHunk = createTestChangeSet({
    headSha: "0000000000000000000000000000000000000002",
    files: [{ path: "src/core/independent-verifier.mjs", additions: 2, deletions: 0 }],
    diffHunks: `diff --git a/src/core/independent-verifier.mjs b/src/core/independent-verifier.mjs
index 1111111..2222222 100644
--- a/src/core/independent-verifier.mjs
+++ b/src/core/independent-verifier.mjs
@@ -1 +5000,2 @@
+const forgedLine1 = 1;
+const forgedLine2 = 2;
`
  });

  const omissionOnFabricatedHunk = {
    title: "SQL injection with fabricated hunk on non-existent commit",
    file: "src/core/independent-verifier.mjs",
    line_start: 5000,
    line_end: 5001,
    locatorAccurate: true,
    severity: "high",
    evidenceSupport: "SUPPORTED",
    reasoning: "Executing query without parameterization causes database corruption",
    counterexample: "query('SELECT * FROM users WHERE id = ' + input) -> SQL injection"
  };

  const res2 = validateVerificationOutput(
    { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [omissionOnFabricatedHunk] },
    { changeSet: changeSetFabricatedHunk, headSha: changeSetFabricatedHunk.headSha }
  );

  assert.ok(res2.ok);
  assert.equal(res2.verifierOmissions[0].locatorAccurate, false, "Invalid Exact Head must reject diff hunk line verification when head is unverified");
  assert.equal(res2.verifierOmissions[0].evidenceSupport, "INSUFFICIENT_EVIDENCE", "Invalid Exact Head must downgrade diff hunk omission to INSUFFICIENT_EVIDENCE");
});

// ============================================================================
// PHASE2-NEG-18: (P2-LOC-06) Diff Hunk Provenance Verification & Unverified Hunk Rejection
// ============================================================================
test("PHASE2-NEG-18: Diff hunk provenance strictly verified against authentic Git/disk/manifest backing", () => {
  // Scenario 1: Valid Commit SHA on real repo, but target file does not exist in commit or on disk.
  // External changeSet declares fabricated diff hunk targeting line 5000 -> must NOT allow locator to become accurate or omission to become SUPPORTED.
  const validHeadSha = currentRepoHeadSha;
  const changeSetFabricatedFileOnRealRepo = createTestChangeSet({
    repository: { root: process.cwd() },
    headSha: validHeadSha,
    files: [{ path: "src/__does_not_exist__/fabricated_target.mjs", additions: 2, deletions: 0 }],
    diffHunks: `diff --git a/src/__does_not_exist__/fabricated_target.mjs b/src/__does_not_exist__/fabricated_target.mjs
index 1111111..2222222 100644
--- a/src/__does_not_exist__/fabricated_target.mjs
+++ b/src/__does_not_exist__/fabricated_target.mjs
@@ -1 +5000,2 @@
+const fabricatedLine1 = 1;
+const fabricatedLine2 = 2;
`
  });

  const omissionScenario1 = {
    title: "SQL injection on fabricated non-existent file",
    file: "src/__does_not_exist__/fabricated_target.mjs",
    line_start: 5000,
    line_end: 5001,
    locatorAccurate: true,
    severity: "high",
    evidenceSupport: "SUPPORTED",
    reasoning: "Executing query without parameterization causes database corruption",
    counterexample: "query('SELECT * FROM users WHERE id = ' + input) -> SQL injection"
  };

  const res1 = validateVerificationOutput(
    { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [omissionScenario1] },
    { changeSet: changeSetFabricatedFileOnRealRepo, headSha: validHeadSha }
  );

  assert.ok(res1.ok);
  assert.equal(res1.verifierOmissions[0].locatorAccurate, false, "Fabricated diff hunk on non-existent file must reject locator accuracy");
  assert.equal(res1.verifierOmissions[0].evidenceSupport, "INSUFFICIENT_EVIDENCE", "Fabricated diff hunk on non-existent file must downgrade to INSUFFICIENT_EVIDENCE");

  // Scenario 2: No Git Repository (!isGitRepo), but exact head is specified and diff is self-declared
  // -> must NOT obtain source verification.
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-p2-neg18-"));
  try {
    const changeSetNoGitRepo = {
      repository: { root: tempDir },
      headSha: validHeadSha,
      files: [{ path: "src/mock-unverified-file.mjs", additions: 2, deletions: 0 }],
      diffHunks: `diff --git a/src/mock-unverified-file.mjs b/src/mock-unverified-file.mjs
index 1111111..2222222 100644
--- a/src/mock-unverified-file.mjs
+++ b/src/mock-unverified-file.mjs
@@ -1 +5000,2 @@
+const forgedLine1 = 1;
+const forgedLine2 = 2;
`
    };

    const omissionScenario2 = {
      title: "Vulnerability in unverified diff hunk on non-git repo",
      file: "src/mock-unverified-file.mjs",
      line_start: 5000,
      line_end: 5001,
      locatorAccurate: true,
      severity: "high",
      evidenceSupport: "SUPPORTED",
      reasoning: "Executing query without parameterization causes database corruption",
      counterexample: "query('SELECT * FROM users WHERE id = ' + input) -> SQL injection"
    };

    const res2 = validateVerificationOutput(
      { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [omissionScenario2] },
      { changeSet: changeSetNoGitRepo, headSha: validHeadSha }
    );

    assert.ok(res2.ok);
    assert.equal(res2.verifierOmissions[0].locatorAccurate, false, "Exact head in non-git directory without verified manifest must reject locator accuracy");
    assert.equal(res2.verifierOmissions[0].evidenceSupport, "INSUFFICIENT_EVIDENCE", "Self-declared diff on non-git directory without manifest must downgrade to INSUFFICIENT_EVIDENCE");
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }

  // Scenario 3: Legitimate newly added file positive scenario: substantiated via authentic working tree (file on disk) or committed exact-head Git source, avoiding False Hold.
  // 3A: Committed exact-head Git source
  const changeSetPositiveCommitted = createTestChangeSet({
    repository: { root: process.cwd() },
    headSha: validHeadSha,
    files: [{ path: "package.json", additions: 5, deletions: 0 }]
  });

  const omissionPositiveCommitted = {
    title: "Vulnerability in committed package.json",
    file: "package.json",
    line_start: 2,
    line_end: 4,
    locatorAccurate: true,
    severity: "high",
    evidenceSupport: "SUPPORTED",
    reasoning: "Malformed configuration block causes unhandled rejection",
    counterexample: "loadConfig(null) -> throws UnhandledPromiseRejection"
  };

  const res3A = validateVerificationOutput(
    { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [omissionPositiveCommitted] },
    { changeSet: changeSetPositiveCommitted, headSha: validHeadSha }
  );

  assert.ok(res3A.ok);
  assert.equal(res3A.verifierOmissions[0].locatorAccurate, true, "Committed file at exact head must establish accurate locator");
  assert.equal(res3A.verifierOmissions[0].evidenceSupport, "SUPPORTED", "Committed file at exact head must preserve SUPPORTED without false hold");

  // 3B: Working tree file substantiated on disk
  const tempFixtureFile = path.resolve(process.cwd(), "tests/fixtures/__temp_p2_neg18_working_tree__.mjs");
  fs.writeFileSync(tempFixtureFile, "const line1 = 1;\nconst line2 = 2;\nconst line3 = 3;\nconst line4 = 4;\nconst line5 = 5;\n");
  try {
    const changeSetPositiveWorkingTree = {
      repository: { root: process.cwd() },
      scopeMode: "working-tree",
      files: [{ path: "tests/fixtures/__temp_p2_neg18_working_tree__.mjs", additions: 5, deletions: 0 }]
    };

    const omissionPositiveWorkingTree = {
      title: "Vulnerability in authentic working tree file",
      file: "tests/fixtures/__temp_p2_neg18_working_tree__.mjs",
      line_start: 2,
      line_end: 4,
      locatorAccurate: true,
      severity: "high",
      evidenceSupport: "SUPPORTED",
      reasoning: "Evaluating untrusted token causes denial of service crash",
      counterexample: "verifyToken('invalid') -> throws SIGTERM"
    };

    const res3B = validateVerificationOutput(
      { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [omissionPositiveWorkingTree] },
      { changeSet: changeSetPositiveWorkingTree, scopeMode: "working-tree" }
    );

    assert.ok(res3B.ok);
    assert.equal(res3B.verifierOmissions[0].locatorAccurate, true, "Authentic working tree file on disk must establish accurate locator");
    assert.equal(res3B.verifierOmissions[0].evidenceSupport, "SUPPORTED", "Authentic working tree file on disk must preserve SUPPORTED without false hold");
  } finally {
    fs.rmSync(tempFixtureFile, { force: true });
  }
});

// ============================================================================
// PHASE2-NEG-19: (P2-LOC-07) Manifest Authority Provenance & Unverified Manifest Rejection
// ============================================================================
test("PHASE2-NEG-19: Unverified self-declared manifests in non-git directory cannot grant source locator authority or SUPPORTED omission", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-p2-neg19-"));
  try {
    const fictionalHead = "0000000000000000000000000000000000000001";
    const fabricatedDiff = `diff --git a/src/mock.mjs b/src/mock.mjs
index 1111111..2222222 100644
--- a/src/mock.mjs
+++ b/src/mock.mjs
@@ -1 +5000,2 @@
+const fabricatedLine1 = 1;
+const fabricatedLine2 = 2;
`;
    const fabricatedOmission = {
      title: "Arbitrary flaw in unverified manifest",
      file: "src/mock.mjs",
      line_start: 5000,
      line_end: 5001,
      locatorAccurate: true,
      severity: "high",
      evidenceSupport: "SUPPORTED",
      reasoning: "Executing buffer allocation causes out-of-bounds write crash",
      counterexample: "allocBuffer(5000) -> SIGSEGV crash"
    };

    // Scenario 1: Non-Git directory (!isGitRepo), fictional Head SHA, fabricated Diff Hunk,
    // with self-declared manifest claiming { file: "src/mock.mjs", exactHeadAvailable: true }
    // -> must NOT allow locator to become accurate or omission to achieve SUPPORTED.
    const changeSetScenario1 = {
      repository: { root: tempDir },
      headSha: fictionalHead,
      files: [{ path: "src/mock.mjs", additions: 2, deletions: 0 }],
      diffHunks: fabricatedDiff,
      contextPackage: {
        fileCoverageManifest: [
          { file: "src/mock.mjs", exactHeadAvailable: true }
        ]
      }
    };

    const res1 = validateVerificationOutput(
      { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [fabricatedOmission] },
      { changeSet: changeSetScenario1, headSha: fictionalHead }
    );

    assert.ok(res1.ok);
    assert.equal(res1.verifierOmissions[0].locatorAccurate, false, "Self-declared exactHeadAvailable manifest must reject locator accuracy");
    assert.equal(res1.verifierOmissions[0].evidenceSupport, "INSUFFICIENT_EVIDENCE", "Unverified manifest claiming exactHeadAvailable must downgrade to INSUFFICIENT_EVIDENCE");

    // Scenario 2: Same non-git environment, fictional Head SHA, fabricated Diff Hunk,
    // with manifest containing only filename and irrelevant annotation { file: "src/mock.mjs", other: "annotation" }
    // -> must NOT allow locator to become accurate or omission to achieve SUPPORTED.
    const changeSetScenario2 = {
      repository: { root: tempDir },
      headSha: fictionalHead,
      files: [{ path: "src/mock.mjs", additions: 2, deletions: 0 }],
      diffHunks: fabricatedDiff,
      contextPackage: {
        fileCoverageManifest: [
          { file: "src/mock.mjs", other: "annotation" }
        ]
      }
    };

    const res2 = validateVerificationOutput(
      { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [fabricatedOmission] },
      { changeSet: changeSetScenario2, headSha: fictionalHead }
    );

    assert.ok(res2.ok);
    assert.equal(res2.verifierOmissions[0].locatorAccurate, false, "Manifest containing only irrelevant annotation must reject locator accuracy");
    assert.equal(res2.verifierOmissions[0].evidenceSupport, "INSUFFICIENT_EVIDENCE", "Manifest with only irrelevant annotation must downgrade to INSUFFICIENT_EVIDENCE");

    // Positive Control: Legitimate synthetic test with explicit allowSynthetic authorization,
    // bound Head SHA, matching diff digest, and complete schema can achieve SUPPORTED within bounds.
    const computedDigest = crypto.createHash("sha256").update(fabricatedDiff).digest("hex");
    const changeSetPositiveSynthetic = {
      repository: { root: tempDir },
      headSha: fictionalHead,
      files: [{ path: "src/mock.mjs", additions: 2, deletions: 0 }],
      diffHunks: fabricatedDiff,
      allowSynthetic: true,
      contextPackage: {
        schemaVersion: "1.0.0",
        headSha: fictionalHead,
        contentDigest: computedDigest,
        fileCoverageManifest: [
          {
            file: "src/mock.mjs",
            inspected: true,
            exactHeadAvailable: true,
            calleesExtracted: []
          }
        ]
      }
    };

    const resPositive = validateSyntheticVerificationOutput(
      { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [fabricatedOmission] },
      { changeSet: changeSetPositiveSynthetic, headSha: fictionalHead }
    );

    assert.ok(resPositive.ok);
    assert.equal(resPositive.verifierOmissions[0].locatorAccurate, true, "Authorized synthetic test with cryptographically bound manifest must establish accurate locator");
    assert.equal(resPositive.verifierOmissions[0].evidenceSupport, "SUPPORTED", "Authorized synthetic test must preserve SUPPORTED without false hold");
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

// ============================================================================
// PHASE2-NEG-20: (P2-CAP-01) Formal verifier validateVerificationOutput ignores caller-injected allowSynthetic fields
// ============================================================================
test("PHASE2-NEG-20: Formal verifier validateVerificationOutput strictly ignores caller-injected allowSynthetic fields and fails closed", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-p2-neg20-"));
  try {
    const fictionalHead = "0000000000000000000000000000000000000002";
    const fabricatedDiff = `diff --git a/src/mock.mjs b/src/mock.mjs
index 1111111..2222222 100644
--- a/src/mock.mjs
+++ b/src/mock.mjs
@@ -1 +5000,2 @@
+const fabricatedLine1 = 1;
+const fabricatedLine2 = 2;
`;
    const fabricatedOmission = {
      title: "Arbitrary flaw in unverified manifest",
      file: "src/mock.mjs",
      line_start: 5000,
      line_end: 5001,
      locatorAccurate: true,
      severity: "high",
      evidenceSupport: "SUPPORTED",
      reasoning: "Executing buffer allocation causes out-of-bounds write crash",
      counterexample: "allocBuffer(5000) -> SIGSEGV crash"
    };

    const computedDigest = crypto.createHash("sha256").update(fabricatedDiff).digest("hex");
    const changeSetWithInjectedAllowSynthetic = {
      repository: { root: tempDir },
      headSha: fictionalHead,
      files: [{ path: "src/mock.mjs", additions: 2, deletions: 0 }],
      diffHunks: fabricatedDiff,
      allowSynthetic: true, // Caller attempts injection here
      contextPackage: {
        schemaVersion: "1.0.0",
        headSha: fictionalHead,
        contentDigest: computedDigest,
        fileCoverageManifest: [
          {
            file: "src/mock.mjs",
            inspected: true,
            exactHeadAvailable: true,
            calleesExtracted: []
          }
        ]
      }
    };

    // 1. Formal validateVerificationOutput must strictly ignore context.allowSynthetic and changeSet.allowSynthetic
    const formalResult = validateVerificationOutput(
      { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [fabricatedOmission] },
      { changeSet: changeSetWithInjectedAllowSynthetic, headSha: fictionalHead, allowSynthetic: true, options: { allowSynthetic: true } }
    );

    assert.ok(formalResult.ok);
    assert.equal(formalResult.verifierOmissions[0].locatorAccurate, false, "Formal verifier must ignore caller-injected allowSynthetic and reject locator accuracy");
    assert.equal(formalResult.verifierOmissions[0].evidenceSupport, "INSUFFICIENT_EVIDENCE", "Formal verifier must downgrade unverified manifest omission to INSUFFICIENT_EVIDENCE");

    // 2. Positive Control: Segregated validateSyntheticVerificationOutput dedicated entry point preserves synthetic test capability
    const syntheticResult = validateSyntheticVerificationOutput(
      { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [fabricatedOmission] },
      { changeSet: changeSetWithInjectedAllowSynthetic, headSha: fictionalHead }
    );

    assert.ok(syntheticResult.ok);
    assert.equal(syntheticResult.verifierOmissions[0].locatorAccurate, true, "Segregated synthetic entrypoint must accept authorized synthetic payload");
    assert.equal(syntheticResult.verifierOmissions[0].evidenceSupport, "SUPPORTED", "Segregated synthetic entrypoint must preserve SUPPORTED status");
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

// ============================================================================
// PHASE2-NEG-21: (P2-CAP-02) Arbitrary registration of untrusted context packages rejected without Git backing or workflow evidence
// ============================================================================
test("PHASE2-NEG-21: Arbitrary registration of untrusted context packages rejected without Git backing or workflow evidence", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-p2-neg21-"));
  try {
    const fakeHead = "0000000000000000000000000000000000000003";
    const fakeDiff = `diff --git a/src/fake.mjs b/src/fake.mjs
index 1111111..2222222 100644
--- a/src/fake.mjs
+++ b/src/fake.mjs
@@ -1 +200,2 @@
+const line1 = 1;
+const line2 = 2;
`;
    const fakeDigest = crypto.createHash("sha256").update(fakeDiff).digest("hex");
    const fakePkg = {
      schemaVersion: "1.0.0",
      headSha: fakeHead,
      contentDigest: fakeDigest,
      layers: { layer0Diff: fakeDiff },
      budgetAccounting: { consumedBytes: 100 },
      fileCoverageManifest: [
        {
          file: "src/fake.mjs",
          inspected: true,
          exactHeadAvailable: true,
          calleesExtracted: []
        }
      ]
    };

    // 1. Direct registration of unverified package without authentic evidence must be rejected
    const regResultNoEvidence = registerTrustedContextPackage(fakePkg);
    assert.equal(regResultNoEvidence, null, "registerTrustedContextPackage without evidence must return null");
    assert.equal(isTrustedContextPackage(fakePkg), false, "unverified package must not be in trusted registry");

    // 2. Direct registration with non-git repo root must be rejected
    const regResultNonGit = registerTrustedContextPackage(fakePkg, { repositoryRoot: tempDir, headSha: fakeHead });
    assert.equal(regResultNonGit, null, "registerTrustedContextPackage with non-git repositoryRoot must return null");
    assert.equal(isTrustedContextPackage(fakePkg), false, "package with non-git repositoryRoot must not be in trusted registry");

    // 3. Passing unverified package to formal validateVerificationOutput fails closed
    const changeSetWithFakePkg = {
      repository: { root: tempDir },
      headSha: fakeHead,
      files: [{ path: "src/fake.mjs", additions: 2, deletions: 0 }],
      diffHunks: fakeDiff,
      contextPackage: fakePkg
    };
    const fabricatedOmission = {
      title: "Arbitrary flaw with unverified package",
      file: "src/fake.mjs",
      line_start: 200,
      line_end: 201,
      locatorAccurate: true,
      severity: "high",
      evidenceSupport: "SUPPORTED",
      reasoning: "Out-of-bounds pointer dereference causes memory corruption",
      counterexample: "deref(200) -> SIGSEGV crash"
    };

    const resUnverified = validateVerificationOutput(
      { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [fabricatedOmission] },
      { changeSet: changeSetWithFakePkg, headSha: fakeHead }
    );
    assert.ok(resUnverified.ok);
    assert.equal(resUnverified.verifierOmissions[0].locatorAccurate, false, "Unverified package must fail closed on locator accuracy");
    assert.equal(resUnverified.verifierOmissions[0].evidenceSupport, "INSUFFICIENT_EVIDENCE", "Unverified package must downgrade to INSUFFICIENT_EVIDENCE");

    // 4. Positive Control: Authentic package backed by real Git repository and committed files
    const realRepoRoot = process.cwd();
    const realHeadSha = currentRepoHeadSha;
    const realFile = "src/core/independent-verifier.mjs";
    const validGitPkg = {
      schemaVersion: "1.0.0",
      headSha: realHeadSha,
      repositoryRoot: realRepoRoot,
      contentDigest: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
      layers: { layer0Diff: "" },
      budgetAccounting: { consumedBytes: 50 },
      fileCoverageManifest: [
        {
          file: realFile,
          inspected: true,
          exactHeadAvailable: true,
          calleesExtracted: []
        }
      ]
    };

    const regGitSuccess = registerTrustedContextPackage(validGitPkg, {
      repositoryRoot: realRepoRoot,
      headSha: realHeadSha
    });
    assert.equal(regGitSuccess, validGitPkg, "Authentic Git-backed package must successfully register");
    assert.equal(isTrustedContextPackage(validGitPkg), true, "Authentic Git-backed package must be trusted");

    // 5. Positive Control: Authentic review workflow evidence produced by Context Builder
    const workflowDiff = `diff --git a/${realFile} b/${realFile}
index 1111111..2222222 100644
--- a/${realFile}
+++ b/${realFile}
@@ -100,6 +100,10 @@
+const testAdd = 1;
`;
    const workflowChangeSet = {
      headSha: realHeadSha,
      files: [{ path: realFile, additions: 1, deletions: 0 }],
      diffHunks: workflowDiff,
      repository: { root: realRepoRoot }
    };
    const validWorkflowPkg = buildContextPackage(workflowChangeSet, null, {
      repositoryRoot: realRepoRoot,
      headSha: realHeadSha
    });
    assert.ok(validWorkflowPkg, "Context builder produces valid package");
    assert.equal(isTrustedContextPackage(validWorkflowPkg), true, "Package produced by authentic review workflow must be trusted");
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

// ============================================================================
// PHASE2-NEG-22: (P2-CAP-03) Arbitrary caller cannot gain Registry trust solely via verifiedBy string and diff digest
// ============================================================================
test("PHASE2-NEG-22: Arbitrary caller cannot gain Registry trust solely via verifiedBy string and self-generated diff digest", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-p2-neg22-"));
  try {
    const fakeHead = "0000000000000000000000000000000000000004";
    const fakeDiff = `diff --git a/src/spoofed.mjs b/src/spoofed.mjs
index 1111111..2222222 100644
--- a/src/spoofed.mjs
+++ b/src/spoofed.mjs
@@ -1 +5000,2 @@
+const line1 = 1;
+const line2 = 2;
`;
    const fakeDigest = crypto.createHash("sha256").update(fakeDiff).digest("hex");
    const fakePkg = {
      schemaVersion: "1.0.0",
      headSha: fakeHead,
      contentDigest: fakeDigest,
      layers: { layer0Diff: fakeDiff },
      budgetAccounting: { consumedBytes: 100 },
      fileCoverageManifest: [
        {
          file: "src/spoofed.mjs",
          inspected: true,
          exactHeadAvailable: true,
          calleesExtracted: []
        }
      ]
    };

    // 1. Calling registerTrustedContextPackage with self-attested verifiedBy: "dogfood-review"
    // in a non-git directory without authentic physical Git backing or authentic workflow token
    // MUST be rejected (returns null) and MUST NOT be trusted in registry (P2-CAP-03).
    const regSpoofedDogfood = registerTrustedContextPackage(fakePkg, {
      verifiedBy: "dogfood-review",
      diffHunks: fakeDiff
    });
    assert.equal(regSpoofedDogfood, null, "Self-attested verifiedBy: 'dogfood-review' must return null without Git backing or authority token");
    assert.equal(isTrustedContextPackage(fakePkg), false, "Self-attested package must not gain Registry trust");

    // 2. Calling with other valid workflow names ("context-builder", "staged-review") also rejected
    const regSpoofedContextBuilder = registerTrustedContextPackage(fakePkg, {
      verifiedBy: "context-builder",
      diffHunks: fakeDiff
    });
    assert.equal(regSpoofedContextBuilder, null, "Self-attested verifiedBy: 'context-builder' must return null");
    assert.equal(isTrustedContextPackage(fakePkg), false);

    const regSpoofedStagedReview = registerTrustedContextPackage(fakePkg, {
      verifiedBy: "staged-review",
      diffHunks: fakeDiff
    });
    assert.equal(regSpoofedStagedReview, null, "Self-attested verifiedBy: 'staged-review' must return null");
    assert.equal(isTrustedContextPackage(fakePkg), false);

    // 3. Passing the self-attested package to formal validateVerificationOutput fails closed:
    // locatorAccurate is false, and omission downgrades to INSUFFICIENT_EVIDENCE
    const fabricatedOmission = {
      title: "Arbitrary flaw with spoofed workflow package",
      file: "src/spoofed.mjs",
      line_start: 5000,
      line_end: 5001,
      locatorAccurate: true,
      severity: "high",
      evidenceSupport: "SUPPORTED",
      reasoning: "Buffer overflow vulnerability on mock execution path",
      counterexample: "alloc(5000) -> crash"
    };

    const changeSetWithSpoofedPkg = {
      repository: { root: tempDir },
      headSha: fakeHead,
      files: [{ path: "src/spoofed.mjs", additions: 2, deletions: 0 }],
      diffHunks: fakeDiff,
      contextPackage: fakePkg
    };

    const formalResult = validateVerificationOutput(
      { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [fabricatedOmission] },
      { changeSet: changeSetWithSpoofedPkg, headSha: fakeHead }
    );

    assert.ok(formalResult.ok);
    assert.equal(formalResult.verifierOmissions[0].locatorAccurate, false, "Formal verifier must reject locator accuracy for self-attested package");
    assert.equal(formalResult.verifierOmissions[0].evidenceSupport, "INSUFFICIENT_EVIDENCE", "Formal verifier must downgrade self-attested omission to INSUFFICIENT_EVIDENCE");
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

// ============================================================================
// PHASE2-NEG-23: (P2-CAP-04) Public mintWorkflowAuthorityToken cannot be used by arbitrary external callers to forge Registry trust or promote fabricated omissions
// ============================================================================
test("PHASE2-NEG-23: Arbitrary external caller cannot use mintWorkflowAuthorityToken to forge Registry trust or promote fabricated omissions", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-p2-neg23-"));
  try {
    const fakeHead = "0000000000000000000000000000000000000005";
    const fakeDiff = `diff --git a/src/spoofed2.mjs b/src/spoofed2.mjs
index 1111111..2222222 100644
--- a/src/spoofed2.mjs
+++ b/src/spoofed2.mjs
@@ -1 +5000,2 @@
+const line1 = 1;
+const line2 = 2;
`;
    const fakeDigest = crypto.createHash("sha256").update(fakeDiff).digest("hex");
    const fakePkg = {
      schemaVersion: "1.0.0",
      headSha: fakeHead,
      contentDigest: fakeDigest,
      layers: { layer0Diff: fakeDiff },
      budgetAccounting: { consumedBytes: 100 },
      fileCoverageManifest: [
        {
          file: "src/spoofed2.mjs",
          inspected: true,
          exactHeadAvailable: true,
          calleesExtracted: []
        }
      ]
    };

    // 1. External caller invokes public mintWorkflowAuthorityToken for recognized workflow names
    const externalDogfoodToken = mintWorkflowAuthorityToken("dogfood-review");
    assert.ok(externalDogfoodToken, "Public minter returns a token object");
    assert.equal(externalDogfoodToken.workflow, "dogfood-review");
    assert.equal(externalDogfoodToken.isInternal, false, "Token minted by external caller must have isInternal: false");

    // 2. Calling registerTrustedContextPackage with token minted by external caller
    // MUST NOT grant Registry trust (returns null)
    const regSpoofedWithToken = registerTrustedContextPackage(fakePkg, {
      repositoryRoot: tempDir,
      headSha: fakeHead,
      diffHunks: fakeDiff,
      verifiedBy: "dogfood-review",
      workflowAuthority: externalDogfoodToken
    });
    assert.equal(regSpoofedWithToken, null, "External caller token must not grant Registry trust");
    assert.equal(isTrustedContextPackage(fakePkg), false, "Fabricated package must not be trusted in registry");

    // 3. Same check for other workflows ("context-builder", "staged-review")
    const externalBuilderToken = mintWorkflowAuthorityToken("context-builder");
    assert.equal(externalBuilderToken.isInternal, false);
    assert.equal(registerTrustedContextPackage(fakePkg, {
      repositoryRoot: tempDir,
      headSha: fakeHead,
      diffHunks: fakeDiff,
      verifiedBy: "context-builder",
      workflowAuthority: externalBuilderToken
    }), null);
    assert.equal(isTrustedContextPackage(fakePkg), false);

    const externalStagedToken = mintWorkflowAuthorityToken("staged-review");
    assert.equal(externalStagedToken.isInternal, false);
    assert.equal(registerTrustedContextPackage(fakePkg, {
      repositoryRoot: tempDir,
      headSha: fakeHead,
      diffHunks: fakeDiff,
      verifiedBy: "staged-review",
      workflowAuthority: externalStagedToken
    }), null);
    assert.equal(isTrustedContextPackage(fakePkg), false);

    // 4. Formal verifier validateVerificationOutput cannot promote omission to SUPPORTED
    const fabricatedOmission = {
      title: "Arbitrary flaw with externally minted token",
      file: "src/spoofed2.mjs",
      line_start: 5000,
      line_end: 5001,
      locatorAccurate: true,
      severity: "high",
      evidenceSupport: "SUPPORTED",
      reasoning: "Arbitrary code execution on unverified path",
      counterexample: "crash(5000)"
    };

    const changeSetWithSpoofedPkg = {
      repository: { root: tempDir },
      headSha: fakeHead,
      files: [{ path: "src/spoofed2.mjs", additions: 2, deletions: 0 }],
      diffHunks: fakeDiff,
      contextPackage: fakePkg
    };

    const formalResult = validateVerificationOutput(
      { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [fabricatedOmission] },
      { changeSet: changeSetWithSpoofedPkg, headSha: fakeHead }
    );

    assert.ok(formalResult.ok);
    assert.equal(formalResult.verifierOmissions[0].locatorAccurate, false, "Formal verifier must reject locator accuracy for externally minted token");
    assert.equal(formalResult.verifierOmissions[0].evidenceSupport, "INSUFFICIENT_EVIDENCE", "Formal verifier must downgrade omission to INSUFFICIENT_EVIDENCE");
    assert.notEqual(formalResult.verifierOmissions[0].evidenceSupport, "SUPPORTED");
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

// ============================================================================
// PHASE2-NEG-24: (P2-CAP-05) External module with identical relative path (src/core/context-builder.mjs) cannot forge internal authority or promote fabricated context to SUPPORTED
// ============================================================================
test("PHASE2-NEG-24: External module with identical relative path (src/core/context-builder.mjs) cannot forge internal authority or promote fabricated context to SUPPORTED", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-p2-neg24-"));
  try {
    const fakeHead = "0000000000000000000000000000000000000006";
    const fakeDiff = `diff --git a/src/spoofed_p2_cap05.mjs b/src/spoofed_p2_cap05.mjs
index 1111111..2222222 100644
--- a/src/spoofed_p2_cap05.mjs
+++ b/src/spoofed_p2_cap05.mjs
@@ -1 +5000,2 @@
+const forgedLine1 = 1;
+const forgedLine2 = 2;
`;
    const fakeDigest = crypto.createHash("sha256").update(fakeDiff).digest("hex");
    const fakePkg = {
      schemaVersion: "1.0.0",
      headSha: fakeHead,
      contentDigest: fakeDigest,
      layers: { layer0Diff: fakeDiff },
      budgetAccounting: { consumedBytes: 100 },
      fileCoverageManifest: [
        {
          file: "src/spoofed_p2_cap05.mjs",
          inspected: true,
          exactHeadAvailable: true,
          calleesExtracted: []
        }
      ]
    };

    // 1. Create directory structure outside the project with matching relative path: <tempDir>/src/core/context-builder.mjs
    const spoofedCoreDir = path.join(tempDir, "src", "core");
    fs.mkdirSync(spoofedCoreDir, { recursive: true });
    const spoofedScriptPath = path.join(spoofedCoreDir, "context-builder.mjs");

    const realVerifierPath = path.resolve(process.cwd(), "src", "core", "independent-verifier.mjs");
    const realVerifierUrl = pathToFileURL(realVerifierPath).href;

    // 2. Write external module that imports public mintWorkflowAuthorityToken and registerTrustedContextPackage
    // from Triad-Flow's genuine independent-verifier.mjs
    const externalModuleCode = `
import {
  mintWorkflowAuthorityToken,
  registerTrustedContextPackage,
  isWorkflowAuthorityToken,
  isTrustedContextPackage,
  validateVerificationOutput
} from "${realVerifierUrl}";

export async function runSpoofProbe(fakePkg, fakeDiff, fakeHead, repoRoot) {
  // A. Attempt to mint authority token for 'context-builder' from identical relative path / filename
  const token = mintWorkflowAuthorityToken("context-builder", {
    contentDigest: fakePkg.contentDigest,
    headSha: fakeHead
  });

  // B. Attempt to register package in Trusted Registry using the minted token
  const regResult = registerTrustedContextPackage(fakePkg, {
    repositoryRoot: repoRoot,
    headSha: fakeHead,
    diffHunks: fakeDiff,
    verifiedBy: "context-builder",
    workflowAuthority: token
  });

  const isTrusted = isTrustedContextPackage(fakePkg);
  const isTokenValid = isWorkflowAuthorityToken(token, fakePkg);

  // C. Attempt to validate verification output with fabricated omission
  const fabricatedOmission = {
    title: "Arbitrary flaw spoofed from external context-builder.mjs",
    file: "src/spoofed_p2_cap05.mjs",
    line_start: 5000,
    line_end: 5001,
    locatorAccurate: true,
    severity: "high",
    evidenceSupport: "SUPPORTED",
    reasoning: "Arbitrary code execution on unverified path",
    counterexample: "crash(5000)"
  };

  const changeSet = {
    repository: { root: repoRoot },
    headSha: fakeHead,
    files: [{ path: "src/spoofed_p2_cap05.mjs", additions: 2, deletions: 0 }],
    diffHunks: fakeDiff,
    contextPackage: fakePkg
  };

  const formalResult = validateVerificationOutput(
    { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [fabricatedOmission] },
    { changeSet, headSha: fakeHead }
  );

  return {
    token,
    isTokenValid,
    regResult,
    isTrusted,
    formalResult
  };
}
`;
    fs.writeFileSync(spoofedScriptPath, externalModuleCode, "utf8");

    // 3. Dynamically import the external spoofed module and execute probe
    const spoofedModuleUrl = pathToFileURL(spoofedScriptPath).href;
    const { runSpoofProbe } = await import(spoofedModuleUrl);
    const probeResult = await runSpoofProbe(fakePkg, fakeDiff, fakeHead, tempDir);

    // Negative Assertions:
    assert.ok(probeResult.token, "External module received a token object");
    assert.equal(probeResult.token.workflow, "context-builder");
    assert.equal(probeResult.token.isInternal, false, "External module with identical relative path MUST NOT receive isInternal: true");
    assert.equal(probeResult.isTokenValid, false, "Token minted by external module must not pass isWorkflowAuthorityToken");
    assert.equal(probeResult.regResult, null, "External module must not be able to register trusted context package (returns null)");
    assert.equal(probeResult.isTrusted, false, "Package registered by external module must not be trusted in registry");

    assert.ok(probeResult.formalResult.ok);
    assert.equal(probeResult.formalResult.verifierOmissions[0].locatorAccurate, false, "Formal verifier must reject locator accuracy for externally spoofed context");
    assert.equal(probeResult.formalResult.verifierOmissions[0].evidenceSupport, "INSUFFICIENT_EVIDENCE", "Formal verifier must downgrade omission from spoofed module to INSUFFICIENT_EVIDENCE");
    assert.notEqual(probeResult.formalResult.verifierOmissions[0].evidenceSupport, "SUPPORTED");

    // 4. Positive Controls: Authentic Context Builder & Dogfood Review retain authority and avoid False Holds
    const genuineChangeSet = createTestChangeSet();
    const authenticPkg = buildContextPackage(genuineChangeSet, null, {
      repositoryRoot: process.cwd()
    });
    assert.ok(authenticPkg, "Genuine Context Builder produces valid package");
    assert.equal(isTrustedContextPackage(authenticPkg), true, "Authentic Context Builder package MUST have Registry trust");

    const authenticOmission = {
      title: "Legitimate flaw verified against authentic context",
      file: "src/core/independent-verifier.mjs",
      line_start: 100,
      line_end: 110,
      locatorAccurate: true,
      severity: "high",
      evidenceSupport: "SUPPORTED",
      reasoning: "Authentic counterexample on verified path in physical repository",
      counterexample: "reproduce(100)"
    };
    const authenticChangeSet = {
      ...genuineChangeSet,
      contextPackage: authenticPkg
    };
    const authenticResult = validateVerificationOutput(
      { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [authenticOmission] },
      { changeSet: authenticChangeSet, headSha: genuineChangeSet.headSha }
    );
    assert.ok(authenticResult.ok);
    assert.equal(authenticResult.verifierOmissions[0].locatorAccurate, true, "Authentic package must preserve accurate locator");
    assert.equal(authenticResult.verifierOmissions[0].evidenceSupport, "SUPPORTED", "Authentic package with concrete counterexample must retain SUPPORTED (No False Hold)");
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

// ============================================================================
// PHASE2-NEG-25: (P2-CAP-06) Public buildContextPackage cannot launder authority from non-git directory with fabricated head/diff/fileContents
// ============================================================================
test("PHASE2-NEG-25: Public buildContextPackage cannot launder authority from non-git directory with fabricated head/diff/fileContents", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-p2-neg25-"));
  try {
    const fakeHead = "0000000000000000000000000000000000000007";
    const fakeFile = "src/nonexistent_auth.mjs";
    const fakeDiff = `diff --git a/${fakeFile} b/${fakeFile}
index 1111111..2222222 100644
--- a/${fakeFile}
+++ b/${fakeFile}
@@ -1 +5000,2 @@
+const forgedLine1 = 1;
+const forgedLine2 = 2;
`;
    const fakeFileContent = "const forgedLine1 = 1;\nconst forgedLine2 = 2;\n";
    const changeSet = {
      repository: { root: tempDir },
      headSha: fakeHead,
      files: [{ path: fakeFile, additions: 2, deletions: 0 }],
      diffHunks: fakeDiff
    };

    // 1. Direct call to public buildContextPackage with non-git repo, fake head, caller-supplied fileContents
    const launderedPkg = buildContextPackage(changeSet, null, {
      repositoryRoot: tempDir,
      headSha: fakeHead,
      fileContents: { [fakeFile]: fakeFileContent }
    });

    assert.ok(launderedPkg, "buildContextPackage returns context package object");
    assert.equal(launderedPkg.targetFile, fakeFile);

    // Negative Assertion 1: Must NOT be registered into Trusted Context Package Registry
    assert.equal(isTrustedContextPackage(launderedPkg), false, "Public buildContextPackage must NOT register package into Trusted Registry without authentic Git backing");

    // Negative Assertion 2: Manifest must NOT mark non-existent file as exactHeadAvailable
    assert.ok(Array.isArray(launderedPkg.fileCoverageManifest), "Package must contain fileCoverageManifest");
    const manifestEntry = launderedPkg.fileCoverageManifest.find(m => m.file === fakeFile);
    assert.ok(manifestEntry, "Manifest must include inspected file entry");
    assert.equal(manifestEntry.exactHeadAvailable, false, "Non-existent file at unverified head must have exactHeadAvailable = false");

    // Negative Assertion 3: Context gaps must record EXACT_HEAD_CONTENT_UNAVAILABLE
    assert.ok(
      launderedPkg.contextGaps.some(g => g.reason === "EXACT_HEAD_CONTENT_UNAVAILABLE" && (g.file === fakeFile || g.file === "src/nonexistent_auth.mjs")),
      "Package must record EXACT_HEAD_CONTENT_UNAVAILABLE context gap for unverified file"
    );

    // Negative Assertion 4: When evaluated by formal verifier, omission pointing to fabricated diff hunk must fail closed
    const fabricatedOmission = {
      title: "Arbitrary flaw laundered via public buildContextPackage",
      file: fakeFile,
      line_start: 5000,
      line_end: 5001,
      locatorAccurate: true,
      severity: "high",
      evidenceSupport: "SUPPORTED",
      reasoning: "Executing arbitrary code via laundered context",
      counterexample: "exploit(5000)"
    };

    const formalResult = validateVerificationOutput(
      { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [fabricatedOmission] },
      { changeSet: { ...changeSet, contextPackage: launderedPkg }, headSha: fakeHead }
    );

    assert.ok(formalResult.ok);
    assert.equal(formalResult.verifierOmissions[0].locatorAccurate, false, "Formal verifier must reject locator accuracy for laundered context");
    assert.equal(formalResult.verifierOmissions[0].evidenceSupport, "INSUFFICIENT_EVIDENCE", "Formal verifier must downgrade omission to INSUFFICIENT_EVIDENCE");
    assert.notEqual(formalResult.verifierOmissions[0].evidenceSupport, "SUPPORTED");

    // 2. Positive Control: Authentic review context with genuine Git backing retains Registry trust and accurate locator
    const realRepoRoot = process.cwd();
    const realHeadSha = currentRepoHeadSha;
    const realFile = "src/core/independent-verifier.mjs";
    const authenticChangeSet = {
      repository: { root: realRepoRoot },
      headSha: realHeadSha,
      files: [{ path: realFile, additions: 10, deletions: 2 }],
      diffHunks: `diff --git a/${realFile} b/${realFile}
index 1111111..2222222 100644
--- a/${realFile}
+++ b/${realFile}
@@ -100,6 +100,10 @@
+const authenticLine = 1;
`
    };

    const authenticPkg = buildContextPackage(authenticChangeSet, null, {
      repositoryRoot: realRepoRoot,
      headSha: realHeadSha
    });

    assert.ok(authenticPkg, "Authentic package built successfully");
    assert.equal(isTrustedContextPackage(authenticPkg), true, "Authentic Git-backed package MUST have Registry trust");
    assert.equal(authenticPkg.fileCoverageManifest[0].exactHeadAvailable, true, "Authentic Git-backed file MUST have exactHeadAvailable = true");

    const authenticOmission = {
      title: "Legitimate flaw verified against authentic context",
      file: realFile,
      line_start: 100,
      line_end: 105,
      locatorAccurate: true,
      severity: "high",
      evidenceSupport: "SUPPORTED",
      reasoning: "Authentic counterexample on verified path in physical repository",
      counterexample: "reproduce(100)"
    };

    const authenticResult = validateVerificationOutput(
      { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [authenticOmission] },
      { changeSet: { ...authenticChangeSet, contextPackage: authenticPkg }, headSha: realHeadSha }
    );

    assert.ok(authenticResult.ok);
    assert.equal(authenticResult.verifierOmissions[0].locatorAccurate, true, "Authentic package must preserve accurate locator");
    assert.equal(authenticResult.verifierOmissions[0].evidenceSupport, "SUPPORTED", "Authentic package with concrete counterexample must retain SUPPORTED");
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

// ============================================================================
// PHASE2-NEG-26: (P2-CAP-07) Caller cannot provide tampered fileContents to override committed Git content in Exact-Head mode
// ============================================================================
test("PHASE2-NEG-26: Caller cannot provide tampered fileContents to override committed Git content in Exact-Head mode", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-p2-neg26-"));
  try {
    // 1. Set up real Git repository with committed authentic code
    execFileSync("git", ["init"], { cwd: tempDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "Test"], { cwd: tempDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "test@example.com"], { cwd: tempDir, stdio: "ignore" });

    const authRelPath = "src/auth.mjs";
    const authAbsDir = path.join(tempDir, "src");
    fs.mkdirSync(authAbsDir, { recursive: true });
    const committedContent = `export function authorizeUser(user) {
  if (!user || user.role !== "admin") {
    return false;
  }
  return true;
}
`;
    fs.writeFileSync(path.join(tempDir, authRelPath), committedContent, "utf8");
    execFileSync("git", ["add", "."], { cwd: tempDir, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "Commit authentic auth function"], { cwd: tempDir, stdio: "ignore" });
    const headSha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: tempDir, encoding: "utf8" }).trim();

    const diffHunks = `diff --git a/${authRelPath} b/${authRelPath}
index 1111111..2222222 100644
--- a/${authRelPath}
+++ b/${authRelPath}
@@ -2,3 +2,3 @@
-  if (!user || user.role !== "admin") {
-    return false;
-  }
+  return true;
`;
    const changeSet = {
      repository: { root: tempDir },
      headSha,
      files: [{ path: authRelPath, additions: 1, deletions: 3 }],
      diffHunks
    };

    // 2. Caller calls public buildContextPackage passing tampered fileContents (claiming authorizeUser returns true)
    const tamperedFileContent = `export function authorizeUser(user) {
  return true;
}
`;
    const tamperedPkg = buildContextPackage(changeSet, null, {
      repositoryRoot: tempDir,
      headSha,
      fileContents: {
        [authRelPath]: tamperedFileContent
      }
    });

    assert.ok(tamperedPkg, "buildContextPackage returned package");
    // Negative Assertion 1: Must NOT be registered into Trusted Context Package Registry
    assert.equal(isTrustedContextPackage(tamperedPkg), false, "Tampered package must NOT be registered into Trusted Registry");

    // Negative Assertion 2: Manifest must mark file as exactHeadAvailable = false and exactHeadUnavailable = true
    assert.ok(Array.isArray(tamperedPkg.fileCoverageManifest), "Package must contain fileCoverageManifest");
    const manifestEntry = tamperedPkg.fileCoverageManifest.find(m => m.file === authRelPath);
    assert.ok(manifestEntry, "Manifest must include inspected file entry");
    assert.equal(manifestEntry.exactHeadAvailable, false, "Conflicting fileContents must result in exactHeadAvailable = false");
    assert.equal(manifestEntry.exactHeadUnavailable, true, "Conflicting fileContents must result in exactHeadUnavailable = true");

    // Negative Assertion 3: Context gaps must record EXACT_HEAD_CONTENT_MISMATCH
    assert.ok(
      tamperedPkg.contextGaps.some(g => g.reason === "EXACT_HEAD_CONTENT_MISMATCH" && g.file === authRelPath),
      "Package must record EXACT_HEAD_CONTENT_MISMATCH context gap"
    );

    // Negative Assertion 4: Manual registerTrustedContextPackage must fail closed
    const regResult = registerTrustedContextPackage(tamperedPkg, {
      repositoryRoot: tempDir,
      headSha,
      diffHunks
    });
    assert.equal(regResult, null, "Manual registerTrustedContextPackage must fail closed for tampered package");

    // Negative Assertion 5: Verifier Clean Challenge must fail closed to UNCERTAIN due to EXACT_HEAD_CONTENT_MISMATCH
    const cleanResult = validateVerificationOutput(
      { overallStatus: "CLEAN", evaluations: [], verifierOmissions: [] },
      {
        verificationMode: "clean_challenge",
        changeSet: { ...changeSet, contextPackage: tamperedPkg },
        headSha
      }
    );
    assert.ok(cleanResult.ok);
    assert.equal(cleanResult.overallStatus, "UNCERTAIN", "Clean Challenge with tampered package must fail closed to UNCERTAIN");

    const mockAdapter = createMockVerifierAdapter("mock-adapter", {
      executeVerification: async () => ({
        ok: true,
        overallStatus: "CLEAN",
        evaluations: [],
        verifierOmissions: []
      })
    });
    const verifierRecord = await conductIndependentVerification(
      { ...changeSet, contextPackage: tamperedPkg },
      [],
      mockAdapter,
      {
        verificationMode: "clean_challenge",
        headSha
      }
    );
    assert.equal(verifierRecord.overallStatus, "UNCERTAIN", "conductIndependentVerification must fail closed to UNCERTAIN for tampered package");

    // Negative Assertion 6: validateContextPackageAuthenticity rejects tampered sourceDigest or forged callee snippets
    const forgedDigestPkg = {
      ...tamperedPkg,
      fileCoverageManifest: [
        {
          ...tamperedPkg.fileCoverageManifest[0],
          exactHeadAvailable: true,
          exactHeadUnavailable: false,
          sourceDigest: "0000000000000000000000000000000000000000000000000000000000000000"
        }
      ]
    };
    assert.equal(
      validateContextPackageAuthenticity(forgedDigestPkg, { repositoryRoot: tempDir, headSha, diffHunks }),
      false,
      "validateContextPackageAuthenticity must reject tampered sourceDigest"
    );

    const forgedSnippetPkg = {
      ...tamperedPkg,
      fileCoverageManifest: [
        {
          ...tamperedPkg.fileCoverageManifest[0],
          exactHeadAvailable: true,
          exactHeadUnavailable: false
        }
      ],
      layers: {
        ...tamperedPkg.layers,
        layer1AstEnclosure: {
          ...tamperedPkg.layers.layer1AstEnclosure,
          callees: [
            {
              name: "forgedFunction",
              file: authRelPath,
              definition: "function forgedFunction() { return 'forged'; }"
            }
          ]
        }
      }
    };
    assert.equal(
      validateContextPackageAuthenticity(forgedSnippetPkg, { repositoryRoot: tempDir, headSha, diffHunks }),
      false,
      "validateContextPackageAuthenticity must reject forged callee snippet not in committed Git object"
    );

    // 3. Positive Control 1: Authentic review context without tampered fileContents gains Registry trust
    const authenticPkg = buildContextPackage(changeSet, null, {
      repositoryRoot: tempDir,
      headSha
    });
    assert.ok(authenticPkg, "Authentic package built successfully");
    assert.equal(isTrustedContextPackage(authenticPkg), true, "Authentic Git package must gain Registry trust");
    assert.equal(authenticPkg.fileCoverageManifest[0].exactHeadAvailable, true, "Authentic Git package has exactHeadAvailable = true");
    assert.equal(
      authenticPkg.contextGaps.some(g => g.reason === "EXACT_HEAD_CONTENT_MISMATCH"),
      false,
      "Authentic package must have no EXACT_HEAD_CONTENT_MISMATCH gap"
    );

    // Verify AST enclosure extracts committed code containing 'admin'
    const authenticFn = authenticPkg.layers.layer1AstEnclosure.enclosingFunctions.find(f => f.name === "authorizeUser");
    assert.ok(authenticFn, "Authentic AST enclosure extracts authorizeUser");
    assert.match(authenticFn.bodySnippet, /admin/, "Authentic AST bodySnippet reflects committed Git object");

    // Verify legitimate omission against authentic context retains SUPPORTED (No False Hold)
    const authenticOmission = {
      title: "Legitimate flaw verified against authentic Git context",
      file: authRelPath,
      line_start: 2,
      line_end: 4,
      locatorAccurate: true,
      severity: "high",
      evidenceSupport: "SUPPORTED",
      reasoning: "Role check can be bypassed if user is crafted",
      counterexample: "authorizeUser({ role: null }) -> false"
    };
    const authenticResult = validateVerificationOutput(
      { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [authenticOmission] },
      { changeSet: { ...changeSet, contextPackage: authenticPkg }, headSha }
    );
    assert.ok(authenticResult.ok);
    assert.equal(authenticResult.verifierOmissions[0].locatorAccurate, true, "Authentic package must preserve accurate locator");
    assert.equal(authenticResult.verifierOmissions[0].evidenceSupport, "SUPPORTED", "Authentic package with concrete counterexample must retain SUPPORTED (No False Hold)");

    // 4. Positive Control 2: Caller supplying fileContents identical to committed Git object preserves exact-head authority
    const matchingPkg = buildContextPackage(changeSet, null, {
      repositoryRoot: tempDir,
      headSha,
      fileContents: {
        [authRelPath]: committedContent
      }
    });
    assert.equal(isTrustedContextPackage(matchingPkg), true, "Matching caller fileContents preserves exact-head authority");
    assert.equal(matchingPkg.fileCoverageManifest[0].exactHeadAvailable, true, "Matching fileContents has exactHeadAvailable = true");
    assert.equal(
      matchingPkg.contextGaps.some(g => g.reason === "EXACT_HEAD_CONTENT_MISMATCH"),
      false,
      "Matching fileContents has no EXACT_HEAD_CONTENT_MISMATCH gap"
    );
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

// ============================================================================
// PHASE2-NEG-27: (P2-CAP-08) Context package in-memory mutation or cloning cannot retain Trusted Registry authority or promote unverified omissions
// ============================================================================
test("PHASE2-NEG-27: (P2-CAP-08) Context package in-memory mutation or cloning cannot retain Trusted Registry authority or promote unverified omissions", async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-p2-neg27-"));
  const nonGitDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-p2-neg27-nongit-"));
  try {
    // 1. Set up real Git repository with committed authentic code
    execFileSync("git", ["init"], { cwd: tempDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "Test"], { cwd: tempDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "test@example.com"], { cwd: tempDir, stdio: "ignore" });

    const authRelPath = "src/auth.mjs";
    const authAbsDir = path.join(tempDir, "src");
    fs.mkdirSync(authAbsDir, { recursive: true });
    const committedContent = `export function authorizeUser(user) {
  if (!user || user.role !== "admin") {
    return false;
  }
  return true;
}
`;
    fs.writeFileSync(path.join(tempDir, authRelPath), committedContent, "utf8");
    execFileSync("git", ["add", "."], { cwd: tempDir, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "Commit authentic auth code"], { cwd: tempDir, stdio: "ignore" });
    const headSha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: tempDir, encoding: "utf8" }).trim();

    const diffHunks = `diff --git a/${authRelPath} b/${authRelPath}
index 1111111..2222222 100644
--- a/${authRelPath}
+++ b/${authRelPath}
@@ -2,3 +2,3 @@
-  if (!user || user.role !== "admin") {
-    return false;
-  }
+  return Boolean(user && user.role === "admin");
`;

    const changeSet = {
      repository: { root: tempDir },
      headSha,
      files: [{ path: authRelPath, additions: 1, deletions: 3 }],
      diffHunks
    };

    // 2. Build authentic context package
    const authenticPkg = buildContextPackage(changeSet, null, {
      repositoryRoot: tempDir,
      headSha
    });

    assert.ok(authenticPkg, "Authentic package built successfully");
    assert.equal(isTrustedContextPackage(authenticPkg), true, "Authentic package must initially be trusted in registry");

    // 3. Immutability verification: authentic package must be deeply frozen
    assert.equal(Object.isFrozen(authenticPkg), true, "Authentic package top-level must be frozen");
    assert.equal(Object.isFrozen(authenticPkg.layers), true, "Package layers must be frozen");
    assert.equal(Object.isFrozen(authenticPkg.fileCoverageManifest), true, "Package fileCoverageManifest must be frozen");
    assert.equal(Object.isFrozen(authenticPkg.fileCoverageManifest[0]), true, "Package fileCoverageManifest entries must be frozen");
    assert.equal(Object.isFrozen(authenticPkg.budgetAccounting), true, "Package budgetAccounting must be frozen");

    // 4. Probe 1 (In-Memory Direct Mutation): In strict mode, direct assignment must throw TypeError
    assert.throws(() => {
      authenticPkg.headSha = "0000000000000000000000000000000000000005";
    }, TypeError, "Direct assignment to headSha on frozen package must throw TypeError");

    assert.throws(() => {
      authenticPkg.contentDigest = "0000000000000000000000000000000000000000000000000000000000000005";
    }, TypeError, "Direct assignment to contentDigest on frozen package must throw TypeError");

    assert.throws(() => {
      authenticPkg.targetFile = "src/spoofed.mjs";
    }, TypeError, "Direct assignment to targetFile on frozen package must throw TypeError");

    assert.throws(() => {
      authenticPkg.injectedProperty = "tampered";
    }, TypeError, "Adding new property to frozen package must throw TypeError");

    assert.throws(() => {
      authenticPkg.fileCoverageManifest[0].file = "src/spoofed.mjs";
    }, TypeError, "Direct mutation of nested manifest entry must throw TypeError");

    assert.throws(() => {
      authenticPkg.fileCoverageManifest.push({ file: "src/spoofed.mjs", inspected: true });
    }, TypeError, "Mutating nested array on frozen package must throw TypeError");

    // 5. Probe 2 (Cloning / Detached Mutation): Cloned packages do not inherit WeakMap registry trust
    const fakeHead = "0000000000000000000000000000000000000005";
    const fakeDiff = `diff --git a/src/spoofed.mjs b/src/spoofed.mjs
index 1111111..2222222 100644
--- a/src/spoofed.mjs
+++ b/src/spoofed.mjs
@@ -1 +5000,2 @@
+const line1 = 1;
+const line2 = 2;
`;
    const fakeDigest = crypto.createHash("sha256").update(fakeDiff).digest("hex");

    const clonedMutated = {
      ...authenticPkg,
      headSha: fakeHead,
      contentDigest: fakeDigest,
      fileCoverageManifest: [
        {
          file: "src/spoofed.mjs",
          inspected: true,
          exactHeadAvailable: true,
          calleesExtracted: []
        }
      ]
    };

    assert.equal(
      isTrustedContextPackage(clonedMutated),
      false,
      "Cloned/mutated package must NOT be trusted in registry"
    );

    // Even if attacker freezes the cloned package, it lacks registry provenance
    const frozenClone = deepFreeze({ ...clonedMutated });
    assert.equal(
      isTrustedContextPackage(frozenClone),
      false,
      "Frozen clone without registration must NOT be trusted in registry"
    );

    // 6. Probe 3: Snapshot hash integrity check
    const initialHash = computeContextPackageSnapshotHash(authenticPkg);
    assert.ok(initialHash && initialHash.startsWith("sha256:"), "Snapshot hash must be a valid sha256 digest");
    const mutatedHash = computeContextPackageSnapshotHash(clonedMutated);
    assert.notEqual(initialHash, mutatedHash, "Snapshot hash of mutated package must differ from original");

    // 7. Probe 4 (Non-Git Omission Promotion Attack): Attempting to pass mutated package to formal gate
    const fabricatedOmission = {
      title: "Fabricated omission on non-existent line 5000",
      file: "src/spoofed.mjs",
      line_start: 5000,
      line_end: 5001,
      locatorAccurate: true,
      severity: "high",
      evidenceSupport: "SUPPORTED",
      reasoning: "Buffer overflow on non-existent execution path",
      counterexample: "alloc(5000) -> crash"
    };

    const nonGitChangeSet = {
      repository: { root: nonGitDir },
      headSha: fakeHead,
      files: [{ path: "src/spoofed.mjs", additions: 2, deletions: 0 }],
      diffHunks: fakeDiff,
      contextPackage: clonedMutated
    };

    const attackResult = validateVerificationOutput(
      { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [fabricatedOmission] },
      { changeSet: nonGitChangeSet, headSha: fakeHead }
    );

    assert.ok(attackResult.ok);
    assert.equal(
      attackResult.verifierOmissions[0].locatorAccurate,
      false,
      "Formal verifier must reject locator accuracy for mutated package without trusted provenance"
    );
    assert.equal(
      attackResult.verifierOmissions[0].evidenceSupport,
      "INSUFFICIENT_EVIDENCE",
      "Formal verifier must downgrade fabricated omission to INSUFFICIENT_EVIDENCE (never SUPPORTED)"
    );

    // 8. Positive Control: Authentic package with real Git backing validates cleanly
    const legitimateOmission = {
      title: "Legitimate flaw verified against authentic Git context",
      file: authRelPath,
      line_start: 2,
      line_end: 4,
      locatorAccurate: true,
      severity: "high",
      evidenceSupport: "SUPPORTED",
      reasoning: "Role check can be bypassed if user is crafted",
      counterexample: "authorizeUser({ role: null }) -> false"
    };

    const authenticResult = validateVerificationOutput(
      { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [legitimateOmission] },
      { changeSet: { ...changeSet, contextPackage: authenticPkg }, headSha }
    );

    assert.ok(authenticResult.ok);
    assert.equal(authenticResult.verifierOmissions[0].locatorAccurate, true, "Authentic package retains accurate locator");
    assert.equal(authenticResult.verifierOmissions[0].evidenceSupport, "SUPPORTED", "Authentic package retains SUPPORTED");
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
    fs.rmSync(nonGitDir, { recursive: true, force: true });
  }
});

// ============================================================================
// PHASE2-NEG-28: (RVCBQ Counterexample A) Non-Git working-tree mode with target file absent from disk cannot use self-declared diff hunks to grant SUPPORTED
// ============================================================================
test("PHASE2-NEG-28: Non-Git working-tree mode with target file absent from disk cannot use self-declared diff hunks to grant SUPPORTED", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-rvcbq-neg28-"));
  try {
    const changeSet = {
      repository: { root: tempDir },
      files: [{ path: "src/not-on-disk.js" }],
      diffHunks: "diff --git a/src/not-on-disk.js b/src/not-on-disk.js\n@@ -0,0 +1,999999 @@\n+line"
    };

    const candidate = {
      title: "Fabricated omission on non-existent file",
      file: "src/not-on-disk.js",
      line_start: 999999,
      line_end: 999999,
      locatorAccurate: true,
      severity: "critical",
      evidenceSupport: "SUPPORTED",
      reasoning: "Detailed substantive reasoning explaining why this is vulnerable in execution flow",
      counterexample: "fn(payload) -> crash"
    };

    const result = validateVerificationOutput(
      { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [candidate] },
      { changeSet }
    );

    assert.ok(result.ok);
    assert.equal(result.verifierOmissions[0].locatorAccurate, false, "Absent target file in non-Git working-tree mode must set locatorAccurate to false");
    assert.equal(result.verifierOmissions[0].evidenceSupport, "INSUFFICIENT_EVIDENCE", "Fabricated diff hunk on absent file must downgrade SUPPORTED to INSUFFICIENT_EVIDENCE");
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

// ============================================================================
// PHASE2-NEG-29: (RVCBQ Counterexample B) Trailing newline in file must not overcount physical line count and grant SUPPORTED to out-of-bounds line
// ============================================================================
test("PHASE2-NEG-29: Trailing newline in file must not overcount physical line count and grant SUPPORTED to out-of-bounds line", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-rvcbq-neg29-"));
  try {
    const filePath = "src/three-lines.js";
    const fullPath = path.join(tempDir, filePath);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, "const a = 1;\nconst b = 2;\nconst c = 3;\n", "utf8");

    const changeSet = {
      repository: { root: tempDir },
      files: [{ path: filePath }],
      diffHunks: ""
    };

    const candidate = {
      title: "Omission referencing non-existent line 4 after trailing newline",
      file: filePath,
      line_start: 4,
      line_end: 4,
      locatorAccurate: true,
      severity: "high",
      evidenceSupport: "SUPPORTED",
      reasoning: "Substantive reasoning explaining crash on trailing empty line",
      counterexample: "call() -> crash"
    };

    const result = validateVerificationOutput(
      { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [candidate] },
      { changeSet, scopeMode: "working-tree" }
    );

    assert.ok(result.ok);
    assert.equal(result.verifierOmissions[0].locatorAccurate, false, "Line beyond last code line must set locatorAccurate to false");
    assert.equal(result.verifierOmissions[0].evidenceSupport, "INSUFFICIENT_EVIDENCE", "Out-of-bounds line after trailing newline must downgrade to INSUFFICIENT_EVIDENCE");
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

// ============================================================================
// PHASE2-POS-03: (Boundary Check) Single blank line file ("\n" / "\r\n") accepts line 1 as valid and rejects line 2
// ============================================================================
test("PHASE2-POS-03: Single blank line file ('\\n' / '\\r\\n') accepts line 1 as valid and rejects line 2; empty file rejects line 1", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-rvcbq-pos03-"));
  try {
    fs.mkdirSync(path.join(tempDir, "src"), { recursive: true });
    // 1. Single blank line with LF ("\n") -> 1 physical line
    const lfFile = "src/blank-lf.js";
    fs.writeFileSync(path.join(tempDir, lfFile), "\n", "utf8");

    const candidateLine1 = {
      title: "Legitimate flaw on blank line 1",
      file: lfFile,
      line_start: 1,
      line_end: 1,
      locatorAccurate: true,
      severity: "high",
      evidenceSupport: "SUPPORTED",
      reasoning: "Substantive reasoning explaining crash on line 1",
      counterexample: "call(1) -> crash"
    };

    const resLfLine1 = validateVerificationOutput(
      { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [candidateLine1] },
      { changeSet: { repository: { root: tempDir }, files: [{ path: lfFile }] }, scopeMode: "working-tree" }
    );
    assert.ok(resLfLine1.ok);
    assert.equal(resLfLine1.verifierOmissions[0].locatorAccurate, true, "Line 1 of single blank line LF file must remain locatorAccurate true");
    assert.equal(resLfLine1.verifierOmissions[0].evidenceSupport, "SUPPORTED", "Line 1 of single blank line LF file must remain SUPPORTED (no false rejection)");

    const candidateLine2 = { ...candidateLine1, line_start: 2, line_end: 2 };
    const resLfLine2 = validateVerificationOutput(
      { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [candidateLine2] },
      { changeSet: { repository: { root: tempDir }, files: [{ path: lfFile }] }, scopeMode: "working-tree" }
    );
    assert.ok(resLfLine2.ok);
    assert.equal(resLfLine2.verifierOmissions[0].locatorAccurate, false, "Line 2 of single blank line LF file must be locatorAccurate false");
    assert.equal(resLfLine2.verifierOmissions[0].evidenceSupport, "INSUFFICIENT_EVIDENCE", "Line 2 of single blank line LF file must downgrade to INSUFFICIENT_EVIDENCE");

    // 2. Single blank line with CRLF ("\r\n") -> 1 physical line
    const crlfFile = "src/blank-crlf.js";
    fs.writeFileSync(path.join(tempDir, crlfFile), "\r\n", "utf8");

    const candidateCrlfLine1 = { ...candidateLine1, file: crlfFile };
    const resCrlfLine1 = validateVerificationOutput(
      { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [candidateCrlfLine1] },
      { changeSet: { repository: { root: tempDir }, files: [{ path: crlfFile }] }, scopeMode: "working-tree" }
    );
    assert.ok(resCrlfLine1.ok);
    assert.equal(resCrlfLine1.verifierOmissions[0].locatorAccurate, true, "Line 1 of single blank line CRLF file must remain locatorAccurate true");
    assert.equal(resCrlfLine1.verifierOmissions[0].evidenceSupport, "SUPPORTED", "Line 1 of single blank line CRLF file must remain SUPPORTED");

    const candidateCrlfLine2 = { ...candidateLine1, file: crlfFile, line_start: 2, line_end: 2 };
    const resCrlfLine2 = validateVerificationOutput(
      { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [candidateCrlfLine2] },
      { changeSet: { repository: { root: tempDir }, files: [{ path: crlfFile }] }, scopeMode: "working-tree" }
    );
    assert.ok(resCrlfLine2.ok);
    assert.equal(resCrlfLine2.verifierOmissions[0].locatorAccurate, false, "Line 2 of single blank line CRLF file must be locatorAccurate false");
    assert.equal(resCrlfLine2.verifierOmissions[0].evidenceSupport, "INSUFFICIENT_EVIDENCE", "Line 2 of single blank line CRLF file must downgrade to INSUFFICIENT_EVIDENCE");

    // 3. Completely empty file ("") -> 0 physical lines
    const emptyFile = "src/empty.js";
    fs.writeFileSync(path.join(tempDir, emptyFile), "", "utf8");

    const candidateEmpty = { ...candidateLine1, file: emptyFile };
    const resEmpty = validateVerificationOutput(
      { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [candidateEmpty] },
      { changeSet: { repository: { root: tempDir }, files: [{ path: emptyFile }] }, scopeMode: "working-tree" }
    );
    assert.ok(resEmpty.ok);
    assert.equal(resEmpty.verifierOmissions[0].locatorAccurate, false, "Line 1 of empty 0-byte file must be locatorAccurate false");
    assert.equal(resEmpty.verifierOmissions[0].evidenceSupport, "INSUFFICIENT_EVIDENCE", "Line 1 of empty 0-byte file must downgrade to INSUFFICIENT_EVIDENCE");
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

// ============================================================================
// PHASE2-NEG-30: (Boundary Check) Exact-Head branch physicalLineCount boundary check
// ============================================================================
test("PHASE2-NEG-30: Exact-Head branch verifies physicalLineCount bounds on committed repo file and rejects out-of-bounds line", () => {
  const targetFile = "src/core/independent-verifier.mjs";
  const exactContent = getExactHeadFileContent(process.cwd(), currentRepoHeadSha, targetFile);
  assert.ok(typeof exactContent === "string", "Must be able to read target file from checked-out exact HEAD");

  const expectedLines = exactContent.length === 0
    ? 0
    : exactContent.split(/\r?\n/).length - (exactContent.endsWith("\n") ? 1 : 0);
  assert.ok(expectedLines > 100, "independent-verifier.mjs must have substantive physical lines");

  const changeSet = createTestChangeSet({
    repository: { root: process.cwd() },
    headSha: currentRepoHeadSha,
    files: [{ path: targetFile }]
  });

  // Scenario 1: Legitimate omission on the exact last physical line -> SUPPORTED (positive control)
  const lastLineCandidate = {
    title: "Flaw on the exact last physical line of file",
    file: targetFile,
    line_start: expectedLines,
    line_end: expectedLines,
    locatorAccurate: true,
    severity: "high",
    evidenceSupport: "SUPPORTED",
    reasoning: "Substantive reasoning explaining flaw at final line boundary",
    counterexample: "verifyBoundary(lastLine) -> crash"
  };

  const resLastLine = validateVerificationOutput(
    { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [lastLineCandidate] },
    { changeSet, headSha: currentRepoHeadSha }
  );
  assert.ok(resLastLine.ok);
  assert.equal(resLastLine.verifierOmissions[0].locatorAccurate, true, "Exact last physical line must retain locatorAccurate true");
  assert.equal(resLastLine.verifierOmissions[0].evidenceSupport, "SUPPORTED", "Exact last physical line must retain SUPPORTED");

  // Scenario 2: Omission referencing expectedLines + 1 (1 past physical end) -> downgraded (negative control)
  const beyondEndCandidate = {
    ...lastLineCandidate,
    line_start: expectedLines + 1,
    line_end: expectedLines + 1
  };

  const resBeyondEnd = validateVerificationOutput(
    { overallStatus: "DEFECTS_FOUND", evaluations: [], verifierOmissions: [beyondEndCandidate] },
    { changeSet, headSha: currentRepoHeadSha }
  );
  assert.ok(resBeyondEnd.ok);
  assert.equal(resBeyondEnd.verifierOmissions[0].locatorAccurate, false, "Line expectedLines + 1 must set locatorAccurate false");
  assert.equal(resBeyondEnd.verifierOmissions[0].evidenceSupport, "INSUFFICIENT_EVIDENCE", "Line expectedLines + 1 must downgrade to INSUFFICIENT_EVIDENCE");
});
