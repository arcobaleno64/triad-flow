/**
 * Remediation Acceptance Test Suite: Six Additional Review Threads (PR #39)
 *
 * Covers:
 *   - tfxJh (P1): Authoritative risk evaluation via evaluateDiffScale(changeSet.files);
 *                 rejection of forged plan downgrades (highestRisk > 1 or single mode for Tier 1).
 *   - tfxJn (P1): Authoritative objective binding passed consistently to Macro, Micro, Single Adapter, and Gate;
 *                 deterministic conflict fail-closed.
 *   - tfxJq (P1): Optional chaining ?. receiver extraction in context-builder;
 *                 prevents false binding to local bare functions and generates EXTERNAL_CALLEE_UNRESOLVED context gap.
 *   - tfxJo (P2): CLI transport prevents input.options from overriding canonical patchObjective,
 *                 objectiveContract, and contextGaps; conflict fail-closed.
 *   - tfxJr (P2): Safe handling of non-string callee definitions; structured untrusted/incomplete rejection
 *                 without unhandled TypeError or silent approval.
 *   - tfxJj (P2): Format SARIF when consensus is null; valid failure SARIF output with non-zero exit code
 *                 without unhandled TypeError.
 */

import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { execFileSync } from "node:child_process";

import { orchestrateReview, orchestrateBenchmarkEvaluation } from "../src/adapters/review-orchestrator.mjs";
import { CliReviewAdapter } from "../src/adapters/cli-transport.mjs";
import { formatContextPackageXml } from "../src/adapters/review-prompts.mjs";
import {
  extractCandidateCallSymbols,
  extractLocalCalleeContext
} from "../src/core/context-builder.mjs";
import { runCli, EXIT_CODES } from "../src/cli.mjs";
import { validateSarifStructure } from "../src/core/harness.mjs";
import { evaluateCorpusCase } from "../src/core/real-benchmark-runner.mjs";
import { getCorpusCaseById, createMockCorpusAdapters } from "./fixtures/real-corpus-fixtures.mjs";

class MockStream {
  constructor() {
    this.buffer = "";
  }
  write(chunk) {
    this.buffer += String(chunk);
  }
}

function makeChangeSet(files = [{ path: "src/sample.js", additions: 10, deletions: 2 }], hunks = "+ const a = 1;") {
  const contentDigest = crypto.createHash("sha256").update(hunks).digest("hex");
  return {
    ok: true,
    schemaVersion: "1.0.0",
    scopeMode: "working-tree",
    repository: { root: "/repo", hasHead: true, currentBranch: "main" },
    contentDigest,
    totalFiles: files.length,
    totalAdditions: files.reduce((s, f) => s + (f.additions || 0), 0),
    totalDeletions: files.reduce((s, f) => s + (f.deletions || 0), 0),
    files,
    diffHunks: hunks
  };
}

// --------------------------------------------------------------------------
// 1. Thread tfxJh: Authoritative Risk Evaluation & Plan Downgrade Rejection
// --------------------------------------------------------------------------

test("tfxJh NEGATIVE: Attempt to downgrade Tier 1 diff using external plan with highestRisk > 1 fails closed", async () => {
  // src/auth/jwt.js is classified as Tier 1 (Critical) by graph-router
  const changeSet = makeChangeSet([
    { path: "src/auth/jwt.js", additions: 5, deletions: 2 }
  ]);

  const mockAdapter = {
    executeReview: async () => ({
      ok: true,
      findings: [],
      coverage: { coveredFiles: ["src/auth/jwt.js"], omittedFiles: [] }
    })
  };

  // Caller attempts to downgrade Tier 1 diff by passing external plan with highestRisk: 2
  const forgedPlan = { mode: "single", highestRisk: 2, totalFiles: 1, totalLines: 7 };
  const res = await orchestrateReview(changeSet, { macro: mockAdapter }, { plan: forgedPlan });

  assert.equal(res.status, "incomplete");
  assert.equal(res.gate.decision, "block");
  assert.match(res.gate.reason, /INVALID_OR_DOWNGRADED_TIER/i);
});

test("tfxJh NEGATIVE: Attempt to downgrade Tier 1 diff using external plan with mode 'single' fails closed", async () => {
  const changeSet = makeChangeSet([
    { path: "src/auth/jwt.js", additions: 5, deletions: 2 }
  ]);

  const mockAdapter = {
    executeReview: async () => ({
      ok: true,
      findings: [],
      coverage: { coveredFiles: ["src/auth/jwt.js"], omittedFiles: [] }
    })
  };

  // External plan claims highestRisk: 1 but forces single mode to bypass dual sentries
  const forgedSinglePlan = { mode: "single", highestRisk: 1, totalFiles: 1, totalLines: 7 };
  const res = await orchestrateReview(changeSet, { macro: mockAdapter }, { plan: forgedSinglePlan });

  assert.equal(res.status, "incomplete");
  assert.equal(res.gate.decision, "block");
  assert.match(res.gate.reason, /INVALID_OR_DOWNGRADED_TIER/i);
});

test("tfxJh NEGATIVE: Attempt to downgrade hierarchical scale diff via single mode plan fails closed", async () => {
  // Multiple files exceeding single sentry threshold (> 3 files)
  const changeSet = makeChangeSet([
    { path: "src/file1.js", additions: 20, deletions: 5 },
    { path: "src/file2.js", additions: 25, deletions: 10 },
    { path: "src/file3.js", additions: 15, deletions: 5 },
    { path: "src/file4.js", additions: 10, deletions: 2 }
  ]);

  const mockAdapter = {
    executeReview: async () => ({
      ok: true,
      findings: [],
      coverage: { coveredFiles: ["src/file1.js", "src/file2.js", "src/file3.js", "src/file4.js"], omittedFiles: [] }
    })
  };

  const forgedSinglePlan = { mode: "single", highestRisk: 2, totalFiles: 4, totalLines: 70 };
  const res = await orchestrateReview(changeSet, { macro: mockAdapter }, { plan: forgedSinglePlan });

  assert.equal(res.status, "incomplete");
  assert.equal(res.gate.decision, "block");
  assert.match(res.gate.reason, /INVALID_OR_DOWNGRADED_TIER/i);
});

test("tfxJh POSITIVE: Low-risk small diff matching plan runs successfully", async () => {
  const changeSet = makeChangeSet([
    { path: "docs/readme.md", additions: 2, deletions: 1 }
  ]);

  const mockAdapter = {
    executeReview: async () => ({
      ok: true,
      findings: [],
      coverage: { coveredFiles: ["docs/readme.md"], omittedFiles: [] }
    })
  };

  const legitimatePlan = { mode: "single", highestRisk: 3, totalFiles: 1, totalLines: 3 };
  const res = await orchestrateReview(changeSet, { macro: mockAdapter }, {
    plan: legitimatePlan,
    preliminary: true
  });

  assert.equal(res.status, "preliminary-clean");
  assert.equal(res.gate.decision, "approve");
});

// --------------------------------------------------------------------------
// 2. Thread tfxJn: Authoritative Objective Binding & Conflict Fail-Closed
// --------------------------------------------------------------------------

test("tfxJn NEGATIVE: Conflicting objectives between options.patchObjective and changeSet.patchObjective fail closed", async () => {
  const changeSet = makeChangeSet([
    { path: "src/calc.js", additions: 5, deletions: 2 }
  ]);
  changeSet.patchObjective = "Objective Alpha: Fix zero division";

  const mockAdapter = {
    executeReview: async () => ({
      ok: true,
      findings: [],
      coverage: { coveredFiles: ["src/calc.js"], omittedFiles: [] }
    })
  };

  const res = await orchestrateReview(changeSet, { macro: mockAdapter }, {
    patchObjective: "Objective Beta: Enhance performance"
  });

  assert.equal(res.status, "incomplete");
  assert.equal(res.gate.decision, "block");
  assert.match(res.gate.reason, /EXCLUSION_OR_OBJECTIVE_MISMATCH|objective mismatch/i);
});

test("tfxJn NEGATIVE: Conflicting objectives between options.patchObjective and options.objectiveContract fail closed", async () => {
  const changeSet = makeChangeSet([
    { path: "src/calc.js", additions: 5, deletions: 2 }
  ]);

  const mockAdapter = {
    executeReview: async () => ({
      ok: true,
      findings: [],
      coverage: { coveredFiles: ["src/calc.js"], omittedFiles: [] }
    })
  };

  const res = await orchestrateReview(changeSet, { macro: mockAdapter }, {
    patchObjective: "Fix SQL injection",
    objectiveContract: { objective: "Update documentation styles" }
  });

  assert.equal(res.status, "incomplete");
  assert.equal(res.gate.decision, "block");
  assert.match(res.gate.reason, /EXCLUSION_OR_OBJECTIVE_MISMATCH|objective mismatch/i);
});

test("tfxJn POSITIVE: Authoritative objective is consistently passed to macro, micro, and single adapters", async () => {
  const changeSet = makeChangeSet([
    { path: "src/calc.js", additions: 5, deletions: 2 }
  ]);

  let capturedInputSingle = null;
  const mockSingleAdapter = {
    executeReview: async (input) => {
      capturedInputSingle = input;
      return {
        ok: true,
        findings: [],
        coverage: { coveredFiles: ["src/calc.js"], omittedFiles: [] }
      };
    }
  };

  const objective = "Authoritative Fix: Validate buffer bounds";
  const contract = { objective, exclusions: [] };

  await orchestrateReview(changeSet, { macro: mockSingleAdapter }, {
    patchObjective: objective,
    objectiveContract: contract,
    preliminary: true
  });

  assert.ok(capturedInputSingle);
  assert.equal(capturedInputSingle.patchObjective, objective);
  assert.deepEqual(capturedInputSingle.objectiveContract, contract);

  // Also test dual sentries (hierarchical mode with Tier 1 file)
  const tier1ChangeSet = makeChangeSet([
    { path: "src/auth/jwt.js", additions: 5, deletions: 2 }
  ]);

  let capturedMacro = null;
  let capturedMicro = null;
  const mockMacro = {
    executeReview: async (input) => {
      capturedMacro = input;
      return {
        ok: true,
        findings: [],
        coverage: { coveredFiles: ["src/auth/jwt.js"], omittedFiles: [] }
      };
    }
  };
  const mockMicro = {
    executeReview: async (input) => {
      capturedMicro = input;
      return {
        ok: true,
        findings: [],
        coverage: { coveredFiles: ["src/auth/jwt.js"], omittedFiles: [] }
      };
    }
  };

  await orchestrateReview(tier1ChangeSet, { macro: mockMacro, micro: mockMicro }, {
    patchObjective: objective,
    objectiveContract: contract,
    preliminary: true
  });

  assert.ok(capturedMacro);
  assert.ok(capturedMicro);
  assert.equal(capturedMacro.patchObjective, objective);
  assert.equal(capturedMicro.patchObjective, objective);
  assert.deepEqual(capturedMacro.objectiveContract, contract);
  assert.deepEqual(capturedMicro.objectiveContract, contract);
});

// --------------------------------------------------------------------------
// 3. Thread tfxJq: Optional Chaining Receiver Extraction in Context Builder
// --------------------------------------------------------------------------

test("tfxJq COUNTEREXAMPLE & FIX: auth?.authorize(user) extracts 'auth' qualifier and does not bind to local bare function", () => {
  const diffHunks = [
    "@@ -5,3 +5,4 @@",
    " function handleRequest(user) {",
    "+  auth?.authorize(user);",
    " }"
  ].join("\n");

  const candidates = extractCandidateCallSymbols(diffHunks);
  assert.equal(candidates.length, 1);
  const call = candidates[0];
  assert.equal(call.symbol, "authorize");
  assert.equal(call.qualifier, "auth");
  assert.deepEqual(call.qualifiers, ["auth"]);
  assert.equal(call.isQualified, true);

  // In target file, there is a local bare function 'authorize()'
  const fileContent = [
    "// target file",
    "function authorize() {",
    "  return false;",
    "}",
    "function handleRequest(user) {",
    "  auth?.authorize(user);",
    "}"
  ].join("\n");

  const res = extractLocalCalleeContext(fileContent, diffHunks, "src/handler.js");

  // It MUST NOT bind to the local bare authorize function!
  assert.equal(res.callees.length, 0, "Must not bind qualified auth?.authorize to local bare function authorize");

  // It MUST record EXTERNAL_CALLEE_UNRESOLVED in unresolvedCallees
  const unresolved = res.unresolvedCallees.find(u => u.symbol === "authorize");
  assert.ok(unresolved, "Must record unresolved callee for authorize");
  assert.equal(unresolved.qualifier, "auth");
  assert.equal(unresolved.reason, "EXTERNAL_CALLEE_UNRESOLVED");

  // It MUST record a contextGap for sensitive security path
  const gap = res.contextGaps.find(g => g.symbol === "authorize");
  assert.ok(gap, "Must record context gap for sensitive callee authorize");
  assert.equal(gap.reason, "EXTERNAL_CALLEE_UNRESOLVED");
});

test("tfxJq POSITIVE: Chained optional calls like service?.auth?.authorize(user) extract receiver qualifiers correctly", () => {
  const diffHunks = [
    "@@ -1,3 +1,4 @@",
    "+  service?.auth?.authorize(user);"
  ].join("\n");

  const candidates = extractCandidateCallSymbols(diffHunks);
  assert.equal(candidates.length, 1);
  const call = candidates[0];
  assert.equal(call.symbol, "authorize");
  assert.equal(call.qualifier, "auth");
  assert.deepEqual(call.qualifiers, ["service", "auth"]);
  assert.equal(call.isQualified, true);
});

// --------------------------------------------------------------------------
// 4. Thread tfxJo: CLI Transport Prevents input.options Override of Authority Keys
// --------------------------------------------------------------------------

test("tfxJo NEGATIVE: CliReviewAdapter fails closed when input.options contradicts input.patchObjective", async () => {
  const adapter = new CliReviewAdapter({
    command: "agy",
    execFn: async () => ({ stdout: '{"verdict": "pass", "findings": []}' })
  });

  const changeSet = makeChangeSet();

  const res = await adapter.executeReview({
    runId: "run-test-1",
    role: "macro",
    policyId: "SINGLE_SENTRY",
    changeSet,
    patchObjective: "Canonical Fix: Prevent CSRF",
    options: {
      patchObjective: "Spoofed Fix: Tamper with CSRF"
    }
  });

  assert.equal(res.executionStatus, "error");
  assert.match(res.error, /Conflicting patchObjective or objectiveContract detected/i);
});

test("tfxJo POSITIVE: Safe input.options are retained while authority keys cannot override canonical values", async () => {
  let capturedPrompt = null;

  const adapter = new CliReviewAdapter({
    command: "claude",
    execFn: async ({ prompt }) => {
      capturedPrompt = prompt;
      return {
        stdout: JSON.stringify({
          findings: [],
          coverage: { coveredFiles: ["src/sample.js"], omittedFiles: [] }
        })
      };
    }
  });

  const changeSet = makeChangeSet();
  const canonicalObjective = "Secure Token Generation";
  const canonicalContract = { objective: canonicalObjective, exclusions: ["tests/"] };
  const canonicalGaps = [{ symbol: "generateKey", reason: "EXTERNAL_CALLEE_UNRESOLVED" }];

  const res = await adapter.executeReview({
    runId: "run-test-2",
    role: "macro",
    policyId: "SINGLE_SENTRY",
    changeSet,
    patchObjective: canonicalObjective,
    objectiveContract: canonicalContract,
    contextGaps: canonicalGaps,
    options: {
      // Attempt to tamper with contextGaps and patchObjective
      patchObjective: canonicalObjective, // identical text passes conflict check
      contextGaps: [], // attempt to wipe out context gaps!
      customUserFlag: "safe_flag_preserved"
    }
  });

  assert.equal(res.ok, true);
  assert.equal(res.executionStatus, "empty");
  assert.ok(capturedPrompt, "Prompt must be generated and passed to execFn");
  assert.match(capturedPrompt, new RegExp(canonicalObjective), "Prompt must contain canonical patch objective");
  assert.match(capturedPrompt, /generateKey/, "Prompt must retain canonical context gaps despite options.contextGaps attempt");
});

// --------------------------------------------------------------------------
// 5. Thread tfxJr: Non-String Callee Definition Safe Handling & Structured Rejection
// --------------------------------------------------------------------------

test("tfxJr NEGATIVE: formatContextPackageXml handles non-string callee definition without throwing TypeError", () => {
  const malformedPackage = {
    targetFile: "src/auth.js",
    layers: {
      layer1AstEnclosure: {
        enclosingFunctions: [],
        enclosingClasses: [],
        callees: [
          {
            symbol: "tamperedFn",
            lines: 5,
            bytes: 50,
            definition: 1234567 // Illegal non-string definition!
          }
        ]
      }
    }
  };

  // Pre-fix: threw TypeError: c.definition.trim is not a function
  // Post-fix: returns structured untrusted status without throwing
  let xml = null;
  assert.doesNotThrow(() => {
    xml = formatContextPackageXml(malformedPackage);
  });

  assert.ok(xml);
  assert.match(xml, /status="untrusted"/);
  assert.match(xml, /INVALID_CALLEE_DEFINITION/);
});

test("tfxJr NEGATIVE: orchestrateReview fails closed when contextPackage has non-string callee definition", async () => {
  const changeSet = makeChangeSet();
  const malformedPackage = {
    targetFile: "src/auth.js",
    layers: {
      layer1AstEnclosure: {
        callees: [
          {
            symbol: "invalidDefFn",
            definition: { malicious: true } // Non-string object!
          }
        ]
      }
    }
  };

  const mockAdapter = {
    executeReview: async () => ({
      ok: true,
      findings: [],
      coverage: { coveredFiles: ["src/sample.js"], omittedFiles: [] }
    })
  };

  const res = await orchestrateReview(changeSet, { macro: mockAdapter }, {
    contextPackage: malformedPackage
  });

  assert.equal(res.status, "incomplete");
  assert.equal(res.gate.decision, "block");
  assert.match(res.gate.reason, /INVALID_CALLEE_DEFINITION/);
});

test("tfxJr POSITIVE: formatContextPackageXml formats valid string callee definition properly", () => {
  const validPackage = {
    targetFile: "src/auth.js",
    layers: {
      layer1AstEnclosure: {
        enclosingFunctions: [],
        enclosingClasses: [],
        callees: [
          {
            symbol: "validFn",
            startLine: 10,
            endLine: 12,
            lines: 3,
            bytes: 40,
            definition: "function validFn() {\n  return true;\n}"
          }
        ]
      }
    }
  };

  const xml = formatContextPackageXml(validPackage);
  assert.match(xml, /<callee symbol="validFn"/);
  assert.match(xml, /function validFn\(\)/);
  assert.doesNotMatch(xml, /status="untrusted"/);
});

// --------------------------------------------------------------------------
// 6. Thread tfxJj: SARIF Output with Null Consensus & Non-Zero Exit Code
// --------------------------------------------------------------------------

test("tfxJj NEGATIVE: CLI review with --format=sarif and --tier=0 produces valid SARIF without TypeError and non-zero exit", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();

  const changeSet = makeChangeSet([
    { path: "src/calc.js", additions: 5, deletions: 1 }
  ]);

  const mockAdapter = {
    executeReview: async () => ({
      ok: true,
      findings: [],
      coverage: { coveredFiles: ["src/calc.js"], omittedFiles: [] }
    })
  };

  // Provide reviewAdapters so orchestrateReview is invoked; --tier=0 triggers illegal tier failure
  // where consensus is null
  const exitCode = await runCli(["review", "--format=sarif", "--tier=0"], { stdout, stderr }, {
    getChangeSet: () => changeSet,
    reviewAdapters: { macro: mockAdapter }
  });

  // Pre-fix: threw TypeError: Cannot read properties of null (reading 'findings')
  // Post-fix: exits non-zero, outputs valid SARIF
  assert.notEqual(exitCode, 0, "Exit code must be non-zero on illegal tier failure");
  assert.equal(exitCode, EXIT_CODES.GATE_BLOCKED);

  assert.ok(stdout.buffer.trim().length > 0, "Stdout must contain SARIF JSON output");
  let parsedSarif = null;
  assert.doesNotThrow(() => {
    parsedSarif = JSON.parse(stdout.buffer);
  }, "Stdout must be valid JSON");

  assert.equal(parsedSarif.version, "2.1.0");
  assert.ok(Array.isArray(parsedSarif.runs));
  assert.equal(parsedSarif.runs.length, 1);
  const run = parsedSarif.runs[0];
  assert.ok(Array.isArray(run.results));
  assert.equal(run.results.length, 0);
  assert.ok(run.invocations);
  assert.equal(run.invocations[0].executionSuccessful, false);
  assert.match(run.invocations[0].toolExecutionNotifications[0].message.text, /INVALID_OR_DOWNGRADED_TIER/i);

  // Validate SARIF structural conformance
  const validationResult = validateSarifStructure(parsedSarif);
  assert.equal(validationResult.valid, true);
  assert.deepEqual(validationResult.errors, []);
});

test("tfxJj POSITIVE: CLI review with --format=sarif on approved review produces valid SARIF with exit code 0", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();

  // No changed files -> approved with exit code 0
  const emptyChangeSet = {
    ok: true,
    schemaVersion: "1.0.0",
    scopeMode: "working-tree",
    repository: { root: "/repo", hasHead: true, currentBranch: "main" },
    contentDigest: "abc123digest",
    totalFiles: 0,
    totalAdditions: 0,
    totalDeletions: 0,
    files: [],
    diffHunks: ""
  };

  const exitCode = await runCli(["review", "--format=sarif"], { stdout, stderr }, {
    getChangeSet: () => emptyChangeSet
  });

  assert.equal(exitCode, EXIT_CODES.SUCCESS);
  const parsedSarif = JSON.parse(stdout.buffer);
  assert.equal(parsedSarif.version, "2.1.0");
  const validationResult = validateSarifStructure(parsedSarif);
  assert.equal(validationResult.valid, true);
  assert.deepEqual(validationResult.errors, []);
});

// --------------------------------------------------------------------------
// 7. Advanced Boundary & Edge Case Verifications across All 6 Threads
// --------------------------------------------------------------------------

test("tfxJh NEGATIVE (USER REPRODUCED): External file named real-benchmark-runner.mjs outside repo fails closed against orchestrateReview", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-repro-"));
  const externalScript = path.join(tmpDir, "real-benchmark-runner.mjs");
  try {
    const orchestratorUrl = pathToFileURL(path.resolve("src/adapters/review-orchestrator.mjs")).href;
    const scriptCode = `
import { orchestrateReview } from ${JSON.stringify(orchestratorUrl)};

const changeSet = {
  ok: true,
  files: [{ path: "src/auth/jwt.js", additions: 10, deletions: 0 }],
  diffHunks: "+ export function verifyToken() {}"
};

const mockAdapter = {
  executeReview: async () => ({
    ok: true,
    findings: [],
    coverage: { coveredFiles: ["src/auth/jwt.js"], omittedFiles: [] }
  })
};

const res = await orchestrateReview(changeSet, { macro: mockAdapter }, {
  preliminary: true,
  plan: {
    mode: "single",
    highestRisk: 2,
    reason: "benchmark-single-reviewer"
  }
});

console.log(JSON.stringify({
  decision: res.gate?.decision,
  status: res.status,
  reason: res.gate?.reason,
  governanceAuthority: res.governanceAuthority
}));
`;
    fs.writeFileSync(externalScript, scriptCode, "utf8");

    const outStr = execFileSync(process.execPath, [externalScript], { encoding: "utf8" });
    const parsed = JSON.parse(outStr.trim());

    // Pre-fix: decision was 'approve', status was 'preliminary-clean'
    // Post-fix: decision is 'block', status is 'incomplete', reason matches INVALID_OR_DOWNGRADED_TIER
    assert.equal(parsed.decision, "block");
    assert.equal(parsed.status, "incomplete");
    assert.match(parsed.reason, /INVALID_OR_DOWNGRADED_TIER/i);
    assert.notEqual(parsed.status, "preliminary-clean");
    assert.notEqual(parsed.decision, "approve");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("tfxJh NEGATIVE: External caller using all canonical benchmark reasons fails closed against orchestrateReview", async () => {
  const changeSet = makeChangeSet([
    { path: "src/auth/jwt.js", additions: 10, deletions: 0 }
  ]);

  const mockAdapter = {
    executeReview: async () => ({
      ok: true,
      findings: [],
      coverage: { coveredFiles: ["src/auth/jwt.js"], omittedFiles: [] }
    })
  };

  const canonicalReasons = [
    "benchmark-single-reviewer",
    "benchmark-dual-heterogeneous",
    "benchmark-risk-routed:Modified high-risk security files",
    "benchmark-default-plan"
  ];

  for (const reason of canonicalReasons) {
    const res = await orchestrateReview(changeSet, { macro: mockAdapter }, {
      preliminary: true,
      plan: { mode: "single", highestRisk: 2, reason }
    });

    assert.equal(res.status, "incomplete", `Reason '${reason}' must fail closed with incomplete status`);
    assert.equal(res.gate.decision, "block", `Reason '${reason}' must fail closed with block decision`);
    assert.match(res.gate.reason, /INVALID_OR_DOWNGRADED_TIER/i);
    assert.notEqual(res.status, "preliminary-clean");
    assert.notEqual(res.gate.decision, "approve");
  }
});

test("tfxJh NEGATIVE: Direct call to orchestrateBenchmarkEvaluation without capability token or with forged token fails closed", async () => {
  const changeSet = makeChangeSet([
    { path: "src/auth/jwt.js", additions: 10, deletions: 0 }
  ]);

  const mockAdapter = {
    executeReview: async () => ({
      ok: true,
      findings: [],
      coverage: { coveredFiles: ["src/auth/jwt.js"], omittedFiles: [] }
    })
  };

  // 1. Missing capability token
  const resMissing = await orchestrateBenchmarkEvaluation(changeSet, { macro: mockAdapter }, {
    preliminary: true,
    plan: { mode: "single", highestRisk: 2, reason: "benchmark-single-reviewer" }
  });
  assert.equal(resMissing.status, "incomplete");
  assert.equal(resMissing.gate.decision, "block");
  assert.match(resMissing.gate.reason, /UNAUTHORIZED_BENCHMARK_EXECUTION/i);

  // 2. Forged fake capability token
  const resForged = await orchestrateBenchmarkEvaluation(changeSet, { macro: mockAdapter }, {
    preliminary: true,
    plan: { mode: "single", highestRisk: 2, reason: "benchmark-single-reviewer" },
    __internalBenchmarkCapability: { type: "INTERNAL_BENCHMARK_CAPABILITY", forged: true }
  });
  assert.equal(resForged.status, "incomplete");
  assert.equal(resForged.gate.decision, "block");
  assert.match(resForged.gate.reason, /UNAUTHORIZED_BENCHMARK_EXECUTION/i);
});

test("tfxJh POSITIVE: Genuine internal benchmark execution preserves clean benchmark execution and explicitly marks non-governance authority", async () => {
  // Vulnerable Tier 1 Case: BENCH-REAL-002
  const caseDefVulnerable = getCorpusCaseById("BENCH-REAL-002");
  assert.ok(caseDefVulnerable);
  const mockAdapters = createMockCorpusAdapters();
  const resVuln = await evaluateCorpusCase(caseDefVulnerable, mockAdapters, { mode: "single", virtual: true });
  assert.equal(resVuln.caseId, "BENCH-REAL-002");
  assert.equal(resVuln.evalResult.caughtGoldens, 1);
  assert.equal(resVuln.evalResult.passed, true);
  assert.equal(resVuln.actualGateDecision, "block");
  assert.equal(resVuln.promotionEligible, false);

  // Clean Tier 1 Case: BENCH-REAL-016
  const caseDefClean = getCorpusCaseById("BENCH-REAL-016");
  assert.ok(caseDefClean);
  const resClean = await evaluateCorpusCase(caseDefClean, mockAdapters, { mode: "single", virtual: true });
  assert.equal(resClean.caseId, "BENCH-REAL-016");
  assert.equal(resClean.isFalseBlock, false);
  assert.equal(resClean.preliminaryPassed, true);
  assert.equal(resClean.preliminaryGateDecision, "approve");
  assert.equal(resClean.promotionEligible, false);
});

test("tfxJh POSITIVE: Normal Tier 1 dual sentry review and Tier 2 single sentry review proceed without regression", async () => {
  const cleanTier1ChangeSet = makeChangeSet([
    { path: "src/auth/jwt.js", additions: 5, deletions: 1 }
  ]);

  const cleanAdapter = {
    executeReview: async () => ({
      ok: true,
      findings: [],
      providerIdentity: { provider: "claude", family: "anthropic", model: "claude-3-5-sonnet", transport: "cli" },
      coverage: { coveredFiles: ["src/auth/jwt.js"], omittedFiles: [] }
    })
  };
  const cleanMicroAdapter = {
    executeReview: async () => ({
      ok: true,
      findings: [],
      providerIdentity: { provider: "agy", family: "google", model: "gemini-3.8-flash", transport: "cli" },
      coverage: { coveredFiles: ["src/auth/jwt.js"], omittedFiles: [] }
    })
  };

  // 1. Tier 1 Dual Sentry (Hierarchical)
  const resTier1 = await orchestrateReview(cleanTier1ChangeSet, {
    macro: cleanAdapter,
    micro: cleanMicroAdapter
  }, {
    preliminary: true
  });
  assert.equal(resTier1.status, "preliminary-clean");
  assert.equal(resTier1.gate.decision, "approve");

  // 2. Tier 2 Single Sentry (Single)
  const cleanTier2ChangeSet = makeChangeSet([
    { path: "src/utils/calc.js", additions: 5, deletions: 1 }
  ]);
  const cleanT2Adapter = {
    executeReview: async () => ({
      ok: true,
      findings: [],
      providerIdentity: { provider: "agy", family: "google", model: "gemini-3.8-flash", transport: "cli" },
      coverage: { coveredFiles: ["src/utils/calc.js"], omittedFiles: [] }
    })
  };
  const resTier2 = await orchestrateReview(cleanTier2ChangeSet, {
    macro: cleanT2Adapter
  }, {
    preliminary: true,
    plan: { mode: "single", highestRisk: 2 }
  });
  assert.equal(resTier2.status, "preliminary-clean");
  assert.equal(resTier2.gate.decision, "approve");
});

test("tfxJh NEGATIVE: Illegal tier and plan options fail closed", async () => {
  const changeSet = makeChangeSet();
  const mockAdapter = {
    executeReview: async () => ({ ok: true, findings: [], coverage: { coveredFiles: ["src/sample.js"], omittedFiles: [] } })
  };

  // tier: 0
  const res0 = await orchestrateReview(changeSet, { macro: mockAdapter }, { tier: 0 });
  assert.equal(res0.status, "incomplete");
  assert.equal(res0.gate.decision, "block");

  // tier: 5
  const res5 = await orchestrateReview(changeSet, { macro: mockAdapter }, { tier: 5 });
  assert.equal(res5.status, "incomplete");
  assert.equal(res5.gate.decision, "block");

  // invalid plan.highestRisk
  const resPlanRisk = await orchestrateReview(changeSet, { macro: mockAdapter }, {
    plan: { mode: "single", highestRisk: 0 }
  });
  assert.equal(resPlanRisk.status, "incomplete");
  assert.equal(resPlanRisk.gate.decision, "block");

  // invalid plan.mode
  const resPlanMode = await orchestrateReview(changeSet, { macro: mockAdapter }, {
    plan: { mode: "swarm_custom", highestRisk: 2 }
  });
  assert.equal(resPlanMode.status, "incomplete");
  assert.equal(resPlanMode.gate.decision, "block");
});

test("tfxJn NEGATIVE: Nested options.options with conflicting patchObjective fails closed", async () => {
  const changeSet = makeChangeSet();
  const mockAdapter = {
    executeReview: async () => ({ ok: true, findings: [], coverage: { coveredFiles: ["src/sample.js"], omittedFiles: [] } })
  };

  const res = await orchestrateReview(changeSet, { macro: mockAdapter }, {
    patchObjective: "Canonical Fix",
    options: {
      patchObjective: "Canonical Fix",
      options: {
        patchObjective: "Contradictory Fix"
      }
    }
  });

  assert.equal(res.status, "incomplete");
  assert.equal(res.gate.decision, "block");
  assert.match(res.gate.reason, /EXCLUSION_OR_OBJECTIVE_MISMATCH|objective mismatch/i);
});

test("tfxJn POSITIVE: Case-insensitive and trimmed whitespace objective matching succeeds", async () => {
  const changeSet = makeChangeSet([
    { path: "src/calc.js", additions: 2, deletions: 1 }
  ]);
  changeSet.patchObjective = "  Fix Null Pointer Exception  ";

  let capturedInput = null;
  const mockAdapter = {
    executeReview: async (input) => {
      capturedInput = input;
      return { ok: true, findings: [], coverage: { coveredFiles: ["src/calc.js"], omittedFiles: [] } };
    }
  };

  const res = await orchestrateReview(changeSet, { macro: mockAdapter }, {
    patchObjective: "fix null pointer exception",
    preliminary: true
  });

  assert.equal(res.status, "preliminary-clean");
  assert.equal(res.gate.decision, "approve");
  assert.ok(capturedInput);
  assert.equal(capturedInput.patchObjective.toLowerCase().trim(), "fix null pointer exception");
});

test("tfxJq POSITIVE: Optional chaining with whitespace extracts receiver qualifier correctly", () => {
  const diffHunks = [
    "@@ -10,3 +10,4 @@",
    "+  auth   ?.   authorize(user);"
  ].join("\n");

  const candidates = extractCandidateCallSymbols(diffHunks);
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].symbol, "authorize");
  assert.equal(candidates[0].qualifier, "auth");
  assert.equal(candidates[0].isQualified, true);
});

test("tfxJq COUNTEREXAMPLE & FIX: Qualified call with non-identifier receiver does not bind to bare function", () => {
  const diffHunks = [
    "@@ -5,3 +5,4 @@",
    " function handle() {",
    "+  (auth)?.authorize(user);",
    " }"
  ].join("\n");

  const fileContent = [
    "function authorize() { return false; }",
    "function handle() { (auth)?.authorize(user); }"
  ].join("\n");

  const res = extractLocalCalleeContext(fileContent, diffHunks, "src/handler.js");
  assert.equal(res.callees.length, 0, "Must not bind qualified (auth)?.authorize to local bare function authorize");
  const unresolved = res.unresolvedCallees.find(u => u.symbol === "authorize");
  assert.ok(unresolved);
  assert.equal(unresolved.reason, "EXTERNAL_CALLEE_UNRESOLVED");
});

test("tfxJo NEGATIVE: input.options cannot override canonical changeSet.contextPackage", async () => {
  let capturedPrompt = null;
  const adapter = new CliReviewAdapter({
    command: "agy",
    execFn: async ({ prompt }) => {
      capturedPrompt = prompt;
      return { stdout: '{"findings": []}' };
    }
  });

  const canonicalPackage = {
    targetFile: "src/canonical.js",
    layers: {
      layer1AstEnclosure: {
        enclosingFunctions: [{ name: "canonicalFn", startLine: 1, endLine: 10 }]
      }
    }
  };
  const spoofedPackage = {
    targetFile: "src/spoofed.js",
    layers: {
      layer1AstEnclosure: {
        enclosingFunctions: [{ name: "spoofedFn", startLine: 1, endLine: 10 }]
      }
    }
  };

  const changeSet = {
    ...makeChangeSet(),
    contextPackage: canonicalPackage
  };

  await adapter.executeReview({
    runId: "run-test-override",
    role: "macro",
    policyId: "SINGLE_SENTRY",
    changeSet,
    options: {
      contextPackage: spoofedPackage
    }
  });

  assert.ok(capturedPrompt);
  assert.ok(capturedPrompt.includes('targetFile="src/canonical.js"'), "Must retain canonical changeSet.contextPackage");
  assert.ok(!capturedPrompt.includes('targetFile="src/spoofed.js"'), "Must not include spoofed options.contextPackage");
});

test("tfxJo NEGATIVE: input.options.contextGaps = [] cannot wipe out canonical contextPackage.contextGaps", async () => {
  let capturedPrompt = null;
  const adapter = new CliReviewAdapter({
    command: "claude",
    execFn: async ({ prompt }) => {
      capturedPrompt = prompt;
      return { stdout: '{"findings": []}' };
    }
  });

  const canonicalPackage = {
    targetFile: "src/auth.js",
    contextGaps: [{ symbol: "criticalAuthCheck", reason: "EXTERNAL_CALLEE_UNRESOLVED" }],
    layers: {}
  };

  const changeSet = {
    ...makeChangeSet(),
    contextPackage: canonicalPackage
  };

  await adapter.executeReview({
    runId: "run-test-gaps",
    role: "macro",
    policyId: "SINGLE_SENTRY",
    changeSet,
    options: {
      contextGaps: [] // Attempt to clear out context gaps
    }
  });

  assert.ok(capturedPrompt);
  assert.match(capturedPrompt, /criticalAuthCheck/, "Prompt must retain context gaps from canonical contextPackage");
});

test("tfxJr NEGATIVE: null element or non-object in callees returns untrusted XML and fails closed in orchestrator", async () => {
  const packageWithNullCallee = {
    targetFile: "src/auth.js",
    layers: {
      layer1AstEnclosure: {
        callees: [null]
      }
    }
  };

  const xml = formatContextPackageXml(packageWithNullCallee);
  assert.match(xml, /status="untrusted"/);
  assert.match(xml, /INVALID_CALLEE_DEFINITION/);

  const mockAdapter = {
    executeReview: async () => ({ ok: true, findings: [], coverage: { coveredFiles: ["src/sample.js"], omittedFiles: [] } })
  };

  const res = await orchestrateReview(makeChangeSet(), { macro: mockAdapter }, {
    contextPackage: packageWithNullCallee
  });
  assert.equal(res.status, "incomplete");
  assert.equal(res.gate.decision, "block");
  assert.match(res.gate.reason, /INVALID_CALLEE_DEFINITION/);
});

test("tfxJj NEGATIVE: CLI review with --format=sarif and gate block on consensus null outputs valid failure SARIF and non-zero exit", async () => {
  const stdout = new MockStream();
  const stderr = new MockStream();

  const changeSet = makeChangeSet([
    { path: "src/calc.js", additions: 2, deletions: 1 }
  ]);
  const mockAdapter = {
    executeReview: async () => ({
      ok: true,
      findings: [],
      coverage: { coveredFiles: ["src/calc.js"], omittedFiles: [] }
    })
  };

  const exitCode = await runCli(["review", "--format=sarif", "--tier=5"], { stdout, stderr }, {
    getChangeSet: () => changeSet,
    reviewAdapters: { macro: mockAdapter }
  });

  assert.notEqual(exitCode, 0, "Must exit non-zero on gate blocked");
  assert.equal(exitCode, EXIT_CODES.GATE_BLOCKED);

  const sarif = JSON.parse(stdout.buffer);
  assert.equal(sarif.version, "2.1.0");
  assert.equal(sarif.runs[0].invocations[0].executionSuccessful, false);
  const validationResult = validateSarifStructure(sarif);
  assert.equal(validationResult.valid, true);
});
