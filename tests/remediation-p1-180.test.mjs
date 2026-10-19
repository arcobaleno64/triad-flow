import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

import {
  conductIndependentVerification,
  isTrustedVerificationRecord,
  isSegregatedSyntheticRecord,
  createMockVerifierAdapter
} from "../src/core/independent-verifier.mjs";
import {
  evaluateGateDecision,
  evaluatePostVerificationGate,
  evaluateIsolatedTestPostVerificationGate,
  RunContext
} from "../src/core/harness.mjs";
import {
  extractCandidateCallSymbols,
  extractLocalCalleeContext,
  findCallInvocations
} from "../src/core/context-builder.mjs";
import { runDogfoodReview } from "../scripts/dogfood-review.mjs";
import { aggregateConsensus } from "../src/core/loop.mjs";
import { isTrustedConsensus } from "../src/core/consensus-state.mjs";
import { CliReviewAdapter } from "../src/adapters/cli-transport.mjs";
import { computeDigest } from "../src/core/canonical-digest.mjs";

const TEST_HEAD_SHA = "a1dde481db4a4725e7ac5ca0f80d0ea605468cde";

// Helper: build authentic trusted consensus
function createTrustedConsensus(findings = [], { tier = 2, quorumReached = true } = {}) {
  const agyFindings = [];
  const claudeFindings = [];
  const codexFindings = [];

  for (const f of findings) {
    const rawF = {
      ...f,
      id: f.id || f.findingId,
      title: f.title,
      severity: f.severity,
      file: f.file,
      line_start: f.line_start || f.line || 1
    };
    const sources = Array.isArray(f.sources) && f.sources.length > 0
      ? f.sources
      : (f.corroborations >= 2 ? ["agy", "claude"] : ["codex"]);

    if (sources.includes("agy")) agyFindings.push(rawF);
    if (sources.includes("claude")) claudeFindings.push(rawF);
    if (sources.includes("codex")) codexFindings.push(rawF);
  }

  const reports = {
    agy: {
      provider: "agy",
      executionStatus: quorumReached === false ? "timeout" : "success",
      error: quorumReached === false ? "TIMEOUT" : undefined,
      fileCoverageComplete: true,
      findings: agyFindings
    },
    claude: {
      provider: "claude",
      executionStatus: quorumReached === false ? "timeout" : "success",
      error: quorumReached === false ? "TIMEOUT" : undefined,
      fileCoverageComplete: true,
      findings: claudeFindings
    },
    codex: {
      provider: "codex",
      executionStatus: quorumReached === false ? "timeout" : "success",
      error: quorumReached === false ? "TIMEOUT" : undefined,
      fileCoverageComplete: true,
      findings: codexFindings
    }
  };

  return aggregateConsensus(reports, { tier, policy: "TRI_PARTY_HETEROGENEOUS" });
}

// ============================================================================
// Thread trycn: Trusted Gate Bypass Prevention with Security Context Gaps
// ============================================================================

test("trycn-NEGATIVE: conductIndependentVerification trusted record with DEFECTS_FOUND, Supported Low Omission, and Security Context Gap must refuse approve in Tier 2 Gate", async () => {
  const diffHunks = "@@ -1,2 +1,3 @@\n {\n-  \"name\": \"triad-flow-prev\"\n+  \"name\": \"triad-flow\"\n }\n";
  const digest = computeDigest(diffHunks);
  const changeSet = {
    headSha: TEST_HEAD_SHA,
    diffHunks,
    contentDigest: digest,
    files: [{ path: "package.json", additions: 1, deletions: 1, riskTier: 2 }]
  };

  const securityGap = {
    code: "EXTERNAL_CALLEE_UNRESOLVED",
    symbol: "authorize",
    qualifier: "auth",
    category: "security",
    reason: "EXTERNAL_CALLEE_UNRESOLVED",
    impact: "Referenced qualified callee 'auth.authorize' definition not found in modified file on sensitive execution path",
    file: "package.json",
    line: 2
  };

  // Verifier adapter returns DEFECTS_FOUND with one Supported Low omission
  const mockAdapter = {
    providerName: "claude",
    modelName: "claude-3-5-sonnet",
    executeVerification: async () => ({
      ok: true,
      executionStatus: "success",
      overallStatus: "DEFECTS_FOUND",
      evaluations: [],
      verifierOmissions: [
        {
          findingId: "omission-1",
          title: "Advisory format notice in package configuration",
          severity: "low",
          evidenceSupport: "SUPPORTED",
          objectiveImpact: "NOT_ASSESSED",
          locatorAccurate: true,
          file: "package.json",
          line: 2,
          counterexample: "validate(null) throws TypeError when called",
          reasoning: "Observable counterexample: calling validate(null) throws TypeError when passed."
        }
      ]
    })
  };

  // Use actual conductIndependentVerification to create authentic in-process trusted record
  const record = await conductIndependentVerification(changeSet, [], mockAdapter, {
    verificationMode: "clean_challenge",
    headSha: TEST_HEAD_SHA,
    changeSetDigest: digest,
    contextGaps: [securityGap]
  });

  // Verify authentic trusted record invariants
  assert.strictEqual(isTrustedVerificationRecord(record), true, "Must be an authentic trusted verification record");
  assert.strictEqual(isSegregatedSyntheticRecord(record), false, "Must not be segregated synthetic");
  assert.strictEqual(record.overallStatus, "DEFECTS_FOUND", "Overall status must reflect DEFECTS_FOUND from omission");
  assert.ok(Array.isArray(record.contextGaps) && record.contextGaps.length >= 1, "Record must preserve contextGaps");

  // Create trusted clean consensus (0 findings)
  const consensus = createTrustedConsensus([], { tier: 2, quorumReached: true });
  assert.strictEqual(isTrustedConsensus(consensus), true, "Consensus must possess trusted capability");

  const runContext = new RunContext({ headSha: TEST_HEAD_SHA, contentDigest: digest });

  // Formally evaluate Gate decision
  const gateTier2 = evaluatePostVerificationGate(consensus, record, { tier: 2, runContext });
  assert.notStrictEqual(gateTier2.decision, "approve", "Formal Tier 2 Gate must NEVER approve when unresolved Security Context Gap exists");
  assert.strictEqual(gateTier2.decision, "human_review_required", "Tier 2 Gate must require human review for unresolved Security Context Gap");
  assert.match(gateTier2.reason, /Security Context Gap/, "Gate reason must identify Security Context Gap");

  // Tier 1 Gate must refuse approve and block under Tier 1 high-risk policy
  const gateTier1 = evaluatePostVerificationGate(consensus, record, { tier: 1, runContext });
  assert.notStrictEqual(gateTier1.decision, "approve", "Tier 1 Gate must refuse approve when unresolved Security Context Gap exists");
  assert.strictEqual(gateTier1.decision, "block", "Tier 1 Gate must block when unresolved Security Context Gap exists under Tier 1 high-risk policy");
  assert.match(gateTier1.reason, /Security Context Gap|Tier 1 high-risk policy/, "Gate reason must identify Security Context Gap or Tier 1 policy");

  // evaluateGateDecision must also enforce this
  const gateViaWrapper = evaluateGateDecision(consensus, { verificationRecord: record, tier: 2, runContext });
  assert.strictEqual(gateViaWrapper.decision, "human_review_required", "evaluateGateDecision wrapper must refuse approve");
});

test("trycn-NEGATIVE-CLEAN-VERIFIER: Security Context Gap with Verifier returning CLEAN downgrades to UNCERTAIN and refuses approve", async () => {
  const diffHunks = "@@ -1,2 +1,3 @@\n function handle(user) {\n-  return false;\n+  return auth.authorize(user);\n }\n";
  const digest = computeDigest(diffHunks);
  const changeSet = {
    headSha: TEST_HEAD_SHA,
    diffHunks,
    contentDigest: digest,
    files: [{ path: "src/auth.js", additions: 1, deletions: 1, riskTier: 2 }]
  };

  const securityGap = {
    code: "EXTERNAL_CALLEE_UNRESOLVED",
    symbol: "authorize",
    qualifier: "auth",
    category: "security",
    reason: "EXTERNAL_CALLEE_UNRESOLVED"
  };

  const mockCleanAdapter = {
    providerName: "claude",
    modelName: "claude-3-5-sonnet",
    executeVerification: async () => ({
      ok: true,
      executionStatus: "success",
      overallStatus: "CLEAN",
      evaluations: [],
      verifierOmissions: []
    })
  };

  const record = await conductIndependentVerification(changeSet, [], mockCleanAdapter, {
    verificationMode: "clean_challenge",
    headSha: TEST_HEAD_SHA,
    changeSetDigest: digest,
    contextGaps: [securityGap]
  });

  assert.strictEqual(isTrustedVerificationRecord(record), true);
  assert.strictEqual(record.overallStatus, "UNCERTAIN", "Context gap must downgrade CLEAN verifier output to UNCERTAIN");

  const consensus = createTrustedConsensus([], { tier: 2, quorumReached: true });
  const gate = evaluatePostVerificationGate(consensus, record, { tier: 2 });
  assert.strictEqual(gate.decision, "human_review_required", "Tier 2 Gate must require human review");
});

test("trycn-POSITIVE: Supported Low Omission WITHOUT Security Context Gap approves in Tier 2 as Advisory (not globally blocked)", async () => {
  const diffHunks = "@@ -1,2 +1,3 @@\n {\n-  \"name\": \"triad-flow-prev\"\n+  \"name\": \"triad-flow\"\n }\n";
  const digest = computeDigest(diffHunks);
  const changeSet = {
    headSha: TEST_HEAD_SHA,
    diffHunks,
    contentDigest: digest,
    files: [{ path: "package.json", additions: 1, deletions: 1, riskTier: 2 }]
  };

  // Verifier adapter returns DEFECTS_FOUND with one Supported Low omission, NO context gaps
  const mockAdapter = {
    providerName: "claude",
    modelName: "claude-3-5-sonnet",
    executeVerification: async () => ({
      ok: true,
      executionStatus: "success",
      overallStatus: "DEFECTS_FOUND",
      evaluations: [],
      verifierOmissions: [
        {
          findingId: "omission-1",
          title: "Advisory format notice in package configuration",
          severity: "low",
          evidenceSupport: "SUPPORTED",
          objectiveImpact: "NOT_ASSESSED",
          locatorAccurate: true,
          file: "package.json",
          line: 2,
          counterexample: "validate(null) throws TypeError when called",
          reasoning: "Observable counterexample: calling validate(null) throws TypeError when passed."
        }
      ]
    })
  };

  const record = await conductIndependentVerification(changeSet, [], mockAdapter, {
    verificationMode: "clean_challenge",
    headSha: TEST_HEAD_SHA,
    changeSetDigest: digest
  });

  assert.strictEqual(isTrustedVerificationRecord(record), true);
  assert.strictEqual(record.overallStatus, "DEFECTS_FOUND");
  assert.strictEqual(record.contextGaps, undefined, "No context gaps should be present");

  const runContext = new RunContext({ headSha: TEST_HEAD_SHA, contentDigest: digest });
  const consensus = createTrustedConsensus([], { tier: 2, quorumReached: true });
  const gateTier2 = evaluatePostVerificationGate(consensus, record, { tier: 2, runContext });
  assert.strictEqual(gateTier2.decision, "approve", "Positive control: Supported Low omission without context gaps must approve in Tier 2");
  assert.strictEqual(gateTier2.advisoryFindings.length, 1, "Low omission must be recorded as advisory");
});

// ============================================================================
// Thread tryci: Dogfood Gap Propagation from ChangeSet.contextGaps
// ============================================================================

test("tryci-NEGATIVE-REPRODUCTION: changeSet.contextGaps propagates to Sentry, Staged Fallback, and Clean Challenge in runDogfoodReview", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-tryci-"));
  const tmpOut = path.join(tmpDir, "dogfood-run.json");

  const gapSymbol = "customAuthorizeGuard";
  const initialGap = {
    code: "EXTERNAL_CALLEE_UNRESOLVED",
    symbol: gapSymbol,
    qualifier: "auth",
    category: "security",
    reason: "EXTERNAL_CALLEE_UNRESOLVED",
    file: "src/index.js",
    line: 1
  };

  const diffHunks = "+ const a = auth.customAuthorizeGuard();";
  const digest = crypto.createHash("sha256").update(diffHunks, "utf8").digest("hex");

  const changeSet = {
    ok: true,
    schemaVersion: "1.0.0",
    repository: { name: "test/repo", headSha: TEST_HEAD_SHA, root: process.cwd() },
    headSha: TEST_HEAD_SHA,
    head: TEST_HEAD_SHA,
    contentDigest: digest,
    totalFiles: 1,
    totalAdditions: 1,
    totalDeletions: 0,
    files: [{ path: "src/index.js", additions: 1, deletions: 0, riskTier: 2 }],
    diffHunks,
    contextGaps: [initialGap]
  };

  let capturedAgyGaps = null;
  let capturedClaudeGaps = null;
  let capturedCodexGaps = null;
  let capturedVerifierGaps = null;

  const reviewAdapters = {
    agy: new CliReviewAdapter({
      command: "agy",
      providerName: "agy",
      family: "google",
      modelName: "gemini-3.8-flash",
      execFn: async ({ input }) => {
        capturedAgyGaps = input?.contextGaps;
        return {
          stdout: JSON.stringify({
            findings: [],
            coverage: { coveredFiles: ["src/index.js"], omittedFiles: [] }
          })
        };
      }
    }),
    claude: new CliReviewAdapter({
      command: "claude",
      providerName: "claude",
      family: "anthropic",
      modelName: "claude-5.5-sonnet",
      execFn: async ({ input }) => {
        capturedClaudeGaps = input?.contextGaps;
        return {
          stdout: JSON.stringify({
            findings: [],
            coverage: { coveredFiles: ["src/index.js"], omittedFiles: [] }
          })
        };
      }
    }),
    codex: new CliReviewAdapter({
      command: "codex",
      providerName: "codex",
      family: "openai",
      modelName: "gpt-6.1-sol",
      execFn: async ({ input }) => {
        capturedCodexGaps = input?.contextGaps;
        return {
          stdout: JSON.stringify({
            findings: [],
            coverage: { coveredFiles: ["src/index.js"], omittedFiles: [] }
          })
        };
      }
    })
  };

  const verifierAdapter = {
    providerName: "claude",
    modelName: "claude-3-5-sonnet",
    executeVerification: async (input) => {
      capturedVerifierGaps = input.contextGaps;
      return {
        ok: true,
        executionStatus: "success",
        overallStatus: "CLEAN",
        evaluations: [],
        verifierOmissions: []
      };
    }
  };

  try {
    const report = await runDogfoodReview({
      mock: false,
      changeSet,
      reviewAdapters,
      verifierAdapter,
      out: tmpOut,
      log: false
    });

    // Verify Sentry reviewers received the gap from changeSet.contextGaps
    assert.ok(Array.isArray(capturedAgyGaps), "Agy sentry must receive contextGaps");
    assert.ok(capturedAgyGaps.some(g => g.symbol === gapSymbol), "Agy sentry must receive changeSet.contextGaps");

    assert.ok(Array.isArray(capturedClaudeGaps), "Claude sentry must receive contextGaps");
    assert.ok(capturedClaudeGaps.some(g => g.symbol === gapSymbol), "Claude sentry must receive changeSet.contextGaps");

    assert.ok(Array.isArray(capturedCodexGaps), "Codex sentry must receive contextGaps");
    assert.ok(capturedCodexGaps.some(g => g.symbol === gapSymbol), "Codex sentry must receive changeSet.contextGaps");

    // Verify Clean Challenge verifier received the gap from changeSet.contextGaps
    assert.ok(Array.isArray(capturedVerifierGaps), "Clean challenge verifier must receive contextGaps");
    assert.ok(capturedVerifierGaps.some(g => g.symbol === gapSymbol), "Verifier must receive changeSet.contextGaps");

    // Verify final gate decision reflects uncertainty from the gap
    assert.notStrictEqual(report.gate.decision, "approve", "Gate must not approve with unresolved Security Context Gap");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("tryci-NEGATIVE-EMPTY-CALLER-OPTIONS: Explicitly passing options.contextGaps = [] does not wipe out changeSet.contextGaps in Dogfood", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-tryci-empty-"));
  const tmpOut = path.join(tmpDir, "dogfood-run.json");

  const gapSymbol = "resilientTokenValidation";
  const diffHunks = "+ const ok = auth.resilientTokenValidation();";
  const digest = crypto.createHash("sha256").update(diffHunks, "utf8").digest("hex");

  const changeSet = {
    ok: true,
    schemaVersion: "1.0.0",
    repository: { name: "test/repo", headSha: TEST_HEAD_SHA, root: process.cwd() },
    headSha: TEST_HEAD_SHA,
    head: TEST_HEAD_SHA,
    contentDigest: digest,
    totalFiles: 1,
    totalAdditions: 1,
    totalDeletions: 0,
    files: [{ path: "src/index.js", additions: 1, deletions: 0, riskTier: 2 }],
    diffHunks,
    contextGaps: [{
      code: "EXTERNAL_CALLEE_UNRESOLVED",
      symbol: gapSymbol,
      category: "security",
      reason: "EXTERNAL_CALLEE_UNRESOLVED"
    }]
  };

  let capturedAgyGaps = null;
  const reviewAdapters = {
    agy: new CliReviewAdapter({
      command: "agy",
      providerName: "agy",
      family: "google",
      modelName: "gemini-3.8-flash",
      execFn: async ({ input }) => {
        capturedAgyGaps = input?.contextGaps;
        return {
          stdout: JSON.stringify({
            findings: [],
            coverage: { coveredFiles: ["src/index.js"], omittedFiles: [] }
          })
        };
      }
    }),
    claude: new CliReviewAdapter({
      command: "claude",
      providerName: "claude",
      family: "anthropic",
      modelName: "claude-5.5-sonnet",
      execFn: async () => ({
        stdout: JSON.stringify({
          findings: [],
          coverage: { coveredFiles: ["src/index.js"], omittedFiles: [] }
        })
      })
    }),
    codex: new CliReviewAdapter({
      command: "codex",
      providerName: "codex",
      family: "openai",
      modelName: "gpt-6.1-sol",
      execFn: async () => ({
        stdout: JSON.stringify({
          findings: [],
          coverage: { coveredFiles: ["src/index.js"], omittedFiles: [] }
        })
      })
    })
  };

  try {
    await runDogfoodReview({
      mock: false,
      changeSet,
      reviewAdapters,
      contextGaps: [], // Explicitly passing empty array
      cleanChallenge: false,
      out: tmpOut,
      log: false
    });

    assert.ok(Array.isArray(capturedAgyGaps), "Agy sentry must receive contextGaps");
    assert.ok(capturedAgyGaps.some(g => g.symbol === gapSymbol), "Passing contextGaps: [] must not wipe out changeSet.contextGaps");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

// ============================================================================
// Thread trycg: Conservative Generic Sensitive Call Identification
// ============================================================================

test("trycg-NEGATIVE-REPRODUCTION: auth.authorize<Session>(user) extracts candidate and records EXTERNAL_CALLEE_UNRESOLVED security context gap", () => {
  const diffHunks = "@@ -2,2 +2,3 @@\n function handle(user) {\n-  return false;\n+  return auth.authorize<Session>(user);\n }\n";
  const fileContent = "import { auth } from './auth.mjs';\nfunction handle(user) {\n  return auth.authorize<Session>(user);\n}\n";

  // 1. extractCandidateCallSymbols must recognize generic call
  const candidates = extractCandidateCallSymbols(diffHunks);
  assert.strictEqual(candidates.length, 1, "Candidate call must be extracted for auth.authorize<Session>(user)");
  assert.strictEqual(candidates[0].symbol, "authorize");
  assert.strictEqual(candidates[0].qualifier, "auth");
  assert.strictEqual(candidates[0].isSensitive, true);
  assert.strictEqual(candidates[0].category, "security");
  assert.strictEqual(candidates[0].hasTypeArguments, true);

  // 2. extractLocalCalleeContext must record Security Context Gap
  const calleeCtx = extractLocalCalleeContext(fileContent, diffHunks, "src/handler.ts");
  assert.strictEqual(calleeCtx.contextGaps.length, 1, "Context gap must be generated for unresolvable generic call");
  assert.strictEqual(calleeCtx.contextGaps[0].symbol, "authorize");
  assert.strictEqual(calleeCtx.contextGaps[0].qualifier, "auth");
  assert.strictEqual(calleeCtx.contextGaps[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");
  assert.strictEqual(calleeCtx.contextGaps[0].category, "security");
});

test("trycg-NEGATIVE-BARE-GENERIC: bare authorizeUser<Session>(user) extracts candidate and records EXTERNAL_CALLEE_UNRESOLVED security context gap", () => {
  const diffHunks = "@@ -2,2 +2,3 @@\n function handle(user) {\n-  return false;\n+  return authorizeUser<Session>(user);\n }\n";
  const fileContent = "import { authorizeUser } from './auth.mjs';\nfunction handle(user) {\n  return authorizeUser<Session>(user);\n}\n";

  const candidates = extractCandidateCallSymbols(diffHunks);
  assert.strictEqual(candidates.length, 1, "Candidate call must be extracted for authorizeUser<Session>(user)");
  assert.strictEqual(candidates[0].symbol, "authorizeUser");
  assert.strictEqual(candidates[0].qualifier, null);
  assert.strictEqual(candidates[0].isSensitive, true);
  assert.strictEqual(candidates[0].category, "security");
  assert.strictEqual(candidates[0].hasTypeArguments, true);

  const calleeCtx = extractLocalCalleeContext(fileContent, diffHunks, "src/handler.ts");
  assert.strictEqual(calleeCtx.contextGaps.length, 1, "Context gap must be generated for unresolvable bare generic call");
  assert.strictEqual(calleeCtx.contextGaps[0].symbol, "authorizeUser");
  assert.strictEqual(calleeCtx.contextGaps[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");
  assert.strictEqual(calleeCtx.contextGaps[0].category, "security");
});

test("trycg-NEGATIVE-MULTI-TYPE-PARAMS: multi-type arguments and nested generics are recognized and bound", () => {
  const diffHunks = "@@ -2,2 +2,4 @@\n function handle(user) {\n-  return false;\n+  auth.authorize<Session, Permissions>(user);\n+  auth.verify<Map<string, number>>(data);\n }\n";

  const candidates = extractCandidateCallSymbols(diffHunks);
  assert.strictEqual(candidates.length, 2, "Both multi-type generic calls must be extracted");
  assert.strictEqual(candidates[0].symbol, "authorize");
  assert.strictEqual(candidates[0].hasTypeArguments, true);
  assert.strictEqual(candidates[1].symbol, "verify");
  assert.strictEqual(candidates[1].hasTypeArguments, true);
});

test("trycg-OPTIONAL-CHAINING-GENERIC: auth.authorize?.<Session>(user) and auth.authorize<Session>?.(user) are extracted", () => {
  const diffA = "@@ -1,1 +1,2 @@\n+ return auth.authorize?.<Session>(user);\n";
  const candidatesA = extractCandidateCallSymbols(diffA);
  assert.strictEqual(candidatesA.length, 1);
  assert.strictEqual(candidatesA[0].symbol, "authorize");
  assert.strictEqual(candidatesA[0].qualifier, "auth");
  assert.strictEqual(candidatesA[0].hasTypeArguments, true);

  const diffB = "@@ -1,1 +1,2 @@\n+ return auth.authorize<Session>?.(user);\n";
  const candidatesB = extractCandidateCallSymbols(diffB);
  assert.strictEqual(candidatesB.length, 1);
  assert.strictEqual(candidatesB[0].symbol, "authorize");
  assert.strictEqual(candidatesB[0].qualifier, "auth");
  assert.strictEqual(candidatesB[0].hasTypeArguments, true);
});

test("trycg-POSITIVE-STANDARD-CALL: standard non-generic call auth.authorize(user) behaves identically", () => {
  const diffHunks = "@@ -2,2 +2,3 @@\n function handle(user) {\n-  return false;\n+  return auth.authorize(user);\n }\n";
  const candidates = extractCandidateCallSymbols(diffHunks);
  assert.strictEqual(candidates.length, 1);
  assert.strictEqual(candidates[0].symbol, "authorize");
  assert.strictEqual(candidates[0].hasTypeArguments, false);
});

test("trycg-POSITIVE-LOCAL-DEFINITION: resolved generic method in same file emits 0 context gaps", () => {
  const diffHunks = "@@ -7,2 +7,3 @@\n function handle(user) {\n-  return false;\n+  return auth.authorize<Session>(user);\n }\n";
  const fileContent = [
    "class Auth {",
    "  authorize<Session>(user: Session) {",
    "    return true;",
    "  }",
    "}",
    "const auth = new Auth();",
    "function handle(user) {",
    "  return auth.authorize<Session>(user);",
    "}"
  ].join("\n");

  const calleeCtx = extractLocalCalleeContext(fileContent, diffHunks, "src/auth.ts");
  assert.strictEqual(calleeCtx.callees.length, 1, "Callee definition should be resolved locally");
  assert.strictEqual(calleeCtx.callees[0].symbol, "authorize");
  assert.strictEqual(calleeCtx.contextGaps.length, 0, "No context gaps should be emitted when definition is resolved");
});

test("trycg-POSITIVE-NON-CALL-EXPRESSIONS: comparison operators and comments do not emit false call candidates", () => {
  const diffHunks = [
    "@@ -1,1 +1,5 @@",
    "+ if (a < b && c > (d)) { return; }",
    "+ // auth.authorize<Session>(user)",
    "+ /* authorizeUser<Session>(user) */",
    "+ const str = \"auth.authorize<Session>(user)\";"
  ].join("\n");

  const candidates = extractCandidateCallSymbols(diffHunks);
  assert.strictEqual(candidates.length, 0, "Comparison operators, comments, and strings must not emit false call candidates");
});

test("trycg-NEGATIVE-ARROW-FUNCTION-TYPE: auth.authorize<(x: string) => boolean>(user) and auth.authorize<() => void>(user) extract candidate and record gap", () => {
  const diffHunks = "@@ -2,2 +2,4 @@\n function handle(user) {\n-  return false;\n+  auth.authorize<(x: string) => boolean>(user);\n+  auth.authorize<() => void>(user);\n }\n";
  const fileContent = "import { auth } from './auth.mjs';\nfunction handle(user) {\n  auth.authorize<(x: string) => boolean>(user);\n  auth.authorize<() => void>(user);\n}\n";

  const candidates = extractCandidateCallSymbols(diffHunks);
  assert.strictEqual(candidates.length, 1, "authorize candidate must be extracted for arrow function type args");
  assert.strictEqual(candidates[0].symbol, "authorize");
  assert.strictEqual(candidates[0].qualifier, "auth");
  assert.strictEqual(candidates[0].hasTypeArguments, true);

  const calleeCtx = extractLocalCalleeContext(fileContent, diffHunks, "src/handler.ts");
  assert.strictEqual(calleeCtx.contextGaps.length, 1, "Context gap must be generated for unresolvable arrow generic call");
  assert.strictEqual(calleeCtx.contextGaps[0].symbol, "authorize");
  assert.strictEqual(calleeCtx.contextGaps[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");
});

test("trycg-NEGATIVE-OBJECT-LITERAL-TYPE: auth.authorize<{ id: string; role: string }>(user) extracts candidate and records gap", () => {
  const diffHunks = "@@ -2,2 +2,3 @@\n function handle(user) {\n-  return false;\n+  return auth.authorize<{ id: string; role: string }>(user);\n }\n";
  const fileContent = "import { auth } from './auth.mjs';\nfunction handle(user) {\n  return auth.authorize<{ id: string; role: string }>(user);\n}\n";

  const candidates = extractCandidateCallSymbols(diffHunks);
  assert.strictEqual(candidates.length, 1, "Candidate must be extracted for object literal type argument with semicolon");
  assert.strictEqual(candidates[0].symbol, "authorize");
  assert.strictEqual(candidates[0].hasTypeArguments, true);

  const calleeCtx = extractLocalCalleeContext(fileContent, diffHunks, "src/handler.ts");
  assert.strictEqual(calleeCtx.contextGaps.length, 1);
  assert.strictEqual(calleeCtx.contextGaps[0].symbol, "authorize");
  assert.strictEqual(calleeCtx.contextGaps[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");
});

test("trycg-NEGATIVE-SPLIT-LINE-ARROW-GENERIC: split line generic call with arrow type is extracted across lines", () => {
  const diffHunks = "@@ -1,1 +1,3 @@\n+ return auth.authorize<() => void>\n+   (user);\n";
  const candidates = extractCandidateCallSymbols(diffHunks);
  assert.strictEqual(candidates.length, 1, "Candidate must be extracted for split-line generic call with arrow type");
  assert.strictEqual(candidates[0].symbol, "authorize");
  assert.strictEqual(candidates[0].qualifier, "auth");
  assert.strictEqual(candidates[0].hasTypeArguments, true);
});

test("trycn-RUNCONTEXT-GAPS-IN-EVALUATE-GATE-DECISION: evaluateGateDecision with contextGaps refuses approve", () => {
  const finding = {
    id: "f-1",
    title: "Advisory finding",
    severity: "low",
    file: "src/auth.js",
    line_start: 1,
    sources: ["agy", "claude"]
  };
  const consensus = createTrustedConsensus([finding], { tier: 2, quorumReached: true });
  const securityGap = {
    code: "EXTERNAL_CALLEE_UNRESOLVED",
    symbol: "authorize",
    qualifier: "auth",
    category: "security",
    reason: "EXTERNAL_CALLEE_UNRESOLVED"
  };

  // 1. Direct options.contextGaps
  const gateViaOptions = evaluateGateDecision(consensus, { tier: 2, contextGaps: [securityGap] });
  assert.strictEqual(gateViaOptions.decision, "human_review_required");
  assert.match(gateViaOptions.reason, /Security Context Gap/);

  // 2. options.changeSet.contextGaps
  const gateViaChangeSet = evaluateGateDecision(consensus, { tier: 2, changeSet: { contextGaps: [securityGap] } });
  assert.strictEqual(gateViaChangeSet.decision, "human_review_required");
  assert.match(gateViaChangeSet.reason, /Security Context Gap/);

  // 3. options.runContext.contextGaps
  const gateViaRunContext = evaluateGateDecision(consensus, { tier: 2, runContext: { contextGaps: [securityGap] } });
  assert.strictEqual(gateViaRunContext.decision, "human_review_required");
  assert.match(gateViaRunContext.reason, /Security Context Gap/);

  // 4. Tier 1 with contextGaps refuses approve and blocks
  const gateTier1 = evaluateGateDecision(consensus, { tier: 1, contextGaps: [securityGap] });
  assert.strictEqual(gateTier1.decision, "block", "Tier 1 evaluateGateDecision must block on security context gap");
  assert.match(gateTier1.reason, /Security Context Gap|Tier 1 high-risk policy/);
});

// ============================================================================
// Thread trycg: Multiline Generic Sensitive Call Invocations & Fail-Closed Gaps
// ============================================================================

test("trycg-NEGATIVE-MULTILINE-GENERIC-PATTERN-1: auth.authorize<\\n  Session>(user) extracts candidate and records EXTERNAL_CALLEE_UNRESOLVED security context gap", () => {
  const diffHunks = "@@ -2,2 +2,4 @@\n function handle(user) {\n-  return false;\n+  return auth.authorize<\n+    Session>(user);\n }\n";
  const fileContent = "import { auth } from './auth.mjs';\nfunction handle(user) {\n  return auth.authorize<\n    Session>(user);\n}\n";

  const candidates = extractCandidateCallSymbols(diffHunks);
  assert.strictEqual(candidates.length, 1, "Candidate call must be extracted for auth.authorize<\\n  Session>(user)");
  assert.strictEqual(candidates[0].symbol, "authorize");
  assert.strictEqual(candidates[0].qualifier, "auth");
  assert.strictEqual(candidates[0].isSensitive, true);
  assert.strictEqual(candidates[0].category, "security");
  assert.strictEqual(candidates[0].hasTypeArguments, true);

  const calleeCtx = extractLocalCalleeContext(fileContent, diffHunks, "src/handler.ts");
  assert.strictEqual(calleeCtx.contextGaps.length, 1, "Context gap must be generated for unresolvable multiline generic call");
  assert.strictEqual(calleeCtx.contextGaps[0].symbol, "authorize");
  assert.strictEqual(calleeCtx.contextGaps[0].qualifier, "auth");
  assert.strictEqual(calleeCtx.contextGaps[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");
  assert.strictEqual(calleeCtx.contextGaps[0].category, "security");
});

test("trycg-NEGATIVE-MULTILINE-GENERIC-PATTERN-2: auth.authorize\\n  <Session>(user) extracts candidate and records EXTERNAL_CALLEE_UNRESOLVED security context gap", () => {
  const diffHunks = "@@ -2,2 +2,4 @@\n function handle(user) {\n-  return false;\n+  return auth.authorize\n+    <Session>(user);\n }\n";
  const fileContent = "import { auth } from './auth.mjs';\nfunction handle(user) {\n  return auth.authorize\n    <Session>(user);\n}\n";

  const candidates = extractCandidateCallSymbols(diffHunks);
  assert.strictEqual(candidates.length, 1, "Candidate call must be extracted for auth.authorize\\n  <Session>(user)");
  assert.strictEqual(candidates[0].symbol, "authorize");
  assert.strictEqual(candidates[0].qualifier, "auth");
  assert.strictEqual(candidates[0].isSensitive, true);
  assert.strictEqual(candidates[0].category, "security");
  assert.strictEqual(candidates[0].hasTypeArguments, true);

  const calleeCtx = extractLocalCalleeContext(fileContent, diffHunks, "src/handler.ts");
  assert.strictEqual(calleeCtx.contextGaps.length, 1, "Context gap must be generated for unresolvable multiline generic call");
  assert.strictEqual(calleeCtx.contextGaps[0].symbol, "authorize");
  assert.strictEqual(calleeCtx.contextGaps[0].qualifier, "auth");
  assert.strictEqual(calleeCtx.contextGaps[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");
  assert.strictEqual(calleeCtx.contextGaps[0].category, "security");
});

test("trycg-NEGATIVE-UNTERMINATED-MULTILINE-GENERIC: unclosed auth.authorize< fails closed to EXTERNAL_CALLEE_UNRESOLVED gap", () => {
  const diffHunks = "@@ -2,2 +2,3 @@\n function handle(user) {\n-  return false;\n+  return auth.authorize<\n }\n";
  const fileContent = "import { auth } from './auth.mjs';\nfunction handle(user) {\n  return auth.authorize<\n}\n";

  const candidates = extractCandidateCallSymbols(diffHunks);
  assert.strictEqual(candidates.length, 1, "Unclosed sensitive generic attempt must be extracted as candidate");
  assert.strictEqual(candidates[0].symbol, "authorize");
  assert.strictEqual(candidates[0].isSensitive, true);
  assert.strictEqual(candidates[0].hasTypeArguments, true);
  assert.strictEqual(candidates[0].isUnterminated, true);

  const calleeCtx = extractLocalCalleeContext(fileContent, diffHunks, "src/handler.ts");
  assert.strictEqual(calleeCtx.contextGaps.length, 1, "Unclosed sensitive generic attempt must emit EXTERNAL_CALLEE_UNRESOLVED gap");
  assert.strictEqual(calleeCtx.contextGaps[0].symbol, "authorize");
  assert.strictEqual(calleeCtx.contextGaps[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");
  assert.strictEqual(calleeCtx.contextGaps[0].category, "security");
});

test("trycg-POSITIVE-MULTILINE-GENERIC-LOCAL-DEFINITION: resolved multiline generic method in same file emits 0 context gaps", () => {
  const diffHunks = "@@ -7,2 +7,4 @@\n function handle(user) {\n-  return false;\n+  return auth.authorize<\n+    Session>(user);\n }\n";
  const fileContent = [
    "class Auth {",
    "  authorize<Session>(user: Session) {",
    "    return true;",
    "  }",
    "}",
    "const auth = new Auth();",
    "function handle(user) {",
    "  return auth.authorize<Session>(user);",
    "}"
  ].join("\n");

  const calleeCtx = extractLocalCalleeContext(fileContent, diffHunks, "src/auth.ts");
  assert.strictEqual(calleeCtx.callees.length, 1, "Callee definition should be resolved locally");
  assert.strictEqual(calleeCtx.callees[0].symbol, "authorize");
  assert.strictEqual(calleeCtx.contextGaps.length, 0, "No context gaps should be emitted when multiline generic definition is resolved locally");
});

test("trycg-NEGATIVE-BARE-MULTILINE-GENERIC: bare authorizeUser<\\n  Session>(user) and authorizeUser\\n  <Session>(user) extract and record gap", () => {
  const diffA = "@@ -2,2 +2,4 @@\n function handle(user) {\n-  return false;\n+  return authorizeUser<\n+    Session>(user);\n }\n";
  const diffB = "@@ -2,2 +2,4 @@\n function handle(user) {\n-  return false;\n+  return authorizeUser\n+    <Session>(user);\n }\n";
  const fileContent = "import { authorizeUser } from './auth.mjs';\nfunction handle(user) {\n  return authorizeUser<Session>(user);\n}\n";

  const candA = extractCandidateCallSymbols(diffA);
  assert.strictEqual(candA.length, 1);
  assert.strictEqual(candA[0].symbol, "authorizeUser");
  assert.strictEqual(candA[0].hasTypeArguments, true);
  const ctxA = extractLocalCalleeContext(fileContent, diffA, "src/handler.ts");
  assert.strictEqual(ctxA.contextGaps.length, 1);
  assert.strictEqual(ctxA.contextGaps[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");

  const candB = extractCandidateCallSymbols(diffB);
  assert.strictEqual(candB.length, 1);
  assert.strictEqual(candB[0].symbol, "authorizeUser");
  assert.strictEqual(candB[0].hasTypeArguments, true);
  const ctxB = extractLocalCalleeContext(fileContent, diffB, "src/handler.ts");
  assert.strictEqual(ctxB.contextGaps.length, 1);
  assert.strictEqual(ctxB.contextGaps[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");
});

test("trycg-NEGATIVE-MULTILINE-GENERIC-CONTEXT-TO-ADDED-LINES: multiline generic starting on context line and finishing on added line extracts and records gap", () => {
  const diffPattern1 = "@@ -10,3 +10,4 @@\n function handle(user) {\n   return auth.authorize<\n+    Session>(user);\n }\n";
  const fileContent1 = "import { auth } from './auth.mjs';\nfunction handle(user) {\n  return auth.authorize<\n    Session>(user);\n}\n";

  const candA = extractCandidateCallSymbols(diffPattern1);
  assert.strictEqual(candA.length, 1, "Pattern 1 starting on context line must be extracted");
  assert.strictEqual(candA[0].symbol, "authorize");
  assert.strictEqual(candA[0].qualifier, "auth");
  assert.strictEqual(candA[0].isAdded, true, "Call completed by added line must be marked isAdded: true");
  assert.strictEqual(candA[0].hasTypeArguments, true);
  const ctxA = extractLocalCalleeContext(fileContent1, diffPattern1, "src/handler.ts");
  assert.strictEqual(ctxA.contextGaps.length, 1);
  assert.strictEqual(ctxA.contextGaps[0].symbol, "authorize");
  assert.strictEqual(ctxA.contextGaps[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");

  const diffPattern2 = "@@ -10,3 +10,4 @@\n function handle(user) {\n   return auth.authorize\n+    <Session>(user);\n }\n";
  const fileContent2 = "import { auth } from './auth.mjs';\nfunction handle(user) {\n  return auth.authorize\n    <Session>(user);\n}\n";

  const candB = extractCandidateCallSymbols(diffPattern2);
  assert.strictEqual(candB.length, 1, "Pattern 2 starting on context line must be extracted");
  assert.strictEqual(candB[0].symbol, "authorize");
  assert.strictEqual(candB[0].qualifier, "auth");
  assert.strictEqual(candB[0].isAdded, true, "Call completed by added line must be marked isAdded: true");
  assert.strictEqual(candB[0].hasTypeArguments, true);
  const ctxB = extractLocalCalleeContext(fileContent2, diffPattern2, "src/handler.ts");
  assert.strictEqual(ctxB.contextGaps.length, 1);
  assert.strictEqual(ctxB.contextGaps[0].symbol, "authorize");
  assert.strictEqual(ctxB.contextGaps[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");
});

test("trycg-NEGATIVE-MULTILINE-GENERIC-COMPLEX-NESTED-TYPES: complex nested generic types spanning 5+ lines extract and record gap", () => {
  const diffHunks = [
    "@@ -2,2 +2,8 @@",
    " function handle(user) {",
    "-  return false;",
    "+  return auth.authorize<",
    "+    Map<string, {",
    "+      id: string;",
    "+      roles: Array<string | number>;",
    "+    }>",
    "+  >(user);",
    " }"
  ].join("\n");
  const fileContent = "import { auth } from './auth.mjs';\nfunction handle(user) {\n  return auth.authorize<\n    Map<string, {\n      id: string;\n      roles: Array<string | number>;\n    }>\n  >(user);\n}\n";

  const candidates = extractCandidateCallSymbols(diffHunks);
  assert.strictEqual(candidates.length, 1, "Complex nested multiline generic call must be extracted");
  assert.strictEqual(candidates[0].symbol, "authorize");
  assert.strictEqual(candidates[0].qualifier, "auth");
  assert.strictEqual(candidates[0].hasTypeArguments, true);
  assert.strictEqual(candidates[0].isSensitive, true);

  const calleeCtx = extractLocalCalleeContext(fileContent, diffHunks, "src/handler.ts");
  assert.strictEqual(calleeCtx.contextGaps.length, 1);
  assert.strictEqual(calleeCtx.contextGaps[0].symbol, "authorize");
  assert.strictEqual(calleeCtx.contextGaps[0].reason, "EXTERNAL_CALLEE_UNRESOLVED");
});

test("trycn-TIER1-VS-TIER2-CONTEXT-GAP-ALIGNMENT: Tier 1 returns block while Tier 2 returns human_review_required for unresolved context gaps", async () => {
  const finding = {
    id: "f-advisory",
    title: "Advisory code style finding",
    severity: "low",
    file: "src/auth.js",
    line_start: 1,
    sources: ["agy", "claude"]
  };
  const consensus = createTrustedConsensus([finding], { tier: 2, quorumReached: true });
  const securityGap = {
    code: "EXTERNAL_CALLEE_UNRESOLVED",
    symbol: "authorize",
    qualifier: "auth",
    category: "security",
    reason: "EXTERNAL_CALLEE_UNRESOLVED"
  };

  // Tier 1 Gate Evaluation -> must BLOCK
  const gateTier1 = evaluateGateDecision(consensus, { tier: 1, contextGaps: [securityGap] });
  assert.strictEqual(gateTier1.decision, "block", "Tier 1 Gate MUST return block for unresolved Security Context Gap");
  assert.match(gateTier1.reason, /Tier 1 high-risk policy/);

  // Tier 2 Gate Evaluation -> must return HUMAN_REVIEW_REQUIRED
  const gateTier2 = evaluateGateDecision(consensus, { tier: 2, contextGaps: [securityGap] });
  assert.strictEqual(gateTier2.decision, "human_review_required", "Tier 2 Gate MUST return human_review_required for unresolved Security Context Gap");
  assert.match(gateTier2.reason, /Security Context Gap/);

  // PostVerificationGate equivalent with authentic Clean Challenge record
  const diffHunks = "@@ -1,1 +1,2 @@\n- a\n+ b\n";
  const digest = computeDigest(diffHunks);
  const changeSet = {
    headSha: TEST_HEAD_SHA,
    diffHunks,
    contentDigest: digest,
    files: [{ path: "src/auth.js", additions: 1, deletions: 1, riskTier: 2 }]
  };
  const mockAdapter = {
    providerName: "claude",
    modelName: "claude-3-5-sonnet",
    executeVerification: async () => ({
      ok: true,
      executionStatus: "success",
      overallStatus: "CLEAN",
      evaluations: [],
      verifierOmissions: []
    })
  };
  const trustedRecord = await conductIndependentVerification(changeSet, [], mockAdapter, {
    verificationMode: "clean_challenge",
    headSha: TEST_HEAD_SHA,
    changeSetDigest: digest,
    contextGaps: [securityGap]
  });

  const cleanConsensus = createTrustedConsensus([], { tier: 2, quorumReached: true });
  const postTier1 = evaluatePostVerificationGate(cleanConsensus, trustedRecord, { tier: 1 });
  assert.strictEqual(postTier1.decision, "block", "PostVerificationGate Tier 1 MUST block");

  const postTier2 = evaluatePostVerificationGate(cleanConsensus, trustedRecord, { tier: 2 });
  assert.strictEqual(postTier2.decision, "human_review_required", "PostVerificationGate Tier 2 MUST return human_review_required");
});

test("trycg-POSITIVE-MULTILINE-CONTEXT-LINES-UNMODIFIED: unchanged multiline call on context lines does not emit context gaps", () => {
  const diffHunks = [
    "@@ -10,4 +10,5 @@",
    " function handle(user) {",
    "   return auth.authorize<",
    "     Session>(user);",
    "+  logOperation();",
    " }"
  ].join("\n");
  const fileContent = "import { auth } from './auth.mjs';\nfunction handle(user) {\n  return auth.authorize<\n    Session>(user);\n  logOperation();\n}\n";

  const candidates = extractCandidateCallSymbols(diffHunks);
  const authCand = candidates.find(c => c.symbol === "authorize");
  assert.ok(authCand, "Context line multiline call should be extracted");
  assert.strictEqual(authCand.isAdded, false, "Unmodified context lines must have isAdded: false");

  const calleeCtx = extractLocalCalleeContext(fileContent, diffHunks, "src/handler.ts");
  const authGaps = calleeCtx.contextGaps.filter(g => g.symbol === "authorize");
  assert.strictEqual(authGaps.length, 0, "Unmodified context line multiline call must NOT emit context gaps");
});
