/**
 * Empirical Challenger Test Suite for PR #39 Phase 3 Remediation
 *
 * Exhaustively stress-tests:
 * 1. Tier downgrade prevention (R4) boundary values & defaults
 * 2. CLI verification boundary (R5) injection payloads & usage errors
 * 3. Clean Challenge lifecycle (R5) exit codes and gate decisions
 */

import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import path from "node:path";
import process from "node:process";

import { orchestrateReview } from "../src/adapters/review-orchestrator.mjs";
import { runCli, EXIT_CODES } from "../src/cli.mjs";
import { REVIEW_RUN_STATUS } from "../src/core/review-run-report.mjs";
import { normalizeLineEndings } from "../src/core/canonical-digest.mjs";
import {
  conductIndependentVerification,
  createMockVerifierAdapter
} from "../src/core/independent-verifier.mjs";

class MockStream {
  constructor() {
    this.buffer = "";
  }
  write(chunk) {
    this.buffer += String(chunk);
  }
}

function createTestChangeSet(overrides = {}) {
  const diffHunks = overrides.diffHunks !== undefined
    ? overrides.diffHunks
    : "diff --git a/src/auth/token.mjs b/src/auth/token.mjs\n--- a/src/auth/token.mjs\n+++ b/src/auth/token.mjs\n@@ -1,1 +1,2 @@\n+const verified = true;\n";
  const normDiff = normalizeLineEndings(diffHunks);
  const contentDigest = overrides.contentDigest !== undefined
    ? overrides.contentDigest
    : crypto.createHash("sha256").update(normDiff, "utf8").digest("hex");

  return {
    ok: true,
    schemaVersion: "1.0.0",
    scopeMode: "working-tree",
    headSha: "a".repeat(40),
    contentDigest,
    totalFiles: 1,
    totalAdditions: 15,
    totalDeletions: 2,
    files: [
      { path: "src/auth/token.mjs", additions: 15, deletions: 2, riskTier: 1 }
    ],
    diffHunks,
    patchObjective: "Harden authentication token verification",
    ...overrides
  };
}

function createTier2ChangeSet(overrides = {}) {
  const diffHunks = overrides.diffHunks !== undefined
    ? overrides.diffHunks
    : "diff --git a/src/utils/math.mjs b/src/utils/math.mjs\n--- a/src/utils/math.mjs\n+++ b/src/utils/math.mjs\n@@ -1,1 +1,2 @@\n+export const add = (a, b) => a + b;\n";
  const normDiff = normalizeLineEndings(diffHunks);
  const contentDigest = overrides.contentDigest !== undefined
    ? overrides.contentDigest
    : crypto.createHash("sha256").update(normDiff, "utf8").digest("hex");

  return {
    ok: true,
    schemaVersion: "1.0.0",
    scopeMode: "working-tree",
    headSha: "b".repeat(40),
    contentDigest,
    totalFiles: 1,
    totalAdditions: 5,
    totalDeletions: 1,
    files: [
      { path: "src/utils/math.mjs", additions: 5, deletions: 1, riskTier: 2 }
    ],
    diffHunks,
    patchObjective: "Add helper math functions",
    ...overrides
  };
}

function createCleanReviewAdapter(role = "macro") {
  const provider = role === "macro" ? "claude" : "agy";
  const family = role === "macro" ? "anthropic" : "google";
  return {
    providerName: provider,
    family,
    modelName: `${provider}-default`,
    executeReview: async ({ runId, changeSet }) => ({
      ok: true,
      status: "success",
      findings: [],
      providerIdentity: {
        provider,
        family,
        model: `${provider}-default`,
        transport: "cli"
      },
      coverage: {
        coveredFiles: (changeSet.files || []).map(f => f.path),
        omittedFiles: []
      }
    })
  };
}

async function runCliHelper(args, options = {}) {
  const stdout = new MockStream();
  const stderr = new MockStream();
  const exitCode = await runCli(args, { stdout, stderr }, options);
  return { exitCode, stdout: stdout.buffer, stderr: stderr.buffer };
}

// ============================================================================
// SUITE 1: Tier Downgrade Prevention (R4) Boundary Value Stress Testing
// ============================================================================

test("R4-BOUNDARY-01: Boundary value illegal tiers fail closed with INVALID_OR_DOWNGRADED_TIER", async (t) => {
  const illegalValues = [
    { label: "null", value: null },
    { label: "0", value: 0 },
    { label: "-1", value: -1 },
    { label: "0.5 (float)", value: 0.5 },
    { label: "1.5 (float)", value: 1.5 },
    { label: "NaN", value: NaN },
    { label: "false (boolean)", value: false },
    { label: "true (boolean)", value: true },
    { label: "'0' (string 0)", value: "0" },
    { label: "'-1' (string -1)", value: "-1" },
    { label: "'0.5' (string float)", value: "0.5" },
    { label: "'' (empty string)", value: "" },
    { label: "'   ' (whitespace string)", value: "   " },
    { label: "'NaN' (string NaN)", value: "NaN" },
    { label: "'undefined' (string undefined)", value: "undefined" },
    { label: "'abc' (alphanumeric string)", value: "abc" },
    { label: "5 (out of range > 4)", value: 5 },
    { label: "100 (out of range)", value: 100 },
    { label: "Infinity", value: Infinity },
    { label: "-Infinity", value: -Infinity },
    { label: "{} (plain object)", value: {} },
    { label: "[] (array)", value: [] }
  ];

  const changeSet = createTestChangeSet(); // Tier 1 changeSet
  const adapters = {
    macro: createCleanReviewAdapter("macro"),
    micro: createCleanReviewAdapter("micro")
  };

  for (const item of illegalValues) {
    await t.test(`illegal tier: ${item.label}`, async () => {
      const res = await orchestrateReview(changeSet, adapters, { tier: item.value });
      assert.equal(res.status, "incomplete", `Status must be incomplete for tier: ${item.label}`);
      assert.equal(res.gate.decision, "block", `Gate decision must be block for tier: ${item.label}`);
      assert.match(
        res.gate.reason,
        /INVALID_OR_DOWNGRADED_TIER/i,
        `Gate reason must state INVALID_OR_DOWNGRADED_TIER for tier: ${item.label}`
      );
    });
  }
});

test("R4-BOUNDARY-02: Attempted downgrades on Tier 1 diffs fail closed with INVALID_OR_DOWNGRADED_TIER", async (t) => {
  const downgradeCases = [
    { label: "tier: 2 on Tier 1 diff", options: { tier: 2 } },
    { label: "tier: 3 on Tier 1 diff", options: { tier: 3 } },
    { label: "tier: 4 on Tier 1 diff", options: { tier: 4 } },
    { label: "tier: '2' (string) on Tier 1 diff", options: { tier: "2" } },
    { label: "tier: '3' (string) on Tier 1 diff", options: { tier: "3" } },
    { label: "isTier1: false on Tier 1 diff without tier option", options: { isTier1: false } },
    { label: "isTier1: false with tier: 1 on Tier 1 diff", options: { isTier1: false, tier: 1 } },
    { label: "isTier1: false with tier: 2 on Tier 1 diff", options: { isTier1: false, tier: 2 } }
  ];

  const changeSet = createTestChangeSet(); // Tier 1 changeSet (files in src/auth/)
  const adapters = {
    macro: createCleanReviewAdapter("macro"),
    micro: createCleanReviewAdapter("micro")
  };

  for (const c of downgradeCases) {
    await t.test(c.label, async () => {
      const res = await orchestrateReview(changeSet, adapters, c.options);
      assert.equal(res.status, "incomplete");
      assert.equal(res.gate.decision, "block");
      assert.match(res.gate.reason, /INVALID_OR_DOWNGRADED_TIER/i);
    });
  }
});

test("R4-BOUNDARY-03: Valid tier omission defaults safely to computed diff scale risk tier", async (t) => {
  // Test Tier 1 diff with omitted tier
  const tier1ChangeSet = createTestChangeSet();
  const adapters = {
    macro: createCleanReviewAdapter("macro"),
    micro: createCleanReviewAdapter("micro")
  };
  const mockAdapter = createMockVerifierAdapter("claude", {
    executeVerification: async () => ({
      ok: true,
      fileCoverageComplete: true,
      overallStatus: "CLEAN",
      evaluations: [],
      verifierOmissions: []
    })
  });
  const runId = "test-run-omitted-tier-01";
  const vr = await conductIndependentVerification(tier1ChangeSet, [], mockAdapter, {
    verificationMode: "clean_challenge",
    runId,
    headSha: tier1ChangeSet.headSha,
    patchObjective: tier1ChangeSet.patchObjective
  });

  // Call with no tier specified (options.tier is undefined)
  const resTier1 = await orchestrateReview(tier1ChangeSet, adapters, {
    runId,
    verificationRecord: vr
  });
  assert.equal(resTier1.gate.decision, "approve");
  assert.equal(resTier1.status, "reviewed-clean");

  // Verify that single sentry fails closed on Tier 1 diff even when tier is omitted
  const singleAdapter = { macro: createCleanReviewAdapter("macro") };
  const resTier1Single = await orchestrateReview(tier1ChangeSet, singleAdapter, {
    runId: "single-sentry-tier1",
    verificationRecord: vr
  });
  assert.equal(resTier1Single.status, "incomplete");
  assert.equal(resTier1Single.gate.decision, "block");
  assert.match(resTier1Single.gate.reason, /Quorum Failure|requires dual sentries/i);

  // Test Tier 2 diff with omitted tier: single sentry is allowed for small Tier 2 diff
  const tier2ChangeSet = createTier2ChangeSet();
  const vr2 = await conductIndependentVerification(tier2ChangeSet, [], mockAdapter, {
    verificationMode: "clean_challenge",
    runId: "tier2-run-001",
    headSha: tier2ChangeSet.headSha,
    patchObjective: tier2ChangeSet.patchObjective
  });
  const resTier2Single = await orchestrateReview(tier2ChangeSet, singleAdapter, {
    runId: "tier2-run-001",
    verificationRecord: vr2
  });
  assert.equal(resTier2Single.gate.decision, "approve");
  assert.equal(resTier2Single.status, "reviewed-clean");
});

test("R4-BOUNDARY-04: Explicit valid tiers pass when not downgrading", async (t) => {
  const tier1ChangeSet = createTestChangeSet();
  const adapters = {
    macro: createCleanReviewAdapter("macro"),
    micro: createCleanReviewAdapter("micro")
  };
  const mockAdapter = createMockVerifierAdapter("claude", {
    executeVerification: async () => ({
      ok: true,
      fileCoverageComplete: true,
      overallStatus: "CLEAN",
      evaluations: [],
      verifierOmissions: []
    })
  });
  const runId = "test-run-valid-tier-1";
  const vr = await conductIndependentVerification(tier1ChangeSet, [], mockAdapter, {
    verificationMode: "clean_challenge",
    runId,
    headSha: tier1ChangeSet.headSha,
    patchObjective: tier1ChangeSet.patchObjective
  });

  // Explicit tier: 1 on Tier 1 diff -> passes
  const res1 = await orchestrateReview(tier1ChangeSet, adapters, {
    runId,
    tier: 1,
    verificationRecord: vr
  });
  assert.equal(res1.gate.decision, "approve");
  assert.equal(res1.status, "reviewed-clean");

  // String "1" on Tier 1 diff -> passes
  const resStr1 = await orchestrateReview(tier1ChangeSet, adapters, {
    runId,
    tier: "1",
    verificationRecord: vr
  });
  assert.equal(resStr1.gate.decision, "approve");
  assert.equal(resStr1.status, "reviewed-clean");

  // Explicit tier: 1 (risk upgrade) on Tier 2 diff -> passes
  const tier2ChangeSet = createTier2ChangeSet();
  const vr2 = await conductIndependentVerification(tier2ChangeSet, [], mockAdapter, {
    verificationMode: "clean_challenge",
    runId: "tier2-upgrade-01",
    headSha: tier2ChangeSet.headSha,
    patchObjective: tier2ChangeSet.patchObjective
  });
  const resUpgrade = await orchestrateReview(tier2ChangeSet, adapters, {
    runId: "tier2-upgrade-01",
    tier: 1,
    verificationRecord: vr2
  });
  assert.equal(resUpgrade.gate.decision, "approve");
  assert.equal(resUpgrade.status, "reviewed-clean");
});

// ============================================================================
// SUITE 2: CLI Verification Boundary (R5) Injection & Validation Probes
// ============================================================================

test("R5-INJECTION-01: Shell injection payloads in --verify-with exit strictly with code 2 (USAGE_ERROR)", async (t) => {
  const injectionPayloads = [
    "claude; rm -rf",
    "claude && echo hacked",
    "| cat",
    "`whoami`",
    "claude`whoami`",
    "`id`",
    "$(whoami)",
    "claude$(id)",
    "claude > /tmp/pwn",
    "claude < /tmp/pwn",
    "claude\"evil\"",
    "claude'evil'",
    "claude;reboot",
    "claude&evil",
    "claude|evil",
    "-o evil",
    "--malicious"
  ];

  const changeSet = createTestChangeSet();

  for (const payload of injectionPayloads) {
    await t.test(`payload: ${payload}`, async () => {
      // Test both --verify-with=payload and --verify-with payload
      const resEqual = await runCliHelper(["review", `--verify-with=${payload}`], {
        getChangeSet: () => changeSet
      });
      assert.equal(resEqual.exitCode, EXIT_CODES.USAGE_ERROR, `Payload '${payload}' with '=' must exit code 2`);
      assert.match(resEqual.stderr, /\[USAGE ERROR\]/i);

      const resSpace = await runCliHelper(["review", "--verify-with", payload], {
        getChangeSet: () => changeSet
      });
      assert.equal(resSpace.exitCode, EXIT_CODES.USAGE_ERROR, `Payload '${payload}' with space must exit code 2`);
      assert.match(resSpace.stderr, /\[USAGE ERROR\]/i);
    });
  }
});

test("R5-EMPTY-02: Empty, missing, and whitespace --verify-with exit strictly with code 2 (USAGE_ERROR)", async (t) => {
  const emptyCases = [
    { label: "--verify-with=''", args: ["review", "--verify-with="] },
    { label: "--verify-with (missing value at end)", args: ["review", "--verify-with"] },
    { label: "--verify-with before another flag", args: ["review", "--verify-with", "--format=json"] },
    { label: "--verify-with='   ' (spaces)", args: ["review", "--verify-with=   "] },
    { label: "--verify-with with '   ' next arg", args: ["review", "--verify-with", "   "] }
  ];

  const changeSet = createTestChangeSet();

  for (const c of emptyCases) {
    await t.test(c.label, async () => {
      const res = await runCliHelper(c.args, {
        getChangeSet: () => changeSet
      });
      assert.equal(res.exitCode, EXIT_CODES.USAGE_ERROR, `${c.label} must exit with code 2`);
      assert.match(res.stderr, /\[USAGE ERROR\]/i);
    });
  }
});

test("R5-UNSUPPORTED-03: Unsupported verifier providers exit strictly with code 2 (USAGE_ERROR)", async (t) => {
  const unsupportedProviders = [
    "unknown",
    "gpt4",
    "curl",
    "bash",
    "node",
    "python",
    "openai",
    "anthropic", // The canonical ID is "claude"
    "google",    // The canonical ID is "agy"
    "gemini",    // The canonical ID is "agy"
    "chatgpt"
  ];

  const changeSet = createTestChangeSet();

  for (const provider of unsupportedProviders) {
    await t.test(`provider: ${provider}`, async () => {
      const res = await runCliHelper(["review", `--verify-with=${provider}`], {
        getChangeSet: () => changeSet
      });
      assert.equal(res.exitCode, EXIT_CODES.USAGE_ERROR, `Provider '${provider}' must exit with code 2`);
      assert.match(res.stderr, /\[USAGE ERROR\]/i);
      assert.match(res.stderr, /does not resolve to a canonical provider profile/i);
    });
  }
});

// ============================================================================
// SUITE 3: Clean Challenge Lifecycle (R5) Exit Code & Gate Decisions
// ============================================================================

test("R5-LIFECYCLE-01: Clean review on changed code WITHOUT verifier fails closed with exit code 1 (GATE_BLOCKED)", async () => {
  const changeSet = createTestChangeSet(); // 1 file changed
  const reviewAdapters = {
    macro: createCleanReviewAdapter("macro"),
    micro: createCleanReviewAdapter("micro")
  };

  const res = await runCliHelper(["review"], {
    getChangeSet: () => changeSet,
    reviewAdapters
  });

  assert.equal(res.exitCode, EXIT_CODES.GATE_BLOCKED, "Zero findings on changed code without verifier must exit code 1");
  assert.match(res.stderr, /Gate Decision: BLOCK/i);
  assert.match(res.stderr, /Clean Challenge missing/i);
});

test("R5-LIFECYCLE-02: Clean review on changed code WITH verifier (CLEAN) exits with code 0 (SUCCESS)", async (t) => {
  const changeSet = createTestChangeSet();
  const reviewAdapters = {
    macro: createCleanReviewAdapter("macro"),
    micro: createCleanReviewAdapter("micro")
  };
  let verifierInvoked = false;
  const mockCleanVerifier = createMockVerifierAdapter("claude", {
    executeVerification: async () => {
      verifierInvoked = true;
      return {
        ok: true,
        fileCoverageComplete: true,
        overallStatus: "CLEAN",
        evaluations: [],
        verifierOmissions: []
      };
    }
  });

  // 1. Text mode
  await t.test("text output format", async () => {
    verifierInvoked = false;
    const resText = await runCliHelper(["review", "--verify-with=claude"], {
      getChangeSet: () => changeSet,
      reviewAdapters,
      verifierAdapter: mockCleanVerifier
    });
    assert.equal(verifierInvoked, true, "Verifier must have been invoked");
    assert.equal(resText.exitCode, EXIT_CODES.SUCCESS, "Clean verified review must exit code 0");
    assert.match(resText.stderr, /Gate Decision: APPROVE/i);
    assert.match(resText.stderr, /reviewed-clean/i);
  });

  // 2. JSON mode
  await t.test("json output format", async () => {
    verifierInvoked = false;
    const resJson = await runCliHelper(["review", "--verify-with=claude", "--format=json"], {
      getChangeSet: () => changeSet,
      reviewAdapters,
      verifierAdapter: mockCleanVerifier
    });
    assert.equal(verifierInvoked, true, "Verifier must have been invoked");
    assert.equal(resJson.exitCode, EXIT_CODES.SUCCESS, "Clean verified review in JSON mode must exit code 0");
    assert.ok(resJson.stdout.length > 0, "Stdout must contain JSON output");
    const parsed = JSON.parse(resJson.stdout);
    assert.equal(parsed.exitCode, EXIT_CODES.SUCCESS);
    assert.equal(parsed.status, REVIEW_RUN_STATUS.REVIEWED_CLEAN);
    assert.equal(parsed.gate.decision, "approve");
  });

  // 3. Space-separated flag: --verify-with claude
  await t.test("space-separated argument --verify-with claude", async () => {
    verifierInvoked = false;
    const resSpace = await runCliHelper(["review", "--verify-with", "claude"], {
      getChangeSet: () => changeSet,
      reviewAdapters,
      verifierAdapter: mockCleanVerifier
    });
    assert.equal(verifierInvoked, true, "Verifier must have been invoked");
    assert.equal(resSpace.exitCode, EXIT_CODES.SUCCESS);
    assert.match(resSpace.stderr, /Gate Decision: APPROVE/i);
  });
});

test("R5-LIFECYCLE-03: Clean review where verifier returns DEFECTS_FOUND fails closed with exit code 1", async (t) => {
  const changeSet = createTestChangeSet();
  const reviewAdapters = {
    macro: createCleanReviewAdapter("macro"),
    micro: createCleanReviewAdapter("micro")
  };

  // Case A: Supported Critical Omission -> Gate decision is BLOCK, exit code 1
  await t.test("DEFECTS_FOUND with supported critical omission", async () => {
    const changeSetWithRealFile = createTestChangeSet({
      headSha: "",
      files: [{ path: "src/cli.mjs", additions: 15, deletions: 2, riskTier: 1 }],
      diffHunks: "diff --git a/src/cli.mjs b/src/cli.mjs\n--- a/src/cli.mjs\n+++ b/src/cli.mjs\n@@ -1,1 +1,2 @@\n+const verified = true;\n"
    });
    const mockDefectsVerifier = createMockVerifierAdapter("claude", {
      executeVerification: async () => ({
        ok: true,
        fileCoverageComplete: true,
        overallStatus: "DEFECTS_FOUND",
        evaluations: [],
        verifierOmissions: [
          {
            title: "Hardcoded secret exposed",
            file: "src/cli.mjs",
            line_start: 1,
            line_end: 2,
            locatorAccurate: true,
            severity: "critical",
            evidenceSupport: "SUPPORTED",
            objectiveImpact: "FALSIFIES_PATCH_OBJECTIVE",
            reasoning: "Passing empty token string bypasses check at line 2"
          }
        ]
      })
    });

    const res = await runCliHelper(["review", "--verify-with=claude"], {
      getChangeSet: () => changeSetWithRealFile,
      reviewAdapters,
      verifierAdapter: mockDefectsVerifier
    });

    assert.equal(res.exitCode, EXIT_CODES.GATE_BLOCKED, "DEFECTS_FOUND verifier verdict must exit code 1");
    assert.match(res.stderr, /Gate Decision: BLOCK/i);
    assert.match(res.stderr, /Confirmed Objective Violation|Confirmed Critical \/ High Omission/i);
  });

  // Case B: DEFECTS_FOUND without omissions -> Gate decision is BLOCK, exit code 1
  await t.test("DEFECTS_FOUND without omissions", async () => {
    const mockDefectsVerifier = createMockVerifierAdapter("claude", {
      executeVerification: async () => ({
        ok: true,
        fileCoverageComplete: true,
        overallStatus: "DEFECTS_FOUND",
        evaluations: [],
        verifierOmissions: []
      })
    });

    const res = await runCliHelper(["review", "--verify-with=claude"], {
      getChangeSet: () => changeSet,
      reviewAdapters,
      verifierAdapter: mockDefectsVerifier
    });

    assert.equal(res.exitCode, EXIT_CODES.GATE_BLOCKED, "DEFECTS_FOUND without omissions must exit code 1");
    assert.match(res.stderr, /Gate Decision: BLOCK/i);
    assert.match(res.stderr, /Verifier reported DEFECTS_FOUND without omissions/i);
  });
});

// ============================================================================
// SUITE 4: Real CLI Subprocess Invocation Verification
// ============================================================================

test("R5-SUBPROCESS-01: Spawned triad-flow CLI process enforces --verify-with USAGE_ERROR", () => {
  const cliPath = path.resolve("bin/triad-flow.mjs");

  // 1. Injection attack: claude;cat
  const procInjection = spawnSync(process.execPath, [cliPath, "review", "--verify-with=claude;cat /etc/passwd"], {
    encoding: "utf8"
  });
  assert.equal(procInjection.status, 2, "Spawned process must exit with code 2 on injection attempt");
  assert.match(procInjection.stderr, /\[USAGE ERROR\]/i);

  // 2. Unsupported provider: curl
  const procUnsupported = spawnSync(process.execPath, [cliPath, "review", "--verify-with=curl"], {
    encoding: "utf8"
  });
  assert.equal(procUnsupported.status, 2, "Spawned process must exit with code 2 on unsupported provider");
  assert.match(procUnsupported.stderr, /\[USAGE ERROR\]/i);

  // 3. Empty flag: --verify-with=
  const procEmpty = spawnSync(process.execPath, [cliPath, "review", "--verify-with="], {
    encoding: "utf8"
  });
  assert.equal(procEmpty.status, 2, "Spawned process must exit with code 2 on empty --verify-with");
  assert.match(procEmpty.stderr, /\[USAGE ERROR\]/i);
});
