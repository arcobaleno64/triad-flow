import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import { orchestrateReview } from "../src/adapters/review-orchestrator.mjs";
import { EXECUTION_STATUS } from "../src/adapters/provider-contract.mjs";

function makeChangeSet(files = []) {
  const hunks = files.map(f => `diff --git a/${f.path} b/${f.path}\n@@ -1,1 +1,2 @@\n+const x = 1;`).join("\n");
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

test("Orchestrator authorized omissions: Tier-2/3 file omitted with valid code and reason satisfies coverage in single mode", async () => {
  const changeSet = makeChangeSet([
    { path: "src/calc.js", additions: 5, deletions: 1 },
    { path: "docs/readme.md", additions: 10, deletions: 0 }
  ]);

  const mockAdapter = {
    providerName: "mock-authorized-omission",
    modelName: "mock-model",
    executeReview: async () => ({
      ok: true,
      executionStatus: EXECUTION_STATUS.EMPTY,
      findings: [],
      coverage: {
        coveredFiles: ["src/calc.js"],
        omittedFiles: [
          { file: "docs/readme.md", code: "OMIT_OUT_OF_SCOPE", reason: "Documentation file out of review scope" }
        ]
      },
      providerIdentity: { provider: "mock-authorized-omission", family: "anthropic", model: "test", transport: "mock" }
    })
  };

  const result = await orchestrateReview(changeSet, { macro: mockAdapter }, {
    plan: { mode: "single", role: "macro" }
  });

  assert.equal(result.status, "reviewed-clean");
  assert.equal(result.gate.decision, "approve");
});

test("Orchestrator authorized omissions: Dual sentry mode passes when both sentries provide authorized omissions", async () => {
  const changeSet = makeChangeSet([
    { path: "src/calc.js", additions: 5, deletions: 1 },
    { path: "docs/guide.md", additions: 10, deletions: 0 }
  ]);

  let macroInvoked = false;
  let microInvoked = false;

  const macroAdapter = {
    providerName: "macro-sentry",
    modelName: "claude-model",
    executeReview: async () => {
      macroInvoked = true;
      return {
        ok: true,
        executionStatus: EXECUTION_STATUS.EMPTY,
        findings: [],
        coverage: {
          coveredFiles: ["src/calc.js"],
          omittedFiles: [
            { file: "docs/guide.md", code: "OMIT_OUT_OF_SCOPE", reason: "Documentation file" }
          ]
        },
        providerIdentity: { provider: "macro-sentry", family: "anthropic", model: "test-macro", transport: "mock" }
      };
    }
  };

  const microAdapter = {
    providerName: "micro-sentry",
    modelName: "gemini-model",
    executeReview: async () => {
      microInvoked = true;
      return {
        ok: true,
        executionStatus: EXECUTION_STATUS.EMPTY,
        findings: [],
        coverage: {
          coveredFiles: ["src/calc.js"],
          omittedFiles: [
            { file: "docs/guide.md", code: "OMIT_GENERATED", reason: "Auto-generated file" }
          ]
        },
        providerIdentity: { provider: "micro-sentry", family: "google", model: "test-micro", transport: "mock" }
      };
    }
  };

  const result = await orchestrateReview(changeSet, { macro: macroAdapter, micro: microAdapter }, {
    plan: { mode: "hierarchical", roles: ["macro", "micro"] }
  });

  assert.equal(macroInvoked, true);
  assert.equal(microInvoked, true);
  assert.ok(result.results);
  assert.ok(result.results.macro);
  assert.ok(result.results.micro);
  assert.equal(result.status, "reviewed-clean");
  assert.equal(result.gate.decision, "approve");
});

test("Orchestrator authorized omissions: Tier-1 critical file omission fails closed to incomplete & block", async () => {
  // A security dir or critical pattern file is classified as Tier 1
  const changeSet = makeChangeSet([
    { path: "src/auth/login.js", additions: 5, deletions: 1 },
    { path: "src/calc.js", additions: 10, deletions: 0 }
  ]);

  const mockAdapter = {
    providerName: "mock-critical-omission",
    modelName: "mock-model",
    executeReview: async () => ({
      ok: true,
      executionStatus: EXECUTION_STATUS.EMPTY,
      findings: [],
      coverage: {
        coveredFiles: ["src/calc.js"],
        omittedFiles: [
          { file: "src/auth/login.js", code: "OMIT_OUT_OF_SCOPE", reason: "Skipping auth file" }
        ]
      },
      providerIdentity: { provider: "mock-critical-omission", family: "anthropic", model: "test", transport: "mock" }
    })
  };

  const result = await orchestrateReview(changeSet, { macro: mockAdapter }, {
    plan: { mode: "single", role: "macro" }
  });

  assert.equal(result.status, "incomplete");
  assert.equal(result.gate.decision, "block");
  assert.match(result.gate.reason, /Coverage Incomplete/i);
});

test("Orchestrator authorized omissions: Missing omission code fails closed to incomplete & block", async () => {
  const changeSet = makeChangeSet([
    { path: "src/calc.js", additions: 5, deletions: 1 },
    { path: "docs/readme.md", additions: 10, deletions: 0 }
  ]);

  const mockAdapter = {
    providerName: "mock-no-code",
    modelName: "mock-model",
    executeReview: async () => ({
      ok: true,
      executionStatus: EXECUTION_STATUS.EMPTY,
      findings: [],
      coverage: {
        coveredFiles: ["src/calc.js"],
        omittedFiles: [
          { file: "docs/readme.md", reason: "Missing code property" }
        ]
      },
      providerIdentity: { provider: "mock-no-code", family: "anthropic", model: "test", transport: "mock" }
    })
  };

  const result = await orchestrateReview(changeSet, { macro: mockAdapter }, {
    plan: { mode: "single", role: "macro" }
  });

  assert.equal(result.status, "incomplete");
  assert.equal(result.gate.decision, "block");
  assert.match(result.gate.reason, /Coverage Incomplete/i);
});

test("Orchestrator authorized omissions: Contradictory coverage declaration fails closed", async () => {
  const changeSet = makeChangeSet([
    { path: "src/calc.js", additions: 5, deletions: 1 }
  ]);

  const mockAdapter = {
    providerName: "mock-contradiction",
    modelName: "mock-model",
    executeReview: async () => ({
      ok: true,
      executionStatus: EXECUTION_STATUS.EMPTY,
      findings: [],
      coverage: {
        coveredFiles: ["src/calc.js"],
        omittedFiles: [
          { file: "src/calc.js", code: "OMIT_OUT_OF_SCOPE", reason: "Both covered and omitted" }
        ]
      },
      providerIdentity: { provider: "mock-contradiction", family: "anthropic", model: "test", transport: "mock" }
    })
  };

  const result = await orchestrateReview(changeSet, { macro: mockAdapter }, {
    plan: { mode: "single", role: "macro" }
  });

  assert.equal(result.status, "incomplete");
  assert.equal(result.gate.decision, "block");
  assert.match(result.gate.reason, /Coverage Incomplete/i);
});

test("Orchestrator authorized omissions: Missing coveredFiles array fails closed to incomplete & block (P1)", async () => {
  const changeSet = makeChangeSet([
    { path: "docs/readme.md", additions: 10, deletions: 0 }
  ]);

  const mockAdapter = {
    providerName: "mock-missing-covered",
    modelName: "mock-model",
    executeReview: async () => ({
      ok: true,
      executionStatus: EXECUTION_STATUS.EMPTY,
      findings: [],
      coverage: {
        // coveredFiles completely missing!
        omittedFiles: [
          { file: "docs/readme.md", code: "OMIT_OUT_OF_SCOPE", reason: "Documentation file" }
        ]
      },
      providerIdentity: { provider: "mock-missing-covered", family: "anthropic", model: "test", transport: "mock" }
    })
  };

  const result = await orchestrateReview(changeSet, { macro: mockAdapter }, {
    plan: { mode: "single", role: "macro" }
  });

  assert.equal(result.status, "incomplete");
  assert.equal(result.gate.decision, "block");
  assert.match(result.gate.reason, /Coverage Incomplete/i);
});

test("Orchestrator authorized omissions: Hostile throwing getter in omission list fails closed safely without unhandled throw (P2)", async () => {
  const changeSet = makeChangeSet([
    { path: "src/calc.js", additions: 5, deletions: 1 },
    { path: "docs/readme.md", additions: 10, deletions: 0 }
  ]);

  let reads = 0;
  const hostileOmission = {
    file: "docs/readme.md",
    reason: "Documentation",
    get code() {
      reads++;
      if (reads > 1) {
        throw new Error("Hostile secondary getter read detonated!");
      }
      return "OMIT_OUT_OF_SCOPE";
    }
  };

  const mockAdapter = {
    providerName: "mock-hostile-getter",
    modelName: "mock-model",
    executeReview: async () => ({
      ok: true,
      executionStatus: EXECUTION_STATUS.EMPTY,
      findings: [],
      coverage: {
        coveredFiles: ["src/calc.js"],
        omittedFiles: [hostileOmission]
      },
      providerIdentity: { provider: "mock-hostile-getter", family: "anthropic", model: "test", transport: "mock" }
    })
  };

  // Must not throw out of orchestrateReview
  const result = await orchestrateReview(changeSet, { macro: mockAdapter }, {
    plan: { mode: "single", role: "macro" }
  });

  assert.ok(result);
  assert.equal(result.status, "reviewed-clean");
  assert.equal(result.gate.decision, "approve");
});
