import test from "node:test";
import assert from "node:assert/strict";
import {
  buildVerificationPrompt,
  conductIndependentVerification,
  truncateUtf8Safe
} from "../src/core/independent-verifier.mjs";
import {
  buildEvidenceReviewPrompt,
  buildReviewPrompt
} from "../src/adapters/review-prompts.mjs";

test("G5-P2-06: buildVerificationPrompt strictly enforces maxInputBytes hard ceiling (rte6b)", () => {
  const pkg = {
    targetFile: "src/auth.js",
    layers: {
      layer1AstEnclosure: {
        callees: [
          { symbol: "validateToken", lines: 200, bytes: 8000, definition: "x = 1;\n".repeat(200) }
        ]
      }
    }
  };
  const changeSet = {
    scopeMode: "working-tree",
    diffHunks: "@@ -1,5 +1,5 @@\n+ // change line\n".repeat(60),
    files: [{ path: "src/auth.js", additions: 60, deletions: 0 }],
    contextPackage: pkg
  };

  const maxBytes = 6000;
  const prompt = buildVerificationPrompt(changeSet, [], { limits: { maxInputBytes: maxBytes } });
  const promptBytes = Buffer.byteLength(prompt, "utf8");

  assert.ok(promptBytes <= maxBytes, `Verifier prompt byte length (${promptBytes}) must not exceed maxInputBytes (${maxBytes})`);
  assert.ok(prompt.includes("PROMPT_BUDGET_CONTEXT_TRUNCATED"), "Must inject PROMPT_BUDGET_CONTEXT_TRUNCATED gap when context is reduced");
  assert.ok(prompt.includes("[UNRESOLVED CODE CONTEXT GAPS]"), "Must render unresolved context gaps section");
});

test("G5-P2-06: buildEvidenceReviewPrompt strictly enforces maxInputBytes hard ceiling (sMI66)", () => {
  const pkg = {
    targetFile: "src/service.js",
    layers: {
      layer1AstEnclosure: {
        callees: [
          { symbol: "checkPolicy", lines: 300, bytes: 9000, definition: "y = 2;\n".repeat(300) }
        ]
      }
    }
  };
  const changeSet = {
    scopeMode: "working-tree",
    diffHunks: "@@ -1,5 +1,5 @@\n+ // change line\n".repeat(70),
    files: [{ path: "src/service.js", additions: 70, deletions: 0 }]
  };

  const maxBytes = 7000;
  const prompt = buildEvidenceReviewPrompt(changeSet, "macro", { maxInputBytes: maxBytes }, pkg);
  const promptBytes = Buffer.byteLength(prompt, "utf8");

  assert.ok(promptBytes <= maxBytes, `Review prompt byte length (${promptBytes}) must not exceed maxInputBytes (${maxBytes})`);
  assert.ok(prompt.includes("PROMPT_BUDGET_CONTEXT_TRUNCATED"), "Must inject PROMPT_BUDGET_CONTEXT_TRUNCATED gap when context is reduced");
  assert.ok(prompt.includes("[UNRESOLVED CODE CONTEXT GAPS]"), "Must render unresolved context gaps section in sentry prompt");
});

test("G5-P2-06: Diff takes priority over Context in both prompts (DIFF-01)", () => {
  const diffContent = "@@ -1,5 +1,5 @@\n+ const key = 'critical_diff_payload';\n".repeat(40);
  const diffBytes = Buffer.byteLength(diffContent, "utf8");

  const pkg = {
    targetFile: "src/crypto.js",
    layers: {
      layer1AstEnclosure: {
        callees: [
          { symbol: "encrypt", lines: 150, bytes: 5000, definition: "encrypt() {\n" + "  z = 3;\n".repeat(150) + "}" }
        ]
      }
    }
  };
  const changeSet = {
    scopeMode: "working-tree",
    diffHunks: diffContent,
    files: [{ path: "src/crypto.js", additions: 40, deletions: 0 }],
    contextPackage: pkg
  };

  // Set budget sufficient for diff + overhead (~6,700 bytes) but tight for context (+5,000 bytes)
  const maxBytes = 8000;
  const vPrompt = buildVerificationPrompt(changeSet, [], { limits: { maxInputBytes: maxBytes } });
  const sPrompt = buildEvidenceReviewPrompt(changeSet, "macro", { maxInputBytes: maxBytes }, pkg);

  assert.ok(Buffer.byteLength(vPrompt, "utf8") <= maxBytes);
  assert.ok(Buffer.byteLength(sPrompt, "utf8") <= maxBytes);

  // Both should preserve the diff content and inject context truncation gap
  assert.ok(vPrompt.includes("critical_diff_payload"), "Verifier prompt must retain diff payload over context");
  assert.ok(sPrompt.includes("critical_diff_payload"), "Sentry prompt must retain diff payload over context");
  assert.ok(vPrompt.includes("PROMPT_BUDGET_CONTEXT_TRUNCATED"), "Verifier prompt must flag truncated context");
  assert.ok(sPrompt.includes("PROMPT_BUDGET_CONTEXT_TRUNCATED"), "Sentry prompt must flag truncated context");
});

test("G5-P2-06: conductIndependentVerification propagates PROMPT_BUDGET_CONTEXT_TRUNCATED into contextGaps", async () => {
  const pkg = {
    targetFile: "src/handler.js",
    layers: {
      layer1AstEnclosure: {
        callees: [
          { symbol: "handleAuth", lines: 250, bytes: 9000, definition: "auth() {\n" + "  a = 1;\n".repeat(250) + "}" }
        ]
      }
    }
  };
  const changeSet = {
    scopeMode: "working-tree",
    diffHunks: "@@ -1,5 +1,5 @@\n+ // update\n".repeat(50),
    files: [{ path: "src/handler.js", additions: 50, deletions: 0 }],
    contextPackage: pkg
  };

  let capturedAdapterInput = null;
  const mockAdapter = {
    providerName: "claude",
    modelName: "claude-test",
    executeVerification: async (input) => {
      capturedAdapterInput = input;
      return {
        ok: true,
        executionStatus: "success",
        overallStatus: "UNCERTAIN",
        evaluations: [],
        verifierOmissions: []
      };
    }
  };

  const record = await conductIndependentVerification(changeSet, [], mockAdapter, {
    limits: { maxInputBytes: 5000 },
    verificationMode: "clean_challenge"
  });

  assert.ok(capturedAdapterInput !== null, "Verifier adapter was invoked");
  assert.ok(
    capturedAdapterInput.contextGaps.some(g => g.reason === "PROMPT_BUDGET_CONTEXT_TRUNCATED"),
    "Adapter input must include PROMPT_BUDGET_CONTEXT_TRUNCATED gap"
  );
  assert.ok(
    Buffer.byteLength(capturedAdapterInput.prompt, "utf8") <= 5000,
    "Adapter input prompt byte length must be <= 5000"
  );
});
