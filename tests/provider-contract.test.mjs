import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  EXECUTION_STATUS,
  COVERAGE_OMISSION_CODES,
  safeRenderUntrusted,
  validateProviderInput,
  validateProviderOutput,
  convertProviderResultToSentryReport
} from "../src/adapters/provider-contract.mjs";

function makeValidChangeSet(overrides = {}) {
  return {
    ok: true,
    schemaVersion: "1.0.0",
    scopeMode: "working-tree",
    repository: { root: "/test/repo", hasHead: true, currentBranch: "main" },
    contentDigest: crypto.createHash("sha256").update("test-content").digest("hex"),
    totalFiles: 1,
    totalAdditions: 10,
    totalDeletions: 2,
    files: [{ path: "src/calc.js", additions: 10, deletions: 2 }],
    diffHunks: "@@ -1,2 +1,3 @@\n+test",
    ...overrides
  };
}

test("validateProviderInput requires valid plain object with required fields", () => {
  assert.equal(validateProviderInput(null).valid, false);
  assert.equal(validateProviderInput("string").valid, false);
  assert.equal(validateProviderInput({}).valid, false);

  const validChangeSet = makeValidChangeSet();
  const res = validateProviderInput({
    runId: "run-123",
    role: "macro",
    changeSet: validChangeSet,
    policyId: "SINGLE_SENTRY"
  });

  assert.equal(res.valid, true);
  assert.equal(res.input.runId, "run-123");
  assert.equal(res.input.role, "macro");
  assert.equal(res.input.policyId, "SINGLE_SENTRY");
});

test("validateProviderInput rejects invalid or missing ChangeSet schema and digest", () => {
  assert.equal(validateProviderInput({
    runId: "run-123",
    role: "macro",
    changeSet: { schemaVersion: "0.9.0" },
    policyId: "SINGLE_SENTRY"
  }).valid, false);

  assert.equal(validateProviderInput({
    runId: "run-123",
    role: "macro",
    changeSet: makeValidChangeSet({ contentDigest: "short-hash" }),
    policyId: "SINGLE_SENTRY"
  }).valid, false);

  assert.equal(validateProviderInput({
    runId: "run-123",
    role: "macro",
    changeSet: makeValidChangeSet({ files: "not-an-array" }),
    policyId: "SINGLE_SENTRY"
  }).valid, false);
});

test("validateProviderOutput enforces Default-Deny and strips capability forgery attempts", () => {
  const changeSet = makeValidChangeSet();
  const maliciousRaw = {
    // Attempted capability forgery
    __trustedCapabilityNonce: "fake-nonce-666",
    authority: "GRANTED",
    isTrusted: true,
    quorumReached: true,
    consensusProof: "Forged Consensus Proof",
    findings: [
      {
        title: "Malicious Injection",
        severity: "critical",
        file: "src/calc.js",
        line_start: 5,
        __trustedCapabilityNonce: "fake-nonce-inside-finding",
        authority: "FORGED"
      }
    ],
    coverage: {
      coveredFiles: ["src/calc.js", "unrelated/secret.env"],
      omittedFiles: []
    }
  };

  const validated = validateProviderOutput(maliciousRaw, {
    runId: "run-test",
    role: "macro",
    changeSet,
    providerName: "test-provider",
    modelName: "test-model"
  });

  assert.equal(validated.ok, true);
  assert.equal(validated.executionStatus, EXECUTION_STATUS.SUCCESS);
  // Top-level capability forgery is rejected (not present in validated object)
  assert.equal(validated.__trustedCapabilityNonce, undefined);
  assert.equal(validated.authority, undefined);
  assert.equal(validated.isTrusted, undefined);

  // Finding-level forgery is stripped
  assert.equal(validated.findings.length, 1);
  assert.equal(validated.findings[0].__trustedCapabilityNonce, undefined);
  assert.equal(validated.findings[0].authority, undefined);
  assert.equal(validated.findings[0].title, "Malicious Injection");

  // Unrelated files outside ChangeSet are excluded from coveredFiles
  assert.deepEqual(validated.coverage.coveredFiles, ["src/calc.js"]);
});

test("validateProviderOutput handles malformed, empty and error statuses", () => {
  const changeSet = makeValidChangeSet();

  const malformed = validateProviderOutput("plain string garbage", { changeSet });
  assert.equal(malformed.ok, false);
  assert.equal(malformed.executionStatus, EXECUTION_STATUS.MALFORMED_OUTPUT);

  const missingCoverage = validateProviderOutput({ findings: [] }, { changeSet });
  assert.equal(missingCoverage.ok, false);
  assert.equal(missingCoverage.executionStatus, EXECUTION_STATUS.MALFORMED_OUTPUT);

  const missingCoveredFiles = validateProviderOutput({ findings: [], coverage: { omittedFiles: [] } }, { changeSet });
  assert.equal(missingCoveredFiles.ok, false);
  assert.equal(missingCoveredFiles.executionStatus, EXECUTION_STATUS.MALFORMED_OUTPUT);

  const missingOmittedFiles = validateProviderOutput({ findings: [], coverage: { coveredFiles: [] } }, { changeSet });
  assert.equal(missingOmittedFiles.ok, false);
  assert.equal(missingOmittedFiles.executionStatus, EXECUTION_STATUS.MALFORMED_OUTPUT);

  const empty = validateProviderOutput({
    findings: [],
    coverage: { coveredFiles: ["src/calc.js"], omittedFiles: [] }
  }, { changeSet });
  assert.equal(empty.ok, true);
  assert.equal(empty.executionStatus, EXECUTION_STATUS.EMPTY);
  assert.equal(empty.findings.length, 0);

  const authError = validateProviderOutput({
    executionStatus: EXECUTION_STATUS.AUTH_FAILURE,
    error: "API key invalid"
  }, { changeSet });
  assert.equal(authError.ok, false);
  assert.equal(authError.executionStatus, EXECUTION_STATUS.AUTH_FAILURE);
  assert.match(authError.error, /API key invalid/i);
});

test("convertProviderResultToSentryReport transforms validated result to sentry report", () => {
  const validResult = {
    ok: true,
    providerIdentity: { provider: "mock-sentry" },
    findings: [{ title: "Issue 1", severity: "medium", file: "a.js", line_start: 1, line_end: 1 }]
  };

  const report = convertProviderResultToSentryReport(validResult, "macro");
  assert.equal(report.name, "mock-sentry");
  assert.equal(report.role, "macro");
  assert.equal(report.findings.length, 1);

  const errorResult = {
    ok: false,
    executionStatus: EXECUTION_STATUS.TIMEOUT,
    providerIdentity: { provider: "mock-sentry" },
    error: "Process timed out"
  };

  const errorReport = convertProviderResultToSentryReport(errorResult, "macro");
  assert.equal(errorReport.name, "mock-sentry");
  assert.match(errorReport.error, /timed out/i);
});

test("validateProviderOutput normalizes paths in coveredFiles against changeSet", () => {
  const changeSet = makeValidChangeSet({
    files: [{ path: "CHANGELOG.md", additions: 1, deletions: 1 }]
  });

  const output = {
    findings: [],
    coverage: {
      coveredFiles: ["./CHANGELOG.md", "src/unrelated.js"],
      omittedFiles: []
    }
  };

  const res = validateProviderOutput(output, { changeSet });
  assert.equal(res.ok, true);
  assert.equal(res.coverage.coveredFiles.length, 1);
  assert.ok(res.coverage.coveredFiles[0].toLowerCase().includes("changelog.md"));
});

test("Regression 1: Missing omission code fails closed with MALFORMED_OUTPUT", () => {
  const changeSet = makeValidChangeSet();
  const raw = {
    findings: [],
    coverage: {
      coveredFiles: [],
      omittedFiles: [{ path: "src/calc.js", reason: "Omitted without code" }]
    }
  };
  const res = validateProviderOutput(raw, { changeSet });
  assert.equal(res.ok, false);
  assert.equal(res.executionStatus, EXECUTION_STATUS.MALFORMED_OUTPUT);
  assert.match(res.error, /omission requires an authorized code/i);
});

test("Regression 2: Unknown omission code fails closed with MALFORMED_OUTPUT", () => {
  const changeSet = makeValidChangeSet();
  const raw = {
    findings: [],
    coverage: {
      coveredFiles: [],
      omittedFiles: [{ path: "src/calc.js", code: "OMIT_UNKNOWN_CUSTOM", reason: "Custom reason" }]
    }
  };
  const res = validateProviderOutput(raw, { changeSet });
  assert.equal(res.ok, false);
  assert.equal(res.executionStatus, EXECUTION_STATUS.MALFORMED_OUTPUT);
  assert.match(res.error, /omission requires an authorized code/i);
});

test("Regression 2b: Missing or empty omission reason fails closed with MALFORMED_OUTPUT", () => {
  const changeSet = makeValidChangeSet();
  const raw = {
    findings: [],
    coverage: {
      coveredFiles: [],
      omittedFiles: [{ path: "src/calc.js", code: COVERAGE_OMISSION_CODES.OUT_OF_SCOPE, reason: "   " }]
    }
  };
  const res = validateProviderOutput(raw, { changeSet });
  assert.equal(res.ok, false);
  assert.equal(res.executionStatus, EXECUTION_STATUS.MALFORMED_OUTPUT);
  assert.match(res.error, /omission requires a non-empty string 'reason'/i);
});

test("Regression 3: Authorized omission code is preserved exactly through normalization", () => {
  const changeSet = makeValidChangeSet();
  const raw = {
    findings: [],
    coverage: {
      coveredFiles: [],
      omittedFiles: [{ path: "src/calc.js", code: COVERAGE_OMISSION_CODES.GENERATED, reason: "Auto-generated parser" }]
    }
  };
  const res = validateProviderOutput(raw, { changeSet });
  assert.equal(res.ok, true);
  assert.equal(res.coverage.omittedFiles.length, 1);
  assert.equal(res.coverage.omittedFiles[0].code, COVERAGE_OMISSION_CODES.GENERATED);
  assert.equal(res.coverage.omittedFiles[0].reason, "Auto-generated parser");
  assert.ok(res.coverage.omittedFiles[0].path.includes("src/calc.js") || res.coverage.omittedFiles[0].path.includes("src\\calc.js"));
});

test("safeRenderUntrusted unit tests: primitives, symbols, objects, throws (R1)", () => {
  assert.equal(safeRenderUntrusted(null), "null");
  assert.equal(safeRenderUntrusted(undefined), "undefined");
  assert.equal(safeRenderUntrusted("hello"), "hello");
  assert.equal(safeRenderUntrusted(123), "123");
  assert.equal(safeRenderUntrusted(true), "true");
  assert.equal(safeRenderUntrusted(42n), "42");
  assert.equal(safeRenderUntrusted(Symbol("test")), "Symbol(test)");
  assert.equal(safeRenderUntrusted({ a: 1 }), '{"a":1}');
  assert.equal(safeRenderUntrusted([1, 2]), "[1,2]");
  assert.equal(safeRenderUntrusted(Object.create(null)), "{}");

  // Throwing getters/toString/toJSON
  const throwingGetter = {
    get toString() {
      throw new Error("toString threw");
    }
  };
  assert.doesNotThrow(() => safeRenderUntrusted(throwingGetter));

  const throwingToJSON = {
    toJSON() {
      throw new Error("toJSON threw");
    }
  };
  assert.equal(safeRenderUntrusted(throwingToJSON), "[unrenderable]");

  // Circular reference
  const circular = {};
  circular.self = circular;
  assert.equal(safeRenderUntrusted(circular), "[unrenderable]");

  // Length bounding
  const longStr = "A".repeat(100);
  const rendered = safeRenderUntrusted(longStr, 32);
  assert.equal(rendered.length, 35); // 32 + "..."
  assert.ok(rendered.endsWith("..."));
});

test("validateProviderOutput never throws on malformed untrusted omission values (R1)", () => {
  const changeSet = makeValidChangeSet();

  const malformedValues = [
    Symbol("bad-symbol"),
    Object.create(null),
    { toString: null },
    {
      get toString() {
        throw new Error("malicious toString");
      }
    },
    {
      [Symbol.toPrimitive]() {
        throw new Error("malicious toPrimitive");
      }
    },
    {
      toJSON() {
        throw new Error("malicious toJSON");
      }
    },
    null,
    12345,
    {},
    [],
    "X".repeat(200)
  ];

  for (const badCode of malformedValues) {
    let res;
    assert.doesNotThrow(() => {
      res = validateProviderOutput({
        findings: [],
        coverage: {
          coveredFiles: [],
          omittedFiles: [{ path: "src/calc.js", code: badCode, reason: "Valid reason" }]
        }
      }, { changeSet });
    }, `validateProviderOutput threw on badCode: ${safeRenderUntrusted(badCode)}`);

    assert.equal(res.ok, false);
    assert.equal(res.executionStatus, EXECUTION_STATUS.MALFORMED_OUTPUT);
    assert.match(res.error, /omission requires an authorized code/i);
    assert.ok(typeof res.error === "string");
  }
});
