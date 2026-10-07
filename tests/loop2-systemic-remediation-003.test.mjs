import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import {
  buildEvidenceReviewPrompt,
  buildReviewPrompt
} from "../src/adapters/review-prompts.mjs";
import {
  validateProviderInput,
  EXECUTION_STATUS
} from "../src/adapters/provider-contract.mjs";
import { CliReviewAdapter } from "../src/adapters/cli-transport.mjs";
import {
  buildVerificationPrompt,
  OBJECTIVE_IMPACTS,
  VERIFICATION_VERDICTS
} from "../src/core/independent-verifier.mjs";
import { evaluatePostVerificationGate } from "../src/core/harness.mjs";

test("WP-01: buildEvidenceReviewPrompt includes objective cross-examination block when patchObjective is provided via options", () => {
  const cs = {
    scopeMode: "working-tree",
    contentDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    files: [{ path: "testing/test_debugging.py", additions: 10, deletions: 2 }],
    diffHunks: "- @pytest.mark.xfail\n+ @pytest.mark.xfail(sys.version_info >= (3, 14), reason='Python 3.14 issue')"
  };

  const objective = "Fail the current test and stop the test session on debugger quit / BdbQuit in all cases.";
  const prompt = buildEvidenceReviewPrompt(cs, "macro", undefined, null, { patchObjective: objective });

  assert.match(prompt, /\[DECLARED OBJECTIVE & EXCEPTIONAL BEHAVIOR CROSS-EXAMINATION\]/);
  assert.match(prompt, /Fail the current test and stop the test session on debugger quit \/ BdbQuit in all cases\./);
  assert.match(prompt, /Does retained exceptional behavior contradict the scope the change explicitly claims to complete\?/);
  assert.match(prompt, /@pytest\.mark\.xfail/);
  assert.match(prompt, /OBJECTIVE_CONTRADICTION/);
});

test("WP-01: buildEvidenceReviewPrompt inherits patchObjective from changeSet when options is empty", () => {
  const cs = {
    scopeMode: "working-tree",
    contentDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    patchObjective: "Ensure mounted transports are closed even if main transport raises",
    files: [{ path: "httpx/_client.py", additions: 5, deletions: 1 }],
    diffHunks: "+ for transport in self._mounts.values(): transport.close()"
  };

  const prompt = buildEvidenceReviewPrompt(cs, "macro");

  assert.match(prompt, /\[DECLARED OBJECTIVE & EXCEPTIONAL BEHAVIOR CROSS-EXAMINATION\]/);
  assert.match(prompt, /Ensure mounted transports are closed even if main transport raises/);
});

test("WP-01: buildEvidenceReviewPrompt omits cross-examination section cleanly when patchObjective is absent", () => {
  const cs = {
    scopeMode: "working-tree",
    contentDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    files: [{ path: "lib/utils.js", additions: 3, deletions: 1 }],
    diffHunks: "+ return x + 1;"
  };

  const prompt = buildEvidenceReviewPrompt(cs, "macro");

  assert.doesNotMatch(prompt, /\[DECLARED OBJECTIVE & EXCEPTIONAL BEHAVIOR CROSS-EXAMINATION\]/);
  assert.doesNotMatch(prompt, /Mandatory Cross-Examination Rule/);
});

test("WP-01: buildReviewPrompt maintains backward compatibility while accepting options.patchObjective", () => {
  const cs = {
    scopeMode: "working-tree",
    contentDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    files: [{ path: "lib/utils.js", additions: 2, deletions: 0 }],
    diffHunks: "+ const y = 2;"
  };

  const legacyPrompt = buildReviewPrompt(cs, "micro");
  assert.doesNotMatch(legacyPrompt, /\[DECLARED OBJECTIVE & EXCEPTIONAL BEHAVIOR CROSS-EXAMINATION\]/);

  const objectivePrompt = buildReviewPrompt(cs, "macro", undefined, { patchObjective: "Fix memory leak in buffer pool" });
  assert.match(objectivePrompt, /\[DECLARED OBJECTIVE & EXCEPTIONAL BEHAVIOR CROSS-EXAMINATION\]/);
  assert.match(objectivePrompt, /Fix memory leak in buffer pool/);
});

test("WP-01: validateProviderInput preserves patchObjective and options on sanitized input", () => {
  const rawInput = {
    runId: "run-test-001",
    role: "sentry",
    changeSet: {
      schemaVersion: "1.0.0",
      contentDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      files: [{ path: "index.js" }]
    },
    policyId: "TEST_POLICY",
    timeoutMs: 30000,
    patchObjective: "Stop test session on BdbQuit in all cases",
    options: { someFlag: true }
  };

  const validated = validateProviderInput(rawInput);
  assert.equal(validated.valid, true);
  assert.equal(validated.input.patchObjective, "Stop test session on BdbQuit in all cases");
  assert.equal(validated.input.options?.someFlag, true);
});

test("WP-01: CliReviewAdapter forwards patchObjective into buildReviewPrompt and execution context", async () => {
  let capturedPrompt = null;
  const cs = {
    schemaVersion: "1.0.0",
    scopeMode: "working-tree",
    contentDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    files: [{ path: "src/core.py" }],
    diffHunks: "+ pass"
  };

  const adapter = new CliReviewAdapter({
    command: "agy",
    providerName: "agy",
    execFn: async ({ prompt }) => {
      capturedPrompt = prompt;
      return {
        stdout: JSON.stringify({
          findings: [],
          coverage: { coveredFiles: ["src/core.py"], omittedFiles: [] }
        })
      };
    }
  });

  const res = await adapter.executeReview({
    runId: "test-forwarding-001",
    role: "agy",
    changeSet: cs,
    policyId: "TEST_POLICY",
    patchObjective: "Explicit cross-examination test objective"
  });

  assert.equal(res.ok, true);
  assert.ok(capturedPrompt, "Prompt should have been generated and passed to execFn");
  assert.match(capturedPrompt, /Explicit cross-examination test objective/);
  assert.match(capturedPrompt, /\[DECLARED OBJECTIVE & EXCEPTIONAL BEHAVIOR CROSS-EXAMINATION\]/);
});

test("WP-02: buildVerificationPrompt includes the algebraic objective completeness rubric", () => {
  const cs = {
    scopeMode: "working-tree",
    contentDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    files: [{ path: "httpx/_client.py", additions: 5, deletions: 1 }],
    diffHunks: "+ for transport in self._mounts.values(): transport.close()"
  };

  const findings = [{
    id: "finding-1",
    title: "Failure in one mounted transport still skips remaining mounts",
    file: "httpx/_client.py",
    line_start: 1270,
    line_end: 1275,
    severity: "low"
  }];

  const prompt = buildVerificationPrompt(cs, findings, {
    patchObjective: "Ensure mounted transports are closed even if main transport raises"
  });

  assert.match(prompt, /Objective Completeness = Declared Scope \* (?:Documented|Authorized Pre-Bound) Exclusions \* Observable Residual Counterexample/);
  assert.match(prompt, /Assign "FALSIFIES_PATCH_OBJECTIVE" if and only if:/);
  assert.match(prompt, /The counterexample falls strictly within the (?:Declared Scope|Stated Patch Objective)/);
  assert.match(prompt, /The counterexample is NOT (?:an explicitly documented exclusion|listed in the Authorized Pre-Bound Exclusions)/);
  assert.match(prompt, /Assign "DOES_NOT_FALSIFY_PATCH_OBJECTIVE" if:/);
  assert.match(prompt, /Assign "NOT_ASSESSED" if no stated patch objective was provided/);
});

test("WP-02: Gate blocks when finding has FALSIFIES_PATCH_OBJECTIVE under WP-02 (CYCLE-0021 Pattern)", () => {
  const consensus = {
    findings: [{
      id: "f-httpx-01",
      title: "Failure in one mounted transport still skips remaining mounts",
      severity: "low",
      file: "httpx/_client.py",
      line_start: 1270,
      line_end: 1275
    }]
  };

  const verificationRecord = {
    ok: true,
    patchObjective: "Ensure mounted transports are closed even if main transport raises",
    evaluations: [{
      findingId: "f-httpx-01",
      verdict: "SUPPORTED",
      locatorAccurate: true,
      typeAccurate: true,
      severityAccurate: true,
      objectiveImpact: "FALSIFIES_PATCH_OBJECTIVE",
      reasoning: "First failing mount aborts cleanup loop before subsequent mounts are closed. This residual failure is within declared scope and not an excluded boundary."
    }]
  };

  const gateResult = evaluatePostVerificationGate(consensus, verificationRecord, { tier: 2 });
  assert.equal(gateResult.decision, "block");
  assert.match(gateResult.reason, /falsifies stated patch objective/);
});

test("WP-02: Gate approves advisory Low when limitation is a documented exclusion (DOES_NOT_FALSIFY)", () => {
  const consensus = {
    findings: [{
      id: "f-doc-excl-01",
      title: "Unix domain sockets remain unhandled by Windows named pipe transport",
      severity: "low",
      file: "httpx/_client.py",
      line_start: 100,
      line_end: 105
    }]
  };

  const verificationRecord = {
    ok: true,
    patchObjective: "Add Windows named pipe transport (Unix domain sockets explicitly excluded)",
    evaluations: [{
      findingId: "f-doc-excl-01",
      verdict: "SUPPORTED",
      locatorAccurate: true,
      typeAccurate: true,
      severityAccurate: true,
      objectiveImpact: "DOES_NOT_FALSIFY_PATCH_OBJECTIVE",
      reasoning: "The limitation is explicitly stated in the PR body as an intentional exclusion."
    }]
  };

  const gateResult = evaluatePostVerificationGate(consensus, verificationRecord, { tier: 2 });
  assert.equal(gateResult.decision, "approve");
});

test("WP-02: Gate blocks when sentry flags retained xfail contradicting all-cases objective (CYCLE-0022 Pattern)", () => {
  const consensus = {
    findings: [{
      id: "f-pytest-01",
      title: "Retained xfail contradicts declared patch objective",
      severity: "low",
      type: "OBJECTIVE_CONTRADICTION",
      file: "testing/test_debugging.py",
      line_start: 50,
      line_end: 55
    }]
  };

  const verificationRecord = {
    ok: true,
    patchObjective: "Fail the current test and stop the test session on debugger quit / BdbQuit in all cases.",
    evaluations: [{
      findingId: "f-pytest-01",
      verdict: "SUPPORTED",
      locatorAccurate: true,
      typeAccurate: true,
      severityAccurate: true,
      objectiveImpact: "FALSIFIES_PATCH_OBJECTIVE",
      reasoning: "Retained xfail on Python 3.14 means test does not report as failed on 3.14, directly contradicting claimed 'in all cases' scope."
    }]
  };

  const gateResult = evaluatePostVerificationGate(consensus, verificationRecord, { tier: 2 });
  assert.equal(gateResult.decision, "block");
  assert.match(gateResult.reason, /falsifies stated patch objective/);
});

test("WP-02: Gate allows ordinary advisory Low finding without patch objective falsification (Precision Guard)", () => {
  const consensus = {
    findings: [{
      id: "f-style-01",
      title: "Consider using helper function instead of manual loop",
      severity: "low",
      file: "src/utils.py",
      line_start: 20,
      line_end: 25
    }]
  };

  const verificationRecord = {
    ok: true,
    patchObjective: "Refactor string parsing for performance",
    evaluations: [{
      findingId: "f-style-01",
      verdict: "SUPPORTED",
      locatorAccurate: true,
      typeAccurate: true,
      severityAccurate: true,
      objectiveImpact: "DOES_NOT_FALSIFY_PATCH_OBJECTIVE",
      reasoning: "Style preference does not falsify string parsing performance objective."
    }]
  };

  const gateResult = evaluatePostVerificationGate(consensus, verificationRecord, { tier: 2 });
  assert.equal(gateResult.decision, "approve");
});

test("WP-03: Historical cohort (receipts 1-22 in dogfood-receipts.jsonl) remains intact and frozen", () => {
  const receiptsPath = path.resolve(process.cwd(), "docs/benchmarks/dogfood-receipts.jsonl");
  assert.ok(fs.existsSync(receiptsPath), "dogfood-receipts.jsonl must exist");

  const lines = fs.readFileSync(receiptsPath, "utf8").trim().split("\n");
  assert.ok(lines.length >= 22, "Historical baseline must contain at least 22 receipts");

  const r21 = JSON.parse(lines[20]);
  assert.equal(r21.cycleId, "CYCLE-0021");
  assert.equal(r21.discrepancy, "FALSE_ADVANCE");

  const r22 = JSON.parse(lines[21]);
  assert.equal(r22.cycleId, "CYCLE-0022");
  assert.equal(r22.discrepancy, "FALSE_ADVANCE");
});
