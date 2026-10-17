import test from "node:test";
import assert from "node:assert/strict";

import {
  getFindingSignature,
  evaluateGateDecision,
  evaluateIsolatedTestGate
} from "../src/core/harness.mjs";
import { aggregateConsensus } from "../src/core/loop.mjs";
import {
  CliVerifierAdapter,
  RunContext,
  isTrustedVerificationRecord,
  issueVerificationRecordFromOutput
} from "../src/core/independent-verifier.mjs";
import { EXECUTION_STATUS } from "../src/adapters/provider-contract.mjs";
import {
  findBraceScopeEnd,
  findFunctionDefinitions,
  findQualifiedFunctionDefinitions,
  extractBoundedFunctionSnippet
} from "../src/core/context-builder.mjs";

// ============================================================================
// td7cI: Finding signature binding for sources and corroborations
// ============================================================================
test("td7cI-NEG: getFindingSignature differentiates findings by sources and corroborations", () => {
  const baseFinding = {
    id: "SEC-001",
    ruleId: "NO_EVAL",
    title: "Arbitrary code execution",
    file: "src/eval.js",
    line_start: 10,
    line_end: 20,
    severity: "critical",
    cwe: "CWE-95",
    type: "vulnerability",
    recommendation: "Avoid eval"
  };

  const sigSolitary = getFindingSignature({
    ...baseFinding,
    sources: ["agy"],
    corroborations: 1
  });

  const sigCorroborated = getFindingSignature({
    ...baseFinding,
    sources: ["agy", "claude"],
    corroborations: 2
  });

  assert.notEqual(sigSolitary, sigCorroborated, "Solitary finding signature must differ from corroborated finding signature");

  // Sources normalization: sorting, case-insensitivity, trimming, and deduplication
  const sigUnnormalizedSources = getFindingSignature({
    ...baseFinding,
    sources: [" Claude ", "agy", "CLAUDE"],
    corroborations: 2
  });
  assert.equal(sigUnnormalizedSources, sigCorroborated, "Sources must be deterministically trimmed, lowercased, sorted, and deduplicated");

  // Corroborations string vs number parsing
  const sigStringCorroborations = getFindingSignature({
    ...baseFinding,
    sources: ["agy", "claude"],
    corroborations: "2"
  });
  assert.equal(sigStringCorroborations, sigCorroborated, "Integer string corroborations must parse to numeric corroborations");

  // Illegal corroboration values must be tagged ILLEGAL
  const sigIllegalCorroboration = getFindingSignature({
    ...baseFinding,
    corroborations: -1
  });
  assert.match(sigIllegalCorroboration, /"ILLEGAL:-1"/);

  const sigNaNCorroboration = getFindingSignature({
    ...baseFinding,
    corroborations: NaN
  });
  assert.match(sigNaNCorroboration, /"ILLEGAL:NaN"/);

  // Corroborations: 0 must be rejected as ILLEGAL:0
  const sigZeroNumber = getFindingSignature({
    ...baseFinding,
    corroborations: 0
  });
  assert.match(sigZeroNumber, /"ILLEGAL:0"/, "corroborations: 0 must be flagged as ILLEGAL:0");

  const sigZeroString = getFindingSignature({
    ...baseFinding,
    corroborations: "0"
  });
  assert.match(sigZeroString, /"ILLEGAL:0"/, 'corroborations: "0" must be flagged as ILLEGAL:0');

  const sigNonInteger = getFindingSignature({
    ...baseFinding,
    corroborations: 1.5
  });
  assert.match(sigNonInteger, /"ILLEGAL:1.5"/, "Non-integer corroborations must be flagged as ILLEGAL:1.5");
});

function makeTrustedConsensus(findings = [], { tier = 2, quorumReached = true } = {}) {
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

  const rawReports = {
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

  return aggregateConsensus(rawReports, {
    policy: "TRI_PARTY_HETEROGENEOUS",
    tier
  });
}

test("td7cI-NEG: evaluateGateDecision blocks on sources/corroborations mismatch between producer and bound findings", () => {
  const producerFindings = [
    {
      id: "SEC-001",
      ruleId: "NO_EVAL",
      title: "Arbitrary code execution",
      file: "src/eval.js",
      line_start: 10,
      line_end: 20,
      severity: "critical",
      cwe: "CWE-95",
      type: "vulnerability",
      recommendation: "Avoid eval",
      sources: ["agy", "claude"],
      corroborations: 2
    }
  ];

  const boundProducerFindings = [
    {
      id: "SEC-001",
      ruleId: "NO_EVAL",
      title: "Arbitrary code execution",
      file: "src/eval.js",
      line_start: 10,
      line_end: 20,
      severity: "critical",
      cwe: "CWE-95",
      type: "vulnerability",
      recommendation: "Avoid eval",
      sources: ["agy"], // Altered sources -> different signature
      corroborations: 1
    }
  ];

  const mockRecord = issueVerificationRecordFromOutput({
    ok: true,
    verificationMode: "producer_verification",
    producerFindings: boundProducerFindings,
    evaluations: [
      {
        findingId: "SEC-001",
        verdict: "CONTESTED",
        locatorAccurate: true,
        typeAccurate: true,
        severityAccurate: true,
        reasoning: "Not reachable in production path because callers never reach this code."
      }
    ],
    verifierOmissions: []
  });

  const consensus = makeTrustedConsensus(producerFindings, { tier: 2 });
  const gateResult = evaluateIsolatedTestGate(consensus, {
    verificationRecord: mockRecord
  });

  assert.equal(gateResult.decision, "block");
  assert.match(gateResult.reason, /FINDING_SET_BINDING_MISMATCH/);
});

// ============================================================================
// td7cG: CliVerifierAdapter bounds stderr and combined stream memory
// ============================================================================
test("td7cG-NEG: CliVerifierAdapter terminates child process when stderr alone exceeds maxOutputBytes", async () => {
  const adapter = new CliVerifierAdapter({
    command: process.execPath,
    args: ["-e", "process.stderr.write(Buffer.alloc(50000, 66));"]
  });

  const res = await adapter.executeVerification({
    prompt: "Evaluate diff",
    limits: {
      maxOutputBytes: 1024
    }
  });

  assert.equal(res.ok, false, "Execution must fail when stderr exceeds maxOutputBytes");
  assert.equal(res.executionStatus, EXECUTION_STATUS.PAYLOAD_TOO_LARGE);
  assert.match(res.error, /maxOutputBytes/i);
});

test("td7cG-NEG: CliVerifierAdapter terminates child when combined stdout and stderr exceeds maxOutputBytes", async () => {
  const adapter = new CliVerifierAdapter({
    command: process.execPath,
    args: ["-e", "process.stdout.write(Buffer.alloc(800, 65)); process.stderr.write(Buffer.alloc(800, 66));"]
  });

  const res = await adapter.executeVerification({
    prompt: "Evaluate diff",
    limits: {
      maxOutputBytes: 1000 // 800 + 800 = 1600 > 1000
    }
  });

  assert.equal(res.ok, false, "Execution must fail when combined stdout+stderr exceeds maxOutputBytes");
  assert.equal(res.executionStatus, EXECUTION_STATUS.PAYLOAD_TOO_LARGE);
  assert.match(res.error, /maxOutputBytes/i);
});

test("td7cG-POS: CliVerifierAdapter succeeds when combined stdout and stderr is within maxOutputBytes", async () => {
  const validJson = JSON.stringify({
    ok: true,
    overallStatus: "CLEAN",
    evaluations: [],
    omissions: []
  });

  const adapter = new CliVerifierAdapter({
    command: process.execPath,
    args: ["-e", `process.stderr.write("log message\\n"); process.stdout.write(${JSON.stringify(validJson)});`]
  });

  const res = await adapter.executeVerification({
    prompt: "Evaluate diff",
    limits: {
      maxOutputBytes: 10000
    }
  });

  assert.equal(res.ok, true);
  assert.equal(res.overallStatus, "CLEAN");
});

test("td7cG-NEG: _processResult bounds combined stdout and stderr for custom execFn results", () => {
  const adapter = new CliVerifierAdapter({
    providerName: "mock-custom"
  });

  const mockRes = {
    ok: true,
    stdout: "A".repeat(600),
    stderr: "B".repeat(600)
  };

  const processed = adapter._processResult(mockRes, { maxOutputBytes: 1000 });
  assert.equal(processed.ok, false);
  assert.equal(processed.executionStatus, EXECUTION_STATUS.PAYLOAD_TOO_LARGE);
  assert.match(processed.error, /maxOutputBytes/);
});

// ============================================================================
// td7cF: Brace scope lexer and callee extraction robustness
// ============================================================================
test("td7cF-NEG: findBraceScopeEnd handles regex literals containing braces without corrupting scope", () => {
  // Regex /}/
  const codeRegexClose = [
    "function parseClose() {",
    "  const regex = /}/;",
    "  return regex.test('}');",
    "}"
  ];
  assert.equal(findBraceScopeEnd(codeRegexClose, 0), 4, "Regex with closing brace /}/ must not close scope prematurely");

  // Regex /{/
  const codeRegexOpen = [
    "function parseOpen() {",
    "  const regex = /{/;",
    "  return regex.test('{');",
    "}",
    "function nextFn() { return 1; }"
  ];
  assert.equal(findBraceScopeEnd(codeRegexOpen, 0), 4, "Regex with opening brace /{/ must not inflate scope depth");

  // Regex character class with braces /[{}]/
  const codeRegexClass = [
    "function parseClass() {",
    "  const regex = /[{}]/g;",
    "  return true;",
    "}"
  ];
  assert.equal(findBraceScopeEnd(codeRegexClass, 0), 4, "Regex with character class /[{}]/ must not alter scope depth");

  // Division operator should not be misidentified as regex
  const codeDivision = [
    "function divide(a, b) {",
    "  const result = a / b;",
    "  return result;",
    "}"
  ];
  assert.equal(findBraceScopeEnd(codeDivision, 0), 4, "Division operator / must not disrupt brace tracking");
});

test("td7cF-NEG: findBraceScopeEnd handles multiline template literals containing braces", () => {
  const codeTemplate = [
    "function formatOutput() {",
    "  const template = `",
    "  {",
    "    \"not_a_code_block\": true",
    "  }",
    "  `;",
    "  return template.trim();",
    "}"
  ];
  assert.equal(findBraceScopeEnd(codeTemplate, 0), 8, "Multiline template strings with braces must not affect scope depth");
});

test("td7cF-POS: findBraceScopeEnd and findFunctionDefinitions accurately extract full function containing return /}/", () => {
  const codeValidateToken = [
    "function validateToken(token) {",
    '  if (token === "edge") return /}/.test(token);',
    '  if (!authorize(token)) throw new Error("ACCESS_DENIED");',
    "  return true;",
    "}"
  ];

  // 1. findBraceScopeEnd must return line 5 (not line 2)
  const endLine = findBraceScopeEnd(codeValidateToken, 0);
  assert.equal(endLine, 5, "findBraceScopeEnd must return line 5 for validateToken containing return /}/");

  // 2. findFunctionDefinitions must return lines 1-5
  const matches = findFunctionDefinitions(codeValidateToken, "validateToken");
  assert.equal(matches.length, 1, "findFunctionDefinitions must find exactly one definition");
  assert.equal(matches[0].startLine, 1);
  assert.equal(matches[0].endLine, 5);

  // 3. extractBoundedFunctionSnippet must label full_body and preserve guards
  const snippet = extractBoundedFunctionSnippet(codeValidateToken, 1, 5);
  assert.equal(snippet.extractionMode, "full_body", "Valid closed function must be extracted as full_body");
  assert.equal(snippet.lines, 5);
  assert.ok(snippet.definition.includes("authorize(token)"), "Full body must preserve authorization guard");
});

test("td7cF-NEG: extractBoundedFunctionSnippet never labels unconfirmed or truncated function as full_body", () => {
  const codeValidateToken = [
    "function validateToken(token) {",
    '  if (token === "edge") return /}/.test(token);',
    '  if (!authorize(token)) throw new Error("ACCESS_DENIED");',
    "  return true;",
    "}"
  ];

  // If prematurely truncated at line 2, it must not be labeled full_body
  const snippetTruncated = extractBoundedFunctionSnippet(codeValidateToken, 1, 2);
  assert.notEqual(snippetTruncated.extractionMode, "full_body", "Truncated function must never be labeled full_body");
  assert.equal(snippetTruncated.extractionMode, "incomplete", "Truncated function must be labeled incomplete");
});

test("td7cF-NEG: unclosed function scope fails closed and is never labeled full_body", () => {
  const unclosedCode = [
    "function unclosedFn() {",
    "  const a = 1;",
    "  return a;"
  ];

  // Default findBraceScopeEnd without failClosed bounds to lines.length for backwards compatibility
  assert.equal(findBraceScopeEnd(unclosedCode, 0), unclosedCode.length, "Default findBraceScopeEnd bounds to lines.length");

  // findBraceScopeEnd with failClosed: true returns -1
  assert.equal(findBraceScopeEnd(unclosedCode, 0, { failClosed: true }), -1, "findBraceScopeEnd with failClosed returns -1");

  // findFunctionDefinitions does not match unclosed function
  const defs = findFunctionDefinitions(unclosedCode, "unclosedFn");
  assert.equal(defs.length, 0, "findFunctionDefinitions must reject unclosed function definitions");

  // extractBoundedFunctionSnippet never marks unclosed function as full_body
  const snippet = extractBoundedFunctionSnippet(unclosedCode, 1, unclosedCode.length);
  assert.notEqual(snippet.extractionMode, "full_body", "Unclosed function must never be labeled full_body");
  assert.equal(snippet.extractionMode, "incomplete", "Unclosed function must be labeled incomplete");
});

test("td7cF-NEG: findQualifiedFunctionDefinitions correctly isolates class body despite comments containing braces", () => {
  const classLines = [
    "class SecurityService {",
    "  // Internal notes: ensure token matches format: }",
    "  /* Multi-line comment { brace block } inside class */",
    "  static validateToken(token) {",
    "    return token === 'secret';",
    "  }",
    "}"
  ];

  const matches = findQualifiedFunctionDefinitions(classLines, "SecurityService", "validateToken");
  assert.equal(matches.length, 1, "Must find exactly one definition of validateToken within SecurityService");
  assert.equal(matches[0].startLine, 4);
  assert.equal(matches[0].endLine, 6);
});
