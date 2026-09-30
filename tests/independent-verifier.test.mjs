/**
 * Triad-Flow Independent Verification Layer & Disagreement Ledger Tests
 *
 * Tests compliance with TF-SPEC-RECEIPT-v1.0.0 Section 7:
 * - Producer / Verifier Decoupling
 * - Bit-level verbatim immutability of producer findings
 * - Default-Deny evaluation and Disagreement Ledger mechanics
 * - Verifier omissions isolation without polluting producer findings
 * - Error handling, timeouts, malformed responses, and schema validation
 * - BENCH-REAL-001 Gate Declaration verification
 */

import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  buildVerificationPrompt,
  validateVerificationOutput,
  conductIndependentVerification,
  validateVerificationRecord,
  computeVerificationRecordDigest,
  VERIFICATION_SCHEMA_VERSION,
  VERIFICATION_VERDICTS,
  CliVerifierAdapter,
  deepFreeze
} from "../src/core/independent-verifier.mjs";
import { EXECUTION_STATUS } from "../src/adapters/provider-contract.mjs";
import { getCorpusCaseById, createCorpusCaseWorkspace } from "./fixtures/real-corpus-fixtures.mjs";

function makeChangeSet(files = [{ path: "src/db/user-repo.js", additions: 15, deletions: 2 }], hunks = "+ const query = `SELECT * FROM users WHERE id = '${id}'`;") {
  const contentDigest = crypto.createHash("sha256").update(hunks).digest("hex");
  return {
    ok: true,
    schemaVersion: "1.0.0",
    scopeMode: "working-tree",
    repository: { root: "/virtual/repo", hasHead: true, currentBranch: "main" },
    contentDigest,
    totalFiles: files.length,
    totalAdditions: files.reduce((s, f) => s + (f.additions || 0), 0),
    totalDeletions: files.reduce((s, f) => s + (f.deletions || 0), 0),
    files,
    diffHunks: hunks
  };
}

function makeSampleProducerFindings() {
  return [
    {
      id: "f-sql-001",
      title: "SQL Injection in User Query Handler",
      severity: "critical",
      file: "src/db/user-repo.js",
      line_start: 8,
      line_end: 8,
      cwe: "CWE-89",
      type: "sql-injection",
      recommendation: "Use parameterized queries instead of string interpolation"
    },
    {
      id: "f-log-002",
      title: "Potential Information Exposure through Console Log",
      severity: "low",
      file: "src/db/user-repo.js",
      line_start: 12,
      line_end: 12,
      cwe: "CWE-532",
      type: "info-leak",
      recommendation: "Remove debug logging in production"
    }
  ];
}

// ============================================================================
// Group 1: buildVerificationPrompt Tests
// ============================================================================

test("buildVerificationPrompt: renders changeSet metadata, diff, and structured producer findings", () => {
  const changeSet = makeChangeSet();
  const findings = makeSampleProducerFindings();
  const prompt = buildVerificationPrompt(changeSet, findings);

  assert.match(prompt, /independent verification sentry/i);
  assert.match(prompt, /Scope: working-tree/);
  assert.match(prompt, /src\/db\/user-repo\.js/);
  assert.match(prompt, /SELECT \* FROM users WHERE id/);
  assert.match(prompt, /Finding #1 \[ID: f-sql-001\]/);
  assert.match(prompt, /Title: SQL Injection in User Query Handler/);
  assert.match(prompt, /Severity: critical/);
  assert.match(prompt, /CWE: CWE-89/);
  assert.match(prompt, /Finding #2 \[ID: f-log-002\]/);
  assert.match(prompt, /"evaluations":/);
  assert.match(prompt, /"verifierOmissions":/);
});

test("buildVerificationPrompt: handles empty producer findings gracefully", () => {
  const changeSet = makeChangeSet();
  const prompt = buildVerificationPrompt(changeSet, []);

  assert.match(prompt, /\(No producer findings to evaluate\)/);
  assert.match(prompt, /Scope: working-tree/);
});

test("buildVerificationPrompt: truncates diff exceeding maxInputBytes with notice", () => {
  const hugeHunk = "+ console.log('repeat');\n".repeat(2000);
  const changeSet = makeChangeSet([{ path: "big.js", additions: 2000, deletions: 0 }], hugeHunk);
  const prompt = buildVerificationPrompt(changeSet, [], { limits: { maxInputBytes: 500 } });

  assert.match(prompt, /\[NOTE: Diff truncated at 500 bytes limit\]/);
});

// ============================================================================
// Group 2: validateVerificationOutput Tests (Default-Deny)
// ============================================================================

test("validateVerificationOutput: rejects non-object or null outputs with malformed_output", () => {
  const r1 = validateVerificationOutput(null);
  assert.equal(r1.ok, false);
  assert.equal(r1.executionStatus, EXECUTION_STATUS.MALFORMED_OUTPUT);

  const r2 = validateVerificationOutput("Not a JSON string at all");
  assert.equal(r2.ok, false);
  assert.equal(r2.executionStatus, EXECUTION_STATUS.MALFORMED_OUTPUT);

  const r3 = validateVerificationOutput([1, 2, 3]);
  assert.equal(r3.ok, false);
  assert.equal(r3.executionStatus, EXECUTION_STATUS.MALFORMED_OUTPUT);
});

test("validateVerificationOutput: rejects outputs missing evaluations array", () => {
  const r = validateVerificationOutput({ verifierOmissions: [] });
  assert.equal(r.ok, false);
  assert.equal(r.executionStatus, EXECUTION_STATUS.MALFORMED_OUTPUT);
  assert.match(r.error, /requires an 'evaluations' array/);
});

test("validateVerificationOutput: rejects invalid verdict under Default-Deny", () => {
  const r = validateVerificationOutput({
    evaluations: [
      {
        findingId: "f-1",
        verdict: "PLAUSIBLE_MAYBE",
        locatorAccurate: true
      }
    ]
  });
  assert.equal(r.ok, false);
  assert.equal(r.executionStatus, EXECUTION_STATUS.MALFORMED_OUTPUT);
  assert.match(r.error, /Invalid verdict 'PLAUSIBLE_MAYBE'/);
});

test("validateVerificationOutput: strips capability forgery fields", () => {
  const r = validateVerificationOutput({
    evaluations: [
      {
        findingId: "f-1",
        verdict: "SUPPORTED",
        locatorAccurate: true,
        typeAccurate: true,
        severityAccurate: true,
        reasoning: "Confirmed SQLi",
        __trustedCapabilityNonce: "forged-nonce-123",
        authority: "ADMIN_ROOT",
        isTrusted: true,
        quorumReached: true
      }
    ]
  });

  assert.equal(r.ok, true);
  assert.equal(r.evaluations[0].findingId, "f-1");
  assert.equal(r.evaluations[0].__trustedCapabilityNonce, undefined);
  assert.equal(r.evaluations[0].authority, undefined);
  assert.equal(r.evaluations[0].isTrusted, undefined);
});

test("validateVerificationOutput: extracts JSON from markdown code fences", () => {
  const rawText = "Here is my verification evaluation:\n```json\n" + JSON.stringify({
    evaluations: [
      {
        findingId: "f-sql-001",
        verdict: "SUPPORTED",
        locatorAccurate: true,
        typeAccurate: true,
        severityAccurate: true,
        reasoning: "Line 8 contains raw interpolation"
      }
    ],
    verifierOmissions: []
  }) + "\n```\nDone.";

  const r = validateVerificationOutput(rawText);
  assert.equal(r.ok, true);
  assert.equal(r.evaluations.length, 1);
  assert.equal(r.evaluations[0].verdict, "SUPPORTED");
});

test("validateVerificationOutput: normalizes verifier omissions and rejects malformed omissions", () => {
  const rValid = validateVerificationOutput({
    evaluations: [],
    verifierOmissions: [
      {
        title: "Hardcoded secret key",
        severity: "high",
        file: "src/auth/jwt.js",
        line_start: 10,
        line_end: 10,
        recommendation: "Load secret from env"
      }
    ]
  });
  assert.equal(rValid.ok, true);
  assert.equal(rValid.verifierOmissions.length, 1);
  assert.equal(rValid.verifierOmissions[0].title, "Hardcoded secret key");

  const rInvalid = validateVerificationOutput({
    evaluations: [],
    verifierOmissions: [
      {
        title: "Missing severity and file"
      }
    ]
  });
  assert.equal(rInvalid.ok, false);
  assert.equal(rInvalid.executionStatus, EXECUTION_STATUS.MALFORMED_OUTPUT);
});

test("validateVerificationOutput: preserves upstream transport error status", () => {
  const r = validateVerificationOutput({
    executionStatus: EXECUTION_STATUS.TIMEOUT,
    error: "CLI transport timed out after 30000ms"
  });
  assert.equal(r.ok, false);
  assert.equal(r.executionStatus, EXECUTION_STATUS.TIMEOUT);
  assert.match(r.error, /timed out/);
});

// ============================================================================
// Group 3: conductIndependentVerification Tests (Decoupling & Immutability)
// ============================================================================

test("conductIndependentVerification: producer findings are preserved 100% bit-for-bit (Immutability Guarantee)", async () => {
  const changeSet = makeChangeSet();
  const producerFindings = makeSampleProducerFindings();
  const originalJson = JSON.stringify(producerFindings);

  const mockVerifier = {
    providerName: "claude",
    modelName: "claude-3-5-sonnet",
    executeVerification: async () => ({
      evaluations: [
        {
          findingId: "f-sql-001",
          verdict: "SUPPORTED",
          locatorAccurate: true,
          typeAccurate: true,
          severityAccurate: true,
          reasoning: "SQL injection confirmed."
        },
        {
          findingId: "f-log-002",
          verdict: "CONTESTED",
          locatorAccurate: true,
          typeAccurate: false,
          severityAccurate: false,
          reasoning: "Log contains no PII, benign debugging only.",
          dissent: "Not a security defect."
        }
      ],
      verifierOmissions: []
    })
  };

  const record = await conductIndependentVerification(changeSet, producerFindings, mockVerifier, {
    producerName: "agy"
  });

  // Bit-for-bit verbatim identity test
  assert.deepStrictEqual(record.producer.findings, producerFindings);
  assert.equal(JSON.stringify(record.producer.findings), originalJson);
  assert.equal(record.producer.findingsCount, 2);
  assert.equal(record.producer.providerName, "agy");

  // Ensure producer findings are frozen against mutation
  assert.throws(() => {
    record.producer.findings[0].severity = "MUTATED_VALUE";
  });
});

test("conductIndependentVerification: contested findings and dissents enter disagreementLedger", async () => {
  const changeSet = makeChangeSet();
  const producerFindings = makeSampleProducerFindings();

  const mockVerifier = {
    providerName: "claude",
    modelName: "claude-3-5-sonnet",
    executeVerification: async () => ({
      evaluations: [
        {
          findingId: "f-sql-001",
          verdict: "SUPPORTED",
          locatorAccurate: true,
          typeAccurate: true,
          severityAccurate: true,
          reasoning: "Defect confirmed on line 8."
        },
        {
          findingId: "f-log-002",
          verdict: "CONTESTED",
          locatorAccurate: true,
          typeAccurate: true,
          severityAccurate: false,
          reasoning: "Severity should be info, not low. Also output contains no secrets.",
          dissent: "Contested: benign debug statement without secret leakage."
        }
      ],
      verifierOmissions: []
    })
  };

  const record = await conductIndependentVerification(changeSet, producerFindings, mockVerifier);

  assert.equal(record.evaluations.length, 2);
  assert.equal(record.summary.supportedCount, 1);
  assert.equal(record.summary.contestedCount, 1);
  assert.equal(record.summary.insufficientEvidenceCount, 0);

  // Supported finding MUST NOT enter disagreement ledger
  assert.equal(record.disagreementLedger.length, 1);
  const contestedItem = record.disagreementLedger[0];
  assert.equal(contestedItem.findingId, "f-log-002");
  assert.equal(contestedItem.verdict, "CONTESTED");
  assert.match(contestedItem.dissent, /Contested: benign debug statement/);
  assert.deepStrictEqual(contestedItem.producerFinding, producerFindings[1]);
});

test("conductIndependentVerification: supported finding with inaccurate locator/severity enters disagreementLedger", async () => {
  const changeSet = makeChangeSet();
  const producerFindings = [
    {
      id: "f-auth-001",
      title: "Broken Authentication check",
      severity: "low",
      file: "src/auth.js",
      line_start: 5,
      line_end: 5
    }
  ];

  const mockVerifier = {
    providerName: "claude",
    executeVerification: async () => ({
      evaluations: [
        {
          findingId: "f-auth-001",
          verdict: "SUPPORTED",
          locatorAccurate: false, // Locator contested
          severityAccurate: false, // Severity contested
          typeAccurate: true,
          reasoning: "Defect actually starts at line 20, and severity is critical, not low!",
          dissent: "Severity and line numbers are inaccurate in producer report."
        }
      ],
      verifierOmissions: []
    })
  };

  const record = await conductIndependentVerification(changeSet, producerFindings, mockVerifier);

  // Even though verdict is SUPPORTED, contested locator/severity triggers disagreement ledger entry
  assert.equal(record.evaluations[0].verdict, "SUPPORTED");
  assert.equal(record.disagreementLedger.length, 1);
  assert.equal(record.disagreementLedger[0].locatorAccurate, false);
  assert.equal(record.disagreementLedger[0].severityAccurate, false);
  assert.match(record.disagreementLedger[0].dissent, /Severity and line numbers are inaccurate/);
});

test("conductIndependentVerification: verifier omissions are captured separately and do not pollute producer findings", async () => {
  const changeSet = makeChangeSet();
  const producerFindings = [
    {
      id: "f-1",
      title: "SQL Injection",
      severity: "critical",
      file: "src/db/user-repo.js",
      line_start: 8,
      line_end: 8
    }
  ];

  const mockVerifier = {
    providerName: "claude",
    executeVerification: async () => ({
      evaluations: [
        {
          findingId: "f-1",
          verdict: "SUPPORTED",
          locatorAccurate: true,
          typeAccurate: true,
          severityAccurate: true,
          reasoning: "Confirmed SQL injection"
        }
      ],
      verifierOmissions: [
        {
          title: "Path Traversal in download endpoint",
          severity: "high",
          file: "src/routes/download.js",
          line_start: 45,
          line_end: 45,
          cwe: "CWE-22",
          recommendation: "Sanitize filename parameter"
        }
      ]
    })
  };

  const record = await conductIndependentVerification(changeSet, producerFindings, mockVerifier);

  // Verifier omissions are isolated
  assert.equal(record.verifierOmissions.length, 1);
  assert.equal(record.verifierOmissions[0].title, "Path Traversal in download endpoint");
  assert.equal(record.summary.omissionsCount, 1);

  // Producer findings are NOT polluted
  assert.equal(record.producer.findingsCount, 1);
  assert.equal(record.producer.findings.length, 1);
  assert.equal(record.producer.findings[0].title, "SQL Injection");
});

test("conductIndependentVerification: verifier omission of a producer finding classifies it as INSUFFICIENT_EVIDENCE under Default-Deny", async () => {
  const changeSet = makeChangeSet();
  const producerFindings = [
    { id: "f-1", title: "SQLi", severity: "critical", file: "a.js", line_start: 1, line_end: 1 },
    { id: "f-2", title: "XSS", severity: "high", file: "b.js", line_start: 5, line_end: 5 }
  ];

  // Verifier evaluates f-1, but completely forgets to evaluate f-2
  const mockVerifier = {
    providerName: "claude",
    executeVerification: async () => ({
      evaluations: [
        {
          findingId: "f-1",
          verdict: "SUPPORTED",
          locatorAccurate: true,
          typeAccurate: true,
          severityAccurate: true,
          reasoning: "Confirmed SQLi"
        }
      ],
      verifierOmissions: []
    })
  };

  const record = await conductIndependentVerification(changeSet, producerFindings, mockVerifier);

  assert.equal(record.evaluations.length, 2);
  const f2Eval = record.evaluations.find(e => e.findingId === "f-2");
  assert.ok(f2Eval);
  assert.equal(f2Eval.verdict, VERIFICATION_VERDICTS.INSUFFICIENT_EVIDENCE);
  assert.match(f2Eval.reasoning, /unverified under Default-Deny/i);

  // f-2 MUST be entered in disagreement ledger
  assert.equal(record.disagreementLedger.length, 1);
  assert.equal(record.disagreementLedger[0].findingId, "f-2");
  assert.equal(record.summary.insufficientEvidenceCount, 1);
});

// ============================================================================
// Group 4: Error Handling, Timeouts & Schema Validation
// ============================================================================

test("conductIndependentVerification: handles verifier adapter exception gracefully", async () => {
  const changeSet = makeChangeSet();
  const producerFindings = makeSampleProducerFindings();

  const brokenVerifier = {
    providerName: "broken-tool",
    executeVerification: async () => {
      throw new Error("Network connection reset by peer");
    }
  };

  const record = await conductIndependentVerification(changeSet, producerFindings, brokenVerifier);

  assert.equal(record.ok, false);
  assert.match(record.error, /Network connection reset by peer/);
  // All findings marked INSUFFICIENT_EVIDENCE under Default-Deny
  assert.equal(record.summary.insufficientEvidenceCount, 2);
  assert.equal(record.disagreementLedger.length, 2);
  // Producer findings still preserved intact
  assert.equal(record.producer.findingsCount, 2);
});

test("conductIndependentVerification: handles verifier timeout gracefully", async () => {
  const changeSet = makeChangeSet();
  const producerFindings = makeSampleProducerFindings();

  const timeoutVerifier = {
    providerName: "claude",
    executeVerification: async () => {
      const err = new Error("Verifier process timed out after 30000ms");
      err.name = "TimeoutError";
      throw err;
    }
  };

  const record = await conductIndependentVerification(changeSet, producerFindings, timeoutVerifier);

  assert.equal(record.ok, false);
  assert.equal(record.summary.insufficientEvidenceCount, 2);
  assert.equal(record.summary.supportedCount, 0);
  assert.equal(record.disagreementLedger.length, 2);
});

test("conductIndependentVerification: throwOnError propagates exception", async () => {
  const changeSet = makeChangeSet();
  const producerFindings = makeSampleProducerFindings();

  const failingVerifier = {
    providerName: "claude",
    executeVerification: async () => {
      throw new Error("Fatal CLI crash");
    }
  };

  await assert.rejects(
    async () => {
      await conductIndependentVerification(changeSet, producerFindings, failingVerifier, {
        throwOnError: true
      });
    },
    /Fatal CLI crash/
  );
});

test("conductIndependentVerification: fails closed on invalid input parameters", async () => {
  await assert.rejects(
    async () => conductIndependentVerification(null, [], {}),
    /Invalid changeSet/
  );

  await assert.rejects(
    async () => conductIndependentVerification(makeChangeSet(), null, {}),
    /Invalid producerFindings/
  );

  await assert.rejects(
    async () => conductIndependentVerification(makeChangeSet(), [], null),
    /Invalid verifierAdapter/
  );
});

test("validateVerificationRecord: validates compliant record and detects tampering", async () => {
  const changeSet = makeChangeSet();
  const producerFindings = makeSampleProducerFindings();

  const mockVerifier = {
    providerName: "claude",
    executeVerification: async () => ({
      evaluations: [
        { findingId: "f-sql-001", verdict: "SUPPORTED", locatorAccurate: true, typeAccurate: true, severityAccurate: true },
        { findingId: "f-log-002", verdict: "SUPPORTED", locatorAccurate: true, typeAccurate: true, severityAccurate: true }
      ],
      verifierOmissions: []
    })
  };

  const record = await conductIndependentVerification(changeSet, producerFindings, mockVerifier);

  const val = validateVerificationRecord(record);
  assert.equal(val.valid, true);
  assert.equal(val.errors.length, 0);

  // Compute deterministic digest
  const digest = computeVerificationRecordDigest(record);
  assert.match(digest, /^sha256:[a-f0-9]{64}$/);

  // Tamper with record schema version
  const tamperedRecord = { ...record, schemaVersion: "2.0.0" };
  const tamperedVal = validateVerificationRecord(tamperedRecord);
  assert.equal(tamperedVal.valid, false);
  assert.match(tamperedVal.errors[0], /Invalid schemaVersion/);

  // Digest throws on invalid record
  assert.throws(() => computeVerificationRecordDigest(tamperedRecord));
});

// ============================================================================
// Group 5: Grounded Gate Declaration - BENCH-REAL-001
// ============================================================================

test("Gate Declaration: BENCH-REAL-001 achieves independent verification record without agy findings overwritten or merged away", async () => {
  const caseDef = getCorpusCaseById("BENCH-REAL-001");
  assert.ok(caseDef, "BENCH-REAL-001 must exist in TF-RBC-v0 corpus");

  const workspace = createCorpusCaseWorkspace(caseDef, { virtual: true });
  try {
    const changeSet = workspace.changeSet;
    assert.ok(changeSet, "ChangeSet must be generated for BENCH-REAL-001");

    // Primary findings generated by Google agy (producer)
    const agyPrimaryFindings = [
      {
        id: "BENCH-REAL-001-F1",
        title: "SQL Injection in User Query Handler",
        severity: "critical",
        file: "src/db/user-repo.js",
        line_start: 8,
        line_end: 8,
        cwe: "CWE-89",
        type: "sql-injection",
        recommendation: "Direct SQL query concatenation with user-supplied parameter allows arbitrary SQL injection"
      }
    ];

    // Independent Verifier: Anthropic claude evaluates agy primary findings against diff
    const claudeVerifier = {
      providerName: "claude",
      modelName: "claude-default",
      actualModel: { value: "claude-3-5-sonnet-20241022", source: "runtime" },
      executeVerification: async ({ changeSet, producerFindings }) => {
        // Claude independently confirms SQL injection in src/db/user-repo.js
        assert.equal(producerFindings.length, 1);
        assert.equal(producerFindings[0].cwe, "CWE-89");

        return {
          evaluations: [
            {
              findingId: "BENCH-REAL-001-F1",
              verdict: "SUPPORTED",
              locatorAccurate: true,
              typeAccurate: true,
              severityAccurate: true,
              reasoning: "Confirmed SQL injection in src/db/user-repo.js at line 8: direct template literal interpolation without parameterization.",
              dissent: null
            }
          ],
          verifierOmissions: [],
          usage: {
            promptTokens: 450,
            completionTokens: 85,
            totalTokens: 535
          }
        };
      }
    };

    const verificationRecord = await conductIndependentVerification(
      changeSet,
      agyPrimaryFindings,
      claudeVerifier,
      {
        producerName: "agy",
        verifierName: "claude"
      }
    );

    // Assert Gate Declaration invariants:
    // 1. schemaVersion is 1.0.0
    assert.equal(verificationRecord.schemaVersion, "1.0.0");

    // 2. Producer findings are NOT overwritten, modified, or merged away
    assert.equal(verificationRecord.producer.providerName, "agy");
    assert.equal(verificationRecord.producer.findingsCount, 1);
    assert.deepStrictEqual(verificationRecord.producer.findings, agyPrimaryFindings);

    // 3. Verifier identity preserved
    assert.equal(verificationRecord.verifier.providerName, "claude");
    assert.equal(verificationRecord.verifier.actualModel.value, "claude-3-5-sonnet-20241022");
    assert.equal(verificationRecord.verifier.actualModel.source, "runtime");

    // 4. Evaluation confirmed as SUPPORTED
    assert.equal(verificationRecord.evaluations.length, 1);
    assert.equal(verificationRecord.evaluations[0].verdict, "SUPPORTED");
    assert.equal(verificationRecord.summary.supportedCount, 1);
    assert.equal(verificationRecord.summary.contestedCount, 0);

    // 5. Zero unrecorded dissents
    assert.equal(verificationRecord.disagreementLedger.length, 0);

    // 6. Record validates cleanly
    const validation = validateVerificationRecord(verificationRecord);
    assert.equal(validation.valid, true);
    assert.equal(validation.errors.length, 0);

    // 7. Digest is deterministic
    const digest = computeVerificationRecordDigest(verificationRecord);
    assert.match(digest, /^sha256:[a-f0-9]{64}$/);
  } finally {
    workspace.cleanup();
  }
});

// ============================================================================
// Group 6: Deep Verification & Invariant Hardening
// ============================================================================

test("buildVerificationPrompt: handles multi-byte UTF-8 diffs and Buffer inputs with exact byte-level truncation", () => {
  // Multi-byte Chinese characters (3 bytes each in UTF-8)
  const chineseText = "+ // 安全修復：驗證用戶輸入防止注入漏洞\n".repeat(20);
  const totalBytes = Buffer.byteLength(chineseText, "utf8");
  assert.ok(totalBytes > 200, "Should exceed 200 bytes limit");

  // String input truncated at 200 bytes
  const promptStr = buildVerificationPrompt({ diffHunks: chineseText }, [], { limits: { maxInputBytes: 200 } });
  assert.match(promptStr, /\[NOTE: Diff truncated at 200 bytes limit\]/);

  // Buffer input
  const bufHunks = Buffer.from(chineseText, "utf8");
  const promptBuf = buildVerificationPrompt({ diffHunks: bufHunks }, [], { limits: { maxInputBytes: 200 } });
  assert.match(promptBuf, /\[NOTE: Diff truncated at 200 bytes limit\]/);
});

test("validateVerificationOutput: preserves raw error message when ok is false without executionStatus", () => {
  const rawErr = {
    ok: false,
    error: "External Claude subprocess exited unexpectedly with code 1"
  };

  const validated = validateVerificationOutput(rawErr);
  assert.equal(validated.ok, false);
  assert.equal(validated.executionStatus, EXECUTION_STATUS.ERROR);
  assert.match(validated.error, /External Claude subprocess exited unexpectedly/);
});

test("validateVerificationOutput: correctly parses string boolean representations without treating 'false' as true", () => {
  const raw = {
    evaluations: [
      {
        findingId: "f-1",
        verdict: "SUPPORTED",
        locatorAccurate: "false", // String "false", MUST NOT evaluate to true!
        typeAccurate: "0",
        severityAccurate: "no",
        reasoning: "Defect is actually in another file at line 40"
      }
    ],
    verifierOmissions: []
  };

  const validated = validateVerificationOutput(raw);
  assert.equal(validated.ok, true);
  assert.equal(validated.evaluations[0].locatorAccurate, false);
  assert.equal(validated.evaluations[0].typeAccurate, false);
  assert.equal(validated.evaluations[0].severityAccurate, false);
  // Takes reasoning as dissent
  assert.equal(validated.evaluations[0].dissent, "Defect is actually in another file at line 40");

  // Fallback to constructed dissent when reasoning is empty
  const rawNoReasoning = {
    evaluations: [
      {
        findingId: "f-2",
        verdict: "SUPPORTED",
        locatorAccurate: false,
        typeAccurate: false,
        severityAccurate: false
      }
    ]
  };
  const validated2 = validateVerificationOutput(rawNoReasoning);
  assert.match(validated2.evaluations[0].dissent, /locator and severity and type contested/);
});

test("conductIndependentVerification: correctly matches numeric finding IDs without dropping findings", async () => {
  const changeSet = makeChangeSet();
  const producerFindings = [
    { id: 101, title: "SQL Injection in User Query Handler", severity: "critical", file: "src/db.js" },
    { id: 102, title: "Hardcoded Secret Token", severity: "high", file: "src/config.js" }
  ];

  const mockVerifier = {
    providerName: "claude",
    executeVerification: async () => ({
      evaluations: [
        { findingId: "101", verdict: "SUPPORTED", locatorAccurate: true, typeAccurate: true, severityAccurate: true },
        { findingId: "102", verdict: "SUPPORTED", locatorAccurate: true, typeAccurate: true, severityAccurate: true }
      ],
      verifierOmissions: []
    })
  };

  const record = await conductIndependentVerification(changeSet, producerFindings, mockVerifier);
  assert.equal(record.evaluations.length, 2);
  assert.equal(record.summary.supportedCount, 2);
  assert.equal(record.summary.insufficientEvidenceCount, 0);
  assert.equal(record.disagreementLedger.length, 0);
});

test("conductIndependentVerification: matches case-insensitive finding IDs and prefix variations", async () => {
  const changeSet = makeChangeSet();
  const producerFindings = [
    { id: "SEC-XSS-001", title: "XSS vulnerability", severity: "high", file: "src/view.js" },
    { id: "SEC-SQL-002", title: "SQL injection", severity: "critical", file: "src/db.js" }
  ];

  const mockVerifier = {
    providerName: "claude",
    executeVerification: async () => ({
      evaluations: [
        // Lowercase variant
        { findingId: "sec-xss-001", verdict: "SUPPORTED", locatorAccurate: true, typeAccurate: true, severityAccurate: true },
        // Finding #2 prefix variant
        { findingId: "Finding #2", verdict: "SUPPORTED", locatorAccurate: true, typeAccurate: true, severityAccurate: true }
      ],
      verifierOmissions: []
    })
  };

  const record = await conductIndependentVerification(changeSet, producerFindings, mockVerifier);
  assert.equal(record.evaluations.length, 2);
  assert.equal(record.summary.supportedCount, 2);
  assert.equal(record.summary.insufficientEvidenceCount, 0);
});

test("conductIndependentVerification: marks finding as CONTESTED on conflicting verifier evaluations", async () => {
  const changeSet = makeChangeSet();
  const producerFindings = [
    { id: "f-1", title: "Potential flaw", severity: "medium", file: "src/handler.js" }
  ];

  const conflictingVerifier = {
    providerName: "claude",
    executeVerification: async () => ({
      evaluations: [
        { findingId: "f-1", verdict: "SUPPORTED", reasoning: "Looks like a flaw" },
        { findingId: "f-1", verdict: "CONTESTED", reasoning: "Actually safe, verified sanitized" }
      ],
      verifierOmissions: []
    })
  };

  const record = await conductIndependentVerification(changeSet, producerFindings, conflictingVerifier);
  assert.equal(record.evaluations[0].verdict, VERIFICATION_VERDICTS.CONTESTED);
  assert.match(record.evaluations[0].dissent, /Self-contradiction by verifier/);
  assert.equal(record.disagreementLedger.length, 1);
});

test("conductIndependentVerification: guarantees deep immutability on nested objects within producer findings", async () => {
  const changeSet = makeChangeSet();
  const producerFindings = [
    {
      id: "f-1",
      title: "Nested object finding",
      severity: "high",
      file: "src/app.js",
      metadata: {
        cvss: 7.5,
        vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
      }
    }
  ];

  const mockVerifier = {
    providerName: "claude",
    executeVerification: async () => ({
      evaluations: [
        { findingId: "f-1", verdict: "SUPPORTED", locatorAccurate: true, typeAccurate: true, severityAccurate: true }
      ],
      verifierOmissions: []
    })
  };

  const record = await conductIndependentVerification(changeSet, producerFindings, mockVerifier);

  // Assert deep immutability
  assert.throws(() => {
    record.producer.findings[0].metadata.cvss = 9.9;
  });
  assert.equal(record.producer.findings[0].metadata.cvss, 7.5);
});

test("CliVerifierAdapter: executes verification prompt via execFn and handles child execution", async () => {
  let capturedCommand = null;
  let capturedArgs = null;
  let capturedPrompt = null;

  const adapter = new CliVerifierAdapter({
    command: "claude",
    execFn: async ({ command, args, prompt }) => {
      capturedCommand = command;
      capturedArgs = args;
      capturedPrompt = prompt;
      return {
        stdout: JSON.stringify({
          evaluations: [
            { findingId: "f-1", verdict: "SUPPORTED", locatorAccurate: true, typeAccurate: true, severityAccurate: true }
          ],
          verifierOmissions: []
        })
      };
    }
  });

  const changeSet = makeChangeSet();
  const producerFindings = [{ id: "f-1", title: "SQLi", severity: "critical", file: "src/db.js" }];

  const record = await conductIndependentVerification(changeSet, producerFindings, adapter);
  assert.equal(record.ok, true);
  assert.equal(capturedCommand, "claude");
  assert.ok(capturedArgs.length > 0);
  assert.match(capturedPrompt, /independent verification sentry/i);
  assert.equal(record.summary.supportedCount, 1);
});

test("validateVerificationRecord: detects tampering when disagreementLedger or summary counts are falsified", async () => {
  const changeSet = makeChangeSet();
  const producerFindings = [
    { id: "f-1", title: "SQLi", severity: "critical", file: "src/db.js" }
  ];

  const mockVerifier = {
    providerName: "claude",
    executeVerification: async () => ({
      evaluations: [
        { findingId: "f-1", verdict: "CONTESTED", locatorAccurate: true, typeAccurate: true, severityAccurate: true, dissent: "False positive" }
      ],
      verifierOmissions: []
    })
  };

  const record = await conductIndependentVerification(changeSet, producerFindings, mockVerifier);

  // Untampered record validates
  const untampered = validateVerificationRecord(record);
  assert.equal(untampered.valid, true);

  // Tamper 1: Empty the disagreement ledger to hide the dissent
  const tamperedLedger = { ...record, disagreementLedger: [] };
  const val1 = validateVerificationRecord(tamperedLedger);
  assert.equal(val1.valid, false);
  assert.match(val1.errors[0], /Disagreement ledger count mismatch/);

  // Tamper 2: Falsify summary.supportedCount to fake consensus
  const tamperedSummary = { ...record, summary: { ...record.summary, supportedCount: 1 } };
  const val2 = validateVerificationRecord(tamperedSummary);
  assert.equal(val2.valid, false);
  assert.match(val2.errors[0], /summary\.supportedCount/);

  // Tamper 3: Drop evaluations so producer findings are missing
  const tamperedEvals = { ...record, evaluations: [] };
  const val3 = validateVerificationRecord(tamperedEvals);
  assert.equal(val3.valid, false);
  assert.match(val3.errors[0], /Evaluations count .* does not match producer findings count/);

  // Tamper 4: Invalid timestamp
  const tamperedTime = { ...record, verifiedAt: "not-a-timestamp" };
  const val4 = validateVerificationRecord(tamperedTime);
  assert.equal(val4.valid, false);
  assert.match(val4.errors[0], /valid parseable ISO timestamp/);
});

