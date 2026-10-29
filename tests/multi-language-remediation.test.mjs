/**
 * Test Suite: Multi-Language Patch Synthesis & Remediation Engine (v2.10)
 *
 * Validates:
 * - Contract 1: detectLanguage identifies extensions for C, C++, Rust, Go, Python, and JS/TS.
 * - Contract 2: detectLanguageTestRunner resolves proper test commands for various language ecosystems.
 * - Contract 3: Multi-language assertion stripping detection across Python, Rust, Go, and C/C++.
 * - Contract 4: Multi-language constant branch bypass detection (Python if True:, except: pass; Go/Rust if true {, if false {).
 * - Contract 5: Multi-language test suppression detection (@pytest.mark.skip, #[ignore], t.Skip).
 * - Contract 6: synthesizeUnifiedDiff generates git-applicable unified diffs with guaranteed leading-space context lines.
 * - Contract 7: synthesizeMultiLanguagePatch rejects anti-evasion violations and accepts safe remediations.
 * - Contract 8: BatchRemediationSession supports heterogeneous per-finding test runners across languages.
 * - Contract 9: End-to-end multi-language batch remediation across 5 real OSS cases (C, Rust, Go, Python, JS) in ephemeral worktree patch jail.
 * - Contract 10: Regression detection in multi-language jail worktree triggers REJECTED_FIX and rolls back uncommitted changes.
 * - Contract 11: Multi-language batch remediation produces schema-compliant Batch Remediation Receipt Schema 1.0.0.
 * - Contract 12: Ephemeral jail preserves immutable authority repository during multi-language patch application.
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { execFileSync } from "node:child_process";

import {
  SUPPORTED_LANGUAGES,
  detectLanguage,
  detectLanguageTestRunner,
  synthesizeUnifiedDiff,
  synthesizeMultiLanguagePatch,
  MultiLanguageRemediationOrchestrator
} from "../src/core/multi-language-remediation.mjs";

import {
  scanStructuralAntiEvasionViolations,
  EVASION_VIOLATION_TYPES,
  StructuralAntiEvasionError
} from "../src/core/anti-evasion-guard.mjs";

import {
  REMEDIATION_STATES,
  validateRemediationReceipt
} from "../src/core/controlled-remediation.mjs";

import {
  BATCH_REMEDIATION_STATES,
  BATCH_VERDICTS,
  BatchRemediationSession,
  validateBatchReceipt
} from "../src/core/batch-remediation.mjs";

import {
  TF_OSS_CORPUS_V2_CASES,
  createOssV2CaseWorkspace,
  createOssV2MultiCaseWorkspace
} from "./fixtures/real-oss-v2-fixtures.mjs";

function createMockVerificationRecord(findingId, file) {
  return {
    schemaVersion: "1.0.0",
    verifiedAt: new Date().toISOString(),
    changeSetDigest: "sha256:" + "b".repeat(64),
    producer: {
      providerName: "tri-party-quorum",
      findingsCount: 1,
      findings: [{ id: findingId, findingId, title: "Finding", severity: "high", file }]
    },
    verifier: {
      providerName: "claude",
      modelName: "claude-5.5-sonnet",
      actualModel: { value: "claude-5.5-sonnet", source: "reported" }
    },
    evaluations: [{
      findingId,
      verdict: "SUPPORTED",
      locatorAccurate: true,
      typeAccurate: true,
      severityAccurate: true,
      reasoning: "Multi-language remediation verified safely."
    }],
    verifierOmissions: [],
    disagreementLedger: [],
    summary: {
      totalEvaluated: 1,
      supportedCount: 1,
      contestedCount: 0,
      insufficientEvidenceCount: 0,
      omissionsCount: 0
    },
    residualVulnerabilityDetected: false,
    ok: true
  };
}

test("Contract 1: detectLanguage identifies extensions for C, C++, Rust, Go, Python, and JS/TS", () => {
  assert.equal(detectLanguage("src/cluster.c"), SUPPORTED_LANGUAGES.C);
  assert.equal(detectLanguage("include/server.h"), SUPPORTED_LANGUAGES.C);
  assert.equal(detectLanguage("src/node_contextify.cc"), SUPPORTED_LANGUAGES.CPP);
  assert.equal(detectLanguage("src/parser.cpp"), SUPPORTED_LANGUAGES.CPP);
  assert.equal(detectLanguage("src/proto/h2/ping.rs"), SUPPORTED_LANGUAGES.RUST);
  assert.equal(detectLanguage("pkg/archive/tar.go"), SUPPORTED_LANGUAGES.GO);
  assert.equal(detectLanguage("Lib/urllib/parse.py"), SUPPORTED_LANGUAGES.PYTHON);
  assert.equal(detectLanguage("lib/ejs.js"), SUPPORTED_LANGUAGES.JAVASCRIPT);
  assert.equal(detectLanguage("src/index.mjs"), SUPPORTED_LANGUAGES.JAVASCRIPT);
  assert.equal(detectLanguage("src/types.ts"), SUPPORTED_LANGUAGES.TYPESCRIPT);
  assert.equal(detectLanguage("README.md"), SUPPORTED_LANGUAGES.UNKNOWN);
  assert.equal(detectLanguage(""), SUPPORTED_LANGUAGES.UNKNOWN);
  assert.equal(detectLanguage(null), SUPPORTED_LANGUAGES.UNKNOWN);
});

test("Contract 2: detectLanguageTestRunner resolves proper test commands for various language ecosystems", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-test-detect-runner-"));

  try {
    // 1. Rust project with Cargo.toml
    fs.writeFileSync(path.join(tmpDir, "Cargo.toml"), "[package]\nname = 'test'\n", "utf8");
    const rustRunner = detectLanguageTestRunner(tmpDir, ["src/lib.rs"]);
    assert.deepEqual(rustRunner, { command: "cargo", args: ["test"] });
    fs.rmSync(path.join(tmpDir, "Cargo.toml"));

    // 2. Go project with go.mod
    fs.writeFileSync(path.join(tmpDir, "go.mod"), "module example.com/test\n", "utf8");
    const goRunner = detectLanguageTestRunner(tmpDir, ["pkg/tar.go"]);
    assert.deepEqual(goRunner, { command: "go", args: ["test", "./..."] });
    fs.rmSync(path.join(tmpDir, "go.mod"));

    // 3. Python project with pytest.ini
    fs.writeFileSync(path.join(tmpDir, "pytest.ini"), "[pytest]\n", "utf8");
    const pyRunner = detectLanguageTestRunner(tmpDir, ["app/main.py"]);
    assert.deepEqual(pyRunner, { command: "python", args: ["-m", "unittest"] });
    fs.rmSync(path.join(tmpDir, "pytest.ini"));

    // 4. Custom test oracle script in workspace
    fs.mkdirSync(path.join(tmpDir, "test"), { recursive: true });
    fs.writeFileSync(path.join(tmpDir, "test/test.js"), "console.log('oracle');\n", "utf8");
    const oracleRunner = detectLanguageTestRunner(tmpDir, ["src/cluster.c"]);
    assert.deepEqual(oracleRunner, { command: "node", args: ["test/test.js"] });
  } finally {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {}
  }
});

test("Contract 3: Multi-language assertion stripping detection across Python, Rust, Go, and C/C++", () => {
  // Python assert stripping
  const pyDiff = [
    "diff --git a/app.py b/app.py",
    "--- a/app.py",
    "+++ b/app.py",
    "@@ -1,2 +1,1 @@",
    "-assert token is not None",
    "+print('token checked')"
  ].join("\n");
  const pyViolations = scanStructuralAntiEvasionViolations(pyDiff);
  assert.ok(pyViolations.some(v => v.type === EVASION_VIOLATION_TYPES.ASSERTION_STRIPPING));

  // Rust assert! stripping
  const rsDiff = [
    "diff --git a/lib.rs b/lib.rs",
    "--- a/lib.rs",
    "+++ b/lib.rs",
    "@@ -1,2 +1,1 @@",
    "-assert_eq!(hash, expected);",
    "+let _ = hash;"
  ].join("\n");
  const rsViolations = scanStructuralAntiEvasionViolations(rsDiff);
  assert.ok(rsViolations.some(v => v.type === EVASION_VIOLATION_TYPES.ASSERTION_STRIPPING));

  // Go t.Fatal stripping
  const goDiff = [
    "diff --git a/main_test.go b/main_test.go",
    "--- a/main_test.go",
    "+++ b/main_test.go",
    "@@ -1,2 +1,1 @@",
    "-t.Fatalf('unauthorized access')",
    "+log.Println('unauthorized')"
  ].join("\n");
  const goViolations = scanStructuralAntiEvasionViolations(goDiff);
  assert.ok(goViolations.some(v => v.type === EVASION_VIOLATION_TYPES.ASSERTION_STRIPPING));

  // C assert() stripping
  const cDiff = [
    "diff --git a/cluster.c b/cluster.c",
    "--- a/cluster.c",
    "+++ b/cluster.c",
    "@@ -1,2 +1,1 @@",
    "-assert(buflen >= sizeof(clusterMsg));",
    "+int ok = 1;"
  ].join("\n");
  const cViolations = scanStructuralAntiEvasionViolations(cDiff);
  assert.ok(cViolations.some(v => v.type === EVASION_VIOLATION_TYPES.ASSERTION_STRIPPING));
});

test("Contract 4: Multi-language constant branch bypass detection (Python if True:, except: pass; Go/Rust if true {, if false {)", () => {
  // Python if True: early return
  const pyBypass = [
    "diff --git a/calc.py b/calc.py",
    "--- a/calc.py",
    "+++ b/calc.py",
    "@@ -1,1 +1,2 @@",
    "+if True: return 0"
  ].join("\n");
  assert.ok(scanStructuralAntiEvasionViolations(pyBypass).some(v => v.type === EVASION_VIOLATION_TYPES.TRIVIAL_BRANCH_BYPASS));

  // Python empty except: pass
  const pyExceptPass = [
    "diff --git a/calc.py b/calc.py",
    "--- a/calc.py",
    "+++ b/calc.py",
    "@@ -1,1 +1,2 @@",
    "+except Exception: pass"
  ].join("\n");
  assert.ok(scanStructuralAntiEvasionViolations(pyExceptPass).some(v => v.type === EVASION_VIOLATION_TYPES.TRIVIAL_BRANCH_BYPASS));

  // Rust if true {
  const rsBypass = [
    "diff --git a/lib.rs b/lib.rs",
    "--- a/lib.rs",
    "+++ b/lib.rs",
    "@@ -1,1 +1,2 @@",
    "+if true { return Ok(()); }"
  ].join("\n");
  assert.ok(scanStructuralAntiEvasionViolations(rsBypass).some(v => v.type === EVASION_VIOLATION_TYPES.TRIVIAL_BRANCH_BYPASS));

  // Go if false {
  const goBypass = [
    "diff --git a/main.go b/main.go",
    "--- a/main.go",
    "+++ b/main.go",
    "@@ -1,1 +1,2 @@",
    "+if false {"
  ].join("\n");
  assert.ok(scanStructuralAntiEvasionViolations(goBypass).some(v => v.type === EVASION_VIOLATION_TYPES.TRIVIAL_BRANCH_BYPASS));
});

test("Contract 5: Multi-language test suppression detection (@pytest.mark.skip, #[ignore], t.Skip)", () => {
  // Python @pytest.mark.skip
  const pySkip = [
    "diff --git a/test_app.py b/test_app.py",
    "--- a/test_app.py",
    "+++ b/test_app.py",
    "@@ -1,1 +1,2 @@",
    "+@pytest.mark.skip(reason='flaky')"
  ].join("\n");
  assert.ok(scanStructuralAntiEvasionViolations(pySkip).some(v => v.type === EVASION_VIOLATION_TYPES.TEST_SKIPPING));

  // Rust #[ignore]
  const rsSkip = [
    "diff --git a/tests/test_h2.rs b/tests/test_h2.rs",
    "--- a/tests/test_h2.rs",
    "+++ b/tests/test_h2.rs",
    "@@ -1,1 +1,2 @@",
    "+#[ignore]"
  ].join("\n");
  assert.ok(scanStructuralAntiEvasionViolations(rsSkip).some(v => v.type === EVASION_VIOLATION_TYPES.TEST_SKIPPING));

  // Go t.Skip
  const goSkip = [
    "diff --git a/tar_test.go b/tar_test.go",
    "--- a/tar_test.go",
    "+++ b/tar_test.go",
    "@@ -1,1 +1,2 @@",
    "+t.Skip('skipping in CI')"
  ].join("\n");
  assert.ok(scanStructuralAntiEvasionViolations(goSkip).some(v => v.type === EVASION_VIOLATION_TYPES.TEST_SKIPPING));
});

test("Contract 6: synthesizeUnifiedDiff generates git-applicable unified diffs with guaranteed leading-space context lines", () => {
  const original = [
    "/* C Redis Cluster Packet Processing */",
    "#include <stdint.h>",
    "int clusterProcessPacket(clusterMsg *hdr, size_t buflen) {",
    "    uint32_t explen = hdr->totlen;",
    "    if (explen > buflen) return 0;",
    "    return 1;",
    "}"
  ].join("\n");

  const replacement = "    if (explen < sizeof(clusterMsg) || explen > buflen) return 0;";

  const result = synthesizeUnifiedDiff({
    filePath: "src/cluster.c",
    originalContent: original,
    replacementText: replacement,
    startLine: 5,
    endLine: 5,
    contextLines: 2
  });

  assert.equal(result.targetFiles[0], "src/cluster.c");
  assert.equal(result.additions, 1);
  assert.equal(result.deletions, 1);

  // Assert standard unified diff headers and context line formatting
  const lines = result.diff.split("\n");
  assert.equal(lines[0], "diff --git a/src/cluster.c b/src/cluster.c");
  assert.equal(lines[1], "--- a/src/cluster.c");
  assert.equal(lines[2], "+++ b/src/cluster.c");
  assert.match(lines[3], /^@@ -\d+,\d+ \+\d+,\d+ @@$/);

  // Every context line must strictly start with a space
  for (let i = 4; i < lines.length - 1; i++) {
    const l = lines[i];
    assert.ok(l.startsWith(" ") || l.startsWith("+") || l.startsWith("-"), `Line must start with space, +, or -: '${l}'`);
  }
});

test("Contract 7: synthesizeMultiLanguagePatch rejects anti-evasion violations and accepts safe remediations", () => {
  const origPy = [
    "def parse_url(url):",
    "    assert isinstance(url, str)",
    "    return url.split('?')[0]"
  ].join("\n");

  // Safe fix that preserves assert
  const safeFix = [
    "    assert isinstance(url, str)",
    "    url = url.strip()",
    "    if not url: return ''"
  ].join("\n");

  const safePatch = synthesizeMultiLanguagePatch({
    targetFile: "Lib/urllib/parse.py",
    originalContent: origPy,
    patchReplacement: safeFix,
    startLine: 2,
    endLine: 2
  });
  assert.equal(safePatch.violations.length, 0);
  assert.ok(safePatch.diff.includes("+    url = url.strip()"));

  // Evasive fix that swallows errors via except: pass
  assert.throws(
    () => synthesizeMultiLanguagePatch({
      targetFile: "Lib/urllib/parse.py",
      originalContent: origPy,
      patchReplacement: "    except: pass",
      startLine: 2,
      endLine: 2
    }),
    StructuralAntiEvasionError
  );
});

test("Contract 8: BatchRemediationSession supports heterogeneous per-finding test runners across languages", () => {
  const findings = [
    { id: "F-C-01", targetFiles: ["src/cluster.c"], testRunner: { command: "node", args: ["test/c_test.js"] } },
    { id: "F-RS-01", targetFiles: ["src/lib.rs"], testRunner: { command: "node", args: ["test/rs_test.js"] } }
  ];

  const batch = new BatchRemediationSession("BATCH-MULTI-001", findings);
  const s1 = batch.getSession("F-C-01");
  const s2 = batch.getSession("F-RS-01");

  assert.equal(s1.finding.id, "F-C-01");
  assert.equal(s1.testRunner.command, "node");
  assert.deepEqual(s1.testRunner.args, ["test/c_test.js"]);

  assert.equal(s2.finding.id, "F-RS-01");
  assert.equal(s2.testRunner.command, "node");
  assert.deepEqual(s2.testRunner.args, ["test/rs_test.js"]);
});

test("Contract 9: End-to-end multi-language batch remediation across 5 real OSS cases (C, Rust, Go, Python, JS) in ephemeral worktree patch jail", () => {
  const selectedCaseIds = ["TF-OSS-201", "TF-OSS-203", "TF-OSS-205", "TF-OSS-206", "TF-OSS-208"];
  const selectedCases = TF_OSS_CORPUS_V2_CASES.filter(c => selectedCaseIds.includes(c.id));
  assert.equal(selectedCases.length, 5);

  const multiWs = createOssV2MultiCaseWorkspace(selectedCases);

  try {
    const findings = selectedCases.map(c => ({
      id: c.id,
      targetFiles: c.targetFiles.map(tf => `${c.name}/${tf}`),
      testRunner: { command: "node", args: ["test/test.js"], cwd: c.name }
    }));

    const orchestrator = new MultiLanguageRemediationOrchestrator("BATCH-MULTI-LANG-5", findings);

    // 1. Propose fixes across all 5 languages
    for (const c of selectedCases) {
      const patchedDiff = c.patchDiff.replaceAll(c.targetFiles[0], `${c.name}/${c.targetFiles[0]}`);
      orchestrator.proposeFix(c.id, {
        diff: patchedDiff,
        rationale: `Fix ${c.name} vulnerability (${c.cve})`
      });
    }

    // 2. Authorize all patches
    orchestrator.authorizeAll({ identity: "sec-auditor@triad.flow", type: "human" });

    // 3. Execute in Jail Worktree
    const trial = orchestrator.executeInJail(multiWs.dir, { baseSha: multiWs.baseSha });

    assert.equal(trial.executionResults.length, 5);
    for (const r of trial.executionResults) {
      assert.equal(r.applied, true, `Case ${r.findingId} must apply cleanly`);
      assert.equal(r.testsPassed, true, `Case ${r.findingId} test oracle must pass`);
      assert.equal(r.status, REMEDIATION_STATES.FIXED_PENDING_VERIFY);
    }

    // 4. Record Closure Verification for all 5
    for (const c of selectedCases) {
      const session = orchestrator.batchSession.getSession(c.id);
      session.recordClosureVerification({
        verifier: { providerName: "claude" },
        verificationRecord: createMockVerificationRecord(c.id, `${c.name}/${c.targetFiles[0]}`)
      });
      assert.equal(session.status, REMEDIATION_STATES.CLOSED);
    }

    // 5. Finalize and validate batch receipt
    const { receipt, summary } = orchestrator.finalize();
    assert.equal(receipt.status, BATCH_REMEDIATION_STATES.COMPLETED);
    assert.equal(receipt.verdict, BATCH_VERDICTS.ALL_CLOSED);
    assert.equal(summary.closedCount, 5);
    assert.equal(summary.rejectedCount, 0);
    assert.equal(validateBatchReceipt(receipt), true);

    // 6. Assert repository immutability
    multiWs.assertImmutability();
  } finally {
    multiWs.cleanup();
  }
});

test("Contract 10: Regression detection in multi-language jail worktree triggers REJECTED_FIX and rolls back uncommitted changes", () => {
  const caseDef = TF_OSS_CORPUS_V2_CASES.find(c => c.id === "TF-OSS-201"); // redis (C)
  const ws = createOssV2CaseWorkspace(caseDef);

  try {
    const findings = [{
      id: caseDef.id,
      targetFiles: caseDef.targetFiles,
      testRunner: caseDef.testRunner
    }];

    const orchestrator = new MultiLanguageRemediationOrchestrator("BATCH-REGRESSION-001", findings);

    // Patch that introduces an incomplete fix failing the test oracle
    const badPatch = [
      "diff --git a/src/cluster.c b/src/cluster.c",
      "--- a/src/cluster.c",
      "+++ b/src/cluster.c",
      "@@ -11,5 +11,5 @@",
      " int clusterProcessPacket(clusterMsg *hdr, size_t buflen) {",
      "     uint32_t explen = hdr->totlen;",
      "-    if (explen > buflen) return 0;",
      "+    if (explen == 0) return 0;",
      "     /* VULNERABILITY: explen check lacks lower bound and overflow validation */",
      "     return 1;"
    ].join("\n") + "\n";

    orchestrator.proposeFix(caseDef.id, { diff: badPatch, rationale: "Broken fix" });
    orchestrator.authorizeAll();

    const trial = orchestrator.executeInJail(ws.dir, { baseSha: ws.baseSha });

    assert.equal(trial.executionResults.length, 1);
    const r = trial.executionResults[0];
    assert.equal(r.applied, true);
    assert.equal(r.testsPassed, false);
    assert.equal(r.status, REMEDIATION_STATES.REJECTED_FIX);

    const { receipt } = orchestrator.finalize();
    assert.equal(receipt.verdict, BATCH_VERDICTS.ALL_REJECTED);
    assert.equal(receipt.summary.rejectedCount, 1);
    assert.equal(validateBatchReceipt(receipt), true);

    ws.assertImmutability();
  } finally {
    ws.cleanup();
  }
});

test("Contract 11: Multi-language batch remediation produces schema-compliant Batch Remediation Receipt Schema 1.0.0", () => {
  const findings = [
    { id: "TF-C", targetFiles: ["src/a.c"], language: "c" },
    { id: "TF-RS", targetFiles: ["src/b.rs"], language: "rust" }
  ];

  const orchestrator = new MultiLanguageRemediationOrchestrator("BATCH-SCHEMA-100", findings);
  const { receipt } = orchestrator.finalize();

  assert.equal(receipt.schemaVersion, "1.0.0");
  assert.equal(receipt.batchId, "BATCH-SCHEMA-100");
  assert.equal(receipt.status, BATCH_REMEDIATION_STATES.COMPLETED);
  assert.ok(validateBatchReceipt(receipt));
});

test("Contract 12: Ephemeral jail preserves immutable authority repository during multi-language patch application", () => {
  const caseDef = TF_OSS_CORPUS_V2_CASES.find(c => c.id === "TF-OSS-206"); // cpython (Python)
  const ws = createOssV2CaseWorkspace(caseDef);

  try {
    const origContent = fs.readFileSync(path.join(ws.dir, caseDef.targetFiles[0]), "utf8");

    const findings = [{
      id: caseDef.id,
      targetFiles: caseDef.targetFiles,
      testRunner: caseDef.testRunner
    }];

    const orchestrator = new MultiLanguageRemediationOrchestrator("BATCH-IMMUT-001", findings);
    orchestrator.proposeFix(caseDef.id, { diff: caseDef.patchDiff, rationale: "Fix cpython URL parse" });
    orchestrator.authorizeAll();

    orchestrator.executeInJail(ws.dir, { baseSha: ws.baseSha });

    // Assert that the working directory of the base repo remained 100% unchanged
    const currentContent = fs.readFileSync(path.join(ws.dir, caseDef.targetFiles[0]), "utf8");
    assert.equal(currentContent, origContent, "Authoritative repository file must not be modified by jail execution");
    ws.assertImmutability();
  } finally {
    ws.cleanup();
  }
});
