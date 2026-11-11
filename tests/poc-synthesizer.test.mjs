/**
 * Triad-Flow Active PoC Counterexample Synthesizer Test Suite (Pillar 3 / v2.12)
 *
 * Validates:
 * - Contract 1: Normalization & Hashing invariants (SHA-256 canonical digests)
 * - Contract 2: Dynamic PoC Harness synthesis across CWE taxonomies (CWE-1321, CWE-22, CWE-89, CWE-78)
 * - Contract 3: Custom template registration and synthesis extension
 * - Contract 4: Differential Verification: Pre-Patch Red (Fail) & Post-Patch Green (Pass) -> DIFFERENTIAL_VERIFIED
 * - Contract 5: Differential Verification failure modes: REPRODUCTION_FAILED, PATCH_INEFFECTIVE, PATCH_REGRESSION
 * - Contract 6: Subprocess / File-based module execution
 * - Contract 7: Asset Hardening: transforming ephemeral PoC into permanent node:test regression file
 * - Contract 8: Host isolation: strictly zero prototype pollution leakage
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { execFileSync } from "node:child_process";

import {
  ActivePoCSynthesizer,
  PoCHarness,
  CWE_TAXONOMY,
  VERIFICATION_STATUS,
  HARNESS_LANGUAGES,
  TEST_FRAMEWORKS,
  PoCSynthesisError,
  DifferentialVerificationError,
  PoCExecutionTimeoutError,
  normalizeCwe,
  computeSha256,
  verifyReceiptDigest
} from "../src/core/poc-synthesizer.mjs";

test("Contract 1: Normalization & Digest Invariants", () => {
  // normalizeCwe variants
  assert.equal(normalizeCwe("cwe-22"), "CWE-22");
  assert.equal(normalizeCwe("CWE89"), "CWE-89");
  assert.equal(normalizeCwe(1321), "CWE-1321");
  assert.equal(normalizeCwe("78"), "CWE-78");

  assert.throws(() => normalizeCwe(""), PoCSynthesisError);
  assert.throws(() => normalizeCwe(null), PoCSynthesisError);

  // computeSha256
  const digest1 = computeSha256("test-script\n");
  const digest2 = computeSha256("test-script\r\n");
  assert.equal(digest1, digest2, "Digest must normalize CRLF to LF");
  assert.match(digest1, /^sha256:[a-f0-9]{64}$/);

  // verifyReceiptDigest
  const sampleReceipt = { status: "PASS", timestamp: "2026-11-11" };
  const sampleDigest = computeSha256(JSON.stringify(sampleReceipt));
  assert.equal(verifyReceiptDigest({ ...sampleReceipt, digest: sampleDigest }), true);
  assert.equal(verifyReceiptDigest({ ...sampleReceipt, digest: "sha256:corrupted" }), false);
  assert.equal(verifyReceiptDigest(null), false);
});

test("Contract 2: Synthesis for Built-in CWE Taxonomies", () => {
  const synthesizer = new ActivePoCSynthesizer();
  const supported = synthesizer.getSupportedCwes();
  assert.ok(supported.includes("CWE-1321"));
  assert.ok(supported.includes("CWE-22"));
  assert.ok(supported.includes("CWE-89"));
  assert.ok(supported.includes("CWE-78"));

  // 1. Synthesize CWE-1321 (Prototype Pollution)
  const h1321 = synthesizer.synthesize({
    cwe: "CWE-1321",
    targetFunction: "deepMerge"
  });
  assert.ok(h1321 instanceof PoCHarness);
  assert.equal(h1321.cwe, "CWE-1321");
  assert.equal(h1321.targetFunction, "deepMerge");
  assert.match(h1321.script, /Object\.prototype/);
  assert.ok(Object.isFrozen(h1321));

  // 2. Synthesize CWE-22 (Path Traversal)
  const h22 = synthesizer.synthesize({
    cwe: "CWE-22",
    targetFunction: "safePath",
    traversalSequence: "../../../etc/passwd"
  });
  assert.equal(h22.cwe, "CWE-22");
  assert.match(h22.script, /Path traversal/i);

  // 3. Synthesize CWE-89 (SQL Injection)
  const h89 = synthesizer.synthesize({
    cwe: "CWE-89",
    targetFunction: "findUserQuery"
  });
  assert.equal(h89.cwe, "CWE-89");
  assert.match(h89.script, /SQL/i);

  // 4. Synthesize CWE-78 (OS Command Injection)
  const h78 = synthesizer.synthesize({
    cwe: "CWE-78",
    targetFunction: "runReport"
  });
  assert.equal(h78.cwe, "CWE-78");
  assert.match(h78.script, /shell/i);

  // Unsupported CWE throws
  assert.throws(() => synthesizer.synthesize({ cwe: "CWE-99999" }), PoCSynthesisError);
});

test("Contract 3: Custom Template Registration", () => {
  const synthesizer = new ActivePoCSynthesizer();

  synthesizer.registerTemplate("CWE-79", (spec) => {
    return new PoCHarness({
      cwe: "CWE-79",
      targetFunction: spec.targetFunction || "renderHtml",
      payload: "<script>alert(1)</script>",
      script: `// CWE-79 Custom XSS Harness\nconsole.log("XSS checked");\nprocess.exit(0);`
    });
  });

  assert.ok(synthesizer.getSupportedCwes().includes("CWE-79"));

  const harness = synthesizer.synthesize({
    cwe: "CWE-79",
    targetFunction: "renderUnsafe"
  });
  assert.equal(harness.cwe, "CWE-79");
  assert.equal(harness.targetFunction, "renderUnsafe");
});

test("Contract 4: Differential Verification - CWE-1321 Prototype Pollution", async () => {
  const synthesizer = new ActivePoCSynthesizer();

  // Vulnerable Pre-Patch: Unsafe recursive merge that copies __proto__
  function prePatchMerge(target, source) {
    for (const key of Object.keys(source)) {
      if (typeof source[key] === "object" && source[key] !== null) {
        if (!target[key]) target[key] = {};
        prePatchMerge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
    // Also copies __proto__ if present in raw Object.getOwnPropertyNames
    if (Object.prototype.hasOwnProperty.call(source, "__proto__")) {
      Object.assign(target.__proto__, source["__proto__"]);
    }
    return target;
  }

  // Remediated Post-Patch: Sanitizes prototype pollution keys
  function postPatchMerge(target, source) {
    for (const key of Object.keys(source)) {
      if (key === "__proto__" || key === "constructor" || key === "prototype") {
        continue; // Blocked!
      }
      if (typeof source[key] === "object" && source[key] !== null) {
        if (!target[key]) target[key] = {};
        postPatchMerge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
    return target;
  }

  const result = await synthesizer.verifyDifferential({
    harness: { cwe: "CWE-1321", targetFunction: "merge" },
    prePatch: prePatchMerge,
    postPatch: postPatchMerge
  });

  assert.equal(result.status, VERIFICATION_STATUS.DIFFERENTIAL_VERIFIED);
  assert.equal(result.verified, true);
  assert.equal(result.cwe, "CWE-1321");
  assert.equal(result.prePatch.passed, false, "Pre-patch must fail (red light)");
  assert.equal(result.prePatch.exitCode, 1);
  assert.equal(result.postPatch.passed, true, "Post-patch must pass (green light)");
  assert.equal(result.postPatch.exitCode, 0);
  assert.match(result.digest, /^sha256:[a-f0-9]{64}$/);
  assert.equal(verifyReceiptDigest(result), true, "Receipt digest must be cryptographically valid");

  // Guarantee prototype is clean
  assert.equal(({}).polluted, undefined);
});

test("Contract 4.1: Differential Verification - CWE-22 Path Traversal", async () => {
  const synthesizer = new ActivePoCSynthesizer();

  // Vulnerable Pre-Patch: Naive string joining that allows ../ escape
  function prePatchResolve(baseDir, userInput) {
    return path.join(baseDir, userInput); // escapes if userInput is ../../secret.txt
  }

  // Remediated Post-Patch: Clamps to baseDir or throws
  function postPatchResolve(baseDir, userInput) {
    const resolved = path.resolve(baseDir, userInput);
    const normalizedBase = path.resolve(baseDir);
    if (!resolved.startsWith(normalizedBase + path.sep) && resolved !== normalizedBase) {
      throw new Error("Path traversal blocked: target escapes base directory");
    }
    return resolved;
  }

  const result = await synthesizer.verifyDifferential({
    harness: { cwe: "CWE-22", targetFunction: "resolvePath" },
    prePatch: prePatchResolve,
    postPatch: postPatchResolve
  });

  assert.equal(result.status, VERIFICATION_STATUS.DIFFERENTIAL_VERIFIED);
  assert.equal(result.verified, true);
  assert.equal(result.prePatch.passed, false);
  assert.equal(result.postPatch.passed, true);
});

test("Contract 4.2: Differential Verification - CWE-89 SQL Injection", async () => {
  const synthesizer = new ActivePoCSynthesizer();

  // Vulnerable Pre-Patch: Direct string interpolation
  function prePatchQuery(username) {
    return `SELECT * FROM users WHERE username = '${username}'`;
  }

  // Remediated Post-Patch: Parameterized query object
  function postPatchQuery(username) {
    return {
      text: "SELECT * FROM users WHERE username = $1",
      values: [username]
    };
  }

  const result = await synthesizer.verifyDifferential({
    harness: { cwe: "CWE-89", targetFunction: "queryUser" },
    prePatch: prePatchQuery,
    postPatch: postPatchQuery
  });

  assert.equal(result.status, VERIFICATION_STATUS.DIFFERENTIAL_VERIFIED);
  assert.equal(result.verified, true);
  assert.equal(result.prePatch.passed, false);
  assert.equal(result.postPatch.passed, true);
});

test("Contract 4.3: Differential Verification - CWE-78 OS Command Injection", async () => {
  const synthesizer = new ActivePoCSynthesizer();

  // Vulnerable Pre-Patch: Shell concatenation
  function prePatchCmd(fileName) {
    return `cat /var/log/${fileName}`;
  }

  // Remediated Post-Patch: Array arguments
  function postPatchCmd(fileName) {
    return {
      command: "cat",
      args: [`/var/log/${path.basename(fileName)}`]
    };
  }

  const result = await synthesizer.verifyDifferential({
    harness: { cwe: "CWE-78", targetFunction: "showLog" },
    prePatch: prePatchCmd,
    postPatch: postPatchCmd
  });

  assert.equal(result.status, VERIFICATION_STATUS.DIFFERENTIAL_VERIFIED);
  assert.equal(result.verified, true);
  assert.equal(result.prePatch.passed, false);
  assert.equal(result.postPatch.passed, true);
});

test("Contract 5: Verification Failure Modes (REPRODUCTION_FAILED, PATCH_INEFFECTIVE, PATCH_REGRESSION)", async () => {
  const synthesizer = new ActivePoCSynthesizer();

  // Scenario 1: REPRODUCTION_FAILED (Pre-Patch already safe, PoC cannot reproduce flaw)
  const safeFn = (base, input) => {
    throw new Error("Already secure");
  };

  const reproFailResult = await synthesizer.verifyDifferential({
    harness: { cwe: "CWE-22" },
    prePatch: safeFn,
    postPatch: safeFn
  });
  assert.equal(reproFailResult.status, VERIFICATION_STATUS.REPRODUCTION_FAILED);
  assert.equal(reproFailResult.verified, false);

  // Scenario 2: PATCH_INEFFECTIVE (Pre-Patch vulnerable, Post-Patch STILL vulnerable)
  const stillVulnerable = (base, input) => path.join(base, input);

  const ineffectiveResult = await synthesizer.verifyDifferential({
    harness: { cwe: "CWE-22" },
    prePatch: stillVulnerable,
    postPatch: stillVulnerable
  });
  assert.equal(ineffectiveResult.status, VERIFICATION_STATUS.PATCH_INEFFECTIVE);
  assert.equal(ineffectiveResult.verified, false);

  // Scenario 3: PATCH_REGRESSION (Pre-Patch vulnerable, Post-Patch crashes with unhandled crash)
  const crashingPatch = () => {
    throw new TypeError("Null pointer dereference in patch logic");
  };

  const regressionResult = await synthesizer.verifyDifferential({
    harness: { cwe: "CWE-89" },
    prePatch: (input) => `SELECT * FROM users WHERE u = '${input}'`,
    postPatch: crashingPatch
  });
  assert.equal(regressionResult.status, VERIFICATION_STATUS.PATCH_REGRESSION);
  assert.equal(regressionResult.verified, false);
});

test("Contract 6: Subprocess Execution on Disk Modules", async () => {
  const synthesizer = new ActivePoCSynthesizer();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-poc-subproc-"));

  try {
    const vulnModulePath = path.join(tmpDir, "vuln-resolver.cjs");
    const safeModulePath = path.join(tmpDir, "safe-resolver.cjs");

    // Write pre-patch module
    fs.writeFileSync(vulnModulePath, `
      const path = require("node:path");
      function resolvePath(baseDir, input) {
        return path.join(baseDir, input);
      }
      module.exports = { resolvePath };
    `, "utf8");

    // Write post-patch module
    fs.writeFileSync(safeModulePath, `
      const path = require("node:path");
      function resolvePath(baseDir, input) {
        const resolved = path.resolve(baseDir, input);
        const norm = path.resolve(baseDir);
        if (!resolved.startsWith(norm + path.sep)) {
          throw new Error("Blocked traversal");
        }
        return resolved;
      }
      module.exports = { resolvePath };
    `, "utf8");

    const harness = synthesizer.synthesize({
      cwe: "CWE-22",
      targetModule: "./dummy.cjs",
      targetFunction: "resolvePath"
    });

    const diffResult = await synthesizer.verifyDifferential({
      harness,
      prePatch: vulnModulePath,
      postPatch: safeModulePath
    });

    assert.equal(diffResult.status, VERIFICATION_STATUS.DIFFERENTIAL_VERIFIED);
    assert.equal(diffResult.verified, true);
    assert.equal(diffResult.prePatch.passed, false);
    assert.equal(diffResult.postPatch.passed, true);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Contract 7: Asset Hardening to node:test Regression File", async () => {
  const synthesizer = new ActivePoCSynthesizer();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-poc-hardening-"));

  try {
    const harness = synthesizer.synthesize({
      cwe: "CWE-1321",
      targetFunction: "merge",
      metadata: { advisoryId: "TF-ADV-2026-0033" }
    });

    // 1. Generate test code
    const regressionCode = synthesizer.hardenToRegressionTest(harness, {
      testFramework: TEST_FRAMEWORKS.NODE_TEST,
      advisoryId: "TF-ADV-2026-0033"
    });
    assert.match(regressionCode, /import test from "node:test"/);
    assert.match(regressionCode, /TF-ADV-2026-0033/);
    assert.match(regressionCode, /CWE-1321/);

    // 2. Write to disk
    const destFile = path.join(tmpDir, "security-cwe-1321.test.mjs");
    const writeResult = synthesizer.writeRegressionTestFile(harness, destFile, {
      testFramework: TEST_FRAMEWORKS.NODE_TEST,
      advisoryId: "TF-ADV-2026-0033"
    });

    assert.equal(fs.existsSync(destFile), true);
    assert.ok(writeResult.bytesWritten > 100);
    assert.equal(writeResult.filePath, destFile);

    // 3. Test Python formatting option
    const pythonCode = harness.toRegressionTest({ testFramework: TEST_FRAMEWORKS.PYTEST });
    assert.match(pythonCode, /def test_cwe_1321_regression/);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Contract 8: Host Isolation & Prototype Pollution Cleanup Invariant", () => {
  // Ensure Object.prototype remains clean across all test runs
  assert.equal(({}).polluted, undefined);
  assert.equal(Object.prototype.polluted, undefined);
  assert.equal(({}).tf_compromised, undefined);
});

test("Contract 9: Node.js VM Code String Execution Target", async () => {
  const synthesizer = new ActivePoCSynthesizer();

  const codeTarget = {
    code: `
      globalThis.merge = function(target, source) {
        for (const key of Object.keys(source)) {
          if (key === "__proto__" || key === "constructor") continue;
          target[key] = source[key];
        }
        return target;
      };
    `
  };

  const harness = synthesizer.synthesize({
    cwe: "CWE-1321",
    targetFunction: "merge"
  });

  const result = await synthesizer.executeHarness(harness, codeTarget);
  assert.equal(result.passed, true);
  assert.equal(result.exitCode, 0);
  assert.match(result.stdout, /SAFE/);
});

test("Contract 10: Strict Error Boundary & Parameter Validation", async () => {
  const synthesizer = new ActivePoCSynthesizer();

  // Missing prePatch
  await assert.rejects(
    () => synthesizer.verifyDifferential({ harness: { cwe: "CWE-22" }, postPatch: () => {} }),
    DifferentialVerificationError
  );

  // Missing postPatch
  await assert.rejects(
    () => synthesizer.verifyDifferential({ harness: { cwe: "CWE-22" }, prePatch: () => {} }),
    DifferentialVerificationError
  );

  // Invalid targetContext
  await assert.rejects(
    () => synthesizer.executeHarness(synthesizer.synthesize({ cwe: "CWE-22" }), 12345),
    PoCSynthesisError
  );

  // Register invalid template
  assert.throws(() => synthesizer.registerTemplate("CWE-999", "not-a-function"), PoCSynthesisError);
});

test("Contract 11: End-to-end execution of generated regression test via node --test", () => {
  const synthesizer = new ActivePoCSynthesizer();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-poc-e2e-node-test-"));

  try {
    const safeModPath = path.join(tmpDir, "safe-merge.mjs");
    fs.writeFileSync(safeModPath, `
      export function merge(target, source) {
        for (const k of Object.keys(source)) {
          if (k === "__proto__" || k === "constructor" || k === "prototype") continue;
          target[k] = source[k];
        }
        return target;
      }
    `, "utf8");

    // Synthesize harness
    const harness = synthesizer.synthesize({
      cwe: "CWE-1321",
      targetModule: safeModPath,
      targetFunction: "merge",
      metadata: { advisoryId: "TF-SEC-0042" }
    });

    const testFile = path.join(tmpDir, "generated-regression.test.mjs");
    synthesizer.writeRegressionTestFile(harness, testFile);

    // Run node --test on the generated test file
    const output = execFileSync(process.execPath, ["--test", testFile], {
      encoding: "utf8",
      env: { PATH: process.env.PATH, NODE_ENV: "test" }
    });

    assert.match(output, /pass 1/);
    assert.match(output, /Regression: CWE-1321 mitigation verification/);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

