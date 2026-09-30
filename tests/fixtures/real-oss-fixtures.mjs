/**
 * Triad-Flow Real-World OSS Benchmark Corpus v1 (TF-OSS-v1) Fixtures & Workspace Generator
 *
 * Implements 5 human-adjudicated real-world Node.js OSS repository cases with historical CVEs:
 * - TF-OSS-001: minimist (CVE-2020-7598 / CWE-1321 Prototype Pollution)
 * - TF-OSS-002: ini (CVE-2020-7788 / CWE-1321 Prototype Pollution)
 * - TF-OSS-003: fast-json-patch (CVE-2021-4279 / CWE-1321 Prototype Pollution)
 * - TF-OSS-004: semver (CVE-2022-25883 / CWE-1333 ReDoS)
 * - TF-OSS-005: ejs (CVE-2022-29078 / CWE-94 Code Injection / SSTI)
 *
 * Zero external dependencies: All tests execute via native Node.js assertions (`node:assert`).
 */

import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { assertRepoImmutability } from "./disposable-pilot-repo.mjs";
import { CliReviewAdapter } from "../../src/adapters/cli-transport.mjs";
import { normalizeCanonicalPath } from "../../src/core/scoring.mjs";

export { assertRepoImmutability };

/**
 * 5 Frozen Human-Adjudicated Real-World OSS Benchmark Cases (TF-OSS-v1)
 */
export const TF_OSS_CORPUS_V1_CASES = Object.freeze([
  // 1. TF-OSS-001: minimist (CVE-2020-7598)
  {
    id: "TF-OSS-001",
    name: "minimist",
    title: "Prototype Pollution in minimist argument parsing",
    riskTier: 1,
    category: "vulnerable",
    cve: "CVE-2020-7598",
    ghsa: "GHSA-vh95-rmgr-6w4m",
    cwe: "CWE-1321",
    severity: "high",
    upstream: {
      repository: "https://github.com/minimistjs/minimist",
      vulnerableCommit: "388a963",
      fixCommit: "63e7ed0"
    },
    targetFiles: ["index.js"],
    description: "Unsanitized __proto__ assignment in argument parser allows arbitrary object prototype pollution",
    expectedGateDecision: "block",
    lineTolerance: 50,
    testRunner: {
      command: "node",
      args: ["test/test.js"]
    },
    goldenFindings: [
      {
        cwe: "CWE-1321",
        type: "prototype-pollution",
        file: "index.js",
        line: 9,
        severity: "high",
        rationale: "Direct traversal of __proto__ key allows remote attackers to pollute Object.prototype"
      }
    ],
    baseFiles: {
      "package.json": JSON.stringify({
        name: "minimist",
        version: "1.2.0",
        description: "parse argument options",
        main: "index.js",
        scripts: { test: "node test/test.js" }
      }, null, 2) + "\n",
      "index.js": [
        "module.exports = function (args, opts) {",
        "  if (!opts) opts = {};",
        "  var argv = { _: [] };",
        "",
        "  function setKey(obj, keys, value) {",
        "    var o = obj;",
        "    for (var i = 0; i < keys.length - 1; i++) {",
        "      var key = keys[i];",
        "      if (o[key] === undefined) o[key] = {};",
        "      o = o[key];",
        "    }",
        "    var lastKey = keys[keys.length - 1];",
        "    o[lastKey] = value;",
        "  }",
        "",
        "  for (var i = 0; i < args.length; i++) {",
        "    var arg = args[i];",
        "    if (/^--/.test(arg)) {",
        "      var key = arg.slice(2);",
        "      var val = true;",
        "      if (key.indexOf('=') !== -1) {",
        "        var parts = key.split('=');",
        "        key = parts[0];",
        "        val = parts[1];",
        "      }",
        "      if (key.indexOf('.') !== -1) {",
        "        setKey(argv, key.split('.'), val);",
        "      } else {",
        "        argv[key] = val;",
        "      }",
        "    } else {",
        "      argv._.push(arg);",
        "    }",
        "  }",
        "  return argv;",
        "};",
        ""
      ].join("\n"),
      "test/test.js": [
        "const assert = require('node:assert');",
        "const parse = require('../index.js');",
        "",
        "delete Object.prototype.polluted;",
        "parse(['--__proto__.polluted=yes']);",
        "",
        "assert.strictEqual(",
        "  Object.prototype.polluted,",
        "  undefined,",
        "  'Security defect: Object.prototype was polluted via --__proto__'",
        ");",
        "delete Object.prototype.polluted;",
        "console.log('PASS: CVE-2020-7598 mitigated');",
        ""
      ].join("\n")
    },
    patchDiff: [
      "diff --git a/index.js b/index.js",
      "index 0eef7ba..d689fde 100644",
      "--- a/index.js",
      "+++ b/index.js",
      "@@ -6,6 +6,7 @@ module.exports = function (args, opts) {",
      "     var o = obj;",
      "     for (var i = 0; i < keys.length - 1; i++) {",
      "       var key = keys[i];",
      "+      if (key === '__proto__') return;",
      "       if (o[key] === undefined) o[key] = {};",
      "       o = o[key];",
      "     }",
      ""
    ].join("\n")
  },

  // 2. TF-OSS-002: ini (CVE-2020-7788)
  {
    id: "TF-OSS-002",
    name: "ini",
    title: "Prototype Pollution in ini file section decoding",
    riskTier: 1,
    category: "vulnerable",
    cve: "CVE-2020-7788",
    ghsa: "GHSA-q9h2-87cx-55g6",
    cwe: "CWE-1321",
    severity: "high",
    upstream: {
      repository: "https://github.com/npm/ini",
      vulnerableCommit: "590195d",
      fixCommit: "56d2805"
    },
    targetFiles: ["ini.js"],
    description: "INI section header [__proto__] directly pollutes global Object.prototype",
    expectedGateDecision: "block",
    lineTolerance: 50,
    testRunner: {
      command: "node",
      args: ["test/test.js"]
    },
    goldenFindings: [
      {
        cwe: "CWE-1321",
        type: "prototype-pollution",
        file: "ini.js",
        line: 14,
        severity: "high",
        rationale: "Unsanitized section key allows __proto__ property injection during INI decoding"
      }
    ],
    baseFiles: {
      "package.json": JSON.stringify({
        name: "ini",
        version: "1.3.5",
        description: "an ini format parser and serializer for node",
        main: "ini.js",
        scripts: { test: "node test/test.js" }
      }, null, 2) + "\n",
      "ini.js": [
        "function decode(str) {",
        "  var out = {};",
        "  var p = out;",
        "  var lines = str.split(/\\r?\\n/);",
        "",
        "  for (var i = 0; i < lines.length; i++) {",
        "    var line = lines[i].trim();",
        "    if (!line || line.startsWith(';') || line.startsWith('#')) continue;",
        "",
        "    var secMatch = line.match(/^\\[(.*)\\]$/);",
        "    if (secMatch) {",
        "      var section = secMatch[1];",
        "      p = out[section] = out[section] || {};",
        "      continue;",
        "    }",
        "",
        "    var eqIdx = line.indexOf('=');",
        "    if (eqIdx !== -1) {",
        "      var key = line.slice(0, eqIdx).trim();",
        "      var val = line.slice(eqIdx + 1).trim();",
        "      p[key] = val;",
        "    }",
        "  }",
        "  return out;",
        "}",
        "",
        "module.exports = { parse: decode, decode };",
        ""
      ].join("\n"),
      "test/test.js": [
        "const assert = require('node:assert');",
        "const ini = require('../ini.js');",
        "",
        "delete Object.prototype.polluted;",
        "ini.parse('[__proto__]\\npolluted=yes');",
        "",
        "assert.strictEqual(",
        "  Object.prototype.polluted,",
        "  undefined,",
        "  'Security defect: Object.prototype was polluted via [__proto__]'",
        ");",
        "delete Object.prototype.polluted;",
        "console.log('PASS: CVE-2020-7788 mitigated');",
        ""
      ].join("\n")
    },
    patchDiff: [
      "diff --git a/ini.js b/ini.js",
      "index 63a2f62..e881ae1 100644",
      "--- a/ini.js",
      "+++ b/ini.js",
      "@@ -10,6 +10,10 @@ function decode(str) {",
      "     var secMatch = line.match(/^\\[(.*)\\]$/);",
      "     if (secMatch) {",
      "       var section = secMatch[1];",
      "+      if (section === '__proto__') {",
      "+        p = {};",
      "+        continue;",
      "+      }",
      "       p = out[section] = out[section] || {};",
      "       continue;",
      "     }",
      ""
    ].join("\n")
  },

  // 3. TF-OSS-003: fast-json-patch (CVE-2021-4279)
  {
    id: "TF-OSS-003",
    name: "fast-json-patch",
    title: "Prototype Pollution in JSON-Patch constructor/prototype path",
    riskTier: 1,
    category: "vulnerable",
    cve: "CVE-2021-4279",
    ghsa: "GHSA-q7cm-758j-8q94",
    cwe: "CWE-1321",
    severity: "high",
    upstream: {
      repository: "https://github.com/Starcounter-Jack/JSON-Patch",
      vulnerableCommit: "9a8f737",
      fixCommit: "7ad6af4"
    },
    targetFiles: ["src/core.js"],
    description: "Bypass of prototype modification ban via constructor/prototype path components",
    expectedGateDecision: "block",
    lineTolerance: 50,
    testRunner: {
      command: "node",
      args: ["test/test.js"]
    },
    goldenFindings: [
      {
        cwe: "CWE-1321",
        type: "prototype-pollution",
        file: "src/core.js",
        line: 9,
        severity: "high",
        rationale: "Unvalidated constructor/prototype path components allow prototype attribute mutation"
      }
    ],
    baseFiles: {
      "package.json": JSON.stringify({
        name: "fast-json-patch",
        version: "3.1.0",
        description: "Fast JSON-Patch implementation for JavaScript",
        main: "src/core.js",
        scripts: { test: "node test/test.js" }
      }, null, 2) + "\n",
      "src/core.js": [
        "function applyOperation(document, operation) {",
        "  var path = operation.path || '';",
        "  var keys = path.split('/').slice(1);",
        "  var obj = document;",
        "",
        "  for (var i = 0; i < keys.length - 1; i++) {",
        "    var key = keys[i];",
        "    if (obj[key] === undefined) obj[key] = {};",
        "    obj = obj[key];",
        "  }",
        "",
        "  var lastKey = keys[keys.length - 1];",
        "  if (operation.op === 'add' || operation.op === 'replace') {",
        "    obj[lastKey] = operation.value;",
        "  }",
        "  return document;",
        "}",
        "",
        "module.exports = { applyOperation };",
        ""
      ].join("\n"),
      "test/test.js": [
        "const assert = require('node:assert');",
        "const { applyOperation } = require('../src/core.js');",
        "",
        "delete Object.prototype.polluted;",
        "let threw = false;",
        "try {",
        "  applyOperation({}, { op: 'add', path: '/constructor/prototype/polluted', value: 'yes' });",
        "} catch {",
        "  threw = true;",
        "}",
        "",
        "assert.strictEqual(",
        "  Object.prototype.polluted,",
        "  undefined,",
        "  'Security defect: Object.prototype was polluted via constructor/prototype'",
        ");",
        "assert.ok(threw, 'Expected error when modifying prototype');",
        "delete Object.prototype.polluted;",
        "console.log('PASS: CVE-2021-4279 mitigated');",
        ""
      ].join("\n")
    },
    patchDiff: [
      "diff --git a/src/core.js b/src/core.js",
      "index b173a9c..302734b 100644",
      "--- a/src/core.js",
      "+++ b/src/core.js",
      "@@ -5,6 +5,9 @@ function applyOperation(document, operation) {",
      " ",
      "   for (var i = 0; i < keys.length - 1; i++) {",
      "     var key = keys[i];",
      "+    if (key === '__proto__' || (key === 'prototype' && i > 0 && keys[i - 1] === 'constructor')) {",
      "+      throw new TypeError('JSON-Patch: modifying prototype properties is banned.');",
      "+    }",
      "     if (obj[key] === undefined) obj[key] = {};",
      "     obj = obj[key];",
      "   }",
      ""
    ].join("\n")
  },

  // 4. TF-OSS-004: semver (CVE-2022-25883)
  {
    id: "TF-OSS-004",
    name: "semver",
    title: "ReDoS via greedy whitespace regex in semver",
    riskTier: 1,
    category: "vulnerable",
    cve: "CVE-2022-25883",
    ghsa: "GHSA-c2qf-rxjj-qqgw",
    cwe: "CWE-1333",
    severity: "high",
    upstream: {
      repository: "https://github.com/npm/node-semver",
      vulnerableCommit: "ed88398",
      fixCommit: "f73ef1a"
    },
    targetFiles: ["internal/re.js"],
    description: "Greedy whitespace regex tokenization leads to catastrophic backtracking / ReDoS on large inputs",
    expectedGateDecision: "block",
    lineTolerance: 50,
    testRunner: {
      command: "node",
      args: ["test/test.js"]
    },
    goldenFindings: [
      {
        cwe: "CWE-1333",
        type: "redos",
        file: "internal/re.js",
        line: 4,
        severity: "high",
        rationale: "Greedy whitespace quantifier in version parsing regex causes ReDoS"
      }
    ],
    baseFiles: {
      "package.json": JSON.stringify({
        name: "semver",
        version: "7.5.1",
        description: "The semantic version parser used by npm.",
        main: "internal/re.js",
        scripts: { test: "node test/test.js" }
      }, null, 2) + "\n",
      "internal/re.js": [
        "const re = [];",
        "",
        "// Base regex with greedy whitespace prone to ReDoS",
        "re[0] = /^\\s*([0-9]+)\\.([0-9]+)\\.([0-9]+)\\s*$/;",
        "",
        "function cleanVersion(str) {",
        "  const match = str.match(re[0]);",
        "  return match ? `${match[1]}.${match[2]}.${match[3]}` : null;",
        "}",
        "",
        "module.exports = { cleanVersion, re };",
        ""
      ].join("\n"),
      "test/test.js": [
        "const assert = require('node:assert');",
        "const reModule = require('../internal/re.js');",
        "",
        "assert.ok(reModule.safeRe, 'Security defect: safeRe must be exported to mitigate ReDoS');",
        "assert.ok(reModule.safeRe[0].source.includes('\\\\s{0,1}'), 'safeRe must use bounded whitespace');",
        "assert.strictEqual(reModule.cleanVersion('1.2.3'), '1.2.3');",
        "console.log('PASS: CVE-2022-25883 mitigated');",
        ""
      ].join("\n")
    },
    patchDiff: [
      "diff --git a/internal/re.js b/internal/re.js",
      "index 9c5518b..301cbfe 100644",
      "--- a/internal/re.js",
      "+++ b/internal/re.js",
      "@@ -1,11 +1,13 @@",
      " const re = [];",
      "+const safeRe = [];",
      " ",
      " // Base regex with greedy whitespace prone to ReDoS",
      " re[0] = /^\\s*([0-9]+)\\.([0-9]+)\\.([0-9]+)\\s*$/;",
      "+safeRe[0] = /^\\s{0,1}([0-9]+)\\.([0-9]+)\\.([0-9]+)\\s{0,1}$/;",
      " ",
      " function cleanVersion(str) {",
      "-  const match = str.match(re[0]);",
      "+  const match = str.match(safeRe[0]);",
      "   return match ? `${match[1]}.${match[2]}.${match[3]}` : null;",
      " }",
      " ",
      "-module.exports = { cleanVersion, re };",
      "+module.exports = { cleanVersion, re, safeRe };",
      ""
    ].join("\n")
  },

  // 5. TF-OSS-005: ejs (CVE-2022-29078)
  {
    id: "TF-OSS-005",
    name: "ejs",
    title: "Server-Side Template Injection via outputFunctionName in ejs",
    riskTier: 1,
    category: "vulnerable",
    cve: "CVE-2022-29078",
    ghsa: "GHSA-phwq-j96m-2c2q",
    cwe: "CWE-94",
    severity: "critical",
    upstream: {
      repository: "https://github.com/mde/ejs",
      vulnerableCommit: "aa6322e",
      fixCommit: "15ee698"
    },
    targetFiles: ["lib/ejs.js"],
    description: "Unsanitized outputFunctionName option allows arbitrary code injection during template compilation",
    expectedGateDecision: "block",
    lineTolerance: 50,
    testRunner: {
      command: "node",
      args: ["test/test.js"]
    },
    goldenFindings: [
      {
        cwe: "CWE-94",
        type: "code-injection",
        file: "lib/ejs.js",
        line: 6,
        severity: "critical",
        rationale: "Unvalidated outputFunctionName identifier allows arbitrary statement interpolation and RCE"
      }
    ],
    baseFiles: {
      "package.json": JSON.stringify({
        name: "ejs",
        version: "3.1.6",
        description: "Embedded JavaScript templates",
        main: "lib/ejs.js",
        scripts: { test: "node test/test.js" }
      }, null, 2) + "\n",
      "lib/ejs.js": [
        "function compile(template, opts) {",
        "  opts = opts || {};",
        "  var prepended = 'var __output = \"\"; function __append(s) { __output += s; }\\n';",
        "  if (opts.outputFunctionName) {",
        "    prepended += 'var ' + opts.outputFunctionName + ' = __append;\\n';",
        "  }",
        "  var fnBody = prepended + '__output += \"' + template + '\"; return __output;';",
        "  return new Function(fnBody);",
        "}",
        "",
        "module.exports = { compile };",
        ""
      ].join("\n"),
      "test/test.js": [
        "const assert = require('node:assert');",
        "const { compile } = require('../lib/ejs.js');",
        "",
        "delete global.injectedPollution;",
        "let threw = false;",
        "try {",
        "  const fn = compile('test', { outputFunctionName: 'x; global.injectedPollution=1; var y' });",
        "  fn();",
        "} catch {",
        "  threw = true;",
        "}",
        "",
        "assert.strictEqual(",
        "  global.injectedPollution,",
        "  undefined,",
        "  'Security defect: injected code executed via outputFunctionName'",
        ");",
        "assert.ok(threw, 'Expected error on invalid outputFunctionName identifier');",
        "delete global.injectedPollution;",
        "console.log('PASS: CVE-2022-29078 mitigated');",
        ""
      ].join("\n")
    },
    patchDiff: [
      "diff --git a/lib/ejs.js b/lib/ejs.js",
      "index f6b6d40..88fcbfa 100644",
      "--- a/lib/ejs.js",
      "+++ b/lib/ejs.js",
      "@@ -1,7 +1,12 @@",
      "+var _JS_IDENTIFIER = /^[a-zA-Z_$][0-9a-zA-Z_$]*$/;",
      "+",
      " function compile(template, opts) {",
      "   opts = opts || {};",
      "   var prepended = 'var __output = \"\"; function __append(s) { __output += s; }\\n';",
      "   if (opts.outputFunctionName) {",
      "+    if (!_JS_IDENTIFIER.test(opts.outputFunctionName)) {",
      "+      throw new Error('outputFunctionName is not a valid JS identifier.');",
      "+    }",
      "     prepended += 'var ' + opts.outputFunctionName + ' = __append;\\n';",
      "   }",
      "   var fnBody = prepended + '__output += \"' + template + '\"; return __output;';",
      ""
    ].join("\n")
  }
]);

/**
 * Synthesizes a virtual ChangeSet object for an OSS case without disk/git overhead.
 *
 * @param {object} caseDef
 * @returns {object}
 */
export function buildSynthesizedOssChangeSet(caseDef) {
  const targetFiles = caseDef.targetFiles || ["index.js"];
  const patchDiff = caseDef.patchDiff || "";

  const files = targetFiles.map(filePath => ({
    path: filePath,
    oldPath: null,
    renamed: false,
    additions: 4,
    deletions: 1,
    binary: false,
    unreadable: false,
    largeFile: false
  }));

  const contentDigest = crypto
    .createHash("sha256")
    .update(JSON.stringify({ id: caseDef.id, targetFiles, patchDiff }), "utf8")
    .digest("hex");

  return {
    ok: true,
    schemaVersion: "1.0.0",
    scopeMode: "revision-range",
    repository: {
      root: process.cwd(),
      hasHead: true,
      baseSha: caseDef.upstream?.vulnerableCommit || "1000000000000000000000000000000000000001",
      headSha: caseDef.upstream?.fixCommit || "2000000000000000000000000000000000000002"
    },
    contentDigest,
    totalFiles: files.length,
    totalAdditions: 4,
    totalDeletions: 1,
    files,
    diffHunks: patchDiff
  };
}

/**
 * Creates an isolated ephemeral Git repository workspace for a given OSS corpus case.
 *
 * @param {object} caseDef
 * @param {object} [options]
 * @returns {{ dir: string, caseId: string, caseDef: object, baseSha: string, headSha: string, changeSet: object, cleanup: () => void, assertImmutability: () => void }}
 */
export function createOssCaseWorkspace(caseDef, options = {}) {
  if (!caseDef || !caseDef.baseFiles) {
    throw new Error("Invalid caseDef: must contain baseFiles.");
  }

  if (options.virtual) {
    const changeSet = buildSynthesizedOssChangeSet(caseDef);
    return {
      dir: process.cwd(),
      caseId: caseDef.id,
      caseDef,
      baseSha: changeSet.repository.baseSha,
      headSha: changeSet.repository.headSha,
      changeSet,
      cleanup: () => {},
      assertImmutability: () => true
    };
  }

  const tmpDir = fs.mkdtempSync(
    path.join(os.tmpdir(), `tf-oss-workspace-${caseDef.id || "case"}-${Date.now()}-${crypto.randomBytes(3).toString("hex")}`)
  );

  const gitExec = (args) => {
    return execFileSync("git", ["-c", "core.autocrlf=false", "-c", "core.fsmonitor=false", ...args], {
      cwd: tmpDir,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true
    });
  };

  gitExec(["init", "-q"]);

  for (const [relPath, content] of Object.entries(caseDef.baseFiles)) {
    const fullPath = path.join(tmpDir, relPath);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, content, "utf8");
  }

  gitExec(["add", "."]);
  gitExec([
    "-c", "user.email=oss-corpus@triad.flow",
    "-c", "user.name=OSS Corpus Generator",
    "-c", "core.autocrlf=false",
    "commit", "-q", "-m", `chore(base): vulnerable base for ${caseDef.name || caseDef.id}`
  ]);
  const baseSha = gitExec(["rev-parse", "HEAD"]).trim();

  const changeSet = buildSynthesizedOssChangeSet(caseDef);

  const cleanup = () => {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      // Ignore windows unlock delays
    }
  };

  return {
    dir: tmpDir,
    caseId: caseDef.id,
    caseDef,
    baseSha,
    headSha: baseSha,
    changeSet,
    cleanup,
    assertImmutability: () => assertRepoImmutability(tmpDir, baseSha)
  };
}

/**
 * Creates an isolated multi-case repository workspace.
 *
 * @param {object[]} [caseDefs=TF_OSS_CORPUS_V1_CASES]
 * @returns {{ dir: string, caseDefs: object[], baseSha: string, cleanup: () => void, assertImmutability: () => void }}
 */
export function createOssMultiCaseWorkspace(caseDefs = TF_OSS_CORPUS_V1_CASES) {
  const tmpDir = fs.mkdtempSync(
    path.join(os.tmpdir(), `tf-oss-multi-${Date.now()}-${crypto.randomBytes(3).toString("hex")}`)
  );

  const gitExec = (args) => {
    return execFileSync("git", ["-c", "core.autocrlf=false", "-c", "core.fsmonitor=false", ...args], {
      cwd: tmpDir,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true
    });
  };

  gitExec(["init"]);

  for (const caseDef of caseDefs) {
    const prefix = caseDef.name || caseDef.id;
    for (const [relPath, content] of Object.entries(caseDef.baseFiles || {})) {
      const fullPath = path.join(tmpDir, prefix, relPath);
      fs.mkdirSync(path.dirname(fullPath), { recursive: true });
      fs.writeFileSync(fullPath, content, "utf8");
    }
  }

  gitExec(["add", "."]);
  gitExec([
    "-c", "user.email=oss-corpus@triad.flow",
    "-c", "user.name=OSS Corpus Generator",
    "-c", "core.autocrlf=false",
    "commit", "-q", "-m", "chore(base): multi-package OSS base commit"
  ]);
  const baseSha = gitExec(["rev-parse", "HEAD"]).trim();

  const cleanup = () => {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup error
    }
  };

  return {
    dir: tmpDir,
    caseDefs,
    baseSha,
    cleanup,
    assertImmutability: () => assertRepoImmutability(tmpDir, baseSha)
  };
}

/**
 * Retrieves an OSS corpus case by ID or name (case-insensitive).
 *
 * @param {string} idOrName - e.g. "TF-OSS-001" or "minimist"
 * @returns {object|null}
 */
export function getOssCaseById(idOrName) {
  if (!idOrName || typeof idOrName !== "string") return null;
  const norm = idOrName.trim().toLowerCase();
  return (
    TF_OSS_CORPUS_V1_CASES.find(
      c => c.id.toLowerCase() === norm || c.name.toLowerCase() === norm
    ) || null
  );
}

/**
 * Lists OSS corpus cases with optional filtering.
 *
 * @param {object} [filter]
 * @param {string} [filter.cve]
 * @param {string} [filter.cwe]
 * @param {number} [filter.limit]
 * @returns {object[]}
 */
export function listOssCases(filter = {}) {
  let cases = [...TF_OSS_CORPUS_V1_CASES];

  if (filter.cve) {
    const cveNorm = filter.cve.trim().toLowerCase();
    cases = cases.filter(c => c.cve?.toLowerCase() === cveNorm);
  }

  if (filter.cwe) {
    const cweNorm = filter.cwe.trim().toLowerCase();
    cases = cases.filter(c => c.cwe?.toLowerCase() === cweNorm);
  }

  if (filter.limit && Number.isFinite(filter.limit) && filter.limit > 0) {
    cases = cases.slice(0, filter.limit);
  }

  return cases;
}

/**
 * Creates high-fidelity mock CliReviewAdapters for offline evaluation of OSS corpus cases.
 *
 * @param {object} [options]
 * @returns {{ macro: CliReviewAdapter, micro: CliReviewAdapter }}
 */
export function createMockOssAdapters(options = {}) {
  function findCaseForInput(input) {
    const filePaths = (input.changeSet?.files || []).map(f => normalizeCanonicalPath(f.path));
    for (const c of TF_OSS_CORPUS_V1_CASES) {
      for (const target of c.targetFiles || []) {
        if (filePaths.includes(normalizeCanonicalPath(target))) {
          return c;
        }
      }
    }
    return null;
  }

  function createExecFn(role) {
    return async ({ input }) => {
      const c = findCaseForInput(input);
      const coveredFiles = (input.changeSet?.files || []).map(f => f.path);
      let findings = [];

      if (c && c.goldenFindings) {
        findings = c.goldenFindings.map(g => ({
          title: `Detected ${g.type} (${g.cwe}) in ${c.name}`,
          severity: g.severity,
          file: g.file,
          line_start: g.line,
          line_end: g.line,
          cwe: g.cwe,
          type: g.type,
          recommendation: g.rationale
        }));
      }

      return {
        stdout: JSON.stringify({
          findings,
          coverage: {
            coveredFiles,
            omittedFiles: []
          },
          usage: {
            promptTokens: 400,
            completionTokens: findings.length > 0 ? 60 : 20,
            totalTokens: findings.length > 0 ? 460 : 420
          }
        })
      };
    };
  }

  const macro = new CliReviewAdapter({
    command: "agy",
    providerName: "agy",
    modelName: "gemini-2.5-flash",
    execFn: createExecFn("macro")
  });

  const micro = new CliReviewAdapter({
    command: "claude",
    providerName: "claude",
    modelName: "claude-3-5-sonnet",
    execFn: createExecFn("micro")
  });

  return { macro, micro };
}
