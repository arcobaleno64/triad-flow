/**
 * Test Suite: Canonicalization & Digest Engine (Phase 1 Alpha)
 *
 * Validates Contract 2 and Contract 3 of TF-SPEC-RECEIPT-v1.0.0:
 * - Line ending normalization (LF, CRLF, CR, UTF-8 BOM)
 * - Path normalization (POSIX forward slashes, '.' removal, drive letter stripping)
 * - Deterministic canonical JSON serialization (lexicographical key sorting, whitespace elimination)
 * - SHA-256 hash prefixing ("sha256:...")
 * - Split prompt digests (promptTemplateDigest and renderedPromptDigest)
 * - Cross-platform bit-for-bit hash determinism (Windows vs Linux)
 * - Prohibited runtime fields (timestamps, runId, hostname, temp paths) exclusion from digests
 * - Full 20-case real benchmark corpus identity derivation
 */

import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

import {
  normalizeLineEndings,
  normalizeRelativePath,
  canonicalJsonStringify,
  computeDigest,
  sha256Digest,
  canonicalizeFileMap,
  digestFileMap,
  canonicalizeCaseFiles,
  digestCaseFiles,
  canonicalizeChangeSet,
  digestChangeSet,
  canonicalizePromptTemplate,
  digestPromptTemplate,
  canonicalizeRenderedPrompt,
  digestRenderedPrompt,
  splitPromptDigests,
  canonicalizeCase,
  digestCase,
  createCorpusIdentity,
  digestCorpus,
  BENCHMARK_PROMPT_TEMPLATE,
  PROHIBITED_IDENTITY_KEYS
} from "../src/core/canonical-digest.mjs";

import { TF_RBC_V0_CASES } from "./fixtures/real-corpus-fixtures.mjs";

test("Contract 3: Line ending normalization (LF, CRLF, CR, and UTF-8 BOM)", () => {
  // CRLF -> LF
  assert.equal(normalizeLineEndings("line1\r\nline2\r\nline3"), "line1\nline2\nline3");

  // Lone CR -> LF
  assert.equal(normalizeLineEndings("line1\rline2\rline3"), "line1\nline2\nline3");

  // Already LF -> untouched
  assert.equal(normalizeLineEndings("line1\nline2\nline3"), "line1\nline2\nline3");

  // UTF-8 BOM removal from string
  const strWithBom = "\uFEFFhello\r\nworld\n";
  assert.equal(normalizeLineEndings(strWithBom), "hello\nworld\n");

  // UTF-8 BOM removal from Buffer
  const bufWithBom = Buffer.from([0xef, 0xbb, 0xbf, ...Buffer.from("foo\r\nbar\r\n")]);
  assert.equal(normalizeLineEndings(bufWithBom), "foo\nbar\n");

  // Empty or null
  assert.equal(normalizeLineEndings(""), "");
  assert.equal(normalizeLineEndings(null), "");
  assert.equal(normalizeLineEndings(undefined), "");
});

test("Contract 3: Repository-relative POSIX path normalization", () => {
  // Windows backslashes -> POSIX forward slashes
  assert.equal(normalizeRelativePath("src\\db\\user-repo.js"), "src/db/user-repo.js");

  // Leading slashes stripped
  assert.equal(normalizeRelativePath("/src/db/user-repo.js"), "src/db/user-repo.js");
  assert.equal(normalizeRelativePath("///src/db/user-repo.js"), "src/db/user-repo.js");

  // Leading dot segments stripped
  assert.equal(normalizeRelativePath("./src/db/user-repo.js"), "src/db/user-repo.js");
  assert.equal(normalizeRelativePath(".\\src\\db\\user-repo.js"), "src/db/user-repo.js");

  // Intermediate dot segments resolved
  assert.equal(normalizeRelativePath("src/./db/./user-repo.js"), "src/db/user-repo.js");
  assert.equal(normalizeRelativePath("src/sub/../db/user-repo.js"), "src/db/user-repo.js");

  // Windows drive letters stripped
  assert.equal(normalizeRelativePath("C:\\Users\\repo\\src\\file.js"), "Users/repo/src/file.js");
  assert.equal(normalizeRelativePath("d:/repo/src/file.js"), "repo/src/file.js");

  // Preserves valid filename whitespace
  assert.equal(normalizeRelativePath("src/my file with spaces.js"), "src/my file with spaces.js");

  // Empty or invalid input
  assert.equal(normalizeRelativePath(""), "");
  assert.equal(normalizeRelativePath(null), "");
});

test("Contract 3: Deterministic canonical JSON serialization", () => {
  // Unsorted keys serialized in strict lexicographical order
  const obj = {
    zebra: 1,
    apple: 2,
    mango: 3,
    banana: {
      zulu: "last",
      alpha: "first"
    }
  };

  const expected = '{"apple":2,"banana":{"alpha":"first","zulu":"last"},"mango":3,"zebra":1}';
  assert.equal(canonicalJsonStringify(obj), expected);

  // Numeric string keys sorted lexicographically ("10" before "2")
  const numericKeys = {
    "2": "two",
    "10": "ten",
    "1": "one"
  };
  assert.equal(canonicalJsonStringify(numericKeys), '{"1":"one","10":"ten","2":"two"}');

  // Arrays preserve original index ordering
  const arr = [3, 1, 2];
  assert.equal(canonicalJsonStringify(arr), "[3,1,2]");

  // Undefined in object omitted, in array converted to null
  const withUndefined = {
    a: 1,
    b: undefined,
    c: [1, undefined, 3]
  };
  assert.equal(canonicalJsonStringify(withUndefined), '{"a":1,"c":[1,null,3]}');

  // No extraneous whitespace
  assert.equal(canonicalJsonStringify({}), "{}");
  assert.equal(canonicalJsonStringify([]), "[]");
  assert.equal(canonicalJsonStringify("hello"), '"hello"');
  assert.equal(canonicalJsonStringify(42), "42");
  assert.equal(canonicalJsonStringify(null), "null");
});

test("Contract 3: SHA-256 digest format and test vectors", () => {
  // Empty string SHA-256
  const emptyDigest = computeDigest("");
  const expectedEmpty = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  assert.equal(emptyDigest, expectedEmpty);

  // sha256Digest is alias
  assert.equal(sha256Digest(""), expectedEmpty);

  // "hello world" SHA-256
  const hwDigest = computeDigest("hello world");
  const expectedHw = "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
  assert.equal(hwDigest, expectedHw);

  // Buffer input
  assert.equal(computeDigest(Buffer.from("hello world", "utf8")), expectedHw);
});

test("Contract 3: Cross-platform bit-for-bit fileMap determinism (Windows CRLF vs Linux LF)", () => {
  const windowsFileMap = {
    "src\\db\\user-repo.js": "export class UserRepository {\r\n  constructor() {}\r\n}\r\n",
    "src\\auth\\jwt-service.js": "export function verifyToken() {\r\n  return true;\r\n}\r\n"
  };

  const linuxFileMap = {
    "src/auth/jwt-service.js": "export function verifyToken() {\n  return true;\n}\n",
    "src/db/user-repo.js": "export class UserRepository {\n  constructor() {}\n}\n"
  };

  const canonicalWin = canonicalizeFileMap(windowsFileMap);
  const canonicalLin = canonicalizeFileMap(linuxFileMap);

  assert.deepEqual(canonicalWin, canonicalLin);
  assert.equal(digestFileMap(windowsFileMap), digestFileMap(linuxFileMap));
});

test("Contract 3: Split prompt digests (promptTemplateDigest & renderedPromptDigest)", () => {
  const template = BENCHMARK_PROMPT_TEMPLATE;
  const templateDigest = digestPromptTemplate(template);
  assert.match(templateDigest, /^sha256:[a-f0-9]{64}$/);

  // Prompt with CRLF produces bit-for-bit identical digest to LF
  const crlfTemplate = template.replace(/\n/g, "\r\n");
  assert.equal(digestPromptTemplate(crlfTemplate), templateDigest);

  // Rendered prompt with injected context
  const rendered1 = template
    .replace("{{ROLE}}", "macro")
    .replace("{{SCOPE}}", "working-tree")
    .replace("{{DIFF_HUNKS}}", "+ const secret = 123;\n");

  const rendered2 = template
    .replace("{{ROLE}}", "micro")
    .replace("{{SCOPE}}", "working-tree")
    .replace("{{DIFF_HUNKS}}", "+ const secret = 123;\n");

  const split1 = splitPromptDigests(template, rendered1);
  const split2 = splitPromptDigests(template, rendered2);

  // Both share identical promptTemplateDigest
  assert.equal(split1.promptTemplateDigest, templateDigest);
  assert.equal(split2.promptTemplateDigest, templateDigest);

  // Rendered prompt digests diverge when prompt role or context differs
  assert.notEqual(split1.renderedPromptDigest, split2.renderedPromptDigest);
  assert.match(split1.renderedPromptDigest, /^sha256:[a-f0-9]{64}$/);
});

test("Contract 2 & 3: Case canonicalization and deterministic cross-platform caseDigest", () => {
  const caseA_linux = {
    id: "BENCH-REAL-001",
    title: "SQL Injection in User Query Handler",
    riskTier: 1,
    category: "vulnerable",
    targetFile: "src/db/user-repo.js",
    description: "Raw string concatenation in SQL user lookup",
    expectedGateDecision: "block",
    lineTolerance: 50,
    goldenFindings: [
      {
        cwe: "CWE-89",
        type: "sql-injection",
        file: "src/db/user-repo.js",
        line: 8,
        severity: "critical",
        rationale: "Direct SQL query concatenation"
      }
    ],
    baseFiles: {
      "src/db/user-repo.js": "class Repo {\n  query() {}\n}\n"
    },
    headFiles: {
      "src/db/user-repo.js": "class Repo {\n  query(sql + id) {}\n}\n"
    }
  };

  const caseA_windows = {
    id: "BENCH-REAL-001",
    title: "SQL Injection in User Query Handler",
    riskTier: 1,
    category: "vulnerable",
    targetFile: "src\\db\\user-repo.js",
    description: "Raw string concatenation in SQL user lookup",
    expectedGateDecision: "block",
    lineTolerance: 50,
    goldenFindings: [
      {
        cwe: "cwe-89", // lower case gets normalized
        type: "SQL-INJECTION",
        file: ".\\src\\db\\user-repo.js",
        line: 8,
        severity: "CRITICAL",
        rationale: "Direct SQL query concatenation"
      }
    ],
    baseFiles: {
      "src\\db\\user-repo.js": "class Repo {\r\n  query() {}\r\n}\r\n"
    },
    headFiles: {
      "src\\db\\user-repo.js": "class Repo {\r\n  query(sql + id) {}\r\n}\r\n"
    }
  };

  const digestLinux = digestCase(caseA_linux);
  const digestWindows = digestCase(caseA_windows);

  assert.equal(digestLinux, digestWindows);
  assert.match(digestLinux, /^sha256:[a-f0-9]{64}$/);
});

test("Contract 2 Invariant: Runtime fields are strictly prohibited from participating in caseDigest", () => {
  const cleanCase = {
    id: "BENCH-REAL-001",
    title: "SQL Injection in User Query Handler",
    riskTier: 1,
    category: "vulnerable",
    targetFile: "src/db/user-repo.js",
    description: "Raw SQL concatenation",
    expectedGateDecision: "block",
    lineTolerance: 50,
    goldenFindings: [],
    baseFiles: { "src/db/user-repo.js": "content\n" },
    headFiles: { "src/db/user-repo.js": "content modified\n" }
  };

  const baseDigest = digestCase(cleanCase);

  // Add all prohibited runtime fields
  const contaminatedCase = {
    ...cleanCase,
    runId: "run-20260929-151000-xyz9",
    timestamp: "2026-09-29T07:10:00.000Z",
    timestamps: ["2026-09-29T07:10:00.000Z"],
    startedAt: "2026-09-29T07:10:00.000Z",
    finishedAt: "2026-09-29T07:15:30.000Z",
    hostname: "ci-runner-win-042",
    platform: "win32",
    arch: "x64",
    nodeVersion: "v22.16.0",
    repoDir: "C:\\Users\\Temp\\job-9872\\repo",
    tempDir: "C:\\Users\\Temp\\scratch",
    workspaceDir: "D:\\runner\\work\\1",
    pid: 99482,
    latencyMs: 1420,
    status: "pass",
    actualGateDecision: "block",
    usage: { promptTokens: 400, completionTokens: 80 }
  };

  const contaminatedDigest = digestCase(contaminatedCase);

  // Prohibited fields must have ZERO effect on caseDigest
  assert.equal(contaminatedDigest, baseDigest);
});

test("Contract 3: Changeset canonicalization and deterministic hashing", () => {
  const cs1 = {
    scopeMode: "working-tree",
    diffHunks: "@@ -1 +1 @@\r\n-old\r\n+new\r\n",
    files: [
      { path: "src\\z.js", additions: 1, deletions: 1, binary: false },
      { path: "src\\a.js", additions: 2, deletions: 0, binary: false }
    ],
    repoRoot: "C:\\Users\\Temp\\repo", // transient, should be stripped
    runId: "run-123" // transient, should be stripped
  };

  const cs2 = {
    scopeMode: "working-tree",
    diffHunks: "@@ -1 +1 @@\n-old\n+new\n",
    files: [
      { path: "src/a.js", additions: 2, deletions: 0, binary: false },
      { path: "src/z.js", additions: 1, deletions: 1, binary: false }
    ]
  };

  const digest1 = digestChangeSet(cs1);
  const digest2 = digestChangeSet(cs2);

  assert.equal(digest1, digest2);
  assert.match(digest1, /^sha256:[a-f0-9]{64}$/);
});

test("Contract 2 & 3: Full 20-case real benchmark corpus identity derivation", () => {
  // Ensure all 20 frozen cases produce an immutable identity object
  assert.equal(TF_RBC_V0_CASES.length, 20);

  const identity = createCorpusIdentity(TF_RBC_V0_CASES, { corpusVersion: "TF-RBC-v0" });

  assert.equal(identity.corpusVersion, "TF-RBC-v0");
  assert.match(identity.corpusDigest, /^sha256:[a-f0-9]{64}$/);
  assert.equal(Object.keys(identity.caseDigests).length, 20);

  for (const [caseId, d] of Object.entries(identity.caseDigests)) {
    assert.match(caseId, /^BENCH-REAL-\d{3}$/);
    assert.match(d, /^sha256:[a-f0-9]{64}$/);
  }

  // Digest is 100% deterministic across consecutive calls
  const identity2 = createCorpusIdentity(TF_RBC_V0_CASES, { corpusVersion: "TF-RBC-v0" });
  assert.equal(identity.corpusDigest, identity2.corpusDigest);
  assert.deepEqual(identity.caseDigests, identity2.caseDigests);
});

test("Contract 2: Corpus digest is invariant under simulated cross-platform Windows CRLF & backslashes", () => {
  // Clone corpus with Windows CRLF and backslashes in all files and target paths
  const windowsCorpus = TF_RBC_V0_CASES.map(c => {
    const winBase = {};
    for (const [k, v] of Object.entries(c.baseFiles || {})) {
      winBase[k.replace(/\//g, "\\")] = v.replace(/\n/g, "\r\n");
    }
    const winHead = {};
    for (const [k, v] of Object.entries(c.headFiles || {})) {
      winHead[k.replace(/\//g, "\\")] = v.replace(/\n/g, "\r\n");
    }

    return {
      ...c,
      targetFile: c.targetFile.replace(/\//g, "\\"),
      baseFiles: winBase,
      headFiles: winHead,
      runId: `run-${Math.random()}`,
      tempDir: "C:\\Temp\\scratch"
    };
  });

  const linuxIdentity = createCorpusIdentity(TF_RBC_V0_CASES, { corpusVersion: "TF-RBC-v0" });
  const windowsIdentity = createCorpusIdentity(windowsCorpus, { corpusVersion: "TF-RBC-v0" });

  assert.equal(windowsIdentity.corpusDigest, linuxIdentity.corpusDigest);
  assert.deepEqual(windowsIdentity.caseDigests, linuxIdentity.caseDigests);
});

test("Contract 2: Modifying file content or findings alters corpusDigest", () => {
  const originalIdentity = createCorpusIdentity(TF_RBC_V0_CASES, { corpusVersion: "TF-RBC-v0" });

  // Tamper with a single character in case 1
  const tamperedCorpus = TF_RBC_V0_CASES.map((c, idx) => {
    if (idx === 0) {
      return {
        ...c,
        headFiles: {
          ...c.headFiles,
          "src/db/user-repo.js": (c.headFiles["src/db/user-repo.js"] || "") + "\n// tampered"
        }
      };
    }
    return c;
  });

  const tamperedIdentity = createCorpusIdentity(tamperedCorpus, { corpusVersion: "TF-RBC-v0" });

  // case 1 digest must change
  assert.notEqual(tamperedIdentity.caseDigests["BENCH-REAL-001"], originalIdentity.caseDigests["BENCH-REAL-001"]);
  // other 19 cases remain identical
  assert.equal(tamperedIdentity.caseDigests["BENCH-REAL-002"], originalIdentity.caseDigests["BENCH-REAL-002"]);
  // full corpusDigest must change
  assert.notEqual(tamperedIdentity.corpusDigest, originalIdentity.corpusDigest);
});

test("Contract 3: canonicalJsonStringify handles functions, symbols, Date/toJSON, DAGs, and circular structures", () => {
  // Functions and symbols in objects are omitted
  const mixedObj = {
    a: 1,
    fn: () => "ignored",
    sym: Symbol("ignored"),
    z: 2
  };
  assert.equal(canonicalJsonStringify(mixedObj), '{"a":1,"z":2}');

  // Functions and symbols in arrays are serialized as null
  const mixedArr = [1, () => "ignored", Symbol("ignored"), undefined, 2];
  assert.equal(canonicalJsonStringify(mixedArr), "[1,null,null,null,2]");

  // Date and toJSON objects serialize properly
  const dateStr = "2026-09-29T12:00:00.000Z";
  const withDate = { at: new Date(dateStr) };
  assert.equal(canonicalJsonStringify(withDate), `{"at":"${dateStr}"}`);

  // Non-circular DAGs are permitted
  const shared = { name: "shared" };
  const dag = { first: shared, second: shared };
  assert.equal(canonicalJsonStringify(dag), '{"first":{"name":"shared"},"second":{"name":"shared"}}');

  // Circular references fail fast with TypeError
  const circular = { name: "cycle" };
  circular.self = circular;
  assert.throws(() => canonicalJsonStringify(circular), TypeError);
});

test("Contract 3: goldenFindings sort is fully deterministic regardless of input permutation", () => {
  const casePerm1 = {
    id: "BENCH-TEST-PERM",
    goldenFindings: [
      { file: "src/auth.js", line: 10, cwe: "CWE-79", type: "xss-dom", severity: "high", rationale: "DOM injection" },
      { file: "src/auth.js", line: 10, cwe: "CWE-79", type: "xss-reflected", severity: "critical", rationale: "Reflected injection" }
    ]
  };

  const casePerm2 = {
    id: "BENCH-TEST-PERM",
    goldenFindings: [
      { file: "src/auth.js", line: 10, cwe: "CWE-79", type: "xss-reflected", severity: "critical", rationale: "Reflected injection" },
      { file: "src/auth.js", line: 10, cwe: "CWE-79", type: "xss-dom", severity: "high", rationale: "DOM injection" }
    ]
  };

  const digest1 = digestCase(casePerm1);
  const digest2 = digestCase(casePerm2);
  assert.equal(digest1, digest2);
});

test("Contract 2: createCorpusIdentity rejects duplicate case IDs fail-closed", () => {
  const duplicateCases = [
    { id: "CASE-DUP", title: "Original", baseFiles: {}, headFiles: {} },
    { id: "CASE-DUP", title: "Duplicate Clone", baseFiles: {}, headFiles: {} }
  ];

  assert.throws(
    () => createCorpusIdentity(duplicateCases),
    /Duplicate case ID in corpus: 'CASE-DUP'/
  );
});

test("Contract 3: canonicalizeFileMap rejects path collision with conflicting contents", () => {
  const collidingMap = {
    "src/file.js": "const a = 1;\n",
    "src\\file.js": "const a = 2;\n"
  };

  assert.throws(
    () => canonicalizeFileMap(collidingMap),
    /File map path collision after normalization/
  );
});

test("Contract 3: normalizeLineEndings handles string arrays", () => {
  const lines = ["line1\r\n", "line2\r", "line3\n"];
  assert.equal(normalizeLineEndings(lines), "line1\nline2\nline3\n");
});

