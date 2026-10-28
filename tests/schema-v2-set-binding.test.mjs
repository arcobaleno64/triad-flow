import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";

import {
  evaluateContextPackageBinding,
  isContextPackageBoundToChangeSet,
  validateContextPackageAuthenticity,
  registerTrustedContextPackage,
  isTrustedContextPackage
} from "../src/core/independent-verifier.mjs";
import {
  normalizeGitPath,
  collectMutationSnapshot
} from "../src/core/git-collector.mjs";

function setupGitRepo() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "schema2-set-binding-"));
  const git = (args) => execFileSync("git", ["-c", "core.fsmonitor=false", "-c", "core.autocrlf=false", ...args], {
    cwd: tmpDir,
    encoding: "utf8",
    windowsHide: true
  });
  git(["init"]);
  git(["config", "user.name", "Triad Test"]);
  git(["config", "user.email", "test@triad-flow.dev"]);
  return { tmpDir, git };
}

test("SCHEMA2-POS-01: Multi-file ChangeSet [A, B] with authentic Git provenance across mutation combinations", () => {
  const { tmpDir, git } = setupGitRepo();
  try {
    // Initial commit (Base commit)
    fs.writeFileSync(path.join(tmpDir, "fileA.js"), "export const a = 1;\n", "utf8");
    fs.writeFileSync(path.join(tmpDir, "fileB.js"), "export const b = 1;\n", "utf8");
    fs.writeFileSync(path.join(tmpDir, "fileD.js"), "export const d = 1;\n", "utf8");
    fs.writeFileSync(path.join(tmpDir, "fileR.js"), "export const r = 1;\n", "utf8");
    git(["add", "."]);
    git(["commit", "-m", "Initial commit"]);
    const baseSha = git(["rev-parse", "HEAD"]).trim();

    // 1) Combination 1: M + M (fileA.js, fileB.js)
    fs.writeFileSync(path.join(tmpDir, "fileA.js"), "export const a = 2;\n", "utf8");
    fs.writeFileSync(path.join(tmpDir, "fileB.js"), "export const b = 2;\n", "utf8");
    git(["add", "fileA.js", "fileB.js"]);
    git(["commit", "-m", "M + M"]);
    const headSha1 = git(["rev-parse", "HEAD"]).trim();
    const diffHunks1 = git(["diff", `${baseSha}..${headSha1}`]);
    const digest1 = crypto.createHash("sha256").update(diffHunks1.replace(/\r\n/g, "\n")).digest("hex");

    const changeSet1 = {
      headSha: headSha1,
      baseSha,
      diffHunks: diffHunks1,
      files: [
        { path: "fileA.js", changeType: "M" },
        { path: "fileB.js", changeType: "M" }
      ],
      repository: { root: tmpDir }
    };

    const pkg1 = {
      schemaVersion: "2.0.0",
      headSha: headSha1,
      targetFile: "multi-file",
      contentDigest: digest1,
      repositoryRoot: tmpDir,
      fileCoverageManifest: [
        { file: "fileA.js", inspected: true, exactHeadAvailable: true, calleesExtracted: [] },
        { file: "fileB.js", inspected: true, exactHeadAvailable: true, calleesExtracted: [] }
      ],
      layers: { layer0Diff: diffHunks1 },
      budgetAccounting: { consumedBytes: 100 }
    };

    const bound1 = isContextPackageBoundToChangeSet(pkg1, changeSet1, headSha1);
    assert.equal(bound1, true, "POS-01 M+M: Context package must be strictly bound to ChangeSet");
    const auth1 = validateContextPackageAuthenticity(pkg1, {
      repositoryRoot: tmpDir,
      headSha: headSha1,
      diffHunks: diffHunks1,
      changeSet: changeSet1
    });
    assert.equal(auth1, true, "POS-01 M+M: Package must have verified authenticity");
    const reg1 = registerTrustedContextPackage(pkg1, {
      repositoryRoot: tmpDir,
      headSha: headSha1,
      diffHunks: diffHunks1,
      changeSet: changeSet1
    });
    assert.ok(reg1, "POS-01 M+M: registerTrustedContextPackage must succeed");
    assert.equal(isTrustedContextPackage(reg1), true, "POS-01 M+M: Package must be trusted");

    // 2) Combination 2: M + A (fileA.js, fileNew.js)
    fs.writeFileSync(path.join(tmpDir, "fileNew.js"), "export const n = 1;\n", "utf8");
    fs.writeFileSync(path.join(tmpDir, "fileA.js"), "export const a = 3;\n", "utf8");
    git(["add", "fileA.js", "fileNew.js"]);
    git(["commit", "-m", "M + A"]);
    const headSha2 = git(["rev-parse", "HEAD"]).trim();
    const diffHunks2 = git(["diff", `${headSha1}..${headSha2}`]);
    const digest2 = crypto.createHash("sha256").update(diffHunks2.replace(/\r\n/g, "\n")).digest("hex");

    const changeSet2 = {
      headSha: headSha2,
      baseSha: headSha1,
      diffHunks: diffHunks2,
      files: [
        { path: "fileA.js", changeType: "M" },
        { path: "fileNew.js", changeType: "A" }
      ],
      repository: { root: tmpDir }
    };

    const pkg2 = {
      schemaVersion: "2.0.0",
      headSha: headSha2,
      targetFile: "multi-file",
      contentDigest: digest2,
      repositoryRoot: tmpDir,
      fileCoverageManifest: [
        { file: "fileA.js", inspected: true, exactHeadAvailable: true, calleesExtracted: [] },
        { file: "fileNew.js", inspected: true, exactHeadAvailable: true, calleesExtracted: [] }
      ],
      layers: { layer0Diff: diffHunks2 },
      budgetAccounting: { consumedBytes: 100 }
    };

    assert.equal(isContextPackageBoundToChangeSet(pkg2, changeSet2, headSha2), true, "POS-01 M+A bound");
    assert.ok(registerTrustedContextPackage(pkg2, { repositoryRoot: tmpDir, headSha: headSha2, diffHunks: diffHunks2, changeSet: changeSet2 }), "POS-01 M+A register");

    // 3) Combination 3: M + D (fileA.js, fileD.js)
    git(["rm", "fileD.js"]);
    fs.writeFileSync(path.join(tmpDir, "fileA.js"), "export const a = 4;\n", "utf8");
    git(["add", "fileA.js"]);
    git(["commit", "-m", "M + D"]);
    const headSha3 = git(["rev-parse", "HEAD"]).trim();
    const diffHunks3 = git(["diff", `${headSha2}..${headSha3}`]);
    const digest3 = crypto.createHash("sha256").update(diffHunks3.replace(/\r\n/g, "\n")).digest("hex");

    const changeSet3 = {
      headSha: headSha3,
      baseSha: headSha2,
      diffHunks: diffHunks3,
      files: [
        { path: "fileA.js", changeType: "M" },
        { path: "fileD.js", changeType: "D" }
      ],
      repository: { root: tmpDir }
    };

    const pkg3 = {
      schemaVersion: "2.0.0",
      headSha: headSha3,
      targetFile: "multi-file",
      contentDigest: digest3,
      repositoryRoot: tmpDir,
      fileCoverageManifest: [
        { file: "fileA.js", inspected: true, exactHeadAvailable: true, calleesExtracted: [] },
        { file: "fileD.js", inspected: true, exactHeadAvailable: false, calleesExtracted: [] }
      ],
      layers: { layer0Diff: diffHunks3 },
      budgetAccounting: { consumedBytes: 100 }
    };

    assert.equal(isContextPackageBoundToChangeSet(pkg3, changeSet3, headSha3), true, "POS-01 M+D bound");
    assert.ok(registerTrustedContextPackage(pkg3, { repositoryRoot: tmpDir, headSha: headSha3, diffHunks: diffHunks3, changeSet: changeSet3 }), "POS-01 M+D register");

    // 4) Combination 4: M + R (fileA.js, fileR.js -> fileRenamed.js)
    git(["mv", "fileR.js", "fileRenamed.js"]);
    fs.writeFileSync(path.join(tmpDir, "fileA.js"), "export const a = 5;\n", "utf8");
    git(["add", "fileA.js"]);
    git(["commit", "-m", "M + R"]);
    const headSha4 = git(["rev-parse", "HEAD"]).trim();
    const diffHunks4 = git(["diff", "-M", `${headSha3}..${headSha4}`]);
    const digest4 = crypto.createHash("sha256").update(diffHunks4.replace(/\r\n/g, "\n")).digest("hex");

    const changeSet4 = {
      headSha: headSha4,
      baseSha: headSha3,
      diffHunks: diffHunks4,
      files: [
        { path: "fileA.js", changeType: "M" },
        { path: "fileRenamed.js", changeType: "R" }
      ],
      repository: { root: tmpDir }
    };

    const pkg4 = {
      schemaVersion: "2.0.0",
      headSha: headSha4,
      targetFile: "multi-file",
      contentDigest: digest4,
      repositoryRoot: tmpDir,
      fileCoverageManifest: [
        { file: "fileA.js", inspected: true, exactHeadAvailable: true, calleesExtracted: [] },
        { file: "fileRenamed.js", inspected: true, exactHeadAvailable: true, calleesExtracted: [] }
      ],
      layers: { layer0Diff: diffHunks4 },
      budgetAccounting: { consumedBytes: 100 }
    };

    assert.equal(isContextPackageBoundToChangeSet(pkg4, changeSet4, headSha4), true, "POS-01 M+R bound");
    assert.ok(registerTrustedContextPackage(pkg4, { repositoryRoot: tmpDir, headSha: headSha4, diffHunks: diffHunks4, changeSet: changeSet4 }), "POS-01 M+R register");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("SCHEMA2-POS-02: Single-file ChangeSet [A] (M) with targetFile: 'A'", () => {
  const { tmpDir, git } = setupGitRepo();
  try {
    fs.writeFileSync(path.join(tmpDir, "fileA.js"), "export const a = 1;\n", "utf8");
    git(["add", "."]);
    git(["commit", "-m", "Initial commit"]);
    const baseSha = git(["rev-parse", "HEAD"]).trim();

    fs.writeFileSync(path.join(tmpDir, "fileA.js"), "export const a = 2;\n", "utf8");
    git(["add", "fileA.js"]);
    git(["commit", "-m", "Single file modify"]);
    const headSha = git(["rev-parse", "HEAD"]).trim();
    const diffHunks = git(["diff", `${baseSha}..${headSha}`]);
    const digest = crypto.createHash("sha256").update(diffHunks.replace(/\r\n/g, "\n")).digest("hex");

    const changeSet = {
      headSha,
      baseSha,
      diffHunks,
      files: [{ path: "fileA.js", changeType: "M" }],
      repository: { root: tmpDir }
    };

    const pkg = {
      schemaVersion: "2.0.0",
      headSha,
      targetFile: "fileA.js",
      contentDigest: digest,
      repositoryRoot: tmpDir,
      fileCoverageManifest: [
        { file: "fileA.js", inspected: true, exactHeadAvailable: true, calleesExtracted: [] }
      ],
      layers: { layer0Diff: diffHunks },
      budgetAccounting: { consumedBytes: 100 }
    };

    assert.equal(isContextPackageBoundToChangeSet(pkg, changeSet, headSha), true);
    assert.equal(pkg.targetFile, "fileA.js");
    assert.notEqual(pkg.targetFile, "multi-file");
    const registered = registerTrustedContextPackage(pkg, {
      repositoryRoot: tmpDir,
      headSha,
      diffHunks,
      changeSet
    });
    assert.ok(registered);
    assert.equal(isTrustedContextPackage(registered), true);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("SCHEMA2-NEG-01: Multi-file ChangeSet [A, B], Manifest only contains [A] -> SCOPE_SUBSET_INCOMPLETE", () => {
  const changeSet = {
    headSha: "1".repeat(40),
    files: [{ path: "fileA.js" }, { path: "fileB.js" }]
  };
  const pkg = {
    schemaVersion: "2.0.0",
    headSha: "1".repeat(40),
    targetFile: "multi-file",
    fileCoverageManifest: [
      { file: "fileA.js", inspected: true }
    ]
  };
  const evalResult = evaluateContextPackageBinding(pkg, changeSet);
  assert.equal(evalResult.bound, false);
  assert.equal(evalResult.reason, "SCOPE_SUBSET_INCOMPLETE");
  assert.deepEqual(evalResult.missing, ["fileB.js"]);
});

test("SCHEMA2-NEG-02: Multi-file ChangeSet [A, B], package declares targetFile: 'A' -> MUTUAL_EXCLUSION_VIOLATION", () => {
  const changeSet = {
    headSha: "1".repeat(40),
    files: [{ path: "fileA.js" }, { path: "fileB.js" }]
  };
  const pkg = {
    schemaVersion: "2.0.0",
    headSha: "1".repeat(40),
    targetFile: "fileA.js",
    fileCoverageManifest: [
      { file: "fileA.js", inspected: true },
      { file: "fileB.js", inspected: true }
    ]
  };
  const evalResult = evaluateContextPackageBinding(pkg, changeSet);
  assert.equal(evalResult.bound, false);
  assert.equal(evalResult.reason, "MUTUAL_EXCLUSION_VIOLATION");
});

test("SCHEMA2-NEG-03: Multi-file ChangeSet [A, B], Manifest contains [A, B, C] -> SCOPE_SUPERSET_PROHIBITED", () => {
  const changeSet = {
    headSha: "1".repeat(40),
    files: [{ path: "fileA.js" }, { path: "fileB.js" }]
  };
  const pkg = {
    schemaVersion: "2.0.0",
    headSha: "1".repeat(40),
    targetFile: "multi-file",
    fileCoverageManifest: [
      { file: "fileA.js", inspected: true },
      { file: "fileB.js", inspected: true },
      { file: "fileC.js", inspected: true }
    ]
  };
  const evalResult = evaluateContextPackageBinding(pkg, changeSet);
  assert.equal(evalResult.bound, false);
  assert.equal(evalResult.reason, "SCOPE_SUPERSET_PROHIBITED");
  assert.deepEqual(evalResult.extraneous, ["fileC.js"]);
});

test("SCHEMA2-NEG-04: Manifest contains duplicate canonical path [A, A, B] -> DUPLICATE_MANIFEST_ENTRY", () => {
  const changeSet = {
    headSha: "1".repeat(40),
    files: [{ path: "fileA.js" }, { path: "fileB.js" }]
  };
  const pkg = {
    schemaVersion: "2.0.0",
    headSha: "1".repeat(40),
    targetFile: "multi-file",
    fileCoverageManifest: [
      { file: "fileA.js", inspected: true },
      { file: "fileA.js", inspected: true },
      { file: "fileB.js", inspected: true }
    ]
  };
  const evalResult = evaluateContextPackageBinding(pkg, changeSet);
  assert.equal(evalResult.bound, false);
  assert.equal(evalResult.reason, "DUPLICATE_MANIFEST_ENTRY");
});

test("SCHEMA2-NEG-05: Multi-file ChangeSet [A, B], targetFile is undefined, null, or empty string -> MISSING_TARGET_FILE_ROLE", () => {
  const changeSet = {
    headSha: "1".repeat(40),
    files: [{ path: "fileA.js" }, { path: "fileB.js" }]
  };
  const pkgUndefined = {
    schemaVersion: "2.0.0",
    headSha: "1".repeat(40),
    fileCoverageManifest: [
      { file: "fileA.js", inspected: true },
      { file: "fileB.js", inspected: true }
    ]
  };
  assert.equal(evaluateContextPackageBinding(pkgUndefined, changeSet).reason, "MISSING_TARGET_FILE_ROLE");

  const pkgNull = { ...pkgUndefined, targetFile: null };
  assert.equal(evaluateContextPackageBinding(pkgNull, changeSet).reason, "MISSING_TARGET_FILE_ROLE");

  const pkgEmpty = { ...pkgUndefined, targetFile: "" };
  assert.equal(evaluateContextPackageBinding(pkgEmpty, changeSet).reason, "MISSING_TARGET_FILE_ROLE");
});

test("SCHEMA2-NEG-06: Single-file ChangeSet [A], package declares targetFile: 'multi-file' -> MUTUAL_EXCLUSION_VIOLATION", () => {
  const changeSet = {
    headSha: "1".repeat(40),
    files: [{ path: "fileA.js" }]
  };
  const pkg = {
    schemaVersion: "2.0.0",
    headSha: "1".repeat(40),
    targetFile: "multi-file",
    fileCoverageManifest: [
      { file: "fileA.js", inspected: true }
    ]
  };
  const evalResult = evaluateContextPackageBinding(pkg, changeSet);
  assert.equal(evalResult.bound, false);
  assert.equal(evalResult.reason, "MUTUAL_EXCLUSION_VIOLATION");
});

test("SCHEMA2-NEG-07: Single-file ChangeSet [A], package lacks fileCoverageManifest -> MISSING_FILE_MANIFEST", () => {
  const changeSet = {
    headSha: "1".repeat(40),
    files: [{ path: "fileA.js" }]
  };
  const pkgNoManifest = {
    schemaVersion: "2.0.0",
    headSha: "1".repeat(40),
    targetFile: "fileA.js"
  };
  const evalResult = evaluateContextPackageBinding(pkgNoManifest, changeSet);
  assert.equal(evalResult.bound, false);
  assert.equal(evalResult.reason, "MISSING_FILE_MANIFEST");
});

test("SCHEMA2-NEG-08: ChangeSet files property is undefined, null, or non-array -> INVALID_CHANGESET_SPEC", () => {
  const pkg = {
    schemaVersion: "2.0.0",
    targetFile: "fileA.js",
    fileCoverageManifest: [{ file: "fileA.js", inspected: true }]
  };
  assert.equal(evaluateContextPackageBinding(pkg, {}).reason, "INVALID_CHANGESET_SPEC");
  assert.equal(evaluateContextPackageBinding(pkg, { files: null }).reason, "INVALID_CHANGESET_SPEC");
  assert.equal(evaluateContextPackageBinding(pkg, { files: "fileA.js" }).reason, "INVALID_CHANGESET_SPEC");
});

test("SCHEMA2-NEG-09: ChangeSet files is an empty array [] -> EMPTY_CHANGESET_SPEC", () => {
  const pkg = {
    schemaVersion: "2.0.0",
    targetFile: "fileA.js",
    fileCoverageManifest: [{ file: "fileA.js", inspected: true }]
  };
  assert.equal(evaluateContextPackageBinding(pkg, { files: [] }).reason, "EMPTY_CHANGESET_SPEC");
});

test("SCHEMA2-NEG-10: ChangeSet files contains non-string, non-object, or empty entry -> INVALID_CHANGESET_ENTRY", () => {
  const pkg = {
    schemaVersion: "2.0.0",
    targetFile: "fileA.js",
    fileCoverageManifest: [{ file: "fileA.js", inspected: true }]
  };
  assert.equal(evaluateContextPackageBinding(pkg, { files: [null] }).reason, "INVALID_CHANGESET_ENTRY");
  assert.equal(evaluateContextPackageBinding(pkg, { files: [""] }).reason, "INVALID_CHANGESET_ENTRY");
  assert.equal(evaluateContextPackageBinding(pkg, { files: [123] }).reason, "INVALID_CHANGESET_ENTRY");
  assert.equal(evaluateContextPackageBinding(pkg, { files: [{ path: "" }] }).reason, "INVALID_CHANGESET_ENTRY");
});

test("SCHEMA2-NEG-11: ChangeSet files contains duplicate paths after canonical normalization -> DUPLICATE_CHANGESET_ENTRY", () => {
  const pkg = {
    schemaVersion: "2.0.0",
    targetFile: "multi-file",
    fileCoverageManifest: [
      { file: "src/fileA.js", inspected: true },
      { file: "src/fileB.js", inspected: true }
    ]
  };
  const changeSet = {
    files: [
      { path: "src/fileA.js" },
      { path: "./src/fileA.js" }
    ]
  };
  const evalResult = evaluateContextPackageBinding(pkg, changeSet);
  assert.equal(evalResult.bound, false);
  assert.equal(evalResult.reason, "DUPLICATE_CHANGESET_ENTRY");
});

test("SCHEMA2-NEG-12: Manifest constructs duplicate via path aliases (./foo vs foo) -> CANONICAL_PATH_COLLISION", () => {
  const changeSet = {
    files: [{ path: "fileA.js" }]
  };
  const pkg = {
    schemaVersion: "2.0.0",
    targetFile: "fileA.js",
    fileCoverageManifest: [
      { file: "fileA.js", inspected: true },
      { file: "./fileA.js", inspected: true }
    ]
  };
  const evalResult = evaluateContextPackageBinding(pkg, changeSet);
  assert.equal(evalResult.bound, false);
  assert.equal(evalResult.reason, "CANONICAL_PATH_COLLISION");
});

test("SCHEMA2-NEG-13: Manifest entry sets inspected: false -> INSPECTED_FLAG_INVALID", () => {
  const changeSet = {
    files: [{ path: "fileA.js" }, { path: "fileB.js" }]
  };
  const pkg = {
    schemaVersion: "2.0.0",
    targetFile: "multi-file",
    fileCoverageManifest: [
      { file: "fileA.js", inspected: true },
      { file: "fileB.js", inspected: false }
    ]
  };
  const evalResult = evaluateContextPackageBinding(pkg, changeSet);
  assert.equal(evalResult.bound, false);
  assert.equal(evalResult.reason, "INSPECTED_FLAG_INVALID");
});

test("SCHEMA2-NEG-14: Modified file source blob missing from Git tree -> PROVENANCE_UNAVAILABLE", () => {
  const { tmpDir, git } = setupGitRepo();
  try {
    fs.writeFileSync(path.join(tmpDir, "fileA.js"), "content\n", "utf8");
    git(["add", "."]);
    git(["commit", "-m", "Commit 1"]);
    const fakeBaseSha = "0".repeat(40);

    assert.throws(
      () => collectMutationSnapshot(tmpDir, {
        scopeMode: "revision_range",
        baseSha: fakeBaseSha,
        headSha: git(["rev-parse", "HEAD"]).trim(),
        files: [{ path: "fileA.js", changeType: "M" }]
      }),
      (err) => err.code === "PROVENANCE_UNAVAILABLE" || err.message.includes("Base blob provenance unavailable")
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("SCHEMA2-NEG-15: Input path contains traversal (../), NUL, or control chars -> ILLEGAL_PATH_SECURITY_REJECT", () => {
  assert.throws(
    () => normalizeGitPath("../secret.js"),
    (err) => err.code === "ILLEGAL_PATH_SECURITY_REJECT"
  );
  assert.throws(
    () => normalizeGitPath("foo/../secret.js"),
    (err) => err.code === "ILLEGAL_PATH_SECURITY_REJECT"
  );
  assert.throws(
    () => normalizeGitPath("src/evil\0file.js"),
    (err) => err.code === "ILLEGAL_PATH_SECURITY_REJECT"
  );
  assert.throws(
    () => normalizeGitPath("src/control\x07file.js"),
    (err) => err.code === "ILLEGAL_PATH_SECURITY_REJECT"
  );
  assert.throws(
    () => normalizeGitPath("/absolute/path.js"),
    (err) => err.code === "ILLEGAL_PATH_SECURITY_REJECT"
  );
});

test("SCHEMA2-NEG-16: Invalid mutation state (Added existing in Base; Deleted missing) -> MUTATION_SEMANTICS_MISMATCH", () => {
  const { tmpDir, git } = setupGitRepo();
  try {
    fs.writeFileSync(path.join(tmpDir, "fileA.js"), "content\n", "utf8");
    git(["add", "."]);
    git(["commit", "-m", "Base commit"]);
    const baseSha = git(["rev-parse", "HEAD"]).trim();

    // Subcase 1: Added file that already exists in base commit
    assert.throws(
      () => collectMutationSnapshot(tmpDir, {
        scopeMode: "revision_range",
        baseSha,
        files: [{ path: "fileA.js", changeType: "A" }]
      }),
      (err) => err.code === "MUTATION_SEMANTICS_MISMATCH" || err.message.includes("already exists in base tree")
    );

    // Subcase 2: Deleted file that does NOT exist in base commit
    assert.throws(
      () => collectMutationSnapshot(tmpDir, {
        scopeMode: "revision_range",
        baseSha,
        files: [{ path: "nonExistent.js", changeType: "D" }]
      }),
      (err) => err.code === "MUTATION_SEMANTICS_MISMATCH" || err.message.includes("does not exist in base tree")
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
