import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { execFileSync } from "node:child_process";
import { collectGitWorkingState, buildChangeSet, inspectUntrackedFile, isBinaryBuffer } from "../src/core/git-collector.mjs";

test("isBinaryBuffer detects NUL bytes in sample", () => {
  assert.equal(isBinaryBuffer(Buffer.from("hello world")), false);
  assert.equal(isBinaryBuffer(Buffer.from([0x68, 0x00, 0x69])), true);
});

test("inspectUntrackedFile handles zero-byte, large and binary files safely", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-untracked-test-"));
  const emptyFile = path.join(tmpDir, "empty.txt");
  fs.writeFileSync(emptyFile, "");

  const resEmpty = inspectUntrackedFile(emptyFile);
  assert.equal(resEmpty.additions, 0);
  assert.equal(resEmpty.binary, false);

  const binFile = path.join(tmpDir, "sample.bin");
  fs.writeFileSync(binFile, Buffer.from([0x00, 0x01, 0x02]));
  const resBin = inspectUntrackedFile(binFile);
  assert.equal(resBin.binary, true);
  assert.equal(resBin.additions, 0);

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("inspectUntrackedFile does NOT follow untracked external symlinks (P1-02)", () => {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "triad-symlink-leak-"));
  const repoDir = path.join(tmpRoot, "repo");
  const outsideDir = path.join(tmpRoot, "outside");

  fs.mkdirSync(repoDir, { recursive: true });
  fs.mkdirSync(outsideDir, { recursive: true });

  const secretFile = path.join(outsideDir, "external-fixture.env");
  fs.writeFileSync(secretFile, "SAMPLE_FIXTURE_LINE_1\nLINE_2\nLINE_3\n");

  const symlinkPath = path.join(repoDir, "symlink-fixture.txt");
  let canCreateSymlink = false;
  try {
    fs.symlinkSync(secretFile, symlinkPath, "file");
    canCreateSymlink = true;
  } catch (err) {
    console.log(`[SKIP] OS privilege does not permit symlink: ${err.message}`);
  }

  if (canCreateSymlink) {
    const inspected = inspectUntrackedFile(symlinkPath);
    assert.equal(inspected.symlink, true);
    assert.equal(inspected.additions, 0, "Must NEVER read external target bytes to count additions");
    assert.equal(inspected.deletions, 0);
  }

  fs.rmSync(tmpRoot, { recursive: true, force: true });
});

test("inspectUntrackedFile flags >2MB untracked files as largeFile without reading whole file (P1-06)", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-large-file-"));
  const largeFile = path.join(tmpDir, "large.txt");
  const buf = Buffer.alloc(2.5 * 1024 * 1024, 0x61); // 2.5 MB
  fs.writeFileSync(largeFile, buf);

  const inspected = inspectUntrackedFile(largeFile);
  assert.equal(inspected.largeFile, true);
  assert.equal(inspected.additions, 0);
  assert.equal(inspected.sizeKnown, false);

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("inspectUntrackedFile preserves unreadable/inspectionFailed metadata (P1-07)", () => {
  const info = inspectUntrackedFile("/path/to/definitely/unreadable/file/null");
  assert.equal(info.unreadable, true);
  assert.equal(info.inspectionFailed, true);
  assert.equal(info.sizeKnown, false);
});

test("collectGitWorkingState on non-git directory returns error", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-non-git-"));
  const res = collectGitWorkingState(tmpDir);
  assert.equal(res.ok, false);
  assert.match(res.error.code, /NOT_A_GIT/i);
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("collectGitWorkingState on unborn repository collects staged files", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-unborn-"));
  execFileSync("git", ["init"], { cwd: tmpDir, stdio: "ignore" });
  execFileSync("git", ["config", "user.email", "test@triad.flow"], { cwd: tmpDir, stdio: "ignore" });
  execFileSync("git", ["config", "user.name", "Triad Tester"], { cwd: tmpDir, stdio: "ignore" });

  fs.writeFileSync(path.join(tmpDir, "initial.txt"), "hello\nworld\n");
  execFileSync("git", ["add", "initial.txt"], { cwd: tmpDir, stdio: "ignore" });

  const res = collectGitWorkingState(tmpDir);
  assert.equal(res.ok, true);
  assert.equal(res.repository.hasHead, false);
  assert.equal(res.files.length, 1);
  assert.equal(res.files[0].path, "initial.txt");
  assert.equal(res.files[0].staged, true);

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("collectGitWorkingState collects clean, staged+unstaged, untracked and space filenames", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-git-working-"));
  execFileSync("git", ["init"], { cwd: tmpDir, stdio: "ignore" });
  execFileSync("git", ["config", "user.email", "test@triad.flow"], { cwd: tmpDir, stdio: "ignore" });
  execFileSync("git", ["config", "user.name", "Triad Tester"], { cwd: tmpDir, stdio: "ignore" });

  fs.writeFileSync(path.join(tmpDir, "base.txt"), "base\n");
  execFileSync("git", ["add", "base.txt"], { cwd: tmpDir, stdio: "ignore" });
  execFileSync("git", ["commit", "-m", "Base commit"], { cwd: tmpDir, stdio: "ignore" });

  // Clean state
  const cleanRes = collectGitWorkingState(tmpDir);
  assert.equal(cleanRes.ok, true);
  assert.equal(cleanRes.files.length, 0);

  // Staged + Unstaged
  fs.writeFileSync(path.join(tmpDir, "staged-new.txt"), "staged\n");
  execFileSync("git", ["add", "staged-new.txt"], { cwd: tmpDir, stdio: "ignore" });
  fs.writeFileSync(path.join(tmpDir, "base.txt"), "base modified unstaged\n");

  const mixedRes = collectGitWorkingState(tmpDir);
  assert.equal(mixedRes.ok, true);
  assert.equal(mixedRes.files.length, 2);

  // Untracked + Ignored
  fs.writeFileSync(path.join(tmpDir, ".gitignore"), "ignored.log\n");
  fs.writeFileSync(path.join(tmpDir, "ignored.log"), "ignore this\n");
  fs.writeFileSync(path.join(tmpDir, "space file.js"), "console.log('space')\n");

  const fullRes = collectGitWorkingState(tmpDir);
  assert.equal(fullRes.files.some(f => f.path === "ignored.log"), false);
  assert.equal(fullRes.files.some(f => f.path === "space file.js"), true);

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("collectGitWorkingState with revision-range collects committed diff between two commits with clean working tree", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-range-test-"));
  execFileSync("git", ["init"], { cwd: tmpDir, stdio: "ignore" });
  execFileSync("git", ["config", "user.email", "test@triad.flow"], { cwd: tmpDir, stdio: "ignore" });
  execFileSync("git", ["config", "user.name", "Triad Tester"], { cwd: tmpDir, stdio: "ignore" });

  fs.writeFileSync(path.join(tmpDir, "file1.txt"), "version 1\n");
  execFileSync("git", ["add", "file1.txt"], { cwd: tmpDir, stdio: "ignore" });
  execFileSync("git", ["commit", "-m", "commit 1"], { cwd: tmpDir, stdio: "ignore" });
  const commit1 = execFileSync("git", ["rev-parse", "HEAD"], { cwd: tmpDir, encoding: "utf-8" }).trim();

  fs.writeFileSync(path.join(tmpDir, "file1.txt"), "version 2\nadded line\n");
  fs.writeFileSync(path.join(tmpDir, "file2.txt"), "new file\n");
  execFileSync("git", ["add", "file1.txt", "file2.txt"], { cwd: tmpDir, stdio: "ignore" });
  execFileSync("git", ["commit", "-m", "commit 2"], { cwd: tmpDir, stdio: "ignore" });
  const commit2 = execFileSync("git", ["rev-parse", "HEAD"], { cwd: tmpDir, encoding: "utf-8" }).trim();

  // Working tree is completely clean!
  const statusRes = collectGitWorkingState(tmpDir);
  assert.equal(statusRes.files.length, 0);

  // But revision-range captures the committed changes between commit1 and commit2
  const rangeRes = collectGitWorkingState(tmpDir, { base: commit1, head: commit2 });
  assert.equal(rangeRes.ok, true);
  assert.equal(rangeRes.scopeMode, "revision-range");
  assert.equal(rangeRes.files.length, 2);
  assert.ok(rangeRes.files.some(f => f.path === "file1.txt"));
  assert.ok(rangeRes.files.some(f => f.path === "file2.txt"));

  // buildChangeSet returns canonical ContextPackage
  const changeSet = buildChangeSet(tmpDir, { base: commit1, head: commit2 });
  assert.equal(changeSet.ok, true);
  assert.equal(changeSet.schemaVersion, "1.0.0");
  assert.equal(changeSet.scopeMode, "revision-range");
  assert.match(changeSet.contentDigest, /^[a-f0-9]{64}$/);
  assert.match(changeSet.diffHunks, /version 2/);
  assert.equal(changeSet.totalFiles, 2);

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("collectGitWorkingState with stagedOnly collects only staged files and ignores unstaged", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-staged-test-"));
  execFileSync("git", ["init"], { cwd: tmpDir, stdio: "ignore" });
  execFileSync("git", ["config", "user.email", "test@triad.flow"], { cwd: tmpDir, stdio: "ignore" });
  execFileSync("git", ["config", "user.name", "Triad Tester"], { cwd: tmpDir, stdio: "ignore" });

  fs.writeFileSync(path.join(tmpDir, "initial.txt"), "initial\n");
  execFileSync("git", ["add", "initial.txt"], { cwd: tmpDir, stdio: "ignore" });
  execFileSync("git", ["commit", "-m", "initial"], { cwd: tmpDir, stdio: "ignore" });

  fs.writeFileSync(path.join(tmpDir, "staged.txt"), "staged\n");
  execFileSync("git", ["add", "staged.txt"], { cwd: tmpDir, stdio: "ignore" });

  fs.writeFileSync(path.join(tmpDir, "unstaged.txt"), "unstaged\n");

  const stagedRes = collectGitWorkingState(tmpDir, { stagedOnly: true });
  assert.equal(stagedRes.ok, true);
  assert.equal(stagedRes.scopeMode, "staged");
  assert.equal(stagedRes.files.length, 1);
  assert.equal(stagedRes.files[0].path, "staged.txt");

  fs.rmSync(tmpDir, { recursive: true, force: true });
});
