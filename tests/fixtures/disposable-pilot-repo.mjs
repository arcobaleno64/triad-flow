/**
 * Disposable Isolated Test Repo Fixture Generator (Milestone 2 Real Provider Pilot)
 *
 * Creates disposable, self-contained Git repositories with known clean or vulnerable
 * change sets to test real provider reviewer execution.
 * Enforces strict repository immutability assertions before and after review runs.
 */

import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { execFileSync } from "node:child_process";
import assert from "node:assert/strict";
import { buildChangeSet } from "../../src/core/git-collector.mjs";

/**
 * Asserts that the target Git repository is completely clean and untouched.
 *
 * @param {string} repoDir - Absolute path to the repository directory.
 * @returns {boolean} True if repository working tree is strictly unmodified.
 * @throws {AssertionError} If working tree is dirty or contains untracked changes.
 */
export function assertRepoImmutability(repoDir, expectedHeadSha = null) {
  if (!repoDir || !fs.existsSync(repoDir)) {
    throw new Error(`Invalid repo directory for immutability check: ${repoDir}`);
  }

  const status = execFileSync("git", ["status", "--porcelain"], {
    cwd: repoDir,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });

  assert.equal(
    status.trim(),
    "",
    `Repo immutability violated: working tree contains uncommitted or dirty changes:\n${status}`
  );

  if (expectedHeadSha) {
    const currentHead = execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: repoDir,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"]
    }).trim();

    assert.equal(
      currentHead,
      expectedHeadSha,
      `Repo immutability violated: HEAD commit drift detected (expected ${expectedHeadSha}, got ${currentHead})`
    );
  }

  return true;
}

/**
 * Creates a disposable isolated Git repository with specified fixture type.
 *
 * @param {"clean"|"vulnerable"} type - Fixture type ('clean' for benign changes, 'vulnerable' for OWASP defects).
 * @param {object} [options] - Additional options.
 * @param {boolean} [options.commit=true] - Whether to commit the changes as a feature commit.
 * @returns {{ dir: string, type: string, baseSha: string, headSha: string|null, changeSet: object, cleanup: Function, assertImmutability: Function }}
 */
export function createDisposableRepo(type = "clean", options = {}) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), `triad-pilot-${type}-`));
  const commit = options.commit !== false;

  const gitExec = (args) => execFileSync("git", args, {
    cwd: tmpDir,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });

  // 1. Initialize git repo with safe local config
  gitExec(["init"]);
  gitExec(["config", "user.email", "pilot@triad.flow"]);
  gitExec(["config", "user.name", "Pilot Tester"]);
  gitExec(["config", "core.autocrlf", "false"]);

  // 2. Base files
  const srcDir = path.join(tmpDir, "src");
  fs.mkdirSync(srcDir, { recursive: true });

  fs.writeFileSync(path.join(tmpDir, "package.json"), JSON.stringify({
    name: "pilot-fixture",
    version: "1.0.0",
    type: "module"
  }, null, 2) + "\n", "utf8");

  fs.writeFileSync(path.join(srcDir, "math.js"), [
    "export function sum(a, b) {",
    "  return a + b;",
    "}",
    "",
    "export function multiply(a, b) {",
    "  let result = 0;",
    "  for (let i = 0; i < b; i++) {",
    "    result += a;",
    "  }",
    "  return result;",
    "}",
    ""
  ].join("\n"), "utf8");

  fs.writeFileSync(path.join(srcDir, "auth.js"), [
    "export function verifyToken(token) {",
    "  if (!token) throw new Error(\"Missing token\");",
    "  return { valid: true, user: \"guest\" };",
    "}",
    ""
  ].join("\n"), "utf8");

  fs.writeFileSync(path.join(srcDir, "db.js"), [
    "export function getUser(db, id) {",
    "  return db.query(\"SELECT * FROM users WHERE id = ?\", [id]);",
    "}",
    ""
  ].join("\n"), "utf8");

  gitExec(["add", "."]);
  gitExec(["commit", "-m", "chore: base initial commit"]);
  const baseSha = gitExec(["rev-parse", "HEAD"]).trim();

  // 3. Apply changes according to type
  if (type === "clean") {
    // Benign performance optimization
    fs.writeFileSync(path.join(srcDir, "math.js"), [
      "export function sum(a, b) {",
      "  return a + b;",
      "}",
      "",
      "export function multiply(a, b) {",
      "  // Optimized multiplication",
      "  return a * b;",
      "}",
      ""
    ].join("\n"), "utf8");
  } else if (type === "vulnerable") {
    // Multi-defect sample files: authentication and database operations
    fs.writeFileSync(path.join(srcDir, "auth.js"), [
      "const JWT_SECRET = \"super_secret_jwt_token_key_123456789_triad_pilot\";",
      "",
      "export function verifyToken(token) {",
      "  // Parse token parts and decode payload",
      "  const payload = JSON.parse(Buffer.from(token.split(\".\")[1], \"base64\").toString());",
      "  return payload;",
      "}",
      ""
    ].join("\n"), "utf8");

    fs.writeFileSync(path.join(srcDir, "db.js"), [
      "export function getUser(db, id) {",
      "  // Fetch user record by ID",
      "  return db.query(\"SELECT * FROM users WHERE id = '\" + id + \"'\");",
      "}",
      ""
    ].join("\n"), "utf8");
  } else {
    throw new Error(`Unsupported disposable repo type: '${type}'. Expected 'clean' or 'vulnerable'.`);
  }

  let headSha = null;
  if (commit) {
    gitExec(["add", "."]);
    gitExec(["commit", "-m", "feat: pilot modifications"]);
    headSha = gitExec(["rev-parse", "HEAD"]).trim();
  }

  // Pre-generate changeSet for convenience
  const changeSet = commit
    ? buildChangeSet(tmpDir, { base: baseSha, head: headSha })
    : buildChangeSet(tmpDir);

  const cleanup = () => {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup error on windows locks
    }
  };

  return {
    dir: tmpDir,
    type,
    baseSha,
    headSha,
    changeSet,
    cleanup,
    assertImmutability: () => assertRepoImmutability(tmpDir, headSha)
  };
}
