/**
 * Test Suite: Supply-Chain Identity Closure (M2 / v2.5)
 *
 * Validates:
 * - Contract 1: .github/allowed_signers exists and contains valid SSH signing principals
 * - Contract 2: Release workflow enforces SSH signature verification with allowed_signers
 * - Contract 3: npm sbom generation emits valid SPDX 2.3 JSON with correct package metadata
 * - Contract 4: Rejection of unsigned or untrusted tags under allowed_signers policy
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { execFileSync, spawnSync } from "node:child_process";

test("Contract 1: .github/allowed_signers exists and contains valid SSH principals", () => {
  const allowedSignersPath = path.resolve(".github/allowed_signers");
  assert.ok(fs.existsSync(allowedSignersPath), ".github/allowed_signers must exist in repo");

  const content = fs.readFileSync(allowedSignersPath, "utf8");
  const lines = content.split("\n").map(l => l.trim()).filter(l => l && !l.startsWith("#"));

  assert.ok(lines.length > 0, "allowed_signers must have at least one authorized signer");
  for (const line of lines) {
    const parts = line.split(/\s+/);
    assert.ok(parts.length >= 3, `Line must have at least principal, type/namespace, and key: ${line}`);
    // Email / identity principal
    assert.match(parts[0], /^[^@\s]+@[^@\s]+\.[^@\s]+$/, `Principal must be a valid email: ${parts[0]}`);
    // Must contain ssh key type
    assert.ok(parts.some(p => p.startsWith("ssh-") || p.startsWith("ecdsa-")), `Must contain SSH key type: ${line}`);
  }
});

test("Contract 2: Release workflow enforces SSH tag signature verification and SPDX SBOM", () => {
  const releaseYmlPath = path.resolve(".github/workflows/release.yml");
  assert.ok(fs.existsSync(releaseYmlPath), ".github/workflows/release.yml must exist");

  const content = fs.readFileSync(releaseYmlPath, "utf8");

  // Verify tag verification is present
  assert.ok(content.includes("allowedSignersFile"), "release.yml must configure allowedSignersFile");
  assert.ok(content.includes("verify-tag"), "release.yml must execute git verify-tag");

  // Verify SPDX SBOM generation and attestation
  assert.ok(content.includes("--sbom-format=spdx"), "release.yml must generate SPDX SBOM");
  assert.ok(content.includes("sbom-path"), "release.yml must attest SBOM");
  assert.ok(content.includes("triad-flow.spdx.json.sha256"), "release.yml must generate and upload SBOM SHA256 digest");
  assert.ok(content.includes("sha256sum"), "release.yml must verify SBOM checksum with sha256sum");
});

test("Contract 3: SPDX 2.3 SBOM generation produces compliant document", () => {
  const pkg = JSON.parse(fs.readFileSync("package.json", "utf8"));
  const isWin = process.platform === "win32";
  const npmCmd = isWin ? "npm.cmd" : "npm";
  const res = spawnSync(npmCmd, ["sbom", "--sbom-format=spdx"], {
    encoding: "utf8",
    windowsHide: true,
    shell: isWin
  });

  assert.equal(res.status, 0, `npm sbom exited with non-zero code: ${res.stderr}`);
  const sbom = JSON.parse(res.stdout);

  assert.equal(sbom.spdxVersion, "SPDX-2.3", "Must be SPDX-2.3 format");
  assert.equal(sbom.dataLicense, "CC0-1.0", "Data license must be CC0-1.0");
  assert.ok(Array.isArray(sbom.packages), "Must contain packages array");

  const rootPkg = sbom.packages.find(p => p.name === pkg.name);
  assert.ok(rootPkg, `Must contain root package '${pkg.name}'`);
  assert.equal(rootPkg.versionInfo, pkg.version, "SBOM version must match package.json");
  assert.equal(rootPkg.licenseDeclared, pkg.license, "SBOM license must match package.json");
});

test("Contract 4: Rejection of unsigned or untrusted tags under allowed_signers policy", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-tag-signing-test-"));
  try {
    execFileSync("git", ["init"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "Test Signer"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "signer@triadflow.dev"], { cwd: tmpDir, stdio: "ignore" });
    fs.writeFileSync(path.join(tmpDir, "file.txt"), "content\n");
    execFileSync("git", ["add", "."], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "init"], { cwd: tmpDir, stdio: "ignore" });

    // 1. Unsigned tag verification MUST fail
    execFileSync("git", ["tag", "-a", "v-unsigned", "-m", "unsigned tag"], { cwd: tmpDir, stdio: "ignore" });

    const allowedSigners = path.resolve(".github/allowed_signers");
    const verifyUnsigned = spawnSync("git", [
      "-c", `gpg.ssh.allowedSignersFile=${allowedSigners}`,
      "verify-tag", "v-unsigned"
    ], { cwd: tmpDir, encoding: "utf8" });

    assert.notEqual(verifyUnsigned.status, 0, "Verifying unsigned tag must exit non-zero");
    assert.match(verifyUnsigned.stderr || verifyUnsigned.stdout, /no signature found/i);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
