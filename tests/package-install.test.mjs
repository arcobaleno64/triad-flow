import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(__dirname, "..");
const isWin = process.platform === "win32";

test("NPM Package & Executable Bin Integration (Offline E2E)", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "triad-flow-pkg-test-"));

  try {
    // 1. Shebang check (no BOM, starts with #!)
    const binFileBuffer = fs.readFileSync(path.join(ROOT_DIR, "bin", "triad-flow.mjs"));
    assert.equal(binFileBuffer[0], 0x23); // #
    assert.equal(binFileBuffer[1], 0x21); // !

    // 2. Run npm pack to tempDir
    const packResult = spawnSync(isWin ? "npm.cmd" : "npm", ["pack", "--pack-destination", tempDir, "--json"], {
      cwd: ROOT_DIR,
      encoding: "utf-8",
      shell: isWin
    });

    assert.equal(packResult.status, 0, `npm pack failed: ${packResult.stderr}`);
    const packJson = JSON.parse(packResult.stdout.trim());
    const tarballFilename = packJson[0].filename;
    const tarballPath = path.join(tempDir, tarballFilename);
    assert.equal(fs.existsSync(tarballPath), true);

    // 3. Create consumer package in tempDir
    fs.writeFileSync(
      path.join(tempDir, "package.json"),
      JSON.stringify({ name: "triad-flow-test-consumer", version: "1.0.0", private: true }, null, 2),
      "utf-8"
    );

    // 4. Offline install local tarball
    const installResult = spawnSync(
      isWin ? "npm.cmd" : "npm",
      ["install", "--offline", "--no-audit", "--no-fund", tarballPath],
      {
        cwd: tempDir,
        encoding: "utf-8",
        shell: isWin
      }
    );
    assert.equal(installResult.status, 0, `npm install failed: ${installResult.stderr}`);

    // 5. Test executing installed bin
    const binName = isWin ? "triad-flow.cmd" : "triad-flow";
    const installedBinPath = path.join(tempDir, "node_modules", ".bin", binName);
    assert.equal(fs.existsSync(installedBinPath), true);

    // Run doctor via installed bin
    const docRes = spawnSync(installedBinPath, ["doctor"], {
      cwd: tempDir,
      encoding: "utf-8",
      shell: isWin
    });
    assert.equal(docRes.status, 0, `Doctor failed with code ${docRes.status}: ${docRes.stderr}`);
    assert.match(docRes.stderr + docRes.stdout, /Doctor|Deterministic Safety Core/i);

    // Run demo via installed bin
    const demoRes = spawnSync(installedBinPath, ["demo"], {
      cwd: tempDir,
      encoding: "utf-8",
      shell: isWin
    });
    assert.equal(demoRes.status, 0, `Demo failed: ${demoRes.stderr}`);
    assert.match(demoRes.stderr + demoRes.stdout, /\[DEMO \/ SIMULATION MODE\]/i);

    // Run invalid command (Exit 2)
    const errRes = spawnSync(installedBinPath, ["unknown-command-xyz"], {
      cwd: tempDir,
      encoding: "utf-8",
      shell: isWin
    });
    assert.equal(errRes.status, 2);

    // Run via npx --no-install
    const npxRes = spawnSync(isWin ? "npx.cmd" : "npx", ["--no-install", "triad-flow", "doctor"], {
      cwd: tempDir,
      encoding: "utf-8",
      shell: isWin
    });
    assert.equal(npxRes.status, 0);
  } finally {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup error on Windows
    }
  }
});
