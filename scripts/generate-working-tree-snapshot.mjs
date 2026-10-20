import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import cp from "node:child_process";

const REMOTE_HEAD_SHA = "ebe28be8b4db6ef276e6b3dcc1201a860af5231f";

export function generateWorkingTreeSnapshot() {
  // Ensure authoritative scope of 10 modified tracked files in PR #39
  const knownTrackedModifiedScope = [
    ".github/allowed_signers",
    ".github/workflows/nightly.yml",
    ".gitignore",
    "scripts/dogfood-review.mjs",
    "src/adapters/review-orchestrator.mjs",
    "src/cli.mjs",
    "src/core/context-builder.mjs",
    "src/core/harness.mjs",
    "src/core/independent-verifier.mjs",
    "tests/remediation-007-clean-challenge.test.mjs"
  ];

  // Authoritative scope of 20 untracked files in PR #39
  const knownUntrackedScope = [
    "docs/reports/pr-39-complete-threads-triage-ledger.md",
    "docs/reports/pr-39-comprehensive-change-ledger.md",
    "docs/reports/pr-39-gate-authorization-triage.md",
    "docs/reports/pr-39-pre-merge-governance-packet.md",
    "evidence-runs/PR-39/change-ledger.json",
    "evidence-runs/PR-39/complete-threads-triage-ledger.json",
    "evidence-runs/PR-39/gate-authorization-triage.json",
    "evidence-runs/PR-39/github-threads-raw.json",
    "evidence-runs/PR-39/remaining-66-details.json",
    "evidence-runs/PR-39/remaining-66-summary.json",
    "evidence-runs/PR-39/working-tree-snapshot.json",
    "scripts/generate-change-ledger.mjs",
    "scripts/generate-complete-threads-ledger.mjs",
    "scripts/generate-working-tree-snapshot.mjs",
    "scripts/scan-controlled-crlf.mjs",
    "tests/adversarial-phase3-challenger.test.mjs",
    "tests/challenger-phase3-r1-r2-r3.test.mjs",
    "tests/remediation-phase1-harness.test.mjs",
    "tests/remediation-phase2-verifier.test.mjs",
    "tests/remediation-phase3-orchestrator-cli.test.mjs"
  ];

  // Read porcelain status to discover any modified or untracked files
  const statusOutput = cp.execSync("git status --porcelain", { encoding: "utf8" });
  const lines = statusOutput.split("\n").map(l => l.trimEnd()).filter(Boolean);

  const modifiedTrackedList = [...knownTrackedModifiedScope];
  const untrackedList = [...knownUntrackedScope];

  for (const line of lines) {
    let filePath = line.slice(3).trim();
    if (filePath.startsWith('"') && filePath.endsWith('"')) {
      filePath = filePath.slice(1, -1);
    }
    let inHead = false;
    try {
      cp.execSync(`git cat-file -e HEAD:${filePath}`, { stdio: "ignore" });
      inHead = true;
    } catch {
      inHead = false;
    }

    if (inHead) {
      if (!modifiedTrackedList.includes(filePath)) {
        modifiedTrackedList.push(filePath);
      }
    } else {
      if (!untrackedList.includes(filePath)) {
        untrackedList.push(filePath);
      }
    }
  }

  // Ensure deterministic sorting
  modifiedTrackedList.sort();
  untrackedList.sort();

  // Process modified tracked files
  const modifiedTrackedFiles = {};
  for (const relPath of modifiedTrackedList) {
    const diskBuf = fs.readFileSync(relPath);
    const headBuf = cp.execSync(`git show HEAD:${relPath}`);
    const diskSha = crypto.createHash("sha256").update(diskBuf).digest("hex");
    const headSha = crypto.createHash("sha256").update(headBuf).digest("hex");
    const isConfigFile = relPath.startsWith(".") || relPath === ".gitignore";

    modifiedTrackedFiles[relPath] = {
      category: isConfigFile ? "CONFIG_FILE" : relPath.startsWith("tests/") ? "TEST_SUITE" : "CORE_SOURCE",
      headSha256: headSha,
      diskSha256: diskSha,
      diskBytes: diskBuf.length,
      headBytes: headBuf.length,
      isBitForBitIdentical: diskBuf.equals(headBuf)
    };
  }

  // Process untracked files with classification
  const untrackedFiles = {};
  for (const relPath of untrackedList) {
    if (relPath === "evidence-runs/PR-39/working-tree-snapshot.json") {
      untrackedFiles[relPath] = {
        category: "SNAPSHOT_MANIFEST",
        isSelfReferentialManifest: true,
        excludedFromDigest: true,
        note: "Excluded from manifestDigestSha256 calculation to eliminate circular hash self-invalidation"
      };
      continue;
    }

    let category = "OTHER";
    if (relPath.startsWith("tests/")) category = "TEST_SUITE";
    else if (relPath.startsWith("docs/reports/")) category = "GOVERNANCE_REPORT";
    else if (relPath.startsWith("evidence-runs/")) category = "EVIDENCE_DATA";
    else if (relPath.startsWith("scripts/")) category = "GOVERNANCE_SCRIPT";

    let diskSha = "";
    let diskBytes = 0;
    if (fs.existsSync(relPath)) {
      const diskBuf = fs.readFileSync(relPath);
      diskSha = crypto.createHash("sha256").update(diskBuf).digest("hex");
      diskBytes = diskBuf.length;
    }

    untrackedFiles[relPath] = {
      category,
      diskSha256: diskSha,
      diskBytes
    };
  }

  // Excluded items from .gitignore / runtime artifacts
  const excludedItems = [
    {
      pattern: ".agents/",
      reason: "Multi-agent teamwork runtime workspaces and transcript scratchpads (local-only transient coordination state)"
    },
    {
      pattern: ".triad-flow/",
      reason: "Runtime local execution state, cached telemetry, and temporary test databases"
    },
    {
      pattern: "benchmark-results.json",
      reason: "Runtime benchmarking runner execution output (benchmark telemetry)"
    },
    {
      pattern: "remediation-receipt.json",
      reason: "Local remediation session receipt artifact"
    },
    {
      pattern: "summary.md",
      reason: "Local temporary workspace summary draft"
    }
  ];

  // Full working tree diff of modified tracked files against HEAD
  const diffBuf = cp.execSync(`git diff HEAD -- ${knownTrackedModifiedScope.join(" ")}`, {
    maxBuffer: 50 * 1024 * 1024
  });
  const fullWorkingTreeDiffSha256 = crypto.createHash("sha256").update(diffBuf).digest("hex");
  const fullWorkingTreeDiffBytes = diffBuf.length;

  // Compute canonical manifest digest strictly over the 29 content files (excluding manifest self-reference)
  const allIncludedEntries = [];
  for (const [p, m] of Object.entries(modifiedTrackedFiles)) {
    allIncludedEntries.push(`${p}:${m.diskSha256}:${m.diskBytes}`);
  }
  for (const [p, u] of Object.entries(untrackedFiles)) {
    if (p === "evidence-runs/PR-39/working-tree-snapshot.json" || u.excludedFromDigest) {
      continue;
    }
    allIncludedEntries.push(`${p}:${u.diskSha256}:${u.diskBytes}`);
  }
  allIncludedEntries.sort();

  const manifestDigestSha256 = crypto.createHash("sha256")
    .update(allIncludedEntries.join("\n"))
    .digest("hex");

  const snapshot = {
    metadata: {
      remoteHeadSha: REMOTE_HEAD_SHA,
      timestamp: new Date().toISOString(),
      workingTreeStatus: "UNCOMMITTED_LOCAL_MODIFICATIONS",
      totalTrackedModifiedFiles: Object.keys(modifiedTrackedFiles).length,
      totalUntrackedFiles: Object.keys(untrackedFiles).length,
      totalIncludedFiles: Object.keys(modifiedTrackedFiles).length + Object.keys(untrackedFiles).length,
      totalContentFilesHashed: allIncludedEntries.length,
      manifestSelfPath: "evidence-runs/PR-39/working-tree-snapshot.json",
      manifestDigestSha256,
      fullWorkingTreeDiffSha256,
      fullWorkingTreeDiffBytes
    },
    modifiedTrackedFiles,
    untrackedFiles,
    excludedItems
  };

  const dest = path.join("evidence-runs", "PR-39", "working-tree-snapshot.json");
  fs.writeFileSync(dest, JSON.stringify(snapshot, null, 2) + "\n", "utf8");
  console.log(`Generated complete working tree snapshot: ${dest}`);
  console.log(`- Modified tracked files: ${Object.keys(modifiedTrackedFiles).length}`);
  console.log(`- Untracked files: ${Object.keys(untrackedFiles).length}`);
  console.log(`- Total included files: ${Object.keys(modifiedTrackedFiles).length + Object.keys(untrackedFiles).length}`);
  console.log(`- Total content files hashed: ${allIncludedEntries.length}`);
  console.log(`- Diff SHA-256: ${fullWorkingTreeDiffSha256} (${fullWorkingTreeDiffBytes} bytes)`);
  console.log(`- Manifest Digest: ${manifestDigestSha256}`);
  return snapshot;
}

if (import.meta.url === `file://${process.argv[1]?.replace(/\\/g, "/")}` || process.argv[1]?.endsWith("generate-working-tree-snapshot.mjs")) {
  generateWorkingTreeSnapshot();
}
