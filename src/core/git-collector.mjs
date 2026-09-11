/**
 * Hardened Git Change Collector for Triad-Flow
 * Collects Staged, Unstaged, and Untracked non-ignored files with zero mock fallbacks.
 * Uses authoritative parser from git-numstat.mjs and lstat-safe untracked inspection.
 */

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { parseNumstatZ } from "./git-numstat.mjs";

export { parseNumstatZ };

const MAX_UNTRACKED_SCAN_SIZE = 2 * 1024 * 1024; // 2MB cap
const BINARY_SAMPLE_SIZE = 8000;
const EMPTY_TREE_SHA = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
const EXEC_OPTS = {
  encoding: "utf-8",
  maxBuffer: 10 * 1024 * 1024, // 10MB buffer
  windowsHide: true
};

function gitExec(repoRoot, args, options = {}) {
  return execFileSync("git", ["-c", "core.fsmonitor=false", ...args], {
    cwd: repoRoot,
    ...EXEC_OPTS,
    ...options
  });
}

/**
 * Checks if buffer contains NUL bytes to determine if it is binary.
 */
export function isBinaryBuffer(buf) {
  if (!buf || buf.length === 0) return false;
  const len = Math.min(buf.length, BINARY_SAMPLE_SIZE);
  for (let i = 0; i < len; i++) {
    if (buf[i] === 0) return true;
  }
  return false;
}

/**
 * Safely inspects an untracked file without following external symlinks or causing V8 OOM.
 */
export function inspectUntrackedFile(fullPath) {
  try {
    const stat = fs.lstatSync(fullPath); // Use lstatSync to prevent following symlinks

    if (stat.isSymbolicLink()) {
      return {
        additions: 0,
        deletions: 0,
        binary: false,
        symlink: true,
        sizeKnown: true
      };
    }

    if (!stat.isFile()) {
      return {
        additions: 0,
        deletions: 0,
        binary: false,
        skipped: true,
        sizeKnown: true
      };
    }

    if (stat.size === 0) {
      return { additions: 0, deletions: 0, binary: false, sizeKnown: true };
    }

    // Do not read files > 2MB into memory strings
    if (stat.size > MAX_UNTRACKED_SCAN_SIZE) {
      return { additions: 0, deletions: 0, binary: false, largeFile: true, sizeKnown: false };
    }

    const fd = fs.openSync(fullPath, "r");
    let sampleBuf;
    try {
      sampleBuf = Buffer.alloc(Math.min(stat.size, BINARY_SAMPLE_SIZE));
      fs.readSync(fd, sampleBuf, 0, sampleBuf.length, 0);
    } finally {
      fs.closeSync(fd);
    }

    if (isBinaryBuffer(sampleBuf)) {
      return { additions: 0, deletions: 0, binary: true, sizeKnown: true };
    }

    const content = fs.readFileSync(fullPath);
    let lineCount = 0;
    for (let i = 0; i < content.length; i++) {
      if (content[i] === 0x0a) lineCount++;
    }
    if (content.length > 0 && content[content.length - 1] !== 0x0a) {
      lineCount++;
    }

    return { additions: lineCount, deletions: 0, binary: false, sizeKnown: true };
  } catch (_err) {
    return {
      additions: 0,
      deletions: 0,
      binary: false,
      unreadable: true,
      inspectionFailed: true,
      sizeKnown: false
    };
  }
}

/**
 * Core Git Working State Collector.
 */
export function collectGitWorkingState(cwd = process.cwd(), options = {}) {
  let repoRoot;
  let hasHead = true;

  // 1. Verify directory is inside a real working tree (blocks Bare Repo escape)
  try {
    const isWorkTree = gitExec(cwd, ["rev-parse", "--is-inside-work-tree"], {
      stdio: ["ignore", "pipe", "ignore"]
    }).trim();

    if (isWorkTree !== "true") {
      return {
        ok: false,
        error: {
          code: "NOT_A_GIT_WORK_TREE",
          message: "Current directory is not inside a Git working tree (bare repo or non-git)."
        }
      };
    }

    repoRoot = gitExec(cwd, ["rev-parse", "--show-toplevel"], {
      stdio: ["ignore", "pipe", "ignore"]
    }).trim().replace(/\\/g, "/");
  } catch (err) {
    return {
      ok: false,
      error: {
        code: "NOT_A_GIT_REPO",
        message: err.message || "Failed to inspect Git repository"
      }
    };
  }

  // 2. Check if HEAD exists (Unborn repository support)
  try {
    gitExec(repoRoot, ["rev-parse", "--verify", "HEAD"], {
      stdio: "ignore"
    });
  } catch (_err) {
    hasHead = false;
  }

  // 3. Revision Range Mode (--base / --head)
  if (options.base) {
    let baseSha;
    try {
      baseSha = gitExec(repoRoot, ["rev-parse", "--verify", `${options.base}^{commit}`]).trim();
    } catch (_err) {
      return {
        ok: false,
        error: {
          code: "INVALID_BASE_REF",
          message: `Base reference '${options.base}' is invalid or cannot be resolved.`
        }
      };
    }

    const headRef = options.head || "HEAD";
    let headSha;
    try {
      headSha = gitExec(repoRoot, ["rev-parse", "--verify", `${headRef}^{commit}`]).trim();
    } catch (_err) {
      return {
        ok: false,
        error: {
          code: "INVALID_HEAD_REF",
          message: `Head reference '${headRef}' is invalid or cannot be resolved.`
        }
      };
    }

    try {
      const rangeRaw = gitExec(repoRoot, ["diff", "--numstat", "-z", `${baseSha}...${headSha}`]);
      const records = parseNumstatZ(rangeRaw);
      const fileMap = new Map();
      for (const rec of records) {
        fileMap.set(rec.path, {
          path: rec.path,
          oldPath: rec.oldPath,
          renamed: rec.renamed,
          additions: rec.additions,
          deletions: rec.deletions,
          binary: rec.binary,
          staged: false,
          unstaged: false,
          untracked: false,
          committed: true
        });
      }

      return {
        ok: true,
        scopeMode: "revision-range",
        repository: {
          root: repoRoot,
          hasHead: true,
          base: options.base,
          head: headRef,
          baseSha,
          headSha
        },
        files: Array.from(fileMap.values())
      };
    } catch (err) {
      return {
        ok: false,
        error: {
          code: "GIT_INSPECTION_FAILED",
          message: err.message || "Failed during revision-range Git diff collection"
        }
      };
    }
  }

  try {
    const fileMap = new Map();

    // 4. Collect Staged Changes
    let stagedRaw = "";
    if (hasHead) {
      stagedRaw = gitExec(repoRoot, ["diff", "--cached", "--numstat", "-z"]);
    } else {
      stagedRaw = gitExec(repoRoot, ["diff-index", "--cached", "--numstat", "-z", EMPTY_TREE_SHA]);
    }

    const stagedRecords = parseNumstatZ(stagedRaw);
    for (const rec of stagedRecords) {
      fileMap.set(rec.path, {
        path: rec.path,
        oldPath: rec.oldPath,
        renamed: rec.renamed,
        additions: rec.additions,
        deletions: rec.deletions,
        binary: rec.binary,
        staged: true,
        unstaged: false,
        untracked: false
      });
    }

    if (options.stagedOnly) {
      return {
        ok: true,
        scopeMode: "staged",
        repository: {
          root: repoRoot,
          hasHead
        },
        files: Array.from(fileMap.values())
      };
    }

    // 5. Collect Unstaged Changes (Merge with Staged)
    const unstagedRaw = gitExec(repoRoot, ["diff", "--numstat", "-z"]);
    const unstagedRecords = parseNumstatZ(unstagedRaw);

    for (const rec of unstagedRecords) {
      if (fileMap.has(rec.path)) {
        const existing = fileMap.get(rec.path);
        existing.unstaged = true;
        if (!existing.binary && !rec.binary) {
          existing.additions += rec.additions;
          existing.deletions += rec.deletions;
        } else {
          existing.binary = true;
          existing.additions = 0;
          existing.deletions = 0;
        }
      } else {
        fileMap.set(rec.path, {
          path: rec.path,
          oldPath: rec.oldPath,
          renamed: rec.renamed,
          additions: rec.additions,
          deletions: rec.deletions,
          binary: rec.binary,
          staged: false,
          unstaged: true,
          untracked: false
        });
      }
    }

    // 6. Collect Untracked files (excluding ignored files)
    const untrackedRaw = gitExec(repoRoot, ["ls-files", "--others", "--exclude-standard", "-z"]);

    if (untrackedRaw) {
      const untrackedPaths = untrackedRaw.split("\0").filter(Boolean);
      for (const relPath of untrackedPaths) {
        const fullPath = path.join(repoRoot, relPath);
        const info = inspectUntrackedFile(fullPath);

        if (!fileMap.has(relPath)) {
          fileMap.set(relPath, {
            path: relPath,
            oldPath: null,
            renamed: false,
            additions: info.additions,
            deletions: info.deletions,
            binary: info.binary,
            staged: false,
            unstaged: false,
            untracked: true,
            symlink: Boolean(info.symlink),
            largeFile: Boolean(info.largeFile),
            unreadable: Boolean(info.unreadable),
            inspectionFailed: Boolean(info.inspectionFailed)
          });
        }
      }
    }

    return {
      ok: true,
      scopeMode: "working-tree",
      repository: {
        root: repoRoot,
        hasHead
      },
      files: Array.from(fileMap.values())
    };
  } catch (err) {
    return {
      ok: false,
      error: {
        code: "GIT_INSPECTION_FAILED",
        message: err.message || "Failed during Git diff collection"
      }
    };
  }
}

/**
 * Builds an immutable, canonical ChangeSet context package.
 */
export function buildChangeSet(cwd = process.cwd(), options = {}) {
  const state = collectGitWorkingState(cwd, options);
  if (!state.ok) return state;

  const repoRoot = state.repository.root;
  const scopeMode = state.scopeMode || "working-tree";

  let diffText = "";
  try {
    if (scopeMode === "revision-range") {
      diffText = gitExec(repoRoot, ["diff", "-U3", `${state.repository.baseSha}...${state.repository.headSha}`]);
    } else if (scopeMode === "staged") {
      diffText = state.repository.hasHead
        ? gitExec(repoRoot, ["diff", "--cached", "-U3"])
        : gitExec(repoRoot, ["diff-index", "--cached", "-U3", EMPTY_TREE_SHA]);
    } else {
      const stagedPart = state.repository.hasHead
        ? gitExec(repoRoot, ["diff", "--cached", "-U3"])
        : gitExec(repoRoot, ["diff-index", "--cached", "-U3", EMPTY_TREE_SHA]);
      const unstagedPart = gitExec(repoRoot, ["diff", "-U3"]);
      diffText = `${stagedPart}\n${unstagedPart}`.trim();
    }
  } catch (_err) {
    diffText = "";
  }

  const contentDigest = crypto.createHash("sha256").update(diffText, "utf8").digest("hex");

  const files = state.files.map(f => ({
    path: f.path,
    oldPath: f.oldPath || null,
    renamed: Boolean(f.renamed),
    additions: f.additions || 0,
    deletions: f.deletions || 0,
    binary: Boolean(f.binary),
    unreadable: Boolean(f.unreadable || f.inspectionFailed),
    largeFile: Boolean(f.largeFile)
  }));

  const totalAdditions = files.reduce((sum, f) => sum + f.additions, 0);
  const totalDeletions = files.reduce((sum, f) => sum + f.deletions, 0);

  return {
    ok: true,
    schemaVersion: "1.0.0",
    scopeMode,
    repository: state.repository,
    contentDigest,
    totalFiles: files.length,
    totalAdditions,
    totalDeletions,
    files,
    diffHunks: diffText
  };
}
