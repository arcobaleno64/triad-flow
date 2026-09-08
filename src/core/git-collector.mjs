/**
 * Hardened Git Change Collector for Triad-Flow
 * Collects Staged, Unstaged, and Untracked non-ignored files with zero mock fallbacks.
 * Uses authoritative parser from git-numstat.mjs and lstat-safe untracked inspection.
 */

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
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
export function collectGitWorkingState(cwd = process.cwd()) {
  let repoRoot;
  let hasHead = true;

  // 1. Verify directory is inside a real working tree (blocks Bare Repo escape)
  try {
    const isWorkTree = execFileSync("git", ["rev-parse", "--is-inside-work-tree"], {
      cwd,
      ...EXEC_OPTS,
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

    repoRoot = execFileSync("git", ["rev-parse", "--show-toplevel"], {
      cwd,
      ...EXEC_OPTS,
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
    execFileSync("git", ["rev-parse", "--verify", "HEAD"], {
      cwd: repoRoot,
      ...EXEC_OPTS,
      stdio: "ignore"
    });
  } catch (_err) {
    hasHead = false;
  }

  try {
    const fileMap = new Map();

    // 3. Collect Staged Changes
    let stagedRaw = "";
    if (hasHead) {
      stagedRaw = execFileSync("git", ["diff", "--cached", "--numstat", "-z"], {
        cwd: repoRoot,
        ...EXEC_OPTS
      });
    } else {
      stagedRaw = execFileSync("git", ["diff-index", "--cached", "--numstat", "-z", EMPTY_TREE_SHA], {
        cwd: repoRoot,
        ...EXEC_OPTS
      });
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

    // 4. Collect Unstaged Changes (Merge with Staged)
    const unstagedRaw = execFileSync("git", ["diff", "--numstat", "-z"], {
      cwd: repoRoot,
      ...EXEC_OPTS
    });
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

    // 5. Collect Untracked files (excluding ignored files)
    const untrackedRaw = execFileSync("git", ["ls-files", "--others", "--exclude-standard", "-z"], {
      cwd: repoRoot,
      ...EXEC_OPTS
    });

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
