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

const exactHeadContentCache = new Map();

/**
 * Normalizes scope mode string to canonical form (IMP-F05).
 * Rejects unknown or unmapped mode strings fail-closed.
 *
 * @param {string} mode
 * @returns {string}
 */
export function normalizeScopeMode(mode) {
  if (typeof mode !== "string") {
    const err = new Error(`Unknown scope mode: ${mode}`);
    err.code = "UNKNOWN_SCOPE_MODE";
    throw err;
  }
  const trimmed = mode.trim();
  if (trimmed === "revision-range" || trimmed === "revision_range") {
    return "revision_range";
  }
  if (trimmed === "staged") {
    return "staged";
  }
  if (trimmed === "working-tree" || trimmed === "working_tree") {
    return "working_tree";
  }
  if (trimmed === "synthetic") {
    return "synthetic";
  }
  const err = new Error(`Unknown scope mode: ${mode}`);
  err.code = "UNKNOWN_SCOPE_MODE";
  throw err;
}

/**
 * Validates and normalizes path to canonical POSIX Git identity (Spec §2.5).
 * Rejects illegal characters, NUL, control codes, traversals, and absolute roots fail-closed.
 *
 * @param {string} filePath
 * @returns {string}
 */
export function normalizeGitPath(filePath, repoRoot = "") {
  if (typeof filePath !== "string" || !filePath.trim()) {
    const err = new Error(`Illegal path: path must be a non-empty string`);
    err.code = "ILLEGAL_PATH_SECURITY_REJECT";
    throw err;
  }

  // Pre-validation: reject NUL or ASCII control codes 0x01-0x1F
  for (let i = 0; i < filePath.length; i++) {
    const code = filePath.charCodeAt(i);
    if (code === 0 || (code >= 1 && code <= 31)) {
      const err = new Error(`Illegal path contains NUL or control characters: ${JSON.stringify(filePath)}`);
      err.code = "ILLEGAL_PATH_SECURITY_REJECT";
      throw err;
    }
  }

  // Check directory traversal tokens (../ or ..\ or segment ..)
  if (/(^|[\\/])\.\.([\\/]|$)/.test(filePath)) {
    const err = new Error(`Illegal path traversal: ${filePath}`);
    err.code = "ILLEGAL_PATH_SECURITY_REJECT";
    throw err;
  }

  let normalized = filePath.replace(/\\/g, "/");

  // If repoRoot is provided, allow absolute paths that resolve strictly within repoRoot
  if (repoRoot && typeof repoRoot === "string") {
    let normRoot = repoRoot.replace(/\\/g, "/").replace(/\/+$/, "");
    if (normalized.startsWith(normRoot + "/")) {
      normalized = normalized.slice(normRoot.length + 1);
    }
  }

  // Check absolute paths (starts with / or \, or drive letter like C:/ or C:\)
  if (/^[a-zA-Z]:[\\/]/.test(normalized) || normalized.startsWith("/") || normalized.startsWith("\\")) {
    const err = new Error(`Illegal absolute path: ${filePath}`);
    err.code = "ILLEGAL_PATH_SECURITY_REJECT";
    throw err;
  }

  // Strip redundant leading ./
  while (normalized.startsWith("./")) {
    normalized = normalized.slice(2);
  }

  // Strip redundant double slashes
  normalized = normalized.replace(/\/{2,}/g, "/");

  // Strip trailing slashes
  while (normalized.length > 1 && normalized.endsWith("/")) {
    normalized = normalized.slice(0, -1);
  }

  // Re-check traversal or empty after stripping
  if (!normalized || normalized === "." || normalized === "/" || /(^|\/)\.\.($|\/)/.test(normalized)) {
    const err = new Error(`Illegal path resolution: ${filePath}`);
    err.code = "ILLEGAL_PATH_SECURITY_REJECT";
    throw err;
  }

  // Process segments
  const segments = normalized.split("/");
  const cleanSegments = [];
  for (const seg of segments) {
    if (seg === ".") continue;
    if (seg === "..") {
      const err = new Error(`Illegal path traversal: ${filePath}`);
      err.code = "ILLEGAL_PATH_SECURITY_REJECT";
      throw err;
    }
    cleanSegments.push(seg);
  }

  if (cleanSegments.length === 0) {
    const err = new Error(`Illegal empty path after normalization: ${filePath}`);
    err.code = "ILLEGAL_PATH_SECURITY_REJECT";
    throw err;
  }

  normalized = cleanSegments.join("/");

  // Unicode Normalization Form C (NFC)
  normalized = normalized.normalize("NFC");

  return normalized;
}

/**
 * Detects case collisions across canonical paths on case-insensitive filesystems (Spec §2.5).
 * Throws CANONICAL_PATH_COLLISION fail-closed if different paths map to the same lowercase path.
 *
 * @param {Array<string|object>} paths
 * @returns {boolean}
 */
export function detectCaseCollisions(paths) {
  if (!Array.isArray(paths)) return true;
  const seen = new Map();
  for (const p of paths) {
    const raw = typeof p === "string" ? p : (p?.canonicalPath || p?.path || p?.file || "");
    const normalized = normalizeGitPath(raw);
    const lower = normalized.toLowerCase();
    if (seen.has(lower) && seen.get(lower) !== normalized) {
      const err = new Error(`Canonical path case collision detected: '${seen.get(lower)}' vs '${normalized}'`);
      err.code = "CANONICAL_PATH_COLLISION";
      throw err;
    }
    seen.set(lower, normalized);
  }
  return true;
}

/**
 * Collects an authoritative, byte-exact mutation snapshot for a repository working state (Spec §2.2).
 * Computes mutationSnapshotHash binding canonical paths, changeTypes, index and worktree SHA-256s, base blob SHAs, and index tree SHA.
 *
 * @param {string} repoRoot
 * @param {object} [options={}]
 * @returns {object}
 */
export function collectMutationSnapshot(repoRoot, options = {}) {
  const normRepoRoot = path.resolve(repoRoot || process.cwd()).replace(/\\/g, "/");
  const rawMode = options.scopeMode || (options.stagedOnly ? "staged" : (options.base ? "revision_range" : "working_tree"));
  const scopeMode = normalizeScopeMode(rawMode);

  let baseSha = options.baseSha || options.baseCommitSha || null;
  let headSha = options.headSha || null;

  // Resolve commit SHAs if not explicitly given
  if (scopeMode === "revision_range") {
    if (!baseSha && options.base) {
      try {
        baseSha = gitExec(normRepoRoot, ["rev-parse", "--verify", `${options.base}^{commit}`]).trim();
      } catch (_e) {}
    }
    if (!headSha && (options.head || options.headSha)) {
      try {
        headSha = gitExec(normRepoRoot, ["rev-parse", "--verify", `${options.head || options.headSha}^{commit}`]).trim();
      } catch (_e) {}
    }
  } else {
    try {
      baseSha = gitExec(normRepoRoot, ["rev-parse", "--verify", "HEAD^{commit}"], { stdio: ["ignore", "pipe", "ignore"] }).trim();
    } catch (_e) {
      baseSha = null; // unborn repository
    }
    headSha = baseSha;
  }

  // Obtain index tree SHA
  let indexTreeSha = EMPTY_TREE_SHA;
  try {
    indexTreeSha = gitExec(normRepoRoot, ["write-tree"], { stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch (_e) {
    if (baseSha) {
      try {
        indexTreeSha = gitExec(normRepoRoot, ["rev-parse", `${baseSha}^{tree}`], { stdio: ["ignore", "pipe", "ignore"] }).trim();
      } catch (_e2) {
        indexTreeSha = EMPTY_TREE_SHA;
      }
    }
  }

  // Determine file entries to process
  let candidateEntries = [];
  if (Array.isArray(options.files) && options.files.length > 0) {
    candidateEntries = options.files;
  } else {
    const workingState = collectGitWorkingState(normRepoRoot, {
      ...options,
      base: options.base || baseSha,
      head: options.head || headSha,
      scopeMode: scopeMode === "revision_range" ? "revision-range" : (scopeMode === "working_tree" ? "working-tree" : scopeMode)
    });
    if (workingState.ok && Array.isArray(workingState.files)) {
      candidateEntries = workingState.files;
    }
  }

  // Detect case collisions across all candidate files
  detectCaseCollisions(candidateEntries);

  const fileSnapshots = [];
  for (const entry of candidateEntries) {
    const rawPath = typeof entry === "string" ? entry : (entry.path || entry.canonicalPath || entry.file);
    const canonicalPath = normalizeGitPath(rawPath);

    // If entry already carries full pre-computed snapshot fields (e.g. In synthetic tests), preserve them
    if (entry && entry.indexContentSha256 !== undefined && entry.worktreeContentSha256 !== undefined && entry.baseBlobSha !== undefined) {
      const changeType = entry.changeType || (entry.worktreeContentSha256 === "DELETED" ? "D" : (entry.baseBlobSha === "NEW" ? "A" : "M"));
      // S2-F13 Mixed Deletion Collision check
      if (entry.indexContentSha256 === "DELETED" && entry.worktreeContentSha256 !== "DELETED") {
        if (scopeMode === "working_tree") {
          const err = new Error(`Stale or conflicting mutation state: staged deletion collides with worktree file: ${canonicalPath}`);
          err.code = "STALE_OR_CONFLICTING_MUTATION_STATE";
          throw err;
        }
      }

      fileSnapshots.push({
        canonicalPath,
        changeType,
        indexContentSha256: entry.indexContentSha256,
        worktreeContentSha256: entry.worktreeContentSha256,
        baseBlobSha: entry.baseBlobSha
      });
      continue;
    }

    // Determine changeType
    let changeType = "M";
    if (entry.changeType) {
      changeType = entry.changeType;
    } else if (entry.untracked || entry.added) {
      changeType = "A";
    } else if (entry.deleted) {
      changeType = "D";
    } else if (entry.renamed) {
      changeType = "R";
    } else if (entry.copied) {
      changeType = "C";
    } else if (baseSha) {
      let inBase = true;
      try {
        gitExec(normRepoRoot, ["rev-parse", "--verify", `${baseSha}:${canonicalPath}`], {
          stdio: ["ignore", "pipe", "ignore"]
        });
      } catch (_e) {
        inBase = false;
      }
      if (!inBase) {
        changeType = "A";
      }
    }

    // Determine indexContentSha256
    let indexContentSha256 = "UNSTAGED";
    try {
      const lsOut = gitExec(normRepoRoot, ["ls-files", "-s", "-z", "--", canonicalPath], {
        stdio: ["ignore", "pipe", "ignore"]
      }).trim();
      if (lsOut) {
        const match = lsOut.match(/^[0-9]+\s+([0-9a-fA-F]{40,64})\s+[0-9]+/);
        if (match) {
          const blobSha = match[1];
          const blobBuf = gitExec(normRepoRoot, ["cat-file", "-p", blobSha], {
            encoding: "buffer",
            stdio: ["ignore", "pipe", "ignore"],
            maxBuffer: 20 * 1024 * 1024
          });
          indexContentSha256 = crypto.createHash("sha256").update(blobBuf).digest("hex");
        }
      }
    } catch (_e) {}

    // Check if staged for deletion
    if (entry.staged && changeType === "D") {
      indexContentSha256 = "DELETED";
    }

    // Determine worktreeContentSha256
    let worktreeContentSha256 = "DELETED";
    const fullPhysicalPath = path.join(normRepoRoot, canonicalPath);
    try {
      const st = fs.lstatSync(fullPhysicalPath);
      if (st.isFile()) {
        const fileBuf = fs.readFileSync(fullPhysicalPath);
        worktreeContentSha256 = crypto.createHash("sha256").update(fileBuf).digest("hex");
      }
    } catch (_e) {
      worktreeContentSha256 = "DELETED";
    }

    // Determine baseBlobSha
    let baseBlobSha = "NEW";
    if (changeType === "A" && !entry.modified) {
      baseBlobSha = "NEW";
      if (baseSha) {
        try {
          const existingBlob = gitExec(normRepoRoot, ["rev-parse", "--verify", `${baseSha}:${canonicalPath}`], {
            stdio: ["ignore", "pipe", "ignore"]
          }).trim();
          if (existingBlob) {
            const err = new Error(`Mutation semantics mismatch: added file '${canonicalPath}' already exists in base tree '${baseSha}'`);
            err.code = "MUTATION_SEMANTICS_MISMATCH";
            throw err;
          }
        } catch (checkErr) {
          if (checkErr.code === "MUTATION_SEMANTICS_MISMATCH") throw checkErr;
        }
      }
    } else if (baseSha) {
      try {
        baseBlobSha = gitExec(normRepoRoot, ["rev-parse", "--verify", `${baseSha}:${canonicalPath}`], {
          stdio: ["ignore", "pipe", "ignore"]
        }).trim();
      } catch (_e) {
        if (changeType === "M") {
          const err = new Error(`Base blob provenance unavailable for modified file: ${canonicalPath}`);
          err.code = "PROVENANCE_UNAVAILABLE";
          throw err;
        }
        if (changeType === "D") {
          const err = new Error(`Mutation semantics mismatch: deleted file '${canonicalPath}' does not exist in base tree '${baseSha}'`);
          err.code = "MUTATION_SEMANTICS_MISMATCH";
          throw err;
        }
        baseBlobSha = "NEW";
      }
    } else {
      baseBlobSha = "NEW";
    }

    // S2-F13 Mixed Deletion Collision check
    if (indexContentSha256 === "DELETED" && worktreeContentSha256 !== "DELETED") {
      if (scopeMode === "working_tree") {
        const err = new Error(`Stale or conflicting mutation state: staged deletion collides with worktree file: ${canonicalPath}`);
        err.code = "STALE_OR_CONFLICTING_MUTATION_STATE";
        throw err;
      }
    }

    fileSnapshots.push({
      canonicalPath,
      changeType,
      indexContentSha256,
      worktreeContentSha256,
      baseBlobSha
    });
  }

  // Sort canonically by canonicalPath POSIX order
  fileSnapshots.sort((a, b) => (a.canonicalPath < b.canonicalPath ? -1 : a.canonicalPath > b.canonicalPath ? 1 : 0));

  // Compute authoritative mutationSnapshotHash
  const lines = fileSnapshots.map(f =>
    [f.canonicalPath, f.changeType, f.indexContentSha256, f.worktreeContentSha256, f.baseBlobSha].join(":")
  );
  const payload = lines.join("\n") + "\n" + indexTreeSha;
  const mutationSnapshotHash = crypto.createHash("sha256").update(payload, "utf8").digest("hex");

  return {
    mutationSnapshotHash,
    snapshotHash: mutationSnapshotHash,
    scopeMode,
    indexTreeSha,
    baseSha,
    headSha,
    files: fileSnapshots
  };
}

/**
 * Safely extracts file content at a specific Git commit SHA without touching the working tree.
 * Enforces strict exact-head invariant (Spec §3.3.1).
 * Caches content in memory keyed on `${headSha}:${filePath}`.
 *
 * @param {string} repoRoot - Absolute repository root path
 * @param {string} headSha - Commit SHA (40 or 64 hex characters)
 * @param {string} filePath - Path of file relative to repository root
 * @returns {string|null} File content string or null if unresolvable / non-existent
 */
export function getExactHeadFileContent(repoRoot, headSha, filePath) {
  if (!repoRoot || !headSha || !filePath) return null;
  const normPath = filePath.replace(/\\/g, "/").replace(/^\.\//, "");
  const normSha = String(headSha).trim();
  if (!/^[0-9a-fA-F]{40,64}$/.test(normSha)) return null;

  const normRepo = path.resolve(repoRoot).replace(/\\/g, "/");
  const cacheKey = `${normRepo}:${normSha}:${normPath}`;
  if (exactHeadContentCache.has(cacheKey)) {
    return exactHeadContentCache.get(cacheKey);
  }

  try {
    const content = gitExec(repoRoot, ["show", `${normSha}:${normPath}`], {
      stdio: ["ignore", "pipe", "ignore"],
      maxBuffer: 10 * 1024 * 1024
    });
    exactHeadContentCache.set(cacheKey, content);
    return content;
  } catch (_err) {
    exactHeadContentCache.set(cacheKey, null);
    return null;
  }
}

/**
 * Clears the in-memory exact-head file content cache.
 */
export function clearExactHeadCache() {
  exactHeadContentCache.clear();
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

  // Reject conflicting options (--staged with revision-range)
  if ((options.stagedOnly || options.staged) && (options.base || options.head)) {
    return {
      ok: false,
      error: {
        code: "CONFLICTING_OPTIONS",
        message: "Cannot specify both staged and revision-range options."
      }
    };
  }

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
  let headSha = null;
  try {
    headSha = gitExec(repoRoot, ["rev-parse", "--verify", "HEAD^{commit}"], {
      stdio: ["ignore", "pipe", "ignore"]
    }).trim();
  } catch (_err) {
    hasHead = false;
    headSha = null;
  }

  // 3. Revision Range Mode (--base / --head)
  if (options.base || options.baseSha) {
    const baseRef = options.base || options.baseSha;
    let baseSha;
    try {
      baseSha = gitExec(repoRoot, ["rev-parse", "--verify", `${baseRef}^{commit}`]).trim();
    } catch (_err) {
      return {
        ok: false,
        error: {
          code: "INVALID_BASE_REF",
          message: `Base reference '${baseRef}' is invalid or cannot be resolved.`
        }
      };
    }

    const headRef = options.head || options.headSha || "HEAD";
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
          hasHead,
          ...(headSha ? { headSha } : {})
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

    const isUncommittedScope = !options.base;
    const computedScopeMode = options.scopeMode || (options.stagedOnly ? "staged" : "working-tree");
    return {
      ok: true,
      scopeMode: computedScopeMode,
      repository: {
        root: repoRoot,
        hasHead,
        ...(hasHead && headSha ? { baseCommitSha: headSha } : {}),
        ...(!isUncommittedScope && headSha ? { headSha } : {})
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
  } catch (err) {
    return {
      ok: false,
      error: {
        code: "DIFF_EXTRACTION_FAILED",
        message: err.message || "Failed to extract Git diff"
      }
    };
  }

  // Include safe readable text untracked files in diffHunks and contentDigest
  const diffHunksList = diffText ? [diffText] : [];
  if (scopeMode === "working-tree") {
    for (const f of state.files) {
      if (f.untracked && !f.binary && !f.largeFile && !f.unreadable && !f.inspectionFailed && !f.symlink) {
        const fullPath = path.join(repoRoot, f.path);
        try {
          const content = fs.readFileSync(fullPath, "utf8");
          const cleanContent = content.replace(/\r?\n$/, "");
          const lines = cleanContent.length > 0 ? cleanContent.split(/\r?\n/) : [];
          const normPath = f.path.replace(/\\/g, "/");
          const synthesized = [
            `--- /dev/null`,
            `+++ b/${normPath}`,
            `@@ -0,0 +1,${lines.length} @@`,
            ...lines.map(l => `+${l}`)
          ].join("\n");
          diffHunksList.push(synthesized);
        } catch (_err) {
          f.unreadable = true;
        }
      }
    }
  }

  const finalDiffHunks = diffHunksList.filter(Boolean).join("\n").trim();
  const contentDigest = crypto.createHash("sha256").update(finalDiffHunks, "utf8").digest("hex");

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

  const isUncommitted = scopeMode === "working-tree" || scopeMode === "staged";
  return {
    ok: true,
    schemaVersion: "1.0.0",
    scopeMode,
    repository: state.repository,
    ...(isUncommitted
      ? (state.repository?.baseCommitSha ? { baseCommitSha: state.repository.baseCommitSha } : {})
      : (state.repository?.headSha ? { headSha: state.repository.headSha } : {})),
    ...(isUncommitted ? { contentIdentity: `${scopeMode}:${contentDigest}` } : {}),
    contentDigest,
    totalFiles: files.length,
    totalAdditions,
    totalDeletions,
    files,
    diffHunks: finalDiffHunks
  };
}
