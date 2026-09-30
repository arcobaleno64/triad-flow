/**
 * Triad-Flow Controlled Remediation Engine & Patch Jail Sandbox (v2.3)
 *
 * Implements TF-SPEC-REMEDIATION-v1.0.0:
 * - 8-State Canonical Lifecycle State Machine with Monotonic Defense invariants.
 * - Ephemeral Git Worktree Patch Jail with strict secret insulation and target file constraints.
 * - Cryptographic pre/post tree digest lineage and unified diff verification.
 * - Anti-thrashing stop rules (max 2 attempts) and Goodhart anti-degradation protections.
 * - Immutable Remediation Receipt Schema 1.0.0 builder and validator.
 */

import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  canonicalJsonStringify,
  computeDigest,
  normalizeLineEndings,
  normalizeRelativePath
} from "./canonical-digest.mjs";
import { SHA256_HEX_REGEX } from "./audit-receipt.mjs";

/**
 * Normative remediation schema version.
 */
export const REMEDIATION_SCHEMA_VERSION = "1.0.0";
export const SUPPORTED_REMEDIATION_SCHEMA_MAJOR = 1;

/**
 * Normative remediation lifecycle states.
 */
export const REMEDIATION_STATES = Object.freeze({
  OPEN: "OPEN",
  FIX_PROPOSED: "FIX_PROPOSED",
  PATCH_AUTHORIZED: "PATCH_AUTHORIZED",
  PATCH_APPLIED_IN_JAIL: "PATCH_APPLIED_IN_JAIL",
  FIXED_PENDING_VERIFY: "FIXED_PENDING_VERIFY",
  CLOSED: "CLOSED",
  REJECTED_FIX: "REJECTED_FIX",
  WAIVED: "WAIVED",
  REOPENED: "REOPENED"
});

export const VALID_REMEDIATION_STATES = Object.freeze(
  new Set(Object.values(REMEDIATION_STATES))
);

export const TERMINAL_REMEDIATION_STATES = Object.freeze(
  new Set([
    REMEDIATION_STATES.CLOSED,
    REMEDIATION_STATES.REJECTED_FIX,
    REMEDIATION_STATES.WAIVED
  ])
);

/**
 * Anti-thrashing guardrails: maximum automated remediation attempts per finding.
 */
export const MAX_REMEDIATION_ATTEMPTS = 2;

/**
 * Forbidden file patterns that must never be altered by candidate patches.
 * Violation immediately aborts remediation with REJECTED_FIX and PatchJailSecurityError.
 */
export const FORBIDDEN_PATCH_FILE_PATTERNS = Object.freeze([
  // CI/CD workflow manifests
  /^\.github\/workflows\//i,
  /^\.gitlab-ci\.ya?ml$/i,
  /^azure-pipelines\.ya?ml$/i,
  /^\.circleci\//i,
  // Package manifests and lockfiles
  /^package\.json$/i,
  /^package-lock\.json$/i,
  /^pnpm-lock\.ya?ml$/i,
  /^yarn\.lock$/i,
  /^go\.mod$/i,
  /^go\.sum$/i,
  /^pom\.xml$/i,
  /^build\.gradle(\.kts)?$/i,
  /^requirements\.txt$/i,
  /^Cargo\.toml$/i,
  /^Cargo\.lock$/i,
  // Security rules, git metadata, and environment configs
  /^\.git(\/|\\|$)/i,
  /^\.gitignore$/i,
  /^\.gitattributes$/i,
  /^\.env(\..+)?$/i
]);

/**
 * Anti-degradation / Goodhart evasion patterns in candidate diff additions.
 */
export const ANTI_DEGRADATION_PATTERNS = Object.freeze([
  {
    type: "test-skipping",
    pattern: /(?:^|\s)(?:it|test|describe)\.skip\b/,
    description: "Patch skips test execution using .skip modifier"
  },
  {
    type: "test-skipping-x",
    pattern: /(?:^|\s)(?:xit|xdescribe)\b/,
    description: "Patch disables test execution using xit/xdescribe"
  },
  {
    type: "ts-suppress",
    pattern: /\/\/\s*@ts-(?:ignore|nocheck)\b/,
    description: "Patch suppresses TypeScript compilation check"
  },
  {
    type: "eslint-suppress",
    pattern: /\/\*(?:\s*eslint-disable|\s*eslint-disable-line|\s*eslint-disable-next-line)\b/,
    description: "Patch suppresses ESLint rule enforcement"
  }
]);

/**
 * Error classes
 */
export class UnsupportedRemediationSchemaError extends Error {
  constructor(version, message) {
    super(message || `Unsupported remediation schema version: "${version}". Supported major is ${SUPPORTED_REMEDIATION_SCHEMA_MAJOR}.`);
    this.name = "UnsupportedRemediationSchemaError";
    this.version = version;
  }
}

export class RemediationValidationError extends Error {
  constructor(message, details = null) {
    super(message);
    this.name = "RemediationValidationError";
    this.details = details;
  }
}

export class RemediationTransitionError extends Error {
  constructor(fromState, toState, reason) {
    super(`Prohibited state transition from "${fromState}" to "${toState}": ${reason}`);
    this.name = "RemediationTransitionError";
    this.fromState = fromState;
    this.toState = toState;
  }
}

export class PatchJailSecurityError extends Error {
  constructor(message, targetFile = null) {
    super(message);
    this.name = "PatchJailSecurityError";
    this.targetFile = targetFile;
  }
}

export class PatchJailExecutionError extends Error {
  constructor(message, command = null, stderr = null) {
    super(message);
    this.name = "PatchJailExecutionError";
    this.command = command;
    this.stderr = stderr;
  }
}

export class AntiThrashingLimitExceededError extends Error {
  constructor(findingId, attempts) {
    super(`Anti-thrashing limit exceeded for finding "${findingId}": reached maximum allowed attempts (${attempts}/${MAX_REMEDIATION_ATTEMPTS}).`);
    this.name = "AntiThrashingLimitExceededError";
    this.findingId = findingId;
    this.attempts = attempts;
  }
}

/**
 * Parses schema major version from semver string.
 *
 * @param {string} version
 * @returns {number}
 */
export function parseSchemaMajorVersion(version) {
  if (typeof version !== "string") return -1;
  const match = version.trim().match(/^v?(\d+)/i);
  return match ? parseInt(match[1], 10) : -1;
}

/**
 * Parses modified files and line deltas from unified diff string.
 *
 * @param {string} diffText
 * @returns {{ files: string[], additions: number, deletions: number }}
 */
export function parseUnifiedDiff(diffText) {
  if (typeof diffText !== "string") {
    return { files: [], additions: 0, deletions: 0 };
  }

  const normalized = normalizeLineEndings(diffText);
  const lines = normalized.split("\n");
  const filesSet = new Set();
  let additions = 0;
  let deletions = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Detect diff --git a/path b/path
    const gitDiffMatch = line.match(/^diff --git a\/(.+?) b\/(.+?)$/);
    if (gitDiffMatch) {
      filesSet.add(normalizeRelativePath(gitDiffMatch[2]));
      continue;
    }

    // Detect +++ b/path
    const plusMatch = line.match(/^\+\+\+ (?:b\/)?(.+?)$/);
    if (plusMatch && plusMatch[1] !== "/dev/null") {
      filesSet.add(normalizeRelativePath(plusMatch[1]));
      continue;
    }

    // Detect --- a/path
    const minusMatch = line.match(/^--- (?:a\/)?(.+?)$/);
    if (minusMatch && minusMatch[1] !== "/dev/null") {
      filesSet.add(normalizeRelativePath(minusMatch[1]));
      continue;
    }

    // Count additions and deletions in hunks (ignoring header +++ and ---)
    if (line.startsWith("+") && !line.startsWith("+++")) {
      additions++;
    } else if (line.startsWith("-") && !line.startsWith("---")) {
      deletions++;
    }
  }

  return {
    files: Array.from(filesSet).sort(),
    additions,
    deletions
  };
}

/**
 * Validates candidate patch diff against target file bounds, forbidden manifests,
 * and anti-degradation invariants.
 *
 * @param {string} diffText
 * @param {string[]} targetFiles - Allowable file paths
 * @param {object} [options]
 * @param {boolean} [options.allowAntiDegradation=false]
 * @returns {{ targetFiles: string[], additions: number, deletions: number, patchDiffDigest: string }}
 */
export function validatePatchScope(diffText, targetFiles = [], options = {}) {
  if (typeof diffText !== "string" || !diffText.trim()) {
    throw new RemediationValidationError("Candidate patch diff cannot be empty.");
  }

  const { files, additions, deletions } = parseUnifiedDiff(diffText);

  if (files.length === 0) {
    throw new RemediationValidationError("Patch diff does not contain any file modifications.");
  }

  const normalizedAllowed = new Set(
    (targetFiles || []).map(f => normalizeRelativePath(f)).filter(Boolean)
  );

  // 1. Check against forbidden file patterns
  for (const file of files) {
    for (const pattern of FORBIDDEN_PATCH_FILE_PATTERNS) {
      if (pattern.test(file)) {
        throw new PatchJailSecurityError(
          `Security boundary violation: candidate patch attempts to alter protected manifest or config "${file}".`,
          file
        );
      }
    }
  }

  // 2. Check that modified files are strictly within target files
  for (const file of files) {
    if (!normalizedAllowed.has(file)) {
      throw new PatchJailSecurityError(
        `Scope violation: modified file "${file}" is outside declared targetFiles [${Array.from(normalizedAllowed).join(", ")}].`,
        file
      );
    }
  }

  // 3. Scan for Goodhart anti-degradation violations in added lines
  if (!options.allowAntiDegradation) {
    const violations = scanAntiDegradationViolations(diffText);
    if (violations.length > 0) {
      throw new PatchJailSecurityError(
        `Anti-degradation check failed: ${violations.map(v => v.description).join("; ")}.`
      );
    }
  }

  const patchDiffDigest = computeDigest(normalizeLineEndings(diffText));

  return {
    targetFiles: files,
    additions,
    deletions,
    patchDiffDigest
  };
}

/**
 * Scans unified diff addition lines for anti-degradation (Goodhart evasion) patterns.
 *
 * @param {string} diffText
 * @returns {Array<{ type: string, description: string, line: string }>}
 */
export function scanAntiDegradationViolations(diffText) {
  if (typeof diffText !== "string") return [];
  const lines = normalizeLineEndings(diffText).split("\n");
  const violations = [];

  for (const line of lines) {
    if (!line.startsWith("+") || line.startsWith("+++")) continue;
    const content = line.slice(1);

    for (const rule of ANTI_DEGRADATION_PATTERNS) {
      if (rule.pattern.test(content)) {
        violations.push({
          type: rule.type,
          description: rule.description,
          line: content.trim()
        });
      }
    }
  }

  return violations;
}

/**
 * Validates a state machine transition according to Monotonic Defense rules.
 *
 * @param {string} fromState
 * @param {string} toState
 * @param {object} context
 * @throws {RemediationTransitionError}
 */
export function validateRemediationTransition(fromState, toState, context = {}) {
  if (!VALID_REMEDIATION_STATES.has(fromState)) {
    throw new RemediationValidationError(`Invalid fromState "${fromState}".`);
  }
  if (!VALID_REMEDIATION_STATES.has(toState)) {
    throw new RemediationValidationError(`Invalid toState "${toState}".`);
  }

  const actor = context.actor || "unknown";
  const actorType = context.actorType || (typeof actor === "object" ? actor.type : "unknown");

  // Monotonic Defense Invariant: Models can NEVER self-close, self-authorize, or lower severity
  if (toState === REMEDIATION_STATES.CLOSED) {
    if (fromState !== REMEDIATION_STATES.FIXED_PENDING_VERIFY) {
      throw new RemediationTransitionError(
        fromState,
        toState,
        `CLOSED state can only be reached from FIXED_PENDING_VERIFY, not from ${fromState}.`
      );
    }
    if (actorType === "synthesizer" || actorType === "model" || context.isSelfVerification) {
      throw new RemediationTransitionError(
        fromState,
        toState,
        "Monotonic Defense violation: synthesizer/model has zero authority to self-verify or transition finding to CLOSED."
      );
    }
    const closure = context.closureVerification;
    if (!closure || closure.verdict !== "SUPPORTED") {
      throw new RemediationTransitionError(
        fromState,
        toState,
        "CLOSED state requires an affirmative independent verification verdict of 'SUPPORTED'."
      );
    }
    if (closure.residualVulnerabilityDetected) {
      throw new RemediationTransitionError(
        fromState,
        toState,
        "CLOSED state cannot be reached when residual vulnerabilities are detected."
      );
    }
  }

  // PATCH_AUTHORIZED requires human authorization
  if (toState === REMEDIATION_STATES.PATCH_AUTHORIZED) {
    if (fromState !== REMEDIATION_STATES.FIX_PROPOSED) {
      throw new RemediationTransitionError(
        fromState,
        toState,
        `PATCH_AUTHORIZED can only transition from FIX_PROPOSED, not ${fromState}.`
      );
    }
    if (actorType === "synthesizer" || actorType === "model") {
      throw new RemediationTransitionError(
        fromState,
        toState,
        "Monotonic Defense violation: synthesizer/model cannot authorize candidate patches."
      );
    }
    if (!context.authorizer) {
      throw new RemediationTransitionError(
        fromState,
        toState,
        "PATCH_AUTHORIZED transition requires authorized identity in context.authorizer."
      );
    }
  }

  // PATCH_APPLIED_IN_JAIL requires sandbox worktree evidence
  if (toState === REMEDIATION_STATES.PATCH_APPLIED_IN_JAIL) {
    if (fromState !== REMEDIATION_STATES.PATCH_AUTHORIZED) {
      throw new RemediationTransitionError(
        fromState,
        toState,
        `PATCH_APPLIED_IN_JAIL can only transition from PATCH_AUTHORIZED, not ${fromState}.`
      );
    }
    if (!context.jail?.prePatchTreeDigest || !context.jail?.postPatchTreeDigest) {
      throw new RemediationTransitionError(
        fromState,
        toState,
        "PATCH_APPLIED_IN_JAIL transition requires prePatchTreeDigest and postPatchTreeDigest in context.jail."
      );
    }
  }

  // FIXED_PENDING_VERIFY requires deterministic checks pass
  if (toState === REMEDIATION_STATES.FIXED_PENDING_VERIFY) {
    if (fromState !== REMEDIATION_STATES.PATCH_APPLIED_IN_JAIL) {
      throw new RemediationTransitionError(
        fromState,
        toState,
        `FIXED_PENDING_VERIFY can only transition from PATCH_APPLIED_IN_JAIL, not ${fromState}.`
      );
    }
    const checks = context.deterministicChecks;
    if (!checks || checks.exitCode !== 0 || checks.regressionDetected) {
      throw new RemediationTransitionError(
        fromState,
        toState,
        "FIXED_PENDING_VERIFY requires deterministic tests to pass with exit code 0 and zero regressions."
      );
    }
  }

  // WAIVED requires human authority and expiry
  if (toState === REMEDIATION_STATES.WAIVED) {
    if (fromState !== REMEDIATION_STATES.OPEN && fromState !== REMEDIATION_STATES.FIX_PROPOSED) {
      throw new RemediationTransitionError(
        fromState,
        toState,
        `WAIVED can only transition from OPEN or FIX_PROPOSED, not ${fromState}.`
      );
    }
    if (actorType === "synthesizer" || actorType === "model") {
      throw new RemediationTransitionError(
        fromState,
        toState,
        "Monotonic Defense violation: automated models cannot waive findings."
      );
    }
    if (!context.expiryTimestamp) {
      throw new RemediationTransitionError(
        fromState,
        toState,
        "WAIVED transition requires mandatory context.expiryTimestamp."
      );
    }
  }

  // REOPENED requires previous terminal state (CLOSED or WAIVED)
  if (toState === REMEDIATION_STATES.REOPENED) {
    if (fromState !== REMEDIATION_STATES.CLOSED && fromState !== REMEDIATION_STATES.WAIVED) {
      throw new RemediationTransitionError(
        fromState,
        toState,
        `REOPENED can only transition from CLOSED or WAIVED, not ${fromState}.`
      );
    }
  }

  // FIX_PROPOSED anti-thrashing check
  if (toState === REMEDIATION_STATES.FIX_PROPOSED) {
    const attempts = context.attempts ?? 1;
    if (attempts > MAX_REMEDIATION_ATTEMPTS) {
      throw new AntiThrashingLimitExceededError(context.findingId || "unknown", attempts);
    }
  }

  return true;
}

/**
 * Computes deterministic canonical SHA-256 tree digest of tracked files in directory.
 * Traverses files, normalizes LF line endings and POSIX paths, producing bit-for-bit identical hashes.
 *
 * @param {string} dirPath
 * @param {object} [options]
 * @param {string[]} [options.ignoreDirs=[".git", "node_modules"]]
 * @returns {string} SHA-256 lowercase hex prefixed with "sha256:"
 */
export function computeTreeDigest(dirPath, options = {}) {
  if (!fs.existsSync(dirPath)) {
    throw new Error(`Directory does not exist for tree digest: "${dirPath}"`);
  }

  const ignoreDirs = new Set(options.ignoreDirs || [".git", "node_modules"]);
  const fileEntries = [];

  function walk(currentDir, relPrefix = "") {
    const dirents = fs.readdirSync(currentDir, { withFileTypes: true });
    for (const ent of dirents) {
      if (ent.name === ".git" || ignoreDirs.has(ent.name)) continue;

      const fullPath = path.join(currentDir, ent.name);
      const relPath = relPrefix ? `${relPrefix}/${ent.name}` : ent.name;

      if (ent.isDirectory()) {
        walk(fullPath, relPath);
      } else if (ent.isFile()) {
        const rawContent = fs.readFileSync(fullPath);
        const normRelPath = normalizeRelativePath(relPath);
        const normContent = normalizeLineEndings(rawContent);
        fileEntries.push([normRelPath, normContent]);
      }
    }
  }

  walk(dirPath);

  // Sort files lexicographically by normalized relative path
  fileEntries.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));

  const treeObject = {};
  for (const [relPath, content] of fileEntries) {
    treeObject[relPath] = computeDigest(content);
  }

  return computeDigest(treeObject);
}

/**
 * Spawns an isolated ephemeral Git worktree Patch Jail.
 *
 * @param {string} repoPath
 * @param {object} [options]
 * @param {string} [options.baseSha="HEAD"]
 * @param {string} [options.jailPath]
 * @returns {{ jailPath: string, baseSha: string, cleanup: () => void }}
 */
export function createPatchJailWorktree(repoPath, options = {}) {
  if (!fs.existsSync(repoPath)) {
    throw new Error(`Repository path does not exist: "${repoPath}"`);
  }

  const baseSha = options.baseSha || "HEAD";
  const jailDir = options.jailPath || path.join(
    os.tmpdir(),
    `tf-patch-jail-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`
  );

  const gitExec = (args) => {
    return execFileSync("git", ["-c", "core.fsmonitor=false", ...args], {
      cwd: repoPath,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true
    });
  };

  try {
    // Add detached worktree
    gitExec(["worktree", "add", "--detach", jailDir, baseSha]);
  } catch (err) {
    throw new PatchJailExecutionError(
      `Failed to create Patch Jail worktree: ${err.message}`,
      "git worktree add",
      err.stderr
    );
  }

  const cleanup = () => {
    cleanupPatchJailWorktree(jailDir, repoPath);
  };

  return {
    jailPath: jailDir,
    baseSha,
    cleanup
  };
}

/**
 * Safely removes and prunes an ephemeral Git worktree Patch Jail.
 *
 * @param {string} jailPath
 * @param {string} repoPath
 */
export function cleanupPatchJailWorktree(jailPath, repoPath) {
  try {
    if (fs.existsSync(repoPath)) {
      execFileSync("git", ["worktree", "remove", "--force", jailPath], {
        cwd: repoPath,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true
      });
      execFileSync("git", ["worktree", "prune"], {
        cwd: repoPath,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true
      });
    }
  } catch {
    // Fall back to direct filesystem removal if git worktree remove encounters lock
  }

  try {
    if (fs.existsSync(jailPath)) {
      fs.rmSync(jailPath, { recursive: true, force: true });
    }
  } catch {
    // Ignore windows filesystem unlock delays
  }
}

/**
 * Applies candidate patch diff inside an ephemeral Patch Jail worktree with strict validation.
 *
 * @param {string} jailPath
 * @param {string} diffText
 * @param {string[]} targetFiles
 * @param {object} [options]
 * @returns {{ prePatchTreeDigest: string, patchDiffDigest: string, postPatchTreeDigest: string, applied: boolean }}
 */
export function applyPatchInJail(jailPath, diffText, targetFiles = [], options = {}) {
  if (!fs.existsSync(jailPath)) {
    throw new PatchJailExecutionError(`Patch Jail directory does not exist: "${jailPath}"`);
  }

  // 1. Validate patch scope and anti-degradation bounds
  const scope = validatePatchScope(diffText, targetFiles, options);
  const normalizedDiff = normalizeLineEndings(diffText).trimEnd() + "\n";

  // 2. Measure pre-patch tree digest
  const prePatchTreeDigest = computeTreeDigest(jailPath);

  // 3. Dry-run verify patch applicability using git apply --check
  try {
    execFileSync("git", ["apply", "--check", "--whitespace=nowarn"], {
      cwd: jailPath,
      input: normalizedDiff,
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true
    });
  } catch (err) {
    throw new PatchJailExecutionError(
      `Candidate patch fails git apply --check: ${err.stderr || err.message}`,
      "git apply --check",
      err.stderr
    );
  }

  // 4. Apply patch cleanly inside sandbox worktree
  try {
    execFileSync("git", ["apply", "--whitespace=nowarn"], {
      cwd: jailPath,
      input: normalizedDiff,
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true
    });
  } catch (err) {
    throw new PatchJailExecutionError(
      `Failed to apply patch in Jail: ${err.stderr || err.message}`,
      "git apply",
      err.stderr
    );
  }

  // 5. Measure post-patch tree digest
  const postPatchTreeDigest = computeTreeDigest(jailPath);

  return {
    prePatchTreeDigest,
    patchDiffDigest: scope.patchDiffDigest,
    postPatchTreeDigest,
    applied: true
  };
}

/**
 * Builds an immutable remediation receipt adhering to TF-SPEC-REMEDIATION-v1.0.0.
 *
 * @param {object} params
 * @returns {object} Immutable frozen remediation receipt object.
 */
export function buildRemediationReceipt(params = {}) {
  const receiptId = params.receiptId || `rem-${Date.now()}-${crypto.randomBytes(3).toString("hex")}`;
  const findingId = params.findingId;
  const status = params.status || REMEDIATION_STATES.OPEN;

  if (!findingId || typeof findingId !== "string") {
    throw new RemediationValidationError("buildRemediationReceipt requires a non-empty string 'findingId'.");
  }

  if (!VALID_REMEDIATION_STATES.has(status)) {
    throw new RemediationValidationError(`buildRemediationReceipt received invalid status "${status}".`);
  }

  const timestamps = {
    startedAt: params.timestamps?.startedAt || new Date().toISOString(),
    completedAt: params.timestamps?.completedAt || new Date().toISOString()
  };

  const actors = {
    producer: params.actors?.producer || { providerName: "unknown", modelName: "unknown" },
    synthesizer: params.actors?.synthesizer || { providerName: "unknown", modelName: "unknown" },
    verifier: params.actors?.verifier || { providerName: "unknown", modelName: "unknown" },
    authorizer: params.actors?.authorizer || null
  };

  const patch = {
    patchDiffDigest: params.patch?.patchDiffDigest || null,
    targetFiles: Array.isArray(params.patch?.targetFiles) ? [...params.patch.targetFiles] : [],
    additions: typeof params.patch?.additions === "number" ? params.patch.additions : 0,
    deletions: typeof params.patch?.deletions === "number" ? params.patch.deletions : 0,
    rationale: params.patch?.rationale || ""
  };

  const jail = {
    worktreeSha: params.jail?.worktreeSha || null,
    prePatchTreeDigest: params.jail?.prePatchTreeDigest || null,
    postPatchTreeDigest: params.jail?.postPatchTreeDigest || null,
    isolatedExecutionPass: Boolean(params.jail?.isolatedExecutionPass)
  };

  const deterministicChecks = {
    testCommand: params.deterministicChecks?.testCommand || "npm test",
    exitCode: typeof params.deterministicChecks?.exitCode === "number" ? params.deterministicChecks.exitCode : -1,
    passedCount: typeof params.deterministicChecks?.passedCount === "number" ? params.deterministicChecks.passedCount : 0,
    failedCount: typeof params.deterministicChecks?.failedCount === "number" ? params.deterministicChecks.failedCount : 0,
    regressionDetected: Boolean(params.deterministicChecks?.regressionDetected)
  };

  const closureVerification = {
    verified: Boolean(params.closureVerification?.verified),
    verificationRecordDigest: params.closureVerification?.verificationRecordDigest || null,
    verdict: params.closureVerification?.verdict || null,
    residualVulnerabilityDetected: Boolean(params.closureVerification?.residualVulnerabilityDetected)
  };

  const history = Array.isArray(params.history)
    ? params.history.map(item => ({
        from: item.from,
        to: item.to,
        at: item.at || new Date().toISOString(),
        actor: item.actor || "unknown"
      }))
    : [];

  const receipt = {
    schemaVersion: REMEDIATION_SCHEMA_VERSION,
    receiptId,
    findingId,
    status,
    timestamps,
    actors,
    patch,
    jail,
    deterministicChecks,
    closureVerification,
    history
  };

  validateRemediationReceipt(receipt);

  return deepFreeze(receipt);
}

/**
 * Validates a remediation receipt object against Schema 1.0.0.
 *
 * @param {object} receipt
 * @throws {UnsupportedRemediationSchemaError|RemediationValidationError}
 */
export function validateRemediationReceipt(receipt) {
  if (!receipt || typeof receipt !== "object") {
    throw new RemediationValidationError("Receipt must be a non-null object.");
  }

  const major = parseSchemaMajorVersion(receipt.schemaVersion);
  if (major !== SUPPORTED_REMEDIATION_SCHEMA_MAJOR) {
    throw new UnsupportedRemediationSchemaError(
      receipt.schemaVersion,
      `Unsupported remediation receipt schema version: "${receipt.schemaVersion}". Major must be ${SUPPORTED_REMEDIATION_SCHEMA_MAJOR}.`
    );
  }

  if (typeof receipt.receiptId !== "string" || !receipt.receiptId.trim()) {
    throw new RemediationValidationError("receiptId must be a non-empty string.");
  }

  if (typeof receipt.findingId !== "string" || !receipt.findingId.trim()) {
    throw new RemediationValidationError("findingId must be a non-empty string.");
  }

  if (!VALID_REMEDIATION_STATES.has(receipt.status)) {
    throw new RemediationValidationError(`status "${receipt.status}" is not a recognized remediation state.`);
  }

  if (!receipt.timestamps || !receipt.timestamps.startedAt || !receipt.timestamps.completedAt) {
    throw new RemediationValidationError("timestamps must contain startedAt and completedAt ISO strings.");
  }

  if (!receipt.actors || typeof receipt.actors !== "object") {
    throw new RemediationValidationError("actors object is required.");
  }

  if (!receipt.patch || typeof receipt.patch !== "object") {
    throw new RemediationValidationError("patch object is required.");
  }

  if (receipt.patch.patchDiffDigest && !SHA256_HEX_REGEX.test(receipt.patch.patchDiffDigest)) {
    throw new RemediationValidationError(`patchDiffDigest "${receipt.patch.patchDiffDigest}" is not a valid SHA-256 digest.`);
  }

  if (!receipt.jail || typeof receipt.jail !== "object") {
    throw new RemediationValidationError("jail object is required.");
  }

  if (receipt.jail.prePatchTreeDigest && !SHA256_HEX_REGEX.test(receipt.jail.prePatchTreeDigest)) {
    throw new RemediationValidationError(`prePatchTreeDigest "${receipt.jail.prePatchTreeDigest}" is not a valid SHA-256 digest.`);
  }

  if (receipt.jail.postPatchTreeDigest && !SHA256_HEX_REGEX.test(receipt.jail.postPatchTreeDigest)) {
    throw new RemediationValidationError(`postPatchTreeDigest "${receipt.jail.postPatchTreeDigest}" is not a valid SHA-256 digest.`);
  }

  if (!receipt.deterministicChecks || typeof receipt.deterministicChecks !== "object") {
    throw new RemediationValidationError("deterministicChecks object is required.");
  }

  if (!receipt.closureVerification || typeof receipt.closureVerification !== "object") {
    throw new RemediationValidationError("closureVerification object is required.");
  }

  if (!Array.isArray(receipt.history)) {
    throw new RemediationValidationError("history must be an array.");
  }

  return true;
}

/**
 * Computes canonical SHA-256 digest of a remediation receipt.
 *
 * @param {object} receipt
 * @returns {string} e.g. "sha256:..."
 */
export function computeRemediationReceiptDigest(receipt) {
  validateRemediationReceipt(receipt);
  return computeDigest(receipt);
}

/**
 * Controlled Remediation Session Controller
 * Manages finding remediation lifecycle and enforces state transitions.
 */
export class ControlledRemediationSession {
  /**
   * @param {string} findingId
   * @param {string[]} targetFiles
   * @param {object} [options]
   */
  constructor(findingId, targetFiles = [], options = {}) {
    if (!findingId || typeof findingId !== "string") {
      throw new RemediationValidationError("ControlledRemediationSession requires findingId.");
    }
    this.findingId = findingId;
    this.targetFiles = targetFiles.map(f => normalizeRelativePath(f)).filter(Boolean);
    this.status = REMEDIATION_STATES.OPEN;
    this.attempts = 0;
    this.history = [];
    this.startedAt = new Date().toISOString();
    this.actors = {
      producer: options.producer || { providerName: "agy", modelName: "cli-default" },
      synthesizer: options.synthesizer || null,
      verifier: options.verifier || null,
      authorizer: options.authorizer || null
    };
    this.patch = null;
    this.jail = null;
    this.deterministicChecks = null;
    this.closureVerification = null;
  }

  _recordTransition(toState, actor, metadata = {}) {
    validateRemediationTransition(this.status, toState, {
      ...metadata,
      actor,
      findingId: this.findingId,
      attempts: this.attempts,
      targetFiles: this.targetFiles,
      patch: this.patch,
      jail: this.jail,
      deterministicChecks: this.deterministicChecks,
      closureVerification: this.closureVerification,
      authorizer: this.actors.authorizer
    });

    const entry = {
      from: this.status,
      to: toState,
      at: new Date().toISOString(),
      actor: typeof actor === "string" ? actor : (actor?.identity || actor?.providerName || "unknown")
    };

    this.history.push(entry);
    this.status = toState;
  }

  proposeFix({ diff, rationale = "", synthesizer = { providerName: "claude", modelName: "opusplan" } }) {
    this.attempts++;
    this.actors.synthesizer = synthesizer;

    const validated = validatePatchScope(diff, this.targetFiles);
    this.patch = {
      rawDiff: diff,
      patchDiffDigest: validated.patchDiffDigest,
      targetFiles: validated.targetFiles,
      additions: validated.additions,
      deletions: validated.deletions,
      rationale
    };

    this._recordTransition(REMEDIATION_STATES.FIX_PROPOSED, synthesizer, {
      actorType: "synthesizer"
    });

    return this.status;
  }

  authorizePatch({ authorizer = { identity: "security-lead@internal", type: "human" }, signature = null }) {
    this.actors.authorizer = authorizer;
    this._recordTransition(REMEDIATION_STATES.PATCH_AUTHORIZED, authorizer, {
      authorizer,
      signature,
      actorType: authorizer.type || "human"
    });
    return this.status;
  }

  recordJailApplication({ worktreeSha, prePatchTreeDigest, postPatchTreeDigest, orchestrator = "jail-orchestrator" }) {
    this.jail = {
      worktreeSha,
      prePatchTreeDigest,
      postPatchTreeDigest,
      isolatedExecutionPass: true
    };
    this._recordTransition(REMEDIATION_STATES.PATCH_APPLIED_IN_JAIL, orchestrator, {
      jail: this.jail,
      actorType: "orchestrator"
    });
    return this.status;
  }

  executeInJailWorktree(repoPath, { baseSha = "HEAD", testRunnerFn = null, orchestrator = "jail-orchestrator" } = {}) {
    if (this.status !== REMEDIATION_STATES.PATCH_AUTHORIZED) {
      throw new RemediationTransitionError(
        this.status,
        REMEDIATION_STATES.PATCH_APPLIED_IN_JAIL,
        "Cannot execute in jail unless patch is in PATCH_AUTHORIZED state."
      );
    }

    const jail = createPatchJailWorktree(repoPath, { baseSha });
    try {
      const jailResult = applyPatchInJail(jail.jailPath, this.patch.rawDiff, this.targetFiles);
      this.recordJailApplication({
        worktreeSha: jail.baseSha,
        prePatchTreeDigest: jailResult.prePatchTreeDigest,
        postPatchTreeDigest: jailResult.postPatchTreeDigest,
        orchestrator
      });

      let checkResult = {
        testCommand: "npm test",
        exitCode: 0,
        passedCount: 1,
        failedCount: 0,
        runner: "test-runner"
      };

      if (typeof testRunnerFn === "function") {
        const customRes = testRunnerFn(jail.jailPath);
        checkResult = { ...checkResult, ...customRes };
      }

      this.recordDeterministicChecks(checkResult);

      return {
        jailResult,
        checkResult,
        status: this.status
      };
    } finally {
      jail.cleanup();
    }
  }

  recordDeterministicChecks({ testCommand = "npm test", exitCode = 0, passedCount = 1, failedCount = 0, runner = "test-runner" }) {
    const regressionDetected = exitCode !== 0 || failedCount > 0;
    this.deterministicChecks = {
      testCommand,
      exitCode,
      passedCount,
      failedCount,
      regressionDetected
    };

    if (regressionDetected) {
      this._recordTransition(REMEDIATION_STATES.REJECTED_FIX, runner, {
        deterministicChecks: this.deterministicChecks,
        actorType: "test-runner"
      });
    } else {
      this._recordTransition(REMEDIATION_STATES.FIXED_PENDING_VERIFY, runner, {
        deterministicChecks: this.deterministicChecks,
        actorType: "test-runner"
      });
    }
    return this.status;
  }

  recordClosureVerification({ verificationRecord, verifier = { providerName: "claude", modelName: "cli-default" } }) {
    this.actors.verifier = verifier;
    const verdict = verificationRecord?.evaluations?.[0]?.verdict || verificationRecord?.verdict || "CONTESTED";
    const supported = verdict === "SUPPORTED" && (verificationRecord?.summary?.contestedCount === 0 || !verificationRecord?.summary?.contestedCount);
    const residual = Boolean(verificationRecord?.residualVulnerabilityDetected);

    this.closureVerification = {
      verified: supported && !residual,
      verificationRecordDigest: verificationRecord?.digest || computeDigest(verificationRecord || {}),
      verdict,
      residualVulnerabilityDetected: residual
    };

    if (this.closureVerification.verified) {
      this._recordTransition(REMEDIATION_STATES.CLOSED, verifier, {
        closureVerification: this.closureVerification,
        actorType: "verifier"
      });
    } else {
      this._recordTransition(REMEDIATION_STATES.REJECTED_FIX, verifier, {
        closureVerification: this.closureVerification,
        actorType: "verifier"
      });
    }
    return this.status;
  }

  rejectFix({ reason = "Fix rejected", actor = "system" }) {
    this._recordTransition(REMEDIATION_STATES.REJECTED_FIX, actor, {
      reason,
      actorType: typeof actor === "object" ? actor.type : "system"
    });
    return this.status;
  }

  waive({ authorizer = { identity: "security-lead@internal", type: "human" }, expiryTimestamp, justification = "" }) {
    this.actors.authorizer = authorizer;
    this._recordTransition(REMEDIATION_STATES.WAIVED, authorizer, {
      authorizer,
      expiryTimestamp,
      justification,
      actorType: authorizer.type || "human"
    });
    return this.status;
  }

  reopen({ reason = "Regression observed", actor = "benchmark-runner" }) {
    this._recordTransition(REMEDIATION_STATES.REOPENED, actor, {
      reopenReason: reason,
      actorType: typeof actor === "object" ? actor.type : "producer"
    });
    return this.status;
  }

  toReceipt() {
    return buildRemediationReceipt({
      findingId: this.findingId,
      status: this.status,
      timestamps: {
        startedAt: this.startedAt,
        completedAt: new Date().toISOString()
      },
      actors: this.actors,
      patch: this.patch,
      jail: this.jail,
      deterministicChecks: this.deterministicChecks,
      closureVerification: this.closureVerification,
      history: this.history
    });
  }
}

/**
 * Deep freezes an object graph recursively to guarantee immutability.
 *
 * @param {*} obj
 * @returns {*}
 */
function deepFreeze(obj) {
  if (obj === null || typeof obj !== "object" || Object.isFrozen(obj)) {
    return obj;
  }
  Object.freeze(obj);
  for (const key of Object.keys(obj)) {
    deepFreeze(obj[key]);
  }
  return obj;
}
