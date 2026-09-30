/**
 * Triad-Flow Multi-Finding Remediation Orchestrator Engine (M1a / v2.4)
 *
 * Implements M1 Batch Remediation & Invariant 1:
 * - Invariant 1: Batch authority MUST NOT exceed single-remediation authority.
 * - Conflict DAG & Topological Deterministic Ordering.
 * - Cumulative Tree Digest Lineage tracking (T0 -> T1 -> T2 ...).
 * - Granular partial-failure semantics (failure of B does not erase closed evidence of A).
 * - Immutable Batch Remediation Receipt Schema 1.0.0 builder and validator.
 */

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

import {
  canonicalJsonStringify,
  computeDigest,
  normalizeRelativePath
} from "./canonical-digest.mjs";
import {
  REMEDIATION_STATES,
  ControlledRemediationSession,
  validateRemediationReceipt,
  createPatchJailWorktree,
  cleanupPatchJailWorktree,
  applyPatchInJail,
  computeTreeDigest,
  RemediationValidationError,
  PatchJailExecutionError
} from "./controlled-remediation.mjs";
import {
  resolveSandboxDriver,
  WorktreeDriver,
  ContainerDriver,
  SANDBOX_DRIVERS
} from "./sandbox-driver.mjs";

export {
  resolveSandboxDriver,
  WorktreeDriver,
  ContainerDriver,
  SANDBOX_DRIVERS
};

export const BATCH_SCHEMA_VERSION = "1.0.0";

export const BATCH_REMEDIATION_STATES = Object.freeze({
  OPEN: "OPEN",
  IN_PROGRESS: "IN_PROGRESS",
  COMPLETED: "COMPLETED"
});

export const BATCH_VERDICTS = Object.freeze({
  ALL_CLOSED: "ALL_CLOSED",
  PARTIAL: "PARTIAL",
  ALL_REJECTED: "ALL_REJECTED",
  BLOCKED: "BLOCKED"
});

export class BatchAuthorityViolationError extends Error {
  constructor(message) {
    super(message);
    this.name = "BatchAuthorityViolationError";
  }
}

export class BatchLineageDriftError extends Error {
  constructor(message) {
    super(message);
    this.name = "BatchLineageDriftError";
  }
}

export class BatchValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = "BatchValidationError";
  }
}

const SEVERITY_WEIGHTS = Object.freeze({
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0
});

/**
 * Builds an undirected conflict graph across candidate findings based on target file overlap.
 * Note: Relationships are symmetric (A conflicts B <=> B conflicts A).
 * (Alias: buildConflictDAG maintained for backwards compatibility).
 *
 * @param {Array<{ id: string, targetFiles: string[] }>} findings
 * @returns {{ hasConflict: (id1: string, id2: string) => boolean, conflicts: Map<string, Set<string>> }}
 */
export function buildConflictGraph(findings = []) {
  const fileToFindings = new Map();
  const conflicts = new Map();

  for (const f of findings) {
    conflicts.set(f.id, new Set());
    const files = Array.isArray(f.targetFiles) ? f.targetFiles : [];
    for (const file of files) {
      const norm = normalizeRelativePath(file);
      if (!fileToFindings.has(norm)) {
        fileToFindings.set(norm, new Set());
      }
      fileToFindings.get(norm).add(f.id);
    }
  }

  for (const [, findingSet] of fileToFindings.entries()) {
    if (findingSet.size > 1) {
      const arr = Array.from(findingSet);
      for (let i = 0; i < arr.length; i++) {
        for (let j = i + 1; j < arr.length; j++) {
          conflicts.get(arr[i]).add(arr[j]);
          conflicts.get(arr[j]).add(arr[i]);
        }
      }
    }
  }

  return {
    conflicts,
    hasConflict(id1, id2) {
      return Boolean(conflicts.get(id1)?.has(id2));
    }
  };
}

export const buildConflictDAG = buildConflictGraph;

/**
 * Computes deterministic execution order for batch findings.
 * Findings in the conflict graph are serialized by severity weight (critical first), then original index.
 *
 * @param {Array<{ id: string, severity?: string, targetFiles: string[] }>} findings
 * @param {ReturnType<typeof buildConflictGraph>} [conflictGraph]
 * @returns {string[]} Ordered list of finding IDs
 */
export function computeDeterministicBatchOrder(findings = [], conflictGraph = null) {
  const graph = conflictGraph || buildConflictGraph(findings);
  const items = findings.map((f, idx) => ({
    id: f.id,
    severity: String(f.severity || "medium").toLowerCase(),
    weight: SEVERITY_WEIGHTS[String(f.severity || "medium").toLowerCase()] ?? 2,
    idx
  }));

  // Sort by weight descending, then original index ascending
  items.sort((a, b) => {
    if (b.weight !== a.weight) return b.weight - a.weight;
    return a.idx - b.idx;
  });

  return items.map(item => item.id);
}

/**
 * Manages an orchestrated batch remediation session across multiple findings.
 */
export class BatchRemediationSession {
  /**
   * @param {string} batchId
   * @param {Array<{ id: string, targetFiles: string[], producer?: object }>} findings
   * @param {object} [options]
   */
  constructor(batchId, findings = [], options = {}) {
    if (!batchId || typeof batchId !== "string") {
      throw new BatchValidationError("batchId must be a non-empty string.");
    }

    this.batchId = batchId;
    this.status = BATCH_REMEDIATION_STATES.OPEN;
    this.verdict = null;
    this.createdAt = new Date().toISOString();
    this.completedAt = null;

    this.initialTreeDigest = options.initialTreeDigest || null;
    this.currentTreeDigest = this.initialTreeDigest;
    this.lineageHistory = [];

    this.sessions = new Map();
    this.findings = [...findings];

    for (const f of findings) {
      if (!f.id || typeof f.id !== "string") {
        throw new BatchValidationError("Every finding in batch must have a valid string id.");
      }
      const targetFiles = Array.isArray(f.targetFiles) ? f.targetFiles : [];
      const session = new ControlledRemediationSession(f.id, targetFiles, {
        producer: f.producer || options.producer || { providerName: "unknown", modelName: "unknown" }
      });
      this.sessions.set(f.id, session);
    }
  }

  get sessionsCount() {
    return this.sessions.size;
  }

  getSession(findingId) {
    const s = this.sessions.get(findingId);
    if (!s) {
      throw new BatchValidationError(`No remediation session found for finding '${findingId}'.`);
    }
    return s;
  }

  /**
   * Enforces Invariant 1: Prohibits bulk closing or bypassing individual evidence gates.
   */
  bulkCloseWithoutVerification() {
    throw new BatchAuthorityViolationError(
      "Invariant 1 Violated: Batch authority MUST NOT exceed single-remediation authority. Individual verification cannot be skipped."
    );
  }

  /**
   * Records advancement of cumulative tree digest lineage after successful patch jail trial.
   *
   * @param {string} findingId
   * @param {{ prePatchTreeDigest: string, postPatchTreeDigest: string }} digests
   */
  recordStepSuccess(findingId, { prePatchTreeDigest, postPatchTreeDigest }) {
    if (!this.sessions.has(findingId)) {
      throw new BatchValidationError(`Finding '${findingId}' does not belong to this batch.`);
    }

    if (this.currentTreeDigest && prePatchTreeDigest !== this.currentTreeDigest) {
      throw new BatchLineageDriftError(
        `Cumulative lineage drift detected for '${findingId}': expected base tree ${this.currentTreeDigest}, but patch consumed ${prePatchTreeDigest}`
      );
    }

    this.lineageHistory.push({
      findingId,
      fromDigest: prePatchTreeDigest,
      toDigest: postPatchTreeDigest,
      at: new Date().toISOString()
    });

    this.currentTreeDigest = postPatchTreeDigest;
    this.status = BATCH_REMEDIATION_STATES.IN_PROGRESS;
  }

  /**
   * Executes candidate patches sequentially in an ephemeral Git Worktree Patch Jail.
   *
   * @param {string} repoPath
   * @param {object} [options]
   * @param {string} [options.baseSha="HEAD"]
   * @param {Function} options.testRunnerFn
   * @param {string} [options.orchestrator="batch-orchestrator"]
   * @returns {{ jailPath: string, baseSha: string, order: string[], executionResults: object[], initialTreeDigest: string, currentTreeDigest: string, lineage: object[], aggregateDiff: string }}
   */
  executeBatchInJailWorktree(repoPath, {
    baseSha = "HEAD",
    testRunnerFn = null,
    orchestrator = "batch-orchestrator",
    sandboxDriver = null
  } = {}) {
    if (typeof testRunnerFn !== "function") {
      throw new BatchValidationError("executeBatchInJailWorktree requires a 'testRunnerFn' callback function.");
    }

    const driver = sandboxDriver
      ? (typeof sandboxDriver === "string" ? resolveSandboxDriver(sandboxDriver) : sandboxDriver)
      : new WorktreeDriver();
    this.sandboxDriver = driver;

    const jail = driver.create(repoPath, { baseSha });
    this.jailCapabilities = jail.capabilities || driver.capabilities();
    const initialTreeDigest = computeTreeDigest(jail.jailPath);
    if (!this.initialTreeDigest) {
      this.initialTreeDigest = initialTreeDigest;
    }
    this.currentTreeDigest = initialTreeDigest;

    const order = computeDeterministicBatchOrder(this.findings);
    const executionResults = [];

    const gitExec = (args) => execFileSync("git", ["-c", "core.fsmonitor=false", ...args], {
      cwd: jail.jailPath,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true
    });

    try {
      for (const findingId of order) {
        const session = this.getSession(findingId);

        // Invariant 1: Cannot execute in jail unless patch is in PATCH_AUTHORIZED state
        if (session.status !== REMEDIATION_STATES.PATCH_AUTHORIZED) {
          executionResults.push({
            findingId,
            status: session.status,
            skipped: true,
            reason: `Session status is ${session.status} (requires PATCH_AUTHORIZED)`
          });
          continue;
        }

        let jailResult;
        try {
          jailResult = applyPatchInJail(jail.jailPath, session.patch.rawDiff, session.targetFiles);
          session.recordJailApplication({
            worktreeSha: baseSha,
            prePatchTreeDigest: jailResult.prePatchTreeDigest,
            postPatchTreeDigest: jailResult.postPatchTreeDigest,
            driver: driver.name,
            capabilities: this.jailCapabilities,
            orchestrator
          });
        } catch (err) {
          // Patch application or scope violation in jail -> roll back uncommitted changes
          gitExec(["reset", "--hard", "HEAD"]);
          gitExec(["clean", "-fd"]);
          session._recordTransition(REMEDIATION_STATES.REJECTED_FIX, orchestrator, {
            error: err.message,
            actorType: "orchestrator"
          });
          executionResults.push({
            findingId,
            status: session.status,
            applied: false,
            error: err.message
          });
          continue;
        }

        // Run deterministic test runner in jail
        let testRes;
        try {
          testRes = testRunnerFn(jail.jailPath, { findingId, session });
        } catch (err) {
          testRes = {
            testCommand: "custom-testRunnerFn",
            exitCode: 1,
            passedCount: 0,
            failedCount: 1,
            regressionDetected: true,
            error: err.message
          };
        }

        const exitCode = typeof testRes?.exitCode === "number" ? testRes.exitCode : (testRes ? 0 : 1);
        const passedCount = typeof testRes?.passedCount === "number" ? testRes.passedCount : (exitCode === 0 ? 1 : 0);
        const failedCount = typeof testRes?.failedCount === "number" ? testRes.failedCount : (exitCode === 0 ? 0 : 1);
        const regressionDetected = exitCode !== 0 || failedCount > 0 || Boolean(testRes?.regressionDetected);

        session.recordDeterministicChecks({
          executed: true,
          testCommand: testRes?.testCommand || "npm test",
          exitCode,
          passedCount,
          failedCount,
          regressionDetected,
          postTestTreeDigest: jailResult.postPatchTreeDigest,
          runner: testRes?.runner || "test-runner"
        });

        if (session.status === REMEDIATION_STATES.FIXED_PENDING_VERIFY) {
          // Commit in ephemeral worktree to anchor this step as the new base for next steps
          gitExec(["add", "-A"]);
          gitExec(["-c", "user.name=triad-flow", "-c", "user.email=bot@triad.flow", "commit", "-q", "-m", `remediate: ${findingId}`]);

          this.recordStepSuccess(findingId, {
            prePatchTreeDigest: jailResult.prePatchTreeDigest,
            postPatchTreeDigest: jailResult.postPatchTreeDigest
          });

          executionResults.push({
            findingId,
            status: session.status,
            applied: true,
            prePatchTreeDigest: jailResult.prePatchTreeDigest,
            postPatchTreeDigest: jailResult.postPatchTreeDigest,
            testsPassed: true
          });
        } else {
          // Roll back uncommitted changes from this failed patch
          gitExec(["reset", "--hard", "HEAD"]);
          gitExec(["clean", "-fd"]);

          executionResults.push({
            findingId,
            status: session.status,
            applied: true,
            testsPassed: false
          });
        }
      }

      // Compute aggregate diff across all successfully committed patches
      let aggregateDiff = "";
      try {
        aggregateDiff = gitExec(["diff", baseSha, "HEAD"]);
      } catch {
        // ignore
      }
      this.aggregateDiff = aggregateDiff;

      return {
        jailPath: jail.jailPath,
        baseSha,
        order,
        executionResults,
        initialTreeDigest: this.initialTreeDigest,
        currentTreeDigest: this.currentTreeDigest,
        lineage: [...this.lineageHistory],
        aggregateDiff
      };
    } finally {
      jail.cleanup();
    }
  }

  /**
   * Finalizes batch state and aggregates individual session statuses.
   *
   * @returns {{ status: string, verdict: string, total: number, closedCount: number, rejectedCount: number, waivedCount: number, openCount: number }}
   */
  finalize() {
    let closedCount = 0;
    let rejectedCount = 0;
    let waivedCount = 0;
    let openCount = 0;

    for (const [, session] of this.sessions.entries()) {
      switch (session.status) {
        case REMEDIATION_STATES.CLOSED:
          closedCount++;
          break;
        case REMEDIATION_STATES.REJECTED_FIX:
          rejectedCount++;
          break;
        case REMEDIATION_STATES.WAIVED:
          waivedCount++;
          break;
        default:
          openCount++;
          break;
      }
    }

    const total = this.sessions.size;
    if (closedCount === total) {
      this.verdict = BATCH_VERDICTS.ALL_CLOSED;
    } else if (rejectedCount === total) {
      this.verdict = BATCH_VERDICTS.ALL_REJECTED;
    } else if (openCount > 0) {
      this.verdict = BATCH_VERDICTS.BLOCKED;
    } else {
      this.verdict = BATCH_VERDICTS.PARTIAL;
    }

    this.status = BATCH_REMEDIATION_STATES.COMPLETED;
    this.completedAt = new Date().toISOString();

    return {
      status: this.status,
      verdict: this.verdict,
      total,
      closedCount,
      rejectedCount,
      waivedCount,
      openCount
    };
  }

  /**
   * Assembles the immutable Batch Remediation Receipt Schema 1.0.0.
   *
   * @returns {object} Validated batch remediation receipt
   */
  toBatchReceipt() {
    if (this.status !== BATCH_REMEDIATION_STATES.COMPLETED) {
      this.finalize();
    }

    const receipts = [];
    for (const [, session] of this.sessions.entries()) {
      receipts.push(session.toReceipt());
    }

    let closedCount = 0;
    let rejectedCount = 0;
    let waivedCount = 0;
    let openCount = 0;

    for (const r of receipts) {
      if (r.status === REMEDIATION_STATES.CLOSED) closedCount++;
      else if (r.status === REMEDIATION_STATES.REJECTED_FIX) rejectedCount++;
      else if (r.status === REMEDIATION_STATES.WAIVED) waivedCount++;
      else openCount++;
    }

    const batchReceipt = {
      schemaVersion: BATCH_SCHEMA_VERSION,
      batchId: this.batchId,
      status: this.status,
      verdict: this.verdict,
      timestamps: {
        createdAt: this.createdAt,
        completedAt: this.completedAt || new Date().toISOString()
      },
      summary: {
        totalFindings: receipts.length,
        closedCount,
        rejectedCount,
        waivedCount,
        openCount
      },
      sandbox: {
        driver: this.sandboxDriver?.name || "worktree",
        capabilities: this.jailCapabilities || this.sandboxDriver?.capabilities() || {
          driver: "worktree",
          filesystemIsolation: "git-worktree",
          networkEgressDenial: "unavailable",
          processIsolation: "none",
          hostFilesystemWriteRestriction: "unenforced"
        }
      },
      lineage: {
        initialTreeDigest: this.initialTreeDigest,
        currentTreeDigest: this.currentTreeDigest,
        history: [...this.lineageHistory]
      },
      aggregateDiff: this.aggregateDiff || "",
      receipts
    };

    validateBatchReceipt(batchReceipt);
    return Object.freeze(batchReceipt);
  }
}

/**
 * Validates a batch receipt adhering to Schema 1.0.0.
 *
 * @param {object} receipt
 * @returns {boolean} true if valid, throws otherwise
 */
export function validateBatchReceipt(receipt) {
  if (!receipt || typeof receipt !== "object") {
    throw new BatchValidationError("Batch receipt must be a non-null object.");
  }

  if (receipt.schemaVersion !== BATCH_SCHEMA_VERSION) {
    throw new BatchValidationError(
      `Unsupported batch schema version: '${receipt.schemaVersion}'. Expected '${BATCH_SCHEMA_VERSION}'.`
    );
  }

  if (typeof receipt.batchId !== "string" || !receipt.batchId.trim()) {
    throw new BatchValidationError("batchId must be a non-empty string.");
  }

  if (!Object.values(BATCH_REMEDIATION_STATES).includes(receipt.status)) {
    throw new BatchValidationError(`Invalid batch status '${receipt.status}'.`);
  }

  if (!Object.values(BATCH_VERDICTS).includes(receipt.verdict)) {
    throw new BatchValidationError(`Invalid batch verdict '${receipt.verdict}'.`);
  }

  if (!receipt.summary || typeof receipt.summary !== "object") {
    throw new BatchValidationError("summary must be a non-null object.");
  }

  if (!Array.isArray(receipt.receipts)) {
    throw new BatchValidationError("receipts must be an array.");
  }

  // Validate every individual receipt
  for (const r of receipt.receipts) {
    validateRemediationReceipt(r);
  }

  return true;
}
