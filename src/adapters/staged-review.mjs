/**
 * Triad-Flow Staged Review Pipeline & Checkpoint Manager (RFC-027-01)
 *
 * Implements multi-stage review execution (Triage -> Deep Review -> Reconciliation),
 * atomic checkpoint persistence in .triad-flow/checkpoints/, timeout salvage,
 * and fail-closed coverage contracts.
 */

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { partitionChangeSetIntoChunks } from "../core/chunk-manager.mjs";
import { buildContextPackage } from "../core/context-builder.mjs";
import { buildEvidenceReviewPrompt } from "./review-prompts.mjs";
import { reconcileFindings } from "../core/reconciler.mjs";
import { classifyFileRisk, RISK_TIERS } from "../core/graph-router.mjs";
import { normalizeCanonicalPath } from "../core/scoring.mjs";
import { EXECUTION_STATUS } from "./provider-contract.mjs";

export const COVERAGE_OMISSION_CODES = Object.freeze({
  UNMODIFIED: "OMIT_UNMODIFIED",
  SIZE_LIMIT: "OMIT_SIZE_LIMIT",
  BINARY: "OMIT_BINARY",
  GENERATED: "OMIT_GENERATED",
  OUT_OF_SCOPE: "OMIT_OUT_OF_SCOPE",
  TIMEOUT: "OMIT_TIMEOUT"
});

export const STAGED_REVIEW_STAGES = Object.freeze({
  STAGE_1_TRIAGE: "stage-1-triage",
  STAGE_2_DEEP_REVIEW: "stage-2-deep-review",
  STAGE_3_VERIFICATION: "stage-3-verification"
});

/**
 * Evaluates full coverage contract over a ChangeSet.
 * Enforces Fail-Closed: Tier 1 (Critical) files cannot be omitted under size limits or scope exclusions.
 * @param {object} changeSet
 * @param {string[]} coveredFiles
 * @param {Array<{ file: string, code: string, reason: string }>} [omittedFiles=[]]
 * @returns {{ isComplete: boolean, coveredPercentage: number, violations: string[], declaration: object }}
 */
export function evaluateCoverageContract(changeSet, coveredFiles = [], omittedFiles = []) {
  const allFiles = (changeSet?.files || []).map(f => normalizeCanonicalPath(typeof f === "string" ? f : f.path));
  const coveredSet = new Set(coveredFiles.map(f => normalizeCanonicalPath(f)));
  const omittedMap = new Map();

  for (const omit of omittedFiles) {
    omittedMap.set(normalizeCanonicalPath(omit.file), omit);
  }

  const violations = [];

  for (const f of allFiles) {
    const isCovered = coveredSet.has(f);
    const omitRecord = omittedMap.get(f);

    if (!isCovered && !omitRecord) {
      violations.push(`File '${f}' was neither covered nor declared as omitted.`);
      continue;
    }

    // Tier 1 Check: Critical files MUST NOT be omitted under size limits or out-of-scope
    const tier = classifyFileRisk(f);
    if (tier === RISK_TIERS.TIER_1_CRITICAL && omitRecord) {
      if (omitRecord.code === COVERAGE_OMISSION_CODES.SIZE_LIMIT || omitRecord.code === COVERAGE_OMISSION_CODES.OUT_OF_SCOPE) {
        violations.push(`Tier 1 (Critical) file '${f}' cannot be omitted under code '${omitRecord.code}' (Fail-Closed).`);
      }
    }
  }

  const isComplete = violations.length === 0;
  const coveredCount = coveredSet.size;
  const totalCount = allFiles.length || 1;
  const coveredPercentage = Math.min(100, Math.round((coveredCount / totalCount) * 100));

  return {
    isComplete,
    coveredPercentage,
    violations,
    declaration: {
      coveredFiles: Array.from(coveredSet),
      omittedFiles: Array.from(omittedMap.values()),
      totalFiles: totalCount,
      coveredPercentage,
      isComplete
    }
  };
}

/**
 * Checkpoint Store for intermediate multi-chunk review findings.
 */
export class CheckpointStore {
  constructor(options = {}) {
    this.cwd = options.cwd || process.cwd();
    this.checkpointDir = path.join(this.cwd, ".triad-flow", "checkpoints");
  }

  _ensureDir() {
    if (!fs.existsSync(this.checkpointDir)) {
      fs.mkdirSync(this.checkpointDir, { recursive: true });
    }
  }

  getCheckpointPath(runId) {
    return path.join(this.checkpointDir, `checkpoint-${runId}.json`);
  }

  /**
   * Persists an atomic checkpoint for a running review.
   * @param {string} runId
   * @param {object} checkpointData
   */
  saveCheckpoint(runId, checkpointData) {
    this._ensureDir();
    const filePath = this.getCheckpointPath(runId);
    const tmpPath = `${filePath}.tmp.${Date.now()}`;
    const payload = JSON.stringify({
      schemaVersion: "1.0.0",
      runId,
      timestamp: new Date().toISOString(),
      ...checkpointData
    }, null, 2);

    fs.writeFileSync(tmpPath, payload, "utf8");
    fs.renameSync(tmpPath, filePath);
  }

  /**
   * Reads a checkpoint if one exists.
   * @param {string} runId
   * @returns {object|null}
   */
  readCheckpoint(runId) {
    const filePath = this.getCheckpointPath(runId);
    if (!fs.existsSync(filePath)) return null;
    try {
      const raw = fs.readFileSync(filePath, "utf8");
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }

  /**
   * Cleans up checkpoint file after successful completion.
   * @param {string} runId
   */
  clearCheckpoint(runId) {
    const filePath = this.getCheckpointPath(runId);
    if (fs.existsSync(filePath)) {
      try {
        fs.unlinkSync(filePath);
      } catch {
        // Ignored on cleanup
      }
    }
  }
}

/**
 * Executes a Staged Review Pipeline on a ChangeSet using a given ReviewAdapter.
 * @param {object} changeSet
 * @param {object} adapter ReviewAdapter (e.g. CliReviewAdapter)
 * @param {object} [options={}]
 * @returns {Promise<object>}
 */
export async function executeStagedReview(changeSet, adapter, options = {}) {
  const runId = options.runId || crypto.randomUUID();
  const role = options.role || "macro";
  const limits = options.limits || {};
  const checkpointStore = new CheckpointStore({ cwd: options.cwd });

  // Stage 1: Triage & Chunk Partitioning
  const chunks = partitionChangeSetIntoChunks(changeSet, {
    runId,
    platform: options.platform || process.platform,
    maxChunkBytes: options.maxChunkBytes
  });

  if (chunks.length === 0) {
    return {
      runId,
      status: "no-changes",
      findings: [],
      coverage: { coveredFiles: [], omittedFiles: [], isComplete: true, coveredPercentage: 100 },
      receipts: []
    };
  }

  const accumulatedFindings = [];
  const coveredFiles = new Set();
  const omittedFiles = [];
  const chunkReceipts = [];

  // Stage 2: Deep Contextual Review per Chunk
  for (let idx = 0; idx < chunks.length; idx++) {
    const chunk = chunks[idx];
    const chunkTarget = chunk.targetFiles[0] || "index.js";

    // Build AST Context Package for primary target file in chunk
    const contextPkg = buildContextPackage({
      ...changeSet,
      diffHunks: chunk.diffHunks,
      files: chunk.targetFiles.map(p => ({ path: p, additions: 0, deletions: 0 }))
    }, chunkTarget, {
      runId,
      repositoryRoot: options.cwd || process.cwd()
    });

    // Build structured evidence prompt
    const prompt = buildEvidenceReviewPrompt({
      ...changeSet,
      diffHunks: chunk.diffHunks,
      files: chunk.targetFiles.map(p => ({ path: p, additions: 0, deletions: 0 }))
    }, role, limits, contextPkg);

    const chunkStartTime = Date.now();
    let chunkResult;

    try {
      chunkResult = await adapter.executeReview({
        runId: `${runId}-chunk-${idx}`,
        role,
        policyId: options.policyId || "TRI_PARTY_HETEROGENEOUS",
        timeoutMs: options.timeoutMs,
        signal: options.signal,
        changeSet: {
          ...changeSet,
          diffHunks: chunk.diffHunks,
          files: chunk.targetFiles.map(p => ({ path: p, additions: 0, deletions: 0 })),
          contentDigest: crypto.createHash("sha256").update(chunk.diffHunks || "", "utf8").digest("hex")
        },
        limits,
        prompt
      });
    } catch (err) {
      chunkResult = {
        ok: false,
        status: "error",
        error: err.message || String(err),
        findings: []
      };
    }

    const chunkDurationMs = Date.now() - chunkStartTime;

    // Handle chunk outcome
    if (chunkResult && chunkResult.ok) {
      if (Array.isArray(chunkResult.findings)) {
        accumulatedFindings.push(...chunkResult.findings);
      }
      for (const tf of chunk.targetFiles) {
        coveredFiles.add(normalizeCanonicalPath(tf));
      }
      chunkReceipts.push({
        chunkId: chunk.chunkId,
        chunkIndex: chunk.chunkIndex,
        totalChunks: chunk.totalChunks,
        status: "completed",
        durationMs: chunkDurationMs,
        findingsCount: chunkResult.findings?.length || 0
      });
    } else {
      // Chunk Failed or Timed Out
      const isTimeout = chunkResult?.status === "timeout" || /timeout/i.test(chunkResult?.error || "");
      for (const tf of chunk.targetFiles) {
        omittedFiles.push({
          file: tf,
          code: isTimeout ? COVERAGE_OMISSION_CODES.TIMEOUT : COVERAGE_OMISSION_CODES.SIZE_LIMIT,
          reason: chunkResult?.error || `Chunk ${chunk.chunkId} failed to complete execution.`
        });
      }
      chunkReceipts.push({
        chunkId: chunk.chunkId,
        chunkIndex: chunk.chunkIndex,
        totalChunks: chunk.totalChunks,
        status: isTimeout ? "timeout" : "failed",
        durationMs: chunkDurationMs,
        error: chunkResult?.error || "Execution failed"
      });

      // Persist salvage checkpoint before stopping or continuing
      checkpointStore.saveCheckpoint(runId, {
        runId,
        stage: STAGED_REVIEW_STAGES.STAGE_2_DEEP_REVIEW,
        salvagedFindings: accumulatedFindings,
        completedChunks: idx,
        totalChunks: chunks.length,
        omittedFiles
      });

      // Fail closed if Tier 1 chunk failed
      if (chunk.priorityTier === RISK_TIERS.TIER_1_CRITICAL) {
        break;
      }
    }

    // Persist successful chunk checkpoint
    checkpointStore.saveCheckpoint(runId, {
      runId,
      stage: STAGED_REVIEW_STAGES.STAGE_2_DEEP_REVIEW,
      salvagedFindings: accumulatedFindings,
      completedChunks: idx + 1,
      totalChunks: chunks.length
    });
  }

  // Stage 3: Finding Reconciliation
  const reconciledFindings = reconcileFindings(accumulatedFindings, adapter.providerName || role);

  // Evaluate Coverage
  const coverageEval = evaluateCoverageContract(changeSet, Array.from(coveredFiles), omittedFiles);

  const finalStatus = coverageEval.isComplete ? "completed" : "incomplete";

  // Clean up checkpoint on complete success
  if (coverageEval.isComplete) {
    checkpointStore.clearCheckpoint(runId);
  }

  return {
    runId,
    ok: finalStatus === "completed" || (reconciledFindings.length > 0 && finalStatus !== "failed"),
    executionStatus: finalStatus === "completed" ? EXECUTION_STATUS.SUCCESS : (finalStatus === "incomplete" ? EXECUTION_STATUS.PARTIAL_COVERAGE : EXECUTION_STATUS.ERROR),
    providerIdentity: {
      provider: adapter.providerName || role,
      model: adapter.modelName || "unknown-model",
      family: adapter.family || "unknown",
      transport: "cli-staged",
      runId
    },
    status: finalStatus,
    findings: reconciledFindings,
    coverage: coverageEval.declaration,
    violations: coverageEval.violations,
    receipts: chunkReceipts
  };
}
