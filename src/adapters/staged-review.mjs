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
import { normalizeFinding } from "../core/harness.mjs";
import { EXECUTION_STATUS, COVERAGE_OMISSION_CODES, safeRenderUntrusted, safeGet, safeIsArray, safeArrayLength, safeErrorMessage } from "./provider-contract.mjs";

export { COVERAGE_OMISSION_CODES };
const ALLOWED_OMISSION_CODES = new Set(Object.values(COVERAGE_OMISSION_CODES));

export const STAGED_REVIEW_STAGES = Object.freeze({
  STAGE_1_TRIAGE: "stage-1-triage",
  STAGE_2_DEEP_REVIEW: "stage-2-deep-review",
  STAGE_3_VERIFICATION: "stage-3-verification"
});

/**
 * Validates and canonicalizes a raw candidate finding object before accumulation or persistence.
 * Shields pipeline against revoked Proxies, throwing getters, circular references, and hostile toJSON() hooks.
 * Returns null if the candidate is not a safe, valid object.
 * @param {*} raw
 * @returns {object|null}
 */
export function canonicalizeFinding(raw) {
  if (!raw || typeof raw !== "object" || safeIsArray(raw)) {
    return null;
  }
  try {
    const jsonStr = JSON.stringify(raw);
    if (!jsonStr || typeof jsonStr !== "string") return null;
    const parsed = JSON.parse(jsonStr);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;

    delete parsed.__trustedCapabilityNonce;
    delete parsed.authority;
    delete parsed.isTrusted;
    delete parsed.quorumReached;
    delete parsed.consensusProof;

    const norm = normalizeFinding(parsed);
    if (!norm || !norm.valid || !norm.finding) {
      return null;
    }

    if (parsed.sources !== undefined && parsed.sources !== null) {
      if (!Array.isArray(parsed.sources)) {
        return null;
      }
      for (const s of parsed.sources) {
        if (typeof s !== "string" || !s.trim()) {
          return null;
        }
      }
      norm.finding.sources = parsed.sources.map(s => s.trim());
    }

    return norm.finding;
  } catch {
    return null;
  }
}

/**
 * Evaluates full coverage contract over a ChangeSet.
 * Enforces Fail-Closed: Tier 1 (Critical) files cannot be omitted under size limits or scope exclusions.
 * @param {object} changeSet
 * @param {string[]} coveredFiles
 * @param {Array<{ file: string, code: string, reason: string }>} [omittedFiles=[]]
 * @returns {{ isComplete: boolean, coveredPercentage: number, violations: string[], declaration: object }}
 */
export function evaluateCoverageContract(changeSet, coveredFiles = [], omittedFiles = []) {
  try {
    const rawAllFiles = safeGet(changeSet, "files");
    const violations = [];

    const allFilesLen = safeArrayLength(rawAllFiles);
    if (!safeIsArray(rawAllFiles) || allFilesLen < 0) {
      violations.push("ChangeSet requires a valid 'files' array with readable length.");
    }

    const allFiles = (safeIsArray(rawAllFiles) ? rawAllFiles : []).map(f => normalizeCanonicalPath(typeof f === "string" ? f : safeGet(f, "path") || ""));
    const coveredSet = new Set();
    const omittedMap = new Map();

    const covLen = safeArrayLength(coveredFiles);
    if (!safeIsArray(coveredFiles) || covLen < 0) {
      violations.push("Coverage declaration 'coveredFiles' must be a valid array with readable length.");
    } else {
      for (let i = 0; i < covLen; i++) {
        const cf = safeGet(coveredFiles, i);
        if (typeof cf === "string" && cf.trim()) {
          coveredSet.add(normalizeCanonicalPath(cf.trim()));
        }
      }
    }

    const omittedLen = safeArrayLength(omittedFiles);
    if (!safeIsArray(omittedFiles) || omittedLen < 0) {
      violations.push("Coverage declaration 'omittedFiles' must be a valid array with readable length.");
    } else {
      for (let i = 0; i < omittedLen; i++) {
        const omit = safeGet(omittedFiles, i);
        if (!omit || typeof omit !== "object" || safeIsArray(omit)) {
          violations.push(`Omission entry at index ${i} must be a non-null plain object.`);
          continue;
        }
        const fileProp = safeGet(omit, "file");
        const pathProp = safeGet(omit, "path");
        const targetProp = safeGet(omit, "target");

        const omitFile = (typeof fileProp === "string" && fileProp.trim())
          ? fileProp.trim()
          : ((typeof pathProp === "string" && pathProp.trim())
            ? pathProp.trim()
            : (typeof targetProp === "string" ? targetProp.trim() : null));

        if (!omitFile) {
          violations.push(`Omission entry at index ${i} is missing a valid file path.`);
          continue;
        }

        const norm = normalizeCanonicalPath(omitFile);
        const codeVal = safeGet(omit, "code");
        const reasonVal = safeGet(omit, "reason");
        const code = typeof codeVal === "string" ? codeVal.trim() : "";
        const reason = typeof reasonVal === "string" ? reasonVal.trim() : "";

        if (!code || !ALLOWED_OMISSION_CODES.has(code)) {
          violations.push(`File '${norm}' omission has missing or unauthorized code '${safeRenderUntrusted(codeVal)}'.`);
        }

        if (!reason) {
          violations.push(`File '${norm}' omission has missing or empty reason.`);
        }

        omittedMap.set(norm, {
          file: norm,
          path: norm,
          code: code || undefined,
          reason: reason || undefined
        });
      }
    }

    for (const f of allFiles) {
      const isCovered = coveredSet.has(f);
      const omitRecord = omittedMap.get(f);

      // P1-1: covered XOR omitted (A file MUST NOT be simultaneously covered and omitted)
      if (isCovered && omitRecord) {
        violations.push(`File '${f}' was declared as both covered and omitted (contradictory coverage declaration).`);
        continue;
      }

      if (!isCovered && !omitRecord) {
        violations.push(`File '${f}' was neither covered nor declared as omitted.`);
        continue;
      }

      // Tier 1 Check: Critical files MUST NOT be omitted under any code (Fail-Closed)
      const tier = classifyFileRisk(f);
      if (tier === RISK_TIERS.TIER_1_CRITICAL && omitRecord) {
        violations.push(`Tier 1 (Critical) file '${f}' cannot be omitted under code '${safeRenderUntrusted(omitRecord.code || "unknown")}' (Fail-Closed).`);
      }
    }

    // Check any files outside allFiles that appear in both coveredSet and omittedMap
    for (const [omitFile] of omittedMap) {
      if (coveredSet.has(omitFile) && !allFiles.includes(omitFile)) {
        violations.push(`File '${omitFile}' was declared as both covered and omitted (contradictory coverage declaration).`);
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
  } catch (err) {
    return {
      isComplete: false,
      coveredPercentage: 0,
      violations: [`Coverage evaluation failed closed: ${safeErrorMessage(err)}`],
      declaration: {
        coveredFiles: [],
        omittedFiles: [],
        isComplete: false,
        coveredPercentage: 0
      }
    };
  }
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
    try {
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
    } catch {
      // Checkpoint saving must never crash execution or leak unhandled rejections
    }
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

  // P1-2: Freeze total staged-review budget and track absolute global deadline (RFC-027-01 §8.8)
  const totalBudgetMs = typeof options.timeoutMs === "number" && options.timeoutMs > 0
    ? options.timeoutMs
    : 300000;
  const reviewStartTime = Date.now();
  const globalDeadline = reviewStartTime + totalBudgetMs;

  const rawConcurrency = options.concurrency ?? options.maxConcurrency;
  const parsedConcurrency = Number(rawConcurrency);
  const maxConcurrency = (Number.isFinite(parsedConcurrency) && parsedConcurrency > 0)
    ? Math.max(1, Math.min(4, Math.floor(parsedConcurrency)))
    : 1;

  // REMEDIATION-006: Pre-flight feasibility check (006-C)
  const minViableChunkBudgetMs = (Number.isFinite(Number(options.minChunkBudgetMs)) && Number(options.minChunkBudgetMs) > 0)
    ? Number(options.minChunkBudgetMs)
    : 10000;
  const estimatedWaves = Math.ceil(chunks.length / maxConcurrency);
  const minRequiredBudgetMs = estimatedWaves * minViableChunkBudgetMs;
  const isFeasible = totalBudgetMs >= minRequiredBudgetMs;
  const feasibility = {
    isFeasible,
    totalBudgetMs,
    minRequiredBudgetMs,
    plannedChunks: chunks.length,
    maxConcurrency,
    estimatedWaves,
    warning: isFeasible ? null : `Total budget ${totalBudgetMs}ms may be insufficient for ${chunks.length} chunks across ${estimatedWaves} waves (min required: ${minRequiredBudgetMs}ms)`
  };

  // Stage 2: Bounded Concurrency Chunk Execution with Dynamic Wave Budgeting
  const chunkRawOutcomes = new Array(chunks.length);
  const activeChunkControllers = new Set();
  let tier1ExecutionFailed = false;
  let completedChunkCount = 0;
  let contiguousCommittedPrefix = 0;
  let committedSuccessfulChunks = 0;
  const committedOmittedFiles = [];
  const committedFindings = [];

  function tryCommitCheckpoints() {
    try {
      while (contiguousCommittedPrefix < chunks.length && chunkRawOutcomes[contiguousCommittedPrefix]) {
        const outcome = chunkRawOutcomes[contiguousCommittedPrefix];
        const res = outcome?.result;
        if (res && res.ok) {
          const rawFindings = safeGet(res, "findings");
          const len = safeArrayLength(rawFindings);
          if (safeIsArray(rawFindings) && len >= 0) {
            let valid = true;
            const validFindings = [];
            for (let i = 0; i < len; i++) {
              const item = safeGet(rawFindings, i);
              const canon = canonicalizeFinding(item);
              if (!canon) {
                valid = false;
                break;
              }
              validFindings.push(canon);
            }
            if (valid) {
              committedFindings.push(...validFindings);
            }
          }
          committedSuccessfulChunks++;
          contiguousCommittedPrefix++;
          checkpointStore.saveCheckpoint(runId, {
            runId,
            stage: STAGED_REVIEW_STAGES.STAGE_2_DEEP_REVIEW,
            salvagedFindings: [...committedFindings],
            completedChunks: committedSuccessfulChunks,
            totalChunks: chunks.length,
            omittedFiles: committedOmittedFiles.length > 0 ? [...committedOmittedFiles] : undefined
          });
        } else {
          // Chunk failed or timed out: persist failure state without claiming success
          const rawFindings = safeGet(res, "findings") || safeGet(outcome?.rawResult, "findings");
          const len = safeArrayLength(rawFindings);
          if (safeIsArray(rawFindings) && len > 0) {
            let valid = true;
            const validFindings = [];
            for (let i = 0; i < len; i++) {
              const item = safeGet(rawFindings, i);
              const canon = canonicalizeFinding(item);
              if (!canon) {
                valid = false;
                break;
              }
              validFindings.push(canon);
            }
            if (valid) {
              committedFindings.push(...validFindings);
            }
          }
          if (outcome?.chunk?.targetFiles) {
            for (const tf of outcome.chunk.targetFiles) {
              committedOmittedFiles.push({
                file: tf,
                code: outcome?.status === "timeout" ? COVERAGE_OMISSION_CODES.TIMEOUT : COVERAGE_OMISSION_CODES.SIZE_LIMIT,
                reason: res?.error || "Chunk execution failed"
              });
            }
          }
          contiguousCommittedPrefix++;
          checkpointStore.saveCheckpoint(runId, {
            runId,
            stage: STAGED_REVIEW_STAGES.STAGE_2_DEEP_REVIEW,
            salvagedFindings: [...committedFindings],
            completedChunks: committedSuccessfulChunks,
            totalChunks: chunks.length,
            omittedFiles: [...committedOmittedFiles]
          });
        }
      }
    } catch {
      // Checkpoint commit failure must never throw or crash the scheduler
    }
  }

  let timedOutByGlobal = false;
  const globalDeadlineTimer = setTimeout(() => {
    timedOutByGlobal = true;
    for (const ctrl of activeChunkControllers) {
      ctrl.abort("Global staged review budget exhausted.");
    }
  }, Math.max(1, totalBudgetMs));
  if (typeof globalDeadlineTimer.unref === "function") {
    globalDeadlineTimer.unref();
  }

  let externalGlobalAbortHandler = null;
  if (options.signal) {
    if (options.signal.aborted) {
      for (const ctrl of activeChunkControllers) {
        ctrl.abort(options.signal.reason);
      }
    } else {
      externalGlobalAbortHandler = () => {
        for (const ctrl of activeChunkControllers) {
          ctrl.abort(options.signal.reason);
        }
      };
      options.signal.addEventListener("abort", externalGlobalAbortHandler, { once: true });
    }
  }

  async function executeChunk(chunk, idx) {
    const chunkTarget = chunk.targetFiles[0] || "index.js";
    const now = Date.now();
    const remainingGlobalMs = Math.max(0, globalDeadline - now);
    const wasCancelledExternally = Boolean(options.signal && options.signal.aborted);

    if (remainingGlobalMs <= 0 || wasCancelledExternally) {
      return {
        idx,
        chunk,
        status: wasCancelledExternally ? "cancelled" : "timeout",
        timeoutCategory: wasCancelledExternally ? "none" : "global_exhaustion",
        durationMs: 0,
        budgetAllocatedMs: 0,
        result: {
          ok: false,
          status: wasCancelledExternally ? "cancelled" : "timeout",
          executionStatus: wasCancelledExternally ? EXECUTION_STATUS.CANCELLED : EXECUTION_STATUS.TIMEOUT,
          error: wasCancelledExternally
            ? `Execution cancelled before chunk ${chunk.chunkId} could execute: ${options.signal.reason || "signal aborted"}`
            : `Staged review global budget exhausted (${totalBudgetMs}ms) before chunk ${chunk.chunkId} could execute.`
        }
      };
    }

    // Dynamic wave budget (006-C / P1-05): Recompute allowable timeout from remainingGlobalMs and remaining waves
    const isDynamicBudgeting = maxConcurrency > 1 || Boolean(options.dynamicWaveBudget);
    let nominalChunkBudgetMs;
    if (isDynamicBudgeting) {
      const outstandingChunks = Math.max(1, chunks.length - completedChunkCount);
      const remainingWaves = Math.max(1, Math.ceil(outstandingChunks / maxConcurrency));
      const dynamicWaveBudgetMs = Math.floor(remainingGlobalMs / remainingWaves);
      nominalChunkBudgetMs = Math.min(60000, Math.max(minViableChunkBudgetMs, dynamicWaveBudgetMs));
    } else {
      nominalChunkBudgetMs = Math.min(60000, Math.max(minViableChunkBudgetMs, Math.floor(totalBudgetMs / estimatedWaves)));
    }
    const effectiveChunkTimeoutMs = Math.max(1, Math.min(nominalChunkBudgetMs, remainingGlobalMs));

    const contextPkg = buildContextPackage({
      ...changeSet,
      diffHunks: chunk.diffHunks,
      files: chunk.targetFiles.map(p => ({ path: p, additions: 0, deletions: 0 }))
    }, chunkTarget, {
      runId,
      repositoryRoot: options.cwd || process.cwd()
    });

    const prompt = buildEvidenceReviewPrompt({
      ...changeSet,
      diffHunks: chunk.diffHunks,
      files: chunk.targetFiles.map(p => ({ path: p, additions: 0, deletions: 0 }))
    }, role, limits, contextPkg, { patchObjective: options.patchObjective });

    const chunkStartTime = Date.now();
    let timedOutByScheduler = false;
    let cancelledByExternalSignal = false;
    const chunkController = new AbortController();
    activeChunkControllers.add(chunkController);

    let externalSignalHandler = null;
    if (options.signal) {
      if (options.signal.aborted) {
        cancelledByExternalSignal = true;
        chunkController.abort(options.signal.reason);
      } else {
        externalSignalHandler = () => {
          cancelledByExternalSignal = true;
          chunkController.abort(options.signal.reason);
        };
        options.signal.addEventListener("abort", externalSignalHandler, { once: true });
      }
    }

    const chunkTimer = setTimeout(() => {
      timedOutByScheduler = true;
      chunkController.abort("Chunk timeout budget exhausted.");
    }, effectiveChunkTimeoutMs);

    let chunkResult;
    try {
      chunkResult = await adapter.executeReview({
        runId: `${runId}-chunk-${idx}`,
        role,
        policyId: options.policyId || "TRI_PARTY_HETEROGENEOUS",
        timeoutMs: effectiveChunkTimeoutMs,
        signal: chunkController.signal,
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
        error: safeErrorMessage(err),
        findings: []
      };
    } finally {
      clearTimeout(chunkTimer);
      if (options.signal && externalSignalHandler) {
        options.signal.removeEventListener("abort", externalSignalHandler);
      }
      activeChunkControllers.delete(chunkController);
    }

    const chunkDurationMs = Date.now() - chunkStartTime;
    const isExternalCancellation = Boolean(
      cancelledByExternalSignal ||
      (options.signal && options.signal.aborted)
    );

    const isTimeout = !isExternalCancellation && (
      timedOutByScheduler ||
      timedOutByGlobal ||
      chunkController.signal.aborted ||
      chunkResult?.status === "timeout" ||
      chunkResult?.executionStatus === EXECUTION_STATUS.TIMEOUT ||
      chunkResult?.executionStatus === EXECUTION_STATUS.CANCELLED ||
      /timeout/i.test(chunkResult?.error || "")
    );

    let status = "failed";
    const rawResult = chunkResult;
    if (isTimeout) {
      status = "timeout";
      chunkResult = {
        ok: false,
        status: "timeout",
        executionStatus: EXECUTION_STATUS.TIMEOUT,
        findings: Array.isArray(rawResult?.findings) ? rawResult.findings : [],
        error: chunkResult?.error && /timeout/i.test(chunkResult.error)
          ? chunkResult.error
          : `Chunk timeout budget of ${effectiveChunkTimeoutMs}ms exhausted.`
      };
    } else if (isExternalCancellation) {
      status = "cancelled";
      chunkResult = {
        ok: false,
        status: "cancelled",
        executionStatus: EXECUTION_STATUS.CANCELLED,
        findings: Array.isArray(rawResult?.findings) ? rawResult.findings : [],
        error: `Execution cancelled via signal.`
      };
    } else if (chunkResult && chunkResult.ok) {
      status = "ok";
    }

    return {
      idx,
      chunk,
      status,
      timeoutCategory: isTimeout ? (remainingGlobalMs <= chunkDurationMs ? "global_exhaustion" : "chunk_deadline") : "none",
      durationMs: chunkDurationMs,
      budgetAllocatedMs: effectiveChunkTimeoutMs,
      result: chunkResult,
      rawResult
    };
  }

  let nextIndexToRun = 0;
  async function worker() {
    while (nextIndexToRun < chunks.length) {
      if (tier1ExecutionFailed || (globalDeadline - Date.now() <= 0) || (options.signal && options.signal.aborted)) {
        break;
      }
      const currentIdx = nextIndexToRun++;
      const chunk = chunks[currentIdx];
      const outcome = await executeChunk(chunk, currentIdx);
      chunkRawOutcomes[currentIdx] = outcome;
      completedChunkCount++;
      tryCommitCheckpoints();

      if (chunk.priorityTier === RISK_TIERS.TIER_1_CRITICAL && (!outcome.result || !outcome.result.ok)) {
        tier1ExecutionFailed = true;
        for (const ctrl of activeChunkControllers) {
          ctrl.abort("Tier 1 critical chunk execution failed.");
        }
      }
    }
  }

  try {
    const workerCount = Math.min(chunks.length, maxConcurrency);
    await Promise.all(Array.from({ length: workerCount }, () => worker()));
  } finally {
    clearTimeout(globalDeadlineTimer);
    if (options.signal && externalGlobalAbortHandler) {
      options.signal.removeEventListener("abort", externalGlobalAbortHandler);
    }
  }

  const wasCancelledExternally = Boolean(options.signal && options.signal.aborted);
  for (let i = 0; i < chunks.length; i++) {
    if (!chunkRawOutcomes[i]) {
      const isTier1Halt = Boolean(tier1ExecutionFailed && !wasCancelledExternally);
      chunkRawOutcomes[i] = {
        idx: i,
        chunk: chunks[i],
        status: wasCancelledExternally ? "cancelled" : (isTier1Halt ? "failed" : "timeout"),
        timeoutCategory: (wasCancelledExternally || isTier1Halt) ? "none" : "global_exhaustion",
        durationMs: 0,
        budgetAllocatedMs: 0,
        result: {
          ok: false,
          status: wasCancelledExternally ? "cancelled" : (isTier1Halt ? "failed" : "timeout"),
          executionStatus: wasCancelledExternally ? EXECUTION_STATUS.CANCELLED : (isTier1Halt ? EXECUTION_STATUS.ERROR : EXECUTION_STATUS.TIMEOUT),
          error: wasCancelledExternally
            ? `Execution cancelled before chunk ${chunks[i].chunkId} could execute: ${options.signal.reason || "signal aborted"}`
            : (isTier1Halt
              ? `Execution halted before chunk ${chunks[i].chunkId} could execute due to Tier 1 critical chunk failure.`
              : `Staged review global budget exhausted (${totalBudgetMs}ms) before chunk ${chunks[i].chunkId} could execute.`)
        }
      };
    }
  }

  // Deterministic Reduction in strict chunkIndex order (RFC-027-01 §8.8 / REMEDIATION-006)
  const accumulatedFindings = [];
  const coveredFiles = new Set();
  const omittedFiles = [];
  const chunkReceipts = [];

  for (let idx = 0; idx < chunks.length; idx++) {
    const chunk = chunks[idx];
    const outcome = chunkRawOutcomes[idx];
    const chunkResult = outcome.result;
    const chunkDurationMs = outcome.durationMs;

    // Handle chunk outcome
    if (chunkResult && chunkResult.ok) {
      let chunkCoverageValid = false;
      let contradictionError = null;

      try {
        const rawChunkFindings = safeGet(chunkResult, "findings");
        let findingsValid = true;
        const chunkCanonicalFindings = [];
        const findingsLen = safeArrayLength(rawChunkFindings);
        if (!safeIsArray(rawChunkFindings) || findingsLen < 0) {
          findingsValid = false;
        } else {
          for (let fIdx = 0; fIdx < findingsLen; fIdx++) {
            const fItem = safeGet(rawChunkFindings, fIdx);
            const canonical = canonicalizeFinding(fItem);
            if (!canonical) {
              findingsValid = false;
              break;
            }
            chunkCanonicalFindings.push(canonical);
          }
        }

        // Finding C: findings are atomic per provider chunk. A malformed suffix
        // invalidates the entire array; no valid prefix may enter salvage,
        // reconciliation, checkpoints, or any later trusted path.
        if (findingsValid) {
          accumulatedFindings.push(...chunkCanonicalFindings);
        }

        if (!findingsValid) {
          chunkCoverageValid = false;
          contradictionError = `Chunk ${chunk.chunkId} returned malformed or unreadable findings array`;
          for (const tf of chunk.targetFiles) {
            omittedFiles.push({
              file: tf,
              path: tf,
              code: COVERAGE_OMISSION_CODES.OUT_OF_SCOPE,
              reason: contradictionError
            });
          }
        } else {
          const chunkTargetSet = new Set(chunk.targetFiles.map(tf => normalizeCanonicalPath(tf)));

          const covObj = safeGet(chunkResult, "coverage");
          if (covObj && typeof covObj === "object" && !safeIsArray(covObj)) {
            const rawProvCovered = safeGet(covObj, "coveredFiles");
            const rawProvOmitted = safeGet(covObj, "omittedFiles");

            const coveredLen = safeArrayLength(rawProvCovered);
            const omittedLen = safeArrayLength(rawProvOmitted);

            const isCoveredValid = safeIsArray(rawProvCovered) && coveredLen >= 0;
            const isOmittedValid = safeIsArray(rawProvOmitted) && omittedLen >= 0;

            if (!isCoveredValid || !isOmittedValid) {
              chunkCoverageValid = false;
              contradictionError = `Chunk ${chunk.chunkId} returned malformed coverage arrays (coveredFiles valid: ${isCoveredValid}, omittedFiles valid: ${isOmittedValid})`;
              for (const tf of chunk.targetFiles) {
                omittedFiles.push({
                  file: tf,
                  path: tf,
                  code: "MALFORMED_COVERAGE",
                  reason: contradictionError
                });
              }
            } else {
              const provCovered = rawProvCovered;
              const provOmitted = rawProvOmitted;
              const coveredInThisChunk = new Set();
              const omittedInThisChunk = new Set();
              const omittedObjectsInThisChunk = [];
              let hasMalformedOmission = false;

              for (let cIdx = 0; cIdx < coveredLen; cIdx++) {
                const cf = safeGet(provCovered, cIdx);
                if (typeof cf === "string") {
                  const norm = normalizeCanonicalPath(cf);
                  if (chunkTargetSet.has(norm)) {
                    coveredInThisChunk.add(norm);
                  }
                }
              }

              for (let oIdx = 0; oIdx < omittedLen; oIdx++) {
                const omit = safeGet(provOmitted, oIdx);
                if (!omit || typeof omit !== "object" || safeIsArray(omit)) {
                  hasMalformedOmission = true;
                  omittedObjectsInThisChunk.push({
                    file: `malformed_entry_${oIdx}`,
                    path: `malformed_entry_${oIdx}`,
                    code: "MALFORMED_ENTRY",
                    reason: `Omission entry at index ${oIdx} is not a valid object in chunk ${chunk.chunkId}`
                  });
                  continue;
                }

                const fileProp = safeGet(omit, "file");
                const pathProp = safeGet(omit, "path");
                const targetProp = safeGet(omit, "target");

                const omitFile = (typeof fileProp === "string" && fileProp.trim())
                  ? fileProp.trim()
                  : ((typeof pathProp === "string" && pathProp.trim())
                    ? pathProp.trim()
                    : (typeof targetProp === "string" ? targetProp.trim() : null));

                if (!omitFile) {
                  hasMalformedOmission = true;
                  omittedObjectsInThisChunk.push({
                    file: `missing_path_${oIdx}`,
                    path: `missing_path_${oIdx}`,
                    code: "MALFORMED_ENTRY",
                    reason: `Omission entry at index ${oIdx} is missing a file path in chunk ${chunk.chunkId}`
                  });
                  continue;
                }

                const norm = normalizeCanonicalPath(omitFile);
                if (!chunkTargetSet.has(norm)) {
                  // Ignore provider claims outside chunk targetFiles
                  continue;
                }

                const codeVal = safeGet(omit, "code");
                const reasonVal = safeGet(omit, "reason");
                const code = typeof codeVal === "string" ? codeVal.trim() : "";
                const reason = typeof reasonVal === "string" ? reasonVal.trim() : "";
                const isValidCode = Boolean(code && ALLOWED_OMISSION_CODES.has(code));
                const isValidReason = Boolean(reason && reason.length > 0);

                if (isValidCode && isValidReason) {
                  omittedInThisChunk.add(norm);
                  omittedObjectsInThisChunk.push({
                    file: norm,
                    path: norm,
                    code,
                    reason
                  });
                } else {
                  hasMalformedOmission = true;
                  omittedObjectsInThisChunk.push({
                    file: norm,
                    path: norm,
                    code: code || "MALFORMED_OMISSION",
                    reason: reason || `Malformed omission code '${safeRenderUntrusted(codeVal)}'`
                  });
                }
              }

              if (hasMalformedOmission) {
                chunkCoverageValid = false;
                contradictionError = `Chunk ${chunk.chunkId} contains malformed or unauthorized omission entries`;
              }

              // P1-1 Requirement 1: Reject intra-chunk contradiction (covered AND omitted in same chunk)
              const intraChunkContradictions = chunk.targetFiles.filter(tf => {
                const norm = normalizeCanonicalPath(tf);
                return coveredInThisChunk.has(norm) && omittedInThisChunk.has(norm);
              });

              // P1-1 Requirement 3: Reject cross-chunk contradiction (covered in one chunk, omitted in another)
              const crossChunkContradictions = chunk.targetFiles.filter(tf => {
                const norm = normalizeCanonicalPath(tf);
                const wasCoveredPrior = coveredFiles.has(norm);
                const wasOmittedPrior = omittedFiles.some(o => normalizeCanonicalPath(o.file || o.path) === norm);
                return (omittedInThisChunk.has(norm) && wasCoveredPrior) ||
                       (coveredInThisChunk.has(norm) && wasOmittedPrior);
              });

              if (intraChunkContradictions.length > 0 || crossChunkContradictions.length > 0) {
                chunkCoverageValid = false;
                const badFile = intraChunkContradictions[0] || crossChunkContradictions[0];
                const isIntra = intraChunkContradictions.length > 0;
                contradictionError = isIntra
                  ? `Contradictory coverage declaration for '${badFile}' (both covered and omitted in chunk ${chunk.chunkId})`
                  : `Cross-chunk contradictory coverage for '${badFile}' (covered in one chunk, omitted in chunk ${chunk.chunkId})`;
                for (const cf of coveredInThisChunk) {
                  coveredFiles.add(cf);
                }
                for (const om of omittedObjectsInThisChunk) {
                  omittedFiles.push(om);
                }
                for (const tf of chunk.targetFiles) {
                  const norm = normalizeCanonicalPath(tf);
                  if (!omittedInThisChunk.has(norm)) {
                    omittedFiles.push({
                      file: tf,
                      code: COVERAGE_OMISSION_CODES.OUT_OF_SCOPE,
                      reason: contradictionError
                    });
                  }
                }
              } else if (hasMalformedOmission) {
                chunkCoverageValid = false;
                for (const cf of coveredInThisChunk) {
                  coveredFiles.add(cf);
                }
                for (const om of omittedObjectsInThisChunk) {
                  omittedFiles.push(om);
                }
                for (const tf of chunk.targetFiles) {
                  const norm = normalizeCanonicalPath(tf);
                  if (!coveredInThisChunk.has(norm) && !omittedInThisChunk.has(norm)) {
                    omittedFiles.push({
                      file: tf,
                      path: tf,
                      code: COVERAGE_OMISSION_CODES.OUT_OF_SCOPE,
                      reason: contradictionError
                    });
                  }
                }
              } else {
                // No contradiction: apply valid coverage and omissions
                for (const cf of coveredInThisChunk) {
                  coveredFiles.add(cf);
                }
                for (const om of omittedObjectsInThisChunk) {
                  omittedFiles.push(om);
                }

                // Per-chunk coverage validation: All targetFiles in this chunk must be either covered or omitted
                const uncoveredInChunk = chunk.targetFiles.filter(tf => {
                  const norm = normalizeCanonicalPath(tf);
                  return !coveredInThisChunk.has(norm) && !omittedInThisChunk.has(norm);
                });

                if (uncoveredInChunk.length === 0) {
                  chunkCoverageValid = true;
                } else {
                  for (const utf of uncoveredInChunk) {
                    const normUtf = normalizeCanonicalPath(utf);
                    if (!omittedObjectsInThisChunk.some(o => normalizeCanonicalPath(o.file || o.path) === normUtf)) {
                      omittedFiles.push({
                        file: utf,
                        path: utf,
                        code: COVERAGE_OMISSION_CODES.OUT_OF_SCOPE,
                        reason: `File '${utf}' was not covered or declared omitted in chunk ${chunk.chunkId}`
                      });
                    }
                  }
                }
              }
            }
          } else {
            // FAIL CLOSED (Finding 2): Missing coverage object does not grant coverage!
            for (const tf of chunk.targetFiles) {
              omittedFiles.push({
                file: tf,
                code: COVERAGE_OMISSION_CODES.SIZE_LIMIT,
                reason: `Provider returned no coverage object for chunk ${chunk.chunkId}`
              });
            }
          }
        }
      } catch (chunkProcErr) {
        chunkCoverageValid = false;
        contradictionError = `Chunk result processing failed: ${safeErrorMessage(chunkProcErr)}`;
        for (const tf of chunk.targetFiles) {
          omittedFiles.push({
            file: tf,
            code: COVERAGE_OMISSION_CODES.SIZE_LIMIT,
            reason: contradictionError
          });
        }
      }

      chunkReceipts.push({
        chunkId: chunk.chunkId,
        chunkIndex: chunk.chunkIndex,
        totalChunks: chunk.totalChunks,
        status: chunkCoverageValid ? "completed" : "failed",
        durationMs: chunkDurationMs,
        findingsCount: Math.max(0, safeArrayLength(safeGet(chunkResult, "findings"))),
        error: chunkCoverageValid ? undefined : (contradictionError || "Chunk target files not covered")
      });

      if (chunkCoverageValid) {
        // Persist successful chunk checkpoint
        checkpointStore.saveCheckpoint(runId, {
          runId,
          stage: STAGED_REVIEW_STAGES.STAGE_2_DEEP_REVIEW,
          salvagedFindings: accumulatedFindings,
          completedChunks: idx + 1,
          totalChunks: chunks.length
        });
      } else {
        // Chunk had invalid coverage: save salvage checkpoint
        checkpointStore.saveCheckpoint(runId, {
          runId,
          stage: STAGED_REVIEW_STAGES.STAGE_2_DEEP_REVIEW,
          salvagedFindings: accumulatedFindings,
          completedChunks: idx,
          totalChunks: chunks.length,
          omittedFiles
        });
        if (chunk.priorityTier === RISK_TIERS.TIER_1_CRITICAL) {
          for (let remIdx = idx + 1; remIdx < chunks.length; remIdx++) {
            const remChunk = chunks[remIdx];
            const remOutcome = chunkRawOutcomes[remIdx];
            const isRemTimeout = remOutcome?.status === "timeout" || remOutcome?.result?.executionStatus === EXECUTION_STATUS.TIMEOUT;
            const isRemCancelled = remOutcome?.status === "cancelled" || remOutcome?.result?.executionStatus === EXECUTION_STATUS.CANCELLED;
            for (const tf of remChunk.targetFiles) {
              omittedFiles.push({
                file: tf,
                code: isRemTimeout ? COVERAGE_OMISSION_CODES.TIMEOUT : COVERAGE_OMISSION_CODES.OUT_OF_SCOPE,
                reason: `Halted due to Tier 1 critical chunk coverage failure in chunk ${chunk.chunkId}`
              });
            }
            chunkReceipts.push({
              chunkId: remChunk.chunkId,
              chunkIndex: remChunk.chunkIndex,
              totalChunks: remChunk.totalChunks,
              status: isRemTimeout ? "timeout" : (isRemCancelled ? "cancelled" : "failed"),
              durationMs: remOutcome?.durationMs || 0,
              error: `Halted due to Tier 1 critical chunk coverage failure in chunk ${chunk.chunkId}`
            });
          }
          break;
        }
      }
    } else {
      // Chunk Failed, Cancelled, or Timed Out (P1-06)
      const isChunkCancelled = outcome.status === "cancelled" || chunkResult?.executionStatus === EXECUTION_STATUS.CANCELLED;
      const isTimeout = !isChunkCancelled && (
        outcome.status === "timeout" ||
        chunkResult?.status === "timeout" ||
        chunkResult?.executionStatus === EXECUTION_STATUS.TIMEOUT ||
        /timeout/i.test(chunkResult?.error || "")
      );

      // Salvage valid findings even if chunk timed out or failed (RFC-027-01 partial salvage)
      const rawChunkFindings = safeGet(chunkResult, "findings") || safeGet(outcome.rawResult, "findings");
      const findingsLen = safeArrayLength(rawChunkFindings);
      if (safeIsArray(rawChunkFindings) && findingsLen > 0) {
        let findingsValid = true;
        const chunkCanonicalFindings = [];
        for (let fIdx = 0; fIdx < findingsLen; fIdx++) {
          const fItem = safeGet(rawChunkFindings, fIdx);
          const canonical = canonicalizeFinding(fItem);
          if (!canonical) {
            findingsValid = false;
            break;
          }
          chunkCanonicalFindings.push(canonical);
        }
        if (findingsValid) {
          accumulatedFindings.push(...chunkCanonicalFindings);
        }
      }

      for (const tf of chunk.targetFiles) {
        omittedFiles.push({
          file: tf,
          code: isTimeout
            ? COVERAGE_OMISSION_CODES.TIMEOUT
            : (isChunkCancelled ? COVERAGE_OMISSION_CODES.OUT_OF_SCOPE : COVERAGE_OMISSION_CODES.SIZE_LIMIT),
          reason: chunkResult?.error || (isChunkCancelled ? "Execution cancelled via signal" : `Chunk ${chunk.chunkId} failed to complete execution.`)
        });
      }
      chunkReceipts.push({
        chunkId: chunk.chunkId,
        chunkIndex: chunk.chunkIndex,
        totalChunks: chunk.totalChunks,
        status: isTimeout ? "timeout" : (isChunkCancelled ? "cancelled" : "failed"),
        durationMs: chunkDurationMs,
        error: chunkResult?.error || (isChunkCancelled ? "Execution cancelled" : "Execution failed")
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
        for (let remIdx = idx + 1; remIdx < chunks.length; remIdx++) {
          const remChunk = chunks[remIdx];
          const remOutcome = chunkRawOutcomes[remIdx];
          const isRemTimeout = remOutcome?.status === "timeout" || remOutcome?.result?.executionStatus === EXECUTION_STATUS.TIMEOUT;
          const isRemCancelled = remOutcome?.status === "cancelled" || remOutcome?.result?.executionStatus === EXECUTION_STATUS.CANCELLED;
          for (const tf of remChunk.targetFiles) {
            omittedFiles.push({
              file: tf,
              code: isRemTimeout ? COVERAGE_OMISSION_CODES.TIMEOUT : COVERAGE_OMISSION_CODES.OUT_OF_SCOPE,
              reason: `Halted due to Tier 1 critical chunk failure in chunk ${chunk.chunkId}`
            });
          }
          chunkReceipts.push({
            chunkId: remChunk.chunkId,
            chunkIndex: remChunk.chunkIndex,
            totalChunks: remChunk.totalChunks,
            status: isRemTimeout ? "timeout" : (isRemCancelled ? "cancelled" : "failed"),
            durationMs: remOutcome?.durationMs || 0,
            error: `Halted due to Tier 1 critical chunk failure in chunk ${chunk.chunkId}`
          });
        }
        break;
      }
    }
  }

  // Stage 3: Finding Reconciliation
  let reconciledFindings = [];
  let reconciliationFailed = false;
  let reconciliationError = null;
  try {
    reconciledFindings = reconcileFindings(accumulatedFindings, adapter.providerName || role);
  } catch (recErr) {
    reconciliationFailed = true;
    reconciliationError = `Finding reconciliation failed: ${safeErrorMessage(recErr)}`;
  }

  // Evaluate Coverage
  const coverageEval = evaluateCoverageContract(changeSet, Array.from(coveredFiles), omittedFiles);

  const allReceiptsSucceeded = chunkReceipts.length > 0 && chunkReceipts.every(r => r.status === "completed");
  const hasTimeouts = omittedFiles.some(o => o.code === COVERAGE_OMISSION_CODES.TIMEOUT) || chunkReceipts.some(r => r.status === "timeout");
  const hasCancellations = chunkReceipts.some(r => r.status === "cancelled");
  const isComplete = coverageEval.isComplete && allReceiptsSucceeded && !hasTimeouts && !hasCancellations && !reconciliationFailed;
  const finalStatus = isComplete ? "completed" : "incomplete";

  // Clean up checkpoint on complete success
  if (isComplete) {
    checkpointStore.clearCheckpoint(runId);
  }

  return {
    runId,
    ok: isComplete,
    executionStatus: isComplete ? EXECUTION_STATUS.SUCCESS : (hasCancellations ? EXECUTION_STATUS.CANCELLED : EXECUTION_STATUS.INCOMPLETE),
    error: isComplete ? undefined : (reconciliationError || coverageEval.violations?.[0] || (hasCancellations ? "Execution cancelled via signal." : (hasTimeouts ? "One or more chunks timed out during review." : "Staged review execution incomplete."))),
    providerIdentity: {
      provider: adapter.providerName || role,
      model: adapter.modelName || "unknown-model",
      family: adapter.family || "unknown",
      transport: "cli-staged",
      runId
    },
    status: finalStatus,
    findings: reconciledFindings,
    coverage: {
      ...coverageEval.declaration,
      isComplete
    },
    violations: coverageEval.violations,
    receipts: chunkReceipts,
    telemetry: {
      stagedFallbackUsed: true,
      chunkCount: chunks.length,
      maxConcurrency,
      budgetAllocatedMs: totalBudgetMs,
      globalDeadlineRemainingMs: Math.max(0, globalDeadline - Date.now()),
      feasibility,
      chunkTimeoutCount: chunkReceipts.filter(r => r.status === "timeout").length
    }
  };
}
