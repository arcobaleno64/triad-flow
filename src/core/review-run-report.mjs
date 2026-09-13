/**
 * Review Run Report Generator (PR-04: Unified Run Status & Auditable Report)
 *
 * Emits a canonical, immutable review-run.json audit artifact.
 * Accurately distinguishes clean passes, blocking findings, no-ops, incomplete runs,
 * and configuration/execution errors without capability leakage.
 */

import { deepFreeze } from "./consensus-state.mjs";

export const REVIEW_RUN_STATUS = Object.freeze({
  REVIEWED_CLEAN: "reviewed-clean",
  REVIEWED_WITH_FINDINGS: "reviewed-with-findings",
  NO_CHANGES: "no-changes",
  INCOMPLETE: "incomplete",
  CONFIGURATION_ERROR: "configuration-error",
  EXECUTION_ERROR: "execution-error"
});

export const STATUS_EXIT_CODES = Object.freeze({
  [REVIEW_RUN_STATUS.REVIEWED_CLEAN]: 0,
  [REVIEW_RUN_STATUS.NO_CHANGES]: 0,
  [REVIEW_RUN_STATUS.REVIEWED_WITH_FINDINGS]: 1,
  [REVIEW_RUN_STATUS.INCOMPLETE]: 1,
  [REVIEW_RUN_STATUS.CONFIGURATION_ERROR]: 2,
  [REVIEW_RUN_STATUS.EXECUTION_ERROR]: 3
});

/**
 * Builds an auditable, canonical review-run.json report.
 * Notice: This artifact is strictly an audit log and cannot be reused as an in-process capability.
 */
export const TOOL_VERSION = "2.1.0";

export function buildReviewRunReport(params = {}) {
  const {
    runId = "unassigned-run",
    timestamp = new Date().toISOString(),
    status = REVIEW_RUN_STATUS.INCOMPLETE,
    exitCode = STATUS_EXIT_CODES[status] ?? 1,
    changeSet = null,
    policy = { id: "STRICT_HETEROGENEOUS", strict: false },
    routing = null,
    providers = [],
    consensus = null,
    gate = null,
    error = null
  } = params;

  // Validate status is an allowed enum
  const validStatus = Object.values(REVIEW_RUN_STATUS).includes(status)
    ? status
    : REVIEW_RUN_STATUS.INCOMPLETE;

  // Format scope details from changeSet
  const scope = {
    mode: changeSet?.scopeMode || "unknown",
    base: changeSet?.repository?.baseSha || null,
    head: changeSet?.repository?.headSha || null,
    contentDigest: changeSet?.contentDigest || null,
    totalFiles: Number(changeSet?.totalFiles || 0),
    totalAdditions: Number(changeSet?.totalAdditions || 0),
    totalDeletions: Number(changeSet?.totalDeletions || 0)
  };

  // Format providers execution record
  const providerRecords = (Array.isArray(providers) ? providers : []).map(p => ({
    role: String(p.role || "unknown"),
    provider: String(p.provider || p.providerIdentity?.provider || "unknown-provider"),
    model: String(p.model || p.providerIdentity?.model || "unknown-model"),
    transport: String(p.transport || p.providerIdentity?.transport || "unknown"),
    executionStatus: String(p.executionStatus || "unknown"),
    coverage: {
      coveredFiles: Array.isArray(p.coverage?.coveredFiles) ? [...p.coverage.coveredFiles] : [],
      omittedFiles: Array.isArray(p.coverage?.omittedFiles) ? p.coverage.omittedFiles.map(o => ({
        path: String(o.path || "unknown"),
        reason: String(o.reason || "unspecified")
      })) : []
    },
    usage: p.usage ? {
      promptTokens: p.usage.promptTokens ?? null,
      completionTokens: p.usage.completionTokens ?? null,
      totalTokens: p.usage.totalTokens ?? null
    } : null
  }));

  // Format findings summary
  const findingsList = Array.isArray(consensus?.findings) ? consensus.findings : [];
  const blockingFindings = findingsList.filter(f => /critical|high/i.test(f.severity || ""));

  const findingsSummary = {
    total: findingsList.length,
    blocking: blockingFindings.length,
    findingKeys: findingsList.map(f => `${f.file || "unknown"}:${f.line_start || 1}:${f.ruleId || f.title || "issue"}`)
  };

  const report = {
    schemaVersion: "1.0.0",
    runId: String(runId),
    timestamp: String(timestamp),
    tool: {
      name: "@arcobaleno64/triad-flow",
      version: TOOL_VERSION
    },
    status: validStatus,
    exitCode: Number(exitCode),
    scope,
    policy: {
      id: String(policy.id || "STRICT_HETEROGENEOUS"),
      strict: Boolean(policy.strict)
    },
    routing: routing ? {
      mode: String(routing.mode || "single"),
      highestRisk: Number(routing.highestRisk ?? 2),
      reason: String(routing.reason || "")
    } : null,
    providers: providerRecords,
    findings: findingsSummary,
    consensus: consensus ? {
      verdict: String(consensus.verdict || "error"),
      quorumReached: Boolean(consensus.quorumReached),
      consensusProof: String(consensus.consensusProof || "")
    } : null,
    gate: gate ? {
      decision: String(gate.decision || "block"),
      reason: String(gate.reason || "")
    } : null,
    error: error ? String(error) : null
  };

  return deepFreeze(report);
}
