/**
 * Hardened Loop Engineering: Multi-Agent Consensus Aggregation, In-Process Capability Issuer, OODA Closed Loop & Anti-Livelock
 */

import crypto from "node:crypto";
import {
  issueConsensusFromEvidence,
  isTrustedConsensus,
  hasBlockingFindings,
  deepFreeze,
  VALID_SEVERITY_SET
} from "./consensus-state.mjs";
import { validateSentryReport } from "./harness.mjs";

export const SEVERITY_WEIGHTS = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0
};

export const QuorumPolicies = {
  STRICT_HETEROGENEOUS: (metadataMap = {}) => {
    let macroRec = null;
    let microRec = null;

    for (const [id, rec] of Object.entries(metadataMap)) {
      if (rec.role === "macro") macroRec = rec;
      if (rec.role === "micro") microRec = rec;
    }

    const reached = Boolean(macroRec?.healthy && microRec?.healthy);
    return {
      quorumReached: reached,
      selectedReportIds: reached ? [macroRec.id, microRec.id] : [],
      reason: reached ? null : "Quorum Failure: Both macro and micro sentries must be healthy."
    };
  },

  SINGLE_SENTRY: (metadataMap = {}, requiredRole = "macro") => {
    let target = null;
    for (const [id, rec] of Object.entries(metadataMap)) {
      if (rec.role === requiredRole || rec.source === requiredRole) {
        target = rec;
        break;
      }
    }
    const reached = Boolean(target?.healthy);
    return {
      quorumReached: reached,
      selectedReportIds: reached ? [target.id] : [],
      reason: reached ? null : `Quorum Failure: Designated sentry '${requiredRole}' is unhealthy or missing.`
    };
  },

  K_OF_N: (metadataMap = {}, requiredCount = 2) => {
    const healthyIds = [];
    for (const [id, rec] of Object.entries(metadataMap)) {
      if (rec.healthy) {
        healthyIds.push(id);
      }
    }
    const reached = healthyIds.length >= requiredCount;
    return {
      quorumReached: reached,
      selectedReportIds: reached ? healthyIds.slice(0, requiredCount) : [],
      reason: reached ? null : `Quorum Failure: Need ${requiredCount} valid sentries, but only ${healthyIds.length} available.`
    };
  }
};

export function canonicalFindingKey(finding) {
  if (!finding) return "unknown:1:general";
  const file = (finding.file || finding.path || "root").toLowerCase().replace(/\\/g, "/");
  const lineStart = Math.max(1, Number(finding.line_start || finding.line) || 1);
  const lineBucket = Math.floor(lineStart / 15) * 15;

  const rawTitle = (finding.title || finding.message || "issue").toLowerCase();
  const cweMatch = rawTitle.match(/cwe-\d+/i);
  const cwe = cweMatch ? cweMatch[0].toUpperCase() : "";

  const token = cwe || rawTitle.replace(/[^a-z0-9]/g, "").slice(0, 16);
  return `${file}:${lineBucket}:${token}`;
}

/**
 * Aggregates multi-agent consensus and mints an In-Process Trusted Consensus Capability.
 * Aggregator owns canonical validated report map bound to an invocation-local nonce.
 */
export function aggregateConsensus(reportsInput, ...rest) {
  let rawReports = {};
  let options = {};

  if (
    reportsInput &&
    typeof reportsInput === "object" &&
    !Array.isArray(reportsInput) &&
    !reportsInput.findings &&
    !reportsInput.error &&
    (reportsInput.macro || reportsInput.micro || rest.length === 0)
  ) {
    rawReports = reportsInput;
    options = rest[0] || {};
  } else {
    rawReports = {
      macro: reportsInput || null,
      micro: rest[0] || null
    };
    options = rest[1] || {};
  }

  // 1. Invocation-Local Evidence Binding (Unique random nonce per invocation)
  const invocationNonce = crypto.randomUUID();
  const validatedReportsMap = new Map();
  const metadataMap = {};

  // 2. Invariant (PR-05): Strict Heterogeneity Reference Check
  if (rawReports && typeof rawReports === "object") {
    if (rawReports.macro && rawReports.micro && rawReports.macro === rawReports.micro) {
      return issueConsensusFromEvidence({
        validatedReportsMap,
        quorumResult: { quorumReached: false, selectedReportIds: [] },
        invocationNonce,
        verdict: "error",
        consensusProof: "Consensus aborted: Heterogeneity violation. Macro and micro roles point to identical object reference."
      });
    }
  }

  for (const [key, raw] of Object.entries(rawReports || {})) {
    const reportId = `ev:${invocationNonce}:${key}`;
    const validated = validateSentryReport(raw);

    if (!validated.valid) {
      validatedReportsMap.set(reportId, {
        id: reportId,
        role: key,
        healthy: false,
        error: validated.reason,
        findings: []
      });
      metadataMap[reportId] = {
        id: reportId,
        role: key,
        healthy: false,
        error: validated.reason,
        source: raw?.name || raw?.source || key
      };
    } else {
      const canonicalFindings = deepFreeze(validated.report.findings.map(f => ({ ...f })));
      validatedReportsMap.set(reportId, {
        id: reportId,
        role: key,
        healthy: true,
        findings: canonicalFindings,
        source: validated.report.name || validated.report.source || key
      });
      metadataMap[reportId] = {
        id: reportId,
        role: key,
        healthy: true,
        count: canonicalFindings.length,
        source: validated.report.name || validated.report.source || key
      };
    }
  }

  // 3. Resolve Policy Function
  const policyFn = typeof options.policy === "function"
    ? options.policy
    : (QuorumPolicies[options.policy] || QuorumPolicies.STRICT_HETEROGENEOUS);

  let quorumResult;
  try {
    quorumResult = policyFn(deepFreeze({ ...metadataMap }));
    if (!quorumResult || typeof quorumResult.quorumReached !== "boolean") {
      throw new TypeError("Quorum policy returned malformed result (missing boolean quorumReached).");
    }
  } catch (err) {
    return issueConsensusFromEvidence({
      validatedReportsMap,
      quorumResult: { quorumReached: false, selectedReportIds: [] },
      invocationNonce,
      verdict: "error",
      consensusProof: `Consensus aborted: Quorum evaluation error (${err.message}). Fail-closed enforced.`
    });
  }

  if (!quorumResult.quorumReached) {
    return issueConsensusFromEvidence({
      validatedReportsMap,
      quorumResult: { quorumReached: false, selectedReportIds: [] },
      invocationNonce,
      verdict: "error",
      consensusProof: quorumResult.reason || "Consensus aborted: Quorum Failure."
    });
  }

  // 4. Provenance Validation: Selected IDs must reference actual healthy aggregator-owned reports
  if (!Array.isArray(quorumResult.selectedReportIds) || quorumResult.selectedReportIds.length === 0) {
    return issueConsensusFromEvidence({
      validatedReportsMap,
      quorumResult: { quorumReached: false, selectedReportIds: [] },
      invocationNonce,
      verdict: "error",
      consensusProof: "Consensus aborted: Quorum declared true but no selected report IDs provided. Fail-closed enforced."
    });
  }

  // Duplicate ID detection (Sybil check)
  const selectedUniqueIds = new Set(quorumResult.selectedReportIds);
  if (selectedUniqueIds.size !== quorumResult.selectedReportIds.length) {
    return issueConsensusFromEvidence({
      validatedReportsMap,
      quorumResult: { quorumReached: false, selectedReportIds: [] },
      invocationNonce,
      verdict: "error",
      consensusProof: "Consensus aborted: Duplicate report ID selected in quorum. Sybil inflation rejected."
    });
  }

  const collectedFindings = [];
  const validSelectedIds = [];

  for (const id of selectedUniqueIds) {
    if (!validatedReportsMap.has(id)) {
      return issueConsensusFromEvidence({
        validatedReportsMap,
        quorumResult: { quorumReached: false, selectedReportIds: [] },
        invocationNonce,
        verdict: "error",
        consensusProof: `Consensus aborted: Selected report ID '${id}' is unknown to current invocation. Forged or stale evidence rejected.`
      });
    }

    const reportRec = validatedReportsMap.get(id);
    if (!reportRec.healthy) {
      return issueConsensusFromEvidence({
        validatedReportsMap,
        quorumResult: { quorumReached: false, selectedReportIds: [] },
        invocationNonce,
        verdict: "error",
        consensusProof: `Consensus aborted: Selected report ID '${id}' is in error state (${reportRec.error}). Fail-closed enforced.`
      });
    }

    validSelectedIds.push(id);
    const sentrySource = reportRec.source || reportRec.role || id;
    for (const f of reportRec.findings) {
      collectedFindings.push({ finding: f, source: sentrySource });
    }
  }

  // 5. Finding Deduplication (Highest severity preservation & distinct sentry corroboration)
  const findingsMap = new Map();
  for (const { finding: f, source } of collectedFindings) {
    const key = `${f.file}:${f.line_start}:${f.title}`.toLowerCase();
    const incomingSev = f.severity;
    const incomingWeight = SEVERITY_WEIGHTS[incomingSev] ?? 0;

    if (!findingsMap.has(key)) {
      findingsMap.set(key, {
        ...f,
        sources: [source],
        corroborations: 1
      });
    } else {
      const existing = findingsMap.get(key);
      if (!existing.sources.includes(source)) {
        existing.sources.push(source);
        existing.corroborations = existing.sources.length;
      }
      const currentWeight = SEVERITY_WEIGHTS[existing.severity] ?? 0;
      if (incomingWeight > currentWeight) {
        existing.severity = incomingSev;
      }
      if (!existing.ruleId && f.ruleId) existing.ruleId = f.ruleId;
      if (!existing.cwe && f.cwe) existing.cwe = f.cwe;
      if (!existing.type && f.type) existing.type = f.type;
    }
  }

  const deduplicated = Array.from(findingsMap.values());
  const hasBlockers = hasBlockingFindings(deduplicated);
  const verdict = hasBlockers ? "needs-attention" : (deduplicated.length > 0 ? "warning" : "approve");
  const consensusProof = hasBlockers
    ? `Consensus reached: Blocking vulnerabilities identified by sentry quorum (${validSelectedIds.join(", ")}).`
    : `Consensus reached: Clean diff or non-blocking suggestions from quorum (${validSelectedIds.join(", ")}).`;

  // 6. Issue In-Process Trusted Capability (Self-Validated & Deeply Frozen)
  return issueConsensusFromEvidence({
    validatedReportsMap,
    quorumResult: { quorumReached: true, selectedReportIds: validSelectedIds },
    invocationNonce,
    deduplicatedFindings: deduplicated,
    verdict,
    consensusProof
  });
}

export function synthesizeRemediationVector(consensusReport) {
  const issues = (consensusReport?.findings || []).map(f => ({
    targetFile: f.file,
    line: f.line_start,
    vulnerability: f.title,
    severity: f.severity,
    recommendation: f.recommendation || "Apply secure coding pattern and validate bounds."
  }));

  return {
    strategy: "DIRECT_AST_PATCH",
    targetFiles: Array.from(new Set(issues.map(i => i.targetFile).filter(Boolean))),
    remediationDirectives: issues
  };
}

/**
 * Hardened OODA Loop Controller: State machine with Public Trust Boundary & Gate/OODA Equivalence
 */
export class OodaLoopController {
  constructor(options = {}) {
    this.maxIterations = options.maxIterations || 3;
    this.similarityThreshold = options.similarityThreshold || 0.8;
    this.reset();
  }

  reset() {
    this.currentIteration = 0;
    this.historyFingerprints = [];
    this.patchHashes = new Set();
  }

  step(consensusReport, patchDiff = "") {
    // 1. Mandatory In-Process Capability Verification
    if (!isTrustedConsensus(consensusReport)) {
      return {
        status: "failed",
        action: "escalate_to_human",
        reason: "Consensus validation rejected: Untrusted consensus capability (UNTRUSTED_CONSENSUS)."
      };
    }

    // 2. Strict Quorum & Verdict Invariant
    if (!consensusReport.quorumReached || consensusReport.verdict === "error") {
      return {
        status: "failed",
        action: "escalate_to_human",
        reason: consensusReport.consensusProof || "Sentry Quorum Failure or error verdict."
      };
    }

    // 3. Gate/OODA Equivalence Check: If blocking findings present, MUST NOT exit green
    if (hasBlockingFindings(consensusReport.findings)) {
      if (consensusReport.verdict === "approve") {
        return {
          status: "failed",
          action: "escalate_to_human",
          reason: "Semantic contradiction: 'approve' verdict cannot contain critical/high blocking findings."
        };
      }
    }

    // 4. Success State Transition
    if (consensusReport.verdict === "approve") {
      return { status: "completed", action: "exit_green" };
    }

    // 5. Remediation Iteration Limit & Anti-Livelock
    this.currentIteration += 1;
    if (this.currentIteration > this.maxIterations) {
      return {
        status: "circuit_broken",
        action: "escalate_to_human",
        reason: `Exceeded max self-healing iterations (${this.maxIterations}). Livelock prevented.`
      };
    }

    // 6. Patch Hash Cycle Detection
    if (patchDiff) {
      const patchHash = crypto.createHash("sha256").update(patchDiff.trim()).digest("hex");
      if (this.patchHashes.has(patchHash)) {
        return {
          status: "patch_oscillation_detected",
          action: "escalate_to_human",
          reason: "Patch cycle detected: Identical diff generated in previous iteration. Livelock prevented."
        };
      }
      this.patchHashes.add(patchHash);
    }

    // 7. Semantic Stagnation / Jaccard Similarity Detection
    const currentSet = this.getFindingKeySet(consensusReport.findings || []);
    for (const prevSet of this.historyFingerprints) {
      const sim = this.calculateJaccardSimilarity(currentSet, prevSet);
      if (sim >= this.similarityThreshold && this.currentIteration > 1) {
        return {
          status: "oscillation_detected",
          action: "escalate_to_human",
          reason: `Remediation stagnation/oscillation detected (Similarity: ${(sim * 100).toFixed(1)}% >= ${(this.similarityThreshold * 100)}%). Livelock prevented.`
        };
      }
    }
    this.historyFingerprints.push(currentSet);

    return {
      status: "remediating",
      action: "apply_patch",
      iteration: this.currentIteration,
      vector: synthesizeRemediationVector(consensusReport)
    };
  }

  getFindingKeySet(findings = []) {
    return new Set(findings.map(canonicalFindingKey));
  }

  calculateJaccardSimilarity(setA, setB) {
    if (setA.size === 0 && setB.size === 0) return 1.0;
    if (setA.size === 0 || setB.size === 0) return 0.0;
    let intersection = 0;
    for (const item of setA) {
      if (setB.has(item)) intersection += 1;
    }
    const union = setA.size + setB.size - intersection;
    return union === 0 ? 1.0 : intersection / union;
  }
}
