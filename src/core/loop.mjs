/**
 * Hardened Loop Engineering: Closed-Loop Consensus Resolution & OODA Remediation
 */

import crypto from "node:crypto";

export const SEVERITY_WEIGHTS = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0
};

export function aggregateConsensus(macroReport = {}, microReport = {}) {
  // 1. Sentry Quorum & Health Check
  const macroHealthy = macroReport && !macroReport.error && Array.isArray(macroReport.findings);
  const microHealthy = microReport && !microReport.error && Array.isArray(microReport.findings);

  if (!macroHealthy && !microHealthy) {
    return {
      verdict: "error",
      quorumReached: false,
      totalFindings: 0,
      findings: [],
      consensusProof: "Consensus aborted: All sentry nodes failed or timed out (Quorum Failure)."
    };
  }

  const macroFindings = macroHealthy ? macroReport.findings : [];
  const microFindings = microHealthy ? microReport.findings : [];

  // 2. Strict Severity Escalation Merge (Prevents Downgrade Attacks & Loss on Dedupe)
  const findingsMap = new Map();

  function ingest(findings, source) {
    for (const f of findings) {
      if (!f || typeof f !== "object") continue;
      const file = String(f.file || "").trim();
      const lineStart = Math.max(1, Math.floor(Number(f.line_start) || 1));
      const title = String(f.title || "").trim();
      const key = `${file}:${lineStart}:${title}`.toLowerCase();

      const incomingSev = String(f.severity || "info").toLowerCase();
      const incomingWeight = SEVERITY_WEIGHTS[incomingSev] ?? 0;

      if (!findingsMap.has(key)) {
        findingsMap.set(key, { ...f, severity: incomingSev, sources: [source], corroborations: 1 });
      } else {
        const existing = findingsMap.get(key);
        existing.sources.push(source);
        existing.corroborations += 1;
        const currentWeight = SEVERITY_WEIGHTS[existing.severity] ?? 0;
        if (incomingWeight > currentWeight) {
          existing.severity = incomingSev; // Preserve highest severity
        }
      }
    }
  }

  ingest(macroFindings, "macro-sentry");
  ingest(microFindings, "micro-arbiter");

  const deduplicated = Array.from(findingsMap.values());
  const hasBlockers = deduplicated.some(f => /critical|high/i.test(f.severity || ""));
  const verdict = hasBlockers ? "needs-attention" : (deduplicated.length > 0 ? "warning" : "approve");

  return {
    verdict,
    quorumReached: true,
    totalFindings: deduplicated.length,
    findings: deduplicated,
    consensusProof: hasBlockers
      ? "Consensus reached: Blocking vulnerabilities identified by heterogeneous sentries."
      : "Consensus reached: Clean diff or minor non-blocking suggestions."
  };
}

export class OodaLoopController {
  constructor(options = {}) {
    this.maxIterations = options.maxIterations || 3;
    this.currentIteration = 0;
    this.historyHashes = new Set();
  }

  computeStateHash(findings = []) {
    const serialized = findings
      .map(f => `${f.file}:${f.line_start}:${f.severity}:${f.title}`)
      .sort()
      .join("|");
    return crypto.createHash("sha256").update(serialized).digest("hex");
  }

  step(consensusReport) {
    this.currentIteration += 1;

    if (consensusReport.verdict === "approve") {
      return { status: "completed", action: "exit_green" };
    }

    if (!consensusReport.quorumReached) {
      return { status: "failed", action: "escalate_to_human", reason: "Sentry Quorum Failure." };
    }

    if (this.currentIteration > this.maxIterations) {
      return {
        status: "circuit_broken",
        action: "escalate_to_human",
        reason: `Exceeded max self-healing iterations (${this.maxIterations}). Livelock prevented.`
      };
    }

    const stateHash = this.computeStateHash(consensusReport.findings);
    if (this.historyHashes.has(stateHash)) {
      return {
        status: "oscillation_detected",
        action: "escalate_to_human",
        reason: "Remediation oscillation detected: Repeated error state observed. Livelock prevented."
      };
    }
    this.historyHashes.add(stateHash);

    return {
      status: "remediating",
      action: "apply_patch",
      iteration: this.currentIteration,
      vector: synthesizeRemediationVector(consensusReport)
    };
  }
}

export function synthesizeRemediationVector(consensusReport) {
  if (!consensusReport || consensusReport.verdict === "approve") {
    return { needsFix: false, instructions: [], autoPatchContext: null };
  }

  const findings = consensusReport.findings || [];
  const instructions = findings.map((f, idx) => ({
    step: idx + 1,
    targetFile: f.file,
    severity: f.severity,
    issue: f.title,
    action: f.recommendation || `Fix ${f.title} in ${f.file}`,
    sources: f.sources || ["sentry"]
  }));

  return {
    needsFix: true,
    summary: `Remediation required for ${instructions.length} finding(s).`,
    instructions,
    autoPatchContext: {
      criticalCount: findings.filter(f => /critical|high/i.test(f.severity || "")).length,
      filesToTouch: [...new Set(findings.map(f => f.file))]
    }
  };
}
