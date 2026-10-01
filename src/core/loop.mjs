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
import { getProviderFamily } from "./benchmark-pilot.mjs";

export const SEVERITY_WEIGHTS = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0
};

/**
 * Resolves and normalizes a raw provider family string or fallback source to its verified canonical family.
 *
 * @param {string} [rawFamily=""] - Explicit family name if provided
 * @param {string} [fallbackSource=""] - Provider command/binary/name to infer family from
 * @returns {string} Normalized canonical provider family, or "unknown" under Default-Deny
 */
export function resolveCanonicalProviderFamily(rawFamily = "", fallbackSource = "") {
  if (typeof rawFamily === "string" && rawFamily.trim()) {
    const norm = rawFamily.trim().toLowerCase();
    if (norm === "unknown") return "unknown";
    const verified = getProviderFamily(norm);
    if (verified !== "unknown") return verified;
  }
  return getProviderFamily(fallbackSource);
}

export const QuorumPolicies = {
  STRICT_HETEROGENEOUS: (metadataMap = {}) => {
    let macroRec = null;
    let microRec = null;

    for (const [id, rec] of Object.entries(metadataMap)) {
      if (rec.role === "macro") macroRec = rec;
      if (rec.role === "micro") microRec = rec;
    }

    const reached = Boolean(macroRec?.healthy && microRec?.healthy);
    if (!reached) {
      return {
        quorumReached: false,
        selectedReportIds: [],
        reason: "Quorum Failure: Both macro and micro sentries must be healthy."
      };
    }

    const macroSource = macroRec.provider || macroRec.source || "macro";
    const microSource = microRec.provider || microRec.source || "micro";
    const macroFamily = resolveCanonicalProviderFamily(macroRec.family, macroSource);
    const microFamily = resolveCanonicalProviderFamily(microRec.family, microSource);

    // Default-Deny: fail closed if either provider family cannot be verified
    if (macroFamily === "unknown" || microFamily === "unknown") {
      return {
        quorumReached: false,
        selectedReportIds: [],
        reason: `Quorum Failure: Provider family cannot be verified under Default-Deny policy (macro='${macroFamily}', micro='${microFamily}').`
      };
    }

    // Fail closed if both sentries belong to the same vendor family
    if (macroFamily === microFamily) {
      return {
        quorumReached: false,
        selectedReportIds: [],
        reason: `Quorum Failure: Sentries lack provider-family diversity (both belong to '${macroFamily}').`
      };
    }

    return {
      quorumReached: true,
      selectedReportIds: [macroRec.id, microRec.id],
      reason: null
    };
  },

  TRI_PARTY_HETEROGENEOUS: (metadataMap = {}, policyOptions = {}) => {
    const familyRecords = new Map();
    const unavailableProviders = [];
    let unknownFamilyFound = false;
    let unknownReason = "";
    let duplicateFamilyFound = false;
    let duplicateReason = "";

    for (const [id, rec] of Object.entries(metadataMap)) {
      const source = rec.provider || rec.source || id;
      const family = resolveCanonicalProviderFamily(rec.family, source);

      if (!rec.healthy) {
        unavailableProviders.push({
          id,
          provider: source,
          family,
          reason: rec.error || "UNAVAILABLE"
        });
        continue;
      }

      if (family === "unknown") {
        unknownFamilyFound = true;
        unknownReason = `Quorum Failure: Provider '${source}' family cannot be verified under Default-Deny policy.`;
        continue;
      }

      if (familyRecords.has(family)) {
        duplicateFamilyFound = true;
        duplicateReason = `Quorum Failure: Sentries lack provider-family diversity (multiple sentries belong to '${family}').`;
        continue;
      }

      familyRecords.set(family, rec);
    }

    if (unknownFamilyFound && familyRecords.size < 2) {
      return {
        quorumReached: false,
        topology: "QUORUM_FAILED",
        selectedReportIds: [],
        reason: unknownReason
      };
    }

    if (duplicateFamilyFound && familyRecords.size < 2) {
      return {
        quorumReached: false,
        topology: "QUORUM_FAILED",
        selectedReportIds: [],
        reason: duplicateReason
      };
    }

    const healthyCount = familyRecords.size;
    const healthyIds = Array.from(familyRecords.values()).map(r => r.id);

    // Q-01: 3 of 3 Nominal
    if (healthyCount >= 3) {
      return {
        quorumReached: true,
        topology: "3_OF_3_NOMINAL",
        selectedReportIds: healthyIds.slice(0, 3),
        unavailableProviders,
        reason: null
      };
    }

    // Q-02, Q-03, Q-04: 2 of 3 Degraded
    if (healthyCount === 2) {
      return {
        quorumReached: true,
        topology: "2_OF_3_DEGRADED",
        selectedReportIds: healthyIds,
        unavailableProviders,
        reason: null
      };
    }

    // Q-05, Q-06, Q-07: 1 of 3 Single Sentry
    if (healthyCount === 1) {
      const isHighRisk = Boolean(
        policyOptions.tier === 1 ||
        policyOptions.risk === "high" ||
        policyOptions.mode === "hierarchical" ||
        (policyOptions.totalLines !== undefined && policyOptions.totalLines >= 50) ||
        policyOptions.hasSecurityFiles
      );

      if (isHighRisk) {
        return {
          quorumReached: false,
          topology: "QUORUM_FAILED",
          selectedReportIds: [],
          unavailableProviders,
          reason: "Quorum Failure: High-risk Tier 1 changesets require at least 2 healthy heterogeneous sentries (Fail-Closed)."
        };
      }

      return {
        quorumReached: true,
        topology: "1_OF_3_SINGLE_SENTRY",
        selectedReportIds: healthyIds,
        unavailableProviders,
        reason: null
      };
    }

    // Q-08: 0 of 3
    return {
      quorumReached: false,
      topology: "QUORUM_FAILED",
      selectedReportIds: [],
      unavailableProviders,
      reason: "Quorum Failure: All review providers are unhealthy or unavailable."
    };
  },

  SINGLE_SENTRY: (metadataMap = {}, policyOptions = "macro") => {
    const designatedRole = (typeof policyOptions === "string" ? policyOptions : (policyOptions?.designatedRole || policyOptions?.requiredRole)) || "macro";
    let target = null;
    for (const [id, rec] of Object.entries(metadataMap)) {
      if (rec.role === designatedRole || rec.source === designatedRole) {
        target = rec;
        break;
      }
    }
    const reached = Boolean(target?.healthy);
    return {
      quorumReached: reached,
      selectedReportIds: reached ? [target.id] : [],
      reason: reached ? null : `Quorum Failure: Designated sentry '${designatedRole}' is unhealthy or missing.`
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

  const isPositionalSentryReport = Boolean(
    reportsInput &&
    (Array.isArray(reportsInput.findings) || typeof reportsInput.error === "string")
  );
  const secondArgIsSentryReport = Boolean(
    rest[0] &&
    typeof rest[0] === "object" &&
    (Array.isArray(rest[0].findings) || typeof rest[0].error === "string")
  );

  const isMapForm = Boolean(
    reportsInput &&
    typeof reportsInput === "object" &&
    !Array.isArray(reportsInput) &&
    !isPositionalSentryReport &&
    !secondArgIsSentryReport
  );

  if (isMapForm) {
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

  // 2. Invariant (RFC-027-02): Pairwise Object Reference Equality & Sybil Defense
  if (rawReports && typeof rawReports === "object") {
    const reportKeys = Object.keys(rawReports);
    for (let i = 0; i < reportKeys.length; i++) {
      for (let j = i + 1; j < reportKeys.length; j++) {
        const k1 = reportKeys[i];
        const k2 = reportKeys[j];
        if (
          rawReports[k1] &&
          rawReports[k2] &&
          typeof rawReports[k1] === "object" &&
          typeof rawReports[k2] === "object" &&
          rawReports[k1] === rawReports[k2]
        ) {
          return issueConsensusFromEvidence({
            validatedReportsMap,
            quorumResult: { quorumReached: false, selectedReportIds: [] },
            invocationNonce,
            verdict: "error",
            consensusProof: `Consensus aborted: Heterogeneity violation / Sybil inflation rejected. Roles '${k1}' and '${k2}' point to identical object reference.`
          });
        }
      }
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
        source: raw?.name || raw?.source || key,
        provider: raw?.providerIdentity?.provider || raw?.provider || raw?.name || raw?.source || key,
        family: resolveCanonicalProviderFamily(raw?.providerIdentity?.family || raw?.family, raw?.providerIdentity?.provider || raw?.provider || raw?.name || raw?.source || key)
      };
    } else {
      const canonicalFindings = deepFreeze(validated.report.findings.map(f => ({ ...f })));
      const provider = raw?.providerIdentity?.provider || raw?.provider || validated.report.provider || validated.report.name || validated.report.source || key;
      const family = resolveCanonicalProviderFamily(raw?.providerIdentity?.family || raw?.family || validated.report.family, provider);
      validatedReportsMap.set(reportId, {
        id: reportId,
        role: key,
        healthy: true,
        findings: canonicalFindings,
        source: validated.report.name || validated.report.source || key,
        provider,
        family
      });
      metadataMap[reportId] = {
        id: reportId,
        role: key,
        healthy: true,
        count: canonicalFindings.length,
        source: validated.report.name || validated.report.source || key,
        provider,
        family
      };
    }
  }

  // 3. Resolve Policy Function
  const policyFn = typeof options.policy === "function"
    ? options.policy
    : (QuorumPolicies[options.policy] || QuorumPolicies.STRICT_HETEROGENEOUS);

  const policyOptions = options.policyOptions || options;

  let quorumResult;
  try {
    quorumResult = policyFn(deepFreeze({ ...metadataMap }), policyOptions);
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
  const deduplicatedList = [];

  const extractCweToken = (f) => {
    const rawCwe = String(f.cwe || "").trim();
    const numMatch = rawCwe.match(/^(?:CWE[-_]?)?(\d+)$/i);
    if (numMatch) return `cwe-${numMatch[1]}`;
    const inText = `${rawCwe} ${f.title || ""} ${f.type || ""}`.match(/\bCWE[-_]?(\d+)\b/i);
    if (inText) return `cwe-${inText[1]}`;
    if (f.type) return String(f.type).toLowerCase().replace(/[^a-z0-9_-]/g, "-").slice(0, 24);
    return (f.title || "issue").toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 16);
  };

  for (const { finding: f, source } of collectedFindings) {
    const normFile = (f.file || f.path || "root").toLowerCase().replace(/\\/g, "/");
    const lineStart = Math.max(1, Number(f.line_start || f.line) || 1);
    const cweToken = extractCweToken(f);
    const incomingSev = (f.severity || "info").toLowerCase();
    const incomingWeight = SEVERITY_WEIGHTS[incomingSev] ?? 0;

    let matched = null;
    for (const existing of deduplicatedList) {
      const existingFile = (existing.file || existing.path || "root").toLowerCase().replace(/\\/g, "/");
      const existingCwe = extractCweToken(existing);
      const existingLine = Math.max(1, Number(existing.line_start || existing.line) || 1);

      const exactTitle = (existing.title || "").toLowerCase().trim() === (f.title || "").toLowerCase().trim();
      const sameLocatorAndCwe = (existingFile === normFile && existingCwe === cweToken && Math.abs(existingLine - lineStart) <= 15);
      const exactSameKey = (existingFile === normFile && existingLine === lineStart && exactTitle);

      if (sameLocatorAndCwe || exactSameKey) {
        matched = existing;
        break;
      }
    }

    if (!matched) {
      deduplicatedList.push({
        ...f,
        sources: [source],
        corroborations: 1
      });
    } else {
      if (!matched.sources.includes(source)) {
        matched.sources.push(source);
        matched.corroborations = matched.sources.length;
      }
      const currentWeight = SEVERITY_WEIGHTS[matched.severity] ?? 0;
      if (incomingWeight > currentWeight) {
        matched.severity = incomingSev;
      }
      if (!matched.ruleId && f.ruleId) matched.ruleId = f.ruleId;
      if (!matched.cwe && f.cwe) matched.cwe = f.cwe;
      if (!matched.type && f.type) matched.type = f.type;
    }
  }

  const deduplicated = deduplicatedList;
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
    this.strict = Boolean(options.strict);
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
    if (consensusReport.verdict === "approve" || (consensusReport.verdict === "warning" && !this.strict)) {
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

    // 7. Semantic Stagnation & Cycle Detection (OWASP LLM06 Defenses)
    const currentSet = this.getFindingKeySet(consensusReport.findings || []);

    // Layer 1: Absolute Zero-Tolerance for Exact Cycles across all history
    for (const prevSet of this.historyFingerprints) {
      if (this.areSetsEqual(currentSet, prevSet)) {
        return {
          status: "oscillation_detected",
          action: "escalate_to_human",
          reason: "Remediation cycle detected: Exact identical finding set reproduced from previous iteration. Livelock prevented."
        };
      }
    }

    // Layer 2: Immediate Monotonic Progress vs Jaccard Stagnation
    const immediatePrev = this.historyFingerprints[this.historyFingerprints.length - 1];
    const isImmediateMonotonicProgress = Boolean(
      immediatePrev &&
      currentSet.size < immediatePrev.size &&
      [...currentSet].every(key => immediatePrev.has(key))
    );

    if (!isImmediateMonotonicProgress) {
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

  areSetsEqual(setA, setB) {
    if (!setA || !setB || setA.size !== setB.size) return false;
    for (const item of setA) {
      if (!setB.has(item)) return false;
    }
    return true;
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
