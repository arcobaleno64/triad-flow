/**
 * Hardened Consensus State Model & In-Process Capability Registry
 * Single Source of Truth for Consensus Invariants, Capability Authority & Blocker Classification.
 */

export const ALLOWED_VERDICTS = Object.freeze(["approve", "warning", "needs-attention", "error"]);

function makeReadOnlySet(elements) {
  const privateSet = new Set(elements);
  const wrapper = Object.freeze({
    has: (item) => privateSet.has(item),
    get size() { return privateSet.size; },
    values: () => privateSet.values(),
    entries: () => privateSet.entries(),
    forEach: (cb, thisArg) => {
      privateSet.forEach((value, key) => {
        cb.call(thisArg, value, key, wrapper);
      });
    },
    [Symbol.iterator]: () => privateSet[Symbol.iterator](),
    add: () => { throw new TypeError("Cannot modify read-only severity policy set."); },
    delete: () => { throw new TypeError("Cannot modify read-only severity policy set."); },
    clear: () => { throw new TypeError("Cannot modify read-only severity policy set."); }
  });
  return wrapper;
}

export const BLOCKING_SEVERITIES = makeReadOnlySet(["critical", "high"]);
export const VALID_SEVERITY_SET = makeReadOnlySet(["critical", "high", "medium", "low", "info"]);

/**
 * Recursively freezes an object and its nested properties.
 */
export function deepFreeze(obj, seen = new WeakSet()) {
  if (!obj || typeof obj !== "object" || seen.has(obj)) {
    return obj;
  }
  seen.add(obj);
  Object.freeze(obj);
  for (const key of Object.getOwnPropertyNames(obj)) {
    const val = obj[key];
    if (val && typeof val === "object") {
      deepFreeze(val, seen);
    }
  }
  return obj;
}

/**
 * Module-private authority registry for in-process capability tracking.
 * Callers cannot construct objects that are members of this WeakSet.
 */
const trustedConsensusRegistry = new WeakSet();

/**
 * Checks if findings contain any blocking (critical or high) severity vulnerabilities.
 */
export function hasBlockingFindings(findings) {
  if (!Array.isArray(findings)) return false;
  return findings.some(f => f && typeof f === "object" && BLOCKING_SEVERITIES.has(f.severity));
}

/**
 * Filters and returns all blocking findings.
 */
export function getBlockingFindings(findings) {
  if (!Array.isArray(findings)) return [];
  return findings.filter(f => f && typeof f === "object" && BLOCKING_SEVERITIES.has(f.severity));
}

/**
 * Pure diagnostic / schema validation for Consensus candidates.
 * Note: Semantic validity verifies data quality only; it NEVER grants trusted capability authority.
 * Safe against hostile throwing getters (Fail-Closed).
 */
export function validateConsensusSemantics(report) {
  try {
    if (!report || typeof report !== "object" || Array.isArray(report)) {
      return { ok: false, valid: false, code: "INVALID_REPORT_OBJECT", reason: "Consensus candidate must be a non-null plain object." };
    }

    const quorumReached = report.quorumReached;
    // C-01: quorumReached must be boolean
    if (typeof quorumReached !== "boolean") {
      return { ok: false, valid: false, code: "INVALID_QUORUM_TYPE", reason: "quorumReached must be a boolean." };
    }

    const verdict = report.verdict;
    // C-04: verdict must be in allowed enum
    if (!ALLOWED_VERDICTS.includes(verdict)) {
      return { ok: false, valid: false, code: "INVALID_VERDICT_ENUM", reason: `Verdict must be one of: ${ALLOWED_VERDICTS.join(", ")}.` };
    }

    const rawFindings = report.findings;
    // C-02: findings must be an array
    if (!Array.isArray(rawFindings)) {
      return { ok: false, valid: false, code: "INVALID_FINDINGS_ARRAY", reason: "findings must be an array." };
    }

    const cleanFindings = [];
    for (let i = 0; i < rawFindings.length; i++) {
      const f = rawFindings[i];
      if (!f || typeof f !== "object" || Array.isArray(f)) {
        return { ok: false, valid: false, code: "MALFORMED_FINDING", reason: `Finding at index ${i} must be a non-null plain object.` };
      }
      const rawTitle = f.title;
      const rawMessage = f.message;
      const title = typeof rawTitle === "string" ? rawTitle.trim() : (typeof rawMessage === "string" ? rawMessage.trim() : "");
      if (!title) {
        return { ok: false, valid: false, code: "MALFORMED_FINDING_TITLE", reason: `Finding at index ${i} missing non-empty title or message.` };
      }
      const severity = f.severity;
      if (!VALID_SEVERITY_SET.has(severity)) {
        return { ok: false, valid: false, code: "INVALID_FINDING_SEVERITY", reason: `Finding at index ${i} has invalid severity: '${severity}'.` };
      }
      const file = typeof f.file === "string" ? f.file : (typeof f.path === "string" ? f.path : "");
      if (file.includes("\0")) {
        return { ok: false, valid: false, code: "MALFORMED_FINDING_FILE", reason: `Finding at index ${i} contains illegal NUL byte in file path.` };
      }
      cleanFindings.push({
        title,
        severity,
        file,
        line_start: Number(f.line_start || f.line || 1),
        line_end: Number(f.line_end || f.line_start || f.line || 1),
        ruleId: typeof f.ruleId === "string" ? f.ruleId.trim() : undefined,
        cwe: typeof f.cwe === "string" ? f.cwe.trim() : undefined,
        type: typeof f.type === "string" ? f.type.trim() : undefined,
        recommendation: typeof f.recommendation === "string" ? f.recommendation : (typeof f.body === "string" ? f.body : undefined),
        sources: Array.isArray(f.sources) ? [...f.sources] : ["sentry-node"],
        corroborations: Number(f.corroborations || 1)
      });
    }

    // C-03: totalFindings count must match actual findings length
    if (report.totalFindings !== undefined && report.totalFindings !== null) {
      const n = Number(report.totalFindings);
      if (!Number.isInteger(n) || n !== cleanFindings.length) {
        return {
          ok: false,
          valid: false,
          code: "CONTRADICTION_TOTAL_FINDINGS_MISMATCH",
          reason: `totalFindings (${report.totalFindings}) does not match findings.length (${cleanFindings.length}).`
        };
      }
    }

    // C-05: Invariant: verdict 'approve' cannot coexist with blocking findings
    if (verdict === "approve" && hasBlockingFindings(cleanFindings)) {
      return {
        ok: false,
        valid: false,
        code: "CONTRADICTION_APPROVE_WITH_BLOCKING_FINDINGS",
        reason: "Semantic contradiction: verdict 'approve' cannot coexist with critical or high severity findings."
      };
    }

    // C-07: Invariant: verdict 'approve' cannot coexist with quorumReached = false
    if (verdict === "approve" && !quorumReached) {
      return {
        ok: false,
        valid: false,
        code: "CONTRADICTION_APPROVE_WITHOUT_QUORUM",
        reason: "Semantic contradiction: verdict 'approve' requires quorumReached to be true."
      };
    }

    // C-08: Invariant: verdict 'error' with quorumReached = true requires explicit reason or error state
    if (verdict === "error" && quorumReached && cleanFindings.length === 0 && !report.error && !report.consensusProof) {
      return {
        ok: false,
        valid: false,
        code: "CONTRADICTION_ERROR_WITH_CLEAN_QUORUM",
        reason: "Semantic contradiction: verdict 'error' cannot claim clean quorum without error reason."
      };
    }

    const selectedReportIds = Array.isArray(report.selectedReportIds) ? [...report.selectedReportIds] : [];

    const canonicalSemanticValue = {
      verdict,
      quorumReached,
      totalFindings: cleanFindings.length,
      findings: cleanFindings,
      selectedReportIds,
      consensusProof: typeof report.consensusProof === "string" ? report.consensusProof : ""
    };

    return { ok: true, valid: true, code: "VALID", reason: null, value: canonicalSemanticValue };
  } catch (err) {
    return { ok: false, valid: false, code: "RUNTIME_ACCESS_ERROR", reason: `Access error: ${err.message}` };
  }
}

/**
 * Backward compatibility alias for validateConsensusSemantics.
 */
export const validateConsensusReport = validateConsensusSemantics;

/**
 * Evidence-Bound Trusted Consensus Issuer.
 * Requires an active validatedReportsMap and verified invocation context.
 * Plain objects cannot be registered directly without validated evidence backing.
 */
export function issueConsensusFromEvidence({
  validatedReportsMap,
  quorumResult,
  invocationNonce,
  deduplicatedFindings = [],
  verdict = "error",
  consensusProof = ""
}) {
  if (!(validatedReportsMap instanceof Map) || typeof invocationNonce !== "string" || !invocationNonce) {
    throw new TypeError("Cannot issue trusted consensus: Invalid evidence map or invocation context.");
  }
  if (!quorumResult || typeof quorumResult.quorumReached !== "boolean") {
    throw new TypeError("Cannot issue trusted consensus: Malformed quorum result.");
  }

  const cleanFindings = Array.isArray(deduplicatedFindings) ? deduplicatedFindings : [];
  const selectedReportIds = Array.isArray(quorumResult.selectedReportIds) ? [...quorumResult.selectedReportIds] : [];

  // Security Invariant (R1): Every selectedReportId must exist in validatedReportsMap and be healthy
  for (const id of selectedReportIds) {
    if (!validatedReportsMap.has(id)) {
      throw new TypeError(`Cannot issue trusted consensus: Selected report ID '${id}' is not present in validated reports map.`);
    }
    const reportRec = validatedReportsMap.get(id);
    if (!reportRec || reportRec.healthy === false) {
      throw new TypeError(`Cannot issue trusted consensus: Selected report ID '${id}' is not healthy.`);
    }
  }

  if (quorumResult.quorumReached && selectedReportIds.length === 0) {
    throw new TypeError("Cannot issue trusted consensus: Quorum reached cannot have empty selectedReportIds.");
  }

  const rawConsensus = {
    verdict: String(verdict),
    quorumReached: Boolean(quorumResult.quorumReached),
    totalFindings: cleanFindings.length,
    findings: cleanFindings,
    selectedReportIds,
    consensusProof: String(consensusProof || "")
  };

  const semantic = validateConsensusSemantics(rawConsensus);
  if (!semantic.ok) {
    throw new TypeError(`Cannot issue untrusted consensus: ${semantic.reason} (${semantic.code})`);
  }

  // Deeply freeze all properties and nested objects
  const trustedCapability = deepFreeze({
    verdict: semantic.value.verdict,
    quorumReached: semantic.value.quorumReached,
    totalFindings: semantic.value.totalFindings,
    findings: semantic.value.findings,
    selectedReportIds: semantic.value.selectedReportIds,
    consensusProof: semantic.value.consensusProof
  });

  trustedConsensusRegistry.add(trustedCapability);
  return trustedCapability;
}

/**
 * Public read-only capability checker.
 * Returns true if and only if candidate was minted by issueConsensusFromEvidence.
 */
export function isTrustedConsensus(candidate) {
  if (!candidate || typeof candidate !== "object") {
    return false;
  }
  return trustedConsensusRegistry.has(candidate);
}

/**
 * Asserts that candidate possesses trusted consensus authority.
 */
export function assertTrustedConsensus(candidate) {
  if (!isTrustedConsensus(candidate)) {
    const err = new Error("Untrusted consensus capability (UNTRUSTED_CONSENSUS).");
    err.code = "UNTRUSTED_CONSENSUS";
    throw err;
  }
}
