/**
 * Hardened Harness Engineering: Safety Scaffolding, Secret Redaction, Sentry Normalization, Recursive Symlink Sandbox & SARIF Compliance
 */

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { isTrustedConsensus, hasBlockingFindings, VALID_SEVERITY_SET } from "./consensus-state.mjs";
import {
  isTrustedVerificationRecord,
  isSegregatedSyntheticRecord,
  issueVerificationRecordFromOutput,
  RunContext,
  normalizeDigest,
  normalizeObjective,
  normalizeCommitSha,
  isSubstantiveContestedReasoning,
  isNonVacuousContestedReasoning,
  mergeContextGaps
} from "./independent-verifier.mjs";

export {
  isTrustedVerificationRecord,
  isSegregatedSyntheticRecord,
  issueVerificationRecordFromOutput,
  RunContext,
  normalizeDigest,
  normalizeObjective,
  normalizeCommitSha,
  isSubstantiveContestedReasoning,
  isNonVacuousContestedReasoning,
  mergeContextGaps
} from "./independent-verifier.mjs";

export const SECRET_PATTERNS = [
  // Google API Keys
  /\bAIza[0-9A-Za-z-_]{20,45}\b/g,
  // OpenAI Keys (Legacy sk-, Project sk-proj-, Admin sk-admin-)
  /\bsk-(?:proj-|admin-)?[a-zA-Z0-9_\-]{20,}\b/g,
  // Anthropic Keys
  /\bsk-ant-[a-zA-Z0-9_\-]{20,}\b/g,
  // GitHub Tokens
  /\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}\b/g,
  /\bgithub_pat_[a-zA-Z0-9_]{50,}\b/g,
  // AWS Access Key ID
  /\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/g,
  // JWT Tokens
  /\b(?:bearer\s+)?eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\b/gi,
  // PEM Private Keys
  /-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY(?: BLOCK)?-----[\s\S]+?-----END (?:[A-Z0-9_-]+ )?PRIVATE KEY(?: BLOCK)?-----/g
];

export function redactSecrets(text = "") {
  if (typeof text !== "string") return text;
  let sanitized = text;
  for (const pattern of SECRET_PATTERNS) {
    sanitized = sanitized.replace(pattern, "[REDACTED_SECRET]");
  }
  return sanitized;
}

export function stripExtendedPrefix(p) {
  if (typeof p !== "string") return p;
  if (p.startsWith("\\\\?\\UNC\\")) return "\\\\" + p.slice(8);
  if (p.startsWith("\\\\?\\")) return p.slice(4);
  return p;
}

export function normalizeExclusionPath(s, { platform = process.platform } = {}) {
  const norm = String(s || "").trim().replace(/\\/g, "/");
  return platform === "win32" ? norm.toLowerCase() : norm;
}

const WINDOWS_RESERVED_DEVICE_REGEX = /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$/i;

/**
 * Hardened Workspace Boundary Check: Multi-hop Recursive Symlink Resolution
 * Invariants (INV-07, P1-04):
 * - workspaceRoot must exist and be a directory.
 * - Resolves symlink chains recursively (up to MAX_HOPS = 32), detecting cycles.
 * - Ensures all intermediate symlink hops and final targets stay strictly inside canonicalRoot.
 */
export function isPathSafe(targetPath, workspaceRoot) {
  if (typeof targetPath !== "string" || typeof workspaceRoot !== "string") return false;
  if (!targetPath.trim() || !workspaceRoot.trim()) return false;
  if (targetPath.includes("\0") || workspaceRoot.includes("\0")) return false;

  const isWin = process.platform === "win32";

  // 1. Windows DOS Device & Alternate Data Stream (ADS) Checks
  if (isWin) {
    const rawSegments = targetPath.split(/[\\/]/);
    for (const seg of rawSegments) {
      if (WINDOWS_RESERVED_DEVICE_REGEX.test(seg)) return false;
      if (seg.includes(":") && seg.indexOf(":") !== 1) return false;
    }
  }

  try {
    if (!fs.existsSync(workspaceRoot)) return false;
    const rootStat = fs.statSync(workspaceRoot);
    if (!rootStat.isDirectory()) return false;

    const rawCanonicalRoot = fs.realpathSync.native
      ? fs.realpathSync.native(workspaceRoot)
      : fs.realpathSync(workspaceRoot);
    const canonicalRoot = stripExtendedPrefix(rawCanonicalRoot);

    const isInsideRoot = (absPath) => {
      const normAbs = stripExtendedPrefix(absPath);
      const rel = path.relative(canonicalRoot, normAbs);
      const normRel = isWin ? rel.toLowerCase() : rel;
      return normRel !== ".." && !normRel.startsWith(".." + path.sep) && !path.isAbsolute(normRel);
    };

    // 2. Lexical traversal pre-check
    const resolvedTarget = path.resolve(canonicalRoot, targetPath);
    if (!isInsideRoot(resolvedTarget)) {
      return false;
    }

    // 3. Multi-hop recursive symlink resolution
    const MAX_HOPS = 32;
    let hopCount = 0;
    const visitedSymlinks = new Set();

    let currentDir = canonicalRoot;
    const remainingSegments = path.relative(canonicalRoot, resolvedTarget).split(/[\\/]/).filter(Boolean);

    while (remainingSegments.length > 0) {
      const nextSegment = remainingSegments.shift();
      let candidatePath = path.join(currentDir, nextSegment);

      // Inner loop: Recursively resolve symlink hops for candidatePath
      while (true) {
        let segStat;
        try {
          segStat = fs.lstatSync(candidatePath);
        } catch (err) {
          if (err.code === "ENOENT") {
            // Path does not exist on disk.
            // Ensure remaining path from currentDir lexically stays inside canonicalRoot
            const futurePath = path.resolve(currentDir, [nextSegment, ...remainingSegments].join(path.sep));
            return isInsideRoot(futurePath);
          }
          return false; // EPERM, EACCES, ELOOP => Fail-Closed
        }

        if (!segStat.isSymbolicLink()) {
          break; // Concrete directory or regular file
        }

        hopCount++;
        if (hopCount > MAX_HOPS) {
          return false; // Exceeded max hops => Fail-closed
        }

        const linkKey = isWin ? candidatePath.toLowerCase() : candidatePath;
        if (visitedSymlinks.has(linkKey)) {
          return false; // Symlink cycle detected => Fail-closed without hanging
        }
        visitedSymlinks.add(linkKey);

        const linkDest = fs.readlinkSync(candidatePath);
        const resolvedLinkDest = path.resolve(path.dirname(candidatePath), linkDest);

        // Intermediate hop MUST remain inside canonicalRoot
        if (!isInsideRoot(resolvedLinkDest)) {
          return false;
        }

        candidatePath = resolvedLinkDest;
      }

      currentDir = candidatePath;
    }

    return isInsideRoot(currentDir);
  } catch {
    return false; // Fail-closed on any runtime error
  }
}

export const VALID_SEVERITIES = VALID_SEVERITY_SET;

/**
 * Validates and normalizes an individual finding.
 * Invariant (P1-03): Preserves filename whitespace in 'file'/'path' while trimming human prose.
 * Rejects illegal NUL bytes with Fail-Closed.
 */
export function normalizeFinding(raw, options = {}) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return { valid: false, reason: "Finding must be a non-null plain object." };
  }

  const rawTitle = typeof raw.title === "string" ? raw.title.trim() : "";
  const rawMessage = typeof raw.message === "string" ? raw.message.trim() : "";
  const title = rawTitle || rawMessage;
  if (!title) {
    return { valid: false, reason: "Finding missing required non-empty title or message." };
  }

  const rawSev = typeof raw.severity === "string" ? raw.severity.trim().toLowerCase() : "";
  if (!VALID_SEVERITY_SET.has(rawSev)) {
    return { valid: false, reason: `Unknown or invalid severity: '${raw.severity}'. Strict enum required.` };
  }

  let lineStart = 1;
  if (raw.line_start !== undefined && raw.line_start !== null) {
    const n = Number(raw.line_start);
    if (!Number.isInteger(n) || n < 1) {
      return { valid: false, reason: `Invalid line_start: ${raw.line_start}. Must be a positive integer >= 1.` };
    }
    lineStart = n;
  } else if (raw.line !== undefined && raw.line !== null) {
    const n = Number(raw.line);
    if (!Number.isInteger(n) || n < 1) {
      return { valid: false, reason: `Invalid line: ${raw.line}. Must be a positive integer >= 1.` };
    }
    lineStart = n;
  }

  let lineEnd = lineStart;
  if (raw.line_end !== undefined && raw.line_end !== null) {
    const n = Number(raw.line_end);
    if (!Number.isInteger(n) || n < lineStart) {
      return { valid: false, reason: `Invalid line_end: ${raw.line_end}. Must be >= line_start (${lineStart}).` };
    }
    lineEnd = n;
  }

  // Preserve exact filename whitespace without .trim()
  const rawFile = typeof raw.file === "string" ? raw.file : (typeof raw.path === "string" ? raw.path : "");
  if (rawFile.includes("\0")) {
    return { valid: false, reason: "Finding file path contains illegal NUL byte." };
  }
  const file = rawFile;

  const prefix = typeof options === "string"
    ? options.trim()
    : String(options?.prefix || options?.sentry || options?.provider || raw.sentry || raw.provider || raw.source || "").trim();

  const rawId = raw.id !== undefined && raw.id !== null && String(raw.id).trim().length > 0
    ? String(raw.id).trim()
    : (raw.findingId !== undefined && raw.findingId !== null && String(raw.findingId).trim().length > 0 ? String(raw.findingId).trim() : undefined);

  let id = rawId;
  const isLocalId = !rawId || /^(?:finding|vuln|issue|item|f)[-_]?\d+$/i.test(rawId) || /^\d+$/.test(rawId);
  if (prefix.length > 0 && id !== undefined && !id.startsWith(`${prefix}:`)) {
    if (isLocalId || options?.forceNamespace === true) {
      id = `${prefix}:${id}`;
    }
  }

  return {
    valid: true,
    finding: {
      id,
      providerFindingId: rawId,
      provider: prefix || (typeof raw.provider === "string" ? raw.provider.trim() : undefined),
      title,
      severity: rawSev,
      file,
      line_start: lineStart,
      line_end: lineEnd,
      ruleId: typeof raw.ruleId === "string" ? raw.ruleId.trim() : undefined,
      cwe: typeof raw.cwe === "string" ? raw.cwe.trim() : undefined,
      type: typeof raw.type === "string" ? raw.type.trim() : undefined,
      recommendation: typeof raw.recommendation === "string" ? raw.recommendation.trim() : (typeof raw.body === "string" ? raw.body.trim() : undefined)
    }
  };
}

/**
 * Validates a single Sentry Report object.
 */
export function validateSentryReport(report, options = {}) {
  if (!report || typeof report !== "object" || Array.isArray(report)) {
    return { valid: false, reason: "Sentry report must be a non-null object." };
  }
  if (report.error) {
    return { valid: false, reason: `Sentry reported error: ${report.error}` };
  }
  if (!Array.isArray(report.findings)) {
    return { valid: false, reason: "Sentry report.findings must be an array." };
  }

  const reportPrefix = String(
    report.sentry ||
    options?.sentry ||
    options?.prefix ||
    report.provider ||
    report.providerIdentity?.provider ||
    report.name ||
    report.source ||
    report.role ||
    options?.provider ||
    ""
  ).trim();

  const normalizedFindings = [];
  for (let i = 0; i < report.findings.length; i++) {
    const norm = normalizeFinding(report.findings[i], {
      prefix: reportPrefix,
      sentry: report.sentry || options?.sentry
    });
    if (!norm.valid) {
      return { valid: false, reason: `Malformed finding at index ${i}: ${norm.reason}` };
    }
    normalizedFindings.push(norm.finding);
  }

  return {
    valid: true,
    report: {
      ...report,
      findings: normalizedFindings
    }
  };
}

/**
 * Evaluates CI Gate decision with In-Process Trusted Consensus Capability requirement
 * and In-Process Trusted Verification Record Capability.
 * Rejects untrusted plain objects, clones, detached signatures, or forged RunContext bindings with Fail-Closed.
 */
function _evaluateGateDecisionCore(consensus, options = {}, { allowSynthetic = false } = {}) {
  // 1. Mandatory capability verification
  if (!isTrustedConsensus(consensus)) {
    return {
      decision: "block",
      reason: "Gate Fail-Closed: Untrusted consensus capability (UNTRUSTED_CONSENSUS).",
      criticals: [],
      advisoryFindings: []
    };
  }

  // 2. Read from single coherent trusted consensus object
  if (!consensus.quorumReached || consensus.verdict === "error") {
    return {
      decision: "block",
      reason: consensus.consensusProof || "Gate Fail-Closed: Quorum failure or error verdict.",
      criticals: [],
      advisoryFindings: []
    };
  }

  if (options?.coverageOk === false || consensus?.coverageOk === false) {
    return {
      decision: "block",
      reason: "Coverage Incomplete: Sentry omitted file(s) from review.",
      criticals: [],
      advisoryFindings: []
    };
  }

  // 3. Verification Record Capability & Authority (delegated to post-verification core)
  if (options?.verificationRecord) {
    return _evaluatePostVerificationGateCore(consensus, options.verificationRecord, options, { allowSynthetic });
  }

  const findings = Array.isArray(consensus.findings) ? consensus.findings : [];

  // When findings count is 0:
  if (findings.length === 0) {
    if (options?.preliminary === true) {
      return {
        decision: "approve",
        preliminary: true,
        reason: "Preliminary consensus clean. Independent verification (Clean Challenge) required for final merge release.",
        criticals: [],
        advisoryFindings: []
      };
    }

    // Final gate evaluation: zero findings without independent verification record strictly fails closed
    return {
      decision: "block",
      reason: "Clean Challenge missing: zero-finding consensus requires independent verification record",
      criticals: [],
      advisoryFindings: []
    };
  }

  const criticals = findings.filter(f => f && (f.severity === "critical" || f.severity === "high"));

  if (criticals.length > 0) {
    return {
      decision: "block",
      reason: `Found ${criticals.length} critical/high severity findings. Merge blocked.`,
      criticals,
      advisoryFindings: []
    };
  }

  // Tier 1 (High-Risk) or Strict Mode: Any confirmed findings block merge
  const isTier1 = options?.tier === 1;
  const isStrict = Boolean(options && (options.strict || isTier1));

  if (findings.length > 0 && isStrict) {
    return {
      decision: "block",
      reason: isTier1
        ? `Tier 1 high-risk policy: ${findings.length} findings must be resolved before merge. Merge blocked.`
        : `Strict mode enabled: ${findings.length} findings must be resolved.`,
      criticals: [],
      advisoryFindings: []
    };
  }

  return {
    decision: "approve",
    reason: "No blocking vulnerabilities found. CI/CD Gate passed.",
    criticals: [],
    advisoryFindings: []
  };
}

export function evaluateGateDecision(consensus, options = {}) {
  return _evaluateGateDecisionCore(consensus, options, { allowSynthetic: false });
}

export function evaluateIsolatedTestGate(consensus, options = {}) {
  return _evaluateGateDecisionCore(consensus, options, { allowSynthetic: true });
}

/**
 * Evaluates Post-Verification Gate decision incorporating Independent Verification authority
 * and Structured Verifier Omissions (Spec §3.1.1).
 * Adheres to normative LOOP2-REMEDIATION-001 and REMEDIATION-007 authority rules:
 * - Critical/High findings remain strictly fail-closed BLOCK (or HUMAN_REVIEW_REQUIRED if contested)
 * - Supported Low/Medium findings block in Tier 1
 * - Supported Medium findings block in Tier 2
 * - Supported Low findings pass as advisory in Tier 2 unless independent verification marks them as directly falsifying the stated patch objective
 * - Any independently SUPPORTED finding marked FALSIFIES_PATCH_OBJECTIVE blocks regardless of impact severity
 * - Solitary non-Critical/High findings with INSUFFICIENT_EVIDENCE map to HUMAN_REVIEW_REQUIRED
 * - Solitary findings with CONTESTED verdict are removed from blocking set (advisory pass)
 * - Corroborated findings with CONTESTED verdict map to HUMAN_REVIEW_REQUIRED
 * - Structural failures (coverage, quorum, capability, verification error) strictly FAIL-CLOSED BLOCK
 * - Verifier omissions evaluated across Tier 1 and Tier 2 per 13-branch decision truth table (§3.1.1)
 */
function getFindingId(f, i) {
  if (!f) return `finding-${i + 1}`;
  if (f.id !== undefined && f.id !== null && String(f.id).trim().length > 0) {
    return String(f.id).trim();
  }
  if (f.findingId !== undefined && f.findingId !== null && String(f.findingId).trim().length > 0) {
    return String(f.findingId).trim();
  }
  return `finding-${i + 1}`;
}

export function getFindingSignature(f) {
  if (!f || typeof f !== "object") return "";
  const id = f.id !== undefined && f.id !== null ? String(f.id).trim() : (f.findingId !== undefined && f.findingId !== null ? String(f.findingId).trim() : "");
  const ruleId = String(f.ruleId || "").trim();
  const title = String(f.title || f.name || f.message || "").replace(/\r\n/g, "\n").trim();
  const file = String(f.file || f.path || "").replace(/\\/g, "/").trim();
  const lineStart = String(f.line_start ?? f.line ?? f.startLine ?? "1").trim();
  const lineEnd = String(f.line_end ?? f.endLine ?? lineStart).trim();
  const severity = String(f.severity || "").trim().toLowerCase();
  const cwe = String(f.cwe || "").trim();
  const type = String(f.type || "").trim().toLowerCase();
  const recommendation = String(f.recommendation || f.body || "").replace(/\r\n/g, "\n").trim();

  // td7cI: deterministically normalize and bind sources and corroborations
  let normSources;
  if (f.sources === undefined) {
    normSources = null;
  } else if (Array.isArray(f.sources)) {
    normSources = [...new Set(f.sources.map(s => String(s || "").trim().toLowerCase()).filter(Boolean))].sort();
  } else if (typeof f.sources === "string") {
    const trimmed = f.sources.trim().toLowerCase();
    normSources = trimmed ? [trimmed] : [];
  } else {
    normSources = `INVALID:${String(f.sources)}`;
  }

  let normCorroborations;
  if (f.corroborations === undefined) {
    normCorroborations = Array.isArray(normSources) ? normSources.length : null;
  } else if (f.corroborations === null) {
    normCorroborations = null;
  } else if (typeof f.corroborations === "number") {
    if (Number.isFinite(f.corroborations) && f.corroborations > 0 && Math.floor(f.corroborations) === f.corroborations) {
      normCorroborations = f.corroborations;
    } else {
      normCorroborations = `ILLEGAL:${f.corroborations}`;
    }
  } else if (typeof f.corroborations === "string" && /^[1-9]\d*$/.test(f.corroborations.trim())) {
    normCorroborations = parseInt(f.corroborations.trim(), 10);
  } else {
    normCorroborations = `ILLEGAL:${String(f.corroborations)}`;
  }

  return JSON.stringify([id, ruleId, title, file, lineStart, lineEnd, severity, cwe, type, recommendation, normSources, normCorroborations]);
}

function findEvaluationIndexForFinding(evaluations, finding, findingIndex, usedIndices) {
  const fId = getFindingId(finding, findingIndex);
  const lowerFId = fId.toLowerCase();

  // Pass 1: exact match on findingId or id
  let matchIdx = evaluations.findIndex((e, idx) => !usedIndices.has(idx) && (
    String(e?.findingId).trim() === fId || String(e?.id).trim() === fId
  ));
  if (matchIdx !== -1) return matchIdx;

  // Pass 2: case-insensitive exact match
  matchIdx = evaluations.findIndex((e, idx) => !usedIndices.has(idx) && (
    String(e?.findingId).trim().toLowerCase() === lowerFId || String(e?.id).trim().toLowerCase() === lowerFId
  ));
  if (matchIdx !== -1) return matchIdx;

  // Pass 3: match on providerFindingId or raw id
  if (finding?.providerFindingId) {
    const rawId = String(finding.providerFindingId).trim();
    const lowerRawId = rawId.toLowerCase();
    matchIdx = evaluations.findIndex((e, idx) => !usedIndices.has(idx) && (
      String(e?.findingId).trim() === rawId ||
      String(e?.id).trim() === rawId ||
      String(e?.findingId).trim().toLowerCase() === lowerRawId ||
      String(e?.id).trim().toLowerCase() === lowerRawId
    ));
    if (matchIdx !== -1) return matchIdx;
  }

  // Pass 4: prefix strip match (e.g. fId is 'agy:finding-1', eval is 'finding-1')
  const colonIdx = fId.indexOf(':');
  if (colonIdx !== -1) {
    const suffix = fId.slice(colonIdx + 1);
    const lowerSuffix = suffix.toLowerCase();
    matchIdx = evaluations.findIndex((e, idx) => !usedIndices.has(idx) && (
      String(e?.findingId).trim() === suffix ||
      String(e?.id).trim() === suffix ||
      String(e?.findingId).trim().toLowerCase() === lowerSuffix ||
      String(e?.id).trim().toLowerCase() === lowerSuffix
    ));
    if (matchIdx !== -1) return matchIdx;
  }

  // Pass 5: eval prefix strip match (e.g. fId is 'finding-1', eval is 'agy:finding-1')
  matchIdx = evaluations.findIndex((e, idx) => {
    if (usedIndices.has(idx)) return false;
    const evId = String(e?.findingId || e?.id || "").trim();
    const evColon = evId.indexOf(':');
    if (evColon === -1) return false;
    const evSuffix = evId.slice(evColon + 1);
    return evSuffix === fId || evSuffix.toLowerCase() === lowerFId;
  });

  return matchIdx;
}

function _evaluatePostVerificationGateCore(consensus, verificationRecord, options = {}, { allowSynthetic = false } = {}) {
  // Defect 6: Post-Verification Consensus Integrity (PRRT_kwDOUWarIc6sPmw9)
  const isUncertain = verificationRecord?.overallStatus === "UNCERTAIN" || verificationRecord?.status === "UNCERTAIN";
  if (!allowSynthetic && !isUncertain) {
    if (!consensus || !isTrustedConsensus(consensus)) {
      return {
        decision: "block",
        reason: "Gate Fail-Closed: Untrusted or missing consensus capability (UNTRUSTED_OR_MISSING_CONSENSUS).",
        criticals: [],
        advisoryFindings: []
      };
    }

    if (!consensus.quorumReached || consensus.verdict === "error") {
      return {
        decision: "block",
        reason: consensus.consensusProof || "Gate Fail-Closed: Quorum failure or error verdict.",
        criticals: [],
        advisoryFindings: []
      };
    }
  }

  // Row 13: Execution Failure / Timeout / Malformed
  if (!verificationRecord || verificationRecord.ok === false) {
    return {
      decision: "block",
      reason: verificationRecord?.error || "Gate Fail-Closed: Verifier execution failed, timed out, or incomplete.",
      criticals: [],
      advisoryFindings: []
    };
  }

  if (allowSynthetic) {
    if (!isTrustedVerificationRecord(verificationRecord) && !isSegregatedSyntheticRecord(verificationRecord)) {
      return {
        decision: "block",
        reason: "Gate Fail-Closed: Untrusted verification record capability (UNTRUSTED_VERIFICATION_RECORD).",
        criticals: [],
        advisoryFindings: []
      };
    }
  } else {
    if (!isTrustedVerificationRecord(verificationRecord) || isSegregatedSyntheticRecord(verificationRecord)) {
      return {
        decision: "block",
        reason: "Gate Fail-Closed: Untrusted verification record capability (UNTRUSTED_VERIFICATION_RECORD).",
        criticals: [],
        advisoryFindings: []
      };
    }
  }

  const findings = Array.isArray(consensus?.findings) ? consensus.findings : [];
  const evaluations = Array.isArray(verificationRecord.evaluations) ? verificationRecord.evaluations : [];
  const omissions = Array.isArray(verificationRecord.verifierOmissions) ? verificationRecord.verifierOmissions : [];

  if (findings.length === 0) {
    if (evaluations.length > 0) {
      return {
        decision: "block",
        reason: `Gate Fail-Closed: Verification record finding set mismatch (FINDING_SET_BINDING_MISMATCH: zero-finding consensus cannot bind evaluations).`,
        criticals: [],
        advisoryFindings: []
      };
    }
    if (verificationRecord.verificationMode !== "clean_challenge") {
      return {
        decision: "block",
        reason: `Verification mode mismatch: zero-finding consensus requires 'clean_challenge' mode (got: '${verificationRecord.verificationMode || "none"}').`,
        criticals: [],
        advisoryFindings: []
      };
    }
  } else {
    // Defect 7: Strict Verification Mode Validation for Non-Empty Consensus (PRRT_kwDOUWarIc6sPGEP, PRRT_kwDOUWarIc6ra7kY)
    if (verificationRecord.verificationMode !== "producer_verification") {
      return {
        decision: "block",
        reason: `Verification mode mismatch: nonempty consensus requires 'producer_verification' mode (got: '${verificationRecord.verificationMode || "none"}').`,
        criticals: [],
        advisoryFindings: []
      };
    }
  }

  // Finding Set Binding Verification (P1, PR-39 Item 3):
  // When findings are present, verify that current findings strictly match findings bound to verificationRecord.
  if (findings.length > 0) {
    // Check for duplicate finding IDs in producer findings (PR-39 Item 2 / DUPLICATE_FINDING_ID)
    const seenFindingIds = new Set();
    for (let i = 0; i < findings.length; i++) {
      const fId = getFindingId(findings[i], i);
      const normFId = fId.toLowerCase();
      if (seenFindingIds.has(normFId)) {
        return {
          decision: "block",
          reason: `Gate Fail-Closed: Producer findings contain duplicate finding ID '${fId}' (DUPLICATE_FINDING_ID).`,
          criticals: [],
          advisoryFindings: []
        };
      }
      seenFindingIds.add(normFId);
    }

    // Check for duplicate finding IDs in verificationRecord evaluations (PR-39 Item 2 / DUPLICATE_FINDING_ID)
    const seenEvalIds = new Set();
    for (let i = 0; i < evaluations.length; i++) {
      const ev = evaluations[i];
      const evId = String(ev?.findingId || ev?.id || "").trim();
      if (!evId) {
        return {
          decision: "block",
          reason: `Gate Fail-Closed: Verification record evaluation at index ${i} is missing finding ID (MALFORMED_OUTPUT).`,
          criticals: [],
          advisoryFindings: []
        };
      }
      const normEvId = evId.toLowerCase();
      if (seenEvalIds.has(normEvId)) {
        return {
          decision: "block",
          reason: `Gate Fail-Closed: Verification record contains duplicate evaluation for finding ID '${evId}' (DUPLICATE_FINDING_ID).`,
          criticals: [],
          advisoryFindings: []
        };
      }
      seenEvalIds.add(normEvId);
    }

    if (evaluations.length !== findings.length) {
      return {
        decision: "block",
        reason: `Gate Fail-Closed: Verification record finding set mismatch (FINDING_SET_BINDING_MISMATCH: finding count ${findings.length} vs evaluations count ${evaluations.length}).`,
        criticals: [],
        advisoryFindings: []
      };
    }

    const boundProducerFindings = (Array.isArray(verificationRecord.producer?.findings) && verificationRecord.producer.findings.length > 0)
      ? verificationRecord.producer.findings
      : ((Array.isArray(verificationRecord.producerFindings) && verificationRecord.producerFindings.length > 0)
          ? verificationRecord.producerFindings
          : null);
    if (boundProducerFindings) {
      const seenBoundIds = new Set();
      for (let i = 0; i < boundProducerFindings.length; i++) {
        const boundId = getFindingId(boundProducerFindings[i], i);
        const normBoundId = boundId.toLowerCase();
        if (seenBoundIds.has(normBoundId)) {
          return {
            decision: "block",
            reason: `Gate Fail-Closed: Bound producer findings contain duplicate finding ID '${boundId}' (DUPLICATE_FINDING_ID).`,
            criticals: [],
            advisoryFindings: []
          };
        }
        seenBoundIds.add(normBoundId);
      }
      if (boundProducerFindings.length !== findings.length) {
        return {
          decision: "block",
          reason: `Gate Fail-Closed: Verification record finding set mismatch (FINDING_SET_BINDING_MISMATCH: count ${findings.length} vs bound ${boundProducerFindings.length}).`,
          criticals: [],
          advisoryFindings: []
        };
      }
      for (let i = 0; i < findings.length; i++) {
        const curId = getFindingId(findings[i], i);
        const boundId = getFindingId(boundProducerFindings[i], i);
        const idsMatch = curId === boundId ||
          curId.toLowerCase() === boundId.toLowerCase() ||
          (findings[i]?.providerFindingId && String(findings[i].providerFindingId).trim() === boundId) ||
          (boundProducerFindings[i]?.providerFindingId && String(boundProducerFindings[i].providerFindingId).trim() === curId) ||
          (curId.includes(':') && curId.slice(curId.indexOf(':') + 1) === boundId) ||
          (boundId.includes(':') && boundId.slice(boundId.indexOf(':') + 1) === curId);

        let sigsMatch = getFindingSignature(findings[i]) === getFindingSignature(boundProducerFindings[i]);
        if (!sigsMatch && idsMatch) {
          const sigA = getFindingSignature({ ...findings[i], id: "MATCH_ID" });
          const sigB = getFindingSignature({ ...boundProducerFindings[i], id: "MATCH_ID" });
          sigsMatch = sigA === sigB;
          if (!sigsMatch && boundProducerFindings[i]?.sources === undefined && boundProducerFindings[i]?.corroborations === undefined) {
            const fCorroborations = Number(findings[i]?.corroborations || findings[i]?.sources?.length || 1);
            if (fCorroborations <= 1) {
              const sigBWithSolitary = getFindingSignature({
                ...boundProducerFindings[i],
                id: "MATCH_ID",
                sources: findings[i]?.sources,
                corroborations: findings[i]?.corroborations
              });
              sigsMatch = sigA === sigBWithSolitary;
            }
          }
        }

        if (!idsMatch || !sigsMatch) {
          return {
            decision: "block",
            reason: `Gate Fail-Closed: Verification record finding set mismatch (FINDING_SET_BINDING_MISMATCH: finding at index ${i} does not match bound producer finding).`,
            criticals: [],
            advisoryFindings: []
          };
        }
      }
    } else {
      // Synthetic or evaluation-only record: verify evaluations count and ID correspondence
      const matchedEvalIndices = new Set();
      for (let i = 0; i < findings.length; i++) {
        const curId = getFindingId(findings[i], i);
        const matchIdx = findEvaluationIndexForFinding(evaluations, findings[i], i, matchedEvalIndices);
        if (matchIdx === -1) {
          return {
            decision: "block",
            reason: `Gate Fail-Closed: Verification record finding set mismatch (FINDING_SET_BINDING_MISMATCH: missing evaluation for finding '${curId}').`,
            criticals: [],
            advisoryFindings: []
          };
        }
        matchedEvalIndices.add(matchIdx);
      }
    }
  }

  // Defect 1: Mandatory RunContext Binding (PRRT_kwDOUWarIc6sU7ZN)
  if (!allowSynthetic && !isUncertain) {
    if (!options?.runContext || typeof options.runContext !== "object") {
      return {
        decision: "block",
        reason: "Gate Fail-Closed: Mandatory RunContext missing for verification record authority (UNTRUSTED_OR_MISSING_RUN_CONTEXT).",
        criticals: [],
        advisoryFindings: []
      };
    }
  }

  if (options?.runContext) {
    // Defect 4: RunContext Construction Error Containment (PRRT_kwDOUWarIc6riPTv)
    let rc;
    try {
      rc = options.runContext instanceof RunContext
        ? options.runContext
        : new RunContext(options.runContext);
    } catch (err) {
      return {
        decision: "block",
        reason: `Gate Fail-Closed: Malformed RunContext conversion failed (MALFORMED_RUN_CONTEXT_CONVERSION_FAILED): ${err.message}`,
        criticals: [],
        advisoryFindings: []
      };
    }

    const vr = verificationRecord;

    // Defect 5: Malformed Non-Empty Head & Digest Field Handling (PRRT_kwDOUWarIc6rvCBG)
    const rawHead = options.runContext instanceof RunContext
      ? options.runContext.headSha
      : (options.runContext?.headSha ?? options.runContext?.head);
    const rawDigest = options.runContext instanceof RunContext
      ? options.runContext.contentDigest
      : (options.runContext?.contentDigest ?? options.runContext?.changeSetDigest);

    if (rawDigest !== undefined && rawDigest !== null && String(rawDigest).trim().length > 0) {
      if (!normalizeDigest(String(rawDigest))) {
        return {
          decision: "block",
          reason: "Gate Fail-Closed: Malformed RunContext binding (MALFORMED_RUN_CONTEXT_BINDING: invalid contentDigest hex string).",
          criticals: [],
          advisoryFindings: []
        };
      }
    }

    if (rawHead !== undefined && rawHead !== null && String(rawHead).trim().length > 0) {
      if (!normalizeCommitSha(String(rawHead))) {
        return {
          decision: "block",
          reason: "Gate Fail-Closed: Malformed RunContext binding (MALFORMED_RUN_CONTEXT_BINDING: invalid headSha hex string).",
          criticals: [],
          advisoryFindings: []
        };
      }
    }

    // 1. Content Digest Binding (Mandatory if rc has contentDigest)
    if (rc.contentDigest) {
      const vrDigest = vr.changeSetDigest || vr.contentDigest;
      if (!vrDigest || normalizeDigest(vrDigest) !== normalizeDigest(rc.contentDigest)) {
        return {
          decision: "block",
          reason: "Gate Fail-Closed: Verification record binding mismatch (FORGED_OR_STALE_RECORD).",
          criticals: [],
          advisoryFindings: []
        };
      }
    }

    // 2. Patch Objective Binding (Mandatory if rc has patchObjective)
    if (rc.patchObjective) {
      if (!vr.patchObjective || normalizeObjective(vr.patchObjective) !== normalizeObjective(rc.patchObjective)) {
        return {
          decision: "block",
          reason: "Gate Fail-Closed: Verification record binding mismatch (FORGED_OR_STALE_RECORD).",
          criticals: [],
          advisoryFindings: []
        };
      }
    }

    // 3. Head SHA Binding (Mandatory if rc has headSha)
    if (rc.headSha) {
      if (!vr.headSha || normalizeCommitSha(vr.headSha) !== normalizeCommitSha(rc.headSha)) {
        return {
          decision: "block",
          reason: "Gate Fail-Closed: Verification record binding mismatch (FORGED_OR_STALE_RECORD).",
          criticals: [],
          advisoryFindings: []
        };
      }
    }

    // 4. Run ID Binding (Mandatory if rc has runId)
    if (rc.runId) {
      const vrRunId = vr.runId || vr.producer?.runId;
      if (!vrRunId || String(vrRunId).trim() !== String(rc.runId).trim()) {
        return {
          decision: "block",
          reason: "Gate Fail-Closed: Verification record binding mismatch (FORGED_OR_STALE_RECORD).",
          criticals: [],
          advisoryFindings: []
        };
      }
    }

    // 5. Exclusions Binding (Mandatory bidirectional check: rc and vr must strictly match)
    // Defect 3: Platform-Aware Case-Sensitive Exclusions (PRRT_kwDOUWarIc6rsKB_)
    const rcExcl = Array.isArray(rc.exclusions) ? rc.exclusions : [];
    const vrExcl = Array.isArray(vr.exclusions)
      ? vr.exclusions
      : (Array.isArray(vr.objectiveContract?.exclusions) ? vr.objectiveContract.exclusions : []);

    if (rcExcl.length > 0 || (Array.isArray(vrExcl) && vrExcl.length > 0)) {
      if (!Array.isArray(vrExcl)) {
        return {
          decision: "block",
          reason: "Gate Fail-Closed: Verification record binding mismatch (FORGED_OR_STALE_RECORD).",
          criticals: [],
          advisoryFindings: []
        };
      }
      const targetPlatform = allowSynthetic && options?.platform ? options.platform : process.platform;
      const normRcExcl = rcExcl.map(s => normalizeExclusionPath(s, { platform: targetPlatform })).sort();
      const normVrExcl = vrExcl.map(s => normalizeExclusionPath(s, { platform: targetPlatform })).sort();
      if (normRcExcl.length !== normVrExcl.length || !normRcExcl.every((v, i) => v === normVrExcl[i])) {
        return {
          decision: "block",
          reason: "Gate Fail-Closed: Verification record binding mismatch (FORGED_OR_STALE_RECORD: Exclusion path mismatch).",
          criticals: [],
          advisoryFindings: []
        };
      }
    }
  }
  const hasBoundPatchObjective =
    typeof verificationRecord.patchObjective === "string" &&
    verificationRecord.patchObjective.trim().length > 0;
  const isTier1 = options?.tier === 1 || options?.isTier1 === true;
  const isStrict = Boolean(options && (options.strict || isTier1));

  let hasBlocker = false;
  let hasHumanReview = false;
  const blockReasons = [];
  const humanReviewReasons = [];
  const criticals = [];
  const advisoryFindings = [];

  // Row 11 (Record level): Verifier Context Insufficient / Uncertain
  if (verificationRecord.overallStatus === "UNCERTAIN" || verificationRecord.status === "UNCERTAIN") {
    hasHumanReview = true;
    humanReviewReasons.push("Context Insufficient / Uncertain: Verifier declared UNCERTAIN due to missing callee context boundaries.");
  }

  // Record level: Verifier Defects Found consistency (Thread 5 & P1-04)
  const isDefectsFound = verificationRecord.overallStatus === "DEFECTS_FOUND" || verificationRecord.status === "DEFECTS_FOUND";
  if (isDefectsFound) {
    const hasSupportedOmission = omissions.some(o => String(o?.evidenceSupport || "").toUpperCase() === "SUPPORTED");
    const hasSupportedEvaluation = evaluations.some(e => String(e?.verdict || "").toUpperCase() === "SUPPORTED");

    if (findings.length === 0) {
      if (omissions.length === 0) {
        hasBlocker = true;
        blockReasons.push("Clean Challenge failed: Verifier reported DEFECTS_FOUND without omissions.");
      } else if (!hasSupportedOmission) {
        hasHumanReview = true;
        humanReviewReasons.push("Verifier Status Inconsistent: Verifier declared DEFECTS_FOUND without any SUPPORTED omission; requires human adjudication.");
      }
    } else {
      if (!hasSupportedEvaluation && !hasSupportedOmission) {
        hasHumanReview = true;
        humanReviewReasons.push("Verifier Status Inconsistent: Verifier declared DEFECTS_FOUND without any SUPPORTED evaluation or omission; requires human adjudication.");
      }
    }
  }

  // Diff Truncation Fail-Closed (P1-03)
  if (verificationRecord.diffTruncated === true) {
    hasHumanReview = true;
    humanReviewReasons.push("Diff Truncated / Incomplete: Verifier diff exceeded input limit; tail not inspected.");
  }

  // Clean Challenge overallStatus authority check (Spec §3.1)
  if (findings.length === 0) {
    if (verificationRecord.overallStatus !== "CLEAN" && verificationRecord.overallStatus !== "UNCERTAIN" && verificationRecord.overallStatus !== "DEFECTS_FOUND") {
      hasBlocker = true;
      blockReasons.push(`Clean Challenge requires explicit CLEAN overallStatus (got: '${verificationRecord.overallStatus || "none"}').`);
    }
  }

  // Phase A: Evaluate Producer Findings
  const usedEvaluationIndices = new Set();
  for (let i = 0; i < findings.length; i++) {
    const f = findings[i];
    if (!f) continue;

    const fId = getFindingId(f, i);
    const evalMatchIdx = findEvaluationIndexForFinding(evaluations, f, i, usedEvaluationIndices);
    if (evalMatchIdx === -1) {
      return {
        decision: "block",
        reason: `Gate Fail-Closed: Verification record finding set mismatch (FINDING_SET_BINDING_MISMATCH: missing evaluation for finding '${fId}').`,
        criticals: [],
        advisoryFindings: []
      };
    }
    usedEvaluationIndices.add(evalMatchIdx);
    const evalMatch = evaluations[evalMatchIdx];

    let verdict = String(evalMatch?.verdict || "INSUFFICIENT_EVIDENCE").toUpperCase();
    let classification = String(evalMatch?.classification || "").toUpperCase();

    // Invariant (PR-39 Item 3 / UNGROUNDED_CONTESTED_VERDICT):
    // CONTESTED verdict MUST be backed by substantive reasoning, counterexample, or dissent.
    if (verdict === "CONTESTED" || classification === "CONTRADICTED") {
      const hasSubstantive = isSubstantiveContestedReasoning(evalMatch?.reasoning) ||
        isSubstantiveContestedReasoning(evalMatch?.dissent) ||
        isSubstantiveContestedReasoning(evalMatch?.counterexample);
      if (!hasSubstantive) {
        if (isStrict) {
          return {
            decision: "block",
            reason: `Gate Fail-Closed: Verification record contains ungrounded CONTESTED evaluation for finding '${fId}' without substantive counter-evidence (UNGROUNDED_CONTESTED_VERDICT).`,
            criticals: [],
            advisoryFindings: []
          };
        }
        const corroborationsCount = Number(f.corroborations || f.sources?.length || 1);
        if (corroborationsCount >= 2) {
          hasHumanReview = true;
          humanReviewReasons.push(`Corroborated finding contested by verifier requires human adjudication: "${f.title}"`);
          continue;
        }
        verdict = "INSUFFICIENT_EVIDENCE";
        classification = "UNVERIFIABLE";
      }
    }

    const isContested = verdict === "CONTESTED" || classification === "CONTRADICTED";
    const isSupported = verdict === "SUPPORTED";
    const isInsufficient = verdict === "INSUFFICIENT_EVIDENCE" || classification === "UNVERIFIABLE";
    const objectiveImpact = String(evalMatch?.objectiveImpact || "NOT_ASSESSED").toUpperCase();
    const falsifiesPatchObjective =
      isSupported &&
      !isContested &&
      hasBoundPatchObjective &&
      objectiveImpact === "FALSIFIES_PATCH_OBJECTIVE";

    const corroborations = Number(f.corroborations || f.sources?.length || 1);
    const isSolitary = corroborations <= 1;
    const isCorroborated = corroborations >= 2;

    const rawSeverity = String(f.severity || "medium").toLowerCase();
    let effectiveSeverity = rawSeverity;

    if (evalMatch && evalMatch.severityAccurate === false) {
      if (rawSeverity === "critical" || rawSeverity === "high") {
        hasHumanReview = true;
        humanReviewReasons.push(`Critical/high severity contested by verifier: "${f.title}"`);
        if (!falsifiesPatchObjective) continue;
      } else if (rawSeverity === "medium" && isSupported) {
        effectiveSeverity = "low";
      }
    }

    if (falsifiesPatchObjective) {
      hasBlocker = true;
      if (rawSeverity === "critical" || rawSeverity === "high") criticals.push(f);
      blockReasons.push(`Verified finding directly falsifies stated patch objective: "${f.title}"`);
      continue;
    }

    if (effectiveSeverity === "critical" || effectiveSeverity === "high") {
      if (isContested) {
        hasHumanReview = true;
        humanReviewReasons.push(`Critical/high severity finding contested by verifier: "${f.title}"`);
      } else {
        hasBlocker = true;
        criticals.push(f);
        blockReasons.push(`Found critical/high severity finding: "${f.title}"`);
      }
    } else if (effectiveSeverity === "medium") {
      if (isContested) {
        if (isCorroborated) {
          hasHumanReview = true;
          humanReviewReasons.push(`Corroborated medium finding contested by verifier: "${f.title}"`);
        } else {
          // Solitary medium finding contested by verifier -> removed from blocking set (advisory)
          advisoryFindings.push(f);
        }
      } else if (isInsufficient) {
        if (isCorroborated) {
          hasBlocker = true;
          blockReasons.push(`Corroborated medium finding cannot be substantiated by verifier: "${f.title}"`);
        } else {
          hasHumanReview = true;
          humanReviewReasons.push(`Solitary medium finding cannot be substantiated by verifier (INSUFFICIENT_EVIDENCE): "${f.title}"`);
        }
      } else if (isSupported) {
        hasBlocker = true;
        blockReasons.push(isTier1
          ? `Tier 1 high-risk policy: verified medium finding blocks merge: "${f.title}"`
          : `Verified medium finding blocks merge: "${f.title}"`);
      }
    } else if (effectiveSeverity === "low" || effectiveSeverity === "info") {
      if (isContested) {
        if (isCorroborated && (f.type === "OBJECTIVE_CONTRADICTION" || f.ruleId === "OBJECTIVE-CONTRADICTION")) {
          hasHumanReview = true;
          humanReviewReasons.push(`Corroborated objective contradiction contested by verifier requires human adjudication: "${f.title}"`);
        } else {
          advisoryFindings.push(f);
        }
      } else if (isInsufficient) {
        if (isTier1 && isStrict) {
          hasHumanReview = true;
          humanReviewReasons.push(`Tier 1 low finding unverifiable: "${f.title}"`);
        } else {
          advisoryFindings.push(f);
        }
      } else if (isSupported) {
        if (isTier1 || isStrict) {
          hasBlocker = true;
          blockReasons.push(`Tier 1 policy: verified low finding blocks merge: "${f.title}"`);
        } else {
          advisoryFindings.push(f);
        }
      }
    }
  }

  // Phase B: Evaluate Verifier Omissions (Spec §3.1.1 Rows 2-11)
  for (let i = 0; i < omissions.length; i++) {
    const omission = omissions[i];
    if (!omission) continue;

    const rawSev = String(omission.severity || "medium").toLowerCase();
    const evidenceSupport = String(omission.evidenceSupport || "INSUFFICIENT_EVIDENCE").toUpperCase();
    const objectiveImpact = String(omission.objectiveImpact || "NOT_ASSESSED").toUpperCase();
    const falsifiesPatchObjective =
      evidenceSupport === "SUPPORTED" &&
      hasBoundPatchObjective &&
      objectiveImpact === "FALSIFIES_PATCH_OBJECTIVE";

    // Row 2: Confirmed Objective Violation (any severity)
    if (falsifiesPatchObjective) {
      hasBlocker = true;
      if (rawSev === "critical" || rawSev === "high") criticals.push(omission);
      blockReasons.push(`Confirmed Objective Violation: Verified omission directly falsifies stated patch objective: "${omission.title}"`);
      continue;
    }

    // Row 3: Confirmed Critical / High Omission
    if (evidenceSupport === "SUPPORTED" && (rawSev === "critical" || rawSev === "high")) {
      hasBlocker = true;
      criticals.push(omission);
      blockReasons.push(`Confirmed Critical / High Omission: Verified omission missed by sentries: "${omission.title}"`);
      continue;
    }

    // Row 4 & 5: Supported Medium Omission
    if (evidenceSupport === "SUPPORTED" && rawSev === "medium") {
      if (isTier1) {
        // Row 4: Tier 1 -> BLOCK
        hasBlocker = true;
        blockReasons.push(`Supported Medium Omission (Tier 1): Verified medium omission blocks under Tier 1 policy: "${omission.title}"`);
      } else {
        // Row 5: Tier 2 -> HUMAN_REVIEW_REQUIRED
        hasHumanReview = true;
        humanReviewReasons.push(`Supported Medium Omission (Tier 2): Verified medium omission requires human adjudication: "${omission.title}"`);
      }
      continue;
    }

    // Row 6 & 7: Supported Low/Info Omission
    if (evidenceSupport === "SUPPORTED" && (rawSev === "low" || rawSev === "info")) {
      if (isTier1) {
        // Row 6: Tier 1 -> HUMAN_REVIEW_REQUIRED
        hasHumanReview = true;
        humanReviewReasons.push(`Supported Low Omission (Tier 1): Verified low omission requires human confirmation: "${omission.title}"`);
      } else {
        // Row 7: Tier 2 -> APPROVE (Advisory)
        advisoryFindings.push(omission);
      }
      continue;
    }

    // Row 8 & 9: Contested Omission
    if (evidenceSupport === "CONTESTED") {
      const hasSubstantive = isSubstantiveContestedReasoning(omission.reasoning) ||
        isSubstantiveContestedReasoning(omission.dissent) ||
        isSubstantiveContestedReasoning(omission.counterexample) ||
        isSubstantiveContestedReasoning(omission.recommendation) ||
        isSubstantiveContestedReasoning(omission.body);
      if (!hasSubstantive) {
        if (isStrict) {
          return {
            decision: "block",
            reason: `Gate Fail-Closed: Verification record contains ungrounded CONTESTED omission '${omission.title}' without substantive counter-evidence (UNGROUNDED_CONTESTED_VERDICT).`,
            criticals: [],
            advisoryFindings: []
          };
        }
        hasHumanReview = true;
        humanReviewReasons.push(`Ungrounded contested omission lacks substantive counter-evidence (INSUFFICIENT_EVIDENCE): "${omission.title}"`);
        continue;
      }

      if (isTier1 && (rawSev === "critical" || rawSev === "high")) {
        // Row 9: Tier 1 Critical/High -> HUMAN_REVIEW_REQUIRED
        hasHumanReview = true;
        humanReviewReasons.push(`Tier 1 contested high-severity omission requires human adjudication: "${omission.title}"`);
      } else {
        // Row 8: Tier 2 (or non-critical Tier 1) -> Advisory pass
        advisoryFindings.push(omission);
      }
      continue;
    }

    // Row 10: Unverified / Insufficient Evidence
    if (evidenceSupport === "INSUFFICIENT_EVIDENCE") {
      hasHumanReview = true;
      humanReviewReasons.push(`Unverified / Insufficient Evidence: Omission lacks verifiable counterexample: "${omission.title}"`);
      continue;
    }

    // Row 11 (Omission level): Context Insufficient / Uncertain
    if (evidenceSupport === "UNCERTAIN") {
      hasHumanReview = true;
      humanReviewReasons.push(`Context Insufficient / Uncertain: Omission declared UNCERTAIN: "${omission.title}"`);
      continue;
    }

    // Fallback unknown evidence state -> fail-safe human review
    hasHumanReview = true;
    humanReviewReasons.push(`Unrecognized omission assessment state for "${omission.title}"`);
  }

  if (hasBlocker) {
    return {
      decision: "block",
      reason: blockReasons[0] || "Blocking findings identified by verified review.",
      criticals,
      advisoryFindings
    };
  }

  if (hasHumanReview) {
    return {
      decision: "human_review_required",
      reason: humanReviewReasons[0] || "Review requires human adjudication.",
      criticals: [],
      advisoryFindings
    };
  }

  return {
    decision: "approve",
    reason: (findings.length === 0 && omissions.length === 0)
      ? "Clean Challenge passed: zero findings and zero verified omissions."
      : "No blocking vulnerabilities found. CI/CD Gate passed.",
    criticals: [],
    advisoryFindings
  };
}

export function evaluatePostVerificationGate(consensus, verificationRecord, options = {}) {
  return _evaluatePostVerificationGateCore(consensus, verificationRecord, options, { allowSynthetic: false });
}

export function evaluateIsolatedTestPostVerificationGate(consensus, verificationRecord, options = {}) {
  return _evaluatePostVerificationGateCore(consensus, verificationRecord, options, { allowSynthetic: true });
}

function sanitizeText(str) {
  if (typeof str !== "string") return "";
  return str
    .replace(/\u001b\[[0-9;]*[a-zA-Z]/g, "")
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
}

export function toSarifRelativeUri(filePath) {
  if (typeof filePath !== "string" || !filePath.trim()) return "unknown";

  if (/^(?:javascript|data|vbscript|file):/i.test(filePath)) {
    return "sanitized-path-blocked";
  }

  let normalized = filePath.replace(/\\/g, "/").replace(/^\/+/, "");
  return normalized
    .split("/")
    .map(seg => encodeURIComponent(seg))
    .join("/");
}

export function deriveRuleId(finding = {}) {
  if (finding.ruleId && typeof finding.ruleId === "string" && finding.ruleId.trim()) {
    return finding.ruleId.trim();
  }

  const rawTitle = sanitizeText(String(finding.title || finding.message || "security_finding")).trim().normalize("NFC");
  const slug = rawTitle
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 32) || "finding";

  const hash = crypto.createHash("sha256").update(rawTitle, "utf8").digest("hex").slice(0, 8);
  return `${slug}_${hash}`;
}

export function formatSarifReport(findings = [], metadata = {}) {
  const ruleMap = new Map();

  for (const f of findings) {
    const rawTitle = sanitizeText(String(f?.title || "Security Finding")).trim().normalize("NFC");
    const ruleId = deriveRuleId(f);

    if (!ruleMap.has(ruleId)) {
      ruleMap.set(ruleId, {
        id: ruleId,
        name: rawTitle,
        shortDescription: { text: rawTitle }
      });
    }
  }

  const driverRules = Array.from(ruleMap.values()).sort((a, b) => a.id.localeCompare(b.id));
  const ruleIndexMap = new Map(driverRules.map((r, idx) => [r.id, idx]));

  const results = findings.map(f => {
    const rawTitle = sanitizeText(String(f?.title || "Security Finding")).trim().normalize("NFC");
    const body = sanitizeText(String(f?.recommendation || f?.body || f?.summary || f?.message || rawTitle));
    const ruleId = deriveRuleId(f);
    const ruleIndex = ruleIndexMap.get(ruleId) ?? 0;

    const startLine = Math.max(1, Math.floor(Number(f?.line_start || f?.line) || 1));
    const endLine = Math.max(startLine, Math.floor(Number(f?.line_end) || startLine));
    const uri = toSarifRelativeUri(f?.file || f?.path);

    return {
      ruleId,
      ruleIndex,
      level: /critical|high/i.test(String(f?.severity || "")) ? "error" : "warning",
      message: { text: body },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri },
            region: {
              startLine,
              endLine
            }
          }
        }
      ]
    };
  });

  return {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Triad-Flow Sentry",
            version: "2.7.0",
            informationUri: "https://github.com/arcobaleno64/triad-flow",
            rules: driverRules
          }
        },
        ...(metadata.executionSuccessful !== undefined || metadata.failureReason ? {
          invocations: [
            {
              executionSuccessful: metadata.executionSuccessful !== false,
              ...(metadata.failureReason ? {
                toolExecutionNotifications: [
                  {
                    level: metadata.executionSuccessful === false ? "error" : "note",
                    message: { text: sanitizeText(String(metadata.failureReason)) }
                  }
                ]
              } : {})
            }
          ]
        } : {}),
        results
      }
    ]
  };
}

/**
 * Validates a SARIF report object against the OASIS SARIF 2.1.0 specification structure.
 */
export function validateSarifStructure(sarif) {
  const errors = [];

  if (!sarif || typeof sarif !== "object" || Array.isArray(sarif)) {
    return { valid: false, errors: ["SARIF document must be a non-null object."] };
  }

  if (sarif.version !== "2.1.0") {
    errors.push(`SARIF version must be exactly '2.1.0', received: '${sarif.version}'`);
  }

  if (typeof sarif.$schema !== "string" || !sarif.$schema.includes("sarif")) {
    errors.push("SARIF $schema must be a valid schema URI string.");
  }

  if (!Array.isArray(sarif.runs) || sarif.runs.length === 0) {
    errors.push("SARIF runs must be a non-empty array.");
  } else {
    sarif.runs.forEach((run, runIdx) => {
      if (!run.tool?.driver?.name) {
        errors.push(`Run[${runIdx}]: tool.driver.name is required.`);
      }
      if (!run.tool?.driver?.version) {
        errors.push(`Run[${runIdx}]: tool.driver.version is required.`);
      }
      if (!Array.isArray(run.tool?.driver?.rules)) {
        errors.push(`Run[${runIdx}]: tool.driver.rules must be an array.`);
      }

      const driverRules = run.tool?.driver?.rules || [];
      const ruleIds = new Set(driverRules.map(r => r.id));

      if (run.invocations) {
        if (!Array.isArray(run.invocations)) {
          errors.push(`Run[${runIdx}]: invocations must be an array.`);
        } else {
          run.invocations.forEach((inv, invIdx) => {
            if (typeof inv.executionSuccessful !== "boolean") {
              errors.push(`Run[${runIdx}].invocations[${invIdx}]: executionSuccessful boolean is required.`);
            }
          });
        }
      }

      if (!Array.isArray(run.results)) {
        errors.push(`Run[${runIdx}]: results must be an array.`);
      } else {
        run.results.forEach((res, resIdx) => {
          if (!res.ruleId) {
            errors.push(`Run[${runIdx}].results[${resIdx}]: ruleId is required.`);
          } else if (!ruleIds.has(res.ruleId)) {
            errors.push(`Run[${runIdx}].results[${resIdx}]: ruleId '${res.ruleId}' is not declared in driver.rules.`);
          }
          if (typeof res.ruleIndex !== "number" || res.ruleIndex < 0 || res.ruleIndex >= driverRules.length) {
            errors.push(`Run[${runIdx}].results[${resIdx}]: ruleIndex '${res.ruleIndex}' is out of bounds.`);
          }
          if (!["error", "warning", "note", "none"].includes(res.level)) {
            errors.push(`Run[${runIdx}].results[${resIdx}]: level '${res.level}' is invalid.`);
          }
          if (!res.message?.text) {
            errors.push(`Run[${runIdx}].results[${resIdx}]: message.text is required.`);
          }
          if (!Array.isArray(res.locations) || res.locations.length === 0) {
            errors.push(`Run[${runIdx}].results[${resIdx}]: locations must be a non-empty array.`);
          }
        });
      }
    });
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

