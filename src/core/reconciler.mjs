/**
 * Triad-Flow Finding Reconciler & Canonical Semantic Key Aggregator (RFC-027-01)
 *
 * Implements cross-chunk and cross-provider finding deduplication,
 * +/- 15 line sliding window tolerance, and strict severity preservation.
 */

import crypto from "node:crypto";
import { normalizeCanonicalPath } from "./scoring.mjs";

export const SEVERITY_LEVELS = Object.freeze({
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1
});

export const SEVERITY_NAMES = Object.freeze(["info", "low", "medium", "high", "critical"]);

/**
 * Normalizes any severity string to standard lowercase.
 * @param {string} severity
 * @returns {"critical" | "high" | "medium" | "low" | "info"}
 */
export function normalizeSeverity(severity = "") {
  const s = String(severity).toLowerCase().trim();
  if (s === "critical" || s === "blocker") return "critical";
  if (s === "high") return "high";
  if (s === "medium" || s === "moderate") return "medium";
  if (s === "low") return "low";
  return "info";
}

/**
 * Normalizes CWE identifiers into strict lowercase "cwe-<number>".
 * @param {string} cwe
 * @param {string} [title=""]
 * @param {string} [type=""]
 * @returns {string}
 */
export function normalizeCweToken(cwe = "", title = "", type = "") {
  const rawCwe = String(cwe || "").trim();
  const numMatch = rawCwe.match(/^(?:CWE[-_]?)?(\d+)$/i);
  if (numMatch) {
    return `cwe-${numMatch[1]}`;
  }

  // Attempt extraction from title or type
  const combined = `${rawCwe} ${title || ""} ${type || ""}`;
  const extracted = combined.match(/\bCWE[-_]?(\d+)\b/i);
  if (extracted) {
    return `cwe-${extracted[1]}`;
  }

  // Fallback to type or sanitized title snippet
  if (type && typeof type === "string") {
    return type.toLowerCase().replace(/[^a-z0-9_-]/g, "-").slice(0, 24);
  }

  const sanitizedTitle = (title || "unclassified").toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 16);
  return sanitizedTitle || "generic";
}

/**
 * Computes the Canonical Semantic Finding Key:
 * file:line_bucket:cwe_token
 * @param {object} finding
 * @returns {string}
 */
export function computeCanonicalFindingKey(finding) {
  const normFile = normalizeCanonicalPath(finding.file || "");
  const lineStart = Math.max(parseInt(finding.line_start, 10) || 1, 1);
  const lineBucket = Math.floor(lineStart / 15) * 15;
  const cweToken = normalizeCweToken(finding.cwe, finding.title, finding.type);

  return `${normFile}:${lineBucket}:${cweToken}`;
}

/**
 * Determines whether two candidate findings match under adjacent-bucket tolerance (+/- 15 lines).
 * @param {object} a
 * @param {object} b
 * @returns {boolean}
 */
export function areFindingsCorroborating(a, b) {
  const fileA = normalizeCanonicalPath(a.file || "");
  const fileB = normalizeCanonicalPath(b.file || "");
  if (fileA !== fileB) return false;

  const cweA = normalizeCweToken(a.cwe, a.title, a.type);
  const cweB = normalizeCweToken(b.cwe, b.title, b.type);
  if (cweA !== cweB) return false;

  const lineA = Math.max(parseInt(a.line_start, 10) || 1, 1);
  const lineB = Math.max(parseInt(b.line_start, 10) || 1, 1);

  // Exact or within +/- 15 lines tolerance
  return Math.abs(lineA - lineB) <= 15;
}

/**
 * Merges two corroborating findings while strictly preserving maximum severity.
 * @param {object} primary
 * @param {object} incoming
 * @param {string} [sourceId]
 * @returns {object} Merged finding
 */
export function mergeFindings(primary, incoming, sourceId = "") {
  const sevP = normalizeSeverity(primary.severity);
  const sevI = normalizeSeverity(incoming.severity);
  const weightP = SEVERITY_LEVELS[sevP.toUpperCase()] || 1;
  const weightI = SEVERITY_LEVELS[sevI.toUpperCase()] || 1;

  // Highest severity takes precedence
  const dominant = weightI > weightP ? incoming : primary;
  const highestSeverity = weightI > weightP ? sevI : sevP;

  // Aggregate sources
  const sourceSet = new Set(primary.sources || []);
  if (primary.sourceId) sourceSet.add(primary.sourceId);
  if (incoming.sources) incoming.sources.forEach(s => sourceSet.add(s));
  if (incoming.sourceId) sourceSet.add(incoming.sourceId);
  if (sourceId) sourceSet.add(sourceId);

  // Aggregate evidence references & snippets
  const evidenceSnippet = dominant.evidenceSnippet || primary.evidenceSnippet || incoming.evidenceSnippet || "";
  const corroborations = (primary.corroborations || 1) + (incoming.corroborations || 1);

  const canonicalKey = computeCanonicalFindingKey(dominant);
  const idHash = crypto.createHash("sha256").update(`${canonicalKey}:${evidenceSnippet}`).digest("hex").slice(0, 16);

  return {
    ...dominant,
    id: `finding-${idHash}`,
    canonicalKey,
    severity: highestSeverity,
    evidenceSnippet,
    corroborations,
    sources: Array.from(sourceSet)
  };
}

/**
 * Reconciles an array of candidate findings into a unified, deduplicated list.
 * @param {Array<object>} rawFindings
 * @param {string} [sourceId=""]
 * @returns {Array<object>} Reconciled EvidenceFindings
 */
export function reconcileFindings(rawFindings = [], sourceId = "") {
  if (!Array.isArray(rawFindings) || rawFindings.length === 0) {
    return [];
  }

  const reconciled = [];

  for (const raw of rawFindings) {
    if (!raw || typeof raw !== "object") continue;

    let matched = false;
    for (let i = 0; i < reconciled.length; i++) {
      if (areFindingsCorroborating(reconciled[i], raw)) {
        reconciled[i] = mergeFindings(reconciled[i], raw, sourceId);
        matched = true;
        break;
      }
    }

    if (!matched) {
      const normSev = normalizeSeverity(raw.severity);
      const canonicalKey = computeCanonicalFindingKey(raw);
      const snippet = raw.evidenceSnippet || raw.snippet || "";
      const idHash = crypto.createHash("sha256").update(`${canonicalKey}:${snippet}`).digest("hex").slice(0, 16);

      const sources = new Set(raw.sources || []);
      if (raw.sourceId) sources.add(raw.sourceId);
      if (sourceId) sources.add(sourceId);

      reconciled.push({
        id: `finding-${idHash}`,
        canonicalKey,
        title: raw.title || "Unspecified security finding",
        severity: normSev,
        file: normalizeCanonicalPath(raw.file || ""),
        line_start: Math.max(parseInt(raw.line_start, 10) || 1, 1),
        line_end: Math.max(parseInt(raw.line_end || raw.line_start, 10) || 1, 1),
        cwe: normalizeCweToken(raw.cwe, raw.title, raw.type),
        ruleId: raw.ruleId || null,
        type: raw.type || null,
        confidence: raw.confidence || "medium",
        evidenceSnippet: snippet,
        recommendation: raw.recommendation || "Review code modifications according to security guidelines.",
        corroborations: 1,
        sources: Array.from(sources)
      });
    }
  }

  // Sort deterministically: severity descending (critical first), then by file and line
  return reconciled.sort((a, b) => {
    const wA = SEVERITY_LEVELS[a.severity.toUpperCase()] || 0;
    const wB = SEVERITY_LEVELS[b.severity.toUpperCase()] || 0;
    if (wA !== wB) return wB - wA;
    if (a.file !== b.file) return a.file.localeCompare(b.file);
    return a.line_start - b.line_start;
  });
}
