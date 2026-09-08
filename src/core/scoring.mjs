/**
 * Scoring & Benchmark Engineering (Pillar 5 — Eval): Deterministic Verification, CWE Token Extraction & Mutation Scoring
 */

import path from "node:path";

export function calculateMutationScore(totalMutants = 0, killedMutants = 0) {
  if (typeof totalMutants !== "number" || typeof killedMutants !== "number") {
    throw new TypeError("Mutant counts must be numbers.");
  }
  if (!Number.isFinite(totalMutants) || !Number.isFinite(killedMutants)) {
    throw new RangeError("Mutant counts must be finite.");
  }
  if (totalMutants < 0 || killedMutants < 0) {
    throw new RangeError("Mutant counts cannot be negative.");
  }
  if (killedMutants > totalMutants) {
    throw new RangeError("Killed mutants cannot exceed total mutants.");
  }
  if (totalMutants === 0) {
    return null; // N/A, not fake 100%
  }

  return parseFloat(((killedMutants / totalMutants) * 100).toFixed(1));
}

/**
 * Canonicalizes a file path for deterministic identity comparison.
 * Invariant (P1-08, P1-03): Preserves valid filename whitespace without .trim().
 */
export function normalizeCanonicalPath(filePath, workspaceRoot = "") {
  if (typeof filePath !== "string" || filePath === "") return "";

  // Preserves leading/trailing whitespace without calling .trim()
  let clean = filePath.replace(/\0/g, "").normalize("NFC").replace(/\\/g, "/");
  clean = clean.replace(/^\.\//, "");

  if (workspaceRoot) {
    let normRoot = workspaceRoot.replace(/\\/g, "/").replace(/\/+$/, "").normalize("NFC");
    if (process.platform === "win32") {
      normRoot = normRoot.replace(/^[a-zA-Z]:/, m => m.toLowerCase());
      clean = clean.replace(/^[a-zA-Z]:/, m => m.toLowerCase());
    }
    if (clean.startsWith(normRoot + "/")) {
      clean = clean.slice(normRoot.length + 1);
    }
  }

  if (process.platform === "win32") {
    clean = clean.toLowerCase();
  }

  return path.posix.normalize(clean);
}

/**
 * Normalizes a CWE identifier (e.g. "cwe-079" -> "CWE-79").
 */
export function normalizeCwe(raw) {
  if (typeof raw !== "string") return null;
  const match = raw.trim().match(/^CWE-(\d+)$/i);
  if (!match) return null;
  const num = parseInt(match[1], 10);
  return Number.isNaN(num) ? null : `CWE-${num}`;
}

/**
 * Extracts distinct CWE identifiers from text using boundary-aware regex (P1-01).
 * Avoids substring collision (e.g. CWE-79 vs CWE-791).
 */
export function extractCweTokens(text) {
  if (typeof text !== "string" || !text) return new Set();
  const results = new Set();
  const regex = /(?:^|[^a-zA-Z0-9])CWE-(\d+)(?![a-zA-Z0-9])/gi;
  let match;
  while ((match = regex.exec(text)) !== null) {
    const num = parseInt(match[1], 10);
    if (!Number.isNaN(num)) {
      results.add(`CWE-${num}`);
    }
  }
  return results;
}

export function isCweMatched(finding, goldenCwe) {
  const target = normalizeCwe(goldenCwe);
  if (!target) return false;

  // 1. Direct explicit finding.cwe
  if (finding.cwe) {
    const direct = normalizeCwe(finding.cwe);
    if (direct === target) return true;
  }

  // 2. Extracted tokens from title and body
  const titleTokens = extractCweTokens(finding.title);
  if (titleTokens.has(target)) return true;

  const bodyTokens = extractCweTokens(finding.body || finding.recommendation || finding.message);
  if (bodyTokens.has(target)) return true;

  return false;
}

const TYPE_ALIASES = Object.freeze({
  "sql": "sql-injection",
  "sqli": "sql-injection",
  "xss": "cross-site-scripting",
  "rce": "command-injection",
  "csrf": "cross-site-request-forgery",
  "auth": "authentication"
});

export function normalizeType(raw) {
  if (typeof raw !== "string") return "";
  const cleaned = raw.trim().toLowerCase().replace(/[\s_]+/g, "-");
  return TYPE_ALIASES[cleaned] || cleaned;
}

/**
 * Boundary-aware Type matching (P1-02).
 * Prevents "token" from matching "tokenizer" or "auth" from matching "author".
 */
export function isTypeMatched(finding, goldenType) {
  if (!goldenType || typeof goldenType !== "string") return false;
  const rawTarget = goldenType.trim().toLowerCase();
  const canonicalTarget = normalizeType(goldenType);

  // Tier 1: Explicit finding.type
  if (finding.type) {
    const findingType = normalizeType(finding.type);
    if (findingType === canonicalTarget || finding.type.trim().toLowerCase() === rawTarget) {
      return true;
    }
  }

  // Tier 2: Boundary-aware token match in title
  const candidates = Array.from(new Set([rawTarget, canonicalTarget].filter(Boolean)));
  for (const cand of candidates) {
    const escaped = cand.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const boundaryRegex = new RegExp(`(?:^|[^a-zA-Z0-9_-])${escaped}(?:$|[^a-zA-Z0-9_-])`, "i");

    if (typeof finding.title === "string" && boundaryRegex.test(finding.title)) {
      return true;
    }
    if (typeof finding.category === "string" && (normalizeType(finding.category) === cand || finding.category.toLowerCase() === cand)) {
      return true;
    }
  }

  return false;
}

/**
 * Verifies Held-Out benchmark cases with index-qualified matching to prevent duplicate ID collapse.
 */
export function verifyHeldOutBaseline(actualFindings = [], goldenVulnerabilities = [], workspaceRoot = "") {
  if (!Array.isArray(goldenVulnerabilities) || goldenVulnerabilities.length === 0) {
    return {
      applicable: false,
      totalGoldens: 0,
      caughtGoldens: 0,
      recallRate: null,
      passed: false
    };
  }

  const findingsList = Array.isArray(actualFindings) ? actualFindings : [];
  const matchedGoldenIndices = new Set();

  for (let gIdx = 0; gIdx < goldenVulnerabilities.length; gIdx++) {
    const golden = goldenVulnerabilities[gIdx];
    const gFile = normalizeCanonicalPath(golden.file || golden.path || "", workspaceRoot);
    const gCwe = golden.cwe;
    const gType = golden.type;

    const isCaught = findingsList.some(f => {
      const fFile = normalizeCanonicalPath(f.file || f.path || f.location?.file || "", workspaceRoot);

      // Exact canonical file identity check
      if (gFile) {
        if (fFile !== gFile) return false;
      }

      const cweMatches = Boolean(gCwe && isCweMatched(f, gCwe));
      const typeMatches = Boolean(gType && isTypeMatched(f, gType));

      if (gCwe || gType) {
        return cweMatches || typeMatches;
      }

      return Boolean(gFile);
    });

    if (isCaught) {
      matchedGoldenIndices.add(gIdx);
    }
  }

  const found = matchedGoldenIndices.size;
  const total = goldenVulnerabilities.length;
  const recall = (found / total) * 100;

  return {
    applicable: true,
    totalGoldens: total,
    caughtGoldens: found,
    recallRate: `${recall.toFixed(1)}%`,
    passed: recall >= 90.0
  };
}
