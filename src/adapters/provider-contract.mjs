/**
 * Provider Adapter Contract (PR-03: First Read-Only Adapter & Provider Contract)
 *
 * Defines the strict interface and validation rules between Triad-Flow and review providers.
 * All data returned by providers is treated as UNTRUSTED data under review.
 * Providers CANNOT mint capabilities, self-certify consensus, or dictate quorum.
 */

import { normalizeFinding, redactSecrets } from "../core/harness.mjs";
import { getProviderFamily } from "../core/benchmark-pilot.mjs";

export const EXECUTION_STATUS = Object.freeze({
  SUCCESS: "success",
  EMPTY: "empty",
  TIMEOUT: "timeout",
  CANCELLED: "cancelled",
  AUTH_FAILURE: "auth_failure",
  MALFORMED_OUTPUT: "malformed_output",
  PAYLOAD_TOO_LARGE: "payload_too_large",
  ERROR: "error",
  INCOMPLETE: "incomplete"
});

export const DEFAULT_LIMITS = Object.freeze({
  maxInputBytes: 1024 * 1024,   // 1 MB
  maxOutputBytes: 512 * 1024,   // 512 KB
  defaultTimeoutMs: 60 * 1000   // 60 seconds
});

/**
 * Validates the input context passed to a provider adapter.
 */
export function validateProviderInput(input = {}) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return { valid: false, reason: "Provider input must be a non-null plain object." };
  }

  if (typeof input.runId !== "string" || !input.runId.trim()) {
    return { valid: false, reason: "Provider input requires a non-empty string 'runId'." };
  }

  if (typeof input.role !== "string" || !input.role.trim()) {
    return { valid: false, reason: "Provider input requires a non-empty string 'role'." };
  }

  if (!input.changeSet || typeof input.changeSet !== "object") {
    return { valid: false, reason: "Provider input requires a valid 'changeSet' object." };
  }

  if (input.changeSet.schemaVersion !== "1.0.0") {
    return { valid: false, reason: "ChangeSet must have schemaVersion '1.0.0'." };
  }

  if (typeof input.changeSet.contentDigest !== "string" || !/^[a-f0-9]{64}$/i.test(input.changeSet.contentDigest)) {
    return { valid: false, reason: "ChangeSet requires a valid 64-char sha256 'contentDigest'." };
  }

  if (!Array.isArray(input.changeSet.files)) {
    return { valid: false, reason: "ChangeSet requires a 'files' array." };
  }

  if (typeof input.policyId !== "string" || !input.policyId.trim()) {
    return { valid: false, reason: "Provider input requires a non-empty string 'policyId'." };
  }

  const timeoutMs = Number(input.timeoutMs || input.deadline || DEFAULT_LIMITS.defaultTimeoutMs);
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    return { valid: false, reason: "Provider input 'timeoutMs' must be a positive number." };
  }

  if (input.signal && (typeof input.signal !== "object" || typeof input.signal.aborted !== "boolean")) {
    return { valid: false, reason: "Provider input 'signal' must be an AbortSignal instance." };
  }

  const limits = {
    maxInputBytes: Number(input.limits?.maxInputBytes || DEFAULT_LIMITS.maxInputBytes),
    maxOutputBytes: Number(input.limits?.maxOutputBytes || DEFAULT_LIMITS.maxOutputBytes)
  };

  return {
    valid: true,
    input: Object.freeze({
      runId: input.runId.trim(),
      role: input.role.trim(),
      changeSet: input.changeSet,
      policyId: input.policyId.trim(),
      timeoutMs,
      signal: input.signal || null,
      limits: Object.freeze(limits),
      prompt: typeof input.prompt === "string" ? input.prompt : undefined
    })
  };
}

/**
 * Validates and normalizes provider output under Default-Deny.
 * Strips all capability forgery attempts and ensures safe, canonical data.
 */
export function validateProviderOutput(rawOutput, inputContext = {}) {
  const providerName = String(inputContext.providerName || rawOutput?.providerIdentity?.provider || "unknown-provider");
  const providerIdentity = {
    provider: providerName,
    family: getProviderFamily(inputContext.family || rawOutput?.providerIdentity?.family || providerName),
    model: String(inputContext.modelName || rawOutput?.providerIdentity?.model || "unknown-model"),
    transport: String(inputContext.transport || rawOutput?.providerIdentity?.transport || "cli"),
    runId: String(inputContext.runId || rawOutput?.providerIdentity?.runId || "unassigned-run")
  };

function sanitizeRawOutput(raw) {
  if (raw === undefined || raw === null) return undefined;
  const str = typeof raw === "string" ? raw : (typeof raw === "object" ? JSON.stringify(raw) : String(raw));
  const MAX_RAW_OUTPUT_BYTES = 4096;
  const redacted = redactSecrets(str);
  const buf = Buffer.from(redacted, "utf8");
  if (buf.length > MAX_RAW_OUTPUT_BYTES) {
    let end = MAX_RAW_OUTPUT_BYTES;
    let seqStart = end;
    while (seqStart > 0 && (buf[seqStart] & 0xC0) === 0x80) {
      seqStart--;
    }
    if (seqStart >= 0 && seqStart < buf.length) {
      const lead = buf[seqStart];
      let seqLen = 1;
      if ((lead & 0xE0) === 0xC0) seqLen = 2;
      else if ((lead & 0xF0) === 0xE0) seqLen = 3;
      else if ((lead & 0xF8) === 0xF0) seqLen = 4;

      if (seqStart + seqLen > MAX_RAW_OUTPUT_BYTES) {
        end = seqStart;
      }
    }
    return buf.subarray(0, end).toString("utf8") + " ... [TRUNCATED]";
  }
  return redacted;
}

  // If rawOutput indicates a transport-level error or terminal status
  if (rawOutput && rawOutput.executionStatus && rawOutput.executionStatus !== EXECUTION_STATUS.SUCCESS && rawOutput.executionStatus !== EXECUTION_STATUS.EMPTY) {
    const status = Object.values(EXECUTION_STATUS).includes(rawOutput.executionStatus)
      ? rawOutput.executionStatus
      : EXECUTION_STATUS.ERROR;

    return Object.freeze({
      ok: false,
      executionStatus: status,
      findings: Object.freeze([]),
      coverage: Object.freeze({ coveredFiles: Object.freeze([]), omittedFiles: Object.freeze([]) }),
      usage: null,
      providerIdentity: Object.freeze(providerIdentity),
      rawOutput: sanitizeRawOutput(rawOutput.rawOutput),
      error: rawOutput.error ? redactSecrets(String(rawOutput.error)) : `Execution terminated with status '${status}'.`
    });
  }

  if (!rawOutput || typeof rawOutput !== "object" || Array.isArray(rawOutput)) {
    return Object.freeze({
      ok: false,
      executionStatus: EXECUTION_STATUS.MALFORMED_OUTPUT,
      findings: Object.freeze([]),
      coverage: Object.freeze({ coveredFiles: Object.freeze([]), omittedFiles: Object.freeze([]) }),
      usage: null,
      providerIdentity: Object.freeze(providerIdentity),
      rawOutput: sanitizeRawOutput(rawOutput),
      error: "Provider output must be a non-null plain object."
    });
  }

  // Enforce required findings array (Fail-Closed: cannot be missing or non-array)
  if (!Array.isArray(rawOutput.findings)) {
    return Object.freeze({
      ok: false,
      executionStatus: EXECUTION_STATUS.MALFORMED_OUTPUT,
      findings: Object.freeze([]),
      coverage: Object.freeze({ coveredFiles: Object.freeze([]), omittedFiles: Object.freeze([]) }),
      usage: null,
      providerIdentity: Object.freeze(providerIdentity),
      error: "Provider output requires a 'findings' array."
    });
  }

  // Coverage validation: MUST be a non-null plain object with coveredFiles (array) and omittedFiles (array)
  if (!rawOutput.coverage || typeof rawOutput.coverage !== "object" || Array.isArray(rawOutput.coverage)) {
    return Object.freeze({
      ok: false,
      executionStatus: EXECUTION_STATUS.MALFORMED_OUTPUT,
      findings: Object.freeze([]),
      coverage: Object.freeze({ coveredFiles: Object.freeze([]), omittedFiles: Object.freeze([]) }),
      usage: null,
      providerIdentity: Object.freeze(providerIdentity),
      error: "Provider output requires a 'coverage' plain object."
    });
  }

  if (!Array.isArray(rawOutput.coverage.coveredFiles)) {
    return Object.freeze({
      ok: false,
      executionStatus: EXECUTION_STATUS.MALFORMED_OUTPUT,
      findings: Object.freeze([]),
      coverage: Object.freeze({ coveredFiles: Object.freeze([]), omittedFiles: Object.freeze([]) }),
      usage: null,
      providerIdentity: Object.freeze(providerIdentity),
      error: "Provider coverage requires a 'coveredFiles' array."
    });
  }

  if (!Array.isArray(rawOutput.coverage.omittedFiles)) {
    return Object.freeze({
      ok: false,
      executionStatus: EXECUTION_STATUS.MALFORMED_OUTPUT,
      findings: Object.freeze([]),
      coverage: Object.freeze({ coveredFiles: Object.freeze([]), omittedFiles: Object.freeze([]) }),
      usage: null,
      providerIdentity: Object.freeze(providerIdentity),
      error: "Provider coverage requires an 'omittedFiles' array."
    });
  }

  // Treat input findings under Default-Deny: normalize each finding
  // Fail-Closed: any candidate finding that fails normalization triggers MALFORMED_OUTPUT
  const rawFindings = rawOutput.findings;
  const normalizedFindings = [];

  for (let i = 0; i < rawFindings.length; i++) {
    const candidate = rawFindings[i];
    // Defense against Capability Forgery: delete any forged capability fields
    if (candidate && typeof candidate === "object") {
      delete candidate.__trustedCapabilityNonce;
      delete candidate.authority;
      delete candidate.isTrusted;
      delete candidate.quorumReached;
      delete candidate.consensusProof;
    }

    const norm = normalizeFinding(candidate);
    if (!norm.valid) {
      return Object.freeze({
        ok: false,
        executionStatus: EXECUTION_STATUS.MALFORMED_OUTPUT,
        findings: Object.freeze([]),
        coverage: Object.freeze({ coveredFiles: Object.freeze([]), omittedFiles: Object.freeze([]) }),
        usage: null,
        providerIdentity: Object.freeze(providerIdentity),
        error: `Malformed finding at index ${i}: ${norm.reason || "invalid finding format"}`
      });
    }
    normalizedFindings.push(norm.finding);
  }

  // Coverage normalization
  const validFiles = new Set((inputContext.changeSet?.files || []).map(f => f.path));
  const rawCovered = rawOutput.coverage.coveredFiles;
  const coveredFiles = rawCovered.filter(p => typeof p === "string" && (validFiles.size === 0 || validFiles.has(p)));

  const rawOmitted = rawOutput.coverage.omittedFiles;
  const omittedFiles = rawOmitted.map(o => ({
    path: String(o?.path || "unknown"),
    reason: String(o?.reason || "unspecified")
  }));

  // Usage validation
  let usage = null;
  if (rawOutput.usage && typeof rawOutput.usage === "object") {
    usage = {
      promptTokens: Number.isFinite(rawOutput.usage.promptTokens) ? Number(rawOutput.usage.promptTokens) : null,
      completionTokens: Number.isFinite(rawOutput.usage.completionTokens) ? Number(rawOutput.usage.completionTokens) : null,
      totalTokens: Number.isFinite(rawOutput.usage.totalTokens) ? Number(rawOutput.usage.totalTokens) : null
    };
  }

  const executionStatus = normalizedFindings.length === 0
    ? EXECUTION_STATUS.EMPTY
    : EXECUTION_STATUS.SUCCESS;

  return Object.freeze({
    ok: true,
    executionStatus,
    findings: Object.freeze(normalizedFindings),
    coverage: Object.freeze({
      coveredFiles: Object.freeze(coveredFiles),
      omittedFiles: Object.freeze(omittedFiles)
    }),
    usage: usage ? Object.freeze(usage) : null,
    providerIdentity: Object.freeze(providerIdentity),
    error: null
  });
}

/**
 * Converts a validated provider result into a Sentry Report object suitable for aggregateConsensus.
 */
export function convertProviderResultToSentryReport(result, roleName = "macro") {
  if (!result || !result.ok) {
    return {
      name: result?.providerIdentity?.provider || roleName,
      source: result?.providerIdentity?.provider || roleName,
      role: roleName,
      providerIdentity: result?.providerIdentity,
      coverage: result?.coverage,
      error: result?.error || `Provider execution failed (${result?.executionStatus || "unknown"})`
    };
  }

  return {
    name: result.providerIdentity.provider,
    source: result.providerIdentity.provider,
    role: roleName,
    providerIdentity: result.providerIdentity,
    coverage: result.coverage,
    findings: result.findings
  };
}

function stripTrailingCommas(str) {
  let inString = false;
  let escaped = false;
  let result = "";
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === '"') inString = false;
      result += char;
      continue;
    }
    if (char === '"') {
      inString = true;
      escaped = false;
      result += char;
      continue;
    }
    if (char === ",") {
      let j = i + 1;
      while (j < str.length && /\s/.test(str[j])) j++;
      if (j < str.length && (str[j] === "}" || str[j] === "]")) {
        continue;
      }
    }
    result += char;
  }
  return result;
}

function tryParseJsonCandidate(str) {
  if (!str || typeof str !== "string") return null;
  const trimmed = str.trim();
  if (!trimmed) return null;
  try {
    return JSON.parse(trimmed);
  } catch {
    try {
      const sanitized = stripTrailingCommas(trimmed);
      return JSON.parse(sanitized);
    } catch {
      return null;
    }
  }
}

function findMatchingBrace(text, startIdx) {
  let depth = 0;
  let inString = false;
  let escaped = false;

  for (let i = startIdx; i < text.length; i++) {
    const char = text[i];

    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (char === "\\") {
        escaped = true;
      } else if (char === '"') {
        inString = false;
      }
      continue;
    }

    if (char === '"') {
      inString = true;
      escaped = false;
    } else if (char === "{" || char === "[") {
      depth++;
    } else if (char === "}" || char === "]") {
      depth--;
      if (depth === 0) {
        return i;
      }
    }
  }

  return -1;
}

/**
 * Extracts a JSON string from raw text that may contain markdown code fences, pre/postambles, or formatting quirks.
 * Uses direct parsing, markdown fence extraction, and bracket-depth balancing.
 *
 * @param {string} text - Raw input text from reviewer CLI or model response
 * @returns {object|null} Parsed JSON object/array or null if not extractable
 */
export function extractJsonFromText(text = "") {
  if (typeof text !== "string") return null;
  const trimmed = text.trim();
  if (!trimmed) return null;

  // 1. Direct parse attempt
  const direct = tryParseJsonCandidate(trimmed);
  if (direct && typeof direct === "object") return direct;

  // 2. Extract from markdown code fences: ```json ... ``` or ``` ... ```
  const fenceRegex = /```(?:json)?\s*([\s\S]*?)\s*```/gi;
  let fenceMatch;
  while ((fenceMatch = fenceRegex.exec(trimmed)) !== null) {
    const candidate = fenceMatch[1];
    const parsed = tryParseJsonCandidate(candidate);
    if (parsed && typeof parsed === "object") {
      if (Array.isArray(parsed.findings)) return parsed;
    }

    // Inside fence, try bracket extraction
    const firstBrace = candidate.indexOf("{");
    if (firstBrace !== -1) {
      const closing = findMatchingBrace(candidate, firstBrace);
      if (closing !== -1) {
        const sub = tryParseJsonCandidate(candidate.slice(firstBrace, closing + 1));
        if (sub && typeof sub === "object") {
          if (Array.isArray(sub.findings)) return sub;
        }
      }
    }
  }

  // 3. Bracket-balanced JSON extraction across top-level blocks
  const candidates = [];
  let scanIdx = 0;
  while (scanIdx < trimmed.length) {
    const openBrace = trimmed.indexOf("{", scanIdx);
    if (openBrace === -1) break;
    const closeBrace = findMatchingBrace(trimmed, openBrace);
    if (closeBrace !== -1) {
      candidates.push(trimmed.slice(openBrace, closeBrace + 1));
      scanIdx = closeBrace + 1;
    } else {
      scanIdx = openBrace + 1;
    }
  }

  // Prioritize candidates that contain an explicit "findings" array
  for (const cand of candidates) {
    const parsed = tryParseJsonCandidate(cand);
    if (parsed && typeof parsed === "object" && Array.isArray(parsed.findings)) {
      return parsed;
    }
  }

  // Fallback: any parsed candidate object
  for (const cand of candidates) {
    const parsed = tryParseJsonCandidate(cand);
    if (parsed && typeof parsed === "object") {
      return parsed;
    }
  }

  // 4. Fallback: scan from first '{' to last '}'
  const startIdx = trimmed.indexOf("{");
  const lastIdx = trimmed.lastIndexOf("}");
  if (startIdx !== -1 && lastIdx > startIdx) {
    const candidate = tryParseJsonCandidate(trimmed.slice(startIdx, lastIdx + 1));
    if (candidate && typeof candidate === "object") return candidate;
  }

  return null;
}
