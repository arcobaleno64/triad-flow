/**
 * Provider Adapter Contract (PR-03: First Read-Only Adapter & Provider Contract)
 *
 * Defines the strict interface and validation rules between Triad-Flow and review providers.
 * All data returned by providers is treated as UNTRUSTED data under review.
 * Providers CANNOT mint capabilities, self-certify consensus, or dictate quorum.
 */

import { normalizeFinding, redactSecrets } from "../core/harness.mjs";
import { getProviderFamily } from "../core/benchmark-pilot.mjs";
import { normalizeCanonicalPath } from "../core/scoring.mjs";

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

export const COVERAGE_OMISSION_CODES = Object.freeze({
  UNMODIFIED: "OMIT_UNMODIFIED",
  SIZE_LIMIT: "OMIT_SIZE_LIMIT",
  BINARY: "OMIT_BINARY",
  GENERATED: "OMIT_GENERATED",
  OUT_OF_SCOPE: "OMIT_OUT_OF_SCOPE",
  TIMEOUT: "OMIT_TIMEOUT"
});

const ALLOWED_OMISSION_CODES = new Set(Object.values(COVERAGE_OMISSION_CODES));

/**
 * Safely renders an untrusted diagnostic value into a bounded string without throwing.
 * Handles symbols, Object.create(null), throwing getters/toString/toJSON, and circular references.
 * @param {*} val
 * @param {number} [maxLen=64]
 * @returns {string}
 */
export function safeRenderUntrusted(val, maxLen = 64) {
  const limit = (typeof maxLen === "number" && maxLen > 0) ? maxLen : 64;
  try {
    if (val === null) return "null";
    if (val === undefined) return "undefined";
    const t = typeof val;
    let s;
    if (t === "string") {
      s = val;
    } else if (t === "number" || t === "boolean" || t === "bigint" || t === "symbol") {
      s = String(val);
    } else if (t === "object") {
      try {
        s = JSON.stringify(val);
      } catch {
        s = "[unrenderable]";
      }
    } else {
      s = String(val);
    }
    if (typeof s !== "string") return "[unrenderable]";
    if (s.length > limit) return s.slice(0, limit) + "...";
    return s;
  } catch {
    return "[unrenderable]";
  }
}

/**
 * Safely accesses a property on an untrusted object without throwing if a getter throws.
 * @param {*} obj
 * @param {string|number|symbol} prop
 * @returns {*}
 */
export function safeGet(obj, prop) {
  if (obj === null || obj === undefined) return undefined;
  try {
    return obj[prop];
  } catch {
    return undefined;
  }
}

/**
 * Safely checks if a value is an Array without throwing on revoked Proxies.
 * @param {*} val
 * @returns {boolean}
 */
export function safeIsArray(val) {
  try {
    return Array.isArray(val);
  } catch {
    return false;
  }
}

/**
 * Safely reads the length of an Array or array-like object without throwing if a getter throws.
 * Returns -1 if length cannot be safely read or is not a valid non-negative integer.
 * @param {*} arr
 * @returns {number}
 */
export function safeArrayLength(arr) {
  try {
    if (arr === null || arr === undefined) return -1;
    const len = arr.length;
    return typeof len === "number" && Number.isSafeInteger(len) && len >= 0 ? len : -1;
  } catch {
    return -1;
  }
}

/**
 * Safely extracts an error message from an untrusted thrown value (e.g. throw null, object with throwing getter).
 * @param {*} err
 * @param {string} [fallback="Unknown error"]
 * @returns {string}
 */
export function safeErrorMessage(err, fallback = "Unknown error") {
  try {
    if (err === null || err === undefined) return fallback;
    const msg = safeGet(err, "message");
    if (typeof msg === "string" && msg.trim()) return msg.trim();
    const str = safeRenderUntrusted(err);
    return str && str !== "[unrenderable]" ? str : fallback;
  } catch {
    return fallback;
  }
}

function safeCoerceString(val, fallback = "") {
  try {
    if (val === null || val === undefined) return fallback;
    const s = String(val);
    return typeof s === "string" ? s : fallback;
  } catch {
    return fallback;
  }
}

/**
 * Validates the input context passed to a provider adapter.
 */
export function validateProviderInput(input = {}) {
  try {
    if (!input || typeof input !== "object" || safeIsArray(input)) {
      return { valid: false, reason: "Provider input must be a non-null plain object." };
    }

    const runId = safeGet(input, "runId");
    if (typeof runId !== "string" || !runId.trim()) {
      return { valid: false, reason: "Provider input requires a non-empty string 'runId'." };
    }

    const role = safeGet(input, "role");
    if (typeof role !== "string" || !role.trim()) {
      return { valid: false, reason: "Provider input requires a non-empty string 'role'." };
    }

    const changeSet = safeGet(input, "changeSet");
    if (!changeSet || typeof changeSet !== "object" || safeIsArray(changeSet)) {
      return { valid: false, reason: "Provider input requires a valid 'changeSet' object." };
    }

    if (safeGet(changeSet, "schemaVersion") !== "1.0.0") {
      return { valid: false, reason: "ChangeSet must have schemaVersion '1.0.0'." };
    }

    const contentDigest = safeGet(changeSet, "contentDigest");
    if (typeof contentDigest !== "string" || !/^[a-f0-9]{64}$/i.test(contentDigest)) {
      return { valid: false, reason: "ChangeSet requires a valid 64-char sha256 'contentDigest'." };
    }

    const files = safeGet(changeSet, "files");
    if (!safeIsArray(files)) {
      return { valid: false, reason: "ChangeSet requires a 'files' array." };
    }

    const policyId = safeGet(input, "policyId");
    if (typeof policyId !== "string" || !policyId.trim()) {
      return { valid: false, reason: "Provider input requires a non-empty string 'policyId'." };
    }

    const timeoutMsVal = safeGet(input, "timeoutMs") ?? safeGet(input, "deadline") ?? DEFAULT_LIMITS.defaultTimeoutMs;
    const timeoutMs = Number(timeoutMsVal);
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
      return { valid: false, reason: "Provider input 'timeoutMs' must be a positive number." };
    }

    const signal = safeGet(input, "signal");
    if (signal && (typeof signal !== "object" || typeof safeGet(signal, "aborted") !== "boolean")) {
      return { valid: false, reason: "Provider input 'signal' must be an AbortSignal instance." };
    }

    const inputLimits = safeGet(input, "limits");
    const limits = {
      maxInputBytes: Number(safeGet(inputLimits, "maxInputBytes") || DEFAULT_LIMITS.maxInputBytes),
      maxOutputBytes: Number(safeGet(inputLimits, "maxOutputBytes") || DEFAULT_LIMITS.maxOutputBytes)
    };

    return {
      valid: true,
      input: Object.freeze({
        runId: runId.trim(),
        role: role.trim(),
        changeSet,
        policyId: policyId.trim(),
        timeoutMs,
        signal: signal || null,
        limits: Object.freeze(limits),
        prompt: typeof safeGet(input, "prompt") === "string" ? safeGet(input, "prompt") : undefined,
        patchObjective: typeof safeGet(input, "patchObjective") === "string" ? safeGet(input, "patchObjective").trim() : undefined,
        objectiveContract: (safeGet(input, "objectiveContract") && typeof safeGet(input, "objectiveContract") === "object") ? safeGet(input, "objectiveContract") : undefined,
        options: (safeGet(input, "options") && typeof safeGet(input, "options") === "object") ? safeGet(input, "options") : undefined
      })
    };
  } catch (err) {
    return { valid: false, reason: `Provider input validation failed: ${safeErrorMessage(err)}` };
  }
}

/**
 * Validates and normalizes provider output under Default-Deny.
 * Strips all capability forgery attempts and ensures safe, canonical data.
 */
export function validateProviderOutput(rawOutput, inputContext = {}) {
  try {
    const rawProviderIdentity = safeGet(rawOutput, "providerIdentity");
    const providerName = safeCoerceString(inputContext.providerName || safeGet(rawProviderIdentity, "provider") || "unknown-provider");
    const providerIdentity = {
      provider: providerName,
      family: getProviderFamily(safeCoerceString(inputContext.family || safeGet(rawProviderIdentity, "family") || providerName)),
      model: safeCoerceString(inputContext.modelName || safeGet(rawProviderIdentity, "model") || "unknown-model"),
      transport: safeCoerceString(inputContext.transport || safeGet(rawProviderIdentity, "transport") || "cli"),
      runId: safeCoerceString(inputContext.runId || safeGet(rawProviderIdentity, "runId") || "unassigned-run")
    };

    function sanitizeRawOutput(raw) {
      if (raw === undefined || raw === null) return undefined;
      let str;
      try {
        str = typeof raw === "string" ? raw : (typeof raw === "object" ? JSON.stringify(raw) : String(raw));
      } catch {
        str = "[unrenderable]";
      }
      if (!str) return undefined;
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
    const rawExecStatus = safeGet(rawOutput, "executionStatus");
    if (rawExecStatus && rawExecStatus !== EXECUTION_STATUS.SUCCESS && rawExecStatus !== EXECUTION_STATUS.EMPTY) {
      const status = Object.values(EXECUTION_STATUS).includes(rawExecStatus)
        ? rawExecStatus
        : EXECUTION_STATUS.ERROR;

      const rawErr = safeGet(rawOutput, "error");
      return Object.freeze({
        ok: false,
        executionStatus: status,
        findings: Object.freeze([]),
        coverage: Object.freeze({ coveredFiles: Object.freeze([]), omittedFiles: Object.freeze([]) }),
        usage: null,
        providerIdentity: Object.freeze(providerIdentity),
        rawOutput: sanitizeRawOutput(safeGet(rawOutput, "rawOutput")),
        error: rawErr ? redactSecrets(safeCoerceString(rawErr)) : `Execution terminated with status '${status}'.`
      });
    }

    if (!rawOutput || typeof rawOutput !== "object" || safeIsArray(rawOutput)) {
      return Object.freeze({
        ok: false,
        executionStatus: EXECUTION_STATUS.MALFORMED_OUTPUT,
        findings: Object.freeze([]),
        coverage: Object.freeze({ coveredFiles: Object.freeze([]), omittedFiles: Object.freeze([]) }),
        usage: null,
        providerIdentity: Object.freeze(providerIdentity),
        rawOutput: sanitizeRawOutput(safeGet(rawOutput, "rawOutput")),
        error: "Provider output must be a non-null plain object."
      });
    }

    // Enforce required findings array (Fail-Closed: cannot be missing or non-array)
    const rawFindings = safeGet(rawOutput, "findings");
    if (!safeIsArray(rawFindings)) {
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
    const rawCoverage = safeGet(rawOutput, "coverage");
    if (!rawCoverage || typeof rawCoverage !== "object" || safeIsArray(rawCoverage)) {
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

    const rawCoveredFiles = safeGet(rawCoverage, "coveredFiles");
    if (!safeIsArray(rawCoveredFiles)) {
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

    const coveredCount = safeArrayLength(rawCoveredFiles);
    if (coveredCount < 0) {
      return Object.freeze({
        ok: false,
        executionStatus: EXECUTION_STATUS.MALFORMED_OUTPUT,
        findings: Object.freeze([]),
        coverage: Object.freeze({ coveredFiles: Object.freeze([]), omittedFiles: Object.freeze([]) }),
        usage: null,
        providerIdentity: Object.freeze(providerIdentity),
        error: "Provider coverage 'coveredFiles' array length could not be safely read (malformed array)."
      });
    }

    const rawOmittedFiles = safeGet(rawCoverage, "omittedFiles");
    if (!safeIsArray(rawOmittedFiles)) {
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

    const omissionsCount = safeArrayLength(rawOmittedFiles);
    if (omissionsCount < 0) {
      return Object.freeze({
        ok: false,
        executionStatus: EXECUTION_STATUS.MALFORMED_OUTPUT,
        findings: Object.freeze([]),
        coverage: Object.freeze({ coveredFiles: Object.freeze([]), omittedFiles: Object.freeze([]) }),
        usage: null,
        providerIdentity: Object.freeze(providerIdentity),
        error: "Provider coverage 'omittedFiles' array length could not be safely read (malformed array)."
      });
    }

    // Treat input findings under Default-Deny: normalize each finding
    // Fail-Closed: any candidate finding that fails normalization triggers MALFORMED_OUTPUT
    const normalizedFindings = [];
    const findingsCount = safeArrayLength(rawFindings);
    if (findingsCount < 0) {
      return Object.freeze({
        ok: false,
        executionStatus: EXECUTION_STATUS.MALFORMED_OUTPUT,
        findings: Object.freeze([]),
        coverage: Object.freeze({ coveredFiles: Object.freeze([]), omittedFiles: Object.freeze([]) }),
        usage: null,
        providerIdentity: Object.freeze(providerIdentity),
        error: "Provider output 'findings' array length could not be safely read (malformed array)."
      });
    }

    for (let i = 0; i < findingsCount; i++) {
      const candidate = safeGet(rawFindings, i);
      // Defense against Capability Forgery: delete any forged capability fields
      if (candidate && typeof candidate === "object") {
        try {
          delete candidate.__trustedCapabilityNonce;
          delete candidate.authority;
          delete candidate.isTrusted;
          delete candidate.quorumReached;
          delete candidate.consensusProof;
        } catch {}
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
    const validFiles = new Set((inputContext.changeSet?.files || []).map(f => normalizeCanonicalPath(typeof f === "string" ? f : safeGet(f, "path") || "")));
    const coveredFiles = [];
    for (let i = 0; i < coveredCount; i++) {
      const p = safeGet(rawCoveredFiles, i);
      if (typeof p === "string" && (validFiles.size === 0 || validFiles.has(normalizeCanonicalPath(p)))) {
        coveredFiles.push(normalizeCanonicalPath(p));
      }
    }

    const omittedFiles = [];

    for (let i = 0; i < omissionsCount; i++) {
      const candidate = safeGet(rawOmittedFiles, i);
      if (!candidate || typeof candidate !== "object" || safeIsArray(candidate)) {
        return Object.freeze({
          ok: false,
          executionStatus: EXECUTION_STATUS.MALFORMED_OUTPUT,
          findings: Object.freeze([]),
          coverage: Object.freeze({ coveredFiles: Object.freeze([]), omittedFiles: Object.freeze([]) }),
          usage: null,
          providerIdentity: Object.freeze(providerIdentity),
          error: `Malformed omission at index ${i}: omission must be a non-null plain object.`
        });
      }

      const candidatePath = safeGet(candidate, "path");
      const candidateFile = safeGet(candidate, "file");
      const rawPath = typeof candidatePath === "string" && candidatePath.trim()
        ? candidatePath.trim()
        : (typeof candidateFile === "string" && candidateFile.trim() ? candidateFile.trim() : null);

      if (!rawPath) {
        return Object.freeze({
          ok: false,
          executionStatus: EXECUTION_STATUS.MALFORMED_OUTPUT,
          findings: Object.freeze([]),
          coverage: Object.freeze({ coveredFiles: Object.freeze([]), omittedFiles: Object.freeze([]) }),
          usage: null,
          providerIdentity: Object.freeze(providerIdentity),
          error: `Malformed omission at index ${i}: omission requires a non-empty string 'path' or 'file'.`
        });
      }

      const candidateCode = safeGet(candidate, "code");
      const rawCode = typeof candidateCode === "string" ? candidateCode.trim() : "";
      if (!rawCode || !ALLOWED_OMISSION_CODES.has(rawCode)) {
        return Object.freeze({
          ok: false,
          executionStatus: EXECUTION_STATUS.MALFORMED_OUTPUT,
          findings: Object.freeze([]),
          coverage: Object.freeze({ coveredFiles: Object.freeze([]), omittedFiles: Object.freeze([]) }),
          usage: null,
          providerIdentity: Object.freeze(providerIdentity),
          error: `Malformed omission at index ${i}: omission requires an authorized code from COVERAGE_OMISSION_CODES (received: '${safeRenderUntrusted(candidateCode)}').`
        });
      }

      const candidateReason = safeGet(candidate, "reason");
      const rawReason = typeof candidateReason === "string" ? candidateReason.trim() : "";
      if (!rawReason) {
        return Object.freeze({
          ok: false,
          executionStatus: EXECUTION_STATUS.MALFORMED_OUTPUT,
          findings: Object.freeze([]),
          coverage: Object.freeze({ coveredFiles: Object.freeze([]), omittedFiles: Object.freeze([]) }),
          usage: null,
          providerIdentity: Object.freeze(providerIdentity),
          error: `Malformed omission at index ${i}: omission requires a non-empty string 'reason'.`
        });
      }

      const normPath = normalizeCanonicalPath(rawPath);
      omittedFiles.push(Object.freeze({
        path: normPath,
        file: normPath,
        code: rawCode,
        reason: rawReason
      }));
    }

    // Usage validation
    let usage = null;
    const rawUsage = safeGet(rawOutput, "usage");
    if (rawUsage && typeof rawUsage === "object" && !safeIsArray(rawUsage)) {
      const pTokens = safeGet(rawUsage, "promptTokens");
      const cTokens = safeGet(rawUsage, "completionTokens");
      const tTokens = safeGet(rawUsage, "totalTokens");
      usage = {
        promptTokens: Number.isFinite(pTokens) ? Number(pTokens) : null,
        completionTokens: Number.isFinite(cTokens) ? Number(cTokens) : null,
        totalTokens: Number.isFinite(tTokens) ? Number(tTokens) : null
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
  } catch (err) {
    return Object.freeze({
      ok: false,
      executionStatus: EXECUTION_STATUS.MALFORMED_OUTPUT,
      findings: Object.freeze([]),
      coverage: Object.freeze({ coveredFiles: Object.freeze([]), omittedFiles: Object.freeze([]) }),
      usage: null,
      providerIdentity: Object.freeze({
        provider: safeCoerceString(inputContext?.providerName, "unknown-provider"),
        family: getProviderFamily(safeCoerceString(inputContext?.family, "unknown")),
        model: safeCoerceString(inputContext?.modelName, "unknown-model"),
        transport: safeCoerceString(inputContext?.transport, "cli"),
        runId: safeCoerceString(inputContext?.runId, "unassigned-run")
      }),
      error: `Provider output validation failed closed: ${safeErrorMessage(err)}`
    });
  }
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
    name: result?.providerIdentity?.provider || roleName,
    source: result?.providerIdentity?.provider || roleName,
    role: roleName,
    providerIdentity: result?.providerIdentity,
    coverage: result?.coverage,
    findings: result?.findings
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
