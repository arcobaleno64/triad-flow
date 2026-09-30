/**
 * Triad-Flow Independent Verification Layer & Disagreement Ledger (TF-SPEC-RECEIPT-v1.0.0 Section 7)
 *
 * Implements Producer / Verifier Decoupling:
 * - Producer (e.g. Google agy) executes review and produces primary findings.
 * - Deterministic Layer guarantees bit-level non-tampering (corpusDigest + artifact manifest).
 * - Independent Verifier (e.g. Anthropic claude) independently reviews producer findings against physical diff
 *   without capability to overwrite, delete, or silently merge dissenting opinions.
 * - Disagreement Ledger records whether each finding is verified, contested, or classified as INSUFFICIENT_EVIDENCE.
 *   Disagreements survive consensus minting as primary empirical evidence.
 */

import fs from "node:fs";
import process from "node:process";
import { spawn } from "node:child_process";
import {
  canonicalJsonStringify,
  computeDigest,
  digestChangeSet,
  normalizeLineEndings
} from "./canonical-digest.mjs";
import {
  normalizeActualModel,
  normalizeReceiptUsage,
  SOURCE_TRUST_TIERS
} from "./audit-receipt.mjs";
import { normalizeFinding } from "./harness.mjs";
import {
  EXECUTION_STATUS,
  DEFAULT_LIMITS,
  extractJsonFromText
} from "../adapters/provider-contract.mjs";
import {
  resolveProviderProfile,
  assembleProviderArgs,
  SAFE_ARGV_THRESHOLD_BYTES
} from "../adapters/provider-profiles.mjs";

/**
 * Normative verification schema version.
 */
export const VERIFICATION_SCHEMA_VERSION = "1.0.0";
export const SUPPORTED_VERIFICATION_SCHEMA_MAJOR = 1;

/**
 * Normative verifier verdicts.
 */
export const VERIFICATION_VERDICTS = Object.freeze({
  SUPPORTED: "SUPPORTED",
  CONTESTED: "CONTESTED",
  INSUFFICIENT_EVIDENCE: "INSUFFICIENT_EVIDENCE"
});

export const VALID_VERDICTS = Object.freeze(new Set(Object.values(VERIFICATION_VERDICTS)));

const AUTH_ERROR_PATTERNS = [
  /not logged in/i,
  /unauthorized/i,
  /invalid[_\s-]api[_\s-]key/i,
  /authentication failed/i,
  /auth failure/i,
  /you are not logged into/i,
  /login required/i,
  /permission denied/i
];

/**
 * Deep freezes an object and all nested properties recursively.
 * Guarantees bit-level immutability across the verification lifecycle.
 *
 * @template T
 * @param {T} obj
 * @returns {T}
 */
export function deepFreeze(obj) {
  if (!obj || typeof obj !== "object") return obj;
  if (Object.isFrozen(obj)) return obj;
  Object.freeze(obj);
  for (const key of Object.getOwnPropertyNames(obj)) {
    const val = obj[key];
    if (val && typeof val === "object") {
      deepFreeze(val);
    }
  }
  return obj;
}

/**
 * Robust deep cloning preserving primitive types and properties.
 *
 * @template T
 * @param {T} val
 * @returns {T}
 */
export function cloneDeep(val) {
  if (typeof structuredClone === "function") {
    try {
      return structuredClone(val);
    } catch {
      // Fall through to JSON clone if structuredClone fails
    }
  }
  return JSON.parse(JSON.stringify(val));
}

/**
 * Safely parses boolean values from LLM responses handling string variations.
 *
 * @param {any} val
 * @param {boolean} defaultValue
 * @returns {boolean}
 */
function parseBoolean(val, defaultValue = true) {
  if (val === undefined || val === null) return defaultValue;
  if (typeof val === "boolean") return val;
  if (typeof val === "string") {
    const s = val.trim().toLowerCase();
    if (s === "false" || s === "0" || s === "no" || s === "off" || s === "f") return false;
    if (s === "true" || s === "1" || s === "yes" || s === "on" || s === "t") return true;
  }
  if (typeof val === "number") return val !== 0;
  return Boolean(val);
}

/**
 * Builds the canonical structured prompt for an independent verifier.
 * Instructs the verifier to inspect the diff and evaluate each producer finding across:
 * - Evidence support: Is the defect actually present in the diff?
 * - Locator accuracy: Are file and line ranges accurate?
 * - Type accuracy: Is the classification/CWE accurate?
 * - Severity accuracy: Is the severity level warranted?
 * - Contradiction / dissent: Counter-evidence if contested.
 * - Potential omissions: Defects in the diff missed by the producer.
 *
 * @param {object} changeSet - ChangeSet object containing diffHunks, files, scopeMode
 * @param {object[]} producerFindings - Array of findings emitted by the producer
 * @param {object} [options]
 * @param {string} [options.role="verifier"]
 * @param {object} [options.limits=DEFAULT_LIMITS]
 * @returns {string} Fully rendered verification prompt
 */
export function buildVerificationPrompt(changeSet = {}, producerFindings = [], options = {}) {
  const limits = options.limits || DEFAULT_LIMITS;
  const maxBytes = Number(limits.maxInputBytes || DEFAULT_LIMITS.maxInputBytes);
  const role = options.role || "verifier";

  // Multi-byte safe UTF-8 byte boundary truncation
  const hunkBuf = Buffer.isBuffer(changeSet?.diffHunks)
    ? changeSet.diffHunks
    : Buffer.from(String(changeSet?.diffHunks || ""), "utf8");

  let hunks = "";
  let truncatedNotice = "";
  if (hunkBuf.length > maxBytes) {
    hunks = hunkBuf.subarray(0, maxBytes).toString("utf8");
    truncatedNotice = `\n[NOTE: Diff truncated at ${maxBytes} bytes limit]\n`;
  } else {
    hunks = hunkBuf.toString("utf8");
  }

  const files = Array.isArray(changeSet?.files) ? changeSet.files : [];
  const fileList = files.length > 0
    ? files.map(f => {
        const binNotice = f.binary ? " [binary]" : "";
        return `  - ${f.path || "unknown"} (+${f.additions || 0}, -${f.deletions || 0}${binNotice})`;
      }).join("\n")
    : "  (No files listed)";

  const findingsList = Array.isArray(producerFindings) ? producerFindings : [];
  let findingsBlock = "  (No producer findings to evaluate)";

  if (findingsList.length > 0) {
    findingsBlock = findingsList.map((f, i) => {
      if (!f || typeof f !== "object") {
        return `Finding #${i + 1} [ID: finding-${i + 1}]\n  - (Invalid finding entry)`;
      }
      const rawId = f.id !== undefined && f.id !== null ? String(f.id) : (f.findingId !== undefined && f.findingId !== null ? String(f.findingId) : `finding-${i + 1}`);
      const lineStart = f.line_start !== undefined ? f.line_start : (f.line !== undefined ? f.line : 1);
      const lineEnd = f.line_end !== undefined ? f.line_end : lineStart;
      const parts = [
        `Finding #${i + 1} [ID: ${rawId}]`,
        `  - Title: ${f.title || "Untitled Finding"}`,
        `  - File: ${f.file || "unknown"}`,
        `  - Lines: ${lineStart} to ${lineEnd}`,
        `  - Severity: ${f.severity || "unknown"}`
      ];
      if (f.cwe) parts.push(`  - CWE: ${f.cwe}`);
      if (f.type) parts.push(`  - Type: ${f.type}`);
      if (f.ruleId) parts.push(`  - Rule ID: ${f.ruleId}`);
      if (f.recommendation) parts.push(`  - Recommendation: ${f.recommendation}`);
      return parts.join("\n");
    }).join("\n\n");
  }

  const scope = changeSet?.scopeMode || "working-tree";
  const contentDigest = changeSet?.contentDigest || "none";

  return [
    `You are a strict read-only independent verification sentry (${role} role).`,
    `You are conducting adversarial verification of primary code review findings against the physical diff.`,
    `Your role is DECOUPLED from the producer: you must evaluate findings objectively under Default-Deny.`,
    ``,
    `EVALUATION CRITERIA:`,
    `1. Evidence Support: Verify if each finding is concretely supported by the changes in the diff.`,
    `2. Locator Accuracy: Verify whether the file path and line numbers are accurate.`,
    `3. Type Accuracy: Verify whether the reported defect type, classification, or CWE is accurate.`,
    `4. Severity Accuracy: Verify whether the assigned severity level is justified.`,
    `5. Verdict Selection: Assign one of the following exact verdicts:`,
    `   - "SUPPORTED": The finding is conclusively backed by the diff evidence.`,
    `   - "CONTESTED": The finding is factually incorrect, false-positive, or ungrounded. You MUST provide 'dissent' reasoning.`,
    `   - "INSUFFICIENT_EVIDENCE": The diff contains insufficient context to corroborate or refute the finding.`,
    `6. Independent Omissions: If you find security vulnerabilities or bugs in the diff that the producer missed, report them in 'verifierOmissions'.`,
    `7. Immutability Guarantee: You cannot overwrite, delete, or silently merge producer findings.`,
    ``,
    `Scope: ${scope}`,
    `Content Digest: ${contentDigest}`,
    `Files Changed:`,
    fileList,
    truncatedNotice,
    `Producer Findings Under Independent Verification:`,
    findingsBlock,
    ``,
    `Diff:`,
    `\`\`\``,
    hunks,
    `\`\`\``,
    ``,
    `Respond ONLY with a JSON object in this exact format, with no preamble or commentary:`,
    `{`,
    `  "evaluations": [`,
    `    {`,
    `      "findingId": "finding-1",`,
    `      "verdict": "SUPPORTED|CONTESTED|INSUFFICIENT_EVIDENCE",`,
    `      "locatorAccurate": true,`,
    `      "typeAccurate": true,`,
    `      "severityAccurate": true,`,
    `      "reasoning": "Concrete evidence-based explanation",`,
    `      "dissent": null`,
    `    }`,
    `  ],`,
    `  "verifierOmissions": [`,
    `    {`,
    `      "title": "Title of omitted issue",`,
    `      "severity": "critical|high|medium|low|info",`,
    `      "file": "path/to/file",`,
    `      "line_start": 1,`,
    `      "line_end": 1,`,
    `      "recommendation": "Fix instruction",`,
    `      "cwe": "CWE-OPTIONAL",`,
    `      "type": "TYPE-OPTIONAL"`,
    `    }`,
    `  ],`,
    `  "usage": {`,
    `    "promptTokens": null,`,
    `    "completionTokens": null,`,
    `    "totalTokens": null`,
    `  }`,
    `}`
  ].join("\n");
}

/**
 * Validates and normalizes raw verifier output under Default-Deny.
 * Handles malformed/empty/error cases and strips capability forgery.
 *
 * @param {object|string|null} rawOutput - Raw output from verifier adapter or CLI
 * @param {object} [context={}] - Context containing changeSet, producerFindings, verifierIdentity
 * @returns {object} Normalized verifier output
 */
export function validateVerificationOutput(rawOutput, context = {}) {
  // Handle transport-level error or terminal non-success status
  if (rawOutput && (rawOutput.ok === false || (rawOutput.executionStatus && rawOutput.executionStatus !== EXECUTION_STATUS.SUCCESS && rawOutput.executionStatus !== EXECUTION_STATUS.EMPTY))) {
    const status = Object.values(EXECUTION_STATUS).includes(rawOutput.executionStatus)
      ? rawOutput.executionStatus
      : EXECUTION_STATUS.ERROR;

    return Object.freeze({
      ok: false,
      valid: false,
      executionStatus: status,
      evaluations: Object.freeze([]),
      verifierOmissions: Object.freeze([]),
      usage: null,
      error: rawOutput.error ? String(rawOutput.error) : `Verifier execution terminated with status '${status}'.`
    });
  }

  let parsed = rawOutput;
  if (typeof rawOutput === "string") {
    parsed = extractJsonFromText(rawOutput);
    if (!parsed) {
      return Object.freeze({
        ok: false,
        valid: false,
        executionStatus: EXECUTION_STATUS.MALFORMED_OUTPUT,
        evaluations: Object.freeze([]),
        verifierOmissions: Object.freeze([]),
        usage: null,
        error: "Failed to extract valid JSON from verifier output string."
      });
    }
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return Object.freeze({
      ok: false,
      valid: false,
      executionStatus: EXECUTION_STATUS.MALFORMED_OUTPUT,
      evaluations: Object.freeze([]),
      verifierOmissions: Object.freeze([]),
      usage: null,
      error: "Verifier output must be a non-null plain object."
    });
  }

  // Enforce required evaluations array (Fail-Closed)
  if (!Array.isArray(parsed.evaluations)) {
    return Object.freeze({
      ok: false,
      valid: false,
      executionStatus: EXECUTION_STATUS.MALFORMED_OUTPUT,
      evaluations: Object.freeze([]),
      verifierOmissions: Object.freeze([]),
      usage: null,
      error: "Verifier output requires an 'evaluations' array."
    });
  }

  // Validate each evaluation under Default-Deny
  const normalizedEvaluations = [];
  for (let i = 0; i < parsed.evaluations.length; i++) {
    const item = parsed.evaluations[i];
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      return Object.freeze({
        ok: false,
        valid: false,
        executionStatus: EXECUTION_STATUS.MALFORMED_OUTPUT,
        evaluations: Object.freeze([]),
        verifierOmissions: Object.freeze([]),
        usage: null,
        error: `Malformed evaluation at index ${i}: must be a plain object.`
      });
    }

    // Capability forgery defense
    delete item.__trustedCapabilityNonce;
    delete item.authority;
    delete item.isTrusted;
    delete item.quorumReached;
    delete item.consensusProof;

    const findingId = item.findingId !== undefined && item.findingId !== null
      ? String(item.findingId).trim()
      : "";
    if (!findingId) {
      return Object.freeze({
        ok: false,
        valid: false,
        executionStatus: EXECUTION_STATUS.MALFORMED_OUTPUT,
        evaluations: Object.freeze([]),
        verifierOmissions: Object.freeze([]),
        usage: null,
        error: `Evaluation at index ${i} is missing required 'findingId'.`
      });
    }

    const rawVerdict = item.verdict !== undefined && item.verdict !== null
      ? String(item.verdict).toUpperCase().trim()
      : "";
    if (!VALID_VERDICTS.has(rawVerdict)) {
      return Object.freeze({
        ok: false,
        valid: false,
        executionStatus: EXECUTION_STATUS.MALFORMED_OUTPUT,
        evaluations: Object.freeze([]),
        verifierOmissions: Object.freeze([]),
        usage: null,
        error: `Invalid verdict '${item.verdict}' for finding '${findingId}'. Must be one of: ${Array.from(VALID_VERDICTS).join(", ")}.`
      });
    }

    const isContestedVerdict = rawVerdict === VERIFICATION_VERDICTS.CONTESTED;
    const locatorAccurate = parseBoolean(item.locatorAccurate, !isContestedVerdict);
    const typeAccurate = parseBoolean(item.typeAccurate, !isContestedVerdict);
    const severityAccurate = parseBoolean(item.severityAccurate, !isContestedVerdict);
    const reasoning = item.reasoning !== undefined && item.reasoning !== null
      ? String(item.reasoning).trim()
      : "";

    let dissent = null;
    if (item.dissent !== undefined && item.dissent !== null) {
      const dStr = String(item.dissent).trim();
      dissent = dStr.length > 0 ? dStr : null;
    } else if (rawVerdict === VERIFICATION_VERDICTS.CONTESTED) {
      dissent = reasoning || "Contested by independent verifier";
    } else if (rawVerdict === VERIFICATION_VERDICTS.INSUFFICIENT_EVIDENCE) {
      dissent = reasoning || "Insufficient evidence in diff to corroborate finding";
    } else if (!locatorAccurate || !severityAccurate || !typeAccurate) {
      const contestedFields = [];
      if (!locatorAccurate) contestedFields.push("locator");
      if (!severityAccurate) contestedFields.push("severity");
      if (!typeAccurate) contestedFields.push("type");
      dissent = reasoning || `${contestedFields.join(" and ")} contested by independent verifier`;
    }

    normalizedEvaluations.push(deepFreeze({
      findingId,
      verdict: rawVerdict,
      locatorAccurate,
      typeAccurate,
      severityAccurate,
      reasoning,
      dissent
    }));
  }

  // Validate verifier omissions
  const rawOmissions = parsed.verifierOmissions;
  const normalizedOmissions = [];
  if (rawOmissions !== undefined && rawOmissions !== null) {
    if (!Array.isArray(rawOmissions)) {
      return Object.freeze({
        ok: false,
        valid: false,
        executionStatus: EXECUTION_STATUS.MALFORMED_OUTPUT,
        evaluations: Object.freeze([]),
        verifierOmissions: Object.freeze([]),
        usage: null,
        error: "Verifier output 'verifierOmissions' must be an array when present."
      });
    }

    for (let i = 0; i < rawOmissions.length; i++) {
      const candidate = rawOmissions[i];
      if (candidate && typeof candidate === "object") {
        delete candidate.__trustedCapabilityNonce;
        delete candidate.authority;
        delete candidate.isTrusted;
      }

      const norm = normalizeFinding(candidate);
      if (!norm.valid) {
        return Object.freeze({
          ok: false,
          valid: false,
          executionStatus: EXECUTION_STATUS.MALFORMED_OUTPUT,
          evaluations: Object.freeze([]),
          verifierOmissions: Object.freeze([]),
          usage: null,
          error: `Malformed verifier omission at index ${i}: ${norm.reason || "invalid finding format"}`
        });
      }
      const omissionFinding = {
        ...norm.finding,
        id: candidate?.id ? String(candidate.id) : (candidate?.findingId ? String(candidate.findingId) : `omission-${i + 1}`)
      };
      normalizedOmissions.push(deepFreeze(omissionFinding));
    }
  }

  // Validate usage
  let usage = null;
  if (parsed.usage && typeof parsed.usage === "object") {
    usage = {
      promptTokens: Number.isFinite(parsed.usage.promptTokens) ? Number(parsed.usage.promptTokens) : null,
      completionTokens: Number.isFinite(parsed.usage.completionTokens) ? Number(parsed.usage.completionTokens) : null,
      totalTokens: Number.isFinite(parsed.usage.totalTokens) ? Number(parsed.usage.totalTokens) : null
    };
  }

  return Object.freeze({
    ok: true,
    valid: true,
    executionStatus: EXECUTION_STATUS.SUCCESS,
    evaluations: Object.freeze(normalizedEvaluations),
    verifierOmissions: Object.freeze(normalizedOmissions),
    usage: usage ? Object.freeze(usage) : null,
    error: null
  });
}

/**
 * Dedicated CLI Verifier Adapter for independent verification sentries.
 */
export class CliVerifierAdapter {
  constructor(options = {}) {
    this.command = options.command || "claude";
    const profile = resolveProviderProfile(this.command);
    this.profile = profile;
    this.providerName = options.providerName || profile.id || "claude";
    this.modelName = options.modelName || "claude-default";
    this.actualModel = options.actualModel || null;
    this.family = options.family || profile.family;
    this.inputChannel = options.inputChannel || profile.inputChannel || "argv";
    this.supportsStdin = options.supportsStdin !== undefined
      ? Boolean(options.supportsStdin)
      : (profile.supportsStdin ?? true);
    this.execFn = typeof options.execFn === "function" ? options.execFn : null;
    this.useStdin = options.useStdin !== undefined ? Boolean(options.useStdin) : null;
    this.env = options.env || null;
    this.cwd = options.cwd || null;
    this.args = assembleProviderArgs(profile, options.args);
  }

  async executeVerification(adapterInput) {
    const prompt = adapterInput.prompt;
    const limits = adapterInput.limits || DEFAULT_LIMITS;
    const timeoutMs = adapterInput.timeoutMs || 60000;
    const signal = adapterInput.signal || null;

    if (signal && signal.aborted) {
      return {
        ok: false,
        executionStatus: EXECUTION_STATUS.CANCELLED,
        error: "Execution cancelled before child process invocation."
      };
    }

    if (this.cwd && !fs.existsSync(this.cwd)) {
      return {
        ok: false,
        executionStatus: EXECUTION_STATUS.ERROR,
        error: `Configured working directory (cwd) does not exist: ${this.cwd}`
      };
    }

    const effectiveCwd = (this.cwd && fs.existsSync(this.cwd))
      ? this.cwd
      : (adapterInput.changeSet?.repository?.root || undefined);

    if (this.execFn) {
      try {
        const res = await this.execFn({
          command: this.command,
          args: [...this.args, prompt],
          prompt,
          input: adapterInput,
          cwd: effectiveCwd
        });
        return this._processResult(res, limits);
      } catch (err) {
        return {
          ok: false,
          executionStatus: EXECUTION_STATUS.ERROR,
          error: err?.message || String(err)
        };
      }
    }

    return new Promise((resolve) => {
      let stdout = "";
      let stderr = "";
      let timedOut = false;
      let aborted = false;

      const promptBytes = Buffer.byteLength(prompt, "utf8");
      let useStdin = false;
      if (this.useStdin !== null) {
        useStdin = this.useStdin;
      } else if (this.inputChannel === "stdin") {
        useStdin = true;
      } else if (this.supportsStdin && promptBytes > SAFE_ARGV_THRESHOLD_BYTES) {
        useStdin = true;
      }

      if (useStdin && !this.supportsStdin) {
        resolve({
          ok: false,
          executionStatus: EXECUTION_STATUS.ERROR,
          error: `Provider '${this.providerName}' operates strictly via argv and does not support stdin streaming.`
        });
        return;
      }

      if (!useStdin && process.platform === "win32" && promptBytes > 30000) {
        resolve({
          ok: false,
          executionStatus: EXECUTION_STATUS.PAYLOAD_TOO_LARGE,
          error: `Prompt size (${promptBytes} bytes) exceeds safe Windows command line length limit for argv provider '${this.providerName}'.`
        });
        return;
      }

      const childArgs = useStdin ? [...this.args] : [...this.args, prompt];
      let child;
      try {
        child = spawn(this.command, childArgs, {
          cwd: effectiveCwd,
          shell: false,
          windowsHide: true,
          stdio: [useStdin ? "pipe" : "ignore", "pipe", "pipe"],
          ...(this.env ? { env: this.env } : {})
        });
      } catch (spawnErr) {
        resolve({
          ok: false,
          executionStatus: EXECUTION_STATUS.ERROR,
          error: `CLI verifier spawn error: ${spawnErr.message}`
        });
        return;
      }

      if (useStdin && child.stdin) {
        child.stdin.on("error", () => {});
        child.stdin.write(prompt, "utf8", () => {
          child.stdin.end();
        });
      }

      const timer = setTimeout(() => {
        timedOut = true;
        child.kill();
      }, timeoutMs);

      const abortHandler = () => {
        aborted = true;
        child.kill();
      };

      if (signal) {
        signal.addEventListener("abort", abortHandler, { once: true });
      }

      child.stdout.on("data", (chunk) => {
        stdout += chunk.toString("utf8");
      });
      child.stderr.on("data", (chunk) => {
        stderr += chunk.toString("utf8");
      });

      child.on("close", (code) => {
        clearTimeout(timer);
        if (signal) {
          signal.removeEventListener("abort", abortHandler);
        }

        if (timedOut) {
          resolve({
            ok: false,
            executionStatus: EXECUTION_STATUS.TIMEOUT,
            error: `Verifier execution timed out after ${timeoutMs}ms.`
          });
          return;
        }

        if (aborted) {
          resolve({
            ok: false,
            executionStatus: EXECUTION_STATUS.CANCELLED,
            error: "Verifier execution was aborted."
          });
          return;
        }

        if (code !== 0) {
          const combined = `${stderr}\n${stdout}`;
          const isAuthError = AUTH_ERROR_PATTERNS.some(p => p.test(combined));
          resolve({
            ok: false,
            executionStatus: isAuthError ? EXECUTION_STATUS.AUTH_FAILURE : EXECUTION_STATUS.ERROR,
            error: isAuthError
              ? `Authentication failure in CLI verifier: ${combined.trim()}`
              : `CLI verifier exited with code ${code}: ${(stderr || stdout).trim()}`
          });
          return;
        }

        const parsed = extractJsonFromText(stdout);
        if (!parsed) {
          resolve({
            ok: false,
            executionStatus: EXECUTION_STATUS.MALFORMED_OUTPUT,
            error: `Failed to extract valid JSON from verifier output: ${stdout.slice(0, 500)}`
          });
          return;
        }

        resolve(parsed);
      });
    });
  }

  _processResult(res, limits) {
    if (res && (res.ok === false || (res.executionStatus && res.executionStatus !== EXECUTION_STATUS.SUCCESS && res.executionStatus !== EXECUTION_STATUS.EMPTY))) {
      return res;
    }

    const exitCode = res?.code ?? res?.exitCode;
    if (exitCode !== undefined && exitCode !== 0) {
      const fullErr = `${res.stderr || ""}\n${res.stdout || ""}`;
      const isAuthError = AUTH_ERROR_PATTERNS.some(p => p.test(fullErr));
      return {
        ok: false,
        executionStatus: isAuthError ? EXECUTION_STATUS.AUTH_FAILURE : EXECUTION_STATUS.ERROR,
        error: isAuthError
          ? `Authentication failure in CLI verifier: ${fullErr.trim()}`
          : `CLI verifier exited with code ${exitCode}: ${(res.stderr || res.stdout || "").trim()}`
      };
    }

    if (res && typeof res.stdout === "string") {
      const parsed = extractJsonFromText(res.stdout);
      if (!parsed) {
        return {
          ok: false,
          executionStatus: EXECUTION_STATUS.MALFORMED_OUTPUT,
          error: `Failed to extract valid JSON from verifier output: ${res.stdout.slice(0, 500)}`
        };
      }
      return parsed;
    }

    if (res && typeof res === "object") {
      return res;
    }

    return {
      ok: false,
      executionStatus: EXECUTION_STATUS.MALFORMED_OUTPUT,
      error: "Unexpected verifier execution result."
    };
  }
}

/**
 * Finds and matches a verifier evaluation against a producer finding.
 * Handles flexible matching (exact ID, lowercase, generated finding-N, Finding #N, #N).
 * Detects internal verifier contradictions under Default-Deny.
 *
 * @param {object[]} evaluations
 * @param {object} pf
 * @param {number} index
 * @returns {object|null}
 */
function findEvaluationForProducerFinding(evaluations, pf, index) {
  if (!Array.isArray(evaluations)) return null;

  const targetId = pf && typeof pf === "object"
    ? (pf.id !== undefined && pf.id !== null ? String(pf.id) : (pf.findingId !== undefined && pf.findingId !== null ? String(pf.findingId) : `finding-${index + 1}`))
    : `finding-${index + 1}`;

  const candidateKeys = new Set([
    targetId,
    targetId.toLowerCase(),
    `finding-${index + 1}`,
    `finding-${index + 1}`.toLowerCase(),
    String(index + 1),
    `#${index + 1}`,
    `finding #${index + 1}`.toLowerCase(),
    `finding ${index + 1}`.toLowerCase()
  ]);

  const matches = [];
  for (const ev of evaluations) {
    const evId = String(ev.findingId || "").trim();
    const evIdLower = evId.toLowerCase();
    if (candidateKeys.has(evId) || candidateKeys.has(evIdLower)) {
      matches.push(ev);
    } else {
      const cleanMatch = evIdLower.replace(/^finding\s*(?:#|no\.?)?\s*/i, "").trim();
      if (candidateKeys.has(cleanMatch)) {
        matches.push(ev);
      }
    }
  }

  if (matches.length === 0) return null;
  if (matches.length === 1) return matches[0];

  // Self-contradiction by verifier under Default-Deny
  const verdicts = new Set(matches.map(m => m.verdict));
  if (verdicts.size > 1) {
    return {
      findingId: targetId,
      verdict: VERIFICATION_VERDICTS.CONTESTED,
      locatorAccurate: false,
      typeAccurate: false,
      severityAccurate: false,
      reasoning: "Verifier provided multiple conflicting evaluations for this finding.",
      dissent: "Self-contradiction by verifier: multiple conflicting evaluations."
    };
  }

  return matches[0];
}

/**
 * Orchestrates an independent verification run against primary producer findings.
 * Guarantees that:
 * 1. Producer findings are preserved 100% bit-for-bit (strictly verbatim, immutable).
 * 2. Independent verifier reviews producer findings against physical diff without overwrite/delete/merge capability.
 * 3. Contested findings and dissents survive in disagreementLedger.
 * 4. Verifier omissions are isolated in verifierOmissions without polluting producer findings.
 *
 * @param {object} changeSet - ChangeSet under evaluation
 * @param {object[]} producerFindings - Primary findings emitted by producer
 * @param {object|Function} verifierAdapter - Verifier adapter or invocation function
 * @param {object} [options]
 * @param {string} [options.producerName="agy"]
 * @param {string} [options.verifierName="claude"]
 * @param {string} [options.verifierModel]
 * @param {object|string} [options.actualModel]
 * @param {string} [options.verifiedAt]
 * @param {string} [options.changeSetDigest]
 * @param {boolean} [options.throwOnError=false]
 * @param {number} [options.timeoutMs=60000]
 * @returns {Promise<object>} Canonical verificationRecord
 */
export async function conductIndependentVerification(changeSet, producerFindings, verifierAdapter, options = {}) {
  if (!changeSet || typeof changeSet !== "object") {
    throw new TypeError("Invalid changeSet: must be a non-null plain object.");
  }
  if (!Array.isArray(producerFindings)) {
    throw new TypeError("Invalid producerFindings: must be an array.");
  }
  if (!verifierAdapter) {
    throw new TypeError("Invalid verifierAdapter: must be provided.");
  }

  // 1. Bit-for-bit verbatim preservation of producer findings (Immutability Guarantee)
  const preservedProducerFindings = Object.freeze(cloneDeep(producerFindings).map(f => deepFreeze(f)));

  // Map finding IDs to producer finding objects
  const producerFindingsMap = new Map();
  for (let i = 0; i < preservedProducerFindings.length; i++) {
    const pf = preservedProducerFindings[i];
    const generatedId = `finding-${i + 1}`;
    producerFindingsMap.set(generatedId, pf);
    producerFindingsMap.set(String(i + 1), pf);
    if (pf && typeof pf === "object") {
      if (pf.id !== undefined && pf.id !== null) {
        producerFindingsMap.set(String(pf.id), pf);
        producerFindingsMap.set(String(pf.id).toLowerCase(), pf);
      }
      if (pf.findingId !== undefined && pf.findingId !== null) {
        producerFindingsMap.set(String(pf.findingId), pf);
        producerFindingsMap.set(String(pf.findingId).toLowerCase(), pf);
      }
    }
  }

  // 2. ChangeSet digest
  const changeSetDigest = options.changeSetDigest || digestChangeSet(changeSet);

  // 3. Build verification prompt
  const prompt = buildVerificationPrompt(changeSet, preservedProducerFindings, options);

  // 4. Invoke verifier adapter
  const timeoutMs = options.timeoutMs || 60000;
  const adapterInput = {
    changeSet,
    producerFindings: preservedProducerFindings,
    prompt,
    role: "verifier",
    timeoutMs,
    signal: options.signal || null,
    limits: options.limits || DEFAULT_LIMITS
  };

  let rawOutput = null;
  let verifierError = null;

  try {
    if (typeof verifierAdapter.executeVerification === "function") {
      rawOutput = await verifierAdapter.executeVerification(adapterInput);
    } else if (typeof verifierAdapter.verify === "function") {
      rawOutput = await verifierAdapter.verify(adapterInput);
    } else if (typeof verifierAdapter === "function") {
      rawOutput = await verifierAdapter(adapterInput);
    } else if (typeof verifierAdapter.execFn === "function") {
      rawOutput = await verifierAdapter.execFn(adapterInput);
    } else if (verifierAdapter && typeof verifierAdapter.command === "string") {
      const adapter = new CliVerifierAdapter(verifierAdapter);
      rawOutput = await adapter.executeVerification(adapterInput);
    } else {
      throw new TypeError("verifierAdapter does not implement executeVerification, verify, execFn, or function invocation.");
    }
  } catch (err) {
    verifierError = err;
    if (options.throwOnError) {
      throw err;
    }
    const isTimeout = err.name === "TimeoutError" || /timeout|timed out/i.test(err.message);
    rawOutput = {
      ok: false,
      error: err.message || String(err),
      executionStatus: isTimeout ? EXECUTION_STATUS.TIMEOUT : EXECUTION_STATUS.ERROR
    };
  }

  // 5. Validate verifier output under Default-Deny
  const validated = validateVerificationOutput(rawOutput, {
    changeSet,
    producerFindings: preservedProducerFindings,
    providerName: verifierAdapter?.providerName || options.verifierName,
    modelName: verifierAdapter?.modelName || options.verifierModel
  });

  if (!validated.ok && options.throwOnError && !verifierError) {
    throw new Error(validated.error || "Verifier output validation failed.");
  }

  // 6. Map evaluations and guarantee 100% coverage of producer findings
  const finalEvaluations = [];
  for (let i = 0; i < preservedProducerFindings.length; i++) {
    const pf = preservedProducerFindings[i];
    const findingId = pf && typeof pf === "object"
      ? (pf.id !== undefined && pf.id !== null ? String(pf.id) : (pf.findingId !== undefined && pf.findingId !== null ? String(pf.findingId) : `finding-${i + 1}`))
      : `finding-${i + 1}`;

    const matched = validated.ok ? findEvaluationForProducerFinding(validated.evaluations, pf, i) : null;

    if (matched) {
      finalEvaluations.push(deepFreeze({
        findingId,
        verdict: matched.verdict,
        locatorAccurate: matched.locatorAccurate,
        typeAccurate: matched.typeAccurate,
        severityAccurate: matched.severityAccurate,
        reasoning: matched.reasoning,
        dissent: matched.dissent
      }));
    } else {
      // Producer finding omitted or unverified under Default-Deny
      finalEvaluations.push(deepFreeze({
        findingId,
        verdict: VERIFICATION_VERDICTS.INSUFFICIENT_EVIDENCE,
        locatorAccurate: false,
        typeAccurate: false,
        severityAccurate: false,
        reasoning: validated.ok
          ? "Finding omitted from verifier evaluation; unverified under Default-Deny."
          : `Verification unavailable: ${validated.error || "adapter failure"}`,
        dissent: validated.ok
          ? "Omitted by independent verifier."
          : `Verifier execution failed (${validated.executionStatus || "error"}).`
      }));
    }
  }

  // 7. Verifier omissions (isolated without polluting producer findings)
  const verifierOmissions = Object.freeze(validated.ok ? [...validated.verifierOmissions] : []);

  // 8. Construct Disagreement Ledger
  const disagreementLedger = [];
  for (let i = 0; i < finalEvaluations.length; i++) {
    const ev = finalEvaluations[i];
    const isDisagreement = ev.verdict !== VERIFICATION_VERDICTS.SUPPORTED ||
      ev.locatorAccurate === false ||
      ev.severityAccurate === false ||
      ev.typeAccurate === false;

    if (isDisagreement) {
      const origFinding = preservedProducerFindings[i] || producerFindingsMap.get(ev.findingId) || null;
      disagreementLedger.push(deepFreeze({
        findingId: ev.findingId,
        producerFinding: origFinding ? deepFreeze(cloneDeep(origFinding)) : null,
        verdict: ev.verdict,
        locatorAccurate: ev.locatorAccurate,
        typeAccurate: ev.typeAccurate,
        severityAccurate: ev.severityAccurate,
        reasoning: ev.reasoning,
        dissent: ev.dissent || "Disagreement recorded in independent verification"
      }));
    }
  }

  // 9. Summary metrics
  const summary = deepFreeze({
    totalEvaluated: finalEvaluations.length,
    supportedCount: finalEvaluations.filter(e => e.verdict === VERIFICATION_VERDICTS.SUPPORTED).length,
    contestedCount: finalEvaluations.filter(e => e.verdict === VERIFICATION_VERDICTS.CONTESTED).length,
    insufficientEvidenceCount: finalEvaluations.filter(e => e.verdict === VERIFICATION_VERDICTS.INSUFFICIENT_EVIDENCE).length,
    omissionsCount: verifierOmissions.length
  });

  // 10. Verifier identity & provenance
  let actualModelInput = verifierAdapter?.actualModel || options.actualModel || validated?.actualModel;
  if (typeof actualModelInput === "string" && actualModelInput.trim()) {
    actualModelInput = { value: actualModelInput.trim(), source: SOURCE_TRUST_TIERS.CONFIGURED || "configured" };
  }

  const verifierIdentity = deepFreeze({
    providerName: verifierAdapter?.providerName || options.verifierName || "claude",
    modelName: verifierAdapter?.modelName || options.verifierModel || "claude-default",
    actualModel: deepFreeze(normalizeActualModel(actualModelInput)),
    usage: deepFreeze(normalizeReceiptUsage(validated.usage || verifierAdapter?.usage || null))
  });

  const verifiedAt = options.verifiedAt || new Date().toISOString();

  // 11. Canonical verification record
  const record = {
    schemaVersion: VERIFICATION_SCHEMA_VERSION,
    verifiedAt,
    changeSetDigest,
    producer: deepFreeze({
      providerName: options.producerName || options.producer?.providerName || "agy",
      findingsCount: producerFindings.length,
      findings: preservedProducerFindings
    }),
    verifier: verifierIdentity,
    evaluations: deepFreeze(finalEvaluations),
    verifierOmissions,
    disagreementLedger: deepFreeze(disagreementLedger),
    summary,
    ok: validated.ok,
    ...(validated.error ? { error: validated.error } : {})
  };

  return deepFreeze(record);
}

/**
 * Validates a verification record against TF-SPEC-RECEIPT-v1.0.0 Section 7 invariants.
 * Strictly verifies schema structure, producer count alignment, summary counts,
 * and Disagreement Ledger completeness to detect any tampering or omission.
 *
 * @param {object} record
 * @returns {{ valid: boolean, errors: string[] }}
 */
export function validateVerificationRecord(record) {
  const errors = [];
  if (!record || typeof record !== "object" || Array.isArray(record)) {
    return { valid: false, errors: ["Verification record must be a non-null plain object."] };
  }

  if (record.schemaVersion !== VERIFICATION_SCHEMA_VERSION) {
    errors.push(`Invalid schemaVersion: expected '${VERIFICATION_SCHEMA_VERSION}', got '${record.schemaVersion}'.`);
  }

  if (typeof record.verifiedAt !== "string" || !record.verifiedAt.trim()) {
    errors.push("Missing or invalid 'verifiedAt' ISO timestamp.");
  } else if (isNaN(Date.parse(record.verifiedAt))) {
    errors.push("Field 'verifiedAt' is not a valid parseable ISO timestamp.");
  }

  if (typeof record.changeSetDigest !== "string" || !/^sha256:[a-f0-9]{64}$/.test(record.changeSetDigest)) {
    errors.push(`Missing or invalid 'changeSetDigest': must be a 64-char lowercase hex sha256 digest.`);
  }

  // Producer validation
  if (!record.producer || typeof record.producer !== "object") {
    errors.push("Missing or invalid 'producer' object.");
  } else {
    if (typeof record.producer.providerName !== "string" || !record.producer.providerName.trim()) {
      errors.push("Producer requires a non-empty 'providerName'.");
    }
    if (!Array.isArray(record.producer.findings)) {
      errors.push("Producer requires a 'findings' array.");
    } else if (record.producer.findingsCount !== record.producer.findings.length) {
      errors.push(`Producer 'findingsCount' (${record.producer.findingsCount}) does not match findings array length (${record.producer.findings.length}).`);
    }
  }

  // Verifier validation
  if (!record.verifier || typeof record.verifier !== "object") {
    errors.push("Missing or invalid 'verifier' object.");
  } else {
    if (typeof record.verifier.providerName !== "string" || !record.verifier.providerName.trim()) {
      errors.push("Verifier requires a non-empty 'providerName'.");
    }
    if (!record.verifier.actualModel || typeof record.verifier.actualModel !== "object") {
      errors.push("Verifier requires an 'actualModel' object.");
    }
  }

  // Evaluations validation
  if (!Array.isArray(record.evaluations)) {
    errors.push("Verification record requires an 'evaluations' array.");
  } else {
    if (record.producer?.findingsCount !== undefined && record.evaluations.length !== record.producer.findingsCount) {
      errors.push(`Evaluations count (${record.evaluations.length}) does not match producer findings count (${record.producer.findingsCount}).`);
    }

    for (let i = 0; i < record.evaluations.length; i++) {
      const ev = record.evaluations[i];
      if (!ev || typeof ev !== "object") {
        errors.push(`Evaluation at index ${i} is not a plain object.`);
      } else {
        if (!ev.findingId) errors.push(`Evaluation at index ${i} missing 'findingId'.`);
        if (!VALID_VERDICTS.has(ev.verdict)) errors.push(`Evaluation at index ${i} has invalid verdict '${ev.verdict}'.`);
        if (typeof ev.locatorAccurate !== "boolean") errors.push(`Evaluation at index ${i} requires boolean 'locatorAccurate'.`);
        if (typeof ev.typeAccurate !== "boolean") errors.push(`Evaluation at index ${i} requires boolean 'typeAccurate'.`);
        if (typeof ev.severityAccurate !== "boolean") errors.push(`Evaluation at index ${i} requires boolean 'severityAccurate'.`);
      }
    }
  }

  // Verifier omissions validation
  if (!Array.isArray(record.verifierOmissions)) {
    errors.push("Verification record requires a 'verifierOmissions' array.");
  }

  // Disagreement ledger validation (Tamper Detection)
  if (!Array.isArray(record.disagreementLedger)) {
    errors.push("Verification record requires a 'disagreementLedger' array.");
  } else if (Array.isArray(record.evaluations)) {
    const expectedDisagreements = record.evaluations.filter(ev =>
      ev && (
        ev.verdict !== VERIFICATION_VERDICTS.SUPPORTED ||
        ev.locatorAccurate === false ||
        ev.severityAccurate === false ||
        ev.typeAccurate === false
      )
    );

    if (record.disagreementLedger.length !== expectedDisagreements.length) {
      errors.push(`Disagreement ledger count mismatch: expected ${expectedDisagreements.length} contested/dissenting item(s), found ${record.disagreementLedger.length}. Possible ledger tampering.`);
    }

    for (let i = 0; i < record.disagreementLedger.length; i++) {
      const item = record.disagreementLedger[i];
      if (!item || typeof item !== "object") {
        errors.push(`Disagreement ledger item at index ${i} is not a plain object.`);
      } else {
        if (!item.findingId) errors.push(`Disagreement ledger item at index ${i} missing 'findingId'.`);
        if (!VALID_VERDICTS.has(item.verdict)) errors.push(`Disagreement ledger item at index ${i} has invalid verdict '${item.verdict}'.`);
        if (!item.dissent || typeof item.dissent !== "string") {
          errors.push(`Disagreement ledger item at index ${i} missing required 'dissent' statement.`);
        }
      }
    }
  }

  // Summary validation (Tamper Detection)
  if (!record.summary || typeof record.summary !== "object") {
    errors.push("Verification record requires a 'summary' object.");
  } else {
    const evs = Array.isArray(record.evaluations) ? record.evaluations : [];
    const expectedSupported = evs.filter(e => e?.verdict === VERIFICATION_VERDICTS.SUPPORTED).length;
    const expectedContested = evs.filter(e => e?.verdict === VERIFICATION_VERDICTS.CONTESTED).length;
    const expectedInsufficient = evs.filter(e => e?.verdict === VERIFICATION_VERDICTS.INSUFFICIENT_EVIDENCE).length;
    const expectedOmissions = Array.isArray(record.verifierOmissions) ? record.verifierOmissions.length : 0;

    if (record.summary.totalEvaluated !== evs.length) {
      errors.push(`summary.totalEvaluated (${record.summary.totalEvaluated}) does not match evaluations length (${evs.length}).`);
    }
    if (record.summary.supportedCount !== expectedSupported) {
      errors.push(`summary.supportedCount (${record.summary.supportedCount}) does not match actual supported count (${expectedSupported}).`);
    }
    if (record.summary.contestedCount !== expectedContested) {
      errors.push(`summary.contestedCount (${record.summary.contestedCount}) does not match actual contested count (${expectedContested}).`);
    }
    if (record.summary.insufficientEvidenceCount !== expectedInsufficient) {
      errors.push(`summary.insufficientEvidenceCount (${record.summary.insufficientEvidenceCount}) does not match actual insufficient count (${expectedInsufficient}).`);
    }
    if (record.summary.omissionsCount !== expectedOmissions) {
      errors.push(`summary.omissionsCount (${record.summary.omissionsCount}) does not match verifierOmissions length (${expectedOmissions}).`);
    }
  }

  return {
    errors,
    valid: errors.length === 0
  };
}

/**
 * Computes deterministic digest of a verification record.
 *
 * @param {object} record
 * @returns {string} "sha256:..."
 */
export function computeVerificationRecordDigest(record) {
  const validation = validateVerificationRecord(record);
  if (!validation.valid) {
    throw new Error(`Cannot digest invalid verification record:\n  - ${validation.errors.join("\n  - ")}`);
  }
  return computeDigest(canonicalJsonStringify(record));
}
