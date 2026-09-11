/**
 * Controlled CLI Transport Adapter (PR-03)
 *
 * Implements read-only, non-interactive execution of a local CLI reviewer (e.g. agy, claude).
 * Enforces strict timeouts, output size limits, cancellation signals, and Default-Deny output validation.
 * Never executes arbitrary commands returned by models and never mutates the repository.
 */

import { spawn } from "node:child_process";
import {
  EXECUTION_STATUS,
  DEFAULT_LIMITS,
  validateProviderInput,
  validateProviderOutput
} from "./provider-contract.mjs";

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
 * Extracts a JSON string from raw text that may contain markdown code fences.
 */
export function extractJsonFromText(text = "") {
  if (typeof text !== "string") return null;
  const trimmed = text.trim();
  if (!trimmed) return null;

  // Try direct parse first
  if ((trimmed.startsWith("{") && trimmed.endsWith("}")) || (trimmed.startsWith("[") && trimmed.endsWith("]"))) {
    try {
      return JSON.parse(trimmed);
    } catch {
      // Fall through to fence extraction
    }
  }

  // Extract from ```json ... ``` or ``` ... ```
  const fenceMatch = trimmed.match(/```(?:json)?\s*([\s\S]*?)\s*```/i);
  if (fenceMatch && fenceMatch[1]) {
    try {
      return JSON.parse(fenceMatch[1].trim());
    } catch {
      // Fall through
    }
  }

  // Extract outermost balanced JSON object
  const startIdx = trimmed.indexOf("{");
  const endIdx = trimmed.lastIndexOf("}");
  if (startIdx !== -1 && endIdx > startIdx) {
    try {
      return JSON.parse(trimmed.slice(startIdx, endIdx + 1));
    } catch {
      return null;
    }
  }

  return null;
}

/**
 * Builds the canonical read-only prompt for the CLI reviewer.
 */
export function buildReviewPrompt(changeSet, role = "macro", limits = DEFAULT_LIMITS) {
  const maxBytes = limits.maxInputBytes || DEFAULT_LIMITS.maxInputBytes;
  let hunks = changeSet.diffHunks || "";
  let truncatedNotice = "";

  if (Buffer.byteLength(hunks, "utf8") > maxBytes) {
    hunks = hunks.slice(0, maxBytes);
    truncatedNotice = `\n[NOTE: Diff truncated at ${maxBytes} bytes limit]\n`;
  }

  const fileList = (changeSet.files || []).map(f => `  - ${f.path} (+${f.additions || 0}, -${f.deletions || 0})`).join("\n");

  return [
    `You are a strict read-only code review sentry (${role} role).`,
    `Review the following code changes for security vulnerabilities, bugs, and defects.`,
    ``,
    `Scope: ${changeSet.scopeMode || "working-tree"}`,
    `Content Digest: ${changeSet.contentDigest || "none"}`,
    `Files Changed:`,
    fileList,
    truncatedNotice,
    `Diff:`,
    `\`\`\``,
    hunks,
    `\`\`\``,
    ``,
    `Respond ONLY with a JSON object in this exact format, with no preamble or commentary:`,
    `{`,
    `  "findings": [`,
    `    {`,
    `      "title": "Concise issue title",`,
    `      "severity": "critical|high|medium|low|info",`,
    `      "file": "path/to/file",`,
    `      "line_start": 1,`,
    `      "line_end": 1,`,
    `      "recommendation": "Actionable fix instruction",`,
    `      "ruleId": "RULE-ID-OPTIONAL",`,
    `      "cwe": "CWE-OPTIONAL",`,
    `      "type": "TYPE-OPTIONAL"`,
    `    }`,
    `  ],`,
    `  "coverage": {`,
    `    "coveredFiles": ["path/to/file"],`,
    `    "omittedFiles": []`,
    `  },`,
    `  "usage": {`,
    `    "promptTokens": null,`,
    `    "completionTokens": null,`,
    `    "totalTokens": null`,
    `  }`,
    `}`
  ].join("\n");
}

export class CliReviewAdapter {
  constructor(options = {}) {
    this.command = options.command || "agy";
    this.args = Array.isArray(options.args) ? options.args : ["--print"];
    this.providerName = options.providerName || "cli-reviewer";
    this.modelName = options.modelName || "cli-default";
    this.execFn = typeof options.execFn === "function" ? options.execFn : null;
  }

  async executeReview(rawInput) {
    const inputValidation = validateProviderInput(rawInput);
    if (!inputValidation.valid) {
      return validateProviderOutput({
        executionStatus: EXECUTION_STATUS.ERROR,
        error: `Invalid input: ${inputValidation.reason}`
      }, { runId: rawInput?.runId, providerName: this.providerName, modelName: this.modelName, transport: "cli" });
    }

    const input = inputValidation.input;
    const prompt = buildReviewPrompt(input.changeSet, input.role, input.limits);
    const context = {
      runId: input.runId,
      role: input.role,
      changeSet: input.changeSet,
      providerName: this.providerName,
      modelName: this.modelName,
      transport: "cli"
    };

    // Check if signal was already aborted
    if (input.signal && input.signal.aborted) {
      return validateProviderOutput({
        executionStatus: EXECUTION_STATUS.CANCELLED,
        error: "Execution cancelled before child process invocation."
      }, context);
    }

    // Use injected execution function if provided (e.g. for mock unit tests)
    if (this.execFn) {
      try {
        const res = await this.execFn({
          command: this.command,
          args: [...this.args, prompt],
          prompt,
          input
        });
        return this._processResult(res, context, input.limits);
      } catch (err) {
        return validateProviderOutput({
          executionStatus: EXECUTION_STATUS.ERROR,
          error: err?.message || String(err)
        }, context);
      }
    }

    // Spawn native child process safely
    return new Promise((resolve) => {
      let stdout = "";
      let stderr = "";
      let killedReason = null;
      let timedOut = false;
      let aborted = false;

      const childArgs = [...this.args, prompt];
      const child = spawn(this.command, childArgs, {
        shell: false,
        windowsHide: true,
        stdio: ["ignore", "pipe", "pipe"]
      });

      const timer = setTimeout(() => {
        timedOut = true;
        killedReason = EXECUTION_STATUS.TIMEOUT;
        child.kill();
      }, input.timeoutMs);

      const abortHandler = () => {
        aborted = true;
        killedReason = EXECUTION_STATUS.CANCELLED;
        child.kill();
      };

      if (input.signal) {
        input.signal.addEventListener("abort", abortHandler, { once: true });
      }

      child.stdout.on("data", (chunk) => {
        stdout += chunk.toString();
        if (Buffer.byteLength(stdout, "utf8") > input.limits.maxOutputBytes) {
          killedReason = EXECUTION_STATUS.PAYLOAD_TOO_LARGE;
          child.kill();
        }
      });

      child.stderr.on("data", (chunk) => {
        stderr += chunk.toString();
      });

      child.on("error", (err) => {
        clearTimeout(timer);
        if (input.signal) input.signal.removeEventListener("abort", abortHandler);

        // Check if command not found
        resolve(validateProviderOutput({
          executionStatus: EXECUTION_STATUS.ERROR,
          error: `CLI transport spawn error: ${err.message}`
        }, context));
      });

      child.on("close", (code) => {
        clearTimeout(timer);
        if (input.signal) input.signal.removeEventListener("abort", abortHandler);

        if (killedReason) {
          resolve(validateProviderOutput({
            executionStatus: killedReason,
            error: `Process terminated: ${killedReason}`
          }, context));
          return;
        }

        // Check for authentication failure
        const fullOutput = `${stdout}\n${stderr}`;
        const isAuthError = AUTH_ERROR_PATTERNS.some(p => p.test(fullOutput));
        if (isAuthError) {
          resolve(validateProviderOutput({
            executionStatus: EXECUTION_STATUS.AUTH_FAILURE,
            error: `Authentication failure detected in CLI reviewer output: ${stderr.trim() || stdout.trim()}`
          }, context));
          return;
        }

        if (code !== 0 && !stdout.trim()) {
          resolve(validateProviderOutput({
            executionStatus: EXECUTION_STATUS.ERROR,
            error: `CLI reviewer exited with code ${code}: ${stderr.trim()}`
          }, context));
          return;
        }

        const parsed = extractJsonFromText(stdout);
        if (!parsed) {
          resolve(validateProviderOutput({
            executionStatus: EXECUTION_STATUS.MALFORMED_OUTPUT,
            rawOutput: stdout.slice(0, 1000),
            error: "Failed to extract valid JSON findings from CLI reviewer output."
          }, context));
          return;
        }

        resolve(validateProviderOutput(parsed, context));
      });
    });
  }

  _processResult(res, context, limits) {
    if (res && res.executionStatus && res.executionStatus !== EXECUTION_STATUS.SUCCESS && res.executionStatus !== EXECUTION_STATUS.EMPTY) {
      return validateProviderOutput(res, context);
    }

    if (res && typeof res.stdout === "string") {
      if (Buffer.byteLength(res.stdout, "utf8") > limits.maxOutputBytes) {
        return validateProviderOutput({
          executionStatus: EXECUTION_STATUS.PAYLOAD_TOO_LARGE,
          error: `Output exceeded maxOutputBytes (${limits.maxOutputBytes})`
        }, context);
      }

      const fullOutput = `${res.stdout}\n${res.stderr || ""}`;
      if (AUTH_ERROR_PATTERNS.some(p => p.test(fullOutput))) {
        return validateProviderOutput({
          executionStatus: EXECUTION_STATUS.AUTH_FAILURE,
          error: "Authentication failure detected in CLI reviewer output."
        }, context);
      }

      const parsed = extractJsonFromText(res.stdout);
      if (!parsed) {
        return validateProviderOutput({
          executionStatus: EXECUTION_STATUS.MALFORMED_OUTPUT,
          error: "Failed to parse JSON from CLI stdout."
        }, context);
      }
      return validateProviderOutput(parsed, context);
    }

    return validateProviderOutput(res, context);
  }
}

export class OfflineReviewAdapter {
  constructor(options = {}) {
    this.fixture = options.fixture || { findings: [] };
    this.providerName = options.providerName || "offline-replay";
    this.modelName = options.modelName || "fixture";
  }

  async executeReview(rawInput) {
    const inputValidation = validateProviderInput(rawInput);
    if (!inputValidation.valid) {
      return validateProviderOutput({
        executionStatus: EXECUTION_STATUS.ERROR,
        error: `Invalid input: ${inputValidation.reason}`
      }, { runId: rawInput?.runId, providerName: this.providerName, modelName: this.modelName, transport: "offline" });
    }

    const context = {
      runId: inputValidation.input.runId,
      role: inputValidation.input.role,
      changeSet: inputValidation.input.changeSet,
      providerName: this.providerName,
      modelName: this.modelName,
      transport: "offline"
    };

    return validateProviderOutput(this.fixture, context);
  }
}
