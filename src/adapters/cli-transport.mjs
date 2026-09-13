/**
 * Controlled CLI Transport Adapter (PR-03)
 *
 * Implements read-only, non-interactive execution of a local CLI reviewer (e.g. agy, claude).
 * Enforces strict timeouts, output size limits, cancellation signals, and Default-Deny output validation.
 * Never executes arbitrary commands returned by models and never mutates the repository.
 */

import fs from "node:fs";
import { spawn } from "node:child_process";
import {
  EXECUTION_STATUS,
  DEFAULT_LIMITS,
  validateProviderInput,
  validateProviderOutput
} from "./provider-contract.mjs";
import {
  resolveProviderProfile,
  assembleProviderArgs,
  SAFE_ARGV_THRESHOLD_BYTES
} from "./provider-profiles.mjs";

export { resolveProviderProfile, assembleProviderArgs, SAFE_ARGV_THRESHOLD_BYTES } from "./provider-profiles.mjs";

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
    const profile = resolveProviderProfile(this.command);
    this.profile = profile;
    this.providerName = options.providerName || profile.id || "cli-reviewer";
    this.modelName = options.modelName || "cli-default";
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
      family: this.family,
      modelName: this.modelName,
      transport: "cli"
    };

    if (this.cwd && !fs.existsSync(this.cwd)) {
      return validateProviderOutput({
        executionStatus: EXECUTION_STATUS.ERROR,
        error: `Configured working directory (cwd) does not exist: ${this.cwd}`
      }, context);
    }

    const rawCwd = this.cwd || input.changeSet?.repository?.root;
    const effectiveCwd = (rawCwd && fs.existsSync(rawCwd)) ? rawCwd : undefined;

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
          input,
          cwd: effectiveCwd
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

      const promptBytes = Buffer.byteLength(prompt, "utf8");
      let useStdin = false;
      if (this.useStdin !== null) {
        useStdin = this.useStdin;
      } else if (this.inputChannel === "stdin") {
        useStdin = true;
      } else if (this.supportsStdin && promptBytes > SAFE_ARGV_THRESHOLD_BYTES) {
        useStdin = true;
      }

      // If stdin requested for argv-only provider, fail-closed
      if (useStdin && !this.supportsStdin) {
        resolve(validateProviderOutput({
          executionStatus: EXECUTION_STATUS.ERROR,
          error: `Provider '${this.providerName}' operates strictly via argv and does not support stdin streaming.`
        }, context));
        return;
      }

      // If argv is used and prompt exceeds Windows command line limit (32,767 chars), fail closed
      if (!useStdin && process.platform === "win32" && promptBytes > 30000) {
        resolve(validateProviderOutput({
          executionStatus: EXECUTION_STATUS.PAYLOAD_TOO_LARGE,
          error: `Prompt size (${promptBytes} bytes) exceeds safe Windows command line length limit for argv provider '${this.providerName}'.`
        }, context));
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
        resolve(validateProviderOutput({
          executionStatus: EXECUTION_STATUS.ERROR,
          error: `CLI transport spawn error: ${spawnErr.message}`
        }, context));
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
        if (Buffer.byteLength(stderr, "utf8") > input.limits.maxOutputBytes) {
          killedReason = EXECUTION_STATUS.PAYLOAD_TOO_LARGE;
          child.kill();
        }
      });

      child.on("error", (err) => {
        clearTimeout(timer);
        if (input.signal) input.signal.removeEventListener("abort", abortHandler);

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

        // 1. Non-zero exit code priority: always fails closed
        if (code !== 0) {
          const fullErr = `${stderr}\n${stdout}`;
          const isAuthError = AUTH_ERROR_PATTERNS.some(p => p.test(fullErr));
          resolve(validateProviderOutput({
            executionStatus: isAuthError ? EXECUTION_STATUS.AUTH_FAILURE : EXECUTION_STATUS.ERROR,
            error: isAuthError
              ? `Authentication failure detected in CLI reviewer output: ${(stderr || stdout).trim()}`
              : `CLI reviewer exited with code ${code}: ${stderr.trim() || stdout.trim()}`
          }, context));
          return;
        }

        // 2. Process exited with 0: check stderr for auth error
        if (stderr && AUTH_ERROR_PATTERNS.some(p => p.test(stderr))) {
          resolve(validateProviderOutput({
            executionStatus: EXECUTION_STATUS.AUTH_FAILURE,
            error: `Authentication failure detected in CLI reviewer output: ${stderr.trim()}`
          }, context));
          return;
        }

        // 3. Try to extract JSON from stdout
        const parsed = extractJsonFromText(stdout);
        if (!parsed) {
          if (AUTH_ERROR_PATTERNS.some(p => p.test(stdout))) {
            resolve(validateProviderOutput({
              executionStatus: EXECUTION_STATUS.AUTH_FAILURE,
              error: `Authentication failure detected in CLI reviewer output: ${stdout.trim()}`
            }, context));
            return;
          }
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

    const exitCode = res?.code ?? res?.exitCode;
    if (exitCode !== undefined && exitCode !== 0) {
      const fullErr = `${res.stderr || ""}\n${res.stdout || ""}`;
      const isAuthError = AUTH_ERROR_PATTERNS.some(p => p.test(fullErr));
      return validateProviderOutput({
        executionStatus: isAuthError ? EXECUTION_STATUS.AUTH_FAILURE : EXECUTION_STATUS.ERROR,
        error: isAuthError
          ? `Authentication failure detected in CLI reviewer output: ${(res.stderr || res.stdout || "").trim()}`
          : `CLI reviewer exited with code ${exitCode}: ${(res.stderr || "").trim() || (res.stdout || "").trim()}`
      }, context);
    }

    if (res && typeof res.stdout === "string") {
      if (Buffer.byteLength(res.stdout, "utf8") > limits.maxOutputBytes) {
        return validateProviderOutput({
          executionStatus: EXECUTION_STATUS.PAYLOAD_TOO_LARGE,
          error: `Output exceeded maxOutputBytes (${limits.maxOutputBytes})`
        }, context);
      }

      if (res.stderr && Buffer.byteLength(res.stderr, "utf8") > limits.maxOutputBytes) {
        return validateProviderOutput({
          executionStatus: EXECUTION_STATUS.PAYLOAD_TOO_LARGE,
          error: `Stderr exceeded maxOutputBytes (${limits.maxOutputBytes})`
        }, context);
      }

      if (res.stderr && AUTH_ERROR_PATTERNS.some(p => p.test(res.stderr))) {
        return validateProviderOutput({
          executionStatus: EXECUTION_STATUS.AUTH_FAILURE,
          error: `Authentication failure detected in CLI reviewer output: ${res.stderr.trim()}`
        }, context);
      }

      const parsed = extractJsonFromText(res.stdout);
      if (!parsed) {
        if (AUTH_ERROR_PATTERNS.some(p => p.test(res.stdout))) {
          return validateProviderOutput({
            executionStatus: EXECUTION_STATUS.AUTH_FAILURE,
            error: `Authentication failure detected in CLI reviewer output: ${res.stdout.trim()}`
          }, context);
        }
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

    const fixtureObj = (this.fixture && typeof this.fixture === "object" && !Array.isArray(this.fixture))
      ? { ...this.fixture }
      : this.fixture;

    if (fixtureObj && typeof fixtureObj === "object" && !fixtureObj.coverage && inputValidation.input.changeSet?.files) {
      fixtureObj.coverage = {
        coveredFiles: inputValidation.input.changeSet.files.map(f => f.path),
        omittedFiles: []
      };
    }

    return validateProviderOutput(fixtureObj, context);
  }
}
