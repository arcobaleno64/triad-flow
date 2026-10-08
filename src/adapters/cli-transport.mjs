/**
 * Controlled CLI Transport Adapter (PR-03)
 *
 * Implements read-only, non-interactive execution of a local CLI reviewer (e.g. agy, claude).
 * Enforces strict timeouts, output size limits, cancellation signals, and Default-Deny output validation.
 * Never executes arbitrary commands returned by models and never mutates the repository.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import {
  EXECUTION_STATUS,
  DEFAULT_LIMITS,
  validateProviderInput,
  validateProviderOutput,
  extractJsonFromText
} from "./provider-contract.mjs";
import {
  resolveProviderProfile,
  assembleProviderArgs,
  SAFE_ARGV_THRESHOLD_BYTES
} from "./provider-profiles.mjs";

export { resolveProviderProfile, assembleProviderArgs, SAFE_ARGV_THRESHOLD_BYTES } from "./provider-profiles.mjs";
export { extractJsonFromText } from "./provider-contract.mjs";

/**
 * Extracts final result payload from NDJSON stream-json output.
 * @param {string} text
 * @returns {object|null}
 */
export function extractStreamJsonResponse(text) {
  if (!text || typeof text !== "string") return null;
  const lines = text.split(/\r?\n/);
  let resultEvent = null;
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed && typeof parsed === "object" && parsed.event === "result") {
        resultEvent = parsed;
      }
    } catch {}
  }
  return resultEvent;
}


const AUTH_ERROR_PATTERNS = [
  /not logged in/i,
  /\b(?:401\s+unauthorized|unauthorized\s*(?:client|access\s+token|api\s+key))\b/i,
  /invalid[_\s-]api[_\s-]key/i,
  /authentication failed/i,
  /auth failure/i,
  /you are not logged into/i,
  /login required/i,
  /permission denied/i
];

const PROVIDER_REFUSAL_PATTERNS = [
  /blocked by Gemini(?:'s)? filters/i,
  /safety filters?/i,
  /content policy/i,
  /model refused/i
];

import {
  buildReviewPrompt,
  buildEvidenceReviewPrompt,
  TAXONOMY_CHECKLISTS,
  selectChecklists
} from "./review-prompts.mjs";

export {
  buildReviewPrompt,
  buildEvidenceReviewPrompt,
  TAXONOMY_CHECKLISTS,
  selectChecklists
};

/**
 * Reads a file up to maxBytes with strict bounds to prevent unbounded allocations and stat/read races.
 * @param {string} filePath
 * @param {number} maxBytes
 * @returns {string}
 */
export function readBoundedFile(filePath, maxBytes) {
  let stat;
  try {
    stat = fs.statSync(filePath);
    if (stat.size > maxBytes) {
      throw new Error(`Provider file output exceeded maxOutputBytes (${maxBytes})`);
    }
  } catch (err) {
    if (err.message && err.message.includes("exceeded maxOutputBytes")) throw err;
  }

  let fd;
  try {
    fd = fs.openSync(filePath, "r");
    const buf = Buffer.alloc(maxBytes + 1);
    let totalRead = 0;
    while (totalRead <= maxBytes) {
      const n = fs.readSync(fd, buf, totalRead, maxBytes + 1 - totalRead, null);
      if (n === 0) break;
      totalRead += n;
    }
    if (totalRead > maxBytes) {
      throw new Error(`Provider file output exceeded maxOutputBytes (${maxBytes})`);
    }
    const content = buf.toString("utf8", 0, totalRead);
    if (Buffer.byteLength(content, "utf8") > maxBytes) {
      throw new Error(`Provider file output exceeded maxOutputBytes (${maxBytes})`);
    }
    return content;
  } finally {
    if (fd !== undefined) {
      try { fs.closeSync(fd); } catch {}
    }
  }
}

export class CliReviewAdapter {
  constructor(options = {}) {
    this.command = options.command || "agy";
    const profile = resolveProviderProfile(this.command);
    this.profile = profile;
    this.providerName = options.providerName || profile.id || "cli-reviewer";
    this.modelName = options.modelName || "cli-default";
    this.actualModel = options.actualModel || null;
    this.family = options.family || profile.family;
    this.streamJson = options.streamJson !== undefined
      ? Boolean(options.streamJson)
      : Boolean(profile.streamJson);
    this.inputChannel = options.inputChannel || (this.streamJson ? "stdin" : (profile.inputChannel || "argv"));
    this.supportsStdin = options.supportsStdin !== undefined
      ? Boolean(options.supportsStdin)
      : (this.streamJson ? true : (profile.supportsStdin ?? true));
    this.execFn = typeof options.execFn === "function" ? options.execFn : null;
    this.useStdin = options.useStdin !== undefined ? Boolean(options.useStdin) : null;
    this.env = options.env || null;
    this.cwd = options.cwd || null;
    if (this.streamJson && (profile?.id === "agy" || this.command === "agy")) {
      const streamBaseArgs = ["--input-format=stream-json", "--output-format=stream-json"];
      const mandatory = Array.isArray(profile?.mandatorySafetyArgs)
        ? profile.mandatorySafetyArgs
        : (Array.isArray(profile?.readOnlyFlags) ? profile.readOnlyFlags : ["--mode=plan", "--disable-slash-commands"]);
      const merged = [...mandatory, ...streamBaseArgs];
      this.args = Array.isArray(options.args)
        ? options.args.filter(a => a !== "--print" && !streamBaseArgs.includes(a)).concat(merged)
        : merged;
    } else {
      this.args = assembleProviderArgs(profile, options.args);
    }
    this.maxRetries = options.maxRetries !== undefined
      ? Number(options.maxRetries)
      : (this.family === "google" ? 2 : 0);
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
    const objectiveContract = input.objectiveContract || input.changeSet?.objectiveContract || input.options?.objectiveContract;
    const patchObjective = input.patchObjective || input.changeSet?.patchObjective || input.options?.patchObjective || objectiveContract?.objective;
    const prompt = input.prompt || buildReviewPrompt(input.changeSet, input.role, input.limits, { patchObjective, objectiveContract });
    const context = {
      runId: input.runId,
      role: input.role,
      changeSet: input.changeSet,
      providerName: this.providerName,
      family: this.family,
      modelName: this.modelName,
      transport: "cli",
      patchObjective,
      objectiveContract
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

    // Scrub env if envAllowlist is defined
    let effectiveEnv = this.env || process.env;
    if (this.profile?.envAllowlist && Array.isArray(this.profile.envAllowlist)) {
      const allowedSet = new Set(this.profile.envAllowlist);
      effectiveEnv = {};
      for (const [k, v] of Object.entries(this.env || process.env)) {
        if (allowedSet.has(k)) {
          effectiveEnv[k] = v;
        }
      }
    }

    const transportStart = Date.now();

    // Execute with retry on transient safety filter refusal
    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      const elapsedMs = Date.now() - transportStart;
      if (typeof input.timeoutMs === "number" && input.timeoutMs > 0 && elapsedMs >= input.timeoutMs) {
        return validateProviderOutput({
          executionStatus: EXECUTION_STATUS.TIMEOUT,
          error: `CLI reviewer exceeded timeout budget of ${input.timeoutMs}ms across retries.`
        }, context);
      }

      const remainingMs = (typeof input.timeoutMs === "number" && input.timeoutMs > 0)
        ? Math.max(1, input.timeoutMs - elapsedMs)
        : undefined;
      const attemptInput = (remainingMs !== undefined)
        ? { ...input, timeoutMs: remainingMs }
        : input;

      const result = await this._spawnAttempt(attemptInput, prompt, context, effectiveCwd, effectiveEnv);
      const isRefusal = result.executionStatus === EXECUTION_STATUS.ERROR &&
        PROVIDER_REFUSAL_PATTERNS.some(p => p.test(result.error || ""));
      if (isRefusal && attempt < this.maxRetries && (!input.signal || !input.signal.aborted)) {
        const sleepMs = 1000 * (attempt + 1);
        const timeAfterSleep = (Date.now() - transportStart) + sleepMs;
        if (typeof input.timeoutMs === "number" && input.timeoutMs > 0 && timeAfterSleep >= input.timeoutMs) {
          return validateProviderOutput({
            executionStatus: EXECUTION_STATUS.TIMEOUT,
            error: `Timeout budget exhausted during retry backoff (${input.timeoutMs}ms limit)`
          }, context);
        }

        if (input.signal) {
          await new Promise((resolve) => {
            const timer = setTimeout(resolve, sleepMs);
            input.signal.addEventListener("abort", () => {
              clearTimeout(timer);
              resolve();
            }, { once: true });
          });
          if (input.signal.aborted) {
            return validateProviderOutput({
              executionStatus: EXECUTION_STATUS.CANCELLED,
              error: "Execution cancelled during retry backoff."
            }, context);
          }
        } else {
          await new Promise(r => setTimeout(r, sleepMs));
        }
        continue;
      }
      return result;
    }
  }

  async _spawnAttempt(input, prompt, context, effectiveCwd, effectiveEnv) {
    // Determine temp file for file-based output channels
    let tempOutputFile = null;
    if (this.profile?.outputChannel === "file" && this.profile?.outputFileFlag) {
      tempOutputFile = path.join(
        os.tmpdir(),
        `tf-review-${this.profile.id}-${Date.now()}-${Math.random().toString(36).slice(2)}.json`
      );
    }

    // Use injected execution function if provided (e.g. for mock unit tests)
    if (this.execFn) {
      try {
        const promptBytes = Buffer.byteLength(prompt, "utf8");
        let useStdin = false;
        if (this.useStdin !== null) {
          useStdin = this.useStdin;
        } else if (this.inputChannel === "stdin") {
          useStdin = true;
        } else if (this.supportsStdin && promptBytes > SAFE_ARGV_THRESHOLD_BYTES) {
          useStdin = true;
        }
        const injectedArgs = tempOutputFile
          ? [...this.args, this.profile.outputFileFlag, tempOutputFile, ...(useStdin ? [] : [prompt])]
          : (useStdin ? [...this.args] : [...this.args, prompt]);
        const stdinPayload = (this.streamJson && (this.profile?.id === "agy" || this.command === "agy"))
          ? JSON.stringify({ event: "user", message: { content: prompt } }) + "\n"
          : (useStdin ? prompt : undefined);
        const res = await this.execFn({
          command: this.command,
          args: injectedArgs,
          prompt,
          stdin: stdinPayload,
          input,
          cwd: effectiveCwd,
          env: effectiveEnv,
          outputFile: tempOutputFile
        });
        const processed = this._processResult(res, context, input.limits, tempOutputFile);
        if (tempOutputFile && fs.existsSync(tempOutputFile)) {
          try { fs.unlinkSync(tempOutputFile); } catch {}
        }
        return processed;
      } catch (err) {
        if (tempOutputFile && fs.existsSync(tempOutputFile)) {
          try { fs.unlinkSync(tempOutputFile); } catch {}
        }
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
      let killedError = null;
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

      let childArgs = useStdin ? [...this.args] : [...this.args, prompt];
      if (tempOutputFile) {
        childArgs.push(this.profile.outputFileFlag, tempOutputFile);
      }

      let child;
      try {
        child = spawn(this.command, childArgs, {
          cwd: effectiveCwd,
          shell: false,
          windowsHide: true,
          stdio: [useStdin ? "pipe" : "ignore", "pipe", "pipe"],
          env: effectiveEnv
        });
      } catch (spawnErr) {
        if (tempOutputFile && fs.existsSync(tempOutputFile)) {
          try { fs.unlinkSync(tempOutputFile); } catch {}
        }
        resolve(validateProviderOutput({
          executionStatus: EXECUTION_STATUS.ERROR,
          error: `CLI transport spawn error: ${spawnErr.message}`
        }, context));
        return;
      }

      if (useStdin && child.stdin) {
        child.stdin.on("error", () => {});
        const stdinPayload = (this.streamJson && (this.profile?.id === "agy" || this.command === "agy"))
          ? JSON.stringify({ event: "user", message: { content: prompt } }) + "\n"
          : prompt;
        child.stdin.write(stdinPayload, "utf8", () => {
          child.stdin.end();
        });
      }

      const timer = setTimeout(() => {
        timedOut = true;
        if (!killedReason) {
          killedReason = EXECUTION_STATUS.TIMEOUT;
          killedError = `CLI reviewer timed out after ${input.timeoutMs}ms`;
        }
        child.kill();
      }, input.timeoutMs);

      const abortHandler = () => {
        aborted = true;
        if (!killedReason) {
          killedReason = EXECUTION_STATUS.CANCELLED;
          killedError = `CLI reviewer cancelled via signal`;
        }
        child.kill();
      };

      if (input.signal) {
        input.signal.addEventListener("abort", abortHandler, { once: true });
      }

      child.stdout.on("data", (chunk) => {
        stdout += chunk.toString();
        if (Buffer.byteLength(stdout, "utf8") > input.limits.maxOutputBytes) {
          killedReason = EXECUTION_STATUS.ERROR;
          killedError = `Provider stdout exceeded maxOutputBytes (${input.limits.maxOutputBytes})`;
          child.kill();
        }
      });

      child.stderr.on("data", (chunk) => {
        stderr += chunk.toString();
        if (Buffer.byteLength(stderr, "utf8") > input.limits.maxOutputBytes) {
          killedReason = EXECUTION_STATUS.ERROR;
          killedError = `Provider stderr exceeded maxOutputBytes (${input.limits.maxOutputBytes})`;
          child.kill();
        }
      });

      child.on("error", (err) => {
        clearTimeout(timer);
        if (input.signal) input.signal.removeEventListener("abort", abortHandler);
        if (tempOutputFile && fs.existsSync(tempOutputFile)) {
          try { fs.unlinkSync(tempOutputFile); } catch {}
        }

        resolve(validateProviderOutput({
          executionStatus: EXECUTION_STATUS.ERROR,
          error: `CLI transport spawn error: ${err.message}`
        }, context));
      });

      child.on("close", (code) => {
        clearTimeout(timer);
        if (input.signal) input.signal.removeEventListener("abort", abortHandler);

        // Precedence: Output flood takes absolute precedence over timeout/cancellation
        if (Buffer.byteLength(stdout, "utf8") > input.limits.maxOutputBytes) {
          killedReason = EXECUTION_STATUS.ERROR;
          killedError = `Provider stdout exceeded maxOutputBytes (${input.limits.maxOutputBytes})`;
        } else if (Buffer.byteLength(stderr, "utf8") > input.limits.maxOutputBytes) {
          killedReason = EXECUTION_STATUS.ERROR;
          killedError = `Provider stderr exceeded maxOutputBytes (${input.limits.maxOutputBytes})`;
        }

        let fileOutputContent = null;
        if (tempOutputFile && fs.existsSync(tempOutputFile)) {
          let fileReadError = null;
          try {
            fileOutputContent = readBoundedFile(tempOutputFile, input.limits.maxOutputBytes);
          } catch (err) {
            fileReadError = err;
          } finally {
            try { fs.unlinkSync(tempOutputFile); } catch {}
          }

          if (fileReadError && !killedReason) {
            killedReason = EXECUTION_STATUS.ERROR;
            killedError = fileReadError.message && fileReadError.message.includes("exceeded maxOutputBytes")
              ? fileReadError.message
              : `Failed to read CLI provider output file: ${fileReadError.message}`;
          }
        }

        if (killedReason) {
          resolve(validateProviderOutput({
            executionStatus: killedReason,
            error: killedError || `Process terminated: ${killedReason}`
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

        // 3. Try to extract JSON from fileOutput or stdout
        let outputToParse = fileOutputContent || stdout;
        if (this.streamJson && !fileOutputContent) {
          const streamResult = extractStreamJsonResponse(outputToParse);
          if (streamResult) {
            if (streamResult.result?.status === "SUCCESS" && typeof streamResult.result.response === "string") {
              outputToParse = streamResult.result.response;
            } else if (streamResult.result?.status && streamResult.result.status !== "SUCCESS") {
              resolve(validateProviderOutput({
                executionStatus: EXECUTION_STATUS.ERROR,
                error: `Stream-json result reported non-success status: ${streamResult.result.status}`
              }, context));
              return;
            }
          }
        }
        const parsed = extractJsonFromText(outputToParse);
        if (!parsed) {
          if (AUTH_ERROR_PATTERNS.some(p => p.test(outputToParse))) {
            resolve(validateProviderOutput({
              executionStatus: EXECUTION_STATUS.AUTH_FAILURE,
              error: `Authentication failure detected in CLI reviewer output: ${outputToParse.trim()}`
            }, context));
            return;
          }
          if (PROVIDER_REFUSAL_PATTERNS.some(p => p.test(outputToParse))) {
            resolve(validateProviderOutput({
              executionStatus: EXECUTION_STATUS.ERROR,
              rawOutput: outputToParse.slice(0, 1000),
              error: `Provider safety/content filter refusal detected: ${outputToParse.slice(0, 300).trim()}`
            }, context));
            return;
          }
          resolve(validateProviderOutput({
            executionStatus: EXECUTION_STATUS.MALFORMED_OUTPUT,
            rawOutput: outputToParse.slice(0, 1000),
            error: "Failed to extract valid JSON findings from CLI reviewer output."
          }, context));
          return;
        }

        resolve(validateProviderOutput(parsed, context));
      });
    });
  }

  _processResult(res, context, limits, tempOutputFile) {
    let fileContent = null;
    let fileReadError = null;

    if (res && typeof res.fileOutput === "string") {
      if (Buffer.byteLength(res.fileOutput, "utf8") > limits.maxOutputBytes) {
        return validateProviderOutput({
          executionStatus: EXECUTION_STATUS.ERROR,
          error: `Provider file output exceeded maxOutputBytes (${limits.maxOutputBytes})`
        }, context);
      }
      fileContent = res.fileOutput;
    } else if (tempOutputFile && fs.existsSync(tempOutputFile)) {
      try {
        fileContent = readBoundedFile(tempOutputFile, limits.maxOutputBytes);
      } catch (err) {
        fileReadError = err;
      }
    }

    if (fileReadError) {
      return validateProviderOutput({
        executionStatus: EXECUTION_STATUS.ERROR,
        error: fileReadError.message && fileReadError.message.includes("exceeded maxOutputBytes")
          ? fileReadError.message
          : `Failed to read CLI provider output file: ${fileReadError.message}`
      }, context);
    }

    if (res && typeof res.stdout === "string") {
      if (Buffer.byteLength(res.stdout, "utf8") > limits.maxOutputBytes) {
        return validateProviderOutput({
          executionStatus: EXECUTION_STATUS.ERROR,
          error: `Provider stdout exceeded maxOutputBytes (${limits.maxOutputBytes})`
        }, context);
      }
    }

    if (res?.stderr && Buffer.byteLength(res.stderr, "utf8") > limits.maxOutputBytes) {
      return validateProviderOutput({
        executionStatus: EXECUTION_STATUS.ERROR,
        error: `Provider stderr exceeded maxOutputBytes (${limits.maxOutputBytes})`
      }, context);
    }

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

    let outputToParse = fileContent !== null ? fileContent : (res?.stdout || "");
    if (this.streamJson && fileContent === null) {
      const streamResult = extractStreamJsonResponse(outputToParse);
      if (streamResult) {
        if (streamResult.result?.status === "SUCCESS" && typeof streamResult.result.response === "string") {
          outputToParse = streamResult.result.response;
        } else if (streamResult.result?.status && streamResult.result.status !== "SUCCESS") {
          return validateProviderOutput({
            executionStatus: EXECUTION_STATUS.ERROR,
            error: `Stream-json result reported non-success status: ${streamResult.result.status}`
          }, context);
        }
      }
    }

    if (res?.stderr && AUTH_ERROR_PATTERNS.some(p => p.test(res.stderr))) {
      return validateProviderOutput({
        executionStatus: EXECUTION_STATUS.AUTH_FAILURE,
        error: `Authentication failure detected in CLI reviewer output: ${res.stderr.trim()}`
      }, context);
    }

    const parsed = extractJsonFromText(outputToParse);
    if (!parsed) {
      if (AUTH_ERROR_PATTERNS.some(p => p.test(outputToParse))) {
        return validateProviderOutput({
          executionStatus: EXECUTION_STATUS.AUTH_FAILURE,
          error: `Authentication failure detected in CLI reviewer output: ${outputToParse.trim()}`
        }, context);
      }
      if (PROVIDER_REFUSAL_PATTERNS.some(p => p.test(outputToParse))) {
        return validateProviderOutput({
          executionStatus: EXECUTION_STATUS.ERROR,
          rawOutput: outputToParse.slice(0, 1000),
          error: `Provider safety/content filter refusal detected: ${outputToParse.slice(0, 300).trim()}`
        }, context);
      }
      return validateProviderOutput({
        executionStatus: EXECUTION_STATUS.MALFORMED_OUTPUT,
        error: "Failed to parse JSON from CLI stdout."
      }, context);
    }
    return validateProviderOutput(parsed, context);
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
