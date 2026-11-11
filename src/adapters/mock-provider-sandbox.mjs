/**
 * Deterministic Mock / Offline Provider CLI Test Sandbox (Milestone 2.10 Architecture)
 *
 * Provides a zero-dependency, hermetic, deterministic CLI Provider Sandbox simulating
 * Google agy, Anthropic claude, and OpenAI codex.
 *
 * Core Capabilities:
 * - Subprocess simulation: real OS process execution via spawned shims/dispatchers.
 * - Fault injection: CLEAN_PASS, VULNERABILITY_FOUND, AUTH_FAILURE, TIMEOUT, CRASH,
 *   MALFORMED_OUTPUT, OUTPUT_FLOOD, SAFETY_REFUSAL, and RECORD_AND_REPLAY.
 * - Multi-turn stateful sequences: simulate transient errors (e.g. SAFETY_REFUSAL -> CLEAN_PASS).
 * - Safety & policy verification: verifies mandatory flags (--mode=plan, -p, exec, etc.)
 *   and strictly rejects prohibited flags.
 * - Codex -o <file> handling and agy stream-json NDJSON protocol handling.
 * - Non-tampering append-only audit ledger (ledger.jsonl).
 *
 * Zero external npm runtime dependencies: Native Node.js standard libraries only.
 */

import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { CliReviewAdapter } from "./cli-transport.mjs";
import { PROVIDER_PROFILES, assembleProviderArgs, PROHIBITED_ARGS } from "./provider-profiles.mjs";
import { EXECUTION_STATUS } from "./provider-contract.mjs";

export const MOCK_SCENARIOS = Object.freeze({
  CLEAN_PASS: "clean_pass",
  VULNERABILITY_FOUND: "vulnerability_found",
  AUTH_FAILURE: "auth_failure",
  TIMEOUT: "timeout",
  CRASH: "crash",
  MALFORMED_OUTPUT: "malformed_output",
  OUTPUT_FLOOD: "output_flood",
  SAFETY_REFUSAL: "safety_refusal",
  RECORD_AND_REPLAY: "record_and_replay",
  CUSTOM_PAYLOAD: "custom_payload"
});

export const SUPPORTED_MOCK_PROVIDERS = Object.freeze(["agy", "claude", "codex"]);

export const PROVIDER_AUTH_ERROR_MESSAGES = Object.freeze({
  agy: "Error: You are not logged into Antigravity. Please run agy auth login.\n",
  claude: "Authentication failed: 401 Unauthorized client token\n",
  codex: "Error: 401 Unauthorized - invalid_api_key\n"
});

export const PROVIDER_MOCK_VERSIONS = Object.freeze({
  agy: "1.2.0-mock",
  claude: "2.1.0-mock",
  codex: "1.0.0-mock"
});

export const DEFAULT_MOCK_FINDINGS = Object.freeze([
  {
    title: "SQL Injection in User Authentication Query",
    severity: "critical",
    file: "src/auth.js",
    line_start: 42,
    line_end: 45,
    cwe: "CWE-89",
    recommendation: "Use parameterized queries or prepared statements instead of string concatenation."
  }
]);

/**
 * Extracts target file paths from prompt text to populate coveredFiles.
 * @param {string} promptText
 * @returns {string[]}
 */
export function extractFilesFromPrompt(promptText = "") {
  if (!promptText || typeof promptText !== "string") return ["src/index.js"];
  const matches = new Set();
  const lines = promptText.split(/\r?\n/);
  for (const line of lines) {
    const listMatch = line.match(/^\s*-\s+([^\s(:]+\.[a-zA-Z0-9_]+)/);
    if (listMatch && listMatch[1]) {
      matches.add(listMatch[1].trim());
      continue;
    }
    const diffMatch = line.match(/^(?:---|\+\+\+)\s+[ab]\/([^\s]+)/);
    if (diffMatch && diffMatch[1]) {
      matches.add(diffMatch[1].trim());
      continue;
    }
    const fileColonMatch = line.match(/(?:File|Target|Path):\s*`?([^\s`()]+\.[a-zA-Z0-9_]+)`?/i);
    if (fileColonMatch && fileColonMatch[1]) {
      matches.add(fileColonMatch[1].trim());
    }
  }
  return matches.size > 0 ? Array.from(matches) : ["src/index.js"];
}

/**
 * Generates the source code for the standalone mock-provider-dispatcher.mjs script.
 * @returns {string}
 */
export function generateDispatcherSource() {
  return `/**
 * Standalone Mock Provider Dispatcher
 * Dispatched by spawned child processes simulating CLI reviewer binaries.
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const rawArgs = process.argv.slice(2);
const providerName = rawArgs[0] || "agy";
const cliArgs = rawArgs.slice(1);
const fullText = cliArgs.join(" ");

const STATE_FILE = process.env.TRIAD_MOCK_STATE_FILE || path.join(path.dirname(process.argv[1]), "state.json");
const LEDGER_FILE = process.env.TRIAD_MOCK_LEDGER_FILE || path.join(path.dirname(process.argv[1]), "ledger.jsonl");

function readState() {
  try {
    if (fs.existsSync(STATE_FILE)) {
      return JSON.parse(fs.readFileSync(STATE_FILE, "utf8"));
    }
  } catch {}
  return { providers: {} };
}

function writeState(state) {
  try {
    fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2), "utf8");
  } catch {}
}

function appendLedger(entry) {
  try {
    const line = JSON.stringify({
      timestamp: new Date().toISOString(),
      ...entry
    }) + "\\n";
    fs.appendFileSync(LEDGER_FILE, line, "utf8");
  } catch {}
}

function extractFilesFromPromptText(text) {
  const matches = new Set();
  const lines = (text || "").split(/\\r?\\n/);
  for (const line of lines) {
    const listMatch = line.match(/^\\s*-\\s+([^\\s(:]+\\.[a-zA-Z0-9_]+)/);
    if (listMatch && listMatch[1]) {
      matches.add(listMatch[1].trim());
      continue;
    }
    const diffMatch = line.match(/^(?:---|\\+\\+\\+)\\s+[ab]\\/([^\\s]+)/);
    if (diffMatch && diffMatch[1]) {
      matches.add(diffMatch[1].trim());
      continue;
    }
    const fileColonMatch = line.match(/(?:File|Target|Path):\\s*\`?([^\\s\`()]+\\.[a-zA-Z0-9_]+)\`?/i);
    if (fileColonMatch && fileColonMatch[1]) {
      matches.add(fileColonMatch[1].trim());
    }
  }
  return matches.size > 0 ? Array.from(matches) : ["src/index.js"];
}

async function main() {
  // 1. Handle --version probe
  if (cliArgs.includes("--version") || cliArgs.includes("-v")) {
    const versions = {
      agy: "1.2.0-mock",
      claude: "2.1.0-mock",
      codex: "1.0.0-mock"
    };
    const v = versions[providerName] || "1.0.0-mock";
    process.stdout.write(\`\${providerName} \${v}\\n\`);
    appendLedger({ provider: providerName, argv: cliArgs, scenario: "version", exitCode: 0 });
    process.exit(0);
  }

  // 2. Read state & determine scenario
  const state = readState();
  const providerConf = state.providers?.[providerName] || {};
  let scenario = providerConf.scenario || state.defaultScenario || "clean_pass";

  // Check sequence queue
  if (Array.isArray(providerConf.sequence) && providerConf.sequence.length > 0) {
    scenario = providerConf.sequence.shift();
    writeState(state);
  }

  // 3. Early fault injection: timeout, crash, auth_failure
  if (scenario === "timeout") {
    appendLedger({ provider: providerName, argv: cliArgs, scenario: "timeout" });
    process.stderr.write(\`[mock-\${providerName}] Hanging process intentionally for timeout test...\\n\`);
    setInterval(() => {}, 60000);
    return;
  }

  if (scenario === "crash") {
    appendLedger({ provider: providerName, argv: cliArgs, scenario: "crash", exitCode: 137 });
    process.stderr.write(\`[mock-\${providerName}] Fatal error: unhandled exception in LLM backend\\n\`);
    process.exit(137);
  }

  if (scenario === "auth_failure") {
    const authMsgs = {
      agy: "Error: You are not logged into Antigravity. Please run agy auth login.\\n",
      claude: "Authentication failed: 401 Unauthorized client token\\n",
      codex: "Error: 401 Unauthorized - invalid_api_key\\n"
    };
    const msg = authMsgs[providerName] || "Authentication failure: invalid token\\n";
    process.stderr.write(msg);
    appendLedger({ provider: providerName, argv: cliArgs, scenario: "auth_failure", exitCode: 1 });
    process.exit(1);
  }

  // 4. Check prohibited flags
  const prohibited = ["--dangerously-bypass-approvals-and-sandbox", "--approve-for-me", "apply"];
  for (const p of prohibited) {
    if (cliArgs.includes(p)) {
      process.stderr.write(\`[mock-error] Prohibited argument detected: \${p}\\n\`);
      appendLedger({ provider: providerName, argv: cliArgs, scenario: "prohibited_flag_rejected", exitCode: 2 });
      process.exit(2);
    }
  }

  // 5. Verify mandatory safety arguments if strict
  if (state.strictSafetyArgs !== false) {
    if (providerName === "agy") {
      const isStream = cliArgs.includes("--input-format=stream-json") || cliArgs.includes("--output-format=stream-json");
      const hasPlan = cliArgs.some(a => a === "--mode=plan" || a.startsWith("--mode=plan"));
      const hasNoSlash = cliArgs.includes("--disable-slash-commands");
      const hasPrint = cliArgs.includes("--print") || isStream;
      if (!hasPlan || !hasNoSlash || !hasPrint) {
        process.stderr.write("[mock-error] Missing mandatory safety arguments for agy (--mode=plan, --disable-slash-commands, --print)\\n");
        appendLedger({ provider: providerName, argv: cliArgs, scenario: "mandatory_args_missing", exitCode: 2 });
        process.exit(2);
      }
    } else if (providerName === "claude") {
      const hasP = cliArgs.includes("-p");
      const hasTools = cliArgs.some(a => a === "--tools=" || a.startsWith("--tools="));
      if (!hasP || !hasTools) {
        process.stderr.write("[mock-error] Missing mandatory safety arguments for claude (-p, --tools=)\\n");
        appendLedger({ provider: providerName, argv: cliArgs, scenario: "mandatory_args_missing", exitCode: 2 });
        process.exit(2);
      }
    } else if (providerName === "codex") {
      const hasExec = cliArgs.includes("exec");
      const hasSandbox = cliArgs.some(a => a === "--sandbox=read-only" || a.startsWith("--sandbox="));
      if (!hasExec || !hasSandbox) {
        process.stderr.write("[mock-error] Missing mandatory safety arguments for codex (exec, --sandbox=read-only)\\n");
        appendLedger({ provider: providerName, argv: cliArgs, scenario: "mandatory_args_missing", exitCode: 2 });
        process.exit(2);
      }
    }
  }

  // 6. Read stdin if piped
  let stdinContent = "";
  if (!process.stdin.isTTY) {
    const chunks = [];
    for await (const chunk of process.stdin) {
      chunks.push(chunk);
    }
    stdinContent = Buffer.concat(chunks).toString("utf8");
  }

  // 7. Check for output file flag (-o <file>)
  let outputFile = null;
  const oIdx = cliArgs.indexOf("-o");
  if (oIdx !== -1 && oIdx + 1 < cliArgs.length) {
    outputFile = cliArgs[oIdx + 1];
  }

  // Determine target files
  const combinedText = fullText + "\\n" + stdinContent;
  const targetFiles = extractFilesFromPromptText(combinedText);

  // 8. Execute remaining scenarios
  switch (scenario) {
    case "malformed_output": {
      const malformed = "I cannot evaluate this change. { broken json: [1, 2, ";
      if (outputFile) {
        fs.writeFileSync(outputFile, malformed, "utf8");
      } else {
        process.stdout.write(malformed + "\\n");
      }
      appendLedger({ provider: providerName, argv: cliArgs, scenario: "malformed_output", exitCode: 0 });
      process.exit(0);
      break;
    }

    case "output_flood": {
      process.stderr.write(\`[mock-\${providerName}] Flooding output buffer beyond limits...\\n\`);
      process.stdout.on("error", () => {});
      const chunk = "X".repeat(64 * 1024);
      for (let i = 0; i < 32; i++) {
        process.stdout.write(chunk);
      }
      appendLedger({ provider: providerName, argv: cliArgs, scenario: "output_flood", exitCode: 0 });
      break;
    }

    case "safety_refusal": {
      const refusal = "This request was blocked by Gemini's filters. They can occasionally trigger by mistake on safe coding.";
      if (outputFile) {
        fs.writeFileSync(outputFile, refusal, "utf8");
      } else {
        process.stdout.write(refusal + "\\n");
      }
      appendLedger({ provider: providerName, argv: cliArgs, scenario: "safety_refusal", exitCode: 0 });
      process.exit(0);
      break;
    }

    case "vulnerability_found": {
      const payload = providerConf.customPayload || {
        findings: [
          {
            title: "SQL Injection in User Authentication Query",
            severity: "critical",
            file: targetFiles[0] || "src/auth.js",
            line_start: 42,
            line_end: 45,
            cwe: "CWE-89",
            recommendation: "Use parameterized queries or prepared statements instead of string concatenation."
          }
        ],
        coverage: {
          coveredFiles: targetFiles,
          omittedFiles: []
        }
      };

      emitPayload(payload, outputFile, cliArgs, providerName);
      appendLedger({ provider: providerName, argv: cliArgs, scenario: "vulnerability_found", exitCode: 0 });
      process.exit(0);
      break;
    }

    case "custom_payload": {
      const payload = providerConf.customPayload || { findings: [], coverage: { coveredFiles: targetFiles, omittedFiles: [] } };
      emitPayload(payload, outputFile, cliArgs, providerName);
      appendLedger({ provider: providerName, argv: cliArgs, scenario: "custom_payload", exitCode: 0 });
      process.exit(0);
      break;
    }

    case "clean_pass":
    default: {
      const payload = {
        findings: [],
        coverage: {
          coveredFiles: targetFiles,
          omittedFiles: []
        }
      };

      emitPayload(payload, outputFile, cliArgs, providerName);
      appendLedger({ provider: providerName, argv: cliArgs, scenario: "clean_pass", exitCode: 0 });
      process.exit(0);
      break;
    }
  }
}

function emitPayload(payload, outputFile, cliArgs, providerName) {
  const jsonStr = typeof payload === "string" ? payload : JSON.stringify(payload, null, 2);

  if (outputFile) {
    fs.writeFileSync(outputFile, jsonStr, "utf8");
    return;
  }

  // Check for agy stream-json format
  if (providerName === "agy" && (cliArgs.includes("--output-format=stream-json") || cliArgs.includes("--stream-json"))) {
    const streamLine = JSON.stringify({
      event: "result",
      status: "SUCCESS",
      response: jsonStr
    }) + "\\n";
    process.stdout.write(streamLine);
    return;
  }

  process.stdout.write(jsonStr + "\\n");
}

main().catch(err => {
  process.stderr.write("[mock-fatal] " + (err?.stack || String(err)) + "\\n");
  process.exit(1);
});
`;
}

/**
 * Deterministic Mock Provider Sandbox Manager
 */
export class MockProviderSandbox {
  /**
   * @param {object} [options={}]
   * @param {string} [options.baseDir] - Custom temp directory
   * @param {string[]} [options.providers] - List of providers to initialize (default: agy, claude, codex)
   * @param {string} [options.defaultScenario] - Default scenario for all providers (default: clean_pass)
   * @param {boolean} [options.strictSafetyArgs=true] - Whether to strictly verify mandatory safety arguments
   */
  constructor(options = {}) {
    this.options = options;
    this.providers = options.providers || [...SUPPORTED_MOCK_PROVIDERS];
    this.defaultScenario = options.defaultScenario || MOCK_SCENARIOS.CLEAN_PASS;
    this.strictSafetyArgs = options.strictSafetyArgs !== false;

    this.sandboxDir = options.baseDir || fs.mkdtempSync(path.join(os.tmpdir(), "tf-mock-provider-sandbox-"));
    this.binDir = path.join(this.sandboxDir, "bin");
    this.stateFile = path.join(this.sandboxDir, "state.json");
    this.ledgerFile = path.join(this.sandboxDir, "ledger.jsonl");
    this.dispatcherScript = path.join(this.sandboxDir, "mock-provider-dispatcher.mjs");

    this._origPath = null;
    this._initialized = false;
  }

  /**
   * Initializes sandbox filesystem, scripts, state, and shims.
   * @returns {this}
   */
  init() {
    if (this._initialized) return this;

    if (!fs.existsSync(this.binDir)) {
      fs.mkdirSync(this.binDir, { recursive: true });
    }

    // Write initial state
    const initialState = {
      defaultScenario: this.defaultScenario,
      strictSafetyArgs: this.strictSafetyArgs,
      providers: {}
    };
    for (const p of this.providers) {
      initialState.providers[p] = {
        scenario: this.defaultScenario,
        sequence: [],
        customPayload: null
      };
    }
    fs.writeFileSync(this.stateFile, JSON.stringify(initialState, null, 2), "utf8");

    // Write empty ledger
    fs.writeFileSync(this.ledgerFile, "", "utf8");

    // Write dispatcher script
    fs.writeFileSync(this.dispatcherScript, generateDispatcherSource(), "utf8");

    // Create provider shims in binDir
    this._createShims();

    this._initialized = true;
    return this;
  }

  _createShims() {
    const isWindows = process.platform === "win32";

    for (const p of this.providers) {
      // 1. POSIX shell script shim
      const shScriptPath = path.join(this.binDir, p);
      const shContent = `#!/usr/bin/env bash\nexec "${process.execPath}" "${this.dispatcherScript}" "${p}" "$@"\n`;
      fs.writeFileSync(shScriptPath, shContent, { mode: 0o755 });

      // 2. Windows batch script shim (.cmd)
      const cmdScriptPath = path.join(this.binDir, `${p}.cmd`);
      const cmdContent = `@echo off\r\n"${process.execPath}" "${this.dispatcherScript}" ${p} %*\r\n`;
      fs.writeFileSync(cmdScriptPath, cmdContent, "utf8");

      // 3. Node script entry (.js) for resolveNativeWindowsBinary fallback
      const jsScriptPath = path.join(this.binDir, `${p}.js`);
      const jsContent = `import "${path.resolve(this.dispatcherScript).replace(/\\/g, "/")}";\n`;
      fs.writeFileSync(jsScriptPath, jsContent, "utf8");
    }
  }

  /**
   * Updates the active scenario for a provider.
   * @param {string} provider
   * @param {string} scenario
   * @param {object} [options={}]
   */
  setScenario(provider, scenario, options = {}) {
    const state = this.getState();
    if (!state.providers[provider]) {
      state.providers[provider] = { scenario: this.defaultScenario, sequence: [], customPayload: null };
    }
    state.providers[provider].scenario = scenario;
    if (options.customPayload !== undefined) {
      state.providers[provider].customPayload = options.customPayload;
    }
    this.saveState(state);
  }

  /**
   * Configures a sequential list of scenarios for consecutive invocations.
   * @param {string} provider
   * @param {string[]} scenarios
   */
  setSequence(provider, scenarios = []) {
    const state = this.getState();
    if (!state.providers[provider]) {
      state.providers[provider] = { scenario: this.defaultScenario, sequence: [], customPayload: null };
    }
    state.providers[provider].sequence = [...scenarios];
    this.saveState(state);
  }

  /**
   * Sets custom findings or coverage payload for a provider.
   * @param {string} provider
   * @param {object|string} payload
   */
  setCustomPayload(provider, payload) {
    const state = this.getState();
    if (!state.providers[provider]) {
      state.providers[provider] = { scenario: this.defaultScenario, sequence: [], customPayload: null };
    }
    state.providers[provider].customPayload = payload;
    this.saveState(state);
  }

  /**
   * Reads current sandbox state.
   * @returns {object}
   */
  getState() {
    try {
      if (fs.existsSync(this.stateFile)) {
        return JSON.parse(fs.readFileSync(this.stateFile, "utf8"));
      }
    } catch {}
    return { defaultScenario: this.defaultScenario, providers: {} };
  }

  /**
   * Persists sandbox state.
   * @param {object} state
   */
  saveState(state) {
    fs.writeFileSync(this.stateFile, JSON.stringify(state, null, 2), "utf8");
  }

  /**
   * Returns parsed invocation ledger entries.
   * @param {string} [provider] - Optional filter by provider name
   * @returns {object[]}
   */
  getInvocations(provider = null) {
    if (!fs.existsSync(this.ledgerFile)) return [];
    try {
      const content = fs.readFileSync(this.ledgerFile, "utf8");
      const lines = content.split(/\r?\n/).filter(Boolean);
      const entries = lines.map(line => {
        try {
          return JSON.parse(line);
        } catch {
          return null;
        }
      }).filter(Boolean);

      if (provider) {
        return entries.filter(e => e.provider === provider);
      }
      return entries;
    } catch {
      return [];
    }
  }

  /**
   * Clears the invocation ledger.
   */
  clearLedger() {
    try {
      fs.writeFileSync(this.ledgerFile, "", "utf8");
    } catch {}
  }

  /**
   * Returns executable command info for child_process invocation without relying on PATH.
   * @param {string} provider
   * @returns {{ command: string, prefixArgs: string[] }}
   */
  getProviderCommand(provider = "agy") {
    return {
      command: process.execPath,
      prefixArgs: [this.dispatcherScript, provider]
    };
  }

  /**
   * Creates a CliReviewAdapter instance configured to execute in this sandbox.
   * @param {string} provider - Provider name ('agy', 'claude', 'codex')
   * @param {object} [adapterOptions={}] - Additional adapter options
   * @returns {CliReviewAdapter}
   */
  createAdapter(provider = "agy", adapterOptions = {}) {
    const cmd = this.getProviderCommand(provider);
    const env = {
      ...(adapterOptions.env || process.env),
      TRIAD_MOCK_STATE_FILE: this.stateFile,
      TRIAD_MOCK_LEDGER_FILE: this.ledgerFile
    };

    return new CliReviewAdapter({
      command: provider,
      spawnCommand: cmd.command,
      prefixArgs: cmd.prefixArgs,
      ...adapterOptions,
      env,
      providerName: adapterOptions.providerName || provider
    });
  }

  /**
   * Creates an in-memory execution function matching CliReviewAdapter execFn.
   * @param {string} provider
   * @returns {Function}
   */
  createExecFn(provider = "agy") {
    return async ({ command, args, prompt, stdin, outputFile }) => {
      const state = this.getState();
      const providerConf = state.providers?.[provider] || {};
      let scenario = providerConf.scenario || state.defaultScenario || MOCK_SCENARIOS.CLEAN_PASS;

      if (Array.isArray(providerConf.sequence) && providerConf.sequence.length > 0) {
        scenario = providerConf.sequence.shift();
        this.saveState(state);
      }

      const combinedText = (args ? args.join(" ") : "") + "\n" + (prompt || "") + "\n" + (stdin || "");
      const targetFiles = extractFilesFromPrompt(combinedText);

      switch (scenario) {
        case MOCK_SCENARIOS.TIMEOUT:
          return {
            executionStatus: EXECUTION_STATUS.TIMEOUT,
            error: "Process timed out in mock sandbox"
          };
        case MOCK_SCENARIOS.CRASH:
          return {
            status: 137,
            code: 137,
            stdout: "",
            stderr: `[mock-${provider}] Fatal error: unhandled exception in LLM backend`
          };
        case MOCK_SCENARIOS.AUTH_FAILURE:
          return {
            status: 1,
            code: 1,
            stdout: "",
            stderr: PROVIDER_AUTH_ERROR_MESSAGES[provider] || "Authentication failure"
          };
        case MOCK_SCENARIOS.MALFORMED_OUTPUT:
          return {
            status: 0,
            stdout: "I cannot evaluate this change. { broken json: [1, 2, ",
            stderr: ""
          };
        case MOCK_SCENARIOS.OUTPUT_FLOOD:
          return {
            status: 0,
            stdout: "X".repeat(2 * 1024 * 1024),
            stderr: ""
          };
        case MOCK_SCENARIOS.SAFETY_REFUSAL:
          return {
            status: 0,
            stdout: "This request was blocked by Gemini's filters. They can occasionally trigger by mistake on safe coding.",
            stderr: ""
          };
        case MOCK_SCENARIOS.VULNERABILITY_FOUND: {
          const payload = providerConf.customPayload || {
            findings: [
              {
                title: "SQL Injection in User Authentication Query",
                severity: "critical",
                file: targetFiles[0] || "src/auth.js",
                line_start: 42,
                line_end: 45,
                cwe: "CWE-89",
                recommendation: "Use parameterized queries or prepared statements instead of string concatenation."
              }
            ],
            coverage: { coveredFiles: targetFiles, omittedFiles: [] }
          };
          if (outputFile) {
            fs.writeFileSync(outputFile, JSON.stringify(payload, null, 2), "utf8");
            return { status: 0, stdout: "", stderr: "" };
          }
          return { status: 0, stdout: JSON.stringify(payload), stderr: "" };
        }
        case MOCK_SCENARIOS.CUSTOM_PAYLOAD: {
          const payload = providerConf.customPayload || { findings: [], coverage: { coveredFiles: targetFiles, omittedFiles: [] } };
          if (outputFile) {
            fs.writeFileSync(outputFile, JSON.stringify(payload, null, 2), "utf8");
            return { status: 0, stdout: "", stderr: "" };
          }
          return { status: 0, stdout: JSON.stringify(payload), stderr: "" };
        }
        case MOCK_SCENARIOS.CLEAN_PASS:
        default: {
          const payload = { findings: [], coverage: { coveredFiles: targetFiles, omittedFiles: [] } };
          if (outputFile) {
            fs.writeFileSync(outputFile, JSON.stringify(payload, null, 2), "utf8");
            return { status: 0, stdout: "", stderr: "" };
          }
          return { status: 0, stdout: JSON.stringify(payload), stderr: "" };
        }
      }
    };
  }

  /**
   * Temporarily activates the sandbox in process.env.PATH.
   * @returns {Function} restore function
   */
  activateEnvironment() {
    this._origPath = process.env.PATH;
    process.env.PATH = this.binDir + path.delimiter + (this._origPath || "");
    process.env.TRIAD_MOCK_STATE_FILE = this.stateFile;
    process.env.TRIAD_MOCK_LEDGER_FILE = this.ledgerFile;

    return () => {
      this.deactivateEnvironment();
    };
  }

  /**
   * Restores original process.env.PATH.
   */
  deactivateEnvironment() {
    if (this._origPath !== null) {
      process.env.PATH = this._origPath;
      this._origPath = null;
    }
    delete process.env.TRIAD_MOCK_STATE_FILE;
    delete process.env.TRIAD_MOCK_LEDGER_FILE;
  }

  /**
   * Destroys sandbox directory and restores environment.
   */
  cleanup() {
    this.deactivateEnvironment();
    if (fs.existsSync(this.sandboxDir)) {
      try {
        fs.rmSync(this.sandboxDir, { recursive: true, force: true });
      } catch {}
    }
  }
}

/**
 * Creates and initializes a new mock provider sandbox.
 * @param {object} [options={}]
 * @returns {MockProviderSandbox}
 */
export function createMockProviderSandbox(options = {}) {
  const sandbox = new MockProviderSandbox(options);
  return sandbox.init();
}
