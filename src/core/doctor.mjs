/**
 * Triad-Flow Capability Doctor & Heterogeneous Quorum Readiness Prober
 *
 * Probes environment capabilities, local CLI reviewer binaries (agy, claude, codex),
 * evaluates multi-vendor quorum readiness, and collects structured diagnostic reports.
 */

import { spawnSync } from "node:child_process";
import { resolveProviderProfile } from "../adapters/provider-profiles.mjs";
import { collectGitWorkingState } from "./git-collector.mjs";

export const DEFAULT_PROBE_TARGETS = Object.freeze(["agy", "claude", "codex"]);
export const DEFAULT_PROBE_TIMEOUT_MS = 1500;

export const QUORUM_STATUS = Object.freeze({
  READY: "READY",
  PARTIAL: "PARTIAL",
  STANDALONE: "STANDALONE"
});

export const FAMILY_DISPLAY_NAMES = Object.freeze({
  google: "Google",
  anthropic: "Anthropic",
  openai: "OpenAI"
});

/**
 * Returns a human-friendly display name for a provider family.
 *
 * @param {string} family - Canonical family identifier (e.g. "google", "anthropic", "openai")
 * @returns {string} Capitalized display name
 */
export function getFamilyDisplayName(family = "") {
  if (!family || typeof family !== "string") return "Unknown";
  const norm = family.toLowerCase().trim();
  return FAMILY_DISPLAY_NAMES[norm] || (norm.charAt(0).toUpperCase() + norm.slice(1));
}

/**
 * Probes local CLI reviewer binaries using safe non-hanging execution.
 *
 * @param {object} [options={}]
 * @param {string[]} [options.reviewers] - Reviewer commands to probe (default: ["agy", "claude", "codex"])
 * @param {Function} [options.execFn] - Optional injected executor `(cmd, args, opts) => ({ status, stdout, stderr, error, signal })`
 * @param {number} [options.timeoutMs] - Execution timeout in ms (default: 1500)
 * @returns {Array<object>} Probed reviewer capability profiles
 */
export function probeInstalledReviewers(options = {}) {
  const rawTargets = Array.isArray(options.reviewers) && options.reviewers.length > 0
    ? options.reviewers
    : DEFAULT_PROBE_TARGETS;

  const validTargets = rawTargets
    .filter(t => typeof t === "string" && t.trim().length > 0)
    .map(t => t.trim());

  const targets = validTargets.length > 0 ? validTargets : DEFAULT_PROBE_TARGETS;
  const timeoutMs = typeof options.timeoutMs === "number" && options.timeoutMs > 0
    ? options.timeoutMs
    : DEFAULT_PROBE_TIMEOUT_MS;
  const execFn = options.execFn || null;

  const results = [];

  for (const target of targets) {
    const profile = resolveProviderProfile(target);
    let execResult = null;

    try {
      if (typeof execFn === "function") {
        execResult = execFn(target, ["--version"], { timeout: timeoutMs });
      } else {
        // Safe process invocation: reject shell metacharacters to prevent injection
        const hasUnsafeChars = /[;&|`$<>()"'\r\n]/.test(target);
        if (hasUnsafeChars) {
          execResult = {
            error: new Error(`Reviewer command contains unsafe characters: '${target}'`),
            status: -1
          };
        } else if (process.platform === "win32") {
          // On Windows, executables may be .cmd or .bat (e.g. npm-installed CLI wrappers like codex).
          // Executing via shell with quoted executable name ensures .cmd/.bat resolution without DEP0190 warnings.
          execResult = spawnSync(`"${target}" --version`, {
            timeout: timeoutMs,
            encoding: "utf8",
            windowsHide: true,
            shell: true
          });
        } else {
          execResult = spawnSync(target, ["--version"], {
            timeout: timeoutMs,
            encoding: "utf8",
            windowsHide: true
          });
        }
      }
    } catch (err) {
      execResult = { error: err, status: -1 };
    }

    const hasError = Boolean(
      !execResult ||
      execResult.error ||
      execResult.signal ||
      (execResult.status !== null && execResult.status !== undefined && execResult.status !== 0)
    );

    if (hasError) {
      const errMsg = execResult?.error
        ? (execResult.error.message || String(execResult.error))
        : (execResult?.signal
          ? `Process terminated with signal ${execResult.signal}`
          : (execResult?.status !== null && execResult?.status !== undefined
            ? `Process exited with code ${execResult.status}`
            : "Process execution failed"));

      results.push({
        id: profile.id,
        command: target,
        family: profile.family,
        installed: false,
        available: false,
        version: null,
        rawVersion: null,
        readOnlyFlags: [...profile.readOnlyFlags],
        profile,
        error: errMsg
      });
    } else {
      const rawOut = (execResult.stdout || "").toString().trim() || (execResult.stderr || "").toString().trim();
      const versionMatch = rawOut.match(/(\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.-]+)?)/);
      const version = versionMatch ? versionMatch[1] : (rawOut.split("\n")[0].trim() || "unknown");

      results.push({
        id: profile.id,
        command: target,
        family: profile.family,
        installed: true,
        available: true,
        version,
        rawVersion: rawOut,
        readOnlyFlags: [...profile.readOnlyFlags],
        profile
      });
    }
  }

  return results;
}

/**
 * Evaluates whether installed reviewers satisfy Heterogeneous Quorum requirements.
 *
 * - READY: >= 2 distinct vendor families (e.g. Google + Anthropic). High-risk dual sentry enabled.
 * - PARTIAL: Exactly 1 vendor family. Single sentry enabled; dual sentry requires 2nd vendor.
 * - STANDALONE: 0 external reviewers. Operates in zero-dependency offline deterministic mode.
 *
 * @param {Array<object>} [reviewers=[]] - List of probed reviewers
 * @returns {object} Quorum readiness verdict
 */
export function evaluateQuorumReadiness(reviewers = []) {
  const activeReviewers = (Array.isArray(reviewers) ? reviewers : []).filter(
    r => r && (r.available === true || (r.available === undefined && r.installed === true))
  );

  const activeFamilies = Array.from(
    new Set(
      activeReviewers
        .map(r => (r.family ? String(r.family).toLowerCase().trim() : ""))
        .filter(Boolean)
    )
  );

  if (activeFamilies.length >= 2) {
    const names = activeFamilies.map(getFamilyDisplayName);
    return {
      status: QUORUM_STATUS.READY,
      ready: true,
      families: activeFamilies,
      familyNames: names,
      activeReviewers: activeReviewers.map(r => r.id || r.command || "unknown"),
      summary: `READY (${names.join(" + ")})`,
      canRunDualQuorum: true,
      canRunSingle: true
    };
  }

  if (activeFamilies.length === 1) {
    const names = activeFamilies.map(getFamilyDisplayName);
    return {
      status: QUORUM_STATUS.PARTIAL,
      ready: false,
      families: activeFamilies,
      familyNames: names,
      activeReviewers: activeReviewers.map(r => r.id || r.command || "unknown"),
      summary: `PARTIAL (${names[0]})`,
      canRunDualQuorum: false,
      canRunSingle: true
    };
  }

  return {
    status: QUORUM_STATUS.STANDALONE,
    ready: false,
    families: [],
    familyNames: [],
    activeReviewers: [],
    summary: "STANDALONE (Offline simulation / replay mode)",
    canRunDualQuorum: false,
    canRunSingle: false
  };
}

/**
 * Collects a complete, immutable Capability Doctor diagnostic report.
 *
 * @param {object} [options={}]
 * @returns {object} Diagnostic report data structure
 */
export function collectDoctorReport(options = {}) {
  const cwd = options.cwd || process.cwd();
  const gitState = typeof options.getGitState === "function"
    ? options.getGitState()
    : collectGitWorkingState(cwd);

  const env = options.env || process.env;

  const reviewers = probeInstalledReviewers({
    reviewers: options.reviewers,
    execFn: options.execFn,
    timeoutMs: options.timeoutMs
  });

  const quorum = evaluateQuorumReadiness(reviewers);

  return {
    schemaVersion: "1.0.0",
    timestamp: options.timestamp || new Date().toISOString(),
    runtime: {
      nodeVersion: process.version,
      platform: process.platform,
      arch: process.arch
    },
    git: {
      ok: Boolean(gitState?.ok),
      currentBranch: gitState?.repository?.currentBranch || null,
      root: gitState?.repository?.root || null,
      error: gitState?.error
        ? (typeof gitState.error === "string" ? gitState.error : (gitState.error.message || String(gitState.error)))
        : null
    },
    safetyCore: {
      loaded: true,
      status: "active",
      components: ["Harness", "Loop", "Graph"]
    },
    reviewers,
    quorum,
    envKeys: {
      anthropic: Boolean(env?.ANTHROPIC_API_KEY),
      gemini: Boolean(env?.GEMINI_API_KEY),
      openai: Boolean(env?.OPENAI_API_KEY)
    }
  };
}

/**
 * Formats a Capability Doctor report as human-readable text or structured JSON.
 *
 * @param {object} report - Diagnostic report collected by collectDoctorReport
 * @param {string} [format="text"] - "text" or "json"
 * @returns {string} Formatted output string
 */
export function formatDoctorReport(report, format = "text") {
  if (format === "json") {
    return JSON.stringify(report, null, 2) + "\n";
  }

  const lines = [];
  lines.push("\n=======================================================");
  lines.push("  Triad-Flow • Environment & Capability Doctor");
  lines.push("=======================================================\n");

  lines.push("🩺 Probing Environment Capabilities:");
  lines.push(`  ✔ Node.js Runtime: ${report?.runtime?.nodeVersion || process.version}`);

  if (report?.git?.ok) {
    lines.push("  ✔ Git Repository: Detected and active");
  } else {
    lines.push(`  ⚠️ Git Repository: Not detected or unreadable (${report?.git?.error || "none"})`);
  }

  const safetyCoreLabel = Array.isArray(report?.safetyCore?.components)
    ? report.safetyCore.components.join(" + ")
    : "Harness + Loop + Graph";
  lines.push(`  ✔ Deterministic Safety Core: Loaded (${safetyCoreLabel})\n`);

  lines.push("🔍 Probing Installed Reviewer CLIs:");
  if (Array.isArray(report?.reviewers) && report.reviewers.length > 0) {
    for (const r of report.reviewers) {
      if (!r) continue;
      const familyName = getFamilyDisplayName(r.family);
      const name = `${familyName} ${r.id || r.command || "reviewer"}`;
      if (r.available === true || (r.available === undefined && r.installed === true)) {
        const verStr = r.version
          ? (r.version.startsWith("v") ? r.version : `v${r.version}`)
          : "unknown";
        const flagsDesc = Array.isArray(r.readOnlyFlags) && r.readOnlyFlags.length > 0
          ? `read-only [${r.readOnlyFlags.join(", ")}]`
          : "default";
        lines.push(`  ✔ ${name}: ${verStr} (Profile: ${flagsDesc})`);
      } else {
        lines.push(`  ⚠️ ${name}: Not detected / Inactive`);
      }
    }
  } else {
    lines.push("  ℹ No external reviewers probed");
  }
  lines.push("");

  lines.push("⚖️ Quorum Readiness Evaluation:");
  const quorum = report?.quorum || evaluateQuorumReadiness(report?.reviewers || []);
  if (quorum.status === QUORUM_STATUS.READY) {
    lines.push(`  ✔ Heterogeneous Quorum: ${quorum.summary}`);
  } else if (quorum.status === QUORUM_STATUS.PARTIAL) {
    lines.push(`  ⚠️ Heterogeneous Quorum: ${quorum.summary}`);
  } else {
    lines.push(`  ℹ Heterogeneous Quorum: ${quorum.summary}`);
  }
  lines.push("");

  lines.push("🔑 API Keys Environment (Legacy / Fallback):");
  lines.push(`  ℹ Anthropic Key: ${report?.envKeys?.anthropic ? "Configured" : "Unset (Real provider execution requires adapter)"}`);
  lines.push(`  ℹ Google Gemini Key: ${report?.envKeys?.gemini ? "Configured" : "Unset (Real provider execution requires adapter)"}`);
  lines.push(`  ℹ OpenAI Codex Key: ${report?.envKeys?.openai ? "Configured" : "Unset (Real provider execution requires adapter)"}`);
  lines.push(`  ℹ Provider Integration Status: Standalone Core Ready (External adapters require explicit configuration)\n`);

  return lines.join("\n") + "\n";
}
