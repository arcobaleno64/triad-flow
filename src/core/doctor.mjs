/**
 * Triad-Flow Capability Doctor & Heterogeneous Quorum Readiness Prober
 *
 * Probes environment capabilities, local CLI reviewer binaries (agy, claude, codex),
 * evaluates multi-vendor quorum readiness, and collects structured diagnostic reports.
 */

import { spawnSync } from "node:child_process";
import { resolveProviderProfile, verifyProviderReadiness } from "../adapters/provider-profiles.mjs";
import { collectGitWorkingState } from "./git-collector.mjs";

export const DEFAULT_PROBE_TARGETS = Object.freeze(["agy", "claude", "codex"]);
export const DEFAULT_PROBE_TIMEOUT_MS = 1500;

export const QUORUM_STATUS = Object.freeze({
  BINARY_QUORUM_READY: "BINARY_QUORUM_READY",
  READY: "BINARY_QUORUM_READY",
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
    : (options.live ? 30000 : DEFAULT_PROBE_TIMEOUT_MS);

  const results = [];

  for (const target of targets) {
    const profile = resolveProviderProfile(target);
    const readiness = verifyProviderReadiness(target, {
      cwd: options.cwd,
      execFn: options.execFn,
      getGitState: options.getGitState,
      live: Boolean(options.live),
      liveProbe: Boolean(options.liveProbe),
      timeoutMs
    });

    const isDetected = Boolean(readiness.points.point1_binaryDetected?.pass);

    if (!isDetected) {
      const errMsg = readiness.points.point1_binaryDetected?.error || readiness.errors[0] || "Process execution failed";
      results.push({
        available: false,
        command: target,
        error: errMsg,
        family: profile.family,
        id: profile.id,
        installed: false,
        operationalReady: false,
        profile,
        profileStatus: profile.profileStatus ?? "generic",
        readOnlyFlags: [...profile.readOnlyFlags],
        readiness,
        reviewProfileReady: profile.reviewProfileReady ?? false,
        stage: "UNAVAILABLE",
        version: null,
        rawVersion: null
      });
    } else {
      const version = readiness.points.point2_versionParsed?.version || "unknown";
      const rawVersion = readiness.points.point2_versionParsed?.rawVersion || version;

      results.push({
        available: true,
        command: target,
        family: profile.family,
        id: profile.id,
        installed: true,
        operationalReady: readiness.ready,
        profile,
        profileStatus: profile.profileStatus ?? "generic",
        readOnlyFlags: [...profile.readOnlyFlags],
        readiness,
        reviewProfileReady: profile.reviewProfileReady ?? false,
        stage: readiness.ready ? "READY" : "PROFILED",
        version,
        rawVersion
      });
    }
  }

  return results;
}

/**
 * Checks whether a probed reviewer has a verified canonical review profile.
 *
 * @param {object} reviewer - Probed reviewer object
 * @returns {boolean} True if reviewer profile has reviewProfileReady === true
 */
export function isReviewerProfileReady(reviewer) {
  if (!reviewer || typeof reviewer !== "object") return false;
  if (typeof reviewer.reviewProfileReady === "boolean") return reviewer.reviewProfileReady;
  if (reviewer.profile && typeof reviewer.profile.reviewProfileReady === "boolean") return reviewer.profile.reviewProfileReady;
  const resolved = resolveProviderProfile(reviewer.id || reviewer.command);
  return Boolean(resolved?.reviewProfileReady);
}

/**
 * Checks whether a probed reviewer has satisfied the complete 7-point readiness contract.
 *
 * @param {object} reviewer - Probed reviewer object
 * @returns {boolean} True only if reviewer has passed all 7 readiness points
 */
export function isReviewerOperationalReady(reviewer) {
  if (!reviewer || typeof reviewer !== "object") return false;
  if (reviewer.readiness && typeof reviewer.readiness.ready === "boolean") {
    return reviewer.readiness.ready;
  }
  return false;
}

/**
 * Evaluates whether installed reviewers satisfy Heterogeneous Quorum requirements.
 *
 * - BINARY_QUORUM_READY: >= 2 distinct vendor families with canonical review profiles (reviewProfileReady: true).
 * - PARTIAL: Exactly 1 trusted vendor family. Single sentry enabled; dual sentry requires 2nd vendor.
 * - STANDALONE: 0 external reviewers. Operates in zero-dependency offline deterministic mode.
 *
 * Doctor only reports operational READY when all 7 readiness points pass.
 * Non-live / offline probe marks live invocation/output as "unverified" rather than hallucinating READY.
 *
 * @param {Array<object>} [reviewers=[]] - List of probed reviewers
 * @param {object} [options={}]
 * @param {boolean} [options.require7Points=false] - Fail-closed readiness enforcing all 7 points
 * @returns {object} Quorum readiness verdict
 */
export function evaluateQuorumReadiness(reviewers = [], options = {}) {
  const activeReviewers = (Array.isArray(reviewers) ? reviewers : []).filter(
    r => r && (r.available === true || (r.available === undefined && r.installed === true))
  );

  const trustedReviewers = activeReviewers.filter(
    r => r.family && r.family !== "unknown" && isReviewerProfileReady(r)
  );

  const trustedFamilies = Array.from(
    new Set(
      trustedReviewers
        .map(r => (r.family ? String(r.family).toLowerCase().trim() : ""))
        .filter(Boolean)
    )
  );

  const verifiedReviewers = trustedReviewers.filter(r => r.readiness?.ready === true);
  const verifiedFamilies = Array.from(
    new Set(
      verifiedReviewers
        .map(r => (r.family ? String(r.family).toLowerCase().trim() : ""))
        .filter(Boolean)
    )
  );

  const all7PointsVerified = verifiedFamilies.length >= 2;
  const hasUnverifiedLive = trustedReviewers.some(r => r.readiness?.points?.point5_liveInvocationSucceeds?.status === "unverified");

  const require7Points = Boolean(options.require7Points);
  const isReady = require7Points ? all7PointsVerified : (trustedFamilies.length >= 2);

  if (trustedFamilies.length >= 2) {
    const names = trustedFamilies.map(getFamilyDisplayName);
    const summary = all7PointsVerified
      ? `BINARY_QUORUM_READY (${names.join(" + ")}) [All 7 points verified]`
      : `BINARY_QUORUM_READY (${names.join(" + ")})`;
    const note = all7PointsVerified
      ? "all 7 provider readiness points verified (live probe & output contract validated)"
      : (hasUnverifiedLive
          ? "version check only; operational review readiness requires authenticated probe (live probe: unverified)"
          : "version check only; operational review readiness requires authenticated probe");

    return {
      activeReviewers: activeReviewers.map(r => r.id || r.command || "unknown"),
      all7PointsVerified,
      canRunDualQuorum: true,
      canRunSingle: true,
      families: trustedFamilies,
      familyNames: names,
      hasUnverifiedLive,
      note,
      operationalReady: all7PointsVerified,
      ready: isReady,
      stage: all7PointsVerified ? "READY" : "PROFILED",
      status: QUORUM_STATUS.BINARY_QUORUM_READY,
      summary
    };
  }

  if (trustedFamilies.length === 1) {
    const names = trustedFamilies.map(getFamilyDisplayName);
    const note = hasUnverifiedLive
      ? "version check only; operational review readiness requires authenticated probe (live probe: unverified)"
      : "version check only; operational review readiness requires authenticated probe";

    return {
      activeReviewers: activeReviewers.map(r => r.id || r.command || "unknown"),
      all7PointsVerified: false,
      canRunDualQuorum: false,
      canRunSingle: true,
      families: trustedFamilies,
      familyNames: names,
      hasUnverifiedLive,
      note,
      operationalReady: false,
      ready: false,
      stage: "PROFILED",
      status: QUORUM_STATUS.PARTIAL,
      summary: `PARTIAL (${names[0]})`
    };
  }

  return {
    activeReviewers: activeReviewers.map(r => r.id || r.command || "unknown"),
    all7PointsVerified: false,
    canRunDualQuorum: false,
    canRunSingle: false,
    families: [],
    familyNames: [],
    hasUnverifiedLive: false,
    operationalReady: false,
    ready: false,
    stage: "INSTALLED",
    status: QUORUM_STATUS.STANDALONE,
    summary: "STANDALONE (Offline simulation / replay mode)"
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
    cwd,
    execFn: options.execFn,
    getGitState: options.getGitState,
    live: Boolean(options.live),
    liveProbe: Boolean(options.liveProbe),
    reviewers: options.reviewers,
    timeoutMs: options.timeoutMs
  });

  const quorum = evaluateQuorumReadiness(reviewers, {
    live: Boolean(options.live),
    require7Points: options.require7Points
  });

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
    readiness: {
      all7PointsVerified: quorum.all7PointsVerified ?? false,
      operationalReady: quorum.operationalReady ?? false,
      status: quorum.all7PointsVerified ? "READY" : (quorum.hasUnverifiedLive ? "UNVERIFIED" : "NOT_READY")
    },
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
        const ready = isReviewerProfileReady(r);
        const flagsDesc = !ready
          ? "generic launcher; reviewProfileReady: false"
          : (Array.isArray(r.readOnlyFlags) && r.readOnlyFlags.length > 0
            ? `read-only [${r.readOnlyFlags.join(", ")}]`
            : "default");
        let liveDesc = "";
        if (r.readiness?.ready) {
          liveDesc = "; live probe: verified READY";
        } else if (r.readiness?.points?.point5_liveInvocationSucceeds?.status === "unverified") {
          liveDesc = "; live probe: unverified";
        } else if (r.readiness?.points) {
          const pts = r.readiness.points;
          if (pts.point5_liveInvocationSucceeds?.pass === false) {
            liveDesc = `; live probe: FAILED (${pts.point5_liveInvocationSucceeds.error || "invocation error"})`;
          } else if (pts.point6_outputContractValidates?.pass === false) {
            liveDesc = `; output contract: FAILED (${pts.point6_outputContractValidates.error || "schema invalid"})`;
          } else if (pts.point7_workingTreeUnchanged?.pass === false) {
            liveDesc = `; working tree: FAILED (${pts.point7_workingTreeUnchanged.error || "dirty tree"})`;
          } else {
            liveDesc = "; live probe: NOT_READY";
          }
        }
        lines.push(`  ✔ ${name}: ${verStr} (Profile: ${flagsDesc}${liveDesc})`);
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
  if (quorum.status === QUORUM_STATUS.BINARY_QUORUM_READY || quorum.status === "READY" || quorum.status === "BINARY_QUORUM_READY") {
    lines.push(`  ✔ Heterogeneous Quorum: ${quorum.summary}`);
    lines.push(`    [Note: ${quorum.note || "version check only; operational review readiness requires authenticated probe"}]`);
  } else if (quorum.status === QUORUM_STATUS.PARTIAL) {
    lines.push(`  ⚠️ Heterogeneous Quorum: ${quorum.summary}`);
    if (quorum.note) {
      lines.push(`    [Note: ${quorum.note}]`);
    }
  } else {
    lines.push(`  ℹ Heterogeneous Quorum: ${quorum.summary}`);
  }
  lines.push("");

  if (report?.readiness) {
    const rStatus = report.readiness.operationalReady ? "✔" : (report.readiness.status === "UNVERIFIED" ? "ℹ" : "⚠️");
    lines.push("🛡️ 7-Point Provider Readiness Contract:");
    lines.push(`  ${rStatus} Operational Readiness: ${report.readiness.status} (${report.readiness.all7PointsVerified ? "All 7 points verified" : (report.readiness.status === "UNVERIFIED" ? "Live invocation & output contract unverified in offline mode" : "1 or more readiness points failed")})\n`);
  }

  lines.push("🔑 API Keys Environment (Legacy / Fallback):");
  lines.push(`  ℹ Anthropic Key: ${report?.envKeys?.anthropic ? "Configured" : "Unset (Real provider execution requires adapter)"}`);
  lines.push(`  ℹ Google Gemini Key: ${report?.envKeys?.gemini ? "Configured" : "Unset (Real provider execution requires adapter)"}`);
  lines.push(`  ℹ OpenAI Codex Key: ${report?.envKeys?.openai ? "Configured" : "Unset (Real provider execution requires adapter)"}`);
  lines.push(`  ℹ Provider Integration Status: Standalone Core Ready (External adapters require explicit configuration)\n`);

  return lines.join("\n") + "\n";
}
