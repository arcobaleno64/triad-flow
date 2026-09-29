/**
 * Provider Profile Specification (PR-06 / Milestone 2 Real Provider Pilot)
 *
 * Defines canonical provider profiles for local CLI reviewers (e.g. agy, claude).
 * Enforces mandatory read-only flags, family classification, and safe invocation defaults.
 */

import path from "node:path";
import { spawnSync } from "node:child_process";
import { getProviderFamily } from "../core/benchmark-pilot.mjs";
import { validateProviderOutput, extractJsonFromText } from "./provider-contract.mjs";

// Windows CreateProcess lpCommandLine limit is 32,767 characters.
// Use 8 KB on Windows for safety margin; 64 KB on POSIX systems with larger ARG_MAX.
export const SAFE_ARGV_THRESHOLD_BYTES = process.platform === "win32" ? 8 * 1024 : 64 * 1024;

export const PROVIDER_PROFILES = Object.freeze({
  agy: Object.freeze({
    id: "agy",
    command: "agy",
    family: "google",
    reviewProfileReady: true,
    profileStatus: "canonical",
    baseArgs: Object.freeze(["--print"]),
    mandatorySafetyArgs: Object.freeze(["--mode=plan", "--disable-slash-commands"]),
    args: Object.freeze(["--mode=plan", "--disable-slash-commands", "--print"]),
    readOnlyFlags: Object.freeze(["--mode=plan", "--disable-slash-commands"]),
    inputChannel: "argv",
    supportsStdin: false
  }),
  claude: Object.freeze({
    id: "claude",
    command: "claude",
    family: "anthropic",
    reviewProfileReady: true,
    profileStatus: "canonical",
    baseArgs: Object.freeze(["-p"]),
    mandatorySafetyArgs: Object.freeze(["--tools="]),
    args: Object.freeze(["-p", "--tools="]),
    readOnlyFlags: Object.freeze(["--tools="]),
    inputChannel: "argv",
    supportsStdin: true
  })
});

/**
 * Assembles provider execution arguments by merging baseArgs, mandatorySafetyArgs, and userArgs.
 * Enforces mandatory safety flags by preventing user args from stripping or overriding them.
 *
 * @param {object} profile - Canonical or resolved provider profile.
 * @param {string[]} [userArgs] - Optional user-supplied argument list.
 * @returns {string[]} Safe, merged and deduplicated argument list.
 */
export function assembleProviderArgs(profile = {}, userArgs) {
  const mandatory = Array.isArray(profile?.mandatorySafetyArgs)
    ? [...profile.mandatorySafetyArgs]
    : (Array.isArray(profile?.readOnlyFlags) ? [...profile.readOnlyFlags] : []);

  const base = Array.isArray(profile?.baseArgs)
    ? [...profile.baseArgs]
    : (profile?.id === "agy" ? ["--print"] : (profile?.id === "claude" ? ["-p"] : []));

  // If userArgs is undefined or null, return canonical profile.args or merged base+mandatory
  if (userArgs === undefined || userArgs === null) {
    if (Array.isArray(profile?.args)) {
      return [...profile.args];
    }
    const combined = [...base, ...mandatory];
    return Array.from(new Set(combined));
  }

  const rawUser = Array.isArray(userArgs)
    ? [...userArgs]
    : (typeof userArgs === "string" ? [userArgs] : []);

  // Filter out any user args that attempt to conflict with/override mandatory flags
  // Neutralizes both key=val (e.g. --mode=code) and space-separated tokens (e.g. --mode code, --tools bash)
  const filteredUser = [];
  for (let i = 0; i < rawUser.length; i++) {
    const arg = rawUser[i];
    if (!arg || typeof arg !== "string") continue;
    let skip = false;
    for (const m of mandatory) {
      const flagKey = m.includes("=") ? m.split("=")[0] : m;
      if (arg === flagKey || arg.startsWith(flagKey + "=")) {
        skip = true;
        // If flag was passed as a separate token and followed by a value token (not another flag), skip the value too
        if (arg === flagKey && i + 1 < rawUser.length && !String(rawUser[i + 1]).startsWith("-")) {
          i++;
        }
        break;
      }
    }
    if (!skip) {
      filteredUser.push(arg);
    }
  }

  // If user supplied args, start with user args, then guarantee baseArgs and mandatorySafetyArgs
  // If user did not supply args (or supplied empty array []), ensure base + mandatory are present
  const merged = filteredUser.length > 0
    ? [...filteredUser, ...base, ...mandatory]
    : (Array.isArray(profile?.args) ? [...profile.args] : [...base, ...mandatory]);

  for (const m of mandatory) {
    if (!merged.includes(m)) {
      merged.push(m);
    }
  }

  return Array.from(new Set(merged));
}

/**
 * Resolves a command string or name to its canonical provider profile.
 *
 * @param {string} commandOrName - Command string, binary name, or path.
 * @returns {object} Canonical provider profile with resolved arguments and flags.
 */
export function resolveProviderProfile(commandOrName = "") {
  if (!commandOrName || typeof commandOrName !== "string") {
    const defaultProfile = PROVIDER_PROFILES.agy;
    return {
      id: defaultProfile.id,
      command: defaultProfile.command,
      family: defaultProfile.family,
      reviewProfileReady: defaultProfile.reviewProfileReady ?? true,
      profileStatus: defaultProfile.profileStatus ?? "canonical",
      baseArgs: [...defaultProfile.baseArgs],
      mandatorySafetyArgs: [...defaultProfile.mandatorySafetyArgs],
      args: [...defaultProfile.args],
      readOnlyFlags: [...defaultProfile.readOnlyFlags],
      inputChannel: defaultProfile.inputChannel,
      supportsStdin: defaultProfile.supportsStdin
    };
  }

  const trimmed = commandOrName.trim();
  const base = path.basename(trimmed).toLowerCase().replace(/\.exe$/i, "");

  if (PROVIDER_PROFILES[base]) {
    const profile = PROVIDER_PROFILES[base];
    return {
      id: profile.id,
      command: trimmed,
      family: profile.family,
      reviewProfileReady: profile.reviewProfileReady ?? true,
      profileStatus: profile.profileStatus ?? "canonical",
      baseArgs: [...profile.baseArgs],
      mandatorySafetyArgs: [...profile.mandatorySafetyArgs],
      args: [...profile.args],
      readOnlyFlags: [...profile.readOnlyFlags],
      inputChannel: profile.inputChannel,
      supportsStdin: profile.supportsStdin
    };
  }

  for (const [key, profile] of Object.entries(PROVIDER_PROFILES)) {
    const pattern = new RegExp(`(^|[^a-z0-9])${key}([^a-z0-9]|$)`, "i");
    if (pattern.test(base)) {
      return {
        id: profile.id,
        command: trimmed,
        family: profile.family,
        reviewProfileReady: profile.reviewProfileReady ?? true,
        profileStatus: profile.profileStatus ?? "canonical",
        baseArgs: [...profile.baseArgs],
        mandatorySafetyArgs: [...profile.mandatorySafetyArgs],
        args: [...profile.args],
        readOnlyFlags: [...profile.readOnlyFlags],
        inputChannel: profile.inputChannel,
        supportsStdin: profile.supportsStdin
      };
    }
  }

  return {
    id: base || "custom",
    command: trimmed,
    family: getProviderFamily(base || trimmed),
    reviewProfileReady: false,
    profileStatus: "generic",
    baseArgs: [],
    mandatorySafetyArgs: [],
    args: ["--print"],
    readOnlyFlags: [],
    inputChannel: "argv",
    supportsStdin: true
  };
}

/**
 * 7-Point Provider Readiness Contract (TF-SPEC-RECEIPT-v1.0.0 / Phase 2 Beta)
 *
 * Verifies all 7 conditions required for a reviewer provider to achieve verified READY status:
 * Point 1: Binary detected (command found in PATH)
 * Point 2: Version parsed (regex matches semver)
 * Point 3: Canonical profile matched (profile exists with profileStatus === "canonical")
 * Point 4: Mandatory safety args verified (mandatory flags cannot be stripped or overridden)
 * Point 5: Live invocation succeeds (benign probe runs and exits 0 within timeout)
 * Point 6: Output contract validates (validates against validateProviderOutput)
 * Point 7: Working tree unchanged (git status --porcelain is empty and HEAD matches pre-invocation)
 *
 * Non-live / offline probe marks live invocation/output as "unverified" rather than hallucinating READY.
 *
 * @param {string} [providerName="agy"] - Provider command or identifier (e.g. "agy", "claude", "codex")
 * @param {object} [options={}]
 * @param {Function} [options.execFn] - Injected executor (cmd, args, opts) => ({ status, stdout, stderr, error, signal })
 * @param {Function} [options.probeFn] - Custom benign probe executor
 * @param {boolean} [options.live=false] - Whether to perform live execution (Points 5-7)
 * @param {boolean} [options.liveProbe=false] - Explicit flag indicating mock execFn performs live probe
 * @param {number} [options.timeoutMs=10000] - Probe timeout in ms
 * @param {string} [options.cwd] - Working directory for execution and git checks
 * @param {Function} [options.getGitState] - Custom git state extractor
 * @returns {object} Readiness assessment conforming to 7-point contract
 */
export function verifyProviderReadiness(providerName = "agy", options = {}) {
  const profile = resolveProviderProfile(providerName);
  const command = options.command || profile.command || providerName;
  const cwd = options.cwd || process.cwd();
  const timeoutMs = typeof options.timeoutMs === "number" && options.timeoutMs > 0
    ? options.timeoutMs
    : 10000;

  const points = {
    point1_binaryDetected: { pass: false },
    point2_versionParsed: { pass: false, version: null },
    point3_canonicalProfileMatched: { pass: false, profileStatus: profile.profileStatus ?? "generic" },
    point4_mandatorySafetyArgsVerified: { pass: false, mandatorySafetyArgs: [] },
    point5_liveInvocationSucceeds: { pass: false, status: "unverified", verified: false },
    point6_outputContractValidates: { pass: false, status: "unverified", verified: false },
    point7_workingTreeUnchanged: { pass: false, status: "unverified", verified: false }
  };
  const errors = [];

  // Point 3: Canonical profile matched
  if (profile.profileStatus === "canonical") {
    points.point3_canonicalProfileMatched = {
      family: profile.family,
      id: profile.id,
      pass: true,
      profileStatus: "canonical"
    };
  } else {
    const status = profile.profileStatus ?? "generic";
    const err = `Profile status for '${providerName}' is '${status}', expected 'canonical'`;
    errors.push(err);
    points.point3_canonicalProfileMatched = {
      error: err,
      family: profile.family,
      id: profile.id,
      pass: false,
      profileStatus: status
    };
  }

  // Point 4: Mandatory safety args verified
  const mandatory = Array.isArray(profile.mandatorySafetyArgs) && profile.mandatorySafetyArgs.length > 0
    ? profile.mandatorySafetyArgs
    : (Array.isArray(profile.readOnlyFlags) && profile.readOnlyFlags.length > 0 ? profile.readOnlyFlags : []);

  if (mandatory.length === 0) {
    const err = `Provider '${profile.id}' has no mandatory safety args defined`;
    errors.push(err);
    points.point4_mandatorySafetyArgsVerified = {
      error: err,
      mandatorySafetyArgs: [],
      pass: false
    };
  } else {
    // 1. Calling assembleProviderArgs with empty args preserves all mandatory flags
    const emptyArgs = assembleProviderArgs(profile, []);
    const preservesAll = mandatory.every(m => emptyArgs.includes(m));

    // 2. Hostile override attempts are stripped and mandatory args retained
    const hostileArgs = [];
    for (const m of mandatory) {
      const key = m.includes("=") ? m.split("=")[0] : m;
      hostileArgs.push(`${key}=hostile_override`, key, "hostile_token");
    }
    const assembledHostile = assembleProviderArgs(profile, hostileArgs);
    const preservesHostile = mandatory.every(m => assembledHostile.includes(m));
    const stripsHostile = hostileArgs.every(h => !assembledHostile.includes(h) || mandatory.includes(h));

    if (preservesAll && preservesHostile && stripsHostile) {
      points.point4_mandatorySafetyArgsVerified = {
        mandatorySafetyArgs: [...mandatory],
        pass: true
      };
    } else {
      const err = `Provider '${profile.id}' mandatory safety flags can be stripped or overridden`;
      errors.push(err);
      points.point4_mandatorySafetyArgsVerified = {
        error: err,
        mandatorySafetyArgs: [...mandatory],
        pass: false
      };
    }
  }

  // Point 1 & Point 2: Binary detected & Version parsed
  let verExec = null;
  const hasUnsafeChars = /[;&|`$<>()"'\r\n]/.test(command);
  if (hasUnsafeChars) {
    verExec = { error: new Error(`Reviewer command contains unsafe characters: '${command}'`), status: -1 };
  } else {
    try {
      if (typeof options.execFn === "function") {
        verExec = options.execFn(command, ["--version"], { cwd, timeout: timeoutMs });
      } else {
        verExec = spawnSync(command, ["--version"], {
          cwd,
          encoding: "utf8",
          timeout: timeoutMs,
          windowsHide: true
        });
      }
    } catch (err) {
      verExec = { error: err, status: -1 };
    }
  }

  const verFailed = Boolean(
    !verExec ||
    verExec.error ||
    verExec.signal ||
    (verExec.status !== null && verExec.status !== undefined && verExec.status !== 0)
  );

  if (verFailed) {
    const errMsg = verExec?.error
      ? (verExec.error.message || String(verExec.error))
      : (verExec?.signal ? `Process terminated with signal ${verExec.signal}` : `Process exited with code ${verExec?.status}`);
    errors.push(`Binary not detected or invocation failed: ${errMsg}`);
    points.point1_binaryDetected = { error: errMsg, pass: false };
    points.point2_versionParsed = { error: "Cannot parse version: binary invocation failed", pass: false, version: null };
  } else {
    points.point1_binaryDetected = { command, pass: true };

    const rawOut = (verExec.stdout || "").toString().trim() || (verExec.stderr || "").toString().trim();
    const semverMatch = rawOut.match(/(\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.-]+)?)/);
    if (semverMatch) {
      points.point2_versionParsed = {
        pass: true,
        rawVersion: rawOut,
        version: semverMatch[1]
      };
    } else {
      const err = `Output did not contain valid semver: '${rawOut.slice(0, 100)}'`;
      errors.push(err);
      points.point2_versionParsed = {
        error: err,
        pass: false,
        rawVersion: rawOut,
        version: null
      };
    }
  }

  // Live probe (Points 5, 6, 7)
  const isLive = Boolean(options.live) || Boolean(options.probeFn) || Boolean(options.liveProbe);

  if (!isLive) {
    points.point5_liveInvocationSucceeds = {
      error: "Live invocation unverified (offline or non-live mode)",
      pass: false,
      status: "unverified",
      verified: false
    };
    points.point6_outputContractValidates = {
      error: "Output contract unverified (live probe not executed)",
      pass: false,
      status: "unverified",
      verified: false
    };
    points.point7_workingTreeUnchanged = {
      error: "Working tree check unverified (live probe not executed)",
      pass: false,
      status: "unverified",
      verified: false
    };
  } else {
    // 1. Working tree pre-check
    const extractGitInfo = () => {
      let ok = true;
      let headSha = null;
      let status = "";
      try {
        if (typeof options.getGitState === "function") {
          const gs = options.getGitState();
          ok = Boolean(gs?.ok);
          headSha = gs?.repository?.commitSha || gs?.headSha || null;
          if (gs?.status) {
            status = String(gs.status).trim();
          } else if (gs?.isDirty === true || gs?.clean === false) {
            status = "dirty";
          } else if (Array.isArray(gs?.files) && gs.files.length > 0) {
            status = gs.files.map(f => (typeof f === "string" ? f : f.path)).join("\n");
          } else if (Array.isArray(gs?.uncommitted) && gs.uncommitted.length > 0) {
            status = gs.uncommitted.join("\n");
          }
        } else {
          const sRes = spawnSync("git", ["status", "--porcelain"], { cwd, encoding: "utf8" });
          if (sRes.status === 0) {
            status = (sRes.stdout || "").trim();
          } else {
            ok = false;
          }
          const hRes = spawnSync("git", ["rev-parse", "HEAD"], { cwd, encoding: "utf8" });
          if (hRes.status === 0 && hRes.stdout) {
            headSha = hRes.stdout.trim();
          } else {
            ok = false;
          }
        }
      } catch {
        ok = false;
      }
      return { headSha, ok, status };
    };

    const preGit = extractGitInfo();
    const preStatus = preGit.status;
    const preHeadSha = preGit.headSha;
    const preGitOk = preGit.ok;

    // 2. Execute live benign probe
    let probeRes = null;
    try {
      if (typeof options.probeFn === "function") {
        probeRes = options.probeFn(profile, options);
      } else if (typeof options.execFn === "function") {
        const benignPrompt = 'Respond ONLY with a JSON object: {"findings":[],"coverage":{"coveredFiles":[],"omittedFiles":[]},"usage":{"promptTokens":null,"completionTokens":null,"totalTokens":null}}';
        probeRes = options.execFn(command, assembleProviderArgs(profile, [benignPrompt]), {
          cwd,
          timeout: timeoutMs
        });
      } else {
        const benignPrompt = 'Respond ONLY with a JSON object: {"findings":[],"coverage":{"coveredFiles":[],"omittedFiles":[]},"usage":{"promptTokens":null,"completionTokens":null,"totalTokens":null}}';
        const probeArgs = assembleProviderArgs(profile, [benignPrompt]);
        probeRes = spawnSync(command, probeArgs, {
          cwd,
          encoding: "utf8",
          timeout: timeoutMs,
          windowsHide: true
        });
      }
    } catch (err) {
      probeRes = { error: err, status: -1 };
    }

    const probeExit = probeRes?.status ?? (probeRes?.error ? -1 : 0);
    const probeSuccess = Boolean(
      probeRes &&
      !probeRes.error &&
      !probeRes.signal &&
      probeExit === 0
    );

    if (probeSuccess) {
      points.point5_liveInvocationSucceeds = {
        pass: true,
        status: 0,
        verified: true
      };
    } else {
      const errMsg = probeRes?.error
        ? (probeRes.error.message || String(probeRes.error))
        : (probeRes?.signal ? `Probe killed with signal ${probeRes.signal}` : `Probe exited with status ${probeExit}`);
      errors.push(`Live invocation failed: ${errMsg}`);
      points.point5_liveInvocationSucceeds = {
        error: errMsg,
        pass: false,
        status: probeExit,
        verified: true
      };
    }

    // 3. Point 6: Output contract validates against validateProviderOutput
    if (!probeSuccess) {
      points.point6_outputContractValidates = {
        error: "Output contract check skipped due to live invocation failure",
        pass: false,
        verified: true
      };
    } else {
      let rawText = probeRes.stdout || "";
      let parsed = null;
      if (typeof rawText === "object" && rawText !== null) {
        parsed = rawText;
      } else if (typeof rawText === "string") {
        parsed = extractJsonFromText(rawText);
      }

      const valResult = validateProviderOutput(parsed, {
        family: profile.family,
        providerName: profile.id
      });

      if (valResult.ok) {
        points.point6_outputContractValidates = {
          executionStatus: valResult.executionStatus,
          pass: true,
          verified: true
        };
      } else {
        const err = `Output contract failed: ${valResult.error || "invalid output schema"}`;
        errors.push(err);
        points.point6_outputContractValidates = {
          error: err,
          pass: false,
          verified: true
        };
      }
    }

    // 4. Point 7: Working tree unchanged (git status --porcelain empty & HEAD unaltered)
    const postGit = extractGitInfo();
    const postStatus = postGit.status;
    const postHeadSha = postGit.headSha;
    const postGitOk = postGit.ok;

    let workingTreeClean = false;
    let gitErrMsg = "";

    if (!preGitOk || !postGitOk) {
      gitErrMsg = "Git status check failed";
    } else if (preStatus !== "") {
      gitErrMsg = `Working tree dirty prior to invocation (clean repository required):\n${preStatus}`;
    } else if (postStatus !== "") {
      gitErrMsg = `Working tree dirty after invocation:\n${postStatus}`;
    } else if (preHeadSha && postHeadSha && postHeadSha !== preHeadSha) {
      gitErrMsg = `HEAD commit drift detected (pre: ${preHeadSha}, post: ${postHeadSha})`;
    } else {
      workingTreeClean = true;
    }

    if (workingTreeClean) {
      points.point7_workingTreeUnchanged = {
        headSha: postHeadSha,
        pass: true,
        verified: true
      };
    } else {
      errors.push(`Working tree invariant violated: ${gitErrMsg}`);
      points.point7_workingTreeUnchanged = {
        error: gitErrMsg,
        pass: false,
        verified: true
      };
    }
  }

  const all7Pass = Boolean(
    points.point1_binaryDetected?.pass &&
    points.point2_versionParsed?.pass &&
    points.point3_canonicalProfileMatched?.pass &&
    points.point4_mandatorySafetyArgsVerified?.pass &&
    points.point5_liveInvocationSucceeds?.pass &&
    points.point6_outputContractValidates?.pass &&
    points.point7_workingTreeUnchanged?.pass
  );

  return {
    command,
    errors,
    family: profile.family,
    id: profile.id,
    points,
    profile,
    providerName,
    ready: all7Pass,
    summary: all7Pass
      ? "READY (All 7 points verified)"
      : (!isLive
          ? "UNVERIFIED (Points 1-4 profiled; live probe unverified in offline/non-live mode)"
          : `NOT_READY (${errors[0] || "1 or more points failed"})`)
  };
}
