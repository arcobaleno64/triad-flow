/**
 * Provider Profile Specification (PR-06 / Milestone 2 Real Provider Pilot)
 *
 * Defines canonical provider profiles for local CLI reviewers (e.g. agy, claude).
 * Enforces mandatory read-only flags, family classification, and safe invocation defaults.
 */

import path from "node:path";
import { getProviderFamily } from "../core/benchmark-pilot.mjs";

// Windows CreateProcess lpCommandLine limit is 32,767 characters.
// Use 8 KB on Windows for safety margin; 64 KB on POSIX systems with larger ARG_MAX.
export const SAFE_ARGV_THRESHOLD_BYTES = process.platform === "win32" ? 8 * 1024 : 64 * 1024;

export const PROVIDER_PROFILES = Object.freeze({
  agy: Object.freeze({
    id: "agy",
    command: "agy",
    family: "google",
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
    baseArgs: [],
    mandatorySafetyArgs: [],
    args: ["--print"],
    readOnlyFlags: [],
    inputChannel: "argv",
    supportsStdin: true
  };
}
