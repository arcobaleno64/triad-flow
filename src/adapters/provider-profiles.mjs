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
    args: Object.freeze(["--mode=plan", "--disable-slash-commands", "--print"]),
    readOnlyFlags: Object.freeze(["--mode=plan", "--disable-slash-commands"]),
    inputChannel: "argv",
    supportsStdin: false
  }),
  claude: Object.freeze({
    id: "claude",
    command: "claude",
    family: "anthropic",
    args: Object.freeze(["-p", "--tools="]),
    readOnlyFlags: Object.freeze(["--tools="]),
    inputChannel: "argv",
    supportsStdin: true
  })
});

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
    args: ["--print"],
    readOnlyFlags: [],
    inputChannel: "argv",
    supportsStdin: true
  };
}
