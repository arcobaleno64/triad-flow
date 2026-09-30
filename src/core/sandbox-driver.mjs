/**
 * Triad-Flow Pluggable Sandbox Driver Abstraction (M3 / v2.4)
 *
 * Implements ADR-024-02:
 * - Default zero-dependency WorktreeDriver (Git Worktree filesystem write isolation).
 * - Explicit opt-in ContainerDriver (Docker/Podman with network=none egress denial).
 * - Strictly prohibits silent downgrade: fail-closed if container driver is requested but unavailable.
 * - Truthful receipt capabilities recording (no fake sandbox claims).
 */

import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

import {
  createPatchJailWorktree,
  cleanupPatchJailWorktree,
  PatchJailExecutionError
} from "./controlled-remediation.mjs";

export const SANDBOX_DRIVERS = Object.freeze({
  WORKTREE: "worktree",
  CONTAINER: "container"
});

export class SandboxUnavailableError extends Error {
  constructor(message, driver = "container") {
    super(message);
    this.name = "SandboxUnavailableError";
    this.driver = driver;
  }
}

export class SilentDowngradeProhibitedError extends Error {
  constructor(message) {
    super(message || "ADR-024-02: Silent downgrade from requested container sandbox to worktree is strictly prohibited.");
    this.name = "SilentDowngradeProhibitedError";
  }
}

/**
 * Base Sandbox Driver contract.
 */
export class BaseSandboxDriver {
  constructor(name = "base") {
    this.name = name;
  }

  /**
   * Probes host availability and returns readiness status.
   *
   * @param {object} [options]
   * @returns {{ available: boolean, reason?: string, details?: object }}
   */
  probe(options = {}) {
    return { available: true };
  }

  /**
   * Creates an isolated jail sandbox for trial execution.
   *
   * @param {string} repoPath
   * @param {object} [options]
   * @returns {{ jailPath: string, cleanup: Function, driver: string, [key: string]: any }}
   */
  create(repoPath, options = {}) {
    throw new Error(`[BaseSandboxDriver] 'create' not implemented by driver '${this.name}'.`);
  }

  /**
   * Returns authoritative capabilities report for receipt generation.
   *
   * @returns {{ driver: string, filesystemIsolation: string, networkEgressDenial: string, writeBoundary: string }}
   */
  capabilities() {
    return {
      driver: this.name,
      filesystemIsolation: "none",
      networkEgressDenial: "unavailable",
      writeBoundary: "unrestricted"
    };
  }
}

/**
 * WorktreeDriver: Zero-dependency Git Worktree Write Isolation (Default).
 */
export class WorktreeDriver extends BaseSandboxDriver {
  constructor(options = {}) {
    super(SANDBOX_DRIVERS.WORKTREE);
    this.execFn = options.execFn || null;
  }

  probe(options = {}) {
    try {
      const exec = this.execFn || ((cmd, args) => spawnSync(cmd, args, { encoding: "utf8" }));
      const res = exec("git", ["--version"]);
      if (res && (res.status === 0 || (typeof res === "string" && res.includes("git version")))) {
        return { available: true, version: typeof res === "string" ? res.trim() : (res.stdout || "").trim() };
      }
      return { available: false, reason: "Git executable not functional or exited with non-zero status." };
    } catch (err) {
      return { available: false, reason: `Git probe failed: ${err.message}` };
    }
  }

  create(repoPath, options = {}) {
    const jail = createPatchJailWorktree(repoPath, options);
    return {
      jailPath: jail.jailPath,
      baseSha: jail.baseSha,
      cleanup: jail.cleanup,
      driver: this.name,
      capabilities: this.capabilities()
    };
  }

  capabilities() {
    return Object.freeze({
      driver: this.name,
      filesystemIsolation: "git-worktree",
      networkEgressDenial: "unavailable",
      processIsolation: "none",
      hostFilesystemWriteRestriction: "unenforced"
    });
  }
}

/**
 * ContainerDriver: Docker / Podman isolated container execution with --network=none.
 */
export class ContainerDriver extends BaseSandboxDriver {
  constructor(options = {}) {
    super(SANDBOX_DRIVERS.CONTAINER);
    this.runtime = options.containerRuntime || options.runtime || "docker";
    this.image = options.image || "node:20-slim";
    this.execFn = options.execFn || null;
  }

  probe(options = {}) {
    const exec = this.execFn || ((cmd, args) => spawnSync(cmd, args, { encoding: "utf8", windowsHide: true }));

    // 1. Probe container runtime CLI
    let infoRes;
    try {
      infoRes = exec(this.runtime, ["--version"]);
    } catch (err) {
      return {
        available: false,
        reason: `Container runtime binary '${this.runtime}' is not installed or not in PATH (${err.message}).`
      };
    }

    if (infoRes && infoRes.status !== 0 && typeof infoRes !== "string") {
      const errMsg = (infoRes.stderr || infoRes.error?.message || "Non-zero exit").trim();
      return {
        available: false,
        reason: `Container runtime '${this.runtime}' returned exit code ${infoRes.status}: ${errMsg}`
      };
    }

    // 2. Probe container daemon readiness
    let daemonRes;
    try {
      daemonRes = exec(this.runtime, ["info", "--format", "{{.ServerVersion}}"]);
    } catch (err) {
      return {
        available: false,
        reason: `Container daemon for '${this.runtime}' is not responding: ${err.message}`
      };
    }

    if (daemonRes && daemonRes.status !== 0 && typeof daemonRes !== "string") {
      return {
        available: false,
        reason: `Container daemon for '${this.runtime}' is not running or socket is inaccessible.`
      };
    }

    return {
      available: true,
      runtime: this.runtime,
      image: this.image
    };
  }

  create(repoPath, options = {}) {
    throw new SandboxUnavailableError(
      `Container execution sandbox is not yet implemented (in-container process execution primitive pending). To prevent unverified container isolation claims, container driver fails closed under ADR-024-02.`,
      this.runtime
    );
  }

  capabilities() {
    return Object.freeze({
      driver: this.name,
      filesystemIsolation: "container-unverified",
      networkEgressDenial: "unverified",
      processIsolation: "unverified",
      hostFilesystemWriteRestriction: "unenforced"
    });
  }
}

/**
 * Resolves sandbox driver by name adhering strictly to ADR-024-02 (no silent fallback).
 *
 * @param {string} [driverName="worktree"]
 * @param {object} [options]
 * @returns {BaseSandboxDriver}
 */
export function resolveSandboxDriver(driverName = "worktree", options = {}) {
  const norm = String(driverName || "worktree").trim().toLowerCase();

  if (norm === SANDBOX_DRIVERS.WORKTREE || norm === "default" || !norm) {
    return new WorktreeDriver(options);
  }

  if (norm === SANDBOX_DRIVERS.CONTAINER || norm === "docker" || norm === "podman") {
    const driver = new ContainerDriver({
      ...options,
      containerRuntime: norm === "podman" ? "podman" : (options.containerRuntime || "docker")
    });

    // Proactively probe host capability - ADR-024-02 requires immediate fail-closed on unavailability
    const probe = driver.probe(options);
    if (!probe.available) {
      throw new SandboxUnavailableError(
        `Requested sandbox driver 'container' is unavailable on this host: ${probe.reason}. Silent downgrade to worktree is prohibited by ADR-024-02.`,
        driver.runtime
      );
    }

    // Fail-Closed Trust Boundary: Real in-container execution is not yet integrated
    throw new SandboxUnavailableError(
      `Container runtime '${driver.runtime}' is available, but in-container jail process execution is not yet integrated. Generating unverified container isolation receipts is strictly prohibited by ADR-024-02.`,
      driver.runtime
    );
  }

  throw new Error(`Unsupported sandbox driver: '${driverName}'. Supported drivers: 'worktree', 'container'.`);
}
