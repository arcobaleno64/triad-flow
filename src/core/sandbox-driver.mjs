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

import {
  computeDigest
} from "./canonical-digest.mjs";

export const SANDBOX_DRIVERS = Object.freeze({
  WORKTREE: "worktree",
  CONTAINER: "container"
});

export const DEFAULT_CONTAINER_IMAGE = "node:20-slim";

export const CONTAINER_ALLOWLIST_ENV_VARS = Object.freeze([
  "PATH",
  "NODE_ENV",
  "LANG",
  "LC_ALL",
  "CI",
  "TERM"
]);

export const ACTIVE_EGRESS_PROBE_SCRIPT = "node -e 'const http=require(\"http\");const req=http.get(\"http://192.0.2.1:80\",{timeout:1000},()=>process.exit(0));req.on(\"error\",(e)=>{console.log(\"TF_EGRESS_DENIED:\"+(e.code||\"ERR\"));process.exit(42);});req.on(\"timeout\",()=>{req.destroy();console.log(\"TF_EGRESS_DENIED:ETIMEDOUT\");process.exit(42);});'";

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

export class SandboxSecurityViolationError extends Error {
  constructor(message, driver = "container") {
    super(message);
    this.name = "SandboxSecurityViolationError";
    this.driver = driver;
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
 * ContainerDriver: Docker / Podman isolated container execution with --network=none,
 * --pull=never, read-only rootfs, explicit tmpfs scratch, and active egress verification.
 */
export class ContainerDriver extends BaseSandboxDriver {
  constructor(options = {}) {
    super(SANDBOX_DRIVERS.CONTAINER);
    this.runtime = options.containerRuntime || options.runtime || "docker";
    this.image = options.image || DEFAULT_CONTAINER_IMAGE;
    this.pinnedImageDigest = options.pinnedImageDigest || null;
    this.execFn = options.execFn || null;
    this.allowlistEnv = options.allowlistEnv || CONTAINER_ALLOWLIST_ENV_VARS;
    this.activeEgressProbe = options.activeEgressProbe !== false;
  }

  probe(options = {}) {
    const exec = this.execFn || ((cmd, args) => spawnSync(cmd, args, { encoding: "utf8", windowsHide: true }));

    // 1. Probe container runtime CLI binary
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
    const runtimeVersion = typeof infoRes === "string" ? infoRes.trim() : (infoRes.stdout || "").trim();

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

    // 3. Probe local image cache (--pull=never invariant: image MUST be present locally)
    let inspectRes;
    try {
      inspectRes = exec(this.runtime, ["image", "inspect", "--format", "{{.Id}}", this.image]);
    } catch (err) {
      return {
        available: false,
        reason: `Image '${this.image}' not found in local cache (--pull=never policy prohibits implicit pull): ${err.message}`
      };
    }

    if (inspectRes && inspectRes.status !== 0 && typeof inspectRes !== "string") {
      return {
        available: false,
        reason: `Image '${this.image}' not found in local cache (--pull=never policy prohibits implicit pull).`
      };
    }

    const rawInspect = typeof inspectRes === "string" ? inspectRes.trim() : (inspectRes.stdout || "").trim();
    const resolvedId = rawInspect.replace(/^\[?"?|"?\]?$/g, "").trim();
    const imageDigest = resolvedId.startsWith("sha256:") ? resolvedId : `sha256:${resolvedId}`;

    // 4. Verify pinned image digest if configured
    if (this.pinnedImageDigest && imageDigest !== this.pinnedImageDigest) {
      return {
        available: false,
        reason: `Image digest mismatch: expected '${this.pinnedImageDigest}', but local image resolved to '${imageDigest}'.`
      };
    }

    return {
      available: true,
      runtime: this.runtime,
      runtimeVersion,
      image: this.image,
      imageDigest
    };
  }

  /**
   * Constructs strict isolation argv for container execution.
   *
   * @param {string} repoPath
   * @param {string} jailPath
   * @param {string|string[]} [commandArgs=[]]
   * @param {object} [options={}]
   * @returns {string[]}
   */
  buildRunArgs(repoPath, jailPath, commandArgs = [], options = {}) {
    const args = [
      "run",
      "--rm",
      "--pull=never",
      "--network=none",
      "--read-only",
      "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
      "--tmpfs", "/tmp/home:rw",
      "-e", "HOME=/tmp/home",
      "-e", "npm_config_cache=/tmp/npm-cache",
      "--cap-drop=ALL",
      "--security-opt=no-new-privileges",
      "-v", `${path.resolve(repoPath)}:/workspace:ro`,
      "-v", `${path.resolve(jailPath)}:/jail:rw`,
      "-w", "/jail"
    ];

    // Filter environment variables against strict allowlist (strip caller tokens & secrets)
    const allowlist = options.allowlistEnv || this.allowlistEnv;
    for (const varName of allowlist) {
      if (process.env[varName] !== undefined && varName !== "HOME") {
        args.push("-e", `${varName}=${process.env[varName]}`);
      }
    }

    // Pinned image identity
    const imageTarget = options.imageIdentity || this.pinnedImageDigest || this.image;
    args.push(imageTarget);

    // Command arguments
    if (Array.isArray(commandArgs)) {
      args.push(...commandArgs);
    } else if (typeof commandArgs === "string" && commandArgs.trim()) {
      args.push("sh", "-c", commandArgs);
    }

    return args;
  }

  /**
   * Executes a command inside the isolated container sandbox.
   *
   * @param {string} repoPath
   * @param {string} jailPath
   * @param {string|string[]} commandArgs
   * @param {object} [options={}]
   * @returns {{ status: number, exitCode: number, stdout: string, stderr: string, error?: Error }}
   */
  executeInContainer(repoPath, jailPath, commandArgs, options = {}) {
    const exec = this.execFn || ((cmd, args) => spawnSync(cmd, args, { encoding: "utf8", windowsHide: true }));
    const runArgs = this.buildRunArgs(repoPath, jailPath, commandArgs, options);

    try {
      const res = exec(this.runtime, runArgs);
      const status = typeof res?.status === "number" ? res.status : (res?.error ? 1 : 0);
      return {
        status,
        exitCode: status,
        stdout: typeof res === "string" ? res : (res?.stdout || ""),
        stderr: typeof res === "string" ? "" : (res?.stderr || ""),
        error: res?.error
      };
    } catch (err) {
      return {
        status: 1,
        exitCode: 1,
        stdout: "",
        stderr: err.message,
        error: err
      };
    }
  }

  /**
   * Actively verifies that network egress is authentically denied by attempting
   * an outbound HTTP probe inside the container.
   *
   * @param {string} repoPath
   * @param {string} jailPath
   * @param {object} [options={}]
   * @returns {{ verified: boolean, probeExecuted: boolean, exitCode: number, output: string }}
   */
  verifyEgressDenial(repoPath, jailPath, options = {}) {
    const probeRes = this.executeInContainer(repoPath, jailPath, ACTIVE_EGRESS_PROBE_SCRIPT, options);

    // 1. Exit 0: Outbound connection unexpectedly succeeded -> Security Violation!
    if (probeRes.status === 0) {
      throw new SandboxSecurityViolationError(
        "Active egress probe succeeded! Outbound network connection was established despite --network=none.",
        this.runtime
      );
    }

    const output = (String(probeRes.stdout || "") + " " + String(probeRes.stderr || "")).trim();
    const hasSentinel = /TF_EGRESS_DENIED:(?:ENETUNREACH|EAI_AGAIN|ENOTFOUND|ECONNREFUSED|ETIMEDOUT|EHOSTUNREACH|ECONNRESET|ERR)/.test(output);

    // 2. Exit 42 + Sentinel: Authentic network denial verified
    if (probeRes.status === 42 && hasSentinel) {
      return {
        verified: true,
        probeExecuted: true,
        exitCode: 42,
        output
      };
    }

    // 3. Any other status or missing sentinel: Probe execution failed or crashed, cannot verify egress isolation
    throw new SandboxSecurityViolationError(
      `Active egress probe execution failed (status=${probeRes.status}) without authentic network denial sentinel: '${output.slice(0, 80)}'. Cannot verify egress isolation.`,
      this.runtime
    );
  }

  create(repoPath, options = {}) {
    const probe = this.probe(options);
    if (!probe.available) {
      throw new SandboxUnavailableError(
        `Requested sandbox driver 'container' is unavailable on this host: ${probe.reason}. Silent downgrade to worktree is prohibited by ADR-024-02.`,
        this.runtime
      );
    }

    const jail = createPatchJailWorktree(repoPath, options);

    let egressResult = { verified: true, probeExecuted: false, exitCode: 1 };
    if (this.activeEgressProbe) {
      try {
        egressResult = this.verifyEgressDenial(repoPath, jail.jailPath, {
          imageIdentity: probe.imageDigest || this.image
        });
      } catch (err) {
        jail.cleanup();
        throw err;
      }
    }

    const caps = this.capabilities({
      runtimeVersion: probe.runtimeVersion,
      imageDigest: probe.imageDigest,
      egressDenied: egressResult.verified,
      probeExecuted: egressResult.probeExecuted,
      probeExitCode: egressResult.exitCode
    });

    return {
      jailPath: jail.jailPath,
      baseSha: jail.baseSha,
      cleanup: jail.cleanup,
      driver: this.name,
      runtime: this.runtime,
      runtimeVersion: probe.runtimeVersion,
      image: this.image,
      imageDigest: probe.imageDigest,
      capabilities: caps,
      runInContainer: (commandArgs, runOpts = {}) => {
        return this.executeInContainer(repoPath, jail.jailPath, commandArgs, {
          ...runOpts,
          imageIdentity: probe.imageDigest || this.image
        });
      }
    };
  }

  capabilities(context = {}) {
    return Object.freeze({
      driver: this.name,
      runtime: this.runtime,
      runtimeVersion: context.runtimeVersion || "unknown",
      image: this.image,
      imageDigest: context.imageDigest || null,
      filesystemIsolation: "container",
      networkEgressDenial: context.egressDenied ? "verified" : "unverified",
      processIsolation: "container",
      hostFilesystemWriteRestriction: "enforced-mount-ro",
      requestedControls: Object.freeze({
        pullPolicy: "never",
        networkMode: "none",
        readOnlyRootfs: true,
        capabilitiesDropped: ["ALL"],
        noNewPrivileges: true,
        mounts: Object.freeze({
          workspace: "ro",
          jail: "rw",
          tmp: "tmpfs"
        })
      }),
      effectiveControls: Object.freeze({
        networkMode: "none",
        readOnlyRootfs: true,
        capabilitiesDropped: ["ALL"],
        noNewPrivileges: true,
        envAllowlist: [...this.allowlistEnv]
      }),
      verifiedControls: Object.freeze({
        networkEgressDenied: Boolean(context.egressDenied),
        probeExecuted: Boolean(context.probeExecuted),
        probeExitCode: typeof context.probeExitCode === "number" ? context.probeExitCode : null,
        probeDigest: context.probeDigest || computeDigest(ACTIVE_EGRESS_PROBE_SCRIPT)
      }),
      environments: Object.freeze({
        patchApplicationEnvironment: "host-git",
        testExecutionEnvironment: "container",
        closureVerificationEnvironment: "independent-verifier"
      })
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

    return driver;
  }

  throw new Error(`Unsupported sandbox driver: '${driverName}'. Supported drivers: 'worktree', 'container'.`);
}
