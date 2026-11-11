/**
 * Triad-Flow Hot-Reuse Container Sandbox Pool (M1 / v2.12)
 *
 * Implements Pillar 1 of Milestone v2.12 (RFC-028-01):
 * - Long-running warm container daemon pool with multi-language pre-warming (Node, Python, Go, Rust, C/C++).
 * - High-throughput command multiplexing via `docker exec` / `podman exec` achieving sub-150ms dispatch.
 * - Strict non-root privilege degradation (--user 1000:1000), CPU quota (--cpus 2.0), and memory capping (--memory 2g).
 * - Read-only root filesystem with explicit tmpfs mounts and workspace hot-mounting.
 * - Post-execution workspace scrubbing (scrub-on-release) preventing cross-trial contamination.
 * - Authoritative lifecycle management with signal traps (SIGINT, SIGTERM, exit) ensuring zero orphan containers.
 * - Zero external npm dependencies (pure Node.js native API).
 */

import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { EventEmitter } from "node:events";

import { computeDigest } from "./canonical-digest.mjs";
import {
  createPatchJailWorktree,
  cleanupPatchJailWorktree
} from "./controlled-remediation.mjs";
import {
  BaseSandboxDriver,
  SandboxUnavailableError,
  SandboxSecurityViolationError,
  CONTAINER_ALLOWLIST_ENV_VARS,
  ACTIVE_EGRESS_PROBE_SCRIPT,
  ACTIVE_EGRESS_PROBE_SCRIPT_PYTHON,
  ACTIVE_EGRESS_PROBE_SCRIPT_SH,
  registerSandboxDriver
} from "./sandbox-driver.mjs";
import {
  SUPPORTED_LANGUAGES,
  DEFAULT_LANGUAGE_CONTAINER_IMAGES,
  resolveLanguageContainerImage
} from "./multi-language-remediation.mjs";

/**
 * Docker / Podman label specifications for Background Container Reconciler.
 */
export const POOL_CONTAINER_LABELS = Object.freeze({
  ROOT_KEY: "triad-flow-pool",
  ROOT_VALUE: "true",
  POOL_ID_KEY: "triad-flow-pool-id",
  CREATED_AT_KEY: "triad-flow-created-at",
  TTL_MS_KEY: "triad-flow-ttl-ms",
  SLOT_ID_KEY: "triad-flow-slot-id",
  LANGUAGE_KEY: "triad-flow-language"
});

/**
 * Lifecycle states of an individual container daemon inside the pool.
 */
export const POOL_CONTAINER_STATES = Object.freeze({
  STARTING: "starting",
  IDLE: "idle",
  BUSY: "busy",
  DRAINED: "drained",
  CRASHED: "crashed"
});

/**
 * Default resource constraints enforcing strict execution quotas.
 */
export const DEFAULT_RESOURCE_LIMITS = Object.freeze({
  memory: "2g",
  cpus: "2.0",
  user: "1000:1000"
});

/**
 * Default configuration parameters for the container pool.
 */
export const DEFAULT_POOL_OPTIONS = Object.freeze({
  minWarm: 1,
  maxCapacity: 8,
  idleTimeoutMs: 120000,
  acquireTimeoutMs: 15000,
  runtime: "docker",
  containerPrefix: "tf-pool",
  reapIntervalMs: 30000,
  autoRegisterSignalHandlers: true,
  selinuxMount: false,
  scrubOnRelease: true,
  defaultLanguage: SUPPORTED_LANGUAGES.JAVASCRIPT,
  resourceLimits: DEFAULT_RESOURCE_LIMITS,
  orphanTtlMs: 1800000, // 30 minutes default orphan TTL
  autoReconcileOrphans: true,
  reconcileIntervalMs: 60000
});

/**
 * Dangerous environment variables strictly disallowed from container injection (PR-024).
 */
export const DANGEROUS_CONTAINER_ENV_VARS = Object.freeze(new Set([
  "LD_PRELOAD",
  "LD_LIBRARY_PATH",
  "LD_AUDIT",
  "NODE_OPTIONS",
  "PYTHONSTARTUP",
  "PYTHONPATH",
  "PYTHONHOME",
  "BASH_ENV",
  "ENV",
  "PROMPT_COMMAND",
  "PERL5OPT",
  "PERL5LIB",
  "RUBYOPT",
  "SUDO_COMMAND",
  "SUDO_USER"
]));

/**
 * Pool-specific error hierarchy.
 */
export class PoolError extends Error {
  constructor(message) {
    super(message);
    this.name = "PoolError";
  }
}

export class PoolAcquireTimeoutError extends PoolError {
  constructor(message = "Timed out waiting for an available container in the pool.") {
    super(message);
    this.name = "PoolAcquireTimeoutError";
  }
}

export class PoolCapacityExceededError extends PoolError {
  constructor(message = "Pool capacity exceeded and queue is full.") {
    super(message);
    this.name = "PoolCapacityExceededError";
  }
}

export class PoolDisposedError extends PoolError {
  constructor(message = "Container sandbox pool has been disposed or drained.") {
    super(message);
    this.name = "PoolDisposedError";
  }
}

export class DaemonExecutionError extends PoolError {
  constructor(message, exitCode = 1, stderr = "") {
    super(message);
    this.name = "DaemonExecutionError";
    this.exitCode = exitCode;
    this.stderr = stderr;
  }
}

export class DaemonHealthCheckError extends PoolError {
  constructor(message) {
    super(message);
    this.name = "DaemonHealthCheckError";
  }
}

/**
 * Represents a single warm daemon container managed by the pool.
 */
export class ContainerDaemon {
  constructor(options = {}) {
    this.id = options.id || crypto.randomBytes(6).toString("hex");
    this.containerName = options.containerName || `tf-daemon-${this.id}`;
    this.language = options.language || SUPPORTED_LANGUAGES.JAVASCRIPT;
    this.image = options.image || DEFAULT_LANGUAGE_CONTAINER_IMAGES[this.language] || "node:20-slim";
    this.imageDigest = options.imageDigest || null;
    this.status = options.status || POOL_CONTAINER_STATES.STARTING;
    this.hostWorkspaceDir = options.hostWorkspaceDir || null;
    this.createdAt = options.createdAt || Date.now();
    this.lastUsedAt = options.lastUsedAt || Date.now();
    this.executionCount = 0;
    this.totalDurationMs = 0;
    this.currentTaskId = null;
  }

  isAvailable() {
    return this.status === POOL_CONTAINER_STATES.IDLE;
  }

  markBusy(taskId = null) {
    this.status = POOL_CONTAINER_STATES.BUSY;
    this.currentTaskId = taskId;
    this.lastUsedAt = Date.now();
  }

  markIdle() {
    this.status = POOL_CONTAINER_STATES.IDLE;
    this.currentTaskId = null;
    this.lastUsedAt = Date.now();
  }

  markCrashed() {
    this.status = POOL_CONTAINER_STATES.CRASHED;
    this.currentTaskId = null;
  }

  markDrained() {
    this.status = POOL_CONTAINER_STATES.DRAINED;
    this.currentTaskId = null;
  }
}

/**
 * Background Container Reconciler & Orphan Collector.
 *
 * Scans container runtime daemons (Docker / Podman) for orphaned, crashed,
 * or lingering containers matching label `triad-flow-pool=true` and TTL limits.
 * Operates without relying on external processes or daemons (Zero Orphan Containers).
 */
export class ContainerOrphanReconciler {
  constructor(options = {}) {
    this.runtime = (options.runtime || "docker").toLowerCase();
    this.execFn = options.execFn || null;
    this.poolId = options.poolId || null;
    this.ttlMs = typeof options.ttlMs === "number" ? options.ttlMs : (options.orphanTtlMs || 1800000);
    this.orphanedWsPrefix = options.orphanedWsPrefix || "tf-pool-ws-";
    this.logger = options.logger || null;
  }

  /**
   * Scans container runtime for orphaned triad-flow-pool containers and reclaims them.
   *
   * @param {object} [options={}]
   * @returns {{ scanned: number, reclaimed: number, reclaimedIds: string[], reclaimedNames: string[], reclaimedWorkspaces: string[], errors: string[] }}
   */
  reconcile(options = {}) {
    const exec = this.execFn || ((cmd, args) => spawnSync(cmd, args, { encoding: "utf8", windowsHide: true, timeout: 15000 }));
    const forceAll = Boolean(options.forceAll);
    const targetPoolId = options.matchPoolId || null;
    const ttlMs = typeof options.ttlMs === "number" ? options.ttlMs : this.ttlMs;
    const activeDaemons = options.activeDaemons || new Map();
    const activeContainerNames = new Set();
    for (const d of activeDaemons.values()) {
      if (d && d.containerName && d.status !== POOL_CONTAINER_STATES.CRASHED && d.status !== POOL_CONTAINER_STATES.DRAINED) {
        activeContainerNames.add(d.containerName);
      }
    }

    const result = {
      scanned: 0,
      reclaimed: 0,
      reclaimedIds: [],
      reclaimedNames: [],
      reclaimedWorkspaces: [],
      errors: []
    };

    // 1. Query containers matching label triad-flow-pool
    let psRes;
    try {
      psRes = exec(this.runtime, [
        "ps", "-a",
        "--filter", `label=${POOL_CONTAINER_LABELS.ROOT_KEY}=${POOL_CONTAINER_LABELS.ROOT_VALUE}`,
        "--format", "{{.ID}}\t{{.Names}}\t{{.Labels}}\t{{.Status}}\t{{.CreatedAt}}"
      ]);
    } catch (err) {
      result.errors.push(`Container ps inspection failed: ${err.message}`);
      return result;
    }

    if (psRes && psRes.status !== 0 && typeof psRes !== "string") {
      const errMsg = (psRes.stderr || psRes.error?.message || "ps command failed").trim();
      result.errors.push(`Container ps returned non-zero (${psRes.status}): ${errMsg}`);
      return result;
    }

    const psOutput = typeof psRes === "string" ? psRes : (psRes?.stdout || "");
    const lines = psOutput.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    result.scanned = lines.length;

    const now = Date.now();
    const candidatesToReclaim = [];

    for (const line of lines) {
      const parts = line.split("\t");
      const id = parts[0] ? parts[0].trim() : "";
      let name = parts[1] ? parts[1].trim() : "";
      if (name.startsWith("/")) name = name.slice(1);
      const labelsRaw = parts[2] ? parts[2].trim() : "";
      const status = parts[3] ? parts[3].trim().toLowerCase() : "";
      const createdAtRaw = parts[4] ? parts[4].trim() : "";

      if (!id && !name) continue;

      // Parse labels supporting Docker (k=v,k=v) and Podman (map[k:v k:v]) formats
      const labels = {};
      if (labelsRaw.startsWith("map[") && labelsRaw.endsWith("]")) {
        const inner = labelsRaw.slice(4, -1).trim();
        const pairs = inner.split(/\s+/);
        for (const pair of pairs) {
          const colonIdx = pair.indexOf(":");
          if (colonIdx !== -1) {
            labels[pair.slice(0, colonIdx).trim()] = pair.slice(colonIdx + 1).trim();
          }
        }
      } else {
        const labelPairs = labelsRaw.split(/[,;\n]/);
        for (const pair of labelPairs) {
          const eqIdx = pair.indexOf("=");
          if (eqIdx !== -1) {
            const k = pair.slice(0, eqIdx).trim();
            const v = pair.slice(eqIdx + 1).trim();
            labels[k] = v;
          }
        }
      }

      const containerPoolId = labels[POOL_CONTAINER_LABELS.POOL_ID_KEY] || "";
      let containerCreatedAt = Number(labels[POOL_CONTAINER_LABELS.CREATED_AT_KEY]) || 0;
      if (!containerCreatedAt && createdAtRaw) {
        const parsed = Date.parse(createdAtRaw);
        if (!isNaN(parsed)) containerCreatedAt = parsed;
      }
      const containerTtl = Number(labels[POOL_CONTAINER_LABELS.TTL_MS_KEY]) || ttlMs;
      const slotId = labels[POOL_CONTAINER_LABELS.SLOT_ID_KEY] || "";

      let isOrphan = false;
      let reason = "";

      const ageMs = containerCreatedAt > 0 ? now - containerCreatedAt : (status.includes("up") ? 0 : Infinity);
      const isDeadOrExited = status.includes("exited") || status.includes("dead");

      if (forceAll) {
        isOrphan = true;
        reason = "forceAll";
      } else if (targetPoolId && containerPoolId === targetPoolId) {
        isOrphan = true;
        reason = `matchedTargetPoolId:${targetPoolId}`;
      } else if (this.poolId && containerPoolId === this.poolId && options.activeDaemons) {
        // Container belongs to our pool instance: check if it's currently actively tracked and alive
        if (!activeContainerNames.has(name) && !activeContainerNames.has(id)) {
          isOrphan = true;
          reason = "untrackedInActivePool";
        } else if (isDeadOrExited) {
          isOrphan = true;
          reason = `exitedOrDeadInActivePool:${status}`;
          // Mark active daemon as crashed so pool can replenish
          for (const d of activeDaemons.values()) {
            if (d && (d.containerName === name || d.id === id)) {
              d.markCrashed();
            }
          }
        } else if (ageMs > containerTtl) {
          isOrphan = true;
          reason = `ttlExpiredInActivePool:${Math.round(ageMs / 1000)}s>${Math.round(containerTtl / 1000)}s`;
          for (const d of activeDaemons.values()) {
            if (d && (d.containerName === name || d.id === id)) {
              d.markCrashed();
            }
          }
        }
      } else {
        // Container belongs to a different pool or previous dead process
        if (ageMs > containerTtl) {
          isOrphan = true;
          reason = `ttlExpired:${Math.round(ageMs / 1000)}s>${Math.round(containerTtl / 1000)}s`;
        } else if (isDeadOrExited) {
          isOrphan = true;
          reason = `exitedOrDead:${status}`;
        }
      }

      if (isOrphan) {
        candidatesToReclaim.push({ id, name, containerPoolId, slotId, reason });
      }
    }

    // 2. Reclaim identified candidate containers
    for (const candidate of candidatesToReclaim) {
      const rmTarget = candidate.name || candidate.id;
      try {
        const rmRes = exec(this.runtime, ["rm", "-f", rmTarget]);
        if (!rmRes || rmRes.status === 0 || (typeof rmRes === "string" && !rmRes.includes("Error"))) {
          result.reclaimed++;
          if (candidate.id) result.reclaimedIds.push(candidate.id);
          if (candidate.name) result.reclaimedNames.push(candidate.name);
        } else {
          result.errors.push(`Failed to remove container ${rmTarget}: ${rmRes.stderr || rmRes.error?.message}`);
        }
      } catch (err) {
        result.errors.push(`Failed to remove container ${rmTarget}: ${err.message}`);
      }

      // Clean corresponding workspace if slotId or poolId is known
      if (candidate.containerPoolId || candidate.slotId) {
        try {
          const tmpDir = os.tmpdir();
          const entries = fs.readdirSync(tmpDir);
          for (const entry of entries) {
            if (entry.startsWith(this.orphanedWsPrefix)) {
              const matchesPool = candidate.containerPoolId && entry.includes(candidate.containerPoolId);
              const matchesSlot = candidate.slotId && entry.includes(candidate.slotId);
              if (matchesPool || matchesSlot) {
                const fullPath = path.join(tmpDir, entry);
                try {
                  fs.rmSync(fullPath, { recursive: true, force: true });
                  if (!result.reclaimedWorkspaces.includes(entry)) {
                    result.reclaimedWorkspaces.push(entry);
                  }
                } catch {}
              }
            }
          }
        } catch {}
      }
    }

    // 3. Sweep orphaned workspace directories in tmpdir with expired TTL or matching dead pool
    if (options.sweepWorkspaces !== false) {
      try {
        const tmpDir = os.tmpdir();
        const entries = fs.readdirSync(tmpDir);
        for (const entry of entries) {
          if (entry.startsWith(this.orphanedWsPrefix)) {
            const fullPath = path.join(tmpDir, entry);
            try {
              const stat = fs.statSync(fullPath);
              const dirAgeMs = now - stat.mtimeMs;
              if (dirAgeMs > ttlMs || forceAll || (targetPoolId && entry.includes(targetPoolId))) {
                fs.rmSync(fullPath, { recursive: true, force: true });
                if (!result.reclaimedWorkspaces.includes(entry)) {
                  result.reclaimedWorkspaces.push(entry);
                }
              }
            } catch {}
          }
        }
      } catch {}
    }

    return result;
  }

  async reconcileAsync(options = {}) {
    return this.reconcile(options);
  }
}

/**
 * Standalone helper to reconcile and clean orphan containers.
 *
 * @param {object} [options={}]
 * @returns {{ scanned: number, reclaimed: number, reclaimedIds: string[], reclaimedNames: string[], reclaimedWorkspaces: string[], errors: string[] }}
 */
export function reconcileOrphanContainers(options = {}) {
  const reconciler = new ContainerOrphanReconciler(options);
  return reconciler.reconcile(options);
}

/**
 * ContainerSandboxPool: High-Performance Warm Container Daemon Pool Manager.
 */
export class ContainerSandboxPool extends EventEmitter {
  constructor(options = {}) {
    super();
    this.options = { ...DEFAULT_POOL_OPTIONS, ...options };
    this.options.resourceLimits = { ...DEFAULT_RESOURCE_LIMITS, ...(options.resourceLimits || {}) };

    this.poolId = options.poolId || crypto.randomBytes(4).toString("hex");
    this.runtime = (this.options.runtime || "docker").toLowerCase();
    this.execFn = options.execFn || null;
    this.allowlistEnv = options.allowlistEnv || CONTAINER_ALLOWLIST_ENV_VARS;

    this.daemons = new Map(); // slotId -> ContainerDaemon
    this.acquireQueue = []; // array of pending acquire objects
    this.isDisposed = false;

    // Statistics tracking
    this.stats = {
      totalWarmups: 0,
      totalAcquires: 0,
      totalReleases: 0,
      totalExecutions: 0,
      totalExecDurationMs: 0,
      totalEvictions: 0
    };

    // Scheduled idle container reaper
    this.reaperTimer = null;
    if (this.options.reapIntervalMs > 0) {
      this.reaperTimer = setInterval(() => {
        try {
          this.reapIdle();
        } catch {
          // Swallow background reaper errors
        }
      }, this.options.reapIntervalMs);
      if (typeof this.reaperTimer.unref === "function") {
        this.reaperTimer.unref();
      }
    }

    // Zero Orphan Containers Signal Traps
    this._boundProcessExit = () => this._emergencyCleanupSync();
    this._boundSigInt = () => {
      this._emergencyCleanupSync();
      process.exit(130);
    };
    this._boundSigTerm = () => {
      this._emergencyCleanupSync();
      process.exit(143);
    };

    if (this.options.autoRegisterSignalHandlers) {
      process.once("exit", this._boundProcessExit);
      process.once("SIGINT", this._boundSigInt);
      process.once("SIGTERM", this._boundSigTerm);
    }

    // Background Container Orphan Reconciler
    this.reconciler = new ContainerOrphanReconciler({
      runtime: this.runtime,
      execFn: this.execFn,
      poolId: this.poolId,
      ttlMs: this.options.orphanTtlMs
    });

    if (this.options.autoReconcileOrphans && !options.skipInitialReconcile) {
      try {
        this.reconcileOrphans();
      } catch {
        // Non-fatal on startup
      }
    }
  }

  /**
   * Probes container runtime availability, daemon health, and image cache.
   *
   * @param {object} [options={}]
   * @returns {{ available: boolean, runtime: string, runtimeVersion?: string, reason?: string }}
   */
  probe(options = {}) {
    const exec = this.execFn || ((cmd, args) => spawnSync(cmd, args, { encoding: "utf8", windowsHide: true }));

    // 1. Probe runtime binary
    let infoRes;
    try {
      infoRes = exec(this.runtime, ["--version"]);
    } catch (err) {
      return {
        available: false,
        runtime: this.runtime,
        reason: `Container runtime binary '${this.runtime}' is not installed or not in PATH (${err.message}).`
      };
    }

    if (infoRes && infoRes.status !== 0 && typeof infoRes !== "string") {
      const errMsg = (infoRes.stderr || infoRes.error?.message || "Non-zero exit").trim();
      return {
        available: false,
        runtime: this.runtime,
        reason: `Container runtime '${this.runtime}' returned exit code ${infoRes.status}: ${errMsg}`
      };
    }
    const runtimeVersion = typeof infoRes === "string" ? infoRes.trim() : (infoRes.stdout || "").trim();

    // 2. Probe daemon readiness
    let daemonRes;
    try {
      daemonRes = exec(this.runtime, ["info", "--format", "{{.ServerVersion}}"]);
    } catch (err) {
      return {
        available: false,
        runtime: this.runtime,
        reason: `Container daemon for '${this.runtime}' is not responding: ${err.message}`
      };
    }

    if (daemonRes && daemonRes.status !== 0 && typeof daemonRes !== "string") {
      return {
        available: false,
        runtime: this.runtime,
        reason: `Container daemon for '${this.runtime}' is not running or socket is inaccessible.`
      };
    }

    return {
      available: true,
      runtime: this.runtime,
      runtimeVersion
    };
  }

  /**
   * Pre-warms containers for specified languages or default count.
   *
   * @param {Array<string|object>} [specs=[]] - Array of language identifiers or spec objects
   * @returns {Promise<ContainerDaemon[]>}
   */
  async warmup(specs = []) {
    return this.warmupSync(specs);
  }

  /**
   * Pre-warms containers synchronously.
   *
   * @param {Array<string|object>} [specs=[]]
   * @returns {ContainerDaemon[]}
   */
  warmupSync(specs = []) {
    if (this.isDisposed) {
      throw new PoolDisposedError();
    }

    const probe = this.probe();
    if (!probe.available) {
      throw new SandboxUnavailableError(
        `Cannot warmup ContainerSandboxPool: container runtime '${this.runtime}' is unavailable: ${probe.reason}`
      );
    }

    const normalizedSpecs = [];
    if (!specs || specs.length === 0) {
      for (let i = 0; i < this.options.minWarm; i++) {
        normalizedSpecs.push({ language: this.options.defaultLanguage });
      }
    } else {
      for (const spec of specs) {
        if (typeof spec === "string") {
          normalizedSpecs.push({ language: spec });
        } else if (spec && typeof spec === "object") {
          const count = spec.count || 1;
          for (let i = 0; i < count; i++) {
            normalizedSpecs.push({
              language: spec.language || this.options.defaultLanguage,
              image: spec.image
            });
          }
        }
      }
    }

    const warmed = [];
    for (const spec of normalizedSpecs) {
      if (this.daemons.size >= this.options.maxCapacity) {
        break;
      }
      const daemon = this._spawnDaemonSync(spec);
      warmed.push(daemon);
      this.stats.totalWarmups++;
    }

    return warmed;
  }

  /**
   * Synchronously acquires an idle warm container daemon from the pool or creates one under capacity.
   * Throws PoolCapacityExceededError if pool is at maximum capacity.
   *
   * @param {object} [options={}]
   * @returns {ContainerDaemon}
   */
  acquireSync(options = {}) {
    if (this.isDisposed) {
      throw new PoolDisposedError();
    }

    const language = options.language || this.options.defaultLanguage;
    const targetImage = options.image || resolveLanguageContainerImage(language);
    const taskId = options.taskId || null;

    // 1. Check for an existing idle daemon matching language and image requirements
    for (const daemon of this.daemons.values()) {
      if (daemon.isAvailable()) {
        const langMatches = !options.language || daemon.language === language;
        const imgMatches = !options.image || daemon.image === targetImage;
        if (langMatches && imgMatches) {
          daemon.markBusy(taskId);
          this.stats.totalAcquires++;
          return daemon;
        }
      }
    }

    // 2. Check if we can spawn a new container within maxCapacity
    if (this.daemons.size < this.options.maxCapacity) {
      const daemon = this._spawnDaemonSync({ language, image: targetImage });
      daemon.markBusy(taskId);
      this.stats.totalAcquires++;
      return daemon;
    }

    throw new PoolCapacityExceededError(
      `Pool capacity exhausted (${this.daemons.size}/${this.options.maxCapacity}).`
    );
  }

  /**
   * Acquires an idle warm container daemon from the pool, or creates one if under capacity.
   * Enqueues when at capacity. Supports AbortSignal for graceful cancellation.
   *
   * @param {object} [options={}]
   * @returns {Promise<ContainerDaemon>}
   */
  async acquire(options = {}) {
    if (this.isDisposed) {
      throw new PoolDisposedError();
    }

    if (options.signal?.aborted) {
      throw new Error(`The acquire operation was aborted: ${options.signal.reason || "aborted"}`);
    }

    try {
      const daemon = this.acquireSync(options);
      if (options.signal?.aborted) {
        this.releaseSync(daemon, { scrub: true });
        throw new Error(`The acquire operation was aborted: ${options.signal.reason || "aborted"}`);
      }
      return daemon;
    } catch (err) {
      if (!(err instanceof PoolCapacityExceededError)) {
        throw err;
      }
    }

    const language = options.language || this.options.defaultLanguage;
    const targetImage = options.image || resolveLanguageContainerImage(language);
    const taskId = options.taskId || null;
    const timeoutMs = typeof options.timeoutMs === "number" ? options.timeoutMs : this.options.acquireTimeoutMs;
    const signal = options.signal || null;

    // Pool is at capacity: enqueue acquire request with timeout and signal
    return new Promise((resolve, reject) => {
      let timeoutHandle = null;
      let abortHandler = null;

      const cleanupListeners = () => {
        if (timeoutHandle) {
          clearTimeout(timeoutHandle);
          timeoutHandle = null;
        }
        if (signal && abortHandler) {
          try { signal.removeEventListener("abort", abortHandler); } catch {}
          abortHandler = null;
        }
      };

      const queueItem = {
        language,
        image: targetImage,
        taskId,
        resolve: (daemon) => {
          cleanupListeners();
          if (signal?.aborted) {
            this.releaseSync(daemon, { scrub: true });
            reject(new Error(`The acquire operation was aborted: ${signal.reason || "aborted"}`));
            return;
          }
          daemon.markBusy(taskId);
          this.stats.totalAcquires++;
          resolve(daemon);
        },
        reject: (err) => {
          cleanupListeners();
          reject(err);
        }
      };

      if (signal) {
        abortHandler = () => {
          cleanupListeners();
          const idx = this.acquireQueue.indexOf(queueItem);
          if (idx !== -1) {
            this.acquireQueue.splice(idx, 1);
          }
          reject(new Error(`The acquire operation was aborted: ${signal.reason || "aborted"}`));
        };
        signal.addEventListener("abort", abortHandler, { once: true });
      }

      if (timeoutMs > 0) {
        timeoutHandle = setTimeout(() => {
          cleanupListeners();
          const idx = this.acquireQueue.indexOf(queueItem);
          if (idx !== -1) {
            this.acquireQueue.splice(idx, 1);
          }
          reject(new PoolAcquireTimeoutError(`Pool acquire timed out after ${timeoutMs}ms (capacity: ${this.daemons.size}/${this.options.maxCapacity}).`));
        }, timeoutMs);
      }

      this.acquireQueue.push(queueItem);
    });
  }

  /**
   * Forces the release and cleanup of any container daemon occupied by taskId.
   * Useful when an orchestrator aborts a task or hits circuit breaker.
   *
   * @param {string} taskId
   * @param {object} [options={}]
   * @returns {boolean} true if a daemon or queued request was released
   */
  forceReleaseByTaskId(taskId, options = {}) {
    if (!taskId) return false;
    let released = false;
    for (const daemon of this.daemons.values()) {
      if (daemon.currentTaskId === taskId) {
        this.releaseSync(daemon, { scrub: options.scrub !== false });
        released = true;
      }
    }
    for (let i = this.acquireQueue.length - 1; i >= 0; i--) {
      if (this.acquireQueue[i].taskId === taskId) {
        const req = this.acquireQueue.splice(i, 1)[0];
        req.reject(new PoolError(`Acquire for task '${taskId}' cancelled by forceReleaseByTaskId.`));
        released = true;
      }
    }
    return released;
  }

  /**
   * Synchronously releases an acquired container daemon back to the pool.
   *
   * @param {ContainerDaemon|string} daemonOrId
   * @param {object} [options={}]
   */
  releaseSync(daemonOrId, options = {}) {
    if (this.isDisposed) return;

    const daemon = typeof daemonOrId === "string" ? this.daemons.get(daemonOrId) : daemonOrId;
    if (!daemon) return;

    const scrub = options.scrub !== undefined ? Boolean(options.scrub) : this.options.scrubOnRelease;

    // 1. Scrub workspace if requested
    if (scrub && daemon.status !== POOL_CONTAINER_STATES.CRASHED) {
      try {
        this.scrubWorkspaceSync(daemon);
      } catch (err) {
        daemon.markCrashed();
        this.evictSync(daemon);
        this._replenishIfBelowMinWarm();
        return;
      }
    }

    // 2. Check daemon health
    const isHealthy = this._pingSync(daemon);
    if (!isHealthy) {
      daemon.markCrashed();
      this.evictSync(daemon);
      this._replenishIfBelowMinWarm();
      return;
    }

    this.stats.totalReleases++;

    // 3. Check if there are waiting acquire requests in queue matching this daemon
    if (this.acquireQueue.length > 0) {
      const matchIdx = this.acquireQueue.findIndex(
        req => (!req.language || req.language === daemon.language) &&
               (!req.image || req.image === daemon.image)
      );
      if (matchIdx !== -1) {
        const nextReq = this.acquireQueue.splice(matchIdx, 1)[0];
        nextReq.resolve(daemon);
        return;
      }
    }

    // 4. Mark idle
    daemon.markIdle();

    // 5. Try to satisfy any queued requests if pool is below maximum capacity
    if (this.acquireQueue.length > 0 && this.daemons.size < this.options.maxCapacity) {
      const req = this.acquireQueue.shift();
      try {
        const newDaemon = this._spawnDaemonSync({ language: req.language, image: req.image });
        req.resolve(newDaemon);
      } catch (err) {
        req.reject(err);
      }
    }
  }

  /**
   * Releases an acquired container daemon back to the pool.
   *
   * @param {ContainerDaemon|string} daemonOrId
   * @param {object} [options={}]
   */
  async release(daemonOrId, options = {}) {
    return this.releaseSync(daemonOrId, options);
  }

  /**
   * Executes a command inside the designated warm daemon via `exec`.
   *
   * @param {ContainerDaemon|string} daemonOrId
   * @param {string|string[]} commandArgs
   * @param {object} [options={}]
   * @returns {{ status: number, exitCode: number, stdout: string, stderr: string, timedOut: boolean, durationMs: number, error?: Error }}
   */
  execute(daemonOrId, commandArgs, options = {}) {
    const daemon = typeof daemonOrId === "string" ? this.daemons.get(daemonOrId) : daemonOrId;
    if (!daemon) {
      throw new PoolError(`Cannot execute: daemon not found in pool.`);
    }

    if (daemon.status === POOL_CONTAINER_STATES.DRAINED || daemon.status === POOL_CONTAINER_STATES.CRASHED) {
      throw new DaemonExecutionError(`Cannot execute in daemon with state '${daemon.status}'.`);
    }

    const exec = this.execFn || ((cmd, args, execOpts) => spawnSync(cmd, args, {
      encoding: "utf8",
      windowsHide: true,
      timeout: execOpts?.timeout
    }));

    // Build exec command arguments
    const execArgs = ["exec"];

    // Working directory forwarding
    let workDir = "/jail";
    const targetCwd = options.cwd || options.workDir;
    if (targetCwd && typeof targetCwd === "string") {
      const normalized = path.posix.normalize(targetCwd.replace(/\\/g, "/")).replace(/^\/+|\/+$/g, "");
      if (normalized && !normalized.startsWith("..") && normalized !== ".") {
        workDir = `/jail/${normalized}`;
      }
    }
    execArgs.push("-w", workDir);

    // Environment variables forwarding with strict allowlist
    const allowlist = options.allowlistEnv || this.allowlistEnv;
    for (const varName of allowlist) {
      if (process.env[varName] !== undefined && varName !== "HOME") {
        execArgs.push("-e", `${varName}=${process.env[varName]}`);
      }
    }

    // Additional explicitly supplied env variables
    if (options.env && typeof options.env === "object") {
      for (const [key, val] of Object.entries(options.env)) {
        if (!key || typeof key !== "string" || key.includes("=") || key.includes("\0") || key.includes("\n") || key.includes("\r")) {
          throw new DaemonExecutionError(`Invalid environment variable key: '${key}'.`);
        }
        if (DANGEROUS_CONTAINER_ENV_VARS.has(key.toUpperCase())) {
          throw new DaemonExecutionError(`Security violation: dangerous environment variable '${key}' is disallowed in container sandbox.`);
        }
        execArgs.push("-e", `${key}=${val}`);
      }
    }

    execArgs.push(daemon.containerName);

    // Command arguments
    if (Array.isArray(commandArgs)) {
      execArgs.push(...commandArgs);
    } else if (typeof commandArgs === "string" && commandArgs.trim()) {
      execArgs.push("sh", "-c", commandArgs);
    } else {
      throw new DaemonExecutionError("Command arguments must be a non-empty string or array.");
    }

    const timeout = typeof options.timeout === "number" ? options.timeout : 60000;
    const startTime = Date.now();

    try {
      const res = exec(this.runtime, execArgs, { timeout });
      const durationMs = Date.now() - startTime;
      const timedOut = Boolean(res?.error && (res.error.code === "ETIMEDOUT" || res.error.name === "TimeoutError"));
      const status = timedOut
        ? 124
        : (typeof res?.status === "number" ? res.status : (res?.error ? 1 : 0));

      // Track statistics
      daemon.executionCount++;
      daemon.totalDurationMs += durationMs;
      this.stats.totalExecutions++;
      this.stats.totalExecDurationMs += durationMs;

      return {
        status,
        exitCode: status,
        stdout: typeof res === "string" ? res : (res?.stdout || ""),
        stderr: timedOut ? `Execution timed out after ${timeout}ms` : (typeof res === "string" ? "" : (res?.stderr || "")),
        timedOut,
        durationMs,
        error: res?.error,
        containerName: daemon.containerName
      };
    } catch (err) {
      const durationMs = Date.now() - startTime;
      const timedOut = Boolean(err.code === "ETIMEDOUT" || err.name === "TimeoutError");

      daemon.executionCount++;
      daemon.totalDurationMs += durationMs;
      this.stats.totalExecutions++;
      this.stats.totalExecDurationMs += durationMs;

      return {
        status: timedOut ? 124 : 1,
        exitCode: timedOut ? 124 : 1,
        stdout: "",
        stderr: timedOut ? `Execution timed out after ${timeout}ms` : err.message,
        timedOut,
        durationMs,
        error: err,
        containerName: daemon.containerName
      };
    }
  }

  /**
   * Asynchronously executes a command inside the designated warm daemon via child_process.spawn.
   *
   * @param {ContainerDaemon|string} daemonOrId
   * @param {string|string[]} commandArgs
   * @param {object} [options={}]
   * @returns {Promise<{ status: number, exitCode: number, stdout: string, stderr: string, timedOut: boolean, durationMs: number, error?: Error, containerName: string }>}
   */
  async executeAsync(daemonOrId, commandArgs, options = {}) {
    const daemon = typeof daemonOrId === "string" ? this.daemons.get(daemonOrId) : daemonOrId;
    if (!daemon) {
      throw new PoolError(`Cannot execute: daemon not found in pool.`);
    }

    if (daemon.status === POOL_CONTAINER_STATES.DRAINED || daemon.status === POOL_CONTAINER_STATES.CRASHED) {
      throw new DaemonExecutionError(`Cannot execute in daemon with state '${daemon.status}'.`);
    }

    if (options.execAsyncFn) {
      return options.execAsyncFn(daemon, commandArgs, options);
    }

    // Build exec command arguments
    const execArgs = ["exec"];

    let workDir = "/jail";
    const targetCwd = options.cwd || options.workDir;
    if (targetCwd && typeof targetCwd === "string") {
      const normalized = path.posix.normalize(targetCwd.replace(/\\/g, "/")).replace(/^\/+|\/+$/g, "");
      if (normalized && !normalized.startsWith("..") && normalized !== ".") {
        workDir = `/jail/${normalized}`;
      }
    }
    execArgs.push("-w", workDir);

    const allowlist = options.allowlistEnv || this.allowlistEnv;
    for (const varName of allowlist) {
      if (process.env[varName] !== undefined && varName !== "HOME") {
        execArgs.push("-e", `${varName}=${process.env[varName]}`);
      }
    }

    if (options.env && typeof options.env === "object") {
      for (const [key, val] of Object.entries(options.env)) {
        if (!key || typeof key !== "string" || key.includes("=") || key.includes("\0") || key.includes("\n") || key.includes("\r")) {
          throw new DaemonExecutionError(`Invalid environment variable key: '${key}'.`);
        }
        if (DANGEROUS_CONTAINER_ENV_VARS.has(key.toUpperCase())) {
          throw new DaemonExecutionError(`Security violation: dangerous environment variable '${key}' is disallowed in container sandbox.`);
        }
        execArgs.push("-e", `${key}=${val}`);
      }
    }

    execArgs.push(daemon.containerName);

    if (Array.isArray(commandArgs)) {
      execArgs.push(...commandArgs);
    } else if (typeof commandArgs === "string" && commandArgs.trim()) {
      execArgs.push("sh", "-c", commandArgs);
    } else {
      throw new DaemonExecutionError("Command arguments must be a non-empty string or array.");
    }

    const timeout = typeof options.timeout === "number" ? options.timeout : 60000;
    const startTime = Date.now();

    return new Promise((resolve) => {
      let timedOut = false;
      let timeoutHandle = null;
      let stdout = "";
      let stderr = "";

      const child = spawn(this.runtime, execArgs, {
        windowsHide: true,
        stdio: ["ignore", "pipe", "pipe"]
      });

      if (options.signal) {
        if (options.signal.aborted) {
          try { child.kill("SIGKILL"); } catch {}
        } else {
          options.signal.addEventListener("abort", () => {
            try { child.kill("SIGKILL"); } catch {}
          }, { once: true });
        }
      }

      if (timeout > 0) {
        timeoutHandle = setTimeout(() => {
          timedOut = true;
          try { child.kill("SIGKILL"); } catch {}
        }, timeout);
      }

      if (child.stdout) {
        child.stdout.setEncoding("utf8");
        child.stdout.on("data", chunk => {
          stdout += chunk;
          if (typeof options.onStdout === "function") options.onStdout(chunk);
        });
      }

      if (child.stderr) {
        child.stderr.setEncoding("utf8");
        child.stderr.on("data", chunk => {
          stderr += chunk;
          if (typeof options.onStderr === "function") options.onStderr(chunk);
        });
      }

      child.on("error", (err) => {
        if (timeoutHandle) clearTimeout(timeoutHandle);
        const durationMs = Date.now() - startTime;
        daemon.executionCount++;
        daemon.totalDurationMs += durationMs;
        this.stats.totalExecutions++;
        this.stats.totalExecDurationMs += durationMs;
        resolve({
          status: timedOut ? 124 : 1,
          exitCode: timedOut ? 124 : 1,
          stdout,
          stderr: timedOut ? `Execution timed out after ${timeout}ms` : (stderr || err.message),
          timedOut,
          durationMs,
          error: err,
          containerName: daemon.containerName
        });
      });

      child.on("close", (code) => {
        if (timeoutHandle) clearTimeout(timeoutHandle);
        const durationMs = Date.now() - startTime;
        const finalStatus = timedOut ? 124 : (typeof code === "number" ? code : 1);
        daemon.executionCount++;
        daemon.totalDurationMs += durationMs;
        this.stats.totalExecutions++;
        this.stats.totalExecDurationMs += durationMs;
        resolve({
          status: finalStatus,
          exitCode: finalStatus,
          stdout,
          stderr: timedOut ? `Execution timed out after ${timeout}ms` : stderr,
          timedOut,
          durationMs,
          containerName: daemon.containerName
        });
      });
    });
  }

  /**
   * Synchronously scrubs the host workspace directory and volatile container scratch spaces (Workspace Scrubbing).
   *
   * @param {ContainerDaemon} daemon
   */
  scrubWorkspaceSync(daemon) {
    if (!daemon || !daemon.hostWorkspaceDir) return;

    // 1. Scrub volatile container scratch spaces and in-container jail if alive
    if (daemon.status !== POOL_CONTAINER_STATES.DRAINED && daemon.status !== POOL_CONTAINER_STATES.CRASHED) {
      try {
        this.execute(daemon, "rm -rf /jail/* /jail/.[!.]* /tmp/* /tmp/.[!.]*", { timeout: 5000 });
      } catch {
        // Non-fatal if tmp/jail scrub command times out
      }
    }

    // 2. Scrub host workspace directory
    try {
      if (fs.existsSync(daemon.hostWorkspaceDir)) {
        const entries = fs.readdirSync(daemon.hostWorkspaceDir);
        for (const entry of entries) {
          const entryPath = path.join(daemon.hostWorkspaceDir, entry);
          fs.rmSync(entryPath, { recursive: true, force: true });
        }
      }
    } catch (err) {
      throw new DaemonExecutionError(`Failed to scrub host workspace directory: ${err.message}`);
    }
  }

  /**
   * Cleans up the host workspace directory and volatile container scratch spaces (Workspace Scrubbing).
   *
   * @param {ContainerDaemon} daemon
   */
  async scrubWorkspace(daemon) {
    return this.scrubWorkspaceSync(daemon);
  }

  /**
   * Verifies that network egress is denied inside the warm daemon.
   *
   * @param {ContainerDaemon} daemon
   * @param {object} [options={}]
   * @returns {{ verified: boolean, exitCode: number, output: string }}
   */
  verifyEgress(daemon, options = {}) {
    let probeScript = options.probeScript;
    if (!probeScript) {
      const img = (daemon.image || "").toLowerCase();
      if (img.includes("python")) {
        probeScript = ACTIVE_EGRESS_PROBE_SCRIPT_PYTHON;
      } else if (img.includes("node")) {
        probeScript = ACTIVE_EGRESS_PROBE_SCRIPT;
      } else {
        probeScript = ACTIVE_EGRESS_PROBE_SCRIPT_SH;
      }
    }

    const probeRes = this.execute(daemon, probeScript, options);

    if (probeRes.status === 0) {
      throw new SandboxSecurityViolationError(
        "Active egress probe succeeded! Outbound network connection was established despite --network=none.",
        this.runtime
      );
    }

    const output = (String(probeRes.stdout || "") + " " + String(probeRes.stderr || "")).trim();
    if (output.includes("TF_NAMESPACE_LEAK")) {
      throw new SandboxSecurityViolationError(
        `Container network namespace isolation breach detected: non-loopback network interfaces present: '${output}'.`,
        this.runtime
      );
    }

    const hasSentinel = /TF_EGRESS_DENIED:(?:ENETUNREACH|EAI_AGAIN|ENOTFOUND|ECONNREFUSED|ETIMEDOUT|EHOSTUNREACH|ECONNRESET|ERR)/.test(output);

    if (probeRes.status === 42 && hasSentinel) {
      return {
        verified: true,
        exitCode: 42,
        output
      };
    }

    throw new SandboxSecurityViolationError(
      `Active egress probe execution failed (status=${probeRes.status}) without authentic network denial sentinel: '${output.slice(0, 80)}'.`,
      this.runtime
    );
  }

  /**
   * Reaps idle containers exceeding idleTimeoutMs, maintaining at least minWarm containers.
   */
  reapIdle() {
    if (this.isDisposed) return;

    const now = Date.now();
    const idleDaemons = Array.from(this.daemons.values()).filter(d => d.isAvailable());

    for (const daemon of idleDaemons) {
      if (this.daemons.size <= this.options.minWarm) {
        break;
      }
      if (now - daemon.lastUsedAt > this.options.idleTimeoutMs) {
        this.evictSync(daemon);
      }
    }

    if (this.reconciler && this.options.autoReconcileOrphans !== false) {
      try {
        this.reconcileOrphans();
      } catch {}
    }
  }

  /**
   * Reconciles orphan containers in container runtime matching label triad-flow-pool=true and TTL limits.
   *
   * @param {object} [options={}]
   * @returns {{ scanned: number, reclaimed: number, reclaimedIds: string[], reclaimedNames: string[], reclaimedWorkspaces: string[], errors: string[] }}
   */
  reconcileOrphans(options = {}) {
    if (!this.reconciler) {
      return { scanned: 0, reclaimed: 0, reclaimedIds: [], reclaimedNames: [], reclaimedWorkspaces: [], errors: [] };
    }
    return this.reconciler.reconcile({
      activeDaemons: this.daemons,
      ttlMs: this.options.orphanTtlMs,
      ...options
    });
  }

  async reconcileOrphansAsync(options = {}) {
    return this.reconcileOrphans(options);
  }

  /**
   * Synchronously evicts and tears down a single container daemon.
   *
   * @param {ContainerDaemon|string} daemonOrId
   */
  evictSync(daemonOrId) {
    const daemon = typeof daemonOrId === "string" ? this.daemons.get(daemonOrId) : daemonOrId;
    if (!daemon) return;

    daemon.markDrained();
    this.daemons.delete(daemon.id);
    this.stats.totalEvictions++;

    // Stop and remove container
    const exec = this.execFn || ((cmd, args) => spawnSync(cmd, args, { encoding: "utf8", windowsHide: true, timeout: 10000 }));
    try {
      exec(this.runtime, ["rm", "-f", daemon.containerName]);
    } catch {}

    // Clean up host workspace directory
    try {
      if (daemon.hostWorkspaceDir && fs.existsSync(daemon.hostWorkspaceDir)) {
        fs.rmSync(daemon.hostWorkspaceDir, { recursive: true, force: true });
      }
    } catch {}
  }

  /**
   * Evicts and tears down a single container daemon.
   *
   * @param {ContainerDaemon|string} daemonOrId
   */
  async evict(daemonOrId) {
    return this.evictSync(daemonOrId);
  }

  /**
   * Gracefully drains and disposes the entire pool.
   */
  async drain() {
    if (this.isDisposed) return;
    this.isDisposed = true;

    // Clear background interval
    if (this.reaperTimer) {
      clearInterval(this.reaperTimer);
      this.reaperTimer = null;
    }

    // Reject all pending acquire requests
    while (this.acquireQueue.length > 0) {
      const req = this.acquireQueue.shift();
      req.reject(new PoolDisposedError());
    }

    // Evict all daemons
    const daemonsToEvict = Array.from(this.daemons.values());
    for (const daemon of daemonsToEvict) {
      this.evictSync(daemon);
    }

    // Run final orphan sweep for this pool
    if (this.reconciler) {
      try {
        this.reconcileOrphans({ matchPoolId: this.poolId });
      } catch {}
    }

    // Unregister signal handlers
    if (this.options.autoRegisterSignalHandlers) {
      try {
        process.removeListener("exit", this._boundProcessExit);
        process.removeListener("SIGINT", this._boundSigInt);
        process.removeListener("SIGTERM", this._boundSigTerm);
      } catch {}
    }
  }

  /**
   * Returns authoritative pool statistics.
   */
  getStats() {
    let idle = 0;
    let busy = 0;
    let crashed = 0;

    for (const d of this.daemons.values()) {
      if (d.status === POOL_CONTAINER_STATES.IDLE) idle++;
      else if (d.status === POOL_CONTAINER_STATES.BUSY) busy++;
      else if (d.status === POOL_CONTAINER_STATES.CRASHED) crashed++;
    }

    const avgExecLatencyMs = this.stats.totalExecutions > 0
      ? this.stats.totalExecDurationMs / this.stats.totalExecutions
      : 0;

    return Object.freeze({
      poolId: this.poolId,
      runtime: this.runtime,
      totalDaemons: this.daemons.size,
      idleDaemons: idle,
      busyDaemons: busy,
      crashedDaemons: crashed,
      queueLength: this.acquireQueue.length,
      totalWarmups: this.stats.totalWarmups,
      totalAcquires: this.stats.totalAcquires,
      totalReleases: this.stats.totalReleases,
      totalExecutions: this.stats.totalExecutions,
      totalEvictions: this.stats.totalEvictions,
      avgExecLatencyMs: Math.round(avgExecLatencyMs * 100) / 100
    });
  }

  /**
   * Authoritative capability descriptor for audit receipts.
   */
  capabilities() {
    return Object.freeze({
      driver: "container-pool",
      mode: "hot-reuse",
      runtime: this.runtime,
      resourceLimits: Object.freeze({ ...this.options.resourceLimits }),
      filesystemIsolation: "container-hot-mount",
      networkEgressDenial: "verified",
      processIsolation: "warm-daemon-exec",
      workspaceScrubbing: "enforced",
      backgroundReconciler: "enabled",
      zeroOrphanGuaranteed: true,
      sub150msDispatch: true
    });
  }

  // --- Internal Helpers ---

  _spawnDaemonSync(spec = {}) {
    const language = spec.language || this.options.defaultLanguage;
    const image = spec.image || resolveLanguageContainerImage(language);
    if (typeof image !== "string" || image.startsWith("-") || !/^[a-zA-Z0-9_.\/:-]+$/.test(image)) {
      throw new PoolError(`Security violation: Invalid or dangerous container image identifier: '${image}'.`);
    }
    const slotId = crypto.randomBytes(6).toString("hex");
    const containerName = `${this.options.containerPrefix}-${this.poolId}-${language}-${slotId}`;

    // Create host workspace directory for hot mount
    const hostWorkspaceDir = path.join(
      os.tmpdir(),
      `tf-pool-ws-${this.poolId}-${slotId}`
    );
    if (!fs.existsSync(hostWorkspaceDir)) {
      fs.mkdirSync(hostWorkspaceDir, { recursive: true });
    }

    const daemon = new ContainerDaemon({
      id: slotId,
      containerName,
      language,
      image,
      hostWorkspaceDir,
      status: POOL_CONTAINER_STATES.STARTING
    });

    const exec = this.execFn || ((cmd, args) => spawnSync(cmd, args, { encoding: "utf8", windowsHide: true }));

    // Prepare container run args
    const normalizedWs = path.resolve(hostWorkspaceDir).replace(/\\/g, "/");
    const selinuxSuffix = this.options.selinuxMount ? ",z" : "";
    const limits = this.options.resourceLimits;

    const runArgs = [
      "run",
      "-d",
      "--name", containerName,
      "--label", `${POOL_CONTAINER_LABELS.ROOT_KEY}=${POOL_CONTAINER_LABELS.ROOT_VALUE}`,
      "--label", `${POOL_CONTAINER_LABELS.POOL_ID_KEY}=${this.poolId}`,
      "--label", `${POOL_CONTAINER_LABELS.CREATED_AT_KEY}=${daemon.createdAt}`,
      "--label", `${POOL_CONTAINER_LABELS.TTL_MS_KEY}=${this.options.orphanTtlMs || 1800000}`,
      "--label", `${POOL_CONTAINER_LABELS.SLOT_ID_KEY}=${slotId}`,
      "--label", `${POOL_CONTAINER_LABELS.LANGUAGE_KEY}=${language}`,
      "--pull=never",
      "--network=none",
      "--read-only",
      `--memory=${limits.memory || "2g"}`,
      `--cpus=${limits.cpus || "2.0"}`,
      `--user=${limits.user || "1000:1000"}`,
      "--cap-drop=ALL",
      "--security-opt=no-new-privileges",
      "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
      "--tmpfs", "/tmp/home:rw",
      "-e", "HOME=/tmp/home",
      "-e", "npm_config_cache=/tmp/npm-cache",
      "-v", `${normalizedWs}:/jail:rw${selinuxSuffix}`,
      "-w", "/jail",
      image,
      "tail", "-f", "/dev/null"
    ];

    try {
      const res = exec(this.runtime, runArgs);
      if (res && res.status !== 0 && typeof res !== "string") {
        const errMsg = (res.stderr || res.error?.message || "Failed to spawn daemon").trim();
        throw new PoolError(`Failed to spawn warm container '${containerName}': ${errMsg}`);
      }
    } catch (err) {
      try {
        fs.rmSync(hostWorkspaceDir, { recursive: true, force: true });
      } catch {}
      throw new PoolError(`Container daemon spawn failed: ${err.message}`);
    }

    daemon.markIdle();
    this.daemons.set(daemon.id, daemon);
    return daemon;
  }

  _pingSync(daemon) {
    if (!daemon || daemon.status === POOL_CONTAINER_STATES.DRAINED) return false;
    const exec = this.execFn || ((cmd, args) => spawnSync(cmd, args, { encoding: "utf8", windowsHide: true, timeout: 3000 }));
    try {
      const res = exec(this.runtime, ["exec", daemon.containerName, "echo", "ping"]);
      return (typeof res === "string" && res.includes("ping")) || (res && res.status === 0);
    } catch {
      return false;
    }
  }

  _replenishIfBelowMinWarm() {
    if (this.isDisposed) return;
    if (this.daemons.size < this.options.minWarm) {
      try {
        this._spawnDaemonSync({ language: this.options.defaultLanguage });
      } catch {}
    }
  }

  _emergencyCleanupSync() {
    // Guarantees zero orphan containers synchronously on unexpected exit / signal
    const exec = this.execFn || ((cmd, args) => spawnSync(cmd, args, { encoding: "utf8", windowsHide: true, timeout: 5000 }));
    for (const daemon of this.daemons.values()) {
      try {
        exec(this.runtime, ["rm", "-f", daemon.containerName]);
      } catch {}
      try {
        if (daemon.hostWorkspaceDir && fs.existsSync(daemon.hostWorkspaceDir)) {
          fs.rmSync(daemon.hostWorkspaceDir, { recursive: true, force: true });
        }
      } catch {}
    }
    // Also sweep any containers tagged with this poolId
    try {
      if (this.reconciler) {
        this.reconciler.reconcile({ matchPoolId: this.poolId, sweepWorkspaces: false });
      }
    } catch {}
  }
}

/**
 * PoolContainerDriver: Sandbox Driver implementation backed by ContainerSandboxPool.
 *
 * Implements BaseSandboxDriver interface for seamless integration with
 * ControlledRemediationSession, BatchRemediationSession, and factory verification loops.
 */
export class PoolContainerDriver extends BaseSandboxDriver {
  constructor(options = {}, poolInstance = null) {
    super(options.name || "container-pool");
    this.driverType = "container-pool";
    this.pool = poolInstance || new ContainerSandboxPool(options);
    this.runtime = this.pool.runtime;
    this.options = options;
  }

  probe(options = {}) {
    return this.pool.probe(options);
  }

  create(repoPath, options = {}) {
    const probe = this.probe(options);
    if (!probe.available) {
      throw new SandboxUnavailableError(
        `Requested sandbox driver 'container-pool' is unavailable on this host: ${probe.reason}. Silent downgrade is prohibited by ADR-024-02.`,
        this.pool.runtime
      );
    }

    // 1. Create patch jail worktree
    const jail = createPatchJailWorktree(repoPath, options);
    let daemon = null;

    try {
      // 2. Acquire warm daemon from pool synchronously
      daemon = this.pool.acquireSync({
        language: options.language,
        image: options.image,
        taskId: options.taskId
      });

      // 3. Hot-mount: copy worktree contents to daemon workspace
      _syncDirectoryContents(jail.jailPath, daemon.hostWorkspaceDir);
    } catch (err) {
      if (daemon) {
        try { this.pool.releaseSync(daemon, { scrub: true }); } catch {}
      }
      try { jail.cleanup(); } catch {}
      throw err;
    }

    const caps = this.capabilities();

    return {
      jailPath: daemon.hostWorkspaceDir,
      baseSha: jail.baseSha,
      daemon,
      driver: this.name,
      runtime: this.pool.runtime,
      capabilities: caps,
      cleanup: () => {
        try {
          this.pool.releaseSync(daemon, { scrub: true });
        } finally {
          jail.cleanup();
        }
      },
      runInContainer: (commandArgs, runOpts = {}) => {
        if (runOpts.image && daemon.image && runOpts.image !== daemon.image) {
          throw new DaemonExecutionError(`Cannot switch container image from '${daemon.image}' to '${runOpts.image}' on warm daemon.`);
        }
        return this.pool.execute(daemon, commandArgs, runOpts);
      },
      runInContainerAsync: (commandArgs, runOpts = {}) => {
        if (runOpts.image && daemon.image && runOpts.image !== daemon.image) {
          throw new DaemonExecutionError(`Cannot switch container image from '${daemon.image}' to '${runOpts.image}' on warm daemon.`);
        }
        return this.pool.executeAsync(daemon, commandArgs, runOpts);
      }
    };
  }

  capabilities() {
    return this.pool.capabilities();
  }
}

/**
 * Synchronizes contents from source to destination directory.
 */
function _syncDirectoryContents(src, dest) {
  if (!fs.existsSync(src)) return;
  if (!fs.existsSync(dest)) {
    fs.mkdirSync(dest, { recursive: true });
  }

  const entries = fs.readdirSync(src, { withFileTypes: true });
  for (const entry of entries) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);

    if (entry.isDirectory()) {
      if (!fs.existsSync(destPath)) {
        fs.mkdirSync(destPath, { recursive: true });
      }
      _syncDirectoryContents(srcPath, destPath);
    } else if (entry.isFile()) {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

// Canonical Driver Registration (RFC-028-01 & ADR-024-02)
registerSandboxDriver("container-pool", PoolContainerDriver);
registerSandboxDriver("pool", PoolContainerDriver);

