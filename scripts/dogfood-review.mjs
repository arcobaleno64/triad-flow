/**
 * Triad-Flow Dogfooding Review (Track D1: Shadow Dogfooding)
 *
 * Implements Phase 4.3 Dogfood Track D1:
 * - Runs Triad-Flow tri-party review on its own repository pull request diff
 * - Mode: SHADOW_DOGFOOD (Advisory / Observation Only, Zero Merge Authority)
 * - Collects operational telemetry:
 *   • Provider completion / malformed-output rate
 *   • Review latency per provider and overall wall-clock latency
 *   • Inter-provider disagreement frequency and solitary blocker vetoes
 *   • Finding provenance and architecture invariant compliance
 * - Emits `dogfood-run.json`
 */

import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { buildChangeSet } from "../src/core/git-collector.mjs";
import { decodeGitCStyleString } from "../src/core/git-numstat.mjs";
import {
  CliReviewAdapter,
  resolveProviderProfile
} from "../src/adapters/cli-transport.mjs";
import { aggregateConsensus } from "../src/core/loop.mjs";
import { evaluateGateDecision } from "../src/core/harness.mjs";
import {
  EXECUTION_STATUS,
  convertProviderResultToSentryReport
} from "../src/adapters/provider-contract.mjs";
import { executeStagedReview } from "../src/adapters/staged-review.mjs";
import {
  conductIndependentVerification,
  buildDisagreementLedgerDocument,
  CliVerifierAdapter,
  createMockVerifierAdapter,
  VERIFICATION_SCHEMA_VERSION
} from "../src/core/independent-verifier.mjs";
import { TOOL_VERSION } from "../src/core/review-run-report.mjs";

export function getCommitShaForRef(ref = "HEAD") {
  try {
    const out = execFileSync("git", ["rev-parse", "--verify", `${ref}^{commit}`], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"]
    }).trim();
    if (/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/i.test(out) && !/^0+$/.test(out)) return out.toLowerCase();
  } catch {}
  return null;
}

export function getCurrentCommitSha() {
  return getCommitShaForRef("HEAD") || "0000000000000000000000000000000000000000";
}

export function getBranchForRef(ref = "HEAD") {
  try {
    const out = execFileSync("git", ["rev-parse", "--symbolic-full-name", ref], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"]
    }).trim();
    if (!out.includes("\n") && /^refs\/(heads|remotes)\//.test(out)) {
      return out.replace(/^refs\/(heads|remotes)\//, "");
    }
  } catch {}
  return null;
}

export function getCurrentBranch() {
  return getBranchForRef("HEAD");
}

export function normalizeRepositoryIdentity(value) {
  const raw = typeof value === "string" ? value.trim().replace(/\\/g, "/") : "";
  const normalized = raw.replace(/^https?:\/\/github\.com\//i, "")
    .replace(/^ssh:\/\/git@github\.com\//i, "")
    .replace(/^git@github\.com:/i, "")
    .replace(/\.git$/i, "")
    .replace(/^\/+|\/+$/g, "")
    .toLowerCase();
  return /^[a-z0-9_.-]+\/[a-z0-9_.-]+$/.test(normalized) ? normalized : null;
}

export function getRepositoryIdentityFromGit(requestedIdentity = null) {
  let remotes;
  try {
    remotes = execFileSync("git", ["remote"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"]
    }).trim().split(/\r?\n/).filter(Boolean);
  } catch {
    return null;
  }
  const identities = new Set();
  for (const remote of remotes) {
    try {
      const url = execFileSync("git", ["remote", "get-url", remote], {
        encoding: "utf8", stdio: ["ignore", "pipe", "pipe"]
      }).trim();
      const identity = normalizeRepositoryIdentity(url);
      if (identity && remote === "origin") return identity;
      if (identity) identities.add(identity);
    } catch {}
  }
  if (identities.size > 1) {
    if (identities.has(requestedIdentity)) return requestedIdentity;
    throw new Error("Ambiguous repository remotes: --repository must match a canonical remote identity");
  }
  return [...identities][0] || null;
}

export function parseArgs(argv = process.argv.slice(2)) {
  const options = {
    help: false,
    live: false,
    mock: false,
    base: "main",
    head: "HEAD",
    out: "dogfood-run.json",
    timeoutMs: null
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      options.help = true;
    } else if (arg === "--live") {
      options.live = true;
    } else if (arg === "--mock") {
      options.mock = true;
    } else if (arg === "--base") {
      if (i + 1 >= argv.length || argv[i + 1].startsWith("-")) {
        throw new Error("Missing value for --base");
      }
      options.base = argv[++i];
    } else if (arg.startsWith("--base=")) {
      options.base = arg.slice("--base=".length);
    } else if (arg === "--head") {
      if (i + 1 >= argv.length || argv[i + 1].startsWith("-")) {
        throw new Error("Missing value for --head");
      }
      options.head = argv[++i];
    } else if (arg.startsWith("--head=")) {
      options.head = arg.slice("--head=".length);
    } else if (arg === "--repository") {
      if (i + 1 >= argv.length || argv[i + 1].startsWith("-")) {
        throw new Error("Missing value for --repository");
      }
      options.repository = argv[++i];
    } else if (arg.startsWith("--repository=")) {
      options.repository = arg.slice("--repository=".length);
    } else if (arg === "--out") {
      if (i + 1 >= argv.length || argv[i + 1].startsWith("-")) {
        throw new Error("Missing value for --out");
      }
      options.out = argv[++i];
    } else if (arg.startsWith("--out=")) {
      options.out = arg.slice("--out=".length);
    } else if (arg === "--timeout") {
      if (i + 1 >= argv.length || argv[i + 1].startsWith("-")) {
        throw new Error("Missing value for --timeout");
      }
      const val = argv[++i];
      const parsed = parseInt(val, 10);
      if (isNaN(parsed) || parsed <= 0) {
        throw new Error(`Invalid --timeout value: '${val}'. Must be a positive integer.`);
      }
      options.timeoutMs = parsed;
    } else if (arg.startsWith("--timeout=")) {
      const val = arg.slice("--timeout=".length);
      const parsed = parseInt(val, 10);
      if (isNaN(parsed) || parsed <= 0) {
        throw new Error(`Invalid --timeout value: '${val}'. Must be a positive integer.`);
      }
      options.timeoutMs = parsed;
    } else {
      throw new Error(`Unknown argument: '${arg}'`);
    }
  }

  if (!options.live) {
    options.mock = true;
  }

  return options;
}

export function printHelp() {
  console.log(`
Triad-Flow Track D1: Shadow Dogfood Review

Usage:
  node scripts/dogfood-review.mjs [options]

Options:
  --live              Execute review using installed local provider CLIs (agy, claude, codex)
  --mock              Execute review using deterministic simulation (default)
  --base <ref>        Git base reference to diff against (default: main)
  --head <ref>        Git head reference (default: HEAD)
  --repository <id>   Canonical owner/repo for a repository without a resolvable remote; must match any resolved identity
  --out <file>        Output report path (default: dogfood-run.json)
  --timeout <ms>      Per-provider timeout in milliseconds (default: 300000 live / 30000 mock)
  --help, -h          Show this help message
`);
}

/**
 * Creates mock adapters for dogfood review simulation.
 */
function createMockDogfoodAdapters(changeSet) {
  const coveredFiles = (changeSet.files || []).map(f => f.path);

  const agy = new CliReviewAdapter({
    command: "agy",
    providerName: "agy",
    modelName: "gemini-3.8-flash",
    actualModel: { value: "gemini-3.8-flash", source: "reported" },
    execFn: async () => ({
      stdout: JSON.stringify({
        findings: [],
        coverage: { coveredFiles, omittedFiles: [] },
        usage: { promptTokens: 600, completionTokens: 50, totalTokens: 650 }
      })
    })
  });

  const claude = new CliReviewAdapter({
    command: "claude",
    providerName: "claude",
    modelName: "claude-5.5-sonnet",
    actualModel: { value: "claude-5.5-sonnet", source: "reported" },
    execFn: async () => ({
      stdout: JSON.stringify({
        findings: [],
        coverage: { coveredFiles, omittedFiles: [] },
        usage: { promptTokens: 620, completionTokens: 40, totalTokens: 660 }
      })
    })
  });

  const codex = new CliReviewAdapter({
    command: "codex",
    providerName: "codex",
    modelName: "gpt-6.1-sol",
    actualModel: { value: "gpt-6.1-sol", source: "reported" },
    execFn: async () => ({
      stdout: JSON.stringify({
        findings: [],
        coverage: { coveredFiles, omittedFiles: [] },
        usage: { promptTokens: 580, completionTokens: 45, totalTokens: 625 }
      })
    })
  });

  return { agy, claude, codex };
}

/**
 * Filters excluded files from a ChangeSet, updating files, diffHunks, contentDigest, and line counts.
 */
export function filterChangeSetExclusions(changeSet, excludedPaths = []) {
  if (!changeSet || !changeSet.files) return changeSet;
  const normalizedExclusions = new Set(
    excludedPaths.map(p => path.normalize(p).replace(/\\/g, "/").replace(/^\.\//, ""))
  );

  const rawFiles = changeSet.files || [];
  const excludedFiles = [];
  const files = rawFiles.filter(f => {
    const rawPath = typeof f === "string" ? f : f?.path || "";
    const rawOldPath = typeof f === "object" ? f?.oldPath : undefined;
    const decoded = decodeGitCStyleString(rawPath);
    const norm = path.normalize(decoded).replace(/\\/g, "/").replace(/^\.\//, "");
    const isExcludedDest = normalizedExclusions.has(norm);

    let isExcludedSrc = isExcludedDest;
    if (rawOldPath) {
      const decodedOld = decodeGitCStyleString(rawOldPath);
      const normOld = path.normalize(decodedOld).replace(/\\/g, "/").replace(/^\.\//, "");
      isExcludedSrc = normalizedExclusions.has(normOld);
    }

    if (rawOldPath && norm !== rawOldPath) {
      // Rename or copy: exclude only if BOTH source and destination are excluded
      if (isExcludedDest && isExcludedSrc) {
        excludedFiles.push(rawPath);
        return false;
      }
      return true;
    }

    if (isExcludedDest) {
      excludedFiles.push(rawPath);
      return false;
    }
    return true;
  });

  const totalAdditions = files.reduce((acc, f) => acc + (f.additions || 0), 0);
  const totalDeletions = files.reduce((acc, f) => acc + (f.deletions || 0), 0);

  // Filter diffHunks if present
  let filteredDiffHunks = changeSet.diffHunks || "";
  if (filteredDiffHunks) {
    const chunks = filteredDiffHunks.split(/(?=^diff --git )/m);
    const retainedChunks = chunks.filter(chunk => {
      const match = chunk.match(/^diff --git (?:"a\/(.+?)"|a\/(.+?))\s+(?:"b\/(.+?)"|b\/(.+?))(?:\r?\n|$)/m);
      if (match) {
        const isQuotedA = Boolean(match[1]);
        const isQuotedB = Boolean(match[3]);
        const rawA = match[1] || match[2];
        const rawB = match[3] || match[4];
        const decodedA = isQuotedA ? decodeGitCStyleString(`"${rawA}"`) : rawA;
        const decodedB = isQuotedB ? decodeGitCStyleString(`"${rawB}"`) : rawB;
        const fileA = path.normalize(decodedA).replace(/\\/g, "/").replace(/^\.\//, "");
        const fileB = path.normalize(decodedB).replace(/\\/g, "/").replace(/^\.\//, "");
        const isExcludedA = normalizedExclusions.has(fileA);
        const isExcludedB = normalizedExclusions.has(fileB);
        const isDevNullA = fileA === "/dev/null" || fileA === "dev/null";
        const isDevNullB = fileB === "/dev/null" || fileB === "dev/null";

        if (isDevNullB) {
          // File deleted: exclude only if fileA is in exclusions
          return !isExcludedA;
        }
        if (isDevNullA) {
          // File created: exclude only if fileB is in exclusions
          return !isExcludedB;
        }
        if (fileA === fileB) {
          return !isExcludedA;
        }
        // Rename or copy (fileA !== fileB):
        // Exclude only if BOTH source and destination are excluded
        if (isExcludedA && isExcludedB) {
          return false;
        }
        return true;
      }

      // Fallback for chunks without standard diff --git header
      const plusMatch = chunk.match(/^\+\+\+ (?:"b\/(.+?)"|b\/(.+?)|([^\s\r\n]+))(?:\r?\n|$)/m);
      const minusMatch = chunk.match(/^--- (?:"a\/(.+?)"|a\/(.+?)|([^\s\r\n]+))(?:\r?\n|$)/m);
      if (plusMatch && minusMatch) {
        const isQuotedA = Boolean(minusMatch[1]);
        const isQuotedB = Boolean(plusMatch[1]);
        const rawA = minusMatch[1] || minusMatch[2] || minusMatch[3];
        const rawB = plusMatch[1] || plusMatch[2] || plusMatch[3];
        const decodedA = isQuotedA ? decodeGitCStyleString(`"${rawA}"`) : rawA;
        const decodedB = isQuotedB ? decodeGitCStyleString(`"${rawB}"`) : rawB;
        const fileA = path.normalize(decodedA).replace(/\\/g, "/").replace(/^\.\//, "");
        const fileB = path.normalize(decodedB).replace(/\\/g, "/").replace(/^\.\//, "");
        const isExcludedA = normalizedExclusions.has(fileA);
        const isExcludedB = normalizedExclusions.has(fileB);
        const isDevNullA = fileA === "/dev/null" || fileA === "dev/null";
        const isDevNullB = fileB === "/dev/null" || fileB === "dev/null";

        if (isDevNullB) return !isExcludedA;
        if (isDevNullA) return !isExcludedB;
        if (fileA === fileB) return !isExcludedA;
        if (isExcludedA && isExcludedB) return false;
        return true;
      }

      if (plusMatch) {
        const isQuotedB = Boolean(plusMatch[1]);
        const rawB = plusMatch[1] || plusMatch[2] || plusMatch[3];
        const decodedB = isQuotedB ? decodeGitCStyleString(`"${rawB}"`) : rawB;
        const fileB = path.normalize(decodedB).replace(/\\/g, "/").replace(/^\.\//, "");
        if (fileB !== "/dev/null" && fileB !== "dev/null" && normalizedExclusions.has(fileB)) {
          return false;
        }
      }
      if (minusMatch) {
        const isQuotedA = Boolean(minusMatch[1]);
        const rawA = minusMatch[1] || minusMatch[2] || minusMatch[3];
        const decodedA = isQuotedA ? decodeGitCStyleString(`"${rawA}"`) : rawA;
        const fileA = path.normalize(decodedA).replace(/\\/g, "/").replace(/^\.\//, "");
        if (fileA !== "/dev/null" && fileA !== "dev/null" && normalizedExclusions.has(fileA)) {
          return false;
        }
      }
      return true;
    });
    filteredDiffHunks = retainedChunks.join("").trim();
  }

  const rawDigest = crypto.createHash("sha256").update(filteredDiffHunks, "utf8").digest("hex");
  const contentDigest = rawDigest;

  return {
    ...changeSet,
    files,
    diffHunks: filteredDiffHunks,
    contentDigest,
    totalAdditions,
    totalDeletions,
    excludedFiles
  };
}

/**
 * Classifies file risk tier based on sensitivity and architectural boundaries.
 */
export function classifyDogfoodFileRisk(filePath) {
  if (!filePath) return 2;
  const normalized = String(filePath).replace(/\\/g, "/").toLowerCase();
  const tier1Patterns = [
    /^\.github\/workflows\//,
    /^src\/core\//,
    /^src\/adapters\//,
    /^src\/auth\//,
    /^src\/crypto\//,
    /^src\/security\//,
    /^scripts\/bump-version\.mjs/,
    /^scripts\/release-verify\.mjs/,
    /auth|crypto|secret|token|credential|permission/i
  ];
  if (tier1Patterns.some(p => p.test(normalized))) {
    return 1;
  }
  return 2;
}

/**
 * Normalizes provider identity from actual execution result for operational telemetry.
 * Does not fall back to slot names, canonical defaults, or role names.
 *
 * @param {object} res
 * @returns {{ provider: string, family: string, model: string }}
 */
export function normalizeTelemetryIdentity(res) {
  const pId = res?.providerIdentity;
  const provider = (typeof pId?.provider === "string" && pId.provider.trim()) ? pId.provider.trim() : "unknown";
  const family = (typeof pId?.family === "string" && pId.family.trim()) ? pId.family.trim() : "unknown";
  const model = (typeof pId?.model === "string" && pId.model.trim()) ? pId.model.trim() : "unknown";
  return { provider, family, model };
}

/**
 * Builds normalized provider telemetry entry from provider output and raw sentry report.
 *
 * @param {object} output - Execution output containing { res, latencyMs }
 * @param {object} rawReport - Sentry report containing executionStatus and findings
 * @returns {object}
 */
export function buildProviderTelemetry(output, rawReport) {
  const identity = normalizeTelemetryIdentity(output?.res);
  return {
    provider: identity.provider,
    family: identity.family,
    model: identity.model,
    executionStatus: rawReport?.executionStatus || "unknown",
    findingsCount: rawReport?.findings?.length || 0,
    latencyMs: output?.latencyMs ?? 0
  };
}

export function isTimeoutLikeError(err) {
  return Boolean(
    err &&
    (err.name === "TimeoutError" || /timeout|timed out/i.test(String(err.message || err)))
  );
}

export function instrumentVerifierAdapter(adapter, onTimeout) {
  const inspectResult = (result) => {
    if (result?.executionStatus === EXECUTION_STATUS.TIMEOUT) onTimeout();
    return result;
  };
  const wrap = (fn, thisArg) => async (...args) => {
    try {
      return inspectResult(await fn.apply(thisArg, args));
    } catch (err) {
      if (isTimeoutLikeError(err)) onTimeout();
      throw err;
    }
  };

  if (typeof adapter === "function") return wrap(adapter, null);
  if (!adapter || typeof adapter !== "object") return adapter;

  if (
    typeof adapter.command === "string" &&
    typeof adapter.executeVerification !== "function" &&
    typeof adapter.verify !== "function" &&
    typeof adapter.execFn !== "function"
  ) {
    return instrumentVerifierAdapter(new CliVerifierAdapter(adapter), onTimeout);
  }

  return new Proxy(adapter, {
    get(target, prop, receiver) {
      const value = Reflect.get(target, prop, receiver);
      if (["executeVerification", "verify", "execFn"].includes(String(prop)) && typeof value === "function") {
        // The CLI adapter catches execFn exceptions internally. Use its proxy
        // as this so the nested execFn is observed before that catch runs.
        return wrap(value, target instanceof CliVerifierAdapter ? receiver : target);
      }
      return value;
    }
  });
}

/**
 * Executes Track D1 Shadow Dogfood Review.
 */
export async function runDogfoodReview(userOptions = {}) {
  const runStartedAt = new Date().toISOString();
  const runId = `dogfood-${Date.now()}-${crypto.randomUUID()}`;
  const isLive = Boolean(userOptions.live);
  const isMock = !isLive;
  const base = userOptions.base || "main";
  const head = userOptions.head || "HEAD";
  const timeoutMs = userOptions.timeoutMs || (isLive ? 300000 : 30000);
  const log = userOptions.log !== false;
  const outPath = path.resolve(userOptions.out || "dogfood-run.json");

  const branch = getBranchForRef(head);
  const requestedHeadSha = getCommitShaForRef(head);
  if (!requestedHeadSha) {
    throw new Error(`Reviewed head ref '${head}' cannot be resolved to a non-zero commit SHA`);
  }

  if (log) {
    console.log("==================================================================================");
    console.log("  Triad-Flow Track D1: Shadow Dogfood Review");
    console.log(`  Authority Mode: SHADOW_DOGFOOD (Advisory / Observation Only, Zero Merge Authority)`);
    console.log(`  Execution Mode: ${isLive ? "LIVE (Real Provider CLIs)" : "MOCK (Deterministic Simulation)"}`);
    console.log(`  Git Scope: ${base}...${head} (Branch: ${branch}, Reviewed Head: ${requestedHeadSha.slice(0, 10)})`);
    console.log("==================================================================================\n");
  }

  // 1. Capture Git ChangeSet
  let changeSet = userOptions.changeSet || null;
  if (!changeSet) {
    if (log) console.log(`[1/5] Inspecting Git changes between '${base}' and '${head}'...`);
    let resolvedBase = base;
    try {
      execFileSync("git", ["rev-parse", "--verify", base], { stdio: "ignore" });
    } catch {
      try {
        execFileSync("git", ["rev-parse", "--verify", `origin/${base}`], { stdio: "ignore" });
        resolvedBase = `origin/${base}`;
      } catch {
        resolvedBase = "HEAD";
      }
    }
    changeSet = buildChangeSet(process.cwd(), { base: resolvedBase, head });
  }

  if (!changeSet || !changeSet.ok) {
    throw new Error(`Failed to capture ChangeSet: ${changeSet?.error?.message || "Unknown Git inspection failure"}`);
  }

  const changeSetHeadSha = typeof changeSet?.repository?.headSha === "string"
    ? changeSet.repository.headSha.trim().toLowerCase()
    : requestedHeadSha;
  if (changeSetHeadSha !== requestedHeadSha) {
    throw new Error(`Reviewed ChangeSet head SHA '${changeSetHeadSha}' does not match requested --head '${requestedHeadSha}'`);
  }
  const commitSha = requestedHeadSha;
  const requestedRepository = userOptions.repository === undefined
    ? null : normalizeRepositoryIdentity(userOptions.repository);
  if (userOptions.repository !== undefined && !requestedRepository) {
    throw new Error("--repository must use canonical owner/repo syntax");
  }
  const resolvedRepository =
    normalizeRepositoryIdentity(changeSet?.repository?.name) ||
    getRepositoryIdentityFromGit(requestedRepository);
  if (requestedRepository && resolvedRepository && requestedRepository !== resolvedRepository) {
    throw new Error("Requested repository identity does not match the reviewed repository");
  }
  const repositoryName = resolvedRepository || requestedRepository;
  if (!repositoryName) {
    throw new Error("Reviewed repository identity cannot be resolved to canonical owner/repo; provide --repository");
  }

  const relOut = path.relative(process.cwd(), outPath).replace(/\\/g, "/");
  changeSet = filterChangeSetExclusions(changeSet, [relOut]);

  const files = (changeSet.files || []).map(f => ({
    ...f,
    riskTier: f.riskTier || classifyDogfoodFileRisk(f.path)
  }));
  changeSet = {
    ...changeSet,
    files
  };
  const totalAdditions = changeSet.totalAdditions;
  const totalDeletions = changeSet.totalDeletions;
  if (log) {
    console.log(`  ✔ Changed files (excluding telemetry output): ${files.length}`);
    console.log(`  ✔ Total additions: +${totalAdditions} / deletions: -${totalDeletions}`);
    for (const f of files.slice(0, 10)) {
      console.log(`    • ${f.path} (+${f.additions || 0}/-${f.deletions || 0}, Tier ${f.riskTier})`);
    }
    if (files.length > 10) console.log(`    ... and ${files.length - 10} more files`);
  }

  const totalChangedLines = totalAdditions + totalDeletions;
  const hasTier1 = files.some(f => f.riskTier === 1) || totalChangedLines >= 50;
  const diffTier = hasTier1 ? 1 : 2;

  // 2. Configure Tri-Party Reviewers
  if (log) console.log("\n[2/5] Configuring tri-party heterogeneous review sentries...");
  let reviewAdapters = userOptions.reviewAdapters || null;
  let verifierAdapter = userOptions.verifierAdapter || null;

  if (!reviewAdapters) {
    if (isLive) {
      const codexProfile = resolveProviderProfile("codex");
      let codexCommand = "codex";
      let codexArgs;

      if (codexProfile?.nativeResolution?.resolvedType === "NATIVE_EXE") {
        codexCommand = codexProfile.nativeResolution.command;
      } else if (codexProfile?.nativeResolution?.resolvedType === "NODE_SCRIPT") {
        codexCommand = codexProfile.nativeResolution.command;
        codexArgs = [
          ...(codexProfile.nativeResolution.prefixArgs || []),
          ...(codexProfile.args || [])
        ];
      }

      const codexAdapter = new CliReviewAdapter({
        command: codexCommand,
        args: codexArgs,
        providerName: "codex",
        modelName: "gpt-6.1-sol",
        actualModel: { value: "gpt-6.1-sol", source: "reported" },
        inputChannel: "stdin",
        supportsStdin: true,
        useStdin: true
      });
      codexAdapter.profile = codexProfile;

      reviewAdapters = {
        agy: new CliReviewAdapter({
          command: "agy",
          providerName: "agy",
          modelName: "gemini-3.8-flash",
          actualModel: { value: "gemini-3.8-flash", source: "reported" }
        }),
        claude: new CliReviewAdapter({
          command: "claude",
          providerName: "claude",
          modelName: "claude-5.5-sonnet",
          actualModel: { value: "claude-5.5-sonnet", source: "reported" }
        }),
        codex: codexAdapter
      };
    } else {
      reviewAdapters = createMockDogfoodAdapters(changeSet);
    }
  }

  if (!verifierAdapter) {
    if (isLive) {
      verifierAdapter = new CliVerifierAdapter({
        command: "claude",
        providerName: "claude",
        modelName: "claude-5.5-sonnet",
        actualModel: { value: "claude-5.5-sonnet", source: "reported" }
      });
    } else {
      verifierAdapter = createMockVerifierAdapter("claude");
    }
  }

  // 3. Execute Tri-Party Review
  if (log) console.log("\n[3/5] Executing tri-party review on PR changeset...");
  const t0 = Date.now();

  let stagedFallbackUsed = false;
  let stagedChunkCount = null;
  let stagedTimeoutCount = 0;
  const tAgy0 = Date.now();
  const executeAgyReview = async () => {
    const providerRunId = `${runId}-agy`;
    let res = await reviewAdapters.agy.executeReview({
      runId: providerRunId,
      role: "agy",
      changeSet,
      policyId: "TRI_PARTY_HETEROGENEOUS",
      timeoutMs,
      signal: userOptions.signal || null
    });

    if (res?.executionStatus === EXECUTION_STATUS.PAYLOAD_TOO_LARGE) {
      if (log) console.log("    ℹ [agy] Prompt exceeds Windows argv limit; delegating to staged chunked review (RFC-027-01)...");
      stagedFallbackUsed = true;
      res = await executeStagedReview(changeSet, reviewAdapters.agy, {
        runId: providerRunId,
        role: "agy",
        policyId: "TRI_PARTY_HETEROGENEOUS",
        timeoutMs,
        signal: userOptions.signal || null
      });
      stagedChunkCount = Array.isArray(res?.receipts) ? res.receipts.length : null;
      stagedTimeoutCount = Array.isArray(res?.receipts)
        ? res.receipts.filter(r => r?.status === "timeout").length
        : 0;
    }
    return res;
  };
  const pAgy = executeAgyReview().then(res => ({ res, latencyMs: Date.now() - tAgy0 }));

  const tClaude0 = Date.now();
  const pClaude = reviewAdapters.claude.executeReview({
    runId: `${runId}-claude`,
    role: "claude",
    changeSet,
    policyId: "TRI_PARTY_HETEROGENEOUS",
    timeoutMs,
    signal: userOptions.signal || null
  }).then(res => ({ res, latencyMs: Date.now() - tClaude0 }));

  const tCodex0 = Date.now();
  const pCodex = reviewAdapters.codex.executeReview({
    runId: `${runId}-codex`,
    role: "codex",
    changeSet,
    policyId: "TRI_PARTY_HETEROGENEOUS",
    timeoutMs,
    signal: userOptions.signal || null
  }).then(res => ({ res, latencyMs: Date.now() - tCodex0 }));

  const [agyOut, claudeOut, codexOut] = await Promise.all([pAgy, pClaude, pCodex]);
  const reviewerPhaseDurationMs = Date.now() - t0;

  const rawReports = {
    agy: {
      ...convertProviderResultToSentryReport(agyOut.res, "agy"),
      latencyMs: agyOut.latencyMs,
      executionStatus: agyOut.res?.executionStatus || "unknown"
    },
    claude: {
      ...convertProviderResultToSentryReport(claudeOut.res, "claude"),
      latencyMs: claudeOut.latencyMs,
      executionStatus: claudeOut.res?.executionStatus || "unknown"
    },
    codex: {
      ...convertProviderResultToSentryReport(codexOut.res, "codex"),
      latencyMs: codexOut.latencyMs,
      executionStatus: codexOut.res?.executionStatus || "unknown"
    }
  };

  if (log) {
    console.log(`  ✔ Google agy:   status=${rawReports.agy.executionStatus} (${rawReports.agy.findings?.length || 0} findings, ${agyOut.latencyMs}ms)${agyOut.res?.error ? ` - error: ${agyOut.res.error}` : ""}`);
    console.log(`  ✔ Anthropic claude: status=${rawReports.claude.executionStatus} (${rawReports.claude.findings?.length || 0} findings, ${claudeOut.latencyMs}ms)${claudeOut.res?.error ? ` - error: ${claudeOut.res.error}` : ""}`);
    console.log(`  ✔ OpenAI codex: status=${rawReports.codex.executionStatus} (${rawReports.codex.findings?.length || 0} findings, ${codexOut.latencyMs}ms)${codexOut.res?.error ? ` - error: ${codexOut.res.error}` : ""}`);
  }

  // 4. Consensus & Policy Evaluation
  if (log) console.log("\n[4/5] Evaluating consensus & disagreement ledger...");
  const consensus = aggregateConsensus(rawReports, {
    policy: "TRI_PARTY_HETEROGENEOUS",
    tier: diffTier
  });

  const gate = evaluateGateDecision(consensus, {
    tier: diffTier,
    strict: true
  });

  const findings = consensus.findings || [];
  if (log) {
    console.log(`  ★ Consensus Verdict: ${consensus.verdict} (Quorum reached: ${consensus.quorumReached})`);
    console.log(`  🛡️ Policy Gate: ${gate.decision.toUpperCase()} (${gate.reason})`);
    console.log(`  📋 Consensus Findings: ${findings.length}`);
    for (const f of findings) {
      console.log(`    • [${f.severity?.toUpperCase() || "MEDIUM"}] ${f.title} (${f.file}:${f.line_start || 1})`);
    }
  }

  // 5. Verification & Telemetry Compilation
  if (log) console.log("\n[5/5] Compiling operational telemetry into dogfood-run.json...");
  let verificationRecord = null;
  let verifierTimedOut = false;
  if (findings.length > 0) {
    const instrumentedVerifier = instrumentVerifierAdapter(verifierAdapter, () => {
      verifierTimedOut = true;
    });
    verificationRecord = await conductIndependentVerification(
      changeSet,
      findings,
      instrumentedVerifier,
      {
        producerName: "tri-party-quorum",
        producerModel: "agy+claude+codex",
        verifierName: "claude",
        verifierModel: "claude-5.5-sonnet",
        changeSetDigest: changeSet.contentDigest,
        timeoutMs,
        signal: userOptions.signal || null
      }
    );
  }

  const totalDurationMs = Date.now() - t0;

  const providerOutputs = [rawReports.agy, rawReports.claude, rawReports.codex];
  const malformedCount = providerOutputs.filter(r => r.executionStatus === "malformed_output").length;
  const reviewerTimeoutCount =
    providerOutputs.filter(r => r.executionStatus === "timeout").length +
    stagedTimeoutCount;
  const verifierTimeoutCount = verifierTimedOut ? 1 : 0;
  const timeoutCount = reviewerTimeoutCount + verifierTimeoutCount;
  const authFailureCount = providerOutputs.filter(r => r.executionStatus === "auth_failure").length;
  const otherFailureCount = providerOutputs.filter(r => !["success", "empty"].includes(r.executionStatus)).length;
  const allProvidersSucceeded = providerOutputs.every(r => ["success", "empty"].includes(r.executionStatus));
  const verificationAttempted = verificationRecord !== null;
  const isExecutionComplete =
    consensus.quorumReached &&
    allProvidersSucceeded &&
    (!verificationAttempted || verificationRecord.ok === true);

  const dogfoodDoc = {
    schemaVersion: "1.1.0",
    runId,
    executionMode: isLive ? "live" : "mock",
    runStartedAt,
    timestamp: new Date().toISOString(),
    track: "Track D1: SHADOW_DOGFOOD",
    authority: "NONE (ADVISORY_ONLY)",
    triadFlowVersion: TOOL_VERSION,
    repository: {
      name: repositoryName,
      commitSha,
      branch,
      base,
      head
    },
    changeSetSummary: {
      totalFiles: files.length,
      totalAdditions: changeSet.totalAdditions,
      totalDeletions: changeSet.totalDeletions,
      riskTier: diffTier,
      files: files.map(f => ({ path: f.path, additions: f.additions, deletions: f.deletions, riskTier: f.riskTier })),
      excludedFiles: changeSet.excludedFiles || []
    },
    providerTelemetry: {
      agy: { ...buildProviderTelemetry(agyOut, rawReports.agy), stagedFallbackUsed },
      claude: { ...buildProviderTelemetry(claudeOut, rawReports.claude), stagedFallbackUsed: false },
      codex: { ...buildProviderTelemetry(codexOut, rawReports.codex), stagedFallbackUsed: false }
    },
    consensus: {
      verdict: consensus.verdict,
      quorumReached: consensus.quorumReached,
      totalFindings: findings.length,
      findings: findings.map(f => ({
        title: f.title,
        severity: f.severity,
        file: f.file,
        line: f.line_start || f.line,
        corroborations: f.corroborations || 1,
        sources: f.sources || []
      }))
    },
    advisoryGate: {
      decision: gate.decision,
      reason: gate.reason,
      effectiveMergeAuthority: "NONE",
      simulatedGateBlock: gate.decision === "block",
      mergeBlockedInProduction: false
    },
    telemetryMetrics: {
      totalDurationMs,
      reviewerPhaseDurationMs,
      avgProviderLatencyMs: Math.round((agyOut.latencyMs + claudeOut.latencyMs + codexOut.latencyMs) / 3),
      executionComplete: isExecutionComplete,
      malformedOutputCount: malformedCount,
      reviewerTimeoutCount,
      verifierTimeoutCount,
      timeoutCount,
      authFailureCount,
      otherFailureCount,
      stagedFallbackUsed,
      chunkCount: stagedFallbackUsed ? stagedChunkCount : null
    },
    verificationRecord
  };

  fs.writeFileSync(outPath, JSON.stringify(dogfoodDoc, null, 2) + "\n", "utf8");
  if (log) {
    console.log(`  ✔ Saved dogfood telemetry to ${path.relative(process.cwd(), outPath)}`);
    console.log("\n🎉 Shadow Dogfood Review successfully recorded!");
  }

  return dogfoodDoc;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));

  if (options.help) {
    printHelp();
    process.exit(0);
  }

  try {
    await runDogfoodReview(options);
  } catch (err) {
    console.error("Fatal:", err);
    process.exit(1);
  }
}

const isMainModule = process.argv[1] && (
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url) ||
  path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))
);

if (isMainModule) {
  main();
}
