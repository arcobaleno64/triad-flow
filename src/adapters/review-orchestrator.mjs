/**
 * Review Orchestrator (PR-03)
 *
 * Coordinates ChangeSet context packages, risk topology routing, provider adapter execution,
 * strict heterogeneous consensus, and gate decisions.
 * Enforces fail-closed semantics: high-risk changes requiring dual sentries remain
 * incomplete/blocked when only one adapter is configured.
 */

import crypto from "node:crypto";
import { evaluateDiffScale } from "../core/graph-router.mjs";
import { aggregateConsensus } from "../core/loop.mjs";
import {
  evaluateGateDecision,
  RunContext,
  normalizeDigest,
  normalizeCommitSha,
  normalizeObjective
} from "../core/harness.mjs";
import { digestChangeSet, normalizeLineEndings } from "../core/canonical-digest.mjs";
import { convertProviderResultToSentryReport } from "./provider-contract.mjs";
import { evaluateCoverageContract, COVERAGE_OMISSION_CODES } from "./staged-review.mjs";
import { __bindBenchmarkRunnerCapability } from "../core/real-benchmark-runner.mjs";

function isCoverageComplete(changeSet, providerResult) {
  if (!providerResult || !providerResult.ok) return false;
  if (!changeSet || !Array.isArray(changeSet.files)) return false;

  const coverage = providerResult.coverage;
  if (!coverage || typeof coverage !== "object") return false;

  if (!Array.isArray(coverage.coveredFiles) || !Array.isArray(coverage.omittedFiles)) {
    return false;
  }

  const coveredFiles = coverage.coveredFiles;
  const omittedFiles = coverage.omittedFiles;

  const coverageEval = evaluateCoverageContract(changeSet, coveredFiles, omittedFiles);
  if (!coverageEval.isComplete) return false;

  // In non-staged review, size-limit or timeout omissions indicate incomplete execution
  // (files exceeding context budget require staged review / chunking).
  // Read from the sanitized declaration to avoid re-invoking stateful or throwing getters.
  const hasIncompleteOmission = (coverageEval.declaration?.omittedFiles || []).some(o => {
    return o && (o.code === COVERAGE_OMISSION_CODES.SIZE_LIMIT || o.code === COVERAGE_OMISSION_CODES.TIMEOUT);
  });

  return !hasIncompleteOmission;
}

function hasInvalidCalleeDefinition(pkg) {
  if (!pkg || typeof pkg !== "object") return false;
  if (Array.isArray(pkg)) {
    return pkg.some(hasInvalidCalleeDefinition);
  }
  if (pkg.contextPackages && typeof pkg.contextPackages === "object") {
    return Object.values(pkg.contextPackages).some(hasInvalidCalleeDefinition);
  }
  const callees = pkg.layers?.layer1AstEnclosure?.callees;
  if (!Array.isArray(callees)) return false;
  return callees.some(c => !c || typeof c !== "object" || (c.definition !== undefined && typeof c.definition !== "string"));
}

function extractObjectiveText(val) {
  if (!val) return "";
  if (typeof val === "string") return normalizeObjective(val);
  if (typeof val === "object" && typeof val.objective === "string") {
    return normalizeObjective(val.objective);
  }
  return "";
}

function collectAllObjectivesFromOptions(opts, maxDepth = 10, currentDepth = 0) {
  if (!opts || typeof opts !== "object" || currentDepth > maxDepth) return [];
  const results = [];
  if (opts.patchObjective) {
    const norm = normalizeObjective(opts.patchObjective);
    if (norm) results.push(norm);
  }
  if (opts.objectiveContract) {
    const text = extractObjectiveText(opts.objectiveContract);
    if (text) results.push(text);
  }
  if (opts.options && typeof opts.options === "object") {
    results.push(...collectAllObjectivesFromOptions(opts.options, maxDepth, currentDepth + 1));
  }
  return results;
}

function findNestedObjectiveContract(opts, maxDepth = 10, currentDepth = 0) {
  if (!opts || typeof opts !== "object" || currentDepth > maxDepth) return null;
  if (opts.objectiveContract) return opts.objectiveContract;
  if (opts.options && typeof opts.options === "object") {
    return findNestedObjectiveContract(opts.options, maxDepth, currentDepth + 1);
  }
  return null;
}

export function buildCanonicalRunContext(changeSet, options = {}, runId) {
  if (!changeSet || typeof changeSet !== "object") {
    return null;
  }

  const callerRunId = typeof options.runId === "string" ? options.runId.trim() : "";
  const paramRunId = typeof runId === "string" ? runId.trim() : "";
  const activeRunId = callerRunId || paramRunId || null;

  // R3 Replay Check: If verificationRecord is supplied:
  if (options.verificationRecord) {
    const vrRunId = typeof options.verificationRecord.runId === "string" ? options.verificationRecord.runId.trim() : "";
    // Any supplied verification record MUST possess a valid non-empty runId matching activeRunId
    if (!vrRunId) {
      return null;
    }
    if (activeRunId && vrRunId !== activeRunId) {
      return null;
    }
  }

  // R3 RunContext Check: If options.runContext has a runId, it must match activeRunId
  if (options.runContext && typeof options.runContext.runId === "string" && options.runContext.runId.trim()) {
    const rcRunId = options.runContext.runId.trim();
    if (activeRunId && rcRunId !== activeRunId) {
      return null;
    }
  }

  // 1. Compute valid authoritative digests from current ChangeSet (R1 Canonical Diff Digest)
  const computedDigests = new Set();
  try {
    const computed = digestChangeSet(changeSet);
    if (computed) {
      const d = normalizeDigest(computed);
      if (d) computedDigests.add(d);
    }
  } catch {
    // If digest computation fails, computedDigests remains empty
  }

  if (typeof changeSet.diffHunks === "string" || Buffer.isBuffer(changeSet.diffHunks)) {
    // R1: Strictly bind to physical diff content (raw bytes and LF-normalized); NO .trim() variants
    const rawDiffDigest = normalizeDigest(
      crypto.createHash("sha256").update(changeSet.diffHunks).digest("hex")
    );
    if (rawDiffDigest) computedDigests.add(rawDiffDigest);
    const normalizedDiff = normalizeLineEndings(changeSet.diffHunks);
    const normDiffDigest = normalizeDigest(
      crypto.createHash("sha256").update(normalizedDiff, "utf8").digest("hex")
    );
    if (normDiffDigest) computedDigests.add(normDiffDigest);
  }

  if (computedDigests.size === 0) {
    return null;
  }

  // 2. Digest Consistency Contract (P1-01):
  // Re-verify declared digests against computed digests from current ChangeSet.
  // If declared digest conflicts with computed digest, fail closed.
  const declaredContentDigest = changeSet.contentDigest ? normalizeDigest(changeSet.contentDigest) : "";
  const declaredChangeSetDigest = changeSet.changeSetDigest ? normalizeDigest(changeSet.changeSetDigest) : "";

  if (declaredContentDigest && !computedDigests.has(declaredContentDigest)) {
    return null;
  }
  if (declaredChangeSetDigest && !computedDigests.has(declaredChangeSetDigest)) {
    return null;
  }

  // Verified digest candidates for current ChangeSet
  const verifiedDigestCandidates = [];
  if (declaredContentDigest && computedDigests.has(declaredContentDigest)) {
    verifiedDigestCandidates.push(declaredContentDigest);
  }
  if (declaredChangeSetDigest && computedDigests.has(declaredChangeSetDigest)) {
    if (!verifiedDigestCandidates.includes(declaredChangeSetDigest)) {
      verifiedDigestCandidates.push(declaredChangeSetDigest);
    }
  }
  for (const cd of computedDigests) {
    if (!verifiedDigestCandidates.includes(cd)) {
      verifiedDigestCandidates.push(cd);
    }
  }

  if (verifiedDigestCandidates.length === 0) {
    return null;
  }

  const vr = options.verificationRecord;
  const vrDigest = vr ? normalizeDigest(vr.changeSetDigest || vr.contentDigest || "") : "";

  // If vrDigest is present, it must strictly match an authoritative candidate of current ChangeSet
  if (vrDigest && !verifiedDigestCandidates.includes(vrDigest)) {
    return null;
  }

  let selectedDigest = "";
  if (vrDigest && verifiedDigestCandidates.includes(vrDigest)) {
    selectedDigest = vrDigest;
  } else if (verifiedDigestCandidates.length > 0) {
    selectedDigest = verifiedDigestCandidates[0];
  }

  // Canonical RunContext requires an authoritative contentDigest for the current ChangeSet
  if (!selectedDigest) {
    return null;
  }

  const csHeadSha = normalizeCommitSha(
    changeSet.headSha ||
    changeSet.commitSha ||
    changeSet.head ||
    changeSet.repository?.commitSha ||
    changeSet.repository?.headSha ||
    ""
  );

  const headSha = csHeadSha || normalizeCommitSha(
    options.headSha ||
    options.head ||
    options.runContext?.headSha ||
    ""
  );

  // Cross-ChangeSet injection protection:
  // If caller provided runContext with headSha, and current changeSet has headSha, they must match
  if (csHeadSha && options.runContext?.headSha) {
    const rcHeadSha = normalizeCommitSha(options.runContext.headSha);
    if (rcHeadSha && rcHeadSha !== csHeadSha) {
      return null;
    }
  }

  // If verificationRecord has headSha, and current changeSet has headSha, they must match
  if (csHeadSha && vr?.headSha) {
    const vrHeadSha = normalizeCommitSha(vr.headSha);
    if (vrHeadSha && vrHeadSha !== csHeadSha) {
      return null;
    }
  }

  // If caller provided runContext with contentDigest, it must match one of the current changeSet authoritative candidates
  if (options.runContext?.contentDigest) {
    const rcDigest = normalizeDigest(options.runContext.contentDigest);
    if (rcDigest && !verifiedDigestCandidates.includes(rcDigest)) {
      return null;
    }
  }

  // R2: Deterministic Objective Conflict Fail-Closed across all sources
  const rawCandidates = [
    normalizeObjective(options.patchObjective),
    extractObjectiveText(options.objectiveContract),
    normalizeObjective(options.runContext?.patchObjective),
    extractObjectiveText(options.runContext?.objectiveContract),
    normalizeObjective(changeSet.patchObjective),
    extractObjectiveText(changeSet.objectiveContract),
    ...collectAllObjectivesFromOptions(options.options)
  ].filter(Boolean);

  const distinctNormalized = new Set(rawCandidates.map(c => c.toLowerCase()));
  if (distinctNormalized.size > 1) {
    // Deterministic objective conflict detected: fail closed immediately
    return null;
  }

  const patchObjective = rawCandidates.length > 0 ? rawCandidates[0] : "";

  const objectiveContract = options.objectiveContract ||
    options.runContext?.objectiveContract ||
    changeSet.objectiveContract ||
    findNestedObjectiveContract(options.options) ||
    null;

  const rawExclCandidates = [
    { name: "options.exclusions", list: options.exclusions },
    { name: "options.patchExclusions", list: options.patchExclusions },
    { name: "options.runContext.exclusions", list: options.runContext?.exclusions },
    { name: "changeSet.excludedFiles", list: changeSet.excludedFiles },
    { name: "changeSet.exclusions", list: changeSet.exclusions }
  ].filter(c => Array.isArray(c.list));

  let rawExcl = [];
  if (rawExclCandidates.length > 0) {
    const normSets = rawExclCandidates.map(c => ({
      name: c.name,
      raw: c.list,
      set: new Set(c.list.map(x => String(x).trim().replace(/\\/g, "/")).filter(Boolean))
    }));

    const first = normSets[0];
    for (let i = 1; i < normSets.length; i++) {
      const other = normSets[i];
      if (first.set.size !== other.set.size) {
        return null;
      }
      for (const item of first.set) {
        if (!other.set.has(item)) {
          return null;
        }
      }
    }
    rawExcl = first.raw;
  }

  const boundRunId = activeRunId || (options.runContext?.runId ? String(options.runContext.runId).trim() : null);

  try {
    return new RunContext({
      runId: boundRunId,
      headSha,
      contentDigest: selectedDigest,
      patchObjective,
      objectiveContract,
      exclusions: rawExcl
    });
  } catch {
    return null;
  }
}

const internalBenchmarkAuthorityRegistry = new WeakSet();

function _createInternalBenchmarkCapability() {
  const token = Object.freeze({
    type: "INTERNAL_BENCHMARK_CAPABILITY",
    mintedAt: Date.now()
  });
  internalBenchmarkAuthorityRegistry.add(token);
  return token;
}

if (typeof __bindBenchmarkRunnerCapability === "function") {
  __bindBenchmarkRunnerCapability(_createInternalBenchmarkCapability);
}

async function _executeOrchestratedReview(changeSet, adapters = {}, options = {}, internalContext = {}) {
  const runId = options.runId || crypto.randomUUID();
  const strict = Boolean(options.strict);
  const timeoutMs = options.timeoutMs || 60000;
  const signal = options.signal || null;
  const limits = options.limits || null;

  if (!changeSet || !changeSet.ok) {
    return {
      runId,
      status: "error",
      error: changeSet?.error?.message || "Invalid ChangeSet",
      gate: { decision: "block", reason: "Invalid or missing ChangeSet" }
    };
  }

  if (!changeSet.files || changeSet.files.length === 0) {
    return {
      runId,
      status: "no-changes",
      plan: { mode: "single", totalFiles: 0, reason: "No files changed" },
      consensus: null,
      gate: { decision: "approve", reason: "No changes to review" },
      reports: {}
    };
  }

  if (hasInvalidCalleeDefinition(options.contextPackage) || hasInvalidCalleeDefinition(changeSet?.contextPackage)) {
    return {
      runId,
      status: "incomplete",
      plan: options.plan || evaluateDiffScale(changeSet?.files || []),
      consensus: null,
      gate: {
        decision: "block",
        reason: "Gate Fail-Closed: Context package contains invalid callee definition (INVALID_CALLEE_DEFINITION)."
      },
      reports: {}
    };
  }

  // R2 / tfxJn: Deterministic Objective Conflict Fail-Closed across all sources
  const rawObjectiveCandidates = [
    normalizeObjective(options.patchObjective),
    extractObjectiveText(options.objectiveContract),
    normalizeObjective(options.runContext?.patchObjective),
    extractObjectiveText(options.runContext?.objectiveContract),
    normalizeObjective(changeSet.patchObjective),
    extractObjectiveText(changeSet.objectiveContract),
    ...collectAllObjectivesFromOptions(options.options)
  ].filter(Boolean);

  const distinctObjectives = new Set(rawObjectiveCandidates.map(c => c.toLowerCase()));
  if (distinctObjectives.size > 1) {
    return {
      runId,
      status: "incomplete",
      plan: options.plan || evaluateDiffScale(changeSet?.files || []),
      consensus: null,
      gate: {
        decision: "block",
        reason: "Gate Fail-Closed: Verification record, exclusions, or objective mismatch (FORGED_OR_STALE_RECORD / EXCLUSION_OR_OBJECTIVE_MISMATCH)."
      },
      reports: {}
    };
  }

  const effectivePatchObjective = rawObjectiveCandidates.length > 0 ? rawObjectiveCandidates[0] : "";
  const effectiveObjectiveContract = options.objectiveContract ||
    options.runContext?.objectiveContract ||
    changeSet.objectiveContract ||
    findNestedObjectiveContract(options.options) ||
    null;

  const authoritativeScale = evaluateDiffScale(changeSet.files);
  const plan = options.plan || authoritativeScale;
  const computedHighestRisk = authoritativeScale.highestRisk;

  // R4: Validate risk tier and prevent illegal tiers or downgrades
  let isIllegalTier = false;
  let parsedTier = undefined;

  if (options.tier !== undefined) {
    if (
      options.tier === null ||
      typeof options.tier === "symbol" ||
      (typeof options.tier !== "number" && typeof options.tier !== "string") ||
      (typeof options.tier === "string" && options.tier.trim() === "")
    ) {
      isIllegalTier = true;
    } else {
      parsedTier = Number(options.tier);
      if (
        Number.isNaN(parsedTier) ||
        !Number.isInteger(parsedTier) ||
        parsedTier <= 0 ||
        parsedTier > 4
      ) {
        isIllegalTier = true;
      }
    }
  }

  // Benchmark evaluation exemption strictly confined to verified internal benchmark execution
  const isInternalBenchmark = Boolean(internalContext.isInternalBenchmark);

  let isPlanConflict = false;
  if (options.plan) {
    if (options.plan.highestRisk !== undefined) {
      const planRisk = Number(options.plan.highestRisk);
      if (Number.isNaN(planRisk) || !Number.isInteger(planRisk) || planRisk <= 0 || planRisk > 4) {
        isIllegalTier = true;
      } else if (planRisk > authoritativeScale.highestRisk && !isInternalBenchmark) {
        isPlanConflict = true;
      }
    }
    if (options.plan.mode !== undefined && options.plan.mode !== "hierarchical" && options.plan.mode !== "single") {
      isIllegalTier = true;
    }
    if (authoritativeScale.highestRisk === 1) {
      const isRiskDowngraded = options.plan.highestRisk !== undefined && Number(options.plan.highestRisk) > 1;
      const isModeDowngraded = options.plan.mode === "single";
      if ((isRiskDowngraded || isModeDowngraded) && !isInternalBenchmark) {
        isPlanConflict = true;
      }
    }
    if (authoritativeScale.mode === "hierarchical" && options.plan.mode === "single" && !isInternalBenchmark) {
      isPlanConflict = true;
    }
  }

  // Downgrade check: if diff is Tier 1, cannot downgrade to > 1 or override isTier1: false
  const isDowngraded = (authoritativeScale.highestRisk === 1 && (
    (parsedTier !== undefined && parsedTier > 1) ||
    options.isTier1 === false
  )) || isPlanConflict;

  if (isIllegalTier || isDowngraded) {
    return {
      runId,
      status: "incomplete",
      plan,
      consensus: null,
      gate: {
        decision: "block",
        reason: "Gate Fail-Closed: Invalid or downgraded risk tier (INVALID_OR_DOWNGRADED_TIER)."
      },
      reports: {}
    };
  }

  const isTier1Opt = options.tier === 1 || options.isTier1 === true || computedHighestRisk === 1;
  const diffTier = isTier1Opt
    ? 1
    : (parsedTier !== undefined
        ? parsedTier
        : (computedHighestRisk !== undefined ? Number(computedHighestRisk) : undefined));
  const hasMacro = Boolean(adapters.macro && typeof adapters.macro.executeReview === "function");
  const hasMicro = Boolean(adapters.micro && typeof adapters.micro.executeReview === "function");

  // Case 1: No adapters configured at all -> Fail-Closed
  if (!hasMacro && !hasMicro) {
    const rawReports = {
      macro: { error: "No configured macro sentry provider" },
      micro: { error: "No configured micro sentry provider" }
    };
    const consensus = aggregateConsensus(rawReports);
    const gate = evaluateGateDecision(consensus, {
      strict,
      ...(diffTier !== undefined ? { tier: diffTier, isTier1: diffTier === 1 } : {}),
      ...(effectivePatchObjective ? { patchObjective: effectivePatchObjective } : {}),
      ...(effectiveObjectiveContract ? { objectiveContract: effectiveObjectiveContract } : {})
    });

    return {
      runId,
      status: "incomplete",
      plan,
      consensus,
      gate,
      reports: rawReports
    };
  }

  const baseExecutionParams = {
    runId,
    changeSet,
    timeoutMs,
    signal,
    ...(limits ? { limits } : {}),
    ...(options.contextPackage ? { contextPackage: options.contextPackage } : {}),
    ...(options.contextGaps ? { contextGaps: options.contextGaps } : {}),
    ...(effectivePatchObjective ? { patchObjective: effectivePatchObjective } : {}),
    ...(effectiveObjectiveContract ? { objectiveContract: effectiveObjectiveContract } : {})
  };

  // Case 2: Hierarchical mode (High-risk or large diff)
  if (plan.mode === "hierarchical") {
    // High-risk changes REQUIRE strict heterogeneous dual sentries (Macro + Micro).
    // If only one adapter is configured, fail closed as incomplete / blocked.
    if (!hasMacro || !hasMicro) {
      const activeRole = hasMacro ? "macro" : "micro";
      const missingRole = hasMacro ? "micro" : "macro";
      const activeAdapter = hasMacro ? adapters.macro : adapters.micro;

      const activeResult = await activeAdapter.executeReview({
        ...baseExecutionParams,
        role: activeRole,
        policyId: "STRICT_HETEROGENEOUS"
      });

      const rawReports = {
        [activeRole]: convertProviderResultToSentryReport(activeResult, activeRole),
        [missingRole]: {
          name: `unconfigured-${missingRole}`,
          source: `unconfigured-${missingRole}`,
          role: missingRole,
          error: `Quorum Failure: High-risk diff requires dual sentries (macro + micro), but only ${activeRole} is configured.`
        }
      };

      const consensus = aggregateConsensus(rawReports, { policy: "STRICT_HETEROGENEOUS" });
      const gate = evaluateGateDecision(consensus, {
        strict,
        ...(diffTier !== undefined ? { tier: diffTier, isTier1: diffTier === 1 } : {}),
        ...(options.preliminary === true ? { preliminary: true } : {}),
        ...(options.contextPackage ? { contextPackage: options.contextPackage } : {}),
        ...(options.contextGaps ? { contextGaps: options.contextGaps } : {}),
        ...(effectivePatchObjective ? { patchObjective: effectivePatchObjective } : {}),
        ...(effectiveObjectiveContract ? { objectiveContract: effectiveObjectiveContract } : {})
      });

      return {
        runId,
        status: "incomplete",
        plan,
        consensus,
        gate,
        reports: rawReports,
        ...(options.contextPackage ? { contextPackage: options.contextPackage } : {}),
        ...(options.contextGaps ? { contextGaps: options.contextGaps } : {}),
        activeResult
      };
    }

    // Both Macro and Micro adapters configured: execute concurrently
    const [macroResult, microResult] = await Promise.all([
      adapters.macro.executeReview({
        ...baseExecutionParams,
        role: "macro",
        policyId: "STRICT_HETEROGENEOUS"
      }),
      adapters.micro.executeReview({
        ...baseExecutionParams,
        role: "micro",
        policyId: "STRICT_HETEROGENEOUS"
      })
    ]);

    const rawReports = {
      macro: convertProviderResultToSentryReport(macroResult, "macro"),
      micro: convertProviderResultToSentryReport(microResult, "micro")
    };

    const consensus = aggregateConsensus(rawReports, { policy: "STRICT_HETEROGENEOUS" });
    const isPreliminaryOpt = options.preliminary === true;
    let canonicalRunContext = options.runContext;
    let runContextMismatched = false;
    if (options.verificationRecord || options.runContext) {
      canonicalRunContext = buildCanonicalRunContext(changeSet, options, runId);
      if (!canonicalRunContext) {
        runContextMismatched = true;
      }
    }

    let gate = runContextMismatched
      ? { decision: "block", reason: "Gate Fail-Closed: Verification record, exclusions, or objective mismatch (FORGED_OR_STALE_RECORD / EXCLUSION_OR_OBJECTIVE_MISMATCH)." }
      : evaluateGateDecision(consensus, {
          strict,
          ...(diffTier !== undefined ? { tier: diffTier, isTier1: diffTier === 1 } : {}),
          ...(isPreliminaryOpt ? { preliminary: true } : {}),
          ...(options.verificationRecord ? { verificationRecord: options.verificationRecord } : {}),
          ...(canonicalRunContext ? { runContext: canonicalRunContext } : {}),
          ...(options.contextPackage ? { contextPackage: options.contextPackage } : {}),
          ...(options.contextGaps ? { contextGaps: options.contextGaps } : {}),
          ...(effectivePatchObjective ? { patchObjective: effectivePatchObjective } : {}),
          ...(effectiveObjectiveContract ? { objectiveContract: effectiveObjectiveContract } : {})
        });

    const isApprove = gate.decision === "approve";
    const hasFindings = consensus.findings && consensus.findings.length > 0;

    let status = "incomplete";
    if (consensus.quorumReached && !runContextMismatched) {
      if (isApprove) {
        if (hasFindings) {
          status = "reviewed-with-findings";
        } else if (isPreliminaryOpt) {
          status = "preliminary-clean";
        } else {
          status = "reviewed-clean";
        }
      } else if (hasFindings) {
        status = "reviewed-with-findings";
      }
    }

    if (!runContextMismatched) {
      const macroCoverageOk = isCoverageComplete(changeSet, macroResult);
      const microCoverageOk = isCoverageComplete(changeSet, microResult);
      if (!macroCoverageOk || !microCoverageOk) {
        status = "incomplete";
        gate = { decision: "block", reason: "Coverage Incomplete: Sentry omitted file(s) from review." };
      }
    }

    if (isInternalBenchmark && gate) {
      gate.governanceAuthority = false;
      gate.experimental = true;
    }

    const benchmarkMetadata = isInternalBenchmark ? {
      governanceAuthority: false,
      isExperimental: true,
      experimentalBenchmark: true
    } : {};

    return {
      runId,
      status,
      plan,
      consensus,
      gate,
      reports: rawReports,
      ...benchmarkMetadata,
      ...(options.contextPackage ? { contextPackage: options.contextPackage } : {}),
      ...(options.contextGaps ? { contextGaps: options.contextGaps } : {}),
      results: { macro: macroResult, micro: microResult }
    };
  }

  // Case 3: Single sentry mode (Low-risk small diff)
  const singleAdapter = adapters.macro || adapters.micro;
  const singleRole = adapters.macro ? "macro" : "micro";

  const singleResult = await singleAdapter.executeReview({
    ...baseExecutionParams,
    role: singleRole,
    policyId: "SINGLE_SENTRY"
  });

  const singleReport = convertProviderResultToSentryReport(singleResult, singleRole);
  const rawReports = { [singleRole]: singleReport };

  const consensus = aggregateConsensus(rawReports, {
    policy: "SINGLE_SENTRY",
    designatedRole: singleRole
  });
  const isPreliminaryOpt = options.preliminary === true;
  let canonicalRunContext = options.runContext;
  let runContextMismatched = false;
  if (options.verificationRecord || options.runContext) {
    canonicalRunContext = buildCanonicalRunContext(changeSet, options, runId);
    if (!canonicalRunContext) {
      runContextMismatched = true;
    }
  }

  let gate = runContextMismatched
    ? { decision: "block", reason: "Gate Fail-Closed: Verification record, exclusions, or objective mismatch (FORGED_OR_STALE_RECORD / EXCLUSION_OR_OBJECTIVE_MISMATCH)." }
    : evaluateGateDecision(consensus, {
        strict,
        ...(diffTier !== undefined ? { tier: diffTier, isTier1: diffTier === 1 } : {}),
        ...(isPreliminaryOpt ? { preliminary: true } : {}),
        ...(options.verificationRecord ? { verificationRecord: options.verificationRecord } : {}),
        ...(canonicalRunContext ? { runContext: canonicalRunContext } : {}),
        ...(options.contextPackage ? { contextPackage: options.contextPackage } : {}),
        ...(options.contextGaps ? { contextGaps: options.contextGaps } : {}),
        ...(effectivePatchObjective ? { patchObjective: effectivePatchObjective } : {}),
        ...(effectiveObjectiveContract ? { objectiveContract: effectiveObjectiveContract } : {})
      });

  const isApprove = gate.decision === "approve";
  const hasFindings = consensus.findings && consensus.findings.length > 0;

  let status = "incomplete";
  if (consensus.quorumReached && !runContextMismatched) {
    if (isApprove) {
      if (hasFindings) {
        status = "reviewed-with-findings";
      } else if (isPreliminaryOpt) {
        status = "preliminary-clean";
      } else {
        status = "reviewed-clean";
      }
    } else if (hasFindings) {
      status = "reviewed-with-findings";
    }
  }

  if (!runContextMismatched) {
    const singleCoverageOk = isCoverageComplete(changeSet, singleResult);
    if (!singleCoverageOk) {
      status = "incomplete";
      gate = { decision: "block", reason: "Coverage Incomplete: Sentry omitted file(s) from review." };
    }
  }

  if (isInternalBenchmark && gate) {
    gate.governanceAuthority = false;
    gate.experimental = true;
  }

  const benchmarkMetadata = isInternalBenchmark ? {
    governanceAuthority: false,
    isExperimental: true,
    experimentalBenchmark: true
  } : {};

  return {
    runId,
    status,
    plan,
    consensus,
    gate,
    reports: rawReports,
    ...benchmarkMetadata,
    ...(options.contextPackage ? { contextPackage: options.contextPackage } : {}),
    ...(options.contextGaps ? { contextGaps: options.contextGaps } : {}),
    result: singleResult
  };
}

/**
 * Public Governance Review Orchestrator.
 * Strictly enforces all governance invariants: Tier 1 diffs unconditionally require
 * dual heterogeneous sentries (hierarchical mode) and cannot be downgraded by any caller.
 * Fails closed without exception (Thread tfxJh).
 */
export async function orchestrateReview(changeSet, adapters = {}, options = {}) {
  return _executeOrchestratedReview(changeSet, adapters, options, { isInternalBenchmark: false });
}

/**
 * Dedicated Experimental Benchmark Review Orchestrator.
 * Restricted strictly to genuine internal benchmark runs authenticated via unforgeable
 * capability token minted by _createInternalBenchmarkCapability (Thread tfxJh).
 * External callers cannot obtain the capability token and fail closed immediately.
 * All return values are explicitly marked as experimental non-governance authority.
 */
export async function orchestrateBenchmarkEvaluation(changeSet, adapters = {}, options = {}) {
  const token = options?.__internalBenchmarkCapability;
  if (!token || typeof token !== "object" || !internalBenchmarkAuthorityRegistry.has(token)) {
    const runId = options?.runId || crypto.randomUUID();
    return {
      runId,
      status: "incomplete",
      plan: options?.plan || evaluateDiffScale(changeSet?.files || []),
      consensus: null,
      gate: {
        decision: "block",
        reason: "Gate Fail-Closed: Unauthorized benchmark evaluation request (UNAUTHORIZED_BENCHMARK_EXECUTION)."
      },
      reports: {},
      governanceAuthority: false,
      isExperimental: true
    };
  }

  return _executeOrchestratedReview(changeSet, adapters, options, { isInternalBenchmark: true });
}
