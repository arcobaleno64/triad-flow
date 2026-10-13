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
import { digestChangeSet } from "../core/canonical-digest.mjs";
import { convertProviderResultToSentryReport } from "./provider-contract.mjs";
import { evaluateCoverageContract, COVERAGE_OMISSION_CODES } from "./staged-review.mjs";

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

function buildCanonicalRunContext(changeSet, options, runId) {
  // 1. Compute valid authoritative digests from current ChangeSet
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

  if (typeof changeSet.diffHunks === "string") {
    const rawDiffDigest = normalizeDigest(crypto.createHash("sha256").update(changeSet.diffHunks, "utf8").digest("hex"));
    if (rawDiffDigest) computedDigests.add(rawDiffDigest);
    const normalizedDiff = changeSet.diffHunks.replace(/\r\n/g, "\n");
    const normDiffDigest = normalizeDigest(crypto.createHash("sha256").update(normalizedDiff, "utf8").digest("hex"));
    if (normDiffDigest) computedDigests.add(normDiffDigest);
    const trimmedDiffDigest = normalizeDigest(crypto.createHash("sha256").update(changeSet.diffHunks.trim(), "utf8").digest("hex"));
    if (trimmedDiffDigest) computedDigests.add(trimmedDiffDigest);
    const trimmedNormDiffDigest = normalizeDigest(crypto.createHash("sha256").update(normalizedDiff.trim(), "utf8").digest("hex"));
    if (trimmedNormDiffDigest) computedDigests.add(trimmedNormDiffDigest);
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

  const patchObjective = normalizeObjective(
    options.patchObjective ||
    options.objectiveContract?.objective ||
    options.runContext?.patchObjective ||
    changeSet.patchObjective ||
    changeSet.objectiveContract?.objective ||
    ""
  );

  const objectiveContract = options.objectiveContract ||
    options.runContext?.objectiveContract ||
    changeSet.objectiveContract ||
    null;

  const rawExcl = Array.isArray(options.exclusions)
    ? options.exclusions
    : (Array.isArray(options.patchExclusions)
        ? options.patchExclusions
        : (Array.isArray(options.runContext?.exclusions)
            ? options.runContext.exclusions
            : (Array.isArray(changeSet.excludedFiles)
                ? changeSet.excludedFiles
                : (Array.isArray(changeSet.exclusions) ? changeSet.exclusions : []))));

  return new RunContext({
    runId: options.runId || options.runContext?.runId || options.verificationRecord?.runId || null,
    headSha,
    contentDigest: selectedDigest,
    patchObjective,
    objectiveContract,
    exclusions: rawExcl
  });
}

export async function orchestrateReview(changeSet, adapters = {}, options = {}) {
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

  const plan = options.plan || evaluateDiffScale(changeSet.files);
  const evaluatedScale = (!plan || plan.highestRisk === undefined) ? evaluateDiffScale(changeSet?.files || []) : null;
  const computedHighestRisk = plan?.highestRisk ?? evaluatedScale?.highestRisk;
  const isTier1Opt = options.tier === 1 || options.isTier1 === true;
  const diffTier = isTier1Opt
    ? 1
    : (options.tier !== undefined
        ? Number(options.tier)
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
      ...(diffTier !== undefined ? { tier: diffTier, isTier1: diffTier === 1 } : {})
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

  // Case 2: Hierarchical mode (High-risk or large diff)
  if (plan.mode === "hierarchical") {
    // High-risk changes REQUIRE strict heterogeneous dual sentries (Macro + Micro).
    // If only one adapter is configured, fail closed as incomplete / blocked.
    if (!hasMacro || !hasMicro) {
      const activeRole = hasMacro ? "macro" : "micro";
      const missingRole = hasMacro ? "micro" : "macro";
      const activeAdapter = hasMacro ? adapters.macro : adapters.micro;

      const activeResult = await activeAdapter.executeReview({
        runId,
        role: activeRole,
        changeSet,
        policyId: "STRICT_HETEROGENEOUS",
        timeoutMs,
        signal,
        ...(limits ? { limits } : {})
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
        ...(options.preliminary === true ? { preliminary: true } : {})
      });

      return {
        runId,
        status: "incomplete",
        plan,
        consensus,
        gate,
        reports: rawReports,
        activeResult
      };
    }

    // Both Macro and Micro adapters configured: execute concurrently
    const [macroResult, microResult] = await Promise.all([
      adapters.macro.executeReview({
        runId,
        role: "macro",
        changeSet,
        policyId: "STRICT_HETEROGENEOUS",
        timeoutMs,
        signal,
        ...(limits ? { limits } : {})
      }),
      adapters.micro.executeReview({
        runId,
        role: "micro",
        changeSet,
        policyId: "STRICT_HETEROGENEOUS",
        timeoutMs,
        signal,
        ...(limits ? { limits } : {})
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
    if (options.verificationRecord) {
      canonicalRunContext = buildCanonicalRunContext(changeSet, options, runId);
      if (!canonicalRunContext) {
        runContextMismatched = true;
      }
    }

    let gate = runContextMismatched
      ? { decision: "block", reason: "Gate Fail-Closed: Verification record binding mismatch (FORGED_OR_STALE_RECORD)." }
      : evaluateGateDecision(consensus, {
          strict,
          ...(diffTier !== undefined ? { tier: diffTier, isTier1: diffTier === 1 } : {}),
          ...(isPreliminaryOpt ? { preliminary: true } : {}),
          ...(options.verificationRecord ? { verificationRecord: options.verificationRecord } : {}),
          ...(canonicalRunContext ? { runContext: canonicalRunContext } : {})
        });

    const isApprove = gate.decision === "approve";
    const hasFindings = consensus.findings && consensus.findings.length > 0;

    let status = "incomplete";
    if (consensus.quorumReached) {
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

    const macroCoverageOk = isCoverageComplete(changeSet, macroResult);
    const microCoverageOk = isCoverageComplete(changeSet, microResult);
    if (!macroCoverageOk || !microCoverageOk) {
      status = "incomplete";
      gate = { decision: "block", reason: "Coverage Incomplete: Sentry omitted file(s) from review." };
    }

    return {
      runId,
      status,
      plan,
      consensus,
      gate,
      reports: rawReports,
      results: { macro: macroResult, micro: microResult }
    };
  }

  // Case 3: Single sentry mode (Low-risk small diff)
  const singleAdapter = adapters.macro || adapters.micro;
  const singleRole = adapters.macro ? "macro" : "micro";

  const singleResult = await singleAdapter.executeReview({
    runId,
    role: singleRole,
    changeSet,
    policyId: "SINGLE_SENTRY",
    timeoutMs,
    signal,
    ...(limits ? { limits } : {})
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
  if (options.verificationRecord) {
    canonicalRunContext = buildCanonicalRunContext(changeSet, options, runId);
    if (!canonicalRunContext) {
      runContextMismatched = true;
    }
  }

  let gate = runContextMismatched
    ? { decision: "block", reason: "Gate Fail-Closed: Verification record binding mismatch (FORGED_OR_STALE_RECORD)." }
    : evaluateGateDecision(consensus, {
        strict,
        ...(diffTier !== undefined ? { tier: diffTier, isTier1: diffTier === 1 } : {}),
        ...(isPreliminaryOpt ? { preliminary: true } : {}),
        ...(options.verificationRecord ? { verificationRecord: options.verificationRecord } : {}),
        ...(canonicalRunContext ? { runContext: canonicalRunContext } : {})
      });

  const isApprove = gate.decision === "approve";
  const hasFindings = consensus.findings && consensus.findings.length > 0;

  let status = "incomplete";
  if (consensus.quorumReached) {
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

  const singleCoverageOk = isCoverageComplete(changeSet, singleResult);
  if (!singleCoverageOk) {
    status = "incomplete";
    gate = { decision: "block", reason: "Coverage Incomplete: Sentry omitted file(s) from review." };
  }

  return {
    runId,
    status,
    plan,
    consensus,
    gate,
    reports: rawReports,
    result: singleResult
  };
}
