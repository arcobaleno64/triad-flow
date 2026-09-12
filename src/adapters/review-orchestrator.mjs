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
import { evaluateGateDecision } from "../core/harness.mjs";
import { convertProviderResultToSentryReport } from "./provider-contract.mjs";
import { normalizeCanonicalPath } from "../core/scoring.mjs";

function isCoverageComplete(changeSet, providerResult) {
  if (!providerResult || !providerResult.ok) return false;
  if (!changeSet || !Array.isArray(changeSet.files)) return false;

  const coverage = providerResult.coverage;
  if (!coverage) return false;

  if (Array.isArray(coverage.omittedFiles) && coverage.omittedFiles.length > 0) {
    return false;
  }

  const coveredList = Array.isArray(coverage.coveredFiles)
    ? coverage.coveredFiles.map(f => normalizeCanonicalPath(f))
    : [];
  const coveredSet = new Set(coveredList);

  for (const f of changeSet.files) {
    const normPath = normalizeCanonicalPath(f.path);
    if (!coveredSet.has(normPath)) {
      return false;
    }
  }

  return true;
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
  const hasMacro = Boolean(adapters.macro && typeof adapters.macro.executeReview === "function");
  const hasMicro = Boolean(adapters.micro && typeof adapters.micro.executeReview === "function");

  // Case 1: No adapters configured at all -> Fail-Closed
  if (!hasMacro && !hasMicro) {
    const rawReports = {
      macro: { error: "No configured macro sentry provider" },
      micro: { error: "No configured micro sentry provider" }
    };
    const consensus = aggregateConsensus(rawReports);
    const gate = evaluateGateDecision(consensus, { strict });

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
      const gate = evaluateGateDecision(consensus, { strict });

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
    let gate = evaluateGateDecision(consensus, { strict });

    const isApprove = gate.decision === "approve";
    const hasFindings = consensus.findings && consensus.findings.length > 0;

    let status = "incomplete";
    if (consensus.quorumReached) {
      if (isApprove) {
        status = hasFindings ? "reviewed-with-findings" : "reviewed-clean";
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
  let gate = evaluateGateDecision(consensus, { strict });

  const isApprove = gate.decision === "approve";
  const hasFindings = consensus.findings && consensus.findings.length > 0;

  let status = "incomplete";
  if (consensus.quorumReached) {
    if (isApprove) {
      status = hasFindings ? "reviewed-with-findings" : "reviewed-clean";
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
