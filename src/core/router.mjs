/**
 * Graph Engineering: Scale-Adaptive Dynamic Router
 */

export const RISK_TIERS = Object.freeze({
  TIER_1_CRITICAL: 1, // Auth, Crypto, CI/CD, Workflows
  TIER_2_SOURCE: 2,   // Core application code
  TIER_3_DOCS: 3      // Docs, Markdown, Lockfiles
});

const TIER_1_PATTERNS = [
  /(?:^|\/)(?:auth|security|crypto|jwt|login|token|permission)/i,
  /(?:^|\/)\.github\/workflows\//i,
  /(?:^|\/)Dockerfile/i
];

const TIER_3_PATTERNS = [
  /\.md$/i,
  /(?:^|\/)docs\//i,
  /(?:^|\/)(?:package-lock\.json|pnpm-lock\.yaml|yarn\.lock)$/i
];

export function classifyFileRisk(filePath) {
  for (const pattern of TIER_1_PATTERNS) {
    if (pattern.test(filePath)) return RISK_TIERS.TIER_1_CRITICAL;
  }
  for (const pattern of TIER_3_PATTERNS) {
    if (pattern.test(filePath)) return RISK_TIERS.TIER_3_DOCS;
  }
  return RISK_TIERS.TIER_2_SOURCE;
}

export function evaluateDiffScale(files = [], options = {}) {
  const { maxSmallLines = 50, maxSmallFiles = 3 } = options;

  let totalLines = 0;
  let highestRisk = RISK_TIERS.TIER_3_DOCS;
  const categorized = { tier1: [], tier2: [], tier3: [] };

  for (const file of files) {
    const lines = (file.additions || 0) + (file.deletions || 0);
    totalLines += lines;
    const risk = classifyFileRisk(file.path || "");

    if (risk < highestRisk) highestRisk = risk;

    if (risk === RISK_TIERS.TIER_1_CRITICAL) categorized.tier1.push(file.path);
    else if (risk === RISK_TIERS.TIER_2_SOURCE) categorized.tier2.push(file.path);
    else categorized.tier3.push(file.path);
  }

  // Trigger hierarchical subagent swarm if Tier 1 files changed OR diff is large
  const isLarge = files.length > maxSmallFiles || totalLines > maxSmallLines;
  const isCritical = highestRisk === RISK_TIERS.TIER_1_CRITICAL;

  if (isCritical || isLarge) {
    const subagents = ["macro-callers", "macro-deployment"];
    if (isCritical) subagents.push("micro-pen-tester", "micro-race-simulator");

    return {
      mode: "hierarchical",
      highestRisk,
      totalFiles: files.length,
      totalLines,
      reason: isCritical
        ? `Modified high-risk security files (${categorized.tier1.join(", ")})`
        : `Diff exceeds threshold (${files.length} files, ${totalLines} lines)`,
      subagents,
      categorized
    };
  }

  return {
    mode: "single",
    highestRisk,
    totalFiles: files.length,
    totalLines,
    reason: `Small diff within threshold (${files.length} files, ${totalLines} lines)`,
    subagents: [],
    categorized
  };
}
