/**
 * Hardened Graph Engineering: Scale-Adaptive Dynamic Router
 */

export const RISK_TIERS = Object.freeze({
  TIER_1_CRITICAL: 1, // Auth, Crypto, CI/CD, Workflows
  TIER_2_SOURCE: 2,   // Core application code
  TIER_3_DOCS: 3,     // Docs, Markdown, Text
  TIER_IGNORED: 4     // Binary, Lockfiles, Build artifacts
});

const IGNORE_PATTERNS = [
  /\.(?:png|jpg|jpeg|gif|svg|ico|wasm|pdf|zip|tar|gz|exe|dll|so|dylib)$/i,
  /(?:^|[\\/])(?:node_modules|\.git|dist|build|coverage)[\\/]/i,
  /(?:^|[\\/])(?:package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb)$/i
];

const TEST_FILE_PATTERNS = [
  /\.(?:test|spec)\.[jt]sx?$/i,
  /(?:^|[\\/])(?:__tests__|tests?|mocks?)[\\/]/i
];

const TIER_3_PATTERNS = [
  /\.md$/i,
  /(?:^|[\\/])docs[\\/]/i,
  /\.txt$/i
];

const TIER_1_PATTERNS = [
  /(?:^|[\\/])(?:auth|security|crypto|jwt|login|token|permission)[^\\/]*\.[a-z0-9]+$/i,
  /(?:^|[\\/])\.github[\\/]workflows[\\/]/i,
  /(?:^|[\\/])Dockerfile/i
];

export function classifyFileRisk(filePath = "") {
  const normalized = String(filePath).replace(/\\/g, "/");

  // 1. Ignored files (Binary, lockfiles, generated assets)
  for (const pattern of IGNORE_PATTERNS) {
    if (pattern.test(normalized)) return RISK_TIERS.TIER_IGNORED;
  }

  // 2. Documentation and Markdown (Checked before Tier 1 to avoid docs/login.md false positives)
  for (const pattern of TIER_3_PATTERNS) {
    if (pattern.test(normalized)) return RISK_TIERS.TIER_3_DOCS;
  }

  // 3. Test and Mock files (Downgrade to Tier 2 to prevent 500% token blowout on test edits)
  const isTest = TEST_FILE_PATTERNS.some(pattern => pattern.test(normalized));

  // 4. Critical Security & CI files
  for (const pattern of TIER_1_PATTERNS) {
    if (pattern.test(normalized)) {
      return isTest ? RISK_TIERS.TIER_2_SOURCE : RISK_TIERS.TIER_1_CRITICAL;
    }
  }

  return RISK_TIERS.TIER_2_SOURCE;
}

export function evaluateDiffScale(files = [], options = {}) {
  const { maxSmallLines = 50, maxSmallFiles = 3, maxSwarmSubagents = 6 } = options;

  let totalLines = 0;
  let highestRisk = RISK_TIERS.TIER_3_DOCS;
  const categorized = { tier1: [], tier2: [], tier3: [], ignored: [] };

  for (const file of files) {
    const risk = classifyFileRisk(file.path || "");
    if (risk === RISK_TIERS.TIER_IGNORED) {
      categorized.ignored.push(file.path);
      continue;
    }

    const lines = (file.additions || 0) + (file.deletions || 0);
    totalLines += lines;

    if (risk < highestRisk) highestRisk = risk;

    if (risk === RISK_TIERS.TIER_1_CRITICAL) categorized.tier1.push(file.path);
    else if (risk === RISK_TIERS.TIER_2_SOURCE) categorized.tier2.push(file.path);
    else categorized.tier3.push(file.path);
  }

  const activeCount = categorized.tier1.length + categorized.tier2.length + categorized.tier3.length;
  const isLarge = activeCount > maxSmallFiles || totalLines > maxSmallLines;
  const isCritical = highestRisk === RISK_TIERS.TIER_1_CRITICAL;

  if (isCritical || isLarge) {
    const subagents = ["macro-callers", "macro-deployment"];
    if (isCritical) subagents.push("micro-pen-tester", "micro-race-simulator");

    const fileSummary = categorized.tier1.length > 3
      ? `${categorized.tier1.slice(0, 3).join(", ")}... (+${categorized.tier1.length - 3} more)`
      : categorized.tier1.join(", ");

    return {
      mode: "hierarchical",
      highestRisk,
      totalFiles: activeCount,
      totalLines,
      reason: isCritical
        ? `Modified high-risk security files (${fileSummary})`
        : `Diff exceeds threshold (${activeCount} active files, ${totalLines} lines)`,
      subagents: subagents.slice(0, maxSwarmSubagents),
      categorized
    };
  }

  return {
    mode: "single",
    highestRisk,
    totalFiles: activeCount,
    totalLines,
    reason: `Small diff within threshold (${activeCount} active files, ${totalLines} lines)`,
    subagents: [],
    categorized
  };
}
