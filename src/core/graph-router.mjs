/**
 * Graph Engineering (Pillar 2 — Topology Routing): Multi-Tier Risk Classification & Scale-Adaptive Swarm Dispatch
 */

export const RISK_TIERS = {
  TIER_1_CRITICAL: 1, // Auth, Crypto, JWT, CI/CD, Workflows
  TIER_2_SOURCE: 2,   // Core Business Logic, Components, Lockfiles, Tests
  TIER_3_DOCS: 3,     // Markdown, Static Configs, Minor Assets
  TIER_IGNORED: 4     // Build Artifacts, Minified Bundles
};

const IGNORE_PATTERNS = [
  /(?:^|[\\/])node_modules[\\/]/i,
  /(?:^|[\\/])dist[\\/]/i,
  /(?:^|[\\/])build[\\/]/i,
  /(?:^|[\\/])coverage[\\/]/i,
  /\.min\.(js|css)$/i,
  /\.(png|jpe?g|gif|svg|ico|pdf|zip|gz|tar)$/i
];

const LOCKFILE_PATTERNS = [
  /(?:^|[\\/])package-lock\.json$/i,
  /(?:^|[\\/])pnpm-lock\.yaml$/i,
  /(?:^|[\\/])yarn\.lock$/i,
  /(?:^|[\\/])bun\.lockb$/i
];

const DOC_EXTENSIONS = /\.(md|markdown|txt|rst)$/i;

const TIER_3_DIRS = [
  /(?:^|[\\/])docs[\\/]/i,
  /(?:^|[\\/])examples[\\/]/i
];

const TEST_FILE_PATTERNS = [
  /\.(test|spec)\.[a-z0-9]+$/i,
  /(?:^|[\\/])__tests__[\\/]/i,
  /(?:^|[\\/])tests?[\\/]/i
];

const SECURITY_DIR_PATTERNS = [
  /(?:^|[\\/])(auth|security|crypto|jwt|login|token|permission)[\\/]/i
];

const TIER_1_PATTERNS = [
  /(?:^|[\\/])(?:auth|security|crypto|jwt|login|token|permission)[^\\/]*\.[a-z0-9]+$/i,
  /(?:^|[\\/])\.github[\\/]workflows[\\/]/i,
  /(?:^|[\\/])Dockerfile(?:$|\.)/i
];

/**
 * Classifies file into appropriate risk tier with precision directory boundaries.
 */
export function classifyFileRisk(filePath = "") {
  const normalized = String(filePath).replace(/\\/g, "/");

  // 1. Ignored files
  for (const pattern of IGNORE_PATTERNS) {
    if (pattern.test(normalized)) return RISK_TIERS.TIER_IGNORED;
  }

  // 2. Lockfiles (Tier 2)
  for (const pattern of LOCKFILE_PATTERNS) {
    if (pattern.test(normalized)) return RISK_TIERS.TIER_2_SOURCE;
  }

  // 3. True documentation files (Tier 3)
  if (DOC_EXTENSIONS.test(normalized)) {
    return RISK_TIERS.TIER_3_DOCS;
  }

  const isTest = TEST_FILE_PATTERNS.some(p => p.test(normalized));
  const isSecurityDir = SECURITY_DIR_PATTERNS.some(p => p.test(normalized));
  const isSecurityFile = TIER_1_PATTERNS.some(p => p.test(normalized));

  // 4. Critical Security & CI/CD Files (including tests in security directories)
  if (isSecurityDir || isSecurityFile) {
    return RISK_TIERS.TIER_1_CRITICAL;
  }

  // 5. Non-security assets in doc or example folders
  for (const pattern of TIER_3_DIRS) {
    if (pattern.test(normalized)) return RISK_TIERS.TIER_3_DOCS;
  }

  if (isTest) {
    return RISK_TIERS.TIER_2_SOURCE;
  }

  return RISK_TIERS.TIER_2_SOURCE;
}

/**
 * Evaluates the scale and risk topology of changes to determine swarm dispatch.
 * Invariant (P1-06, P1-07): Large untracked or unreadable files force hierarchical mode.
 */
export function evaluateDiffScale(files = [], options = {}) {
  const { maxSmallLines = 50, maxSmallFiles = 3, maxSwarmSubagents = 6 } = options;

  let totalLines = 0;
  let highestRisk = RISK_TIERS.TIER_3_DOCS;
  let hasLargeOrUnreadable = false;
  const categorized = { tier1: [], tier2: [], tier3: [], ignored: [] };

  for (const file of files) {
    const risk = classifyFileRisk(file.path || "");
    if (risk === RISK_TIERS.TIER_IGNORED) {
      categorized.ignored.push(file.path);
      continue;
    }

    if (file.largeFile || file.unreadable || file.inspectionFailed || file.binary) {
      hasLargeOrUnreadable = true;
    }

    const lines = (file.additions || 0) + (file.deletions || 0);
    totalLines += lines;

    if (risk < highestRisk) highestRisk = risk;

    if (risk === RISK_TIERS.TIER_1_CRITICAL) categorized.tier1.push(file.path);
    else if (risk === RISK_TIERS.TIER_2_SOURCE) categorized.tier2.push(file.path);
    else categorized.tier3.push(file.path);
  }

  const activeCount = categorized.tier1.length + categorized.tier2.length + categorized.tier3.length;
  const isLarge = activeCount > maxSmallFiles || totalLines > maxSmallLines || hasLargeOrUnreadable;
  const isCritical = highestRisk === RISK_TIERS.TIER_1_CRITICAL;

  if (isCritical || isLarge) {
    const subagents = ["macro-callers", "macro-deployment"];
    if (isCritical) subagents.push("micro-pen-tester", "micro-race-simulator");

    let reason = "";
    if (isCritical) {
      const fileSummary = categorized.tier1.length > 3
        ? `${categorized.tier1.slice(0, 3).join(", ")}... (+${categorized.tier1.length - 3} more)`
        : categorized.tier1.join(", ");
      reason = `Modified high-risk security files (${fileSummary})`;
    } else if (hasLargeOrUnreadable) {
      reason = `Diff contains binary, large (>2MB) or uninspected files requiring swarm consensus`;
    } else {
      reason = `Diff exceeds threshold (${activeCount} active files, ${totalLines} lines)`;
    }

    return {
      mode: "hierarchical",
      highestRisk,
      totalFiles: activeCount,
      totalLines,
      reason,
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
