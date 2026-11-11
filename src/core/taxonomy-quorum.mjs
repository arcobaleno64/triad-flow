/**
 * Triad-Flow v2.12 Pillar 4: Taxonomy-Aware Heterogeneous Quorum Calibration
 * (RFC-028-04 / Architecture Charter)
 *
 * Implements domain-specialized model weight calibration, dynamic risk-tier consensus thresholds,
 * cross-vendor diversity enforcement, and decisive domain-expert arbitration.
 *
 * Strict Zero External Dependency Invariant: Pure Node.js native API only.
 */

import crypto from "node:crypto";
import { ALLOWED_VERDICTS, BLOCKING_SEVERITIES, deepFreeze, hasBlockingFindings } from "./consensus-state.mjs";
import { normalizeCanonicalPath, normalizeCwe, extractCweTokens } from "./scoring.mjs";
import { getProviderFamily } from "./benchmark-pilot.mjs";
import { RISK_TIERS, classifyFileRisk } from "./graph-router.mjs";

/**
 * Vulnerability Taxonomy Domains.
 */
export const VULNERABILITY_DOMAINS = Object.freeze({
  MEMORY_SAFETY: "memory_safety",
  CONCURRENCY_LOGIC: "concurrency_logic",
  GLOBAL_ARCHITECTURE: "global_architecture",
  GENERAL_SECURITY: "general_security"
});

/**
 * Standard CWEs mapping for Memory Safety (底層記憶體安全).
 * CWE-119 (Buffer errors), CWE-416 (Use After Free), CWE-190 (Integer Overflow), etc.
 */
export const MEMORY_SAFETY_CWES = Object.freeze(new Set([
  "CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-124", "CWE-125",
  "CWE-126", "CWE-127", "CWE-190", "CWE-191", "CWE-401", "CWE-415",
  "CWE-416", "CWE-476", "CWE-676", "CWE-787"
]));

/**
 * Standard CWEs mapping for Concurrency, State & Business Logic (業務邏輯、並行競爭與狀態機).
 * CWE-362 (Race Condition), CWE-835 (Infinite Loop), CWE-755 (Improper Exception Handling), etc.
 */
export const CONCURRENCY_LOGIC_CWES = Object.freeze(new Set([
  "CWE-362", "CWE-366", "CWE-400", "CWE-662", "CWE-670", "CWE-703",
  "CWE-754", "CWE-755", "CWE-770", "CWE-820", "CWE-821", "CWE-834",
  "CWE-835"
]));

/**
 * Standard CWEs mapping for Global Architecture & Cross-Module Monorepo Context (全域架構掃描與跨模組 Monorepo 上下文).
 * CWE-1021 (UI Layer / Clickjacking), CWE-94 (Code Injection across boundary), CWE-693 (Protection Mechanism Failure), etc.
 */
export const GLOBAL_ARCHITECTURE_CWES = Object.freeze(new Set([
  "CWE-22", "CWE-94", "CWE-284", "CWE-434", "CWE-502", "CWE-601",
  "CWE-693", "CWE-862", "CWE-863", "CWE-918", "CWE-922", "CWE-1021",
  "CWE-1022"
]));

/**
 * Keyword patterns for taxonomy domain inference when CWE is omitted or implicit.
 */
const DOMAIN_KEYWORD_PATTERNS = Object.freeze({
  [VULNERABILITY_DOMAINS.MEMORY_SAFETY]: [
    /\b(buffer overflow|buffer underwrite|use[- ]after[- ]free|integer overflow|integer underflow|null pointer(?: dereference)?|memory leak|out[- ]of[- ]bounds|heap overflow|stack overflow|dangling pointer|double free|segfault|segmentation fault)\b/i
  ],
  [VULNERABILITY_DOMAINS.CONCURRENCY_LOGIC]: [
    /\b(race condition|deadlock|livelock|state machine|concurrency|thread[- ]safe|synchronization|data race|mutex|atomic|infinite loop|unhandled exception|resource exhaustion|starvation)\b/i
  ],
  [VULNERABILITY_DOMAINS.GLOBAL_ARCHITECTURE]: [
    /\b(architecture|cross[- ]module|monorepo|boundary violation|access control bypass|authorization bypass|protection mechanism failure|blast radius|uninspected chunk|dependency cycle|circular dependency|import boundary|cross[- ]package)\b/i
  ]
});

/**
 * Default Domain-Specialized Model Family Weights (RFC-028-04).
 *
 * - Memory Safety: OpenAI Codex & Static Analyzers prioritized.
 * - Concurrency & Logic: Anthropic Claude Code prioritized for deep semantic reasoning.
 * - Global Architecture: Google Antigravity (AGY) prioritized for 1M token wide context.
 */
export const DEFAULT_DOMAIN_WEIGHTS = Object.freeze({
  [VULNERABILITY_DOMAINS.MEMORY_SAFETY]: Object.freeze({
    openai: 2.0,
    static: 1.8,
    anthropic: 1.0,
    google: 1.0,
    unknown: 0.5
  }),
  [VULNERABILITY_DOMAINS.CONCURRENCY_LOGIC]: Object.freeze({
    anthropic: 2.0,
    openai: 1.2,
    google: 1.2,
    static: 0.8,
    unknown: 0.5
  }),
  [VULNERABILITY_DOMAINS.GLOBAL_ARCHITECTURE]: Object.freeze({
    google: 2.0,
    anthropic: 1.3,
    openai: 1.0,
    static: 0.8,
    unknown: 0.5
  }),
  [VULNERABILITY_DOMAINS.GENERAL_SECURITY]: Object.freeze({
    google: 1.0,
    anthropic: 1.0,
    openai: 1.0,
    static: 1.0,
    unknown: 0.5
  })
});

/**
 * Dynamic Risk Tier Consensus Base Thresholds.
 * Replaces rigid 2/3 binary voting with tier-adaptive quorum requirements.
 */
export const DYNAMIC_TIER_THRESHOLDS = Object.freeze({
  [RISK_TIERS.TIER_1_CRITICAL]: 0.80, // High-risk Tier 1: 80% consensus + multi-provider diversity
  [RISK_TIERS.TIER_2_SOURCE]: 0.65,   // Standard Source: ~65% consensus
  [RISK_TIERS.TIER_3_DOCS]: 0.50,     // Low-risk Docs: 50% single-sentry permitted
  [RISK_TIERS.TIER_IGNORED]: 0.50
});

/**
 * Risk Multipliers based on active vulnerability domain criticality.
 */
export const DOMAIN_RISK_COEFFICIENTS = Object.freeze({
  [VULNERABILITY_DOMAINS.MEMORY_SAFETY]: 1.15,
  [VULNERABILITY_DOMAINS.CONCURRENCY_LOGIC]: 1.10,
  [VULNERABILITY_DOMAINS.GLOBAL_ARCHITECTURE]: 1.05,
  [VULNERABILITY_DOMAINS.GENERAL_SECURITY]: 1.00
});

/**
 * Resolves canonical provider family for a model or agent identifier.
 * Expands benchmark-pilot's getProviderFamily to recognize static analysis tools.
 *
 * @param {string} providerOrModel
 * @param {string} [declaredFamily]
 * @returns {string} Canonical vendor family: "google" | "anthropic" | "openai" | "static" | "unknown"
 */
export function resolveProviderFamily(providerOrModel = "", declaredFamily = "") {
  if (declaredFamily && typeof declaredFamily === "string") {
    const dec = declaredFamily.toLowerCase().trim();
    if (dec === "google" || dec === "anthropic" || dec === "openai" || dec === "static") {
      return dec;
    }
  }

  const raw = String(providerOrModel || "").toLowerCase().trim();
  if (!raw) return "unknown";

  // Check static analyzer tools
  if (
    raw === "static" ||
    raw.includes("semgrep") ||
    raw.includes("sast") ||
    raw.includes("codeql") ||
    raw.includes("ast-grep") ||
    raw.includes("analyzer") ||
    raw.includes("linter")
  ) {
    return "static";
  }

  // Use benchmark-pilot mapping for LLM families
  const family = getProviderFamily(raw);
  if (family !== "unknown") {
    return family;
  }

  // Fallback checks
  if (raw.includes("claude") || raw.includes("anthropic")) return "anthropic";
  if (raw.includes("codex") || raw.includes("gpt") || raw.includes("openai")) return "openai";
  if (raw.includes("agy") || raw.includes("gemini") || raw.includes("antigravity") || raw.includes("google")) return "google";

  return "unknown";
}

/**
 * Classifies a vulnerability finding or signature into a canonical taxonomy domain.
 *
 * @param {string|object} findingOrCwe
 * @param {object} [context={}]
 * @returns {{ domain: string, matchedBy: string, cwe: string|null }}
 */
export function classifyTaxonomyDomain(findingOrCwe, context = {}) {
  let rawCwe = "";
  let text = "";

  if (typeof findingOrCwe === "string") {
    rawCwe = findingOrCwe;
    text = findingOrCwe;
  } else if (findingOrCwe && typeof findingOrCwe === "object") {
    rawCwe = findingOrCwe.cwe || "";
    text = [
      findingOrCwe.title,
      findingOrCwe.type,
      findingOrCwe.description,
      findingOrCwe.body,
      findingOrCwe.message,
      findingOrCwe.recommendation,
      context.filePath || findingOrCwe.file
    ].filter(Boolean).join(" ");
  }

  // 1. Direct explicit CWE match
  const normCwe = normalizeCwe(rawCwe);
  if (normCwe) {
    if (MEMORY_SAFETY_CWES.has(normCwe)) {
      return { domain: VULNERABILITY_DOMAINS.MEMORY_SAFETY, matchedBy: "explicit_cwe", cwe: normCwe };
    }
    if (CONCURRENCY_LOGIC_CWES.has(normCwe)) {
      return { domain: VULNERABILITY_DOMAINS.CONCURRENCY_LOGIC, matchedBy: "explicit_cwe", cwe: normCwe };
    }
    if (GLOBAL_ARCHITECTURE_CWES.has(normCwe)) {
      return { domain: VULNERABILITY_DOMAINS.GLOBAL_ARCHITECTURE, matchedBy: "explicit_cwe", cwe: normCwe };
    }
  }

  // 2. Extracted CWE tokens from text
  const extractedTokens = extractCweTokens(text);
  for (const token of extractedTokens) {
    if (MEMORY_SAFETY_CWES.has(token)) {
      return { domain: VULNERABILITY_DOMAINS.MEMORY_SAFETY, matchedBy: "extracted_cwe", cwe: token };
    }
    if (CONCURRENCY_LOGIC_CWES.has(token)) {
      return { domain: VULNERABILITY_DOMAINS.CONCURRENCY_LOGIC, matchedBy: "extracted_cwe", cwe: token };
    }
    if (GLOBAL_ARCHITECTURE_CWES.has(token)) {
      return { domain: VULNERABILITY_DOMAINS.GLOBAL_ARCHITECTURE, matchedBy: "extracted_cwe", cwe: token };
    }
  }

  // 3. Keyword heuristic regex matching
  for (const [domain, patterns] of Object.entries(DOMAIN_KEYWORD_PATTERNS)) {
    for (const pattern of patterns) {
      if (pattern.test(text)) {
        return { domain, matchedBy: "keyword_heuristic", cwe: normCwe || null };
      }
    }
  }

  // 4. File extension / context heuristic (e.g. C / C++ / Rust memory files)
  const filePath = String(context.filePath || (findingOrCwe && findingOrCwe.file) || "").toLowerCase();
  if (filePath.endsWith(".c") || filePath.endsWith(".cpp") || filePath.endsWith(".h") || filePath.endsWith(".rs")) {
    if (/malloc|free|pointer|unsafe|buffer|overflow/i.test(text)) {
      return { domain: VULNERABILITY_DOMAINS.MEMORY_SAFETY, matchedBy: "language_context", cwe: normCwe || null };
    }
  }

  return { domain: VULNERABILITY_DOMAINS.GENERAL_SECURITY, matchedBy: "default_fallback", cwe: normCwe || null };
}

/**
 * TaxonomyQuorumCalibrator
 *
 * Core arbitration engine providing domain-weighted multi-model scoring,
 * dynamic risk-tier thresholds, and fail-closed security guarantees.
 */
export class TaxonomyQuorumCalibrator {
  /**
   * @param {object} [options={}]
   * @param {object} [options.domainWeights] Custom domain-to-model weight overrides
   * @param {object} [options.tierThresholds] Custom risk-tier base thresholds
   * @param {object} [options.domainRiskCoefficients] Custom domain risk multipliers
   * @param {number} [options.findingAcceptanceThreshold=0.40] Min weighted confidence to confirm finding
   * @param {number} [options.minTier1ProviderDiversity=2] Min distinct vendor families required for Tier 1
   */
  constructor(options = {}) {
    this.domainWeights = this._mergeDomainWeights(options.domainWeights);
    this.tierThresholds = { ...DYNAMIC_TIER_THRESHOLDS, ...(options.tierThresholds || {}) };
    this.domainRiskCoefficients = { ...DOMAIN_RISK_COEFFICIENTS, ...(options.domainRiskCoefficients || {}) };
    this.findingAcceptanceThreshold = typeof options.findingAcceptanceThreshold === "number"
      ? options.findingAcceptanceThreshold
      : 0.40;
    this.minTier1ProviderDiversity = typeof options.minTier1ProviderDiversity === "number"
      ? options.minTier1ProviderDiversity
      : 2;
  }

  _mergeDomainWeights(custom = {}) {
    const merged = {};
    for (const domain of Object.values(VULNERABILITY_DOMAINS)) {
      merged[domain] = {
        ...DEFAULT_DOMAIN_WEIGHTS[domain],
        ...(custom && custom[domain] ? custom[domain] : {})
      };
    }
    return Object.freeze(merged);
  }

  /**
   * Classifies a finding into its vulnerability taxonomy domain.
   */
  classifyDomain(findingOrCwe, context = {}) {
    return classifyTaxonomyDomain(findingOrCwe, context);
  }

  /**
   * Returns domain-calibrated weight for a given model or provider.
   *
   * @param {string} providerOrModel
   * @param {string} [domain=VULNERABILITY_DOMAINS.GENERAL_SECURITY]
   * @param {string} [declaredFamily]
   * @returns {number} Calibrated weight (> 0)
   */
  getModelWeight(providerOrModel, domain = VULNERABILITY_DOMAINS.GENERAL_SECURITY, declaredFamily = "") {
    const family = resolveProviderFamily(providerOrModel, declaredFamily);
    const domainTable = this.domainWeights[domain] || this.domainWeights[VULNERABILITY_DOMAINS.GENERAL_SECURITY];
    const weight = domainTable[family] !== undefined ? domainTable[family] : domainTable.unknown;
    return typeof weight === "number" && Number.isFinite(weight) && weight > 0 ? weight : 1.0;
  }

  /**
   * Computes the dynamic consensus threshold based on risk tier and active vulnerability domains.
   *
   * @param {object} params
   * @param {number} [params.riskTier=RISK_TIERS.TIER_2_SOURCE]
   * @param {Array<string>} [params.detectedDomains=[]]
   * @param {number} [params.fileCount=0]
   * @param {number} [params.lineCount=0]
   * @returns {number} Dynamic threshold clamped between 0.50 and 0.95
   */
  calculateDynamicThreshold({ riskTier = RISK_TIERS.TIER_2_SOURCE, detectedDomains = [], fileCount = 0, lineCount = 0 } = {}) {
    const base = this.tierThresholds[riskTier] !== undefined
      ? this.tierThresholds[riskTier]
      : this.tierThresholds[RISK_TIERS.TIER_2_SOURCE];

    // Find highest domain risk multiplier
    let maxDomainMultiplier = 1.0;
    for (const d of detectedDomains) {
      const mult = this.domainRiskCoefficients[d] || 1.0;
      if (mult > maxDomainMultiplier) {
        maxDomainMultiplier = mult;
      }
    }

    // Scale penalty for large diffs (e.g. > 5 files or > 200 lines)
    let scaleMultiplier = 1.0;
    if (fileCount > 5 || lineCount > 200) {
      scaleMultiplier = 1.05;
    }

    const calculated = base * maxDomainMultiplier * scaleMultiplier;
    // Clamped strictly between 0.50 and 0.95
    return parseFloat(Math.min(0.95, Math.max(0.50, calculated)).toFixed(4));
  }

  /**
   * Calibrates and deduplicates findings from reports using domain-weighted corroboration.
   *
   * @param {Array<object>} rawFindings
   * @param {Map<string, object>} healthyReportsMap
   * @returns {{ calibratedFindings: Array<object>, blockingFindings: Array<object>, domainCounts: Record<string, number> }}
   */
  calibrateFindings(rawFindings = [], healthyReportsMap = new Map(), physicalProof = null) {
    if (!Array.isArray(rawFindings) || rawFindings.length === 0) {
      return { calibratedFindings: [], blockingFindings: [], domainCounts: {} };
    }

    // Compute total available weights per domain across all healthy reviewers
    const totalDomainWeights = {};
    for (const domain of Object.values(VULNERABILITY_DOMAINS)) {
      let sum = 0;
      for (const rec of healthyReportsMap.values()) {
        const source = rec.provider || rec.source || rec.id;
        sum += this.getModelWeight(source, domain, rec.family);
      }
      totalDomainWeights[domain] = sum > 0 ? sum : 1.0;
    }

    const domainCounts = {};
    const calibratedFindings = [];

    for (const raw of rawFindings) {
      if (!raw || typeof raw !== "object") continue;

      const normCwe = normalizeCwe(raw.cwe);
      const classification = this.classifyDomain(raw, { filePath: raw.file });
      const domain = classification.domain;
      domainCounts[domain] = (domainCounts[domain] || 0) + 1;

      // Identify corroborating reporting agents
      const rawSources = Array.isArray(raw.sources)
        ? raw.sources
        : (typeof raw.sources === "string" ? [raw.sources] : []);
      const sourcesSet = new Set(rawSources);
      if (raw.sourceId) sourcesSet.add(raw.sourceId);
      if (raw.provider) sourcesSet.add(raw.provider);

      // Calculate weighted support for finding
      let findingWeightSum = 0;
      const corroboratingFamilies = new Set();

      for (const rec of healthyReportsMap.values()) {
        const recId = rec.id;
        const sourceName = rec.provider || rec.source || recId;
        const family = resolveProviderFamily(sourceName, rec.family);

        if (sourcesSet.has(recId) || sourcesSet.has(sourceName) || sourcesSet.has(family)) {
          findingWeightSum += this.getModelWeight(sourceName, domain, family);
          corroboratingFamilies.add(family);
        }
      }

      // If sources were not mapped to active reports, default finding weight to primary source
      if (findingWeightSum === 0) {
        const primarySource = raw.sourceId || raw.provider || "unknown";
        findingWeightSum = this.getModelWeight(primarySource, domain);
      }

      const totalWeightForDomain = totalDomainWeights[domain] || 1.0;
      let weightedConfidence = parseFloat(Math.min(1.0, findingWeightSum / totalWeightForDomain).toFixed(4));
      let isConfirmed = weightedConfidence >= this.findingAcceptanceThreshold;

      const severity = String(raw.severity || "info").toLowerCase().trim();
      let isBlocking = isConfirmed && BLOCKING_SEVERITIES.has(severity);
      let physicalProofOverride = false;

      // RFC-028-04 Section 4: Physical Proof Override (Machine proof trumps LLM consensus)
      if (physicalProof && typeof physicalProof === "object") {
        const proofCwe = normalizeCwe(physicalProof.cwe);
        const matchesCwe = normCwe && proofCwe && normCwe === proofCwe;
        const isVerifiedPoC = physicalProof.verified === true || physicalProof.status === "PATCH_INEFFECTIVE";

        if (matchesCwe && isVerifiedPoC) {
          physicalProofOverride = true;
          weightedConfidence = 1.0;
          isConfirmed = true;
          isBlocking = true;
        }
      }

      calibratedFindings.push({
        ...raw,
        cwe: normCwe || raw.cwe || classification.cwe || null,
        severity,
        taxonomyDomain: domain,
        matchedBy: classification.matchedBy,
        weightedConfidence,
        corroboratingFamilies: Array.from(corroboratingFamilies),
        isConfirmed,
        isBlocking,
        ...(physicalProofOverride ? { physicalProofOverride: true, proofDigest: physicalProof.digest || null } : {})
      });
    }

    const blockingFindings = calibratedFindings.filter(f => f.isBlocking);

    return {
      calibratedFindings,
      blockingFindings,
      domainCounts
    };
  }

  /**
   * Main Arbitration & Quorum Calibration Engine.
   *
   * @param {object} input
   * @param {Array<object>|object|Map} input.reports Collection of reviewer reports
   * @param {Array<object>} [input.files=[]] Changeset files for risk-tier classification
   * @param {number} [input.riskTier] Explicit risk tier override
   * @param {object} [input.policyOptions={}]
   * @returns {object} Calibrated Quorum Decision with cryptographic consensus proof
   */
  calibrateQuorum(input = {}) {
    const safeInput = input && typeof input === "object" ? input : {};
    const { reports, files = [], policyOptions = {}, physicalProof = null } = safeInput;

    // 1. Normalize reports into validated Map
    const normalizedReports = this._normalizeReports(reports);
    const healthyReportsMap = new Map();
    const unhealthyReportsMap = new Map();
    const familyToReports = new Map();

    for (const [id, rec] of normalizedReports.entries()) {
      if (rec.healthy) {
        healthyReportsMap.set(id, rec);
        const family = resolveProviderFamily(rec.provider || rec.source || id, rec.family);
        if (!familyToReports.has(family)) {
          familyToReports.set(family, []);
        }
        familyToReports.get(family).push(rec);
      } else {
        unhealthyReportsMap.set(id, rec);
      }
    }

    // 2. Classify Risk Tier
    let riskTier = safeInput.riskTier;
    if (typeof riskTier !== "number") {
      riskTier = this._determineRiskTier(files, policyOptions);
    }

    const isTier1 = riskTier === RISK_TIERS.TIER_1_CRITICAL;
    const healthyFamilies = Array.from(familyToReports.keys()).filter(f => f !== "unknown");
    const selectedReportIds = Array.from(healthyReportsMap.keys());

    // 3. Invariant Verification: Multi-Provider Diversity for Tier 1
    if (isTier1 && healthyFamilies.length < this.minTier1ProviderDiversity) {
      return deepFreeze({
        quorumReached: false,
        verdict: "error",
        topology: "QUORUM_FAILED",
        riskTier,
        calibratedThreshold: this.tierThresholds[RISK_TIERS.TIER_1_CRITICAL],
        weightedApprovalScore: 0,
        selectedReportIds: [],
        findings: [],
        blockingFindings: [],
        domainBreakdown: {},
        reason: `Quorum Failure: High-risk Tier 1 changesets require at least ${this.minTier1ProviderDiversity} healthy heterogeneous provider families (got ${healthyFamilies.length}: [${healthyFamilies.join(", ")}]).`,
        consensusProof: this._generateProof({
          status: "FAILED_DIVERSITY",
          riskTier,
          healthyFamilies
        })
      });
    }

    // Zero healthy reports fail closed
    if (healthyReportsMap.size === 0) {
      return deepFreeze({
        quorumReached: false,
        verdict: "error",
        topology: "QUORUM_FAILED",
        riskTier,
        calibratedThreshold: this.tierThresholds[riskTier] || 0.65,
        weightedApprovalScore: 0,
        selectedReportIds: [],
        findings: [],
        blockingFindings: [],
        domainBreakdown: {},
        reason: "Quorum Failure: No healthy reviewer reports available.",
        consensusProof: this._generateProof({ status: "ZERO_HEALTHY", riskTier })
      });
    }

    // 4. Extract and Calibrate Findings
    const aggregatedRawFindings = [];
    for (const [id, rec] of healthyReportsMap.entries()) {
      if (Array.isArray(rec.findings)) {
        for (const f of rec.findings) {
          aggregatedRawFindings.push({
            ...f,
            sourceId: f.sourceId || id,
            provider: f.provider || rec.provider || rec.source || id
          });
        }
      }
    }

    const { calibratedFindings, blockingFindings, domainCounts } = this.calibrateFindings(
      aggregatedRawFindings,
      healthyReportsMap,
      physicalProof
    );

    const detectedDomains = Object.keys(domainCounts);

    // 5. Calculate Dynamic Threshold
    const lineCount = files.reduce((acc, f) => acc + (f.additions || 0) + (f.deletions || 0), 0);
    const dynamicThreshold = this.calculateDynamicThreshold({
      riskTier,
      detectedDomains,
      fileCount: files.length,
      lineCount
    });

    // 6. Compute Domain-Weighted Model Votes
    let totalReviewerWeight = 0;
    let approvingWeight = 0;
    const reviewerVotes = [];

    // Dominant domain for weighting (or general if none/multiple)
    const dominantDomain = detectedDomains.length === 1
      ? detectedDomains[0]
      : (detectedDomains.includes(VULNERABILITY_DOMAINS.MEMORY_SAFETY)
          ? VULNERABILITY_DOMAINS.MEMORY_SAFETY
          : (detectedDomains.includes(VULNERABILITY_DOMAINS.CONCURRENCY_LOGIC)
              ? VULNERABILITY_DOMAINS.CONCURRENCY_LOGIC
              : (detectedDomains.includes(VULNERABILITY_DOMAINS.GLOBAL_ARCHITECTURE)
                  ? VULNERABILITY_DOMAINS.GLOBAL_ARCHITECTURE
                  : VULNERABILITY_DOMAINS.GENERAL_SECURITY)));

    for (const [id, rec] of healthyReportsMap.entries()) {
      const source = rec.provider || rec.source || id;
      const weight = this.getModelWeight(source, dominantDomain, rec.family);
      totalReviewerWeight += weight;

      // Determine individual vote
      const voteApprove = this._isReportApproving(rec, blockingFindings);
      if (voteApprove) {
        approvingWeight += weight;
      }

      reviewerVotes.push({
        id,
        source,
        family: resolveProviderFamily(source, rec.family),
        weight,
        approves: voteApprove
      });
    }

    const weightedApprovalScore = totalReviewerWeight > 0
      ? parseFloat((approvingWeight / totalReviewerWeight).toFixed(4))
      : 0;

    // 7. Synthesize Verdict & Quorum Formation
    const meetsThreshold = weightedApprovalScore >= dynamicThreshold;
    const hasBlockers = blockingFindings.length > 0;

    let quorumReached = false;
    let verdict = "error";
    let topology = "NOMINAL_HETEROGENEOUS";
    let reason = null;

    if (hasBlockers) {
      // Blocking findings present: cannot approve!
      // Quorum is reached on blocker verification, verdict is needs-attention
      quorumReached = true;
      verdict = "needs-attention";
      reason = `Taxonomy arbitration detected ${blockingFindings.length} blocking finding(s) in [${detectedDomains.join(", ")}].`;
    } else if (meetsThreshold) {
      quorumReached = true;
      verdict = calibratedFindings.length > 0 ? "warning" : "approve";
      reason = `Dynamic quorum reached (score: ${weightedApprovalScore} >= threshold: ${dynamicThreshold}).`;
    } else {
      quorumReached = false;
      verdict = "needs-attention";
      reason = `Dynamic quorum threshold not met (weighted score: ${weightedApprovalScore} < required: ${dynamicThreshold}).`;
    }

    const consensusProof = this._generateProof({
      riskTier,
      dynamicThreshold,
      weightedApprovalScore,
      dominantDomain,
      selectedReportIds,
      blockingCount: blockingFindings.length,
      verdict,
      quorumReached
    });

    return deepFreeze({
      quorumReached,
      verdict,
      topology,
      riskTier,
      calibratedThreshold: dynamicThreshold,
      weightedApprovalScore,
      dominantDomain,
      selectedReportIds,
      findings: calibratedFindings,
      blockingFindings,
      domainBreakdown: domainCounts,
      reviewerVotes,
      reason,
      consensusProof
    });
  }

  /**
   * Creates a policy function compatible with Triad-Flow QuorumPolicies and aggregateConsensus.
   */
  createQuorumPolicy() {
    return (metadataMap = {}, policyOptions = {}) => {
      const reports = [];
      for (const [id, rec] of Object.entries(metadataMap)) {
        reports.push({
          id,
          source: rec.source || id,
          provider: rec.provider || rec.source || id,
          family: rec.family,
          healthy: rec.healthy !== false,
          error: rec.error || null,
          findings: rec.findings || []
        });
      }

      const result = this.calibrateQuorum({
        reports,
        files: policyOptions.files || [],
        riskTier: policyOptions.tier || policyOptions.riskTier,
        policyOptions
      });

      return {
        quorumReached: result.quorumReached,
        topology: result.topology,
        selectedReportIds: result.selectedReportIds,
        calibratedThreshold: result.calibratedThreshold,
        weightedApprovalScore: result.weightedApprovalScore,
        findings: result.findings,
        reason: result.reason,
        consensusProof: result.consensusProof
      };
    };
  }

  _isReportApproving(rec, blockingFindings = []) {
    // If the report explicitly declared verdict
    if (typeof rec.verdict === "string") {
      const v = rec.verdict.toLowerCase().trim();
      if (v === "approve" || v === "warning") return true;
      if (v === "error" || v === "needs-attention") return false;
    }
    // If report has boolean approve property
    if (typeof rec.approve === "boolean") {
      return rec.approve;
    }
    // If report reported any blocking findings itself
    if (Array.isArray(rec.findings) && hasBlockingFindings(rec.findings)) {
      return false;
    }
    return true;
  }

  _normalizeReports(reports) {
    const map = new Map();
    if (!reports) return map;

    if (reports instanceof Map) {
      for (const [k, v] of reports.entries()) {
        map.set(k, { id: k, healthy: true, ...v });
      }
    } else if (Array.isArray(reports)) {
      reports.forEach((r, idx) => {
        if (r && typeof r === "object") {
          const id = r.id || `rep-${idx}`;
          map.set(id, { id, healthy: true, ...r });
        }
      });
    } else if (typeof reports === "object") {
      for (const [k, v] of Object.entries(reports)) {
        if (v && typeof v === "object") {
          map.set(k, { id: k, healthy: true, ...v });
        }
      }
    }
    return map;
  }

  _determineRiskTier(files = [], policyOptions = {}) {
    if (typeof policyOptions.tier === "number") {
      return policyOptions.tier;
    }
    if (policyOptions.risk === "high" || policyOptions.isCritical) {
      return RISK_TIERS.TIER_1_CRITICAL;
    }

    if (!Array.isArray(files) || files.length === 0) {
      return RISK_TIERS.TIER_2_SOURCE;
    }

    let highestRisk = RISK_TIERS.TIER_3_DOCS;
    for (const f of files) {
      const p = typeof f === "string" ? f : (f.path || f.file || "");
      const risk = classifyFileRisk(p);
      if (risk < highestRisk) {
        highestRisk = risk;
      }
    }
    return highestRisk;
  }

  _generateProof(payload) {
    const raw = JSON.stringify(payload);
    return crypto.createHash("sha256").update(raw).digest("hex");
  }
}
