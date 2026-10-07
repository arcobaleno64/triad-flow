/**
 * Hardened Harness Engineering: Safety Scaffolding, Secret Redaction, Sentry Normalization, Recursive Symlink Sandbox & SARIF Compliance
 */

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { isTrustedConsensus, hasBlockingFindings, VALID_SEVERITY_SET } from "./consensus-state.mjs";

export const SECRET_PATTERNS = [
  // Google API Keys
  /\bAIza[0-9A-Za-z-_]{20,45}\b/g,
  // OpenAI Keys (Legacy sk-, Project sk-proj-, Admin sk-admin-)
  /\bsk-(?:proj-|admin-)?[a-zA-Z0-9_\-]{20,}\b/g,
  // Anthropic Keys
  /\bsk-ant-[a-zA-Z0-9_\-]{20,}\b/g,
  // GitHub Tokens
  /\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}\b/g,
  /\bgithub_pat_[a-zA-Z0-9_]{50,}\b/g,
  // AWS Access Key ID
  /\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/g,
  // JWT Tokens
  /\b(?:bearer\s+)?eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\b/gi,
  // PEM Private Keys
  /-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY(?: BLOCK)?-----[\s\S]+?-----END (?:[A-Z0-9_-]+ )?PRIVATE KEY(?: BLOCK)?-----/g
];

export function redactSecrets(text = "") {
  if (typeof text !== "string") return text;
  let sanitized = text;
  for (const pattern of SECRET_PATTERNS) {
    sanitized = sanitized.replace(pattern, "[REDACTED_SECRET]");
  }
  return sanitized;
}

export function stripExtendedPrefix(p) {
  if (typeof p !== "string") return p;
  if (p.startsWith("\\\\?\\UNC\\")) return "\\\\" + p.slice(8);
  if (p.startsWith("\\\\?\\")) return p.slice(4);
  return p;
}

const WINDOWS_RESERVED_DEVICE_REGEX = /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$/i;

/**
 * Hardened Workspace Boundary Check: Multi-hop Recursive Symlink Resolution
 * Invariants (INV-07, P1-04):
 * - workspaceRoot must exist and be a directory.
 * - Resolves symlink chains recursively (up to MAX_HOPS = 32), detecting cycles.
 * - Ensures all intermediate symlink hops and final targets stay strictly inside canonicalRoot.
 */
export function isPathSafe(targetPath, workspaceRoot) {
  if (typeof targetPath !== "string" || typeof workspaceRoot !== "string") return false;
  if (!targetPath.trim() || !workspaceRoot.trim()) return false;
  if (targetPath.includes("\0") || workspaceRoot.includes("\0")) return false;

  const isWin = process.platform === "win32";

  // 1. Windows DOS Device & Alternate Data Stream (ADS) Checks
  if (isWin) {
    const rawSegments = targetPath.split(/[\\/]/);
    for (const seg of rawSegments) {
      if (WINDOWS_RESERVED_DEVICE_REGEX.test(seg)) return false;
      if (seg.includes(":") && seg.indexOf(":") !== 1) return false;
    }
  }

  try {
    if (!fs.existsSync(workspaceRoot)) return false;
    const rootStat = fs.statSync(workspaceRoot);
    if (!rootStat.isDirectory()) return false;

    const rawCanonicalRoot = fs.realpathSync.native
      ? fs.realpathSync.native(workspaceRoot)
      : fs.realpathSync(workspaceRoot);
    const canonicalRoot = stripExtendedPrefix(rawCanonicalRoot);

    const isInsideRoot = (absPath) => {
      const normAbs = stripExtendedPrefix(absPath);
      const rel = path.relative(canonicalRoot, normAbs);
      const normRel = isWin ? rel.toLowerCase() : rel;
      return normRel !== ".." && !normRel.startsWith(".." + path.sep) && !path.isAbsolute(normRel);
    };

    // 2. Lexical traversal pre-check
    const resolvedTarget = path.resolve(canonicalRoot, targetPath);
    if (!isInsideRoot(resolvedTarget)) {
      return false;
    }

    // 3. Multi-hop recursive symlink resolution
    const MAX_HOPS = 32;
    let hopCount = 0;
    const visitedSymlinks = new Set();

    let currentDir = canonicalRoot;
    const remainingSegments = path.relative(canonicalRoot, resolvedTarget).split(/[\\/]/).filter(Boolean);

    while (remainingSegments.length > 0) {
      const nextSegment = remainingSegments.shift();
      let candidatePath = path.join(currentDir, nextSegment);

      // Inner loop: Recursively resolve symlink hops for candidatePath
      while (true) {
        let segStat;
        try {
          segStat = fs.lstatSync(candidatePath);
        } catch (err) {
          if (err.code === "ENOENT") {
            // Path does not exist on disk.
            // Ensure remaining path from currentDir lexically stays inside canonicalRoot
            const futurePath = path.resolve(currentDir, [nextSegment, ...remainingSegments].join(path.sep));
            return isInsideRoot(futurePath);
          }
          return false; // EPERM, EACCES, ELOOP => Fail-Closed
        }

        if (!segStat.isSymbolicLink()) {
          break; // Concrete directory or regular file
        }

        hopCount++;
        if (hopCount > MAX_HOPS) {
          return false; // Exceeded max hops => Fail-closed
        }

        const linkKey = isWin ? candidatePath.toLowerCase() : candidatePath;
        if (visitedSymlinks.has(linkKey)) {
          return false; // Symlink cycle detected => Fail-closed without hanging
        }
        visitedSymlinks.add(linkKey);

        const linkDest = fs.readlinkSync(candidatePath);
        const resolvedLinkDest = path.resolve(path.dirname(candidatePath), linkDest);

        // Intermediate hop MUST remain inside canonicalRoot
        if (!isInsideRoot(resolvedLinkDest)) {
          return false;
        }

        candidatePath = resolvedLinkDest;
      }

      currentDir = candidatePath;
    }

    return isInsideRoot(currentDir);
  } catch {
    return false; // Fail-closed on any runtime error
  }
}

export const VALID_SEVERITIES = VALID_SEVERITY_SET;

/**
 * Validates and normalizes an individual finding.
 * Invariant (P1-03): Preserves filename whitespace in 'file'/'path' while trimming human prose.
 * Rejects illegal NUL bytes with Fail-Closed.
 */
export function normalizeFinding(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return { valid: false, reason: "Finding must be a non-null plain object." };
  }

  const rawTitle = typeof raw.title === "string" ? raw.title.trim() : "";
  const rawMessage = typeof raw.message === "string" ? raw.message.trim() : "";
  const title = rawTitle || rawMessage;
  if (!title) {
    return { valid: false, reason: "Finding missing required non-empty title or message." };
  }

  const rawSev = typeof raw.severity === "string" ? raw.severity.trim().toLowerCase() : "";
  if (!VALID_SEVERITY_SET.has(rawSev)) {
    return { valid: false, reason: `Unknown or invalid severity: '${raw.severity}'. Strict enum required.` };
  }

  let lineStart = 1;
  if (raw.line_start !== undefined && raw.line_start !== null) {
    const n = Number(raw.line_start);
    if (!Number.isInteger(n) || n < 1) {
      return { valid: false, reason: `Invalid line_start: ${raw.line_start}. Must be a positive integer >= 1.` };
    }
    lineStart = n;
  } else if (raw.line !== undefined && raw.line !== null) {
    const n = Number(raw.line);
    if (!Number.isInteger(n) || n < 1) {
      return { valid: false, reason: `Invalid line: ${raw.line}. Must be a positive integer >= 1.` };
    }
    lineStart = n;
  }

  let lineEnd = lineStart;
  if (raw.line_end !== undefined && raw.line_end !== null) {
    const n = Number(raw.line_end);
    if (!Number.isInteger(n) || n < lineStart) {
      return { valid: false, reason: `Invalid line_end: ${raw.line_end}. Must be >= line_start (${lineStart}).` };
    }
    lineEnd = n;
  }

  // Preserve exact filename whitespace without .trim()
  const rawFile = typeof raw.file === "string" ? raw.file : (typeof raw.path === "string" ? raw.path : "");
  if (rawFile.includes("\0")) {
    return { valid: false, reason: "Finding file path contains illegal NUL byte." };
  }
  const file = rawFile;

  return {
    valid: true,
    finding: {
      title,
      severity: rawSev,
      file,
      line_start: lineStart,
      line_end: lineEnd,
      ruleId: typeof raw.ruleId === "string" ? raw.ruleId.trim() : undefined,
      cwe: typeof raw.cwe === "string" ? raw.cwe.trim() : undefined,
      type: typeof raw.type === "string" ? raw.type.trim() : undefined,
      recommendation: typeof raw.recommendation === "string" ? raw.recommendation.trim() : (typeof raw.body === "string" ? raw.body.trim() : undefined)
    }
  };
}

/**
 * Validates a single Sentry Report object.
 */
export function validateSentryReport(report) {
  if (!report || typeof report !== "object" || Array.isArray(report)) {
    return { valid: false, reason: "Sentry report must be a non-null object." };
  }
  if (report.error) {
    return { valid: false, reason: `Sentry reported error: ${report.error}` };
  }
  if (!Array.isArray(report.findings)) {
    return { valid: false, reason: "Sentry report.findings must be an array." };
  }

  const normalizedFindings = [];
  for (let i = 0; i < report.findings.length; i++) {
    const norm = normalizeFinding(report.findings[i]);
    if (!norm.valid) {
      return { valid: false, reason: `Malformed finding at index ${i}: ${norm.reason}` };
    }
    normalizedFindings.push(norm.finding);
  }

  return {
    valid: true,
    report: {
      ...report,
      findings: normalizedFindings
    }
  };
}

/**
 * Evaluates CI Gate decision with In-Process Trusted Consensus Capability requirement.
 * Rejects untrusted plain objects, clones or detached signatures with Fail-Closed.
 */
export function evaluateGateDecision(consensus, options = {}) {
  // 1. Mandatory capability verification
  if (!isTrustedConsensus(consensus)) {
    return {
      decision: "block",
      reason: "Gate Fail-Closed: Untrusted consensus capability (UNTRUSTED_CONSENSUS).",
      criticals: []
    };
  }

  // 2. Read from single coherent trusted consensus object
  if (!consensus.quorumReached || consensus.verdict === "error") {
    return {
      decision: "block",
      reason: consensus.consensusProof || "Gate Fail-Closed: Quorum failure or error verdict.",
      criticals: []
    };
  }

  if (options?.coverageOk === false || consensus?.coverageOk === false) {
    return {
      decision: "block",
      reason: "Coverage Incomplete: Sentry omitted file(s) from review.",
      criticals: []
    };
  }

  const findings = Array.isArray(consensus.findings) ? consensus.findings : [];
  if (findings.length === 0) {
    return {
      decision: "approve",
      reason: "No blocking vulnerabilities found. CI/CD Gate passed.",
      criticals: []
    };
  }

  // If verificationRecord is provided, execute post-verification gate authority
  if (options?.verificationRecord) {
    return evaluatePostVerificationGate(consensus, options.verificationRecord, options);
  }

  const criticals = findings.filter(f => f && (f.severity === "critical" || f.severity === "high"));

  if (criticals.length > 0) {
    return {
      decision: "block",
      reason: `Found ${criticals.length} critical/high severity findings. Merge blocked.`,
      criticals
    };
  }

  // Tier 1 (High-Risk) or Strict Mode: Any confirmed findings block merge
  const isTier1 = options?.tier === 1;
  const isStrict = Boolean(options && (options.strict || isTier1));

  if (findings.length > 0 && isStrict) {
    return {
      decision: "block",
      reason: isTier1
        ? `Tier 1 high-risk policy: ${findings.length} findings must be resolved before merge. Merge blocked.`
        : `Strict mode enabled: ${findings.length} findings must be resolved.`,
      criticals: []
    };
  }

  return {
    decision: "approve",
    reason: "No blocking vulnerabilities found. CI/CD Gate passed.",
    criticals: []
  };
}

/**
 * Evaluates Post-Verification Gate decision incorporating Independent Verification authority.
 * Adheres to normative LOOP2-REMEDIATION-001 authority rules:
 * - Critical/High findings remain strictly fail-closed BLOCK (or HUMAN_REVIEW_REQUIRED if contested)
 * - Supported Low/Medium findings block in Tier 1
 * - Supported Medium findings block in Tier 2
 * - Supported Low findings pass as advisory in Tier 2 unless independent verification marks them as directly falsifying the stated patch objective
 * - Any independently SUPPORTED finding marked FALSIFIES_PATCH_OBJECTIVE blocks regardless of impact severity
 * - Solitary non-Critical/High findings with INSUFFICIENT_EVIDENCE map to HUMAN_REVIEW_REQUIRED
 * - Solitary findings with CONTESTED verdict are removed from blocking set (advisory pass)
 * - Corroborated findings with CONTESTED verdict map to HUMAN_REVIEW_REQUIRED
 * - Structural failures (coverage, quorum, capability, verification error) strictly FAIL-CLOSED BLOCK
 */
export function evaluatePostVerificationGate(consensus, verificationRecord, options = {}) {
  if (!verificationRecord || verificationRecord.ok === false) {
    return {
      decision: "block",
      reason: "Gate Fail-Closed: Verifier execution failed, timed out, or incomplete.",
      criticals: []
    };
  }

  const findings = Array.isArray(consensus.findings) ? consensus.findings : [];
  const evaluations = Array.isArray(verificationRecord.evaluations) ? verificationRecord.evaluations : [];
  const hasBoundPatchObjective =
    typeof verificationRecord.patchObjective === "string" &&
    verificationRecord.patchObjective.trim().length > 0;
  const isTier1 = options?.tier === 1;
  const isStrict = Boolean(options && (options.strict || isTier1));

  let hasBlocker = false;
  let hasHumanReview = false;
  const blockReasons = [];
  const humanReviewReasons = [];
  const criticals = [];

  for (let i = 0; i < findings.length; i++) {
    const f = findings[i];
    if (!f) continue;

    const evalMatch = evaluations.find(e =>
      (f.id && String(e.findingId) === String(f.id)) ||
      (f.findingId && String(e.findingId) === String(f.findingId)) ||
      String(e.findingId) === `finding-${i + 1}`
    ) || evaluations[i];

    const verdict = String(evalMatch?.verdict || "INSUFFICIENT_EVIDENCE").toUpperCase();
    const classification = String(evalMatch?.classification || "").toUpperCase();
    const isContested = verdict === "CONTESTED" || classification === "CONTRADICTED";
    const isSupported = verdict === "SUPPORTED";
    const isInsufficient = verdict === "INSUFFICIENT_EVIDENCE" || classification === "UNVERIFIABLE";
    const objectiveImpact = String(evalMatch?.objectiveImpact || "NOT_ASSESSED").toUpperCase();
    const falsifiesPatchObjective =
      isSupported &&
      !isContested &&
      hasBoundPatchObjective &&
      objectiveImpact === "FALSIFIES_PATCH_OBJECTIVE";

    const corroborations = Number(f.corroborations || f.sources?.length || 1);
    const isSolitary = corroborations <= 1;
    const isCorroborated = corroborations >= 2;

    const rawSeverity = String(f.severity || "medium").toLowerCase();
    let effectiveSeverity = rawSeverity;

    if (evalMatch && evalMatch.severityAccurate === false) {
      if (rawSeverity === "critical" || rawSeverity === "high") {
        hasHumanReview = true;
        humanReviewReasons.push(`Critical/high severity contested by verifier: "${f.title}"`);
        if (!falsifiesPatchObjective) continue;
      } else if (rawSeverity === "medium" && isSupported) {
        effectiveSeverity = "low";
      }
    }

    if (falsifiesPatchObjective) {
      hasBlocker = true;
      if (rawSeverity === "critical" || rawSeverity === "high") criticals.push(f);
      blockReasons.push(`Verified finding directly falsifies stated patch objective: "${f.title}"`);
      continue;
    }

    if (effectiveSeverity === "critical" || effectiveSeverity === "high") {
      if (isContested) {
        hasHumanReview = true;
        humanReviewReasons.push(`Critical/high severity finding contested by verifier: "${f.title}"`);
      } else {
        hasBlocker = true;
        criticals.push(f);
        blockReasons.push(`Found critical/high severity finding: "${f.title}"`);
      }
    } else if (effectiveSeverity === "medium") {
      if (isContested) {
        if (isCorroborated) {
          hasHumanReview = true;
          humanReviewReasons.push(`Corroborated medium finding contested by verifier: "${f.title}"`);
        } else {
          // Solitary medium finding contested by verifier -> removed from blocking set (advisory)
        }
      } else if (isInsufficient) {
        if (isCorroborated) {
          hasBlocker = true;
          blockReasons.push(`Corroborated medium finding cannot be substantiated by verifier: "${f.title}"`);
        } else {
          hasHumanReview = true;
          humanReviewReasons.push(`Solitary medium finding cannot be substantiated by verifier (INSUFFICIENT_EVIDENCE): "${f.title}"`);
        }
      } else if (isSupported) {
        hasBlocker = true;
        blockReasons.push(isTier1
          ? `Tier 1 high-risk policy: verified medium finding blocks merge: "${f.title}"`
          : `Verified medium finding blocks merge: "${f.title}"`);
      }
    } else if (effectiveSeverity === "low") {
      if (isContested) {
        if (isCorroborated && (f.type === "OBJECTIVE_CONTRADICTION" || f.ruleId === "OBJECTIVE-CONTRADICTION")) {
          hasHumanReview = true;
          humanReviewReasons.push(`Corroborated objective contradiction contested by verifier requires human adjudication: "${f.title}"`);
        }
        // Otherwise solitary contested low finding -> removed from blocking set
      } else if (isInsufficient) {
        if (isTier1 && isStrict) {
          hasHumanReview = true;
          humanReviewReasons.push(`Tier 1 low finding unverifiable: "${f.title}"`);
        }
        // In Tier 2: unverified low finding does not block
      } else if (isSupported) {
        if (isTier1 || isStrict) {
          hasBlocker = true;
          blockReasons.push(`Tier 1 policy: verified low finding blocks merge: "${f.title}"`);
        }
        // In Tier 2 non-strict: verified low finding passes as advisory
      }
    }
  }

  if (hasBlocker) {
    return {
      decision: "block",
      reason: blockReasons[0] || "Blocking findings identified by verified review.",
      criticals
    };
  }

  if (hasHumanReview) {
    return {
      decision: "human_review_required",
      reason: humanReviewReasons[0] || "Review requires human adjudication.",
      criticals: []
    };
  }

  return {
    decision: "approve",
    reason: "No blocking vulnerabilities found. CI/CD Gate passed.",
    criticals: []
  };
}

function sanitizeText(str) {
  if (typeof str !== "string") return "";
  return str
    .replace(/\u001b\[[0-9;]*[a-zA-Z]/g, "")
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
}

export function toSarifRelativeUri(filePath) {
  if (typeof filePath !== "string" || !filePath.trim()) return "unknown";

  if (/^(?:javascript|data|vbscript|file):/i.test(filePath)) {
    return "sanitized-path-blocked";
  }

  let normalized = filePath.replace(/\\/g, "/").replace(/^\/+/, "");
  return normalized
    .split("/")
    .map(seg => encodeURIComponent(seg))
    .join("/");
}

export function deriveRuleId(finding = {}) {
  if (finding.ruleId && typeof finding.ruleId === "string" && finding.ruleId.trim()) {
    return finding.ruleId.trim();
  }

  const rawTitle = sanitizeText(String(finding.title || finding.message || "security_finding")).trim().normalize("NFC");
  const slug = rawTitle
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 32) || "finding";

  const hash = crypto.createHash("sha256").update(rawTitle, "utf8").digest("hex").slice(0, 8);
  return `${slug}_${hash}`;
}

export function formatSarifReport(findings = [], metadata = {}) {
  const ruleMap = new Map();

  for (const f of findings) {
    const rawTitle = sanitizeText(String(f?.title || "Security Finding")).trim().normalize("NFC");
    const ruleId = deriveRuleId(f);

    if (!ruleMap.has(ruleId)) {
      ruleMap.set(ruleId, {
        id: ruleId,
        name: rawTitle,
        shortDescription: { text: rawTitle }
      });
    }
  }

  const driverRules = Array.from(ruleMap.values()).sort((a, b) => a.id.localeCompare(b.id));
  const ruleIndexMap = new Map(driverRules.map((r, idx) => [r.id, idx]));

  const results = findings.map(f => {
    const rawTitle = sanitizeText(String(f?.title || "Security Finding")).trim().normalize("NFC");
    const body = sanitizeText(String(f?.recommendation || f?.body || f?.summary || f?.message || rawTitle));
    const ruleId = deriveRuleId(f);
    const ruleIndex = ruleIndexMap.get(ruleId) ?? 0;

    const startLine = Math.max(1, Math.floor(Number(f?.line_start || f?.line) || 1));
    const endLine = Math.max(startLine, Math.floor(Number(f?.line_end) || startLine));
    const uri = toSarifRelativeUri(f?.file || f?.path);

    return {
      ruleId,
      ruleIndex,
      level: /critical|high/i.test(String(f?.severity || "")) ? "error" : "warning",
      message: { text: body },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri },
            region: {
              startLine,
              endLine
            }
          }
        }
      ]
    };
  });

  return {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Triad-Flow Sentry",
            version: "2.7.0",
            informationUri: "https://github.com/arcobaleno64/triad-flow",
            rules: driverRules
          }
        },
        ...(metadata.executionSuccessful !== undefined || metadata.failureReason ? {
          invocations: [
            {
              executionSuccessful: metadata.executionSuccessful !== false,
              ...(metadata.failureReason ? {
                toolExecutionNotifications: [
                  {
                    level: metadata.executionSuccessful === false ? "error" : "note",
                    message: { text: sanitizeText(String(metadata.failureReason)) }
                  }
                ]
              } : {})
            }
          ]
        } : {}),
        results
      }
    ]
  };
}

/**
 * Validates a SARIF report object against the OASIS SARIF 2.1.0 specification structure.
 */
export function validateSarifStructure(sarif) {
  const errors = [];

  if (!sarif || typeof sarif !== "object" || Array.isArray(sarif)) {
    return { valid: false, errors: ["SARIF document must be a non-null object."] };
  }

  if (sarif.version !== "2.1.0") {
    errors.push(`SARIF version must be exactly '2.1.0', received: '${sarif.version}'`);
  }

  if (typeof sarif.$schema !== "string" || !sarif.$schema.includes("sarif")) {
    errors.push("SARIF $schema must be a valid schema URI string.");
  }

  if (!Array.isArray(sarif.runs) || sarif.runs.length === 0) {
    errors.push("SARIF runs must be a non-empty array.");
  } else {
    sarif.runs.forEach((run, runIdx) => {
      if (!run.tool?.driver?.name) {
        errors.push(`Run[${runIdx}]: tool.driver.name is required.`);
      }
      if (!run.tool?.driver?.version) {
        errors.push(`Run[${runIdx}]: tool.driver.version is required.`);
      }
      if (!Array.isArray(run.tool?.driver?.rules)) {
        errors.push(`Run[${runIdx}]: tool.driver.rules must be an array.`);
      }

      const driverRules = run.tool?.driver?.rules || [];
      const ruleIds = new Set(driverRules.map(r => r.id));

      if (run.invocations) {
        if (!Array.isArray(run.invocations)) {
          errors.push(`Run[${runIdx}]: invocations must be an array.`);
        } else {
          run.invocations.forEach((inv, invIdx) => {
            if (typeof inv.executionSuccessful !== "boolean") {
              errors.push(`Run[${runIdx}].invocations[${invIdx}]: executionSuccessful boolean is required.`);
            }
          });
        }
      }

      if (!Array.isArray(run.results)) {
        errors.push(`Run[${runIdx}]: results must be an array.`);
      } else {
        run.results.forEach((res, resIdx) => {
          if (!res.ruleId) {
            errors.push(`Run[${runIdx}].results[${resIdx}]: ruleId is required.`);
          } else if (!ruleIds.has(res.ruleId)) {
            errors.push(`Run[${runIdx}].results[${resIdx}]: ruleId '${res.ruleId}' is not declared in driver.rules.`);
          }
          if (typeof res.ruleIndex !== "number" || res.ruleIndex < 0 || res.ruleIndex >= driverRules.length) {
            errors.push(`Run[${runIdx}].results[${resIdx}]: ruleIndex '${res.ruleIndex}' is out of bounds.`);
          }
          if (!["error", "warning", "note", "none"].includes(res.level)) {
            errors.push(`Run[${runIdx}].results[${resIdx}]: level '${res.level}' is invalid.`);
          }
          if (!res.message?.text) {
            errors.push(`Run[${runIdx}].results[${resIdx}]: message.text is required.`);
          }
          if (!Array.isArray(res.locations) || res.locations.length === 0) {
            errors.push(`Run[${runIdx}].results[${resIdx}]: locations must be a non-empty array.`);
          }
        });
      }
    });
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

