/**
 * Triad-Flow Baseline Artifact Manifest Bundle Engine (Phase 3 RC)
 *
 * Implements Contract 5 of TF-SPEC-RECEIPT-v1.0.0:
 * - Generates summary.md embedding Run ID, Git Commit, Corpus Digest, Receipt Digest, Results Digest.
 * - Builds artifact-manifest.json recording SHA-256 for all artifacts via buildArtifactManifest.
 * - Verifies manifest bundle integrity, detecting any file modification, missing file, or digest mismatch.
 */

import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import {
  computeDigest,
  normalizeLineEndings
} from "./canonical-digest.mjs";
import {
  buildArtifactManifest,
  validateArtifactManifest,
  computeReceiptDigest,
  ReceiptValidationError,
  UnsupportedReceiptSchemaError
} from "./audit-receipt.mjs";

export const DEFAULT_ARTIFACT_NAMES = Object.freeze({
  RESULTS: "benchmark-results.json",
  RECEIPT: "audit-receipt.json",
  SUMMARY: "summary.md",
  MANIFEST: "artifact-manifest.json"
});

export const MANDATORY_ARTIFACT_FILES = Object.freeze([
  DEFAULT_ARTIFACT_NAMES.RESULTS,
  DEFAULT_ARTIFACT_NAMES.RECEIPT,
  DEFAULT_ARTIFACT_NAMES.SUMMARY
]);

/**
 * Formats a clean markdown summary embedding cryptographic provenance and benchmark results.
 *
 * @param {object} params
 * @param {object} [params.results]
 * @param {object} [params.receipt]
 * @param {object} params.metadata
 * @param {Record<string, string>} [params.artifacts]
 * @returns {string} Markdown text with LF line endings.
 */
export function formatSummaryMarkdown({ results = {}, receipt = null, metadata = {}, artifacts = {} } = {}) {
  const runId = metadata.runId || receipt?.run?.runId || results?.runId || "unknown";
  const commitSha = metadata.commitSha || receipt?.systemProvenance?.commitSha || "unknown";
  const corpusDigest = metadata.corpusDigest || receipt?.identity?.corpusDigest || "unknown";
  const receiptDigest = metadata.receiptDigest || "unknown";
  const resultsDigest = metadata.resultsDigest || artifacts["benchmark-results.json"] || "unknown";

  const corpusVersion = receipt?.identity?.corpusVersion || "TF-RBC-v0";
  const framework = results?.framework || "Triad-Flow Real Benchmark Corpus v0 (TF-RBC-v0)";
  const mode = results?.mode || receipt?.results?.mode || "single";
  const executionMode = results?.executionMode || (results?.live ? "live" : "mock");
  const workspaceMode = results?.workspaceMode || (results?.virtual ? "virtual" : "physical");
  const startedAt = receipt?.run?.startedAt || results?.timestamp || new Date().toISOString();
  const finishedAt = receipt?.run?.finishedAt || results?.timestamp || new Date().toISOString();
  const env = receipt?.run?.environment || { platform: process.platform, arch: process.arch, nodeVersion: process.version };

  const lines = [
    "# Triad-Flow Benchmark Audit Summary",
    "",
    "## Cryptographic Provenance & Manifest",
    `- **Run ID**: \`${runId}\``,
    `- **Git Commit**: \`${commitSha}\``,
    `- **Corpus Version**: \`${corpusVersion}\``,
    `- **Corpus Digest**: \`${corpusDigest}\``,
    `- **Receipt Digest**: \`${receiptDigest}\``,
    `- **Results Digest**: \`${resultsDigest}\``,
    "",
    "## Execution Environment",
    `- **Framework**: ${framework}`,
    `- **Evaluation Mode**: \`${mode}\``,
    `- **Execution Mode**: \`${executionMode}\``,
    `- **Workspace Mode**: \`${workspaceMode}\``,
    `- **Environment**: \`${env.platform || process.platform} (${env.arch || process.arch})\` | Node \`${env.nodeVersion || process.version}\``,
    `- **Started At**: ${startedAt}`,
    `- **Finished At**: ${finishedAt}`,
    "",
    "## Benchmark Quality & Performance Metrics"
  ];

  if (results?.configurations) {
    lines.push("| Configuration | Mode | Cases | Recall | Precision | FBR | P50 Latency |");
    lines.push("|---|---|---|---|---|---|---|");
    for (const [cfgName, cfg] of Object.entries(results.configurations)) {
      const cm = cfg.metrics || {};
      const rec = typeof cm.recall === "number" ? `${(cm.recall * 100).toFixed(1)}%` : "N/A";
      const prec = typeof cm.precision === "number" ? `${(cm.precision * 100).toFixed(1)}%` : "N/A";
      const fbr = typeof cm.falseBlockRate === "number" ? `${(cm.falseBlockRate * 100).toFixed(1)}%` : "N/A";
      const p50 = cm.latency?.p50Ms !== undefined ? `${cm.latency.p50Ms} ms` : "N/A";
      lines.push(`| ${cfgName} | \`${cfg.mode}\` | ${cm.totalCases ?? 0} | ${rec} | ${prec} | ${fbr} | ${p50} |`);
    }
    lines.push("");
    if (results.recommendation) {
      lines.push(`**Recommendation**: ${results.recommendation}`);
      lines.push("");
    }
  } else if (results?.metrics) {
    const m = results.metrics;
    const recallStr = typeof m.recall === "number" ? `${(m.recall * 100).toFixed(1)}%` : "N/A";
    const precisionStr = typeof m.precision === "number" ? `${(m.precision * 100).toFixed(1)}%` : "N/A";
    const fbrStr = typeof m.falseBlockRate === "number" ? `${(m.falseBlockRate * 100).toFixed(1)}%` : "N/A";
    const p50Str = m.latency?.p50Ms !== undefined ? `${m.latency.p50Ms} ms` : "N/A";
    const p95Str = m.latency?.p95Ms !== undefined ? `${m.latency.p95Ms} ms` : "N/A";
    const tokensStr = m.tokens?.available
      ? `${m.tokens.totalTokens} tokens (authoritative)`
      : "null (unreported / unavailable)";

    lines.push("| Metric | Value |");
    lines.push("|---|---|");
    lines.push(`| Total Cases | ${m.totalCases ?? "N/A"} |`);
    lines.push(`| Vulnerable Cases | ${m.vulnerableCasesCount ?? "N/A"} |`);
    lines.push(`| Clean Controls | ${m.cleanCasesCount ?? "N/A"} |`);
    lines.push(`| Recall Rate | ${recallStr} |`);
    lines.push(`| Precision | ${precisionStr} |`);
    lines.push(`| False Block Rate | ${fbrStr} |`);
    lines.push(`| Latency P50 | ${p50Str} |`);
    lines.push(`| Latency P95 | ${p95Str} |`);
    lines.push(`| Authoritative Token Usage | ${tokensStr} |`);
    lines.push("");
  }

  lines.push("## Cryptographic Artifact Bundle");
  lines.push("The following artifacts are recorded in `artifact-manifest.json`:");
  lines.push("");
  lines.push(`- \`benchmark-results.json\`: \`${resultsDigest}\``);
  if (artifacts["audit-receipt.json"]) {
    lines.push(`- \`audit-receipt.json\`: \`${artifacts["audit-receipt.json"]}\` (canonical: \`${receiptDigest}\`)`);
  }
  lines.push("");
  lines.push("To verify the integrity of this bundle:");
  lines.push("```bash");
  lines.push("node scripts/verify-artifact-manifest.mjs .");
  lines.push("```");
  lines.push("");

  return normalizeLineEndings(lines.join("\n"));
}

/**
 * Constructs an immutable Contract 5 Baseline Artifact Manifest Bundle.
 *
 * @param {object} params
 * @param {string} [params.targetDir]
 * @param {string} [params.resultsPath]
 * @param {string} [params.receiptPath]
 * @param {string} [params.summaryPath]
 * @param {string} [params.manifestPath]
 * @param {object|null} [params.resultsData]
 * @param {object|null} [params.receiptData]
 * @param {boolean} [params.writeFiles=true]
 * @returns {object} Bundle generation result with paths, manifest, and metadata.
 */
export function generateManifestBundle({
  targetDir,
  resultsPath,
  receiptPath,
  summaryPath,
  manifestPath,
  resultsData = null,
  receiptData = null,
  metadata: customMetadata = null,
  writeFiles = true
} = {}) {
  const dir = targetDir
    ? path.resolve(targetDir)
    : (resultsPath ? path.dirname(path.resolve(resultsPath)) : process.cwd());

  const resolvedResultsPath = resultsPath
    ? path.resolve(resultsPath)
    : path.join(dir, DEFAULT_ARTIFACT_NAMES.RESULTS);

  const resolvedReceiptPath = receiptPath
    ? path.resolve(receiptPath)
    : path.join(dir, DEFAULT_ARTIFACT_NAMES.RECEIPT);

  const resolvedSummaryPath = summaryPath
    ? path.resolve(summaryPath)
    : path.join(dir, DEFAULT_ARTIFACT_NAMES.SUMMARY);

  const resolvedManifestPath = manifestPath
    ? path.resolve(manifestPath)
    : path.join(dir, DEFAULT_ARTIFACT_NAMES.MANIFEST);

  if (writeFiles) {
    fs.mkdirSync(dir, { recursive: true });
    fs.mkdirSync(path.dirname(resolvedResultsPath), { recursive: true });
    fs.mkdirSync(path.dirname(resolvedReceiptPath), { recursive: true });
    fs.mkdirSync(path.dirname(resolvedSummaryPath), { recursive: true });
    fs.mkdirSync(path.dirname(resolvedManifestPath), { recursive: true });
  }

  // 1. Resolve results
  let effectiveResults = resultsData;
  if (!effectiveResults) {
    if (fs.existsSync(resolvedResultsPath)) {
      try {
        effectiveResults = JSON.parse(fs.readFileSync(resolvedResultsPath, "utf8"));
      } catch (err) {
        throw new Error(`Failed to parse results JSON at '${resolvedResultsPath}': ${err.message}`);
      }
    } else {
      throw new Error(`Cannot generate manifest bundle: results file not found at '${resolvedResultsPath}'`);
    }
  } else if (writeFiles) {
    fs.writeFileSync(resolvedResultsPath, JSON.stringify(effectiveResults, null, 2) + "\n", "utf8");
  }

  // 2. Resolve receipt
  let effectiveReceipt = receiptData;
  if (!effectiveReceipt) {
    if (fs.existsSync(resolvedReceiptPath)) {
      try {
        effectiveReceipt = JSON.parse(fs.readFileSync(resolvedReceiptPath, "utf8"));
      } catch (err) {
        throw new Error(`Failed to parse receipt JSON at '${resolvedReceiptPath}': ${err.message}`);
      }
    } else if (effectiveResults?.receipt) {
      effectiveReceipt = effectiveResults.receipt;
      if (writeFiles) {
        fs.writeFileSync(resolvedReceiptPath, JSON.stringify(effectiveReceipt, null, 2) + "\n", "utf8");
      }
    } else {
      throw new Error(`Cannot generate manifest bundle: receipt file not found at '${resolvedReceiptPath}'`);
    }
  } else if (writeFiles) {
    fs.writeFileSync(resolvedReceiptPath, JSON.stringify(effectiveReceipt, null, 2) + "\n", "utf8");
  }

  // Compute digests for results & receipt
  const resultsBytes = writeFiles
    ? fs.readFileSync(resolvedResultsPath)
    : Buffer.from(JSON.stringify(effectiveResults, null, 2) + "\n", "utf8");
  const resultsFileDigest = computeDigest(resultsBytes);

  const receiptBytes = writeFiles
    ? fs.readFileSync(resolvedReceiptPath)
    : Buffer.from(JSON.stringify(effectiveReceipt, null, 2) + "\n", "utf8");
  const receiptFileDigest = computeDigest(receiptBytes);

  let canonicalReceiptDigest;
  try {
    canonicalReceiptDigest = computeReceiptDigest(effectiveReceipt);
  } catch {
    canonicalReceiptDigest = receiptFileDigest;
  }

  const runId = customMetadata?.runId || effectiveReceipt?.run?.runId || effectiveResults?.runId || "unknown";
  const commitSha = customMetadata?.commitSha || effectiveReceipt?.systemProvenance?.commitSha || "unknown";
  const corpusDigest = customMetadata?.corpusDigest || effectiveReceipt?.identity?.corpusDigest || null;

  const metadata = {
    commitSha,
    corpusDigest,
    receiptDigest: canonicalReceiptDigest,
    resultsDigest: resultsFileDigest,
    runId,
    ...(customMetadata || {})
  };

  // 3. Generate summary.md
  const artifacts = {
    [path.basename(resolvedReceiptPath)]: receiptFileDigest,
    [path.basename(resolvedResultsPath)]: resultsFileDigest
  };

  const summaryContent = formatSummaryMarkdown({
    artifacts,
    metadata,
    receipt: effectiveReceipt,
    results: effectiveResults
  });

  if (writeFiles) {
    fs.writeFileSync(resolvedSummaryPath, summaryContent, "utf8");
  }
  const summaryBytes = writeFiles
    ? fs.readFileSync(resolvedSummaryPath)
    : Buffer.from(summaryContent, "utf8");
  const summaryDigest = computeDigest(summaryBytes);
  artifacts[path.basename(resolvedSummaryPath)] = summaryDigest;

  // 4. Build manifest
  const manifest = buildArtifactManifest({
    artifacts,
    metadata
  });

  const validation = validateArtifactManifest(manifest);
  if (!validation.valid) {
    throw new ReceiptValidationError(validation.errors);
  }

  if (writeFiles) {
    fs.writeFileSync(resolvedManifestPath, JSON.stringify(manifest, null, 2) + "\n", "utf8");
  }

  return {
    artifacts,
    manifest,
    manifestPath: resolvedManifestPath,
    metadata,
    receiptPath: resolvedReceiptPath,
    resultsPath: resolvedResultsPath,
    summaryPath: resolvedSummaryPath
  };
}

/**
 * Cryptographically verifies an artifact manifest bundle on disk.
 *
 * @param {object} params
 * @param {string} [params.manifestPath]
 * @param {string} [params.targetDir]
 * @returns {{ valid: boolean, errors: string[], manifest: object|null, baseDir: string, verifiedArtifacts: string[] }}
 */
export function verifyManifestBundle({
  manifestPath,
  targetDir,
  bundle = false,
  requireMandatoryArtifacts
} = {}) {
  let resolvedManifestPath;
  let resolvedBaseDir;

  if (targetDir) {
    resolvedBaseDir = path.resolve(targetDir);
    resolvedManifestPath = manifestPath
      ? path.resolve(manifestPath)
      : path.join(resolvedBaseDir, DEFAULT_ARTIFACT_NAMES.MANIFEST);
  } else if (manifestPath) {
    const p = path.resolve(manifestPath);
    if (fs.existsSync(p) && fs.statSync(p).isDirectory()) {
      resolvedBaseDir = p;
      resolvedManifestPath = path.join(resolvedBaseDir, DEFAULT_ARTIFACT_NAMES.MANIFEST);
    } else {
      resolvedManifestPath = p;
      resolvedBaseDir = path.dirname(resolvedManifestPath);
    }
  } else {
    resolvedBaseDir = process.cwd();
    resolvedManifestPath = path.join(resolvedBaseDir, DEFAULT_ARTIFACT_NAMES.MANIFEST);
  }

  if (!fs.existsSync(resolvedManifestPath)) {
    return {
      baseDir: resolvedBaseDir,
      errors: [`Artifact manifest file not found: '${resolvedManifestPath}'`],
      manifest: null,
      valid: false,
      verifiedArtifacts: []
    };
  }

  let manifest;
  try {
    const raw = fs.readFileSync(resolvedManifestPath, "utf8");
    manifest = JSON.parse(raw);
  } catch (err) {
    return {
      baseDir: resolvedBaseDir,
      errors: [`Failed to parse manifest JSON at '${resolvedManifestPath}': ${err.message}`],
      manifest: null,
      valid: false,
      verifiedArtifacts: []
    };
  }

  try {
    const validation = validateArtifactManifest(manifest);
    if (!validation.valid) {
      return {
        baseDir: resolvedBaseDir,
        errors: validation.errors,
        manifest,
        valid: false,
        verifiedArtifacts: []
      };
    }
  } catch (err) {
    return {
      baseDir: resolvedBaseDir,
      errors: [err.message],
      manifest,
      valid: false,
      verifiedArtifacts: []
    };
  }

  const errors = [];
  const verifiedArtifacts = [];

  // 1. Mandatory artifacts check
  // Standard benchmark run manifests require MANDATORY_ARTIFACT_FILES.
  // Evidence release bundles (identified by bundleId, bundleType, or explicit bundle flag)
  // verify all declared artifacts without requiring single-run root files.
  const isEvidenceBundle = Boolean(
    bundle ||
    manifest?.metadata?.bundleId ||
    manifest?.metadata?.bundleType === "evidence-bundle"
  );
  const shouldCheckMandatory = (requireMandatoryArtifacts !== false) && !isEvidenceBundle;

  if (shouldCheckMandatory) {
    for (const mandatory of MANDATORY_ARTIFACT_FILES) {
      if (!manifest.artifacts[mandatory]) {
        errors.push(`Manifest is missing mandatory artifact entry: '${mandatory}'`);
      }
    }
  }

  // 2. Individual artifact file presence and SHA-256 digest check
  for (const [filename, expectedDigest] of Object.entries(manifest.artifacts || {})) {
    // Guard against path traversal attempts or absolute paths
    const normalizedRelative = path.normalize(filename).replace(/^[\\/]+/, "");
    if (path.isAbsolute(filename) || normalizedRelative.startsWith("..") || filename.includes("..")) {
      errors.push(`Prohibited path traversal or absolute path in artifact filename: '${filename}'`);
      continue;
    }

    const filePath = path.join(resolvedBaseDir, normalizedRelative);
    if (!fs.existsSync(filePath)) {
      errors.push(`Artifact file missing on disk: '${filename}' (expected at '${filePath}')`);
      continue;
    }

    try {
      const fileBytes = fs.readFileSync(filePath);
      const actualDigest = computeDigest(fileBytes);
      if (actualDigest !== expectedDigest) {
        errors.push(`Digest mismatch for artifact '${filename}': expected ${expectedDigest}, got ${actualDigest}`);
      } else {
        verifiedArtifacts.push(filename);
      }
    } catch (err) {
      errors.push(`Failed to read artifact '${filename}': ${err.message}`);
    }
  }

  // 3. Metadata consistency check
  const meta = manifest.metadata || {};

  // Check resultsDigest against benchmark-results.json
  if (meta.resultsDigest && manifest.artifacts[DEFAULT_ARTIFACT_NAMES.RESULTS]) {
    if (meta.resultsDigest !== manifest.artifacts[DEFAULT_ARTIFACT_NAMES.RESULTS]) {
      errors.push(`Metadata resultsDigest (${meta.resultsDigest}) does not match artifacts['${DEFAULT_ARTIFACT_NAMES.RESULTS}'] (${manifest.artifacts[DEFAULT_ARTIFACT_NAMES.RESULTS]})`);
    }
  }

  // Check receiptDigest & corpusDigest against audit-receipt.json
  const receiptFilePath = path.join(resolvedBaseDir, DEFAULT_ARTIFACT_NAMES.RECEIPT);
  if (fs.existsSync(receiptFilePath)) {
    try {
      const receiptRaw = fs.readFileSync(receiptFilePath, "utf8");
      const receiptObj = JSON.parse(receiptRaw);
      let calculatedCanonicalDigest = null;
      try {
        calculatedCanonicalDigest = computeReceiptDigest(receiptObj);
      } catch {
        // Not a strictly conforming receipt
      }

      if (meta.receiptDigest) {
        const fileDigest = manifest.artifacts[DEFAULT_ARTIFACT_NAMES.RECEIPT];
        if (meta.receiptDigest !== calculatedCanonicalDigest && meta.receiptDigest !== fileDigest) {
          errors.push(`Metadata receiptDigest mismatch: manifest specifies ${meta.receiptDigest}, but computed canonical digest is ${calculatedCanonicalDigest}`);
        }
      }

      if (meta.corpusDigest && receiptObj.identity?.corpusDigest) {
        if (meta.corpusDigest !== receiptObj.identity.corpusDigest) {
          errors.push(`Metadata corpusDigest (${meta.corpusDigest}) does not match receipt identity corpusDigest (${receiptObj.identity.corpusDigest})`);
        }
      }
    } catch (err) {
      errors.push(`Failed to parse or validate audit-receipt.json: ${err.message}`);
    }
  }

  // 4. Verify summary.md embeds the required provenance digests
  const summaryFilePath = path.join(resolvedBaseDir, DEFAULT_ARTIFACT_NAMES.SUMMARY);
  if (fs.existsSync(summaryFilePath)) {
    try {
      const summaryText = fs.readFileSync(summaryFilePath, "utf8");
      const requiredTokens = [
        { label: "Run ID", val: meta.runId },
        { label: "Commit SHA", val: meta.commitSha },
        { label: "Corpus Digest", val: meta.corpusDigest },
        { label: "Receipt Digest", val: meta.receiptDigest },
        { label: "Results Digest", val: meta.resultsDigest }
      ];

      for (const token of requiredTokens) {
        if (token.val && token.val !== "unknown" && !summaryText.includes(token.val)) {
          errors.push(`summary.md does not embed required ${token.label}: ${token.val}`);
        }
      }
    } catch (err) {
      errors.push(`Failed to read summary.md: ${err.message}`);
    }
  }

  return {
    baseDir: resolvedBaseDir,
    errors,
    manifest,
    valid: errors.length === 0,
    verifiedArtifacts
  };
}

export {
  buildArtifactManifest,
  validateArtifactManifest
};
