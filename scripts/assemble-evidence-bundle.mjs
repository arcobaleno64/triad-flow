/**
 * Triad-Flow Evidence Release Bundle Assembler & Cryptographic Sealer
 *
 * Assembles and seals TF-EVIDENCE-0001:
 * - corpus-identity.json
 * - release-identity.json
 * - evidence-index.json
 * - README-EVIDENCE.md
 * - artifact-manifest.json (bundle-level cryptographic manifest)
 */

import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import crypto from "node:crypto";
import { TF_RBC_V0_CASES } from "../tests/fixtures/real-corpus-fixtures.mjs";
import { createCorpusIdentity, computeDigest, canonicalJsonStringify } from "../src/core/canonical-digest.mjs";
import { buildArtifactManifest, computeReceiptDigest } from "../src/core/audit-receipt.mjs";
import { validateVerificationRecord } from "../src/core/independent-verifier.mjs";

const BUNDLE_DIR = path.resolve("evidence-runs/TF-EVIDENCE-0001");

function getFileDigest(filePath) {
  const buf = fs.readFileSync(filePath);
  return "sha256:" + crypto.createHash("sha256").update(buf).digest("hex");
}

function getAllFiles(dir, baseDir = dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...getAllFiles(fullPath, baseDir));
    } else {
      files.push(path.relative(baseDir, fullPath).replace(/\\/g, "/"));
    }
  }
  return files;
}

async function main() {
  console.log(`[TF-EVIDENCE-0001] Assembling release bundle in ${BUNDLE_DIR}...`);

  if (!fs.existsSync(BUNDLE_DIR)) {
    throw new Error(`Bundle directory does not exist: ${BUNDLE_DIR}`);
  }

  // 1. Corpus Identity
  const corpusIdentity = createCorpusIdentity(TF_RBC_V0_CASES);
  const corpusDoc = {
    schemaVersion: "1.0.0",
    corpusVersion: corpusIdentity.corpusVersion,
    corpusDigest: corpusIdentity.corpusDigest,
    casesCount: Object.keys(corpusIdentity.caseDigests).length,
    targetCase: "BENCH-REAL-001",
    targetCaseDigest: corpusIdentity.caseDigests["BENCH-REAL-001"],
    caseDigests: corpusIdentity.caseDigests
  };
  const corpusPath = path.join(BUNDLE_DIR, "corpus-identity.json");
  fs.writeFileSync(corpusPath, JSON.stringify(corpusDoc, null, 2) + "\n", "utf8");
  console.log(`✔ Generated ${path.relative(process.cwd(), corpusPath)}`);

  // 2. Read Provider Runs & Verification Record
  const runKeys = ["agy-run-1", "agy-run-2", "claude-run-1", "claude-run-2"];
  const providerRuns = {};

  for (const k of runKeys) {
    const runDir = path.join(BUNDLE_DIR, "provider-runs", k);
    const receiptPath = path.join(runDir, "audit-receipt.json");
    const resultsPath = path.join(runDir, "benchmark-results.json");
    if (!fs.existsSync(receiptPath) || !fs.existsSync(resultsPath)) {
      throw new Error(`Missing artifacts for run '${k}' at ${runDir}`);
    }
    const receipt = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
    const results = JSON.parse(fs.readFileSync(resultsPath, "utf8"));

    const caseRes = results.caseResults[0];
    providerRuns[k] = {
      runId: receipt.run.runId,
      provider: receipt.providerProvenance.macro.providerName,
      providerVersion: caseRes.provider?.version || null,
      commitSha: receipt.systemProvenance.commitSha,
      startedAt: receipt.run.startedAt,
      finishedAt: receipt.run.finishedAt,
      latencyMs: receipt.results.latency.avgMs,
      recall: receipt.results.recall,
      precision: receipt.results.precision,
      expectedGate: caseRes.expectedDecision,
      actualGate: caseRes.actualDecision,
      passed: caseRes.passed,
      findingsCount: caseRes.actualFindings.length,
      receiptDigest: computeReceiptDigest(receipt),
      resultsDigest: getFileDigest(resultsPath)
    };
  }

  // Verification Record
  const verRecordPath = path.join(BUNDLE_DIR, "verification", "verification-record.json");
  if (!fs.existsSync(verRecordPath)) {
    throw new Error(`Missing verification record at ${verRecordPath}`);
  }
  const verRecord = JSON.parse(fs.readFileSync(verRecordPath, "utf8"));
  const verVal = validateVerificationRecord(verRecord);
  if (!verVal.valid) {
    throw new Error(`Verification record validation failed: ${verVal.errors.join("; ")}`);
  }

  // 3. Release Identity
  const releaseDoc = {
    schemaVersion: "1.0.0",
    bundleId: "TF-EVIDENCE-0001",
    title: "Triad-Flow Dual-Provider Live Evidence & Independent Verification Pilot Bundle",
    triadFlowVersion: "2.2.1",
    sealedAt: new Date().toISOString(),
    commitSha: providerRuns["agy-run-1"].commitSha,
    corpusVersion: corpusDoc.corpusVersion,
    corpusDigest: corpusDoc.corpusDigest,
    targetCase: corpusDoc.targetCase,
    targetCaseDigest: corpusDoc.targetCaseDigest,
    environment: {
      platform: process.platform,
      arch: process.arch,
      nodeVersion: process.version
    },
    providerRuns,
    independentVerification: {
      schemaVersion: verRecord.schemaVersion,
      verifiedAt: verRecord.verifiedAt,
      producerProvider: verRecord.producer.providerName,
      verifierProvider: verRecord.verifier.providerName,
      producerFindingsCount: verRecord.producer.findingsCount,
      verdict: verRecord.evaluations[0].verdict,
      locatorAccurate: verRecord.evaluations[0].locatorAccurate,
      typeAccurate: verRecord.evaluations[0].typeAccurate,
      severityAccurate: verRecord.evaluations[0].severityAccurate,
      disagreementsCount: verRecord.disagreementLedger.length,
      verifierOmissionsCount: verRecord.verifierOmissions.length
    }
  };
  const releasePath = path.join(BUNDLE_DIR, "release-identity.json");
  fs.writeFileSync(releasePath, JSON.stringify(releaseDoc, null, 2) + "\n", "utf8");
  console.log(`✔ Generated ${path.relative(process.cwd(), releasePath)}`);

  // 4. README-EVIDENCE.md
  const readmeContent = [
    `# Triad-Flow Immutable Evidence Bundle: TF-EVIDENCE-0001`,
    ``,
    `## Bundle Identity`,
    `- **Bundle ID**: \`TF-EVIDENCE-0001\``,
    `- **Title**: Dual-Provider Live Evidence & Independent Verification Pilot Bundle`,
    `- **Triad-Flow Version**: \`${releaseDoc.triadFlowVersion}\``,
    `- **Git Commit**: \`${releaseDoc.commitSha}\``,
    `- **Corpus Version**: \`${corpusDoc.corpusVersion}\``,
    `- **Corpus Digest**: \`${corpusDoc.corpusDigest}\``,
    `- **Target Case**: \`${corpusDoc.targetCase}\` (SQL Injection in User Query Handler)`,
    `- **Sealed At**: \`${releaseDoc.sealedAt}\``,
    ``,
    `## Bundle Contents`,
    `\`\`\`text`,
    `TF-EVIDENCE-0001/`,
    `├── corpus-identity.json          # Deterministic TF-RBC-v0 corpus identity & digests`,
    `├── release-identity.json         # High-level provenance & run cross-reference`,
    `├── disagreement-ledger.json      # Structured disagreement ledger from independent verifier`,
    `├── evidence-index.json           # Byte-level manifest of all files in bundle`,
    `├── artifact-manifest.json        # Cryptographic SHA-256 manifest of the bundle`,
    `├── README-EVIDENCE.md            # This offline verification guide`,
    `├── verification/`,
    `│   └── verification-record.json  # Live Claude independent verification record of AGY finding`,
    `└── provider-runs/`,
    `    ├── agy-run-1/                # Google agy Run #1 (receipt, results, summary, manifest)`,
    `    ├── agy-run-2/                # Google agy Run #2 (receipt, results, summary, manifest)`,
    `    ├── claude-run-1/             # Anthropic claude Run #1 (receipt, results, summary, manifest)`,
    `    └── claude-run-2/             # Anthropic claude Run #2 (receipt, results, summary, manifest)`,
    `\`\`\``,
    ``,
    `## Verification Instructions (100% Offline)`,
    `This bundle contains authoritative receipts and manifests. You can verify all cryptographic claims offline without invoking any LLMs or network services.`,
    ``,
    `### Step 1: Verify the Outer Bundle Manifest`,
    `\`\`\`bash`,
    `node scripts/verify-artifact-manifest.mjs evidence-runs/TF-EVIDENCE-0001`,
    `\`\`\``,
    ``,
    `### Step 2: Verify Individual Provider Run Manifests`,
    `\`\`\`bash`,
    `node scripts/verify-artifact-manifest.mjs evidence-runs/TF-EVIDENCE-0001/provider-runs/agy-run-1`,
    `node scripts/verify-artifact-manifest.mjs evidence-runs/TF-EVIDENCE-0001/provider-runs/agy-run-2`,
    `node scripts/verify-artifact-manifest.mjs evidence-runs/TF-EVIDENCE-0001/provider-runs/claude-run-1`,
    `node scripts/verify-artifact-manifest.mjs evidence-runs/TF-EVIDENCE-0001/provider-runs/claude-run-2`,
    `\`\`\``,
    ``,
    `### Step 3: Validate Independent Verification Record (Section 7 Invariants)`,
    `\`\`\`bash`,
    `node -e '`,
    `const fs = require(\"fs\");`,
    `const { validateVerificationRecord } = require(\"./src/core/independent-verifier.mjs\");`,
    `const record = JSON.parse(fs.readFileSync(\"evidence-runs/TF-EVIDENCE-0001/verification/verification-record.json\", \"utf8\"));`,
    `const res = validateVerificationRecord(record);`,
    `if (!res.valid) { console.error(\"INVALID:\", res.errors); process.exit(1); }`,
    `console.log(\"✔ Verification Record Section 7 Invariants Validated Successfully!\");`,
    `'`,
    `\`\`\``,
    ``,
    `## Ground-Truth Observations`,
    `All claims, latencies, recall, precision, and verifier evaluations are recorded directly inside the respective \`audit-receipt.json\` and \`verification-record.json\` files. This README serves solely as an index and verification guide.`,
    ``
  ].join("\n");

  const readmePath = path.join(BUNDLE_DIR, "README-EVIDENCE.md");
  fs.writeFileSync(readmePath, readmeContent, "utf8");
  console.log(`✔ Generated ${path.relative(process.cwd(), readmePath)}`);

  // 5. Build evidence-index.json (all files currently in bundle except manifest files)
  const bundleFiles = getAllFiles(BUNDLE_DIR).filter(f => f !== "artifact-manifest.json" && f !== "bundle-manifest.json" && f !== "evidence-index.json");
  bundleFiles.sort();

  const indexEntries = [];
  const manifestArtifacts = {};

  for (const relPath of bundleFiles) {
    const fullPath = path.join(BUNDLE_DIR, relPath);
    const stat = fs.statSync(fullPath);
    const digest = getFileDigest(fullPath);

    indexEntries.push({
      path: relPath,
      sizeBytes: stat.size,
      sha256: digest
    });

    manifestArtifacts[relPath] = digest;
  }

  const indexDoc = {
    schemaVersion: "1.0.0",
    bundleId: "TF-EVIDENCE-0001",
    totalFiles: indexEntries.length,
    files: indexEntries
  };

  const indexPath = path.join(BUNDLE_DIR, "evidence-index.json");
  fs.writeFileSync(indexPath, JSON.stringify(indexDoc, null, 2) + "\n", "utf8");
  console.log(`✔ Generated ${path.relative(process.cwd(), indexPath)}`);

  // Include evidence-index.json in the manifest
  manifestArtifacts["evidence-index.json"] = getFileDigest(indexPath);

  // 6. Build outer artifact-manifest.json
  const outerManifest = buildArtifactManifest({
    artifacts: manifestArtifacts,
    metadata: {
      bundleId: "TF-EVIDENCE-0001",
      commitSha: releaseDoc.commitSha,
      corpusDigest: corpusDoc.corpusDigest,
      sealedAt: releaseDoc.sealedAt,
      runId: "bundle-TF-EVIDENCE-0001"
    }
  });

  const manifestPath = path.join(BUNDLE_DIR, "artifact-manifest.json");
  fs.writeFileSync(manifestPath, JSON.stringify(outerManifest, null, 2) + "\n", "utf8");
  console.log(`✔ Generated ${path.relative(process.cwd(), manifestPath)}`);

  console.log("\n[TF-EVIDENCE-0001] Evidence bundle assembly and cryptographic sealing complete!");
}

main().catch(err => {
  console.error("Fatal:", err);
  process.exit(1);
});
