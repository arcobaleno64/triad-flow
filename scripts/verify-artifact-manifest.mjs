#!/usr/bin/env node
/**
 * Triad-Flow Artifact Manifest Verifier CLI Script
 *
 * Usage:
 *   node scripts/verify-artifact-manifest.mjs [path] [options]
 *
 * Options:
 *   path               Target directory or path to artifact-manifest.json (default: current dir)
 *   --dir=<dir>        Target directory containing artifacts
 *   --manifest=<path>  Path to artifact-manifest.json
 *   -h, --help         Show help and usage information
 */

import { parseArgs } from "node:util";
import process from "node:process";
import { verifyManifestBundle } from "../src/core/manifest-bundle.mjs";

const optionsConfig = {
  dir: { type: "string" },
  manifest: { type: "string" },
  bundle: { type: "boolean", default: false },
  help: { type: "boolean", short: "h", default: false }
};

let values, positionals;
try {
  const parsed = parseArgs({ args: process.argv.slice(2), options: optionsConfig, allowPositionals: true });
  values = parsed.values;
  positionals = parsed.positionals;
} catch (err) {
  process.stderr.write(`Argument error: ${err.message}\n`);
  process.exit(1);
}

if (values.help) {
  process.stdout.write(`
Triad-Flow Artifact Manifest Verifier (TF-RBC-v0)

Usage:
  node scripts/verify-artifact-manifest.mjs [path] [options]

Arguments:
  path               Target directory or path to artifact-manifest.json (default: current dir)

Options:
  --dir=<dir>        Target directory containing artifacts
  --manifest=<path>  Path to artifact-manifest.json
  --bundle           Verify as a release evidence bundle (skips single-run root checks)
  -h, --help         Show help and usage information
\n`);
  process.exit(0);
}

const manifestPath = values.manifest || positionals[0] || null;
const targetDir = values.dir || null;

try {
  const verification = verifyManifestBundle({
    manifestPath,
    targetDir,
    bundle: Boolean(values.bundle)
  });

  if (!verification.valid) {
    process.stderr.write(`[TF-RBC-v0] ✖ Manifest Bundle Verification FAILED (${verification.errors.length} error(s)):\n`);
    for (const err of verification.errors) {
      process.stderr.write(`  - ${err}\n`);
    }
    process.exit(1);
  }

  process.stdout.write(`[TF-RBC-v0] ✔ Manifest Bundle Verification SUCCEEDED:\n`);
  process.stdout.write(`  Schema Version: ${verification.manifest.schemaVersion}\n`);
  process.stdout.write(`  Base Directory: ${verification.baseDir}\n`);
  process.stdout.write(`  Verified Artifacts (${verification.verifiedArtifacts.length}):\n`);
  for (const [filename, digest] of Object.entries(verification.manifest.artifacts)) {
    process.stdout.write(`    * ${filename} (${digest})\n`);
  }
  process.stdout.write(`  Verified Metadata Provenance:\n`);
  process.stdout.write(`    * Run ID: ${verification.manifest.metadata.runId}\n`);
  process.stdout.write(`    * Commit SHA: ${verification.manifest.metadata.commitSha}\n`);
  process.stdout.write(`    * Corpus Digest: ${verification.manifest.metadata.corpusDigest}\n`);
  process.stdout.write(`    * Receipt Digest: ${verification.manifest.metadata.receiptDigest}\n`);
  process.stdout.write(`    * Results Digest: ${verification.manifest.metadata.resultsDigest}\n`);
  process.stdout.write(`[TF-RBC-v0] All artifacts match cryptographic manifest digests.\n`);
  process.exit(0);
} catch (err) {
  process.stderr.write(`[TF-RBC-v0] ✖ Fatal error verifying manifest bundle: ${err.message}\n`);
  process.exit(1);
}
