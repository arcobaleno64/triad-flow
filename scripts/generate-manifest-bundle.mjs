#!/usr/bin/env node
/**
 * Triad-Flow Artifact Manifest Bundle Generator CLI Script
 *
 * Usage:
 *   node scripts/generate-manifest-bundle.mjs [directory] [options]
 *
 * Options:
 *   --dir=<dir>        Target directory for artifacts (default: positional arg or current dir)
 *   --results=<path>   Path to benchmark-results.json (default: <dir>/benchmark-results.json)
 *   --receipt=<path>   Path to audit-receipt.json (default: <dir>/audit-receipt.json)
 *   --summary=<path>   Output path for summary.md (default: <dir>/summary.md)
 *   --manifest=<path>  Output path for artifact-manifest.json (default: <dir>/artifact-manifest.json)
 *   -h, --help         Show help and usage information
 */

import { parseArgs } from "node:util";
import process from "node:process";
import { generateManifestBundle } from "../src/core/manifest-bundle.mjs";

const optionsConfig = {
  dir: { type: "string" },
  results: { type: "string" },
  receipt: { type: "string" },
  summary: { type: "string" },
  manifest: { type: "string" },
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
Triad-Flow Artifact Manifest Bundle Generator (TF-RBC-v0)

Usage:
  node scripts/generate-manifest-bundle.mjs [directory] [options]

Options:
  --dir=<dir>        Target directory for artifacts (default: positional arg or current dir)
  --results=<path>   Path to benchmark-results.json (default: <dir>/benchmark-results.json)
  --receipt=<path>   Path to audit-receipt.json (default: <dir>/audit-receipt.json)
  --summary=<path>   Output path for summary.md (default: <dir>/summary.md)
  --manifest=<path>  Output path for artifact-manifest.json (default: <dir>/artifact-manifest.json)
  -h, --help         Show help and usage information
\n`);
  process.exit(0);
}

const targetDir = values.dir || positionals[0] || process.cwd();

try {
  const bundle = generateManifestBundle({
    targetDir,
    resultsPath: values.results,
    receiptPath: values.receipt,
    summaryPath: values.summary,
    manifestPath: values.manifest
  });

  process.stdout.write(`[TF-RBC-v0] Successfully generated artifact manifest bundle:\n`);
  process.stdout.write(`  Directory: ${targetDir}\n`);
  process.stdout.write(`  Artifacts:\n`);
  for (const [filename, digest] of Object.entries(bundle.manifest.artifacts)) {
    process.stdout.write(`    - ${filename}: ${digest}\n`);
  }
  process.stdout.write(`  Metadata:\n`);
  process.stdout.write(`    - Run ID: ${bundle.manifest.metadata.runId}\n`);
  process.stdout.write(`    - Commit SHA: ${bundle.manifest.metadata.commitSha}\n`);
  process.stdout.write(`    - Corpus Digest: ${bundle.manifest.metadata.corpusDigest}\n`);
  process.stdout.write(`    - Receipt Digest: ${bundle.manifest.metadata.receiptDigest}\n`);
  process.stdout.write(`    - Results Digest: ${bundle.manifest.metadata.resultsDigest}\n`);
  process.stdout.write(`Manifest written to: ${bundle.manifestPath}\n`);
} catch (err) {
  process.stderr.write(`[TF-RBC-v0] Error generating manifest bundle: ${err.message}\n`);
  process.exit(1);
}
