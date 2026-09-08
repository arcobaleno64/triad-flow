#!/usr/bin/env node
/**
 * Triad-Flow CLI Executable Entry Point
 * Invariant: Must use LF line endings and no UTF-8 BOM.
 */

import { runCli, EXIT_CODES } from "../src/cli.mjs";

runCli(process.argv.slice(2), { stdout: process.stdout, stderr: process.stderr })
  .then(code => {
    process.exitCode = typeof code === "number" ? code : EXIT_CODES.SUCCESS;
  })
  .catch(err => {
    process.stderr.write(`[FATAL ERROR] ${err?.stack || err?.message || String(err)}\n`);
    process.exit(EXIT_CODES.SYSTEM_FAILURE);
  });
