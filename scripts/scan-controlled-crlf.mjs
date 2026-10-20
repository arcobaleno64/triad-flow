import fs from "node:fs";
import path from "node:path";

export const CONTROLLED_TEXT_EXTENSIONS = new Set([
  ".js", ".mjs", ".cjs", ".ts", ".json", ".md", ".yml", ".yaml", ".txt", ".sh"
]);

export const CONTROLLED_TEXT_BASENAMES = new Set([
  ".gitignore", "allowed_signers", "LICENSE"
]);

export const EXCLUDED_DIRS = new Set([
  ".git", "node_modules", ".agents", ".triad-flow", "assets"
]);

/**
 * Recursively scans directory for controlled text files and checks for CRLF.
 *
 * @param {string} [rootDir="."]
 * @returns {{ files: string[], crlfFiles: string[], count: number }}
 */
export function scanControlledTextFiles(rootDir = ".") {
  const files = [];
  const crlfFiles = [];

  function walk(currentDir) {
    for (const entry of fs.readdirSync(currentDir, { withFileTypes: true })) {
      if (EXCLUDED_DIRS.has(entry.name)) continue;
      const fullPath = path.join(currentDir, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
      } else {
        const ext = path.extname(entry.name).toLowerCase();
        if (CONTROLLED_TEXT_EXTENSIONS.has(ext) || CONTROLLED_TEXT_BASENAMES.has(entry.name)) {
          files.push(fullPath);
          const buf = fs.readFileSync(fullPath);
          if (buf.includes(Buffer.from("\r\n"))) {
            crlfFiles.push(fullPath);
          }
        }
      }
    }
  }

  walk(rootDir);
  return { files, crlfFiles, count: files.length };
}

// CLI execution
if (import.meta.url === `file://${process.argv[1]?.replace(/\\/g, "/")}` || process.argv[1]?.endsWith("scan-controlled-crlf.mjs")) {
  const { files, crlfFiles, count } = scanControlledTextFiles(".");
  console.log(`Controlled text files scanned: ${count}`);
  console.log(`CRLF violations: ${crlfFiles.length}`);

  if (crlfFiles.length > 0) {
    console.error("CRLF detected in files:");
    for (const f of crlfFiles) {
      console.error(`  - ${f}`);
    }
    process.exit(1);
  } else {
    console.log("All controlled text files verified pure LF (0 CRLF).");
    process.exit(0);
  }
}
