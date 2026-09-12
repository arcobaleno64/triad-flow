#!/usr/bin/env node
// Keeps every place the version is written in lockstep. Adapted in shape (not
// code) from arcobaleno64/agy-security-audit's scripts/bump-version.mjs.
//
// Two targets today:
//   - package.json "version"           — what npm publishes.
//   - src/core/harness.mjs driver.version — what consumers read out of the
//     SARIF report's tool.driver.version. That value is an observable output
//     contract (SARIF 2.1.0 §3.19.3), so it must not drift from the package.
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const VERSION_PATTERN = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

const PACKAGE_FILE = "package.json";
const HARNESS_FILE = "src/core/harness.mjs";
const REPORT_FILE = "src/core/review-run-report.mjs";
// Anchored to the SARIF driver block so an unrelated "2.0.0" elsewhere in the
// file can never be rewritten by accident.
const HARNESS_PATTERN = /(name: "Triad-Flow Sentry",\s*\n\s*version: ")([^"]*)(")/;
const REPORT_PATTERN = /(export const TOOL_VERSION = ")([^"]*)(")/;

function usage() {
  return [
    "Usage:",
    "  node scripts/bump-version.mjs <version>",
    "  node scripts/bump-version.mjs --check [version]",
    "",
    "Options:",
    "  --check        Verify every target already agrees. Uses package.json when version is omitted.",
    "  --root <dir>   Run against a different repository root.",
    "  --help         Print this help."
  ].join("\n");
}

function parseArgs(argv) {
  const options = { check: false, root: process.cwd(), version: null, help: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--check") {
      options.check = true;
    } else if (arg === "--root") {
      if (!argv[i + 1]) throw new Error("--root requires a directory.");
      options.root = argv[i + 1];
      i += 1;
    } else if (arg === "--help" || arg === "-h") {
      options.help = true;
    } else if (arg.startsWith("-")) {
      throw new Error(`Unknown option: ${arg}`);
    } else if (options.version === null) {
      options.version = arg;
    } else {
      throw new Error(`Unexpected argument: ${arg}`);
    }
  }
  return options;
}

function readText(root, file) {
  const full = path.join(root, file);
  if (!fs.existsSync(full)) throw new Error(`Missing target: ${file}`);
  return fs.readFileSync(full, "utf8");
}

function currentVersions(root) {
  const pkg = JSON.parse(readText(root, PACKAGE_FILE));
  const harness = readText(root, HARNESS_FILE);
  const matchHarness = HARNESS_PATTERN.exec(harness);
  if (!matchHarness) {
    throw new Error(`Could not locate the SARIF driver version block in ${HARNESS_FILE}.`);
  }
  const report = readText(root, REPORT_FILE);
  const matchReport = REPORT_PATTERN.exec(report);
  if (!matchReport) {
    throw new Error(`Could not locate the TOOL_VERSION block in ${REPORT_FILE}.`);
  }
  return [
    { file: PACKAGE_FILE, label: "version", value: pkg.version },
    { file: HARNESS_FILE, label: "tool.driver.version", value: matchHarness[2] },
    { file: REPORT_FILE, label: "tool.version", value: matchReport[2] }
  ];
}

function write(root, version) {
  const pkgPath = path.join(root, PACKAGE_FILE);
  const raw = readText(root, PACKAGE_FILE);
  const pkg = JSON.parse(raw);
  pkg.version = version;
  // Preserve the file's trailing newline convention.
  fs.writeFileSync(pkgPath, `${JSON.stringify(pkg, null, 2)}\n`, "utf8");

  const harnessPath = path.join(root, HARNESS_FILE);
  const harness = readText(root, HARNESS_FILE);
  fs.writeFileSync(harnessPath, harness.replace(HARNESS_PATTERN, `$1${version}$3`), "utf8");

  const reportPath = path.join(root, REPORT_FILE);
  const report = readText(root, REPORT_FILE);
  fs.writeFileSync(reportPath, report.replace(REPORT_PATTERN, `$1${version}$3`), "utf8");
}

function main(argv) {
  let options;
  try {
    options = parseArgs(argv);
  } catch (error) {
    process.stderr.write(`${error.message}\n\n${usage()}\n`);
    return 2;
  }

  if (options.help) {
    process.stdout.write(`${usage()}\n`);
    return 0;
  }

  let targets;
  try {
    targets = currentVersions(options.root);
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    return 1;
  }

  const expected = options.version ?? targets[0].value;
  if (!VERSION_PATTERN.test(expected)) {
    process.stderr.write(`Not a semantic version: ${expected}\n`);
    return 2;
  }

  if (options.check) {
    const wrong = targets.filter(target => target.value !== expected);
    if (wrong.length > 0) {
      for (const target of wrong) {
        process.stderr.write(`${target.file} (${target.label}) is ${target.value}, expected ${expected}\n`);
      }
      process.stderr.write("Run 'npm run bump-version <version>' to bring them into lockstep.\n");
      return 1;
    }
    process.stdout.write(`All ${targets.length} version targets agree on ${expected}.\n`);
    return 0;
  }

  if (options.version === null) {
    process.stderr.write(`A version is required when not using --check.\n\n${usage()}\n`);
    return 2;
  }

  write(options.root, expected);
  for (const target of targets) {
    process.stdout.write(`${target.file} (${target.label}): ${target.value} -> ${expected}\n`);
  }
  return 0;
}

process.exit(main(process.argv.slice(2)));
