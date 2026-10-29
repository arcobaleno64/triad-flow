/**
 * Triad-Flow Multi-Language Patch Synthesis & Remediation Engine (v2.10)
 *
 * Extends Triad-Flow Patch Jail and Batch Remediation to support heterogeneous multi-language
 * codebases spanning C, Rust, Go, Python, and JavaScript/TypeScript:
 * - Language Detection & Classifier for 5+ languages.
 * - Language-Aware Test Runner Resolution (Cargo, Go Test, Pytest, Make, Node).
 * - Multi-Language Unified Diff & Patch Synthesizer with strict context-line whitespace formatting.
 * - Anti-Evasion Integration enforcing language-specific assertion and constant branch rules.
 * - MultiLanguageRemediationOrchestrator wrapping BatchRemediationSession with multi-language dispatch.
 */

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import {
  normalizeLineEndings,
  normalizeRelativePath,
  computeDigest
} from "./canonical-digest.mjs";
import {
  scanStructuralAntiEvasionViolations,
  StructuralAntiEvasionError
} from "./anti-evasion-guard.mjs";
import {
  BatchRemediationSession,
  BATCH_REMEDIATION_STATES,
  BATCH_VERDICTS,
  validateBatchReceipt
} from "./batch-remediation.mjs";
import {
  REMEDIATION_STATES,
  validatePatchScope
} from "./controlled-remediation.mjs";

export const SUPPORTED_LANGUAGES = Object.freeze({
  C: "c",
  CPP: "cpp",
  RUST: "rust",
  GO: "go",
  PYTHON: "python",
  JAVASCRIPT: "javascript",
  TYPESCRIPT: "typescript",
  UNKNOWN: "unknown"
});

export const LANGUAGE_FILE_EXTENSIONS = Object.freeze({
  ".c": SUPPORTED_LANGUAGES.C,
  ".h": SUPPORTED_LANGUAGES.C,
  ".cc": SUPPORTED_LANGUAGES.CPP,
  ".cpp": SUPPORTED_LANGUAGES.CPP,
  ".cxx": SUPPORTED_LANGUAGES.CPP,
  ".hpp": SUPPORTED_LANGUAGES.CPP,
  ".rs": SUPPORTED_LANGUAGES.RUST,
  ".go": SUPPORTED_LANGUAGES.GO,
  ".py": SUPPORTED_LANGUAGES.PYTHON,
  ".js": SUPPORTED_LANGUAGES.JAVASCRIPT,
  ".mjs": SUPPORTED_LANGUAGES.JAVASCRIPT,
  ".cjs": SUPPORTED_LANGUAGES.JAVASCRIPT,
  ".ts": SUPPORTED_LANGUAGES.TYPESCRIPT,
  ".mts": SUPPORTED_LANGUAGES.TYPESCRIPT,
  ".cts": SUPPORTED_LANGUAGES.TYPESCRIPT
});

/**
 * Detects the programming language for a given file path.
 *
 * @param {string} filePath
 * @returns {string} Language identifier
 */
export function detectLanguage(filePath) {
  if (!filePath || typeof filePath !== "string") {
    return SUPPORTED_LANGUAGES.UNKNOWN;
  }
  const ext = path.extname(filePath).toLowerCase();
  return LANGUAGE_FILE_EXTENSIONS[ext] || SUPPORTED_LANGUAGES.UNKNOWN;
}

/**
 * Detects an appropriate test runner command for a target repository and file set.
 *
 * @param {string} repoDir
 * @param {string[]} [targetFiles=[]]
 * @returns {{ command: string, args: string[] }|null}
 */
export function detectLanguageTestRunner(repoDir, targetFiles = []) {
  if (!repoDir || typeof repoDir !== "string" || !fs.existsSync(repoDir)) {
    return null;
  }

  // 1. Direct custom test oracle script in workspace
  if (fs.existsSync(path.join(repoDir, "test/test.js")) || fs.existsSync(path.join(repoDir, "test.js"))) {
    const testScript = fs.existsSync(path.join(repoDir, "test/test.js")) ? "test/test.js" : "test.js";
    return { command: "node", args: [testScript] };
  }

  // 2. Language-specific manifest or target file inspection
  const languages = new Set((targetFiles || []).map(f => detectLanguage(f)));

  // Rust
  if (fs.existsSync(path.join(repoDir, "Cargo.toml")) || languages.has(SUPPORTED_LANGUAGES.RUST)) {
    return { command: "cargo", args: ["test"] };
  }

  // Go
  if (fs.existsSync(path.join(repoDir, "go.mod")) || languages.has(SUPPORTED_LANGUAGES.GO)) {
    return { command: "go", args: ["test", "./..."] };
  }

  // Python
  if (
    fs.existsSync(path.join(repoDir, "pytest.ini")) ||
    fs.existsSync(path.join(repoDir, "pyproject.toml")) ||
    fs.existsSync(path.join(repoDir, "requirements.txt")) ||
    languages.has(SUPPORTED_LANGUAGES.PYTHON)
  ) {
    if (fs.existsSync(path.join(repoDir, "test_suite.py"))) {
      return { command: "python", args: ["test_suite.py"] };
    }
    return { command: "python", args: ["-m", "unittest"] };
  }

  // C / C++ with Makefile
  if (fs.existsSync(path.join(repoDir, "Makefile")) && (languages.has(SUPPORTED_LANGUAGES.C) || languages.has(SUPPORTED_LANGUAGES.CPP))) {
    return { command: "make", args: ["test"] };
  }

  // JavaScript / TypeScript with package.json
  if (fs.existsSync(path.join(repoDir, "package.json"))) {
    return { command: "npm", args: ["test"] };
  }

  return null;
}

/**
 * Synthesizes a valid, git-applicable unified diff from original lines and replacement lines.
 * Strictly guarantees leading spaces on context lines to prevent git apply corrupt hunk errors.
 *
 * @param {object} params
 * @param {string} params.filePath
 * @param {string} params.originalContent
 * @param {string} params.replacementText
 * @param {number} params.startLine - 1-based start line of replacement
 * @param {number} params.endLine - 1-based end line of replacement (inclusive)
 * @param {number} [params.contextLines=3]
 * @returns {{ diff: string, additions: number, deletions: number, targetFiles: string[] }}
 */
export function synthesizeUnifiedDiff({
  filePath,
  originalContent,
  replacementText,
  startLine,
  endLine,
  contextLines = 3
}) {
  if (!filePath || typeof filePath !== "string") {
    throw new Error("filePath must be a non-empty string.");
  }
  if (typeof originalContent !== "string") {
    throw new Error("originalContent must be a string.");
  }

  const normPath = normalizeRelativePath(filePath);
  const origLines = normalizeLineEndings(originalContent).split("\n");
  if (origLines.length > 0 && origLines[origLines.length - 1] === "") {
    origLines.pop(); // remove trailing empty string from split
  }

  const replLines = typeof replacementText === "string"
    ? normalizeLineEndings(replacementText).split("\n")
    : [];
  if (replLines.length > 0 && replLines[replLines.length - 1] === "") {
    replLines.pop();
  }

  const sLine = Math.max(1, parseInt(startLine, 10) || 1);
  const eLine = Math.max(sLine, parseInt(endLine, 10) || sLine);

  const preContextStart = Math.max(0, sLine - 1 - contextLines);
  const preContext = origLines.slice(preContextStart, sLine - 1);

  const postContextEnd = Math.min(origLines.length, eLine + contextLines);
  const postContext = origLines.slice(eLine, postContextEnd);

  const deletedLines = origLines.slice(sLine - 1, eLine);
  const addedLines = replLines;

  // Hunk coordinates
  const hunkOrigStart = preContextStart + 1;
  const hunkOrigCount = preContext.length + deletedLines.length + postContext.length;

  const hunkNewStart = preContextStart + 1;
  const hunkNewCount = preContext.length + addedLines.length + postContext.length;

  const hunkLines = [];
  hunkLines.push(`diff --git a/${normPath} b/${normPath}`);
  hunkLines.push(`--- a/${normPath}`);
  hunkLines.push(`+++ b/${normPath}`);
  hunkLines.push(`@@ -${hunkOrigStart},${hunkOrigCount} +${hunkNewStart},${hunkNewCount} @@`);

  for (const line of preContext) {
    hunkLines.push(` ${line}`);
  }
  for (const line of deletedLines) {
    hunkLines.push(`-${line}`);
  }
  for (const line of addedLines) {
    hunkLines.push(`+${line}`);
  }
  for (const line of postContext) {
    hunkLines.push(` ${line}`);
  }

  const diff = hunkLines.join("\n") + "\n";

  return {
    diff,
    additions: addedLines.length,
    deletions: deletedLines.length,
    targetFiles: [normPath]
  };
}

/**
 * Synthesizes a candidate patch with full anti-evasion compliance checking.
 *
 * @param {object} params
 * @param {string} params.targetFile
 * @param {string} params.originalContent
 * @param {string} params.patchReplacement
 * @param {number} params.startLine
 * @param {number} params.endLine
 * @param {boolean} [params.checkAntiEvasion=true]
 * @returns {{ diff: string, additions: number, deletions: number, patchDiffDigest: string, violations: object[] }}
 */
export function synthesizeMultiLanguagePatch({
  targetFile,
  originalContent,
  patchReplacement,
  startLine,
  endLine,
  checkAntiEvasion = true
}) {
  const synthesized = synthesizeUnifiedDiff({
    filePath: targetFile,
    originalContent,
    replacementText: patchReplacement,
    startLine,
    endLine
  });

  const violations = checkAntiEvasion
    ? scanStructuralAntiEvasionViolations(synthesized.diff, { targetFiles: [targetFile] })
    : [];

  if (violations.length > 0) {
    throw new StructuralAntiEvasionError(
      `Synthesized patch fails anti-evasion checks: ${violations.map(v => v.description).join("; ")}`,
      violations
    );
  }

  const patchDiffDigest = computeDigest(normalizeLineEndings(synthesized.diff));

  return {
    diff: synthesized.diff,
    additions: synthesized.additions,
    deletions: synthesized.deletions,
    targetFiles: synthesized.targetFiles,
    patchDiffDigest,
    violations
  };
}

/**
 * Orchestrates multi-language batch remediation across heterogeneous repository targets.
 */
export class MultiLanguageRemediationOrchestrator {
  /**
   * @param {string} batchId
   * @param {Array<{ id: string, targetFiles: string[], testRunner?: object, language?: string }>} findings
   * @param {object} [options]
   */
  constructor(batchId, findings = [], options = {}) {
    this.batchId = batchId;
    this.options = options;

    // Enrich findings with language detection if missing
    this.findings = findings.map(f => {
      const primaryTarget = f.targetFiles?.[0] || "";
      const lang = f.language || detectLanguage(primaryTarget);
      return {
        ...f,
        language: lang
      };
    });

    this.batchSession = new BatchRemediationSession(this.batchId, this.findings, options);
  }

  get status() {
    return this.batchSession.status;
  }

  get verdict() {
    return this.batchSession.verdict;
  }

  get sessionsCount() {
    return this.batchSession.sessionsCount;
  }

  /**
   * Proposes a patch fix for a specific finding in the batch.
   *
   * @param {string} findingId
   * @param {{ diff: string, rationale: string, synthesizer?: object }} params
   */
  proposeFix(findingId, { diff, rationale, synthesizer = { providerName: "triad-orchestrator" } }) {
    const session = this.batchSession.getSession(findingId);
    session.proposeFix({
      diff,
      rationale,
      synthesizer
    });
    return session;
  }

  /**
   * Authorizes all proposed patches in the batch for Patch Jail trial.
   *
   * @param {object} [authorizer]
   */
  authorizeAll(authorizer = { identity: "sec-lead@triad.flow", type: "human" }) {
    for (const f of this.findings) {
      const session = this.batchSession.getSession(f.id);
      if (session.status === REMEDIATION_STATES.FIX_PROPOSED) {
        session.authorizePatch({ authorizer });
      }
    }
  }

  /**
   * Executes the batch remediation inside an ephemeral Git Worktree Patch Jail.
   *
   * @param {string} repoPath
   * @param {object} [execOptions]
   */
  executeInJail(repoPath, execOptions = {}) {
    return this.batchSession.executeBatchInJailWorktree(repoPath, execOptions);
  }

  /**
   * Finalizes the batch remediation and produces the authoritative Batch Receipt.
   *
   * @param {object} [options]
   * @returns {object} Canonical Batch Remediation Receipt Schema 1.0.0
   */
  finalize(options = {}) {
    const summary = this.batchSession.finalize(options);
    const receipt = this.batchSession.toBatchReceipt();
    const valid = validateBatchReceipt(receipt);
    if (!valid) {
      throw new Error("Generated batch remediation receipt failed schema validation.");
    }
    return {
      summary,
      receipt
    };
  }
}
