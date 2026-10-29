/**
 * Triad-Flow Structural & Semantic Anti-Evasion Guard (M2 / v2.4)
 *
 * Implements Defense-in-Depth against Goodhart evasion attacks during automated remediation:
 * - Layer 1 (Zero-dependency deterministic structural & lexical analysis):
 *   1. Assertion & Security Stripping Guard (blocks deletion of asserts, validations, token checks).
 *   2. Comment-Only Substitution Guard (blocks replacing code with comments or blank lines).
 *   3. Trivial Constant Branch Bypass & Dead Code Guard (blocks if(true), if(false), empty catch blocks).
 *   4. Test Suite Integrity Shield (blocks unauthorized test modifications and test assertion weakening).
 *   5. Legacy Goodhart Evasion Guard (blocks .skip, xit, @ts-ignore, eslint-disable).
 * - Layer 2 (Parser Adapter Interface):
 *   Pluggable AST Adapter interface for deep syntactic analysis when external engines are available.
 */

import { normalizeLineEndings, normalizeRelativePath } from "./canonical-digest.mjs";

export const EVASION_VIOLATION_TYPES = Object.freeze({
  ASSERTION_STRIPPING: "assertion-stripping",
  COMMENT_ONLY_SUBSTITUTION: "comment-only-substitution",
  TRIVIAL_BRANCH_BYPASS: "trivial-branch-bypass",
  TEST_TAMPERING: "test-tampering",
  TEST_SKIPPING: "test-skipping",
  TEST_SKIPPING_X: "test-skipping-x",
  TS_SUPPRESS: "ts-suppress",
  ESLINT_SUPPRESS: "eslint-suppress",
  AST_SEMANTIC_VIOLATION: "ast-semantic-violation"
});

export class StructuralAntiEvasionError extends Error {
  constructor(message, violations = []) {
    super(message);
    this.name = "StructuralAntiEvasionError";
    this.violations = violations;
  }
}

/**
 * Base abstract class for Layer 2 pluggable AST parsers.
 */
export class BaseAstAdapter {
  constructor(name = "base-ast-adapter") {
    this.name = name;
  }

  /**
   * @param {string} code
   * @param {string} filename
   * @returns {object} AST representation
   */
  parse(code, filename) {
    throw new Error(`[BaseAstAdapter] 'parse' not implemented by adapter '${this.name}'.`);
  }

  /**
   * @param {{ diff: string, targetFile: string, preCode?: string, postCode?: string }} context
   * @returns {{ ok: boolean, violations: Array<{ type: string, description: string }> }}
   */
  analyze(context) {
    return { ok: true, violations: [] };
  }
}

/**
 * Regex patterns identifying assertions across languages (JS/TS, Python, Rust, Go, C/C++).
 */
export const ASSERTION_PATTERNS = [
  // JavaScript / TypeScript assertions
  /\bassert(?:\.[a-zA-Z0-9_]+)?\s*\(/,
  /\bexpect\s*\(.*?\)\s*\.[a-zA-Z0-9_]+/,
  /\bshould(?:\.[a-zA-Z0-9_]+)+/,
  /\b(?:rejects|resolves)\.[a-zA-Z0-9_]+/,

  // Python assertions
  /\bassert\s+[^=]/,
  /\bself\.assert[a-zA-Z0-9_]+\s*\(/,
  /\bpytest\.(?:fail|raises)\s*\(/,

  // Rust assertions and panic invariants
  /\b(?:assert|assert_eq|assert_ne|debug_assert|debug_assert_eq|debug_assert_ne)!\s*\(?/,
  /\bpanic!\s*\(?/,

  // Go assertions
  /\bt\.(?:Error|Errorf|Fatal|Fatalf|FailNow)\s*\(/,
  /\b(?:assert|require)\.[a-zA-Z0-9_]+\s*\(/,

  // C / C++ assertions
  /\bassert\s*\(/,
  /\bassert_true\s*\(/,
  /\bCU_ASSERT\s*\(/
];

/**
 * Regex patterns identifying security validation and authorization gates across languages.
 */
export const SECURITY_CHECK_PATTERNS = [
  // JS/TS security checks
  /\bif\s*\(.*!(?:valid|auth|verified|allowed|permitted|token|signature|session|permission|isAdmin|csrf|exists|check)\b.*?\)\s*(?:throw|return|process\.exit)/i,
  /\bjwt\.verify\s*\(/i,
  /\bcrypto\.timingSafeEqual\s*\(/i,
  /\bsanitize(?:Html|Input|Url|Path)?\s*\(/i,
  /\bescape(?:Html|Sql|Xml)?\s*\(/i,
  /\bvalidate(?:Token|Schema|Input|Signature|Path)?\s*\(/i,

  // Python security checks
  /\bif\s+not\s+(?:valid|auth|token|verified|allowed|csrf|exists|check)\b.*?:/i,
  /\bhmac\.compare_digest\s*\(/i,

  // Rust security checks
  /\bif\s+!(?:valid|auth|verified|token|signature|check)\b/i,
  /\bconstant_time_eq\s*\(/i,

  // Go security checks
  /\bif\s+!(?:valid|auth|verified|check)\b/i,
  /\bsubtle\.ConstantTimeCompare\s*\(/i,

  // C / C++ bounds and security checks
  /\bif\s*\(\s*!(?:valid|auth|check)\s*\)/i,
  /\bif\s*\(\s*explen\s*<\s*sizeof/i
];

/**
 * Patterns in added lines indicating trivial constant branch bypass or empty error swallowing.
 */
export const CONSTANT_BYPASS_PATTERNS = [
  // JS / TS / C / C++ if (true / 1)
  {
    pattern: /\bif\s*\(\s*(?:true|1|!0)\s*\)\s*(?:return\b|throw\b|process\.exit|exit\b|break\b)/i,
    description: "Patch introduces unconditional early exit via 'if (true)'"
  },
  // Go / Rust if true {
  {
    pattern: /\bif\s+true\s*\{/i,
    description: "Patch introduces unconditional branch via 'if true {'"
  },
  // Python if True:
  {
    pattern: /\bif\s+(?:True|1)\s*:\s*(?:return\b|raise\b|exit\b)/,
    description: "Patch introduces unconditional early exit via 'if True:'"
  },
  // JS / C dead branch if (false / 0)
  {
    pattern: /\bif\s*\(\s*(?:false|0|!1)\s*\)\s*\{/i,
    description: "Patch hides logic inside dead branch 'if (false)'"
  },
  // Go / Rust dead branch if false {
  {
    pattern: /\bif\s+false\s*\{/i,
    description: "Patch hides logic inside dead branch 'if false {'"
  },
  // Python dead branch if False:
  {
    pattern: /\bif\s+(?:False|0)\s*:/,
    description: "Patch hides logic inside dead branch 'if False:'"
  },
  // while (false)
  {
    pattern: /\bwhile\s*\(\s*(?:false|0|!1)\s*\)/i,
    description: "Patch wraps logic in non-executing 'while (false)'"
  },
  // JS empty catch block
  {
    pattern: /\bcatch\s*(?:\([^)]*\))?\s*\{\s*\}/,
    description: "Patch swallows errors silently with empty catch block"
  },
  // Python empty except: pass block
  {
    pattern: /\bexcept(?:\s+[a-zA-Z0-9_.]+)?\s*:\s*(?:pass|\.\.\.)\b/,
    description: "Patch swallows errors silently with 'except: pass'"
  }
];

/**
 * Legacy anti-degradation and test suppression patterns across languages.
 */
export const LEGACY_ANTI_DEGRADATION_PATTERNS = [
  {
    type: EVASION_VIOLATION_TYPES.TEST_SKIPPING,
    pattern: /(?:^|\s)(?:it|test|describe)\.skip\b/,
    description: "Patch skips test execution using .skip modifier"
  },
  {
    type: EVASION_VIOLATION_TYPES.TEST_SKIPPING_X,
    pattern: /(?:^|\s)(?:xit|xdescribe)\b/,
    description: "Patch disables test execution using xit/xdescribe"
  },
  {
    type: EVASION_VIOLATION_TYPES.TEST_SKIPPING,
    pattern: /@pytest\.mark\.skip\b/,
    description: "Patch skips Python test execution using @pytest.mark.skip"
  },
  {
    type: EVASION_VIOLATION_TYPES.TEST_SKIPPING,
    pattern: /@unittest\.skip\b/,
    description: "Patch skips Python test execution using @unittest.skip"
  },
  {
    type: EVASION_VIOLATION_TYPES.TEST_SKIPPING,
    pattern: /#\[ignore\b/,
    description: "Patch skips Rust test execution using #[ignore]"
  },
  {
    type: EVASION_VIOLATION_TYPES.TEST_SKIPPING,
    pattern: /\bt\.Skip(?:f)?\s*\(/,
    description: "Patch skips Go test execution using t.Skip"
  },
  {
    type: EVASION_VIOLATION_TYPES.TS_SUPPRESS,
    pattern: /\/\/\s*@ts-(?:ignore|nocheck)\b/,
    description: "Patch suppresses TypeScript compilation check"
  },
  {
    type: EVASION_VIOLATION_TYPES.ESLINT_SUPPRESS,
    pattern: /\/\*(?:\s*eslint-disable|\s*eslint-disable-line|\s*eslint-disable-next-line)\b/,
    description: "Patch suppresses ESLint rule enforcement"
  }
];

/**
 * Parses unified diff into categorized lines (additions, deletions, modified files).
 *
 * @param {string} diffText
 * @returns {{ files: string[], addedLines: string[], deletedLines: string[] }}
 */
export function extractDiffHunkLines(diffText) {
  if (typeof diffText !== "string") {
    return { files: [], addedLines: [], deletedLines: [] };
  }

  const normalized = normalizeLineEndings(diffText);
  const lines = normalized.split("\n");
  const files = new Set();
  const addedLines = [];
  const deletedLines = [];

  for (const line of lines) {
    const gitDiffMatch = line.match(/^diff --git a\/(.+?) b\/(.+?)$/);
    if (gitDiffMatch) {
      files.add(normalizeRelativePath(gitDiffMatch[2]));
      continue;
    }
    const plusMatch = line.match(/^\+\+\+ (?:b\/)?(.+?)$/);
    if (plusMatch && plusMatch[1] !== "/dev/null") {
      files.add(normalizeRelativePath(plusMatch[1]));
      continue;
    }

    if (line.startsWith("+") && !line.startsWith("+++")) {
      addedLines.push(line.slice(1));
    } else if (line.startsWith("-") && !line.startsWith("---")) {
      deletedLines.push(line.slice(1));
    }
  }

  return {
    files: Array.from(files).sort(),
    addedLines,
    deletedLines
  };
}

/**
 * Checks if a deleted line was a critical assertion or security check and was stripped without replacement.
 *
 * @param {string[]} deletedLines
 * @param {string[]} addedLines
 * @returns {Array<{ type: string, description: string, line: string }>}
 */
export function checkAssertionStripping(deletedLines = [], addedLines = []) {
  const violations = [];

  // Determine if added lines provide equivalent assertions or security checks
  const hasAddedAssertion = addedLines.some(line =>
    ASSERTION_PATTERNS.some(p => p.test(line))
  );
  const hasAddedSecurityCheck = addedLines.some(line =>
    SECURITY_CHECK_PATTERNS.some(p => p.test(line))
  );

  for (const line of deletedLines) {
    const trimmed = line.trim();

    // 1. Assertion stripping check
    const isAssertion = ASSERTION_PATTERNS.some(p => p.test(trimmed));
    if (isAssertion && !hasAddedAssertion) {
      violations.push({
        type: EVASION_VIOLATION_TYPES.ASSERTION_STRIPPING,
        description: `Candidate patch strips test assertion without equivalent replacement: '${trimmed}'`,
        line: trimmed
      });
      continue;
    }

    // 2. Security validation check stripping
    const isSecurityCheck = SECURITY_CHECK_PATTERNS.some(p => p.test(trimmed));
    if (isSecurityCheck && !hasAddedSecurityCheck) {
      violations.push({
        type: EVASION_VIOLATION_TYPES.ASSERTION_STRIPPING,
        description: `Candidate patch strips security validation check without affirmative equivalent: '${trimmed}'`,
        line: trimmed
      });
    }
  }

  return violations;
}

/**
 * Checks if a patch deletes code and only substitutes comments or whitespace.
 *
 * @param {string[]} deletedLines
 * @param {string[]} addedLines
 * @returns {Array<{ type: string, description: string, line: string }>}
 */
export function checkCommentSubstitution(deletedLines = [], addedLines = []) {
  const violations = [];

  // Filter meaningful deleted lines (ignore pure comments and blank lines)
  const meaningfulDeleted = deletedLines.filter(line => {
    const trimmed = line.trim();
    if (!trimmed) return false;
    if (trimmed.startsWith("//") || trimmed.startsWith("/*") || trimmed.startsWith("*") || trimmed.startsWith("#")) return false;
    return true;
  });

  if (meaningfulDeleted.length === 0) {
    return violations;
  }

  // Check if all added lines are comments or whitespace
  const hasExecutableAdditions = addedLines.some(line => {
    const trimmed = line.trim();
    if (!trimmed) return false;
    if (trimmed.startsWith("//") || trimmed.startsWith("/*") || trimmed.startsWith("*") || trimmed.startsWith("*/") || trimmed.startsWith("#")) return false;
    return true;
  });

  if (!hasExecutableAdditions) {
    violations.push({
      type: EVASION_VIOLATION_TYPES.COMMENT_ONLY_SUBSTITUTION,
      description: `Candidate patch deletes ${meaningfulDeleted.length} executable code line(s) and substitutes only comments or whitespace without executable remediation.`,
      line: addedLines[0]?.trim() || "(empty)"
    });
  }

  return violations;
}

/**
 * Checks if added lines introduce trivial constant bypasses or empty catch blocks.
 *
 * @param {string[]} addedLines
 * @returns {Array<{ type: string, description: string, line: string }>}
 */
export function checkConstantBranchBypass(addedLines = []) {
  const violations = [];

  for (const line of addedLines) {
    const trimmed = line.trim();
    for (const rule of CONSTANT_BYPASS_PATTERNS) {
      if (rule.pattern.test(trimmed)) {
        violations.push({
          type: EVASION_VIOLATION_TYPES.TRIVIAL_BRANCH_BYPASS,
          description: `${rule.description}: '${trimmed}'`,
          line: trimmed
        });
      }
    }
  }

  return violations;
}

/**
 * Checks if patch improperly modifies test files when only source files were in target scope.
 *
 * @param {string[]} modifiedFiles
 * @param {string[]} targetFiles
 * @returns {Array<{ type: string, description: string, file: string }>}
 */
export function checkTestTampering(modifiedFiles = [], targetFiles = []) {
  const violations = [];
  const normalizedTargets = new Set(targetFiles.map(f => normalizeRelativePath(f)));

  for (const file of modifiedFiles) {
    const isTestFile = /(?:^|[\\/])(?:tests?|__tests__|spec)\b/i.test(file) || /\.(?:test|spec)\.[a-z0-9]+$/i.test(file);
    if (isTestFile && !normalizedTargets.has(file)) {
      violations.push({
        type: EVASION_VIOLATION_TYPES.TEST_TAMPERING,
        description: `Test Integrity Shield violation: patch alters test suite file '${file}' outside declared source target files.`,
        file
      });
    }
  }

  return violations;
}

/**
 * Comprehensive Layer 1 + Layer 2 Structural Anti-Evasion Scanner.
 *
 * @param {string} diffText
 * @param {object} [options]
 * @param {string[]} [options.targetFiles]
 * @param {BaseAstAdapter} [options.astAdapter]
 * @returns {Array<{ type: string, description: string, line?: string, file?: string }>}
 */
export function scanStructuralAntiEvasionViolations(diffText, options = {}) {
  if (typeof diffText !== "string" || !diffText.trim()) {
    return [];
  }

  const { files, addedLines, deletedLines } = extractDiffHunkLines(diffText);
  const violations = [];

  // 1. Legacy Anti-Degradation Checks (Added lines: .skip, xit, @ts-ignore, eslint-disable)
  for (const line of addedLines) {
    const trimmed = line.trim();
    for (const rule of LEGACY_ANTI_DEGRADATION_PATTERNS) {
      if (rule.pattern.test(trimmed)) {
        violations.push({
          type: rule.type,
          description: rule.description,
          line: trimmed
        });
      }
    }
  }

  // 2. Assertion & Security Check Stripping (Deleted lines vs Added lines)
  const strippingViolations = checkAssertionStripping(deletedLines, addedLines);
  violations.push(...strippingViolations);

  // 3. Comment-Only Substitution
  const commentViolations = checkCommentSubstitution(deletedLines, addedLines);
  violations.push(...commentViolations);

  // 4. Constant Branch Bypass & Error Swallowing
  const bypassViolations = checkConstantBranchBypass(addedLines);
  violations.push(...bypassViolations);

  // 5. Test Suite Integrity Shield
  const targetFiles = Array.isArray(options.targetFiles) ? options.targetFiles : files;
  const testTamperingViolations = checkTestTampering(files, targetFiles);
  violations.push(...testTamperingViolations);

  // 6. Layer 2: Pluggable AST Adapter (if configured)
  if (options.astAdapter && typeof options.astAdapter.analyze === "function") {
    try {
      const astResult = options.astAdapter.analyze({
        diff: diffText,
        targetFile: targetFiles[0] || files[0] || "",
        ...options
      });
      if (astResult && Array.isArray(astResult.violations)) {
        violations.push(...astResult.violations);
      }
    } catch (err) {
      violations.push({
        type: EVASION_VIOLATION_TYPES.AST_SEMANTIC_VIOLATION,
        description: `AST Adapter error during semantic analysis: ${err.message}`
      });
    }
  }

  return violations;
}
