/**
 * Triad-Flow Review Context & AST Enclosure Builder (RFC-027-01)
 *
 * Implements zero-dependency, 4-layer context extraction, deterministic byte budgeting,
 * and Windows ARG_MAX safe transport planning.
 */

import fs from "node:fs";
import crypto from "node:crypto";
import path from "node:path";
import { normalizeCanonicalPath } from "./scoring.mjs";
import { getExactHeadFileContent, normalizeGitPath, normalizeScopeMode, detectCaseCollisions } from "./git-collector.mjs";
import { canonicalJsonStringify } from "./canonical-digest.mjs";
import { splitDiffByFiles } from "./chunk-manager.mjs";
import { truncateUtf8Safe, registerTrustedContextPackage, isGitRepo, isCommitInRepo, deepFreeze } from "./independent-verifier.mjs";

var _internalContextBuilderWorkflowMinter = _internalContextBuilderWorkflowMinter || null;

/**
 * Internal capability binder for context-builder workflow authority.
 * Write-once, called by independent-verifier.mjs during internal module wiring (P2-CAP-05).
 *
 * @param {Function} minter
 */
export function __bindContextBuilderWorkflowMinter(minter) {
  if (typeof minter === "function" && !_internalContextBuilderWorkflowMinter) {
    _internalContextBuilderWorkflowMinter = minter;
  }
}

export const SAFE_ARGV_THRESHOLD_BYTES = 8192;
export const GLOBAL_AST_CONTEXT_CEILING_BYTES = 8000;
export const MAX_CALLEES_PER_FILE = 5;
export const MAX_CALLEES_TOTAL = 10;
export const MAX_SNIPPET_LINES = 60;
export const MAX_SNIPPET_BYTES = 2000;
export const NON_CODE_FILE_REGEX = /\.(?:json|md|markdown|ya?ml|toml|lock|txt|csv|png|jpe?g|svg|ico)$/i;

export const DEFAULT_BUDGET_CONFIG = Object.freeze({
  maxInputBytes: 524288,     // 512 KB Total Budget
  frameBytes: 16384,         // 16 KB reserved for prompts and checklists
  layer0Ratio: 0.50,         // 50% for Layer 0 (Diff hunks)
  layer1Ratio: 0.30,         // 30% for Layer 1 (AST Enclosing Scope)
  layer2Ratio: 0.10,         // 10% for Layer 2 (Module Imports & Exports)
  layer3Ratio: 0.10          // 10% for Layer 3 (Call Graph & Flow References)
});

export const MAX_WORKING_TREE_FILE_BYTES = 2 * 1024 * 1024; // 2 MB ceiling

/**
 * Safely reads a working-tree file while enforcing repository path containment
 * (rejecting .. traversal, absolute path escape, and symlinks pointing outside repoRoot)
 * and file size ceiling (2 MB).
 *
 * @param {string} repoRoot - Canonical repository root path
 * @param {string} filePath - Target file path (relative or absolute)
 * @param {number} [maxBytes=MAX_WORKING_TREE_FILE_BYTES]
 * @returns {{ ok: boolean, exists: boolean, content: string|null, reason?: string, error?: string }}
 */
export function safeReadWorkingTreeFile(repoRoot, filePath, maxBytes = MAX_WORKING_TREE_FILE_BYTES) {
  if (!repoRoot || typeof repoRoot !== "string" || !filePath || typeof filePath !== "string") {
    return { ok: false, exists: false, content: null, reason: "REPOSITORY_PATH_ESCAPE", error: "Missing repository root or file path" };
  }

  let resolvedRepoRoot;
  try {
    resolvedRepoRoot = path.resolve(repoRoot);
  } catch (err) {
    return { ok: false, exists: false, content: null, reason: "REPOSITORY_PATH_ESCAPE", error: `Invalid repository root: ${err.message}` };
  }

  const diskPath = path.isAbsolute(filePath)
    ? path.resolve(filePath)
    : path.resolve(resolvedRepoRoot, filePath);

  const rel = path.relative(resolvedRepoRoot, diskPath);
  if (rel.startsWith("..") || path.isAbsolute(rel)) {
    return { ok: false, exists: false, content: null, reason: "REPOSITORY_PATH_ESCAPE", error: `File path '${filePath}' escapes repository boundary` };
  }

  let realRepoRoot;
  try {
    realRepoRoot = fs.existsSync(resolvedRepoRoot) ? fs.realpathSync(resolvedRepoRoot) : resolvedRepoRoot;
  } catch {
    realRepoRoot = resolvedRepoRoot;
  }

  if (!fs.existsSync(diskPath)) {
    return { ok: true, exists: false, content: null };
  }

  let realDiskPath;
  try {
    realDiskPath = fs.realpathSync(diskPath);
  } catch (err) {
    return { ok: false, exists: false, content: null, reason: "REPOSITORY_PATH_ESCAPE", error: `Cannot resolve realpath for '${filePath}': ${err.message}` };
  }

  const relReal = path.relative(realRepoRoot, realDiskPath);
  if (relReal.startsWith("..") || path.isAbsolute(relReal)) {
    return { ok: false, exists: false, content: null, reason: "REPOSITORY_PATH_ESCAPE", error: `Symlink '${filePath}' resolves outside repository root to '${realDiskPath}'` };
  }

  let stat;
  try {
    stat = fs.statSync(realDiskPath);
  } catch (err) {
    return { ok: false, exists: false, content: null, reason: "REPOSITORY_PATH_ESCAPE", error: `Cannot stat file '${filePath}': ${err.message}` };
  }

  if (!stat.isFile()) {
    return { ok: true, exists: false, content: null };
  }

  if (stat.size > maxBytes) {
    return { ok: false, exists: true, content: null, reason: "REPOSITORY_PATH_ESCAPE", error: `File size (${stat.size} bytes) exceeds working-tree ceiling (${maxBytes} bytes)` };
  }

  let content;
  try {
    content = fs.readFileSync(realDiskPath, "utf8");
  } catch (err) {
    return { ok: false, exists: false, content: null, reason: "REPOSITORY_PATH_ESCAPE", error: `Cannot read file '${filePath}': ${err.message}` };
  }

  return { ok: true, exists: true, content };
}

/**
 * Parses unified diff text to identify line ranges of changes for a file.
 * @param {string} diffHunks
 * @returns {Array<{ start: number, end: number }>}
 */
export function extractChangedLineSpans(diffHunks) {
  const spans = [];
  if (!diffHunks) return spans;

  const hunkHeaderRegex = /@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/g;
  let match;
  while ((match = hunkHeaderRegex.exec(diffHunks)) !== null) {
    const startLine = parseInt(match[3], 10);
    const lineCount = match[4] !== undefined ? parseInt(match[4], 10) : 1;
    spans.push({
      start: startLine,
      end: startLine + Math.max(lineCount - 1, 0)
    });
  }
  return spans;
}

/**
 * Extracts AST enclosing functions and classes from file source code without external dependencies.
 * Uses token-aware regular expressions and brace matching.
 * @param {string} fileContent
 * @param {Array<{ start: number, end: number }>} [changedLineSpans=[]]
 * @returns {{ adapterName: string, enclosingFunctions: Array<object>, enclosingClasses: Array<object> }}
 */
export function extractAstEnclosures(fileContent, changedLineSpans = []) {
  if (!fileContent || typeof fileContent !== "string") {
    return { adapterName: "builtin-semantic", enclosingFunctions: [], enclosingClasses: [] };
  }

  const lines = fileContent.split(/\r?\n/);
  const functions = [];
  const classes = [];

  // Patterns for function detection
  // 1. Function declaration: function foo(...) {
  const fnDeclRegex = /^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function(?:\s+([a-zA-Z0-9_$]+))?\s*\(([^)]*)\)\s*\{/;
  // 2. Class method: methodName(...) { - excluding control flow keywords
  const methodRegex = /^\s*(?:static\s+)?(?:async\s+)?(?!(?:if|for|while|switch|catch|with)\b)([a-zA-Z0-9_$]+)\s*\(([^)]*)\)\s*\{/;
  // 3. Arrow / Function assignment: const foo = (async)? (...) => { or = function
  const arrowRegex = /^\s*(?:export\s+)?(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:async\s*)?(?:\(([^)]*)\)|([a-zA-Z0-9_$]+))\s*=>\s*\{/;
  // 4. Class declaration: class Foo {
  const classDeclRegex = /^\s*(?:export\s+)?(?:default\s+)?class\s+([a-zA-Z0-9_$]+)(?:\s+extends\s+[a-zA-Z0-9_$]+)?\s*\{/;

  // Find line boundaries via brace counting
  for (let i = 0; i < lines.length; i++) {
    const lineNum = i + 1;
    const line = lines[i];

    // Check Class
    const classMatch = line.match(classDeclRegex);
    if (classMatch) {
      const className = classMatch[1];
      const endLine = findBraceScopeEnd(lines, i);
      const effectiveEndLine = endLine !== -1 ? endLine : lines.length;
      classes.push({
        name: className,
        startLine: lineNum,
        endLine: effectiveEndLine
      });
      continue;
    }

    // Check Function Declaration
    const fnMatch = line.match(fnDeclRegex);
    if (fnMatch) {
      const fnName = fnMatch[1] || `anonymous_L${lineNum}`;
      const params = (fnMatch[2] || "").split(",").map(p => p.trim()).filter(Boolean);
      const endLine = findBraceScopeEnd(lines, i);
      const effectiveEndLine = endLine !== -1 ? endLine : lines.length;
      functions.push({
        name: fnName,
        kind: "function",
        startLine: lineNum,
        endLine: effectiveEndLine,
        parameters: params,
        headerCode: line.trim(),
        bodySnippet: lines.slice(i, Math.min(i + 4, effectiveEndLine)).join("\n").trim()
      });
      continue;
    }

    // Check Method Definition
    const methodMatch = line.match(methodRegex);
    if (methodMatch) {
      const methodName = methodMatch[1];
      const params = (methodMatch[2] || "").split(",").map(p => p.trim()).filter(Boolean);
      const endLine = findBraceScopeEnd(lines, i);
      const effectiveEndLine = endLine !== -1 ? endLine : lines.length;
      functions.push({
        name: methodName,
        kind: "method",
        startLine: lineNum,
        endLine: effectiveEndLine,
        parameters: params,
        headerCode: line.trim(),
        bodySnippet: lines.slice(i, Math.min(i + 4, effectiveEndLine)).join("\n").trim()
      });
      continue;
    }

    // Check Arrow Assignment
    const arrowMatch = line.match(arrowRegex);
    if (arrowMatch) {
      const arrowName = arrowMatch[1];
      const params = (arrowMatch[2] || arrowMatch[3] || "").split(",").map(p => p.trim()).filter(Boolean);
      const endLine = findBraceScopeEnd(lines, i);
      const effectiveEndLine = endLine !== -1 ? endLine : lines.length;
      functions.push({
        name: arrowName,
        kind: "arrow",
        startLine: lineNum,
        endLine: effectiveEndLine,
        parameters: params,
        headerCode: line.trim(),
        bodySnippet: lines.slice(i, Math.min(i + 4, effectiveEndLine)).join("\n").trim()
      });
    }
  }

  // Filter enclosures relevant to changed spans if spans are provided
  if (changedLineSpans.length > 0) {
    const relevantFns = functions.filter(fn => {
      return changedLineSpans.some(span => {
        return (span.start <= fn.endLine && span.end >= fn.startLine) ||
               (Math.abs(span.start - fn.startLine) <= 15) ||
               (Math.abs(span.end - fn.endLine) <= 15);
      });
    });

    const relevantClasses = classes.filter(cls => {
      return changedLineSpans.some(span => {
        return span.start <= cls.endLine && span.end >= cls.startLine;
      });
    });

    return {
      adapterName: "builtin-semantic",
      enclosingFunctions: relevantFns.length > 0 ? relevantFns : functions.slice(0, 5),
      enclosingClasses: relevantClasses.length > 0 ? relevantClasses : classes.slice(0, 3)
    };
  }

  return {
    adapterName: "builtin-semantic",
    enclosingFunctions: functions.slice(0, 10),
    enclosingClasses: classes.slice(0, 5)
  };
}

/**
 * Finds the line number (1-indexed) where the opening brace on line startIndex closes.
 * Handles single-line comments, multi-line comments, string literals, multi-line template literals, and regex literals.
 * Returns -1 if the scope is unclosed or invalid.
 * @param {string[]} lines
 * @param {number} startIndex 0-indexed line index
 * @param {{ failClosed?: boolean }} [options={}]
 * @returns {number} 1-indexed end line, or -1 if unclosed
 */
export function findBraceScopeEnd(lines, startIndex, options = {}) {
  if (!Array.isArray(lines) || startIndex < 0 || startIndex >= lines.length) {
    return -1;
  }

  const failClosed = Boolean(options?.failClosed);
  const startCharIndex = typeof options?.startCharIndex === "number" && options.startCharIndex >= 0
    ? options.startCharIndex
    : 0;

  let depth = 0;
  let started = false;
  let inBlockComment = false;
  let inString = false;
  let stringChar = null;
  let lastNonWsChar = "";
  let lastWord = "";
  let currentWord = "";
  let prevWord = "";
  const parenContextStack = [];
  let lastParenWasStatementHeader = false;

  for (let i = startIndex; i < lines.length; i++) {
    const line = lines[i];
    const initialCharIdx = (i === startIndex) ? startCharIndex : 0;

    for (let charIdx = initialCharIdx; charIdx < line.length; charIdx++) {
      const c = line[charIdx];
      const nextC = charIdx + 1 < line.length ? line[charIdx + 1] : "";

      if (inBlockComment) {
        if (c === "*" && nextC === "/") {
          inBlockComment = false;
          charIdx++;
        }
        continue;
      }

      if (inString) {
        if (c === "\\" && charIdx + 1 < line.length) {
          charIdx++; // skip escaped char
        } else if (c === stringChar) {
          inString = false;
          stringChar = null;
          lastNonWsChar = c;
          lastWord = "";
          currentWord = "";
          prevWord = "";
        }
        continue;
      }

      // Check comments
      if (c === "/" && nextC === "/") {
        // Line comment: skip rest of line
        break;
      }
      if (c === "/" && nextC === "*") {
        inBlockComment = true;
        charIdx++;
        continue;
      }

      // Check string quotes
      if (c === '"' || c === "'" || c === "`") {
        inString = true;
        stringChar = c;
        lastWord = "";
        currentWord = "";
        prevWord = "";
        lastParenWasStatementHeader = false;
        continue;
      }

      if (c === "(") {
        if (currentWord) {
          prevWord = lastWord;
          lastWord = currentWord;
          currentWord = "";
        }
        const isHeader = /^(?:if|while|for|with|catch)$/.test(lastWord) || (lastWord === "await" && prevWord === "for");
        parenContextStack.push(isHeader);
        lastNonWsChar = "(";
        lastWord = "";
        currentWord = "";
        prevWord = "";
        lastParenWasStatementHeader = false;
        continue;
      }

      if (c === ")") {
        const isHeader = parenContextStack.pop() || false;
        lastParenWasStatementHeader = isHeader;
        lastNonWsChar = ")";
        lastWord = "";
        currentWord = "";
        prevWord = "";
        continue;
      }

      // Check regex literal vs division operator
      if (c === "/") {
        const isRegexPrecedingChar = !lastNonWsChar || /^[=([{:;,?!&|+*^%~<>-]$/.test(lastNonWsChar) || lastParenWasStatementHeader;
        const isRegexPrecedingWord = /^(?:return|case|typeof|delete|void|throw|yield|await|in|instanceof|new|else|do)$/.test(lastWord);

        if (isRegexPrecedingChar || isRegexPrecedingWord) {
          let j = charIdx + 1;
          let inCharClass = false;
          let foundRegexEnd = false;
          while (j < line.length) {
            if (line[j] === "\\") {
              j += 2;
              continue;
            }
            if (line[j] === "[" && !inCharClass) {
              inCharClass = true;
              j++;
              continue;
            }
            if (line[j] === "]" && inCharClass) {
              inCharClass = false;
              j++;
              continue;
            }
            if (line[j] === "/" && !inCharClass) {
              foundRegexEnd = true;
              break;
            }
            j++;
          }

          if (foundRegexEnd) {
            charIdx = j;
            while (charIdx + 1 < line.length && /^[gimsuy]$/i.test(line[charIdx + 1])) {
              charIdx++;
            }
            lastNonWsChar = "/";
            lastWord = "";
            currentWord = "";
            prevWord = "";
            lastParenWasStatementHeader = false;
            continue;
          }
        }
      }

      if (!/\s/.test(c)) {
        lastParenWasStatementHeader = false;
      }

      if (c === "{") {
        depth++;
        started = true;
        lastNonWsChar = "{";
        lastWord = "";
        currentWord = "";
        prevWord = "";
      } else if (c === "}") {
        depth--;
        lastNonWsChar = "}";
        lastWord = "";
        currentWord = "";
        prevWord = "";
        if (started && depth <= 0) {
          return i + 1;
        }
      } else if (/\s/.test(c)) {
        currentWord = "";
      } else if (/[a-zA-Z0-9_$]/.test(c)) {
        if (!currentWord) prevWord = lastWord;
        currentWord += c;
        lastWord = currentWord;
        lastNonWsChar = c;
      } else {
        lastNonWsChar = c;
        lastWord = "";
        currentWord = "";
        prevWord = "";
      }
    }

    if (inString && stringChar !== "`") {
      inString = false;
      stringChar = null;
    }
    currentWord = "";
  }

  return failClosed ? -1 : lines.length;
}

/**
 * Computes leading visual indentation width in spaces, converting tabs to 4-space tab stops.
 *
 * @param {string} str
 * @returns {number}
 */
export function computeIndent(str) {
  if (!str) return 0;
  let width = 0;
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    if (ch === " ") {
      width += 1;
    } else if (ch === "\t") {
      width += 4 - (width % 4);
    } else {
      break;
    }
  }
  return width;
}

/**
 * Strips Python line comment (# ...) from a string while respecting string literals.
 *
 * @param {string} str
 * @returns {string}
 */
export function stripPythonLineComment(str) {
  if (!str) return "";
  let inString = false;
  let stringChar = null;
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    if (inString) {
      if (ch === "\\" && i + 1 < str.length) {
        i++;
      } else if (ch === stringChar) {
        inString = false;
        stringChar = null;
      }
      continue;
    }
    if (ch === '"' || ch === "'") {
      inString = true;
      stringChar = ch;
      continue;
    }
    if (ch === "#") {
      return str.slice(0, i);
    }
  }
  return str;
}

/**
 * Finds the 1-based end line of a Python function definition starting at defLineIdx (0-based).
 * Handles multiline parameter lists, type annotations, single-line functions, docstrings,
 * nested structures, and dict/set literals without relying on braces (G5-P2-05).
 * Returns -1 if the function signature is malformed/unclosed or has no body.
 *
 * @param {string[]} lines
 * @param {number} defLineIdx - 0-based line index of the def line
 * @returns {number} 1-based end line number, or -1 if invalid
 */
export function findPythonScopeEnd(lines, defLineIdx) {
  if (!Array.isArray(lines) || defLineIdx < 0 || defLineIdx >= lines.length) {
    return -1;
  }

  const defLine = lines[defLineIdx];
  const defMatch = defLine.match(/^(\s*)(?:async\s+)?def\s+([a-zA-Z0-9_$]+)\s*\(/);
  if (!defMatch) {
    return -1;
  }

  const baseIndent = computeIndent(defMatch[1]);
  const sym = defMatch[2];
  const symIdx = defLine.indexOf(sym);
  const openParenIdx = defLine.indexOf("(", symIdx);
  if (openParenIdx === -1) return -1;

  // 1. Scan for signature completion: matching ')' followed by ':'
  let parenDepth = 0;
  let bracketDepth = 0;
  let braceDepth = 0;
  let inString = false;
  let stringChar = null;
  let isTripleQuote = false;
  let sigClosed = false;
  let colonLineIdx = -1;
  let colonCharIdx = -1;

  const maxSigLines = Math.min(lines.length, defLineIdx + 30);
  for (let i = defLineIdx; i < maxSigLines; i++) {
    const line = lines[i];
    const startChar = (i === defLineIdx) ? openParenIdx : 0;

    for (let c = startChar; c < line.length; c++) {
      const ch = line[c];
      const next1 = c + 1 < line.length ? line[c + 1] : "";
      const next2 = c + 2 < line.length ? line[c + 2] : "";

      if (inString) {
        if (ch === "\\" && !isTripleQuote) {
          c++;
          continue;
        }
        if (isTripleQuote) {
          if (ch === stringChar && next1 === stringChar && next2 === stringChar) {
            inString = false;
            stringChar = null;
            isTripleQuote = false;
            c += 2;
          }
        } else {
          if (ch === stringChar) {
            inString = false;
            stringChar = null;
          }
        }
        continue;
      }

      if (ch === "#") {
        break; // comment to end of line
      }

      if (ch === '"' || ch === "'") {
        if (next1 === ch && next2 === ch) {
          inString = true;
          stringChar = ch;
          isTripleQuote = true;
          c += 2;
        } else {
          inString = true;
          stringChar = ch;
          isTripleQuote = false;
        }
        continue;
      }

      if (ch === "(") {
        parenDepth++;
      } else if (ch === ")") {
        if (parenDepth > 0) parenDepth--;
      } else if (ch === "[") {
        bracketDepth++;
      } else if (ch === "]") {
        if (bracketDepth > 0) bracketDepth--;
      } else if (ch === "{") {
        braceDepth++;
      } else if (ch === "}") {
        if (braceDepth > 0) braceDepth--;
      } else if (ch === ":") {
        if (parenDepth === 0 && bracketDepth === 0 && braceDepth === 0) {
          sigClosed = true;
          colonLineIdx = i;
          colonCharIdx = c;
          break;
        }
      }
    }

    if (sigClosed) break;
  }

  if (!sigClosed || colonLineIdx === -1) {
    return -1;
  }

  // 2. Check for single-line function: def foo(x): return x
  const colonLine = lines[colonLineIdx];
  const afterColon = colonLine.slice(colonCharIdx + 1);
  const codeAfterColon = stripPythonLineComment(afterColon).trim();
  if (codeAfterColon.length > 0) {
    return colonLineIdx + 1;
  }

  // 3. Scan indented body lines
  let lastBodyLineIdx = -1;
  inString = false;
  stringChar = null;
  isTripleQuote = false;
  parenDepth = 0;
  bracketDepth = 0;
  braceDepth = 0;

  for (let i = colonLineIdx + 1; i < lines.length; i++) {
    const rawLine = lines[i];
    const trimmed = rawLine.trim();

    // Inside a multiline string/docstring, all lines belong to the body
    if (inString) {
      lastBodyLineIdx = i;
      for (let c = 0; c < rawLine.length; c++) {
        const ch = rawLine[c];
        const next1 = c + 1 < rawLine.length ? rawLine[c + 1] : "";
        const next2 = c + 2 < rawLine.length ? rawLine[c + 2] : "";
        if (isTripleQuote) {
          if (ch === stringChar && next1 === stringChar && next2 === stringChar) {
            inString = false;
            stringChar = null;
            isTripleQuote = false;
            c += 2;
          }
        } else {
          if (ch === "\\" && c + 1 < rawLine.length) {
            c++;
          } else if (ch === stringChar) {
            inString = false;
            stringChar = null;
          }
        }
      }
      continue;
    }

    // Blank line
    if (trimmed.length === 0) {
      continue;
    }

    const indent = computeIndent(rawLine);

    // Comment line handling
    if (trimmed.startsWith("#")) {
      if (indent > baseIndent) {
        lastBodyLineIdx = i;
      } else {
        // Comment at <= baseIndent: check if subsequent non-blank code resumes indent > baseIndent
        let resumes = false;
        for (let k = i + 1; k < lines.length; k++) {
          const nextTrim = lines[k].trim();
          if (nextTrim.length === 0 || nextTrim.startsWith("#")) continue;
          if (computeIndent(lines[k]) > baseIndent) {
            resumes = true;
          }
          break;
        }
        if (!resumes) {
          break;
        }
      }
      continue;
    }

    // Code line: check indentation boundary if outside open brackets/parens/braces
    if (indent <= baseIndent && parenDepth === 0 && bracketDepth === 0 && braceDepth === 0) {
      break;
    }

    lastBodyLineIdx = i;

    // Scan line for string literals, comments, and bracket/paren/brace depths
    for (let c = 0; c < rawLine.length; c++) {
      const ch = rawLine[c];
      const next1 = c + 1 < rawLine.length ? rawLine[c + 1] : "";
      const next2 = c + 2 < rawLine.length ? rawLine[c + 2] : "";

      if (ch === "#") {
        break;
      }

      if (ch === '"' || ch === "'") {
        if (next1 === ch && next2 === ch) {
          inString = true;
          stringChar = ch;
          isTripleQuote = true;
          c += 2;
          // check if closed on same line
          for (let k = c + 1; k < rawLine.length - 2; k++) {
            if (rawLine[k] === stringChar && rawLine[k + 1] === stringChar && rawLine[k + 2] === stringChar) {
              inString = false;
              stringChar = null;
              isTripleQuote = false;
              c = k + 2;
              break;
            }
          }
        } else {
          // single-line string literal
          for (let k = c + 1; k < rawLine.length; k++) {
            if (rawLine[k] === "\\") {
              k++;
            } else if (rawLine[k] === ch) {
              c = k;
              break;
            }
          }
        }
        continue;
      }

      if (ch === "(") parenDepth++;
      else if (ch === ")") { if (parenDepth > 0) parenDepth--; }
      else if (ch === "[") bracketDepth++;
      else if (ch === "]") { if (bracketDepth > 0) bracketDepth--; }
      else if (ch === "{") braceDepth++;
      else if (ch === "}") { if (braceDepth > 0) braceDepth--; }
    }
  }

  if (lastBodyLineIdx === -1) {
    return -1;
  }

  return lastBodyLineIdx + 1;
}

/**
 * Strips block and line comments from lines, replacing comment characters with spaces
 * to preserve line numbers, line lengths, and column positions for lexical analysis (C2).
 *
 * @param {string[]} lines
 * @returns {string[]}
 */
export function stripCommentsPreservingLayout(lines) {
  if (!Array.isArray(lines)) return [];
  const result = [];
  let inBlockComment = false;
  let inString = false;
  let stringChar = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    let out = "";
    for (let j = 0; j < line.length; j++) {
      const c = line[j];
      const next = j + 1 < line.length ? line[j + 1] : "";

      if (inBlockComment) {
        if (c === "*" && next === "/") {
          inBlockComment = false;
          out += "  ";
          j++;
        } else {
          out += " ";
        }
        continue;
      }

      if (inString) {
        if (c === "\\") {
          out += "  ";
          j++;
          continue;
        }
        if (c === stringChar) {
          inString = false;
          stringChar = null;
        }
        out += " ";
        continue;
      }

      if (c === "/" && next === "*") {
        inBlockComment = true;
        out += "  ";
        j++;
        continue;
      }

      if (c === "/" && next === "/") {
        out += " ".repeat(line.length - j);
        break;
      }

      if (c === '"' || c === "'" || c === "`") {
        inString = true;
        stringChar = c;
        out += " ";
        continue;
      }

      out += c;
    }

    if (inString && stringChar !== "`") {
      inString = false;
      stringChar = null;
    }

    result.push(out);
  }
  return result;
}

/**
 * Finds all candidate definition line ranges for a given symbol in file lines.
 *
 * @param {string[]} lines
 * @param {string} symbol
 * @returns {Array<{ startLine: number, endLine: number }>}
 */
export function findFunctionDefinitions(lines, symbol) {
  const matches = [];
  const escapedSym = symbol.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

  const cleanLines = stripCommentsPreservingLayout(lines);

  const HAS_EXPLICIT_DECL_HEADER = new RegExp(
    `(?:` +
    `^(?:\\s*(?:[a-zA-Z0-9_<>*&]|::)+\\s+)+(?:[a-zA-Z0-9_]+::)?${escapedSym}\\s*(?:<[^()]+>\\s*)?\\(|` +
    `^\\s*(?:export\\s+)?(?:default\\s+)?(?:async\\s+)?function(?:\\s+${escapedSym})?\\s*(?:<[^()]+>\\s*)?\\(|` +
    `^\\s*(?:(?:static|async|public|private|protected|virtual|inline|override)\\s+)+${escapedSym}\\s*(?:<[^()]+>\\s*)?\\(|` +
    `^\\s*(?:export\\s+)?(?:const|let|var)?\\s*${escapedSym}\\s*=\\s*(?:async\\s*)?(?:<[^()]+>\\s*)?(?:\\([^)]*\\)|[a-zA-Z0-9_$]+)?\\s*(?:=>|function)|` +
    `^\\s*(?:async\\s+)?def\\s+${escapedSym}\\s*\\(` +
    `)`
  );

  const DEF_REGEX = new RegExp(
    `(?:` +
    `^(?:\\s*(?:[a-zA-Z0-9_<>*&]|::)+\\s+)+(?:[a-zA-Z0-9_]+::)?${escapedSym}\\s*(?:<[^()]+>\\s*)?\\(|` +
    `^\\s*(?:export\\s+)?(?:default\\s+)?(?:async\\s+)?function(?:\\s+${escapedSym})?\\s*(?:<[^()]+>\\s*)?\\(|` +
    `^\\s*(?:static\\s+)?(?:async\\s+)?${escapedSym}\\s*(?:<[^()]+>\\s*)?\\(|` +
    `^\\s*(?:export\\s+)?(?:const|let|var)?\\s*${escapedSym}\\s*=\\s*(?:async\\s*)?(?:<[^()]+>\\s*)?(?:\\([^)]*\\)|[a-zA-Z0-9_$]+)?\\s*(?:=>|function)|` +
    `^\\s*(?:async\\s+)?def\\s+${escapedSym}\\s*\\(` +
    `)`
  );
  const PYTHON_DEF_REGEX = new RegExp(`^\\s*(?:async\\s+)?def\\s+${escapedSym}\\s*\\(`);

  const CONTROL_START = /^\s*(?:if|while|for|switch|catch|with|return|throw|delete|typeof|sizeof|case|else\s+if)\b/;
  const CALL_EXPR_DISQUALIFIERS = /(?:==|!=|&&|\|\||return\s+|throw\s+|new\s+)/;
  const PROP_START = /^\s*(?:[a-zA-Z0-9_$]+|"[^"]*"|'[^']*')\s*:\s*/;

  for (let i = 0; i < cleanLines.length; i++) {
    const line = cleanLines[i];

    if (!line.includes(symbol)) continue;
    if (CONTROL_START.test(line)) continue;
    if (PROP_START.test(line)) continue;
    if (!DEF_REGEX.test(line)) continue;

    // Python function definitions use indentation-based scoping instead of braces (G5-P2-05)
    if (PYTHON_DEF_REGEX.test(line)) {
      const endLine = findPythonScopeEnd(lines, i);
      if (endLine !== -1 && endLine >= i + 1) {
        matches.push({
          startLine: i + 1,
          endLine: endLine
        });
        if (endLine > i + 1) {
          i = endLine - 1;
        }
      }
      continue;
    }

    if (line.includes("=") && !line.includes("=>") && !line.includes("function") && !line.includes("{")) {
      continue;
    }

    if (CALL_EXPR_DISQUALIFIERS.test(line) && !line.includes("=>") && !line.includes("{")) {
      continue;
    }

    let hasBrace = false;
    let braceLineIdx = -1;
    let bodyBraceIdx = 0;
    let isDeclarationOnly = false;
    let parenClosed = false;
    let parenDepth = 0;
    const STATEMENT_KEYWORD = /^\s*(?:if|while|for|switch|catch|with|return|throw|delete|typeof|sizeof|case|else|const|let|var|yield|await)\b/;

    const symIdx = line.indexOf(symbol);
    const openParenIdx = symIdx !== -1 ? line.indexOf("(", symIdx) : -1;
    const scanCharIdx = openParenIdx !== -1 ? openParenIdx : 0;

    for (let j = i; j < Math.min(i + 15, cleanLines.length); j++) {
      const scanLine = cleanLines[j];
      const trimmed = scanLine.trim();

      if (!parenClosed) {
        const startK = j === i ? scanCharIdx : 0;
        for (let k = startK; k < scanLine.length; k++) {
          const ch = scanLine[k];
          if (ch === "(") parenDepth++;
          else if (ch === ")") {
            parenDepth--;
            if (parenDepth <= 0) {
              parenClosed = true;
              let searchFrom = k + 1;
              let foundBraceIdx = -1;
              while (searchFrom < scanLine.length) {
                const bIdx = scanLine.indexOf("{", searchFrom);
                if (bIdx === -1) break;
                const closeIdx = scanLine.indexOf("}", bIdx + 1);
                const nextOpenIdx = scanLine.indexOf("{", bIdx + 1);
                if (closeIdx !== -1 && (nextOpenIdx === -1 || closeIdx < nextOpenIdx)) {
                  const subsequentOpen = scanLine.indexOf("{", closeIdx + 1);
                  if (subsequentOpen !== -1) {
                    searchFrom = subsequentOpen;
                    continue;
                  }
                }
                foundBraceIdx = bIdx;
                break;
              }
              if (foundBraceIdx !== -1) {
                hasBrace = true;
                braceLineIdx = j;
                bodyBraceIdx = foundBraceIdx;
              }
              break;
            }
          }
        }
        if (hasBrace) break;
      } else {
        if (j > i) {
          const isCppQualifier = /^\s*const(?:\s+(?:noexcept|override|final|volatile|=|->))?\s*(?:\{|$|\/\/|\/\*)/.test(trimmed);
          if (STATEMENT_KEYWORD.test(trimmed) && !isCppQualifier) {
            isDeclarationOnly = true;
            break;
          }
          const braceIdx = scanLine.indexOf("{");
          if (trimmed.length > 0 && braceIdx === -1 && !/^(?::|->|const\b|noexcept\b|override\b|\/\*|\/\/)/.test(trimmed)) {
            isDeclarationOnly = true;
            break;
          }
        }
        const braceIdx = scanLine.indexOf("{");
        if (braceIdx !== -1) {
          hasBrace = true;
          braceLineIdx = j;
          bodyBraceIdx = braceIdx;
          break;
        }
      }

      const semiIdx = scanLine.indexOf(";");
      const braceIdx = scanLine.indexOf("{");
      if (semiIdx !== -1 && (braceIdx === -1 || semiIdx < braceIdx)) {
        isDeclarationOnly = true;
        break;
      }
    }

    if (isDeclarationOnly || !hasBrace || braceLineIdx === -1) {
      continue;
    }

    let hasExplicitHeader = HAS_EXPLICIT_DECL_HEADER.test(line);
    if (!hasExplicitHeader) {
      for (let prevIdx = i - 1; prevIdx >= Math.max(0, i - 3); prevIdx--) {
        const prevTrim = cleanLines[prevIdx].trim();
        if (prevTrim.length === 0) continue;
        if (HAS_EXPLICIT_DECL_HEADER.test(`${prevTrim} ${line.trim()}`)) {
          hasExplicitHeader = true;
          break;
        }
        break;
      }
    }

    if (braceLineIdx > i && !hasExplicitHeader) {
      // Reject bare call expressions accepting delayed body brace (sl1Ri / C3)
      continue;
    }

    const endLine = findBraceScopeEnd(cleanLines, braceLineIdx, { failClosed: true, startCharIndex: bodyBraceIdx });
    if (endLine === -1 || endLine < i + 1) {
      continue;
    }
    matches.push({
      startLine: i + 1,
      endLine: endLine
    });

    if (endLine > i + 1) {
      i = endLine - 1;
    }
  }

  return matches;
}

/**
 * Resolves the bound class name for a qualifier at a specific call line using Route B
 * minimal flat-scope whitelist and strict default-deny (RFC-027-01).
 *
 * Rules:
 * 1. Minimal whitelist: only verified static calls (PascalCase) or unique unambiguous
 *    flat-scope instance bindings (const qualifier = new Class()).
 * 2. Default-deny on closures, arrow functions, destructuring parameters, catch blocks,
 *    inner block scopes, and reassignments (let/var or mutation).
 *
 * @param {string[]} lines
 * @param {string} qualifier
 * @param {string} symbol
 * @param {number|null} targetLine
 * @returns {string|null}
 */
function checkVariableBinding(line, qual) {
  const declMatch = line.match(/\b(let|var|const)\s+([\s\S]+)/);
  if (!declMatch) return false;
  const kind = declMatch[1];
  const rest = declMatch[2];
  let depth = 0;
  let inPattern = true;
  let currentPattern = "";
  const qualRegex = new RegExp(`(?:^|[^a-zA-Z0-9_$])${qual}(?:$|[^a-zA-Z0-9_$])`);
  for (let i = 0; i < rest.length; i++) {
    const ch = rest[i];
    if (ch === ";" || (ch === ")" && depth === 0)) break;
    if (ch === "{" || ch === "[" || ch === "(") {
      depth++;
      if (inPattern) currentPattern += ch;
    } else if (ch === "}" || ch === "]" || ch === ")") {
      depth--;
      if (inPattern) currentPattern += ch;
    } else if (ch === "=" && depth === 0) {
      if (inPattern) {
        if (qualRegex.test(currentPattern)) return { kind, pattern: currentPattern.trim() };
        inPattern = false;
        currentPattern = "";
      }
    } else if (ch === "," && depth === 0) {
      if (inPattern && qualRegex.test(currentPattern)) {
        return { kind, pattern: currentPattern.trim() };
      }
      inPattern = true;
      currentPattern = "";
    } else {
      if (inPattern) currentPattern += ch;
    }
  }
  if (inPattern && qualRegex.test(currentPattern)) {
    return { kind, pattern: currentPattern.trim() };
  }
  return false;
}

function findFunctionSignature(srcLines, startLineIdx) {
  let inParams = false;
  let parenDepth = 0;
  let paramsText = "";
  for (let k = startLineIdx; k < Math.min(srcLines.length, startLineIdx + 20); k++) {
    const line = srcLines[k];
    for (let c = 0; c < line.length; c++) {
      const ch = line[c];
      if (ch === "(") {
        if (!inParams) {
          inParams = true;
          parenDepth = 1;
          continue;
        }
        parenDepth++;
      } else if (ch === ")") {
        parenDepth--;
        if (parenDepth === 0) {
          for (let m = k; m < Math.min(srcLines.length, k + 10); m++) {
            const startChar = (m === k) ? c + 1 : 0;
            const braceIdx = srcLines[m].indexOf("{", startChar);
            if (braceIdx !== -1) {
              return {
                bodyLineIdx: m,
                bodyCharIdx: braceIdx,
                paramsText: paramsText.trim()
              };
            }
            if (srcLines[m].slice(startChar).includes(";")) {
              return null;
            }
          }
          return null;
        }
      }
      if (inParams && parenDepth > 0) {
        paramsText += ch;
      }
    }
    if (inParams) {
      paramsText += " ";
    }
  }
  return null;
}

function collectClasses(cleanLines, lines) {
  const anyClassRegex = /^\s*(?:export\s+)?(?:default\s+)?class\s+([A-Za-z0-9_$]+)\b/;
  const classes = [];
  for (let i = 0; i < cleanLines.length; i++) {
    const match = cleanLines[i].match(anyClassRegex);
    if (match) {
      let braceLineIdx = -1;
      let braceCharIdx = -1;
      for (let k = i; k < Math.min(cleanLines.length, i + 5); k++) {
        const idx = cleanLines[k].indexOf("{");
        if (idx !== -1) {
          braceLineIdx = k;
          braceCharIdx = idx;
          break;
        }
        if (cleanLines[k].includes(";")) break;
      }
      if (braceLineIdx !== -1) {
        const endLine = findBraceScopeEnd(lines, braceLineIdx, { failClosed: true, startCharIndex: braceCharIdx });
        if (endLine !== -1 && endLine > braceLineIdx + 1) {
          classes.push({
            name: match[1],
            startLine: i + 1,
            braceLineIdx,
            braceCharIdx,
            endLine
          });
        }
      }
    }
  }
  return classes;
}

function collectFunctions(cleanLines, lines) {
  const fnPatterns = [
    /^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function(?:\s*\*|\s+[a-zA-Z0-9_$]+|\s*\()/i,
    /^\s*(?:export\s+)?(?:const|let|var)\s+[a-zA-Z0-9_$]+\s*=\s*(?:async\s+)?function(?:\s*\*|\s+[a-zA-Z0-9_$]+|\s*\()/i,
    /^\s*(?:static\s+)?(?:async\s+)?(?:\*\s*)?(?!(?:if|for|while|switch|catch|with)\b)([a-zA-Z0-9_$]+)\s*(?:<[^()]+>\s*)?\(/
  ];
  const functions = [];
  for (let i = 0; i < cleanLines.length; i++) {
    if (fnPatterns.some(p => p.test(cleanLines[i]))) {
      const sig = findFunctionSignature(cleanLines, i);
      if (sig) {
        const endLine = findBraceScopeEnd(lines, sig.bodyLineIdx, { failClosed: true, startCharIndex: sig.bodyCharIdx });
        if (endLine !== -1 && endLine >= i + 1) {
          functions.push({
            startLine: i + 1,
            bodyLineIdx: sig.bodyLineIdx,
            bodyCharIdx: sig.bodyCharIdx,
            endLine,
            paramsText: sig.paramsText
          });
        }
      }
    }
  }
  return functions;
}

function isMethodDirectInClass(cleanLines, classRecord, methodLineIdx, classes, functions) {
  if (!classRecord || typeof methodLineIdx !== "number" || !Array.isArray(cleanLines)) {
    return false;
  }
  const lineNum = methodLineIdx + 1;
  // 1. Must be strictly within classRecord boundaries
  if (methodLineIdx <= classRecord.braceLineIdx || methodLineIdx >= classRecord.endLine - 1) {
    return false;
  }

  // 2. Must not be inside any other class
  if (Array.isArray(classes) && classes.some(c => c !== classRecord && c.startLine <= lineNum && lineNum <= c.endLine)) {
    return false;
  }

  // 3. Must not be inside any enclosing function/method body
  if (Array.isArray(functions) && functions.some(f => f.startLine < lineNum && lineNum <= f.endLine)) {
    return false;
  }

  // 4. Syntactic brace depth inside classRecord body must be exactly 1 at the method declaration
  let depth = 1;
  const startLine = classRecord.braceLineIdx;
  const startChar = (typeof classRecord.braceCharIdx === "number" && classRecord.braceCharIdx >= 0)
    ? classRecord.braceCharIdx + 1
    : (cleanLines[startLine] ? cleanLines[startLine].indexOf("{") + 1 : 0);

  for (let l = startLine; l <= methodLineIdx; l++) {
    const line = cleanLines[l] || "";
    const initialChar = (l === startLine) ? startChar : 0;
    let endChar = line.length;
    if (l === methodLineIdx) {
      const match = line.match(/\b(?:static\s+)?(?:async\s+)?(?:\*\s*)?[A-Za-z0-9_$]+\s*(?:<[^()]+>\s*)?\(/);
      endChar = match ? match.index : (line.search(/\S/) !== -1 ? line.search(/\S/) : line.length);
    }

    for (let c = initialChar; c < endChar; c++) {
      if (line[c] === "{") {
        depth++;
      } else if (line[c] === "}") {
        depth--;
        if (depth < 1) return false;
      }
    }
  }

  return depth === 1;
}

export function resolveReceiverLexicalBinding(lines, qualifier, symbol, targetLine, opts = {}) {
  if (!qualifier || typeof qualifier !== "string" || !symbol || typeof symbol !== "string" || !Array.isArray(lines)) {
    return null;
  }
  if (!/^[a-zA-Z0-9_$]+$/.test(qualifier) || !/^[a-zA-Z0-9_$]+$/.test(symbol)) {
    return null;
  }

  const escapedSym = symbol.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const escapedQual = qualifier.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const isPascal = /^[A-Z]/.test(qualifier);

  const cleanLines = Array.isArray(opts?.cleanLines)
    ? opts.cleanLines
    : lines.map(line => stripCommentsAndStrings(line, { val: false, inTemplate: false, templateDepths: [] }));

  const classes = opts?.classes || collectClasses(cleanLines, lines);
  const functions = opts?.functions || collectFunctions(cleanLines, lines);

  // 1. Whitelist Case A: PascalCase calls (Class.method)
  // Only match if class <qualifier> exists in cleanLines AND has an explicit `static <symbol>(` method
  // directly in the class body (not in nested classes or functions).
  // Must prove that qualifier is NOT shadowed by any function parameter, local variable,
  // arrow function, catch block, or reassignment.
  if (isPascal) {
    const classRecord = classes.find(c => c.name === qualifier);
    if (!classRecord) return null;
    if (functions.some(f => f.startLine <= classRecord.startLine && classRecord.startLine <= f.endLine)) {
      return null;
    }
    const staticMethodRegex = new RegExp(`^\\s*static\\s+(?:async\\s+)?(?:\\*\\s*)?${escapedSym}\\s*(?:<[^()]+>\\s*)?\\(`);
    let hasStaticMethod = false;
    for (let j = classRecord.braceLineIdx + 1; j < classRecord.endLine - 1; j++) {
      if (staticMethodRegex.test(cleanLines[j])) {
        if (isMethodDirectInClass(cleanLines, classRecord, j, classes, functions)) {
          hasStaticMethod = true;
          break;
        }
      }
    }
    if (!hasStaticMethod) return null;

    let resolvedCallLine = targetLine;
    if (!resolvedCallLine) {
      const callRegex = new RegExp(`(?:^|[^a-zA-Z0-9_$])${escapedQual}(?:\\.|\\?\\.)${escapedSym}\\s*(?:<[^()]+>\\s*)?(?:\\?\\.\\s*)?\\(`);
      const callLines = [];
      for (let idx = 0; idx < cleanLines.length; idx++) {
        if (callRegex.test(cleanLines[idx])) {
          callLines.push(idx + 1);
        }
      }
      if (callLines.length === 1) {
        resolvedCallLine = callLines[0];
      }
    }

    const qualParamRegex = new RegExp(`(?:^|[^a-zA-Z0-9_$])${escapedQual}(?:$|[^a-zA-Z0-9_$])`);
    const arrowParamRegex = new RegExp(`(?:\\([^)]*\\b${escapedQual}\\b[^)]*\\)|\\b${escapedQual}\\b)\\s*=>`);
    const catchParamRegex = new RegExp(`\\bcatch\\s*\\([^)]*\\b${escapedQual}\\b[^)]*\\)`);
    const reassignmentRegex = new RegExp(`(?:^|[^a-zA-Z0-9_$.])${escapedQual}\\s*(?:=(?!=)|\\+=|-=|\\*=|\\/=|%=|\\+\\+|--)`);

    if (cleanLines.some(l => arrowParamRegex.test(l)) || cleanLines.some(l => catchParamRegex.test(l))) {
      return null;
    }

    if (resolvedCallLine) {
      const enclosingFns = functions.filter(f => f.startLine <= resolvedCallLine && resolvedCallLine <= f.endLine);
      for (const fn of enclosingFns) {
        if (qualParamRegex.test(fn.paramsText)) {
          return null; // 反例 A: review(Auth, user)
        }
        for (let k = fn.startLine - 1; k < fn.endLine; k++) {
          if (k >= classRecord.startLine - 1 && k < classRecord.endLine) continue;
          if (checkVariableBinding(cleanLines[k], escapedQual)) {
            return null; // 反例 2: 區域 const Auth
          }
          if (reassignmentRegex.test(cleanLines[k])) {
            return null;
          }
        }
      }
      if (enclosingFns.length === 0) {
        for (let k = 0; k < cleanLines.length; k++) {
          if (k >= classRecord.startLine - 1 && k < classRecord.endLine) continue;
          if (checkVariableBinding(cleanLines[k], escapedQual) || reassignmentRegex.test(cleanLines[k])) {
            return null;
          }
        }
      }
    } else {
      if (functions.some(f => qualParamRegex.test(f.paramsText))) {
        return null;
      }
      for (let k = 0; k < cleanLines.length; k++) {
        if (k >= classRecord.startLine - 1 && k < classRecord.endLine) continue;
        if (checkVariableBinding(cleanLines[k], escapedQual) || reassignmentRegex.test(cleanLines[k])) {
          return null;
        }
      }
    }

    return qualifier;
  }

  // 2. Instance Receiver Calls: Strict Flat-Scope Whitelist & Default-Deny
  // Invariant 1: Reject if any let or var binds qualifier anywhere
  for (let i = 0; i < cleanLines.length; i++) {
    const bound = checkVariableBinding(cleanLines[i], escapedQual);
    if (bound && (bound.kind === "let" || bound.kind === "var")) {
      return null;
    }
  }

  // Invariant 2: Reject if any reassignment or mutation of qualifier exists anywhere
  const assignRegex = new RegExp(`(?:^|[^a-zA-Z0-9_$.])${escapedQual}\\s*(?:=(?!=)|\\+=|-=|\\*=|\\/=|%=|\\+\\+|--)`);
  const prefixIncDecRegex = new RegExp(`(?:\\+\\+|--)\\s*${escapedQual}\\b`);
  const destructuringAssignRegex = new RegExp(`(?:\\{[^}]*\\b${escapedQual}\\b[^}]*\\}|\\[[^\\]]*\\b${escapedQual}\\b[^\\]]*\\])\\s*=(?!=)`);
  const forLoopAssignRegex = new RegExp(`\\bfor\\s*\\([^)]*\\b${escapedQual}\\b\\s+(?:of|in)\\b`);

  for (let i = 0; i < cleanLines.length; i++) {
    const cl = cleanLines[i];
    if (prefixIncDecRegex.test(cl) || destructuringAssignRegex.test(cl) || forLoopAssignRegex.test(cl)) {
      return null;
    }
    if (assignRegex.test(cl)) {
      // Must strictly be the allowed `const qualifier = new Class(...)`
      const constMatch = cl.match(new RegExp(`(?:^|[^a-zA-Z0-9_$])const\\s+${escapedQual}\\s*=\\s*new\\s+`));
      if (!constMatch) {
        return null;
      }
    }
  }

  // Invariant 3: Must have EXACTLY ONE const declaration binding qualifier, which must be `const qualifier = new ClassName(...)`
  const constBindings = [];
  for (let i = 0; i < cleanLines.length; i++) {
    const bound = checkVariableBinding(cleanLines[i], escapedQual);
    if (bound && bound.kind === "const") {
      constBindings.push({ lineIdx: i, pattern: bound.pattern });
    }
  }
  if (constBindings.length !== 1) {
    return null;
  }
  if (constBindings[0].pattern !== qualifier) {
    return null; // was a destructuring const like { auth } or [auth]
  }

  const declIdx = constBindings[0].lineIdx;
  const declLine = declIdx + 1;
  const instRegex = new RegExp(`(?:^|[^a-zA-Z0-9_$])const\\s+${escapedQual}\\s*=\\s*new\\s+([A-Za-z0-9_$]+)\\s*\\(`);
  const instMatch = cleanLines[declIdx].match(instRegex);
  if (!instMatch || !instMatch[1]) {
    return null;
  }
  const boundClass = instMatch[1];
  const qualPascal = qualifier.charAt(0).toUpperCase() + qualifier.slice(1);
  if (boundClass !== qualPascal) {
    return null;
  }

  const boundClassRecord = classes.find(c => c.name === boundClass);
  if (!boundClassRecord) {
    return null;
  }

  // Verify boundClass has instance method (non-static) matching symbol directly in class body
  const instMethodRegex = new RegExp(`^\\s*(?:async\\s+)?(?:\\*\\s*)?${escapedSym}\\s*(?:<[^()]+>\\s*)?\\(`);
  let classHasInstanceMethod = false;
  for (let j = boundClassRecord.braceLineIdx + 1; j < boundClassRecord.endLine - 1; j++) {
    const cLine = cleanLines[j];
    if (/^\s*static\b/.test(cLine)) continue;
    if (instMethodRegex.test(cLine)) {
      if (isMethodDirectInClass(cleanLines, boundClassRecord, j, classes, functions)) {
        classHasInstanceMethod = true;
        break;
      }
    }
  }
  if (!classHasInstanceMethod) {
    return null;
  }

  // Determine callLine
  let resolvedCallLine = targetLine;
  if (!resolvedCallLine) {
    const callRegex = new RegExp(`(?:^|[^a-zA-Z0-9_$])${escapedQual}(?:\\.|\\?\\.)${escapedSym}\\s*(?:<[^()]+>\\s*)?(?:\\?\\.\\s*)?\\(`);
    for (let idx = 0; idx < cleanLines.length; idx++) {
      if (callRegex.test(cleanLines[idx])) {
        resolvedCallLine = idx + 1;
        break;
      }
    }
  }
  if (!resolvedCallLine) {
    return null;
  }
  if (declLine >= resolvedCallLine) {
    return null;
  }

  // Invariant 4: Arrow function prohibition
  if (cleanLines[resolvedCallLine - 1].includes("=>")) {
    return null;
  }
  if (resolvedCallLine > 1 && cleanLines[resolvedCallLine - 2].includes("=>") && !cleanLines[resolvedCallLine - 2].includes("{")) {
    return null;
  }
  const arrowParamRegex = new RegExp(`(?:\\([^)]*\\b${escapedQual}\\b[^)]*\\)|\\b${escapedQual}\\b)\\s*=>`);
  if (cleanLines.some(l => arrowParamRegex.test(l))) {
    return null;
  }
  for (let i = 0; i < cleanLines.length; i++) {
    if (/=>\s*\{/.test(cleanLines[i])) {
      const idx = cleanLines[i].indexOf("{");
      const endLine = findBraceScopeEnd(lines, i, { failClosed: true, startCharIndex: idx >= 0 ? idx : 0 });
      if (endLine !== -1 && i + 1 <= resolvedCallLine && resolvedCallLine <= endLine) {
        return null;
      }
    }
  }

  // Invariant 5: Catch block prohibition
  const catchParamRegex = new RegExp(`\\bcatch\\s*\\([^)]*\\b${escapedQual}\\b[^)]*\\)`);
  if (cleanLines.some(l => catchParamRegex.test(l))) {
    return null;
  }
  for (let i = 0; i < cleanLines.length; i++) {
    if (/\bcatch\b/.test(cleanLines[i])) {
      let braceIdx = -1;
      for (let k = i; k < Math.min(cleanLines.length, i + 3); k++) {
        const cIdx = cleanLines[k].indexOf("{");
        if (cIdx !== -1) {
          braceIdx = k;
          const endLine = findBraceScopeEnd(lines, braceIdx, { failClosed: true, startCharIndex: cIdx });
          if (endLine !== -1 && braceIdx + 1 <= resolvedCallLine && resolvedCallLine <= endLine) {
            return null;
          }
          break;
        }
      }
    }
  }

  // Helper: check if a line is inside an inner block
  function isLineInInnerBlock(lineNum) {
    const currLine = cleanLines[lineNum - 1] || "";
    if (/^\s*(?:if|for|while|switch|try|catch|else|do)\b/.test(currLine)) {
      return true;
    }
    if (lineNum > 1) {
      const prevLine = cleanLines[lineNum - 2] || "";
      if (/^\s*(?:if|for|while|else)\b/.test(prevLine) && !prevLine.includes("{") && !prevLine.includes(";")) {
        return true;
      }
    }
    for (let k = 0; k < cleanLines.length; k++) {
      const line = cleanLines[k];
      for (let c = 0; c < line.length; c++) {
        if (line[c] === "{") {
          const isClassBody = classes.some(cls => cls.braceLineIdx === k && cls.braceCharIdx === c);
          const isFnBody = functions.some(fn => fn.bodyLineIdx === k && fn.bodyCharIdx === c);
          const isFnParam = functions.some(fn => fn.startLine <= k + 1 && k + 1 <= fn.bodyLineIdx + 1 && (k < fn.bodyLineIdx || c < fn.bodyCharIdx));
          if (!isClassBody && !isFnBody && !isFnParam) {
            const endLine = findBraceScopeEnd(lines, k, { failClosed: true, startCharIndex: c });
            if (endLine !== -1) {
              if (k + 1 < lineNum && lineNum <= endLine) {
                return true;
              }
              if (k + 1 === lineNum && c < (line.indexOf(qualifier) !== -1 ? line.indexOf(qualifier) : line.length)) {
                return true;
              }
            }
          }
        }
      }
    }
    return false;
  }

  // Invariant 6: Neither declLine nor resolvedCallLine can be inside an inner block
  if (isLineInInnerBlock(declLine) || isLineInInnerBlock(resolvedCallLine)) {
    return null;
  }

  // Invariant 7: Nested closure prohibition
  const enclosingFns = functions.filter(f => f.startLine <= resolvedCallLine && resolvedCallLine <= f.endLine);
  if (enclosingFns.length > 1) {
    return null; // nested closure
  }

  const callFn = enclosingFns.length === 1 ? enclosingFns[0] : null;

  if (callFn) {
    // Invariant 8: Parameter shadowing in enclosing function
    const qualParamRegex = new RegExp(`(?:^|[^a-zA-Z0-9_$])${escapedQual}(?:$|[^a-zA-Z0-9_$])`);
    if (qualParamRegex.test(callFn.paramsText)) {
      return null;
    }

    // Check declLine location relative to callFn
    const declInCallFn = (callFn.startLine <= declLine && declLine <= callFn.endLine);
    if (!declInCallFn) {
      if (functions.some(f => f.startLine <= declLine && declLine <= f.endLine)) {
        return null; // in another function
      }
      if (classes.some(c => c.startLine <= declLine && declLine <= c.endLine)) {
        return null; // in class
      }
    }
  } else {
    // resolvedCallLine is at top-level module scope
    if (classes.some(c => c.startLine <= resolvedCallLine && resolvedCallLine <= c.endLine)) {
      return null;
    }
    if (functions.some(f => f.startLine <= declLine && declLine <= f.endLine)) {
      return null;
    }
    if (classes.some(c => c.startLine <= declLine && declLine <= c.endLine)) {
      return null;
    }
  }

  return boundClass;
}

/**
 * Finds candidate definition line ranges for a qualified symbol (e.g. auth.validateAccess, Class::method).
 * Follows Route B minimal whitelist and strict default-deny (RFC-027-01):
 * - PascalCase calls only match explicit static class methods without receiver shadowing.
 * - Explicit C++ scope definitions match Class::symbol.
 * - Flat-scope instance calls match only unique unambiguous const qualifier = new Class() bindings.
 * - JavaScript prototype assignments (Class.prototype.method = ...) and direct property assignments
 *   (auth.authorize = ...) do NOT constitute trusted Receiver identity in security verification mode
 *   (failing closed to EXTERNAL_CALLEE_UNRESOLVED) to eliminate false cleans caused by Prototype/Static
 *   confusion (Auth.authorize calling Auth.prototype.authorize), conditional execution (if (false)),
 *   uncalled closures, or overwritten assignments.
 *   These are preserved solely for optional candidateSearchOnly mode.
 * - Anything else rejects fail-closed with [].
 *
 * @param {string[]} lines
 * @param {string} qualifier
 * @param {string} symbol
 * @param {object|number} [options]
 * @returns {Array<{ startLine: number, endLine: number }>}
 */
export function findQualifiedFunctionDefinitions(lines, qualifier, symbol, options = {}) {
  if (!qualifier || !symbol || !Array.isArray(lines)) return [];
  const matches = [];
  const escapedSym = symbol.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const escapedQual = qualifier.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const isPascal = /^[A-Z]/.test(qualifier);

  const commentRef = { val: false, inTemplate: false, templateDepths: [] };
  const cleanLines = lines.map(line => stripCommentsAndStrings(line, commentRef));

  const classes = collectClasses(cleanLines, lines);
  const functions = collectFunctions(cleanLines, lines);

  const targetLine = typeof options === "number" ? options : (options && typeof options.callLine === "number" ? options.callLine : null);
  const candidateSearchOnly = Boolean(options && options.candidateSearchOnly);

  // 1. Explicit C++ scope definitions: Class::method(...)
  const CPP_SCOPE_DEF_REGEX = new RegExp(
    `^(?:\\s*(?:[a-zA-Z0-9_<>*&]|::)+\\s+)+${escapedQual}::${escapedSym}\\s*(?:<[^()]+>\\s*)?\\(`
  );

  for (let i = 0; i < cleanLines.length; i++) {
    const cleanLine = cleanLines[i];
    if (CPP_SCOPE_DEF_REGEX.test(cleanLine)) {
      let qualBraceIdx = -1;
      for (let k = i; k < Math.min(cleanLines.length, i + 5); k++) {
        if (cleanLines[k].includes("{")) {
          qualBraceIdx = k;
          break;
        }
        if (cleanLines[k].includes(";")) break;
      }
      if (qualBraceIdx !== -1) {
        const endLine = findBraceScopeEnd(lines, qualBraceIdx, { failClosed: true });
        if (endLine !== -1 && endLine >= i + 1) {
          matches.push({ startLine: i + 1, endLine });
          if (endLine > i + 1) i = endLine - 1;
        }
      }
    }
  }

  // 2. JavaScript prototype and direct property assignments:
  // - Class.prototype.method = ...
  // - auth.authorize = ...
  // Preserved for candidate search (e.g. candidateSearchOnly mode).
  // In security verification mode (default), neither JavaScript prototype assignments nor
  // ad-hoc direct property assignments provide trusted Receiver identity proof
  // (failing closed to EXTERNAL_CALLEE_UNRESOLVED) to eliminate false cleans caused by
  // Prototype/Static confusion (Auth.authorize calling Auth.prototype.authorize),
  // conditional branches (if (false)), uncalled closures, or overwritten assignments.
  const JS_PROTO_OR_PROP_DEF_REGEX = new RegExp(
    `(?:` +
    `^\\s*(?:export\\s+)?(?:const|let|var)?\\s*${escapedQual}\\.prototype\\.${escapedSym}\\s*=\\s*|` +
    `^\\s*(?:export\\s+)?(?:const|let|var)?\\s*${escapedQual}\\.${escapedSym}\\s*=\\s*` +
    `)`
  );

  if (candidateSearchOnly) {
    for (let i = 0; i < cleanLines.length; i++) {
      const cleanLine = cleanLines[i];
      if (JS_PROTO_OR_PROP_DEF_REGEX.test(cleanLine)) {
        let qualBraceIdx = -1;
        for (let k = i; k < Math.min(cleanLines.length, i + 5); k++) {
          if (cleanLines[k].includes("{")) {
            qualBraceIdx = k;
            break;
          }
          if (cleanLines[k].includes(";")) break;
        }
        if (qualBraceIdx !== -1) {
          const endLine = findBraceScopeEnd(lines, qualBraceIdx, { failClosed: true });
          if (endLine !== -1 && endLine >= i + 1) {
            matches.push({ startLine: i + 1, endLine });
            if (endLine > i + 1) i = endLine - 1;
          }
        }
      }
    }
  }

  if (matches.length > 0) {
    return matches;
  }

  // 3. Class method matching via resolveReceiverLexicalBinding
  const boundClassName = resolveReceiverLexicalBinding(lines, qualifier, symbol, targetLine, { cleanLines, classes, functions });

  if (boundClassName) {
    const escapedBoundClass = boundClassName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const CLASS_REGEX = new RegExp(`^\\s*(?:export\\s+)?(?:default\\s+)?class\\s+${escapedBoundClass}\\b`);

    for (let i = 0; i < cleanLines.length; i++) {
      const cleanLine = cleanLines[i];
      if (CLASS_REGEX.test(cleanLine)) {
        let classBraceIdx = -1;
        for (let k = i; k < Math.min(cleanLines.length, i + 5); k++) {
          if (cleanLines[k].includes("{")) {
            classBraceIdx = k;
            break;
          }
          if (cleanLines[k].includes(";")) break;
        }
        if (classBraceIdx !== -1) {
          const classEndLine = findBraceScopeEnd(lines, classBraceIdx, { failClosed: true });
          if (classEndLine !== -1 && classEndLine > classBraceIdx + 1) {
            const classRecord = classes.find(c => c.name === boundClassName && c.braceLineIdx === classBraceIdx) || {
              name: boundClassName,
              startLine: i + 1,
              braceLineIdx: classBraceIdx,
              braceCharIdx: cleanLines[classBraceIdx].indexOf("{"),
              endLine: classEndLine
            };
            const METHOD_REGEX = isPascal
              ? new RegExp(`^\\s*static\\s+(?:async\\s+)?(?:\\*\\s*)?${escapedSym}\\s*(?:<[^()]+>\\s*)?\\(`)
              : new RegExp(`^\\s*(?:async\\s+)?(?:\\*\\s*)?${escapedSym}\\s*(?:<[^()]+>\\s*)?\\(`);
            for (let j = classBraceIdx + 1; j < classEndLine - 1; j++) {
              const methodCleanLine = cleanLines[j];
              if (!isPascal && /^\s*static\b/.test(methodCleanLine)) {
                continue; // instance calls do not bind static methods
              }
              if (METHOD_REGEX.test(methodCleanLine)) {
                if (!isMethodDirectInClass(cleanLines, classRecord, j, classes, functions)) {
                  continue; // skip methods in nested classes, nested functions, or inner blocks
                }
                let methodBraceIdx = -1;
                for (let m = j; m < Math.min(classEndLine - 1, j + 5); m++) {
                  if (cleanLines[m].includes("{")) {
                    methodBraceIdx = m;
                    break;
                  }
                  if (cleanLines[m].includes(";")) break;
                }
                if (methodBraceIdx !== -1) {
                  const methodEndLine = findBraceScopeEnd(lines, methodBraceIdx, { failClosed: true });
                  if (methodEndLine !== -1 && methodEndLine >= j + 1 && methodEndLine <= classEndLine) {
                    matches.push({ startLine: j + 1, endLine: methodEndLine });
                    if (methodEndLine > j + 1) j = methodEndLine - 1;
                  }
                }
              }
            }
            i = classEndLine - 1;
            continue;
          }
        }
      }
    }
  }

  return matches;
}

/**
 * Classifies a token or text fragment into a sensitive category according to RFC-027-01.
 * Evaluates default_values ahead of input_validation to ensure default-handling macros
 * and routines (such as CHECK_MAP_DEFAULT or isMapValueDefault) receive appropriate prioritization.
 *
 * @param {string} text
 * @returns {"default_values" | "input_validation" | "error_handling" | "security" | null}
 */
export function classifySensitiveCategory(text) {
  if (!text || typeof text !== "string") return null;

  const normalized = text.replace(/([a-z0-9])([A-Z])/g, "$1_$2");

  const DEFAULT_REGEX = /(?:^|_|\b)(?:default|fallback|isMapValueDefault|missing|absent|zero|optional)\w*/gi;
  if (DEFAULT_REGEX.test(normalized)) {
    return "default_values";
  }

  const REMAINING_PATTERNS = [
    { category: "input_validation", regex: /(?:^|_|\b)(?:valid|check|assert|verify|sanitize|parse|bounds?|range|empty|null|param|limit)\w*/gi },
    { category: "error_handling", regex: /(?:^|_|\b)(?:handle|error|err|fail|throw|catch|reject|abort|except|status|try|drop)\w*/gi },
    { category: "security", regex: /(?:^|_|\b)(?:auth|permit|permiss|allow|deny|token|secret|privilege|guard|secure|policy|enforce|rbac|acl|role|access)\w*/gi }
  ];

  let earliestPos = Infinity;
  let bestCategory = null;

  for (const { category, regex } of REMAINING_PATTERNS) {
    regex.lastIndex = 0;
    const match = regex.exec(normalized);
    if (match && match.index < earliestPos) {
      earliestPos = match.index;
      bestCategory = category;
    }
  }

  return bestCategory;
}

/**
 * Strips comments and string literals from a line of source code, tracking multi-line comment state.
 * @param {string} line
 * @param {{ val: boolean }} inBlockCommentRef
 * @returns {string}
 */
export function stripCommentsAndStrings(line, inBlockCommentRef = { val: false }) {
  const tRef = inBlockCommentRef && typeof inBlockCommentRef === "object" ? inBlockCommentRef : null;
  let inString = Boolean(tRef?.inTemplate);
  let quote = tRef?.inTemplate ? "`" : null;
  const templateDepths = Array.isArray(tRef?.templateDepths) ? [...tRef.templateDepths] : [];
  let result = "";
  let i = 0;

  if (inBlockCommentRef?.val) {
    const endIdx = line.indexOf("*/");
    if (endIdx !== -1) {
      inBlockCommentRef.val = false;
      i = endIdx + 2;
    } else {
      if (tRef) {
        tRef.inTemplate = Boolean(inString && quote === "`");
        tRef.templateDepths = templateDepths;
      }
      return "";
    }
  }

  if (/^\s*\*/.test(line)) {
    if (line.includes("*/")) {
      if (inBlockCommentRef) inBlockCommentRef.val = false;
      const endIdx = line.indexOf("*/");
      i = endIdx + 2;
    } else {
      if (tRef) {
        tRef.inTemplate = Boolean(inString && quote === "`");
        tRef.templateDepths = templateDepths;
      }
      return "";
    }
  }

  for (; i < line.length; i++) {
    const ch = line[i];
    const nextCh = i + 1 < line.length ? line[i + 1] : "";
    if (inString) {
      if (ch === "\\" && i + 1 < line.length) {
        i++;
        continue;
      }
      if (quote === "`" && ch === "$" && nextCh === "{") {
        templateDepths.push(1);
        inString = false;
        quote = null;
        i++;
        result += " ";
        continue;
      }
      if (ch === quote) {
        inString = false;
        quote = null;
      }
      continue;
    }

    if (templateDepths.length > 0) {
      if (ch === "{") {
        templateDepths[templateDepths.length - 1]++;
      } else if (ch === "}") {
        templateDepths[templateDepths.length - 1]--;
        if (templateDepths[templateDepths.length - 1] === 0) {
          templateDepths.pop();
          inString = true;
          quote = "`";
          result += " ";
          continue;
        }
      }
    }

    if (ch === "/" && nextCh === "/") break;
    if (ch === "/" && nextCh === "*") {
      const closeIdx = line.indexOf("*/", i + 2);
      if (closeIdx !== -1) {
        i = closeIdx + 1;
        continue;
      } else {
        if (inBlockCommentRef) inBlockCommentRef.val = true;
        break;
      }
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      inString = true;
      quote = ch;
      continue;
    }
    if (ch === "/" && nextCh !== "/" && nextCh !== "*") {
      let k = i - 1;
      while (k >= 0 && /\s/.test(line[k])) {
        k--;
      }
      const prevNonWs = k >= 0 ? line[k] : null;

      let isDivision = false;
      if (prevNonWs === ")" || prevNonWs === "]" || prevNonWs === "}") {
        isDivision = true;
      } else if (prevNonWs && /[a-zA-Z0-9_$]/.test(prevNonWs)) {
        let wStart = k;
        while (wStart >= 0 && /[a-zA-Z0-9_$]/.test(line[wStart])) {
          wStart--;
        }
        const prevWord = line.slice(wStart + 1, k + 1);
        const isRegexKeyword = /^(?:return|yield|case|throw|delete|typeof|void|await|in|instanceof|new|else|do)$/.test(prevWord);
        if (!isRegexKeyword) {
          isDivision = true;
        }
      }

      if (!isDivision && (prevNonWs === null || /^[=([{:;,?!&|+*^%~<>-]$/.test(prevNonWs) || (i === 0))) {
        let j = i + 1;
        let inCharClass = false;
        let foundEnd = false;
        while (j < line.length) {
          if (line[j] === "\\") {
            j += 2;
            continue;
          }
          if (line[j] === "[" && !inCharClass) {
            inCharClass = true;
            j++;
            continue;
          }
          if (line[j] === "]" && inCharClass) {
            inCharClass = false;
            j++;
            continue;
          }
          if (line[j] === "/" && !inCharClass) {
            foundEnd = true;
            break;
          }
          if (line[j] === ";") break;
          j++;
        }
        if (foundEnd) {
          i = j;
          continue;
        }
      }
    }
    result += ch;
  }
  if (tRef) {
    tRef.inTemplate = Boolean(inString && quote === "`");
    tRef.templateDepths = templateDepths;
  }
  return result;
}

export const BUILTIN_OBJECT_METHODS = new Set([
  "push", "pop", "shift", "unshift", "slice", "splice", "concat",
  "map", "filter", "reduce", "reduceRight", "forEach", "every", "some",
  "find", "findIndex", "findLast", "findLastIndex", "flat", "flatMap",
  "includes", "indexOf", "lastIndexOf", "join", "sort", "reverse", "fill",
  "has", "get", "set", "add", "delete", "clear", "keys", "values", "entries",
  "toString", "valueOf", "toJSON", "trim", "trimStart", "trimEnd",
  "split", "replace", "replaceAll", "startsWith", "endsWith", "substring",
  "toLowerCase", "toUpperCase", "match", "matchAll", "search", "test", "exec",
  "then", "catch", "finally", "bind", "call", "apply"
]);

export const UTILITY_CALLEE_SYMBOLS = new Set([
  "deepFreeze",
  "cloneDeep",
  "normalizeDigest",
  "normalizeCommitSha",
  "normalizeObjective",
  "normalizeObjectiveContract",
  "normalizeReceiptUsage",
  "normalizeActualModel",
  "digestChangeSet",
  "computeDigest",
  "canonicalJsonStringify",
  "truncateUtf8Safe",
  "formatContextPackageXml",
  "formatChecklistsXml",
  "escapeXmlAttribute",
  "escapeXmlText",
  "createHash",
  "resolve",
  "join",
  "dirname",
  "basename",
  "extname",
  "verifyHeldOutBaseline",
  "push",
  "includes"
]);

/**
 * Scans a line of code for function call invocations, supporting both standard calls
 * and conservative generic type arguments (e.g. auth.authorize<Session>(user), authorizeUser<Session>(user)).
 *
 * @param {string} cleanLine
 * @returns {Array<{ sym: string, index: number, hasTypeArguments: boolean }>}
 */
export function findCallInvocations(cleanLine) {
  if (!cleanLine || typeof cleanLine !== "string") return [];
  const calls = [];
  const IDENT_REGEX = /\b([a-zA-Z_][a-zA-Z0-9_]*)/g;
  let m;
  while ((m = IDENT_REGEX.exec(cleanLine)) !== null) {
    const sym = m[1];
    const symIndex = m.index;
    let pos = symIndex + sym.length;

    while (pos < cleanLine.length && /\s/.test(cleanLine[pos])) pos++;

    if (cleanLine.slice(pos, pos + 2) === "?.") {
      pos += 2;
      while (pos < cleanLine.length && /\s/.test(cleanLine[pos])) pos++;
    }

    let hasTypeArguments = false;
    if (cleanLine[pos] === "<") {
      let depth = 0;
      let braceDepth = 0;
      let parenDepth = 0;
      let bracketDepth = 0;
      let valid = true;
      let endIdx = -1;
      for (let k = pos; k < cleanLine.length; k++) {
        const ch = cleanLine[k];
        if (ch === "<") {
          depth++;
        } else if (ch === ">") {
          depth--;
          if (depth === 0) {
            endIdx = k + 1;
            break;
          }
        } else if (ch === "{") {
          braceDepth++;
        } else if (ch === "}") {
          braceDepth--;
          if (braceDepth < 0) { valid = false; break; }
        } else if (ch === "(") {
          parenDepth++;
        } else if (ch === ")") {
          parenDepth--;
          if (parenDepth < 0) { valid = false; break; }
        } else if (ch === "[") {
          bracketDepth++;
        } else if (ch === "]") {
          bracketDepth--;
          if (bracketDepth < 0) { valid = false; break; }
        } else if (ch === ";") {
          if (braceDepth === 0) {
            valid = false;
            break;
          }
        } else if (ch === "=") {
          if (cleanLine[k + 1] === ">") {
            k++;
            continue;
          }
          valid = false;
          break;
        } else if (ch === "&" && cleanLine[k + 1] === "&") {
          valid = false;
          break;
        } else if (ch === "|" && cleanLine[k + 1] === "|") {
          valid = false;
          break;
        }
      }
      if (valid && depth === 0 && braceDepth === 0 && parenDepth === 0 && bracketDepth === 0 && endIdx !== -1) {
        hasTypeArguments = true;
        pos = endIdx;
        while (pos < cleanLine.length && /\s/.test(cleanLine[pos])) pos++;
      }
    }

    if (cleanLine.slice(pos, pos + 2) === "?.") {
      pos += 2;
      while (pos < cleanLine.length && /\s/.test(cleanLine[pos])) pos++;
    }

    if (cleanLine[pos] === "(") {
      calls.push({
        sym,
        index: symIndex,
        hasTypeArguments
      });
      IDENT_REGEX.lastIndex = pos;
    }
  }
  return calls;
}

/**
 * Extracts candidate function call symbols from diff hunks.
 * Prioritizes added lines over context lines, computes target file line numbers,
 * and excludes language keywords.
 *
 * @param {string} diffHunks
 * @returns {Array<{ symbol: string, isAdded: boolean, line: number, lineText: string, isSensitive: boolean, category: string|null }>}
 */
export function extractCandidateCallSymbols(diffHunks, options = {}) {
  if (!diffHunks || typeof diffHunks !== "string") return [];

  const lines = diffHunks.split(/\r?\n/);
  const candidates = [];
  const seen = new Set();
  const KEYWORDS = new Set([
    "if", "else", "for", "while", "do", "switch", "case", "default", "break", "continue",
    "return", "throw", "try", "catch", "finally", "goto", "function", "async", "await",
    "class", "extends", "super", "this", "import", "export", "from", "require", "typeof",
    "instanceof", "new", "delete", "void", "sizeof", "alignof", "decltype", "typeid",
    "static_cast", "dynamic_cast", "const_cast", "reinterpret_cast", "defined", "template",
    "typename", "explicit", "noexcept", "virtual", "override", "final", "inline", "static",
    "const", "constexpr", "auto", "assert", "static_assert", "int", "char", "bool", "float",
    "double", "long", "short", "unsigned", "signed", "struct", "enum", "union",
    "String", "Boolean", "Number", "Date", "Object", "Array", "Set", "Map", "WeakSet", "WeakMap",
    "Promise", "Symbol", "Buffer", "RegExp", "Error", "TypeError", "RangeError", "SyntaxError",
    "parseInt", "parseFloat", "isNaN", "isFinite", "setTimeout", "clearTimeout", "setInterval",
    "clearInterval", "console", "describe", "it", "test", "expect"
  ]);

  let currentTargetLine = 1;
  const HUNK_HEADER_REGEX = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/;
  const inBlockCommentRef = { val: false, inTemplate: false, templateDepths: [] };
  let currentHunkLexicalUncertain = false;
  let currentHunkHasControlFlow = false;

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];

    const hunkMatch = rawLine.match(HUNK_HEADER_REGEX);
    if (hunkMatch) {
      currentTargetLine = parseInt(hunkMatch[1], 10);
      currentHunkHasControlFlow = false;
      if (options.fileContent && typeof options.fileContent === "string") {
        const fLines = options.fileContent.split(/\r?\n/);
        const preLines = fLines.slice(0, Math.max(0, currentTargetLine - 1));
        const reconRef = { val: false, inTemplate: false, templateDepths: [] };
        for (const pLine of preLines) {
          stripCommentsAndStrings(pLine, reconRef);
        }
        inBlockCommentRef.val = reconRef.val;
        inBlockCommentRef.inTemplate = reconRef.inTemplate;
        inBlockCommentRef.templateDepths = reconRef.templateDepths;
        currentHunkLexicalUncertain = false;
      } else if (currentTargetLine > 1) {
        inBlockCommentRef.val = false;
        inBlockCommentRef.inTemplate = false;
        inBlockCommentRef.templateDepths = [];
        currentHunkLexicalUncertain = true;
      } else {
        inBlockCommentRef.val = false;
        inBlockCommentRef.inTemplate = false;
        inBlockCommentRef.templateDepths = [];
        currentHunkLexicalUncertain = false;
      }
      continue;
    }

    if (rawLine.startsWith("---") || rawLine.startsWith("+++") || rawLine.startsWith("diff ") || rawLine.startsWith("index ")) {
      continue;
    }

    if (rawLine.startsWith("+") || rawLine.startsWith("-")) {
      if (/\b(?:if|else|return|throw|while|for|switch|try|catch|finally|break|continue|guard|assert)\b/.test(rawLine)) {
        currentHunkHasControlFlow = true;
      }
    }

    if (rawLine.startsWith("-")) {
      continue;
    }

    const isAdded = rawLine.startsWith("+");
    const lineText = isAdded ? rawLine.slice(1) : (rawLine.startsWith(" ") ? rawLine.slice(1) : rawLine);
    const lineNum = currentTargetLine;
    currentTargetLine++;

    const cleanLine = stripCommentsAndStrings(lineText, inBlockCommentRef);
    const isGuardLine = /^\s*(?:if\s*\(.*?\)\s*(?:return|throw)\b|assert(?:\.|\s*\()|throw\s+new\b)/.test(cleanLine);
    const lineCategory = isGuardLine ? "input_validation" : null;

    const fnDeclMatch = cleanLine.match(/^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function(?:\s+([a-zA-Z_][a-zA-Z0-9_]*))?(?:\s*<[^()]+>)?\s*\(/);
    const pyDeclMatch = cleanLine.match(/^\s*def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/);
    const declaredFn = fnDeclMatch ? fnDeclMatch[1] : (pyDeclMatch ? pyDeclMatch[1] : null);

    const invokedCalls = findCallInvocations(cleanLine);
    for (const call of invokedCalls) {
      const sym = call.sym;
      if (KEYWORDS.has(sym)) continue;
      if (declaredFn && sym === declaredFn) continue;

      const prefix = cleanLine.slice(0, call.index);
      const isQualified = /(?:\.|\->|\?\.)\s*$/.test(prefix);

      const chainMatch = prefix.match(/(?:(?:[a-zA-Z_][a-zA-Z0-9_]*|this)\s*(?:\.|\->|\?\.)\s*)+$/);
      let qualifier = null;
      let qualifiers = [];
      if (chainMatch) {
        qualifiers = chainMatch[0].match(/[a-zA-Z_][a-zA-Z0-9_]*|this/g) || [];
        qualifier = qualifiers.length > 0 ? qualifiers[qualifiers.length - 1] : null;
      }

      const symCat = classifySensitiveCategory(sym);
      let qualCat = null;
      for (const q of qualifiers) {
        const cat = classifySensitiveCategory(q);
        if (cat) {
          qualCat = cat;
          break;
        }
      }

      if (isQualified && BUILTIN_OBJECT_METHODS.has(sym)) {
        if (!qualCat) {
          continue;
        }
      }
      if (UTILITY_CALLEE_SYMBOLS.has(sym)) {
        continue;
      }

      const sensitiveCategory = symCat || qualCat;

      // For qualified calls, only recognize if sensitive (P1-03)
      if (isQualified && !sensitiveCategory) {
        continue;
      }

      const isSensitive = Boolean(sensitiveCategory || isGuardLine);
      const symCategory = isSensitive ? (sensitiveCategory || lineCategory || "input_validation") : null;

      const receiverKey = isQualified
        ? (qualifiers.length > 0 ? qualifiers.join(".") : (qualifier || "qualified"))
        : "";
      const callKey = receiverKey ? `${receiverKey}.${sym}` : sym;

      if (!seen.has(callKey)) {
        seen.add(callKey);
        candidates.push({
          symbol: sym,
          qualifier,
          qualifiers,
          isQualified,
          isAdded,
          isControlFlowModified: Boolean(currentHunkHasControlFlow),
          lexicalStateUncertain: Boolean(currentHunkLexicalUncertain),
          line: lineNum,
          lineText: lineText.trim(),
          isSensitive,
          category: symCategory,
          hasTypeArguments: Boolean(call.hasTypeArguments)
        });
      } else if (isAdded) {
        const existing = candidates.find(c => {
          const cReceiverKey = c.isQualified
            ? (c.qualifiers?.length > 0 ? c.qualifiers.join(".") : (c.qualifier || "qualified"))
            : "";
          const cCallKey = cReceiverKey ? `${cReceiverKey}.${c.symbol}` : c.symbol;
          return cCallKey === callKey;
        });
        if (existing) {
          if (!existing.isAdded) {
            existing.isAdded = true;
            existing.line = lineNum;
            existing.lineText = lineText.trim();
          }
          if (call.hasTypeArguments && !existing.hasTypeArguments) {
            existing.hasTypeArguments = true;
          }
          if (qualifier && !existing.qualifier) {
            existing.qualifier = qualifier;
          }
          if (qualifiers.length > 0 && (!existing.qualifiers || existing.qualifiers.length === 0)) {
            existing.qualifiers = qualifiers;
          }
          if (isQualified && !existing.isQualified) {
            existing.isQualified = isQualified;
          }
          if (isSensitive && !existing.isSensitive) {
            existing.isSensitive = true;
            existing.category = symCategory;
          }
          if (currentHunkHasControlFlow && !existing.isControlFlowModified) {
            existing.isControlFlowModified = true;
          }
        }
      }
    }

    // Parse call expressions and generic invocations that span across lines
    {
      const trimmedEnd = cleanLine.trimEnd();
      const trailingCallMatch = trimmedEnd.match(/(?:^|[\s=([{:;,?!&|+*^%~<>.-]|(?:\?\.)|(?:\->))(?:((?:(?:[a-zA-Z_][a-zA-Z0-9_]*|this)\s*(?:\.|\->|\?\.)\s*)+))?([a-zA-Z_][a-zA-Z0-9_]*)((?:\s*(?:\?\.\s*)?(?:<(?:=>|[^>])*>?)?(?:\s*\?\.)?(?:\s*\()?)?)$/);
      if (trailingCallMatch) {
        const qualifierChain = trailingCallMatch[1] || "";
        const sym = trailingCallMatch[2];
        const trailingRemainder = (trailingCallMatch[3] || "").trim();

        // Ensure this is not a declaration, keyword, or already matched inline
        const isKeyword = KEYWORDS.has(sym);
        const isDecl = cleanLine.match(/^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+/) ||
          cleanLine.match(/^\s*def\s+/) ||
          cleanLine.match(/^\s*class\s+/) ||
          cleanLine.match(/^\s*(?:type|interface)\s+/);

        if (!isKeyword && !isDecl) {
          const hasLeadingDot = /^\s*(?:\.|\->|\?\.)/.test(cleanLine);
          const isQualified = Boolean(qualifierChain || hasLeadingDot);
          let qualifiers = [];
          let qualifier = null;
          if (qualifierChain) {
            qualifiers = qualifierChain.match(/[a-zA-Z_][a-zA-Z0-9_]*|this/g) || [];
            qualifier = qualifiers.length > 0 ? qualifiers[qualifiers.length - 1] : null;
          }

          const symCat = classifySensitiveCategory(sym);
          let qualCat = null;
          for (const q of qualifiers) {
            const cat = classifySensitiveCategory(q);
            if (cat) {
              qualCat = cat;
              break;
            }
          }

          let skip = false;
          if (isQualified && BUILTIN_OBJECT_METHODS.has(sym)) {
            if (!qualCat) {
              skip = true;
            }
          }
          if (UTILITY_CALLEE_SYMBOLS.has(sym)) {
            skip = true;
          }

          if (!skip) {
            const sensitiveCategory = symCat || qualCat;

            if (!isQualified || sensitiveCategory) {
              let foundCall = false;
              let callHasTypeArguments = Boolean(trailingRemainder && trailingRemainder.includes("<"));
              let isUnterminated = false;
              let accumulatedTail = trailingRemainder;
              let callIsAdded = isAdded;

              // Check if trailingRemainder on current line already completes a call
              const selfCalls = findCallInvocations(sym + " " + accumulatedTail);
              if (selfCalls.some(c => c.sym === sym)) {
                foundCall = true;
                const m = selfCalls.find(c => c.sym === sym);
                callHasTypeArguments = Boolean(m.hasTypeArguments);
              }

              // Look ahead to subsequent lines
              if (!foundCall) {
                for (let next = i + 1; next < lines.length; next++) {
                  const nextRaw = lines[next];
                  if (nextRaw.match(HUNK_HEADER_REGEX) || nextRaw.startsWith("---") || nextRaw.startsWith("+++") || nextRaw.startsWith("diff ") || nextRaw.startsWith("index ")) {
                    break;
                  }
                  if (nextRaw.startsWith("-")) {
                    continue; // deleted line
                  }
                  const isContextOrAdded = nextRaw.startsWith("+") || nextRaw.startsWith(" ");
                  if (!isContextOrAdded) {
                    break;
                  }
                  if (nextRaw.startsWith("+")) {
                    callIsAdded = true;
                  }
                  const nextLineContent = nextRaw.slice(1);
                  const nextClean = stripCommentsAndStrings(nextLineContent, { val: inBlockCommentRef.val }).trim();
                  if (!nextClean) {
                    continue; // blank or comment-only line
                  }

                  accumulatedTail += " " + nextClean;

                  const testExpr = sym + " " + accumulatedTail;
                  const calls = findCallInvocations(testExpr);
                  const matchCall = calls.find(c => c.sym === sym);
                  if (matchCall) {
                    foundCall = true;
                    callHasTypeArguments = Boolean(matchCall.hasTypeArguments);
                    break;
                  }

                  // If not inside an unclosed '<' and we hit a statement boundary ';', stop looking ahead
                  if (!accumulatedTail.includes("<") && nextClean.includes(";")) {
                    break;
                  }
                }
              }

              // Fail-Closed: If sensitive and generic or call was opened across lines but unterminated
              if (!foundCall && sensitiveCategory && (accumulatedTail.includes("<") || trailingRemainder.includes("<") || accumulatedTail.startsWith("(") || trailingRemainder.startsWith("("))) {
                foundCall = true;
                isUnterminated = true;
                callHasTypeArguments = true;
              }

              if (foundCall) {
                const isSensitive = Boolean(sensitiveCategory || isGuardLine);
                const symCategory = isSensitive ? (sensitiveCategory || lineCategory || "input_validation") : null;
                const receiverKey = isQualified
                  ? (qualifiers.length > 0 ? qualifiers.join(".") : (qualifier || "qualified"))
                  : "";
                const callKey = receiverKey ? `${receiverKey}.${sym}` : sym;

                if (!seen.has(callKey)) {
                  seen.add(callKey);
                  candidates.push({
                    symbol: sym,
                    qualifier,
                    qualifiers,
                    isQualified,
                    isAdded: Boolean(callIsAdded),
                    isControlFlowModified: Boolean(currentHunkHasControlFlow),
                    lexicalStateUncertain: Boolean(currentHunkLexicalUncertain),
                    line: lineNum,
                    lineText: lineText.trim(),
                    isSensitive,
                    category: symCategory,
                    hasTypeArguments: Boolean(callHasTypeArguments),
                    isUnterminated: Boolean(isUnterminated)
                  });
                } else if (callIsAdded) {
                  const existing = candidates.find(c => {
                    const cReceiverKey = c.isQualified
                      ? (c.qualifiers?.length > 0 ? c.qualifiers.join(".") : (c.qualifier || "qualified"))
                      : "";
                    const cCallKey = cReceiverKey ? `${cReceiverKey}.${c.symbol}` : c.symbol;
                    return cCallKey === callKey;
                  });
                  if (existing) {
                    if (!existing.isAdded) {
                      existing.isAdded = true;
                      existing.line = lineNum;
                      existing.lineText = lineText.trim();
                    }
                    if (callHasTypeArguments && !existing.hasTypeArguments) {
                      existing.hasTypeArguments = true;
                    }
                    if (isUnterminated && !existing.isUnterminated) {
                      existing.isUnterminated = true;
                    }
                    if (qualifier && !existing.qualifier) {
                      existing.qualifier = qualifier;
                    }
                    if (qualifiers.length > 0 && (!existing.qualifiers || existing.qualifiers.length === 0)) {
                      existing.qualifiers = qualifiers;
                    }
                    if (isQualified && !existing.isQualified) {
                      existing.isQualified = isQualified;
                    }
                    if (isSensitive && !existing.isSensitive) {
                      existing.isSensitive = true;
                      existing.category = symCategory;
                    }
                    if (currentHunkHasControlFlow && !existing.isControlFlowModified) {
                      existing.isControlFlowModified = true;
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }

  candidates.sort((a, b) => {
    if (a.isSensitive && !b.isSensitive) return -1;
    if (!a.isSensitive && b.isSensitive) return 1;
    if (a.isAdded && !b.isAdded) return -1;
    if (!a.isAdded && b.isAdded) return 1;
    return a.line - b.line;
  });

  return candidates;
}

/**
 * Locates and bounds a function definition in source text.
 * Short functions (<= 30 lines): complete body (max 2,000 bytes).
 * Long functions (> 30 lines): signature + preconditions + early returns + closing brace
 * (max 60 lines / 2,000 bytes).
 *
 * @param {string[]} lines
 * @param {number} startLine 1-indexed
 * @param {number} endLine 1-indexed
 * @returns {{ definition: string, lines: number, bytes: number, extractionMode: string }}
 */
export function extractBoundedFunctionSnippet(lines, startLine, endLine) {
  if (!Array.isArray(lines) || startLine < 1 || endLine < startLine) {
    return {
      definition: "",
      lines: 0,
      bytes: 0,
      extractionMode: "incomplete"
    };
  }

  // Verify that the function boundary is confirmed and closed
  let isClosed = false;
  const startLineText = lines[startLine - 1] || "";
  const isPythonDef = /^\s*(?:async\s+)?def\s+[a-zA-Z0-9_$]+\s*\(/.test(startLineText);

  if (isPythonDef) {
    const verifiedEnd = findPythonScopeEnd(lines, startLine - 1);
    if (verifiedEnd !== -1 && verifiedEnd === endLine) {
      isClosed = true;
    }
  } else {
    let braceLineIdx = -1;
    let bodyBraceIdx = 0;
    let parenClosed = false;
    let parenDepth = 0;
    for (let j = startLine - 1; j < Math.min(lines.length, startLine + 15); j++) {
      const scanLine = lines[j];
      if (!parenClosed) {
        for (let k = 0; k < scanLine.length; k++) {
          const ch = scanLine[k];
          if (ch === "(") parenDepth++;
          else if (ch === ")") {
            parenDepth--;
            if (parenDepth <= 0) {
              parenClosed = true;
              let searchFrom = k + 1;
              let foundBraceIdx = -1;
              while (searchFrom < scanLine.length) {
                const bIdx = scanLine.indexOf("{", searchFrom);
                if (bIdx === -1) break;
                const closeIdx = scanLine.indexOf("}", bIdx + 1);
                const nextOpenIdx = scanLine.indexOf("{", bIdx + 1);
                if (closeIdx !== -1 && (nextOpenIdx === -1 || closeIdx < nextOpenIdx)) {
                  const subsequentOpen = scanLine.indexOf("{", closeIdx + 1);
                  if (subsequentOpen !== -1) {
                    searchFrom = subsequentOpen;
                    continue;
                  }
                }
                foundBraceIdx = bIdx;
                break;
              }
              if (foundBraceIdx !== -1) {
                braceLineIdx = j;
                bodyBraceIdx = foundBraceIdx;
              }
              break;
            }
          }
        }
        if (braceLineIdx !== -1) break;
      } else {
        const idx = scanLine.indexOf("{");
        if (idx !== -1) {
          braceLineIdx = j;
          bodyBraceIdx = idx;
          break;
        }
      }
    }

    if (braceLineIdx === -1) {
      for (let j = startLine - 1; j < Math.min(lines.length, startLine + 15); j++) {
        const idx = lines[j].indexOf("{");
        if (idx !== -1) {
          braceLineIdx = j;
          bodyBraceIdx = idx;
          break;
        }
      }
    }

    if (braceLineIdx !== -1) {
      const verifiedEnd = findBraceScopeEnd(lines, braceLineIdx, { failClosed: true, startCharIndex: bodyBraceIdx });
      if (verifiedEnd !== -1 && verifiedEnd === endLine) {
        isClosed = true;
      }
    }

    if (isClosed) {
      const endLineText = lines[endLine - 1] || "";
      const cleanEndLine = stripCommentsAndStrings(endLineText).trim();
      const lastBraceIdx = cleanEndLine.lastIndexOf("}");
      if (lastBraceIdx === -1) {
        isClosed = false;
      } else {
        const trailing = cleanEndLine.slice(lastBraceIdx + 1).trim();
        if (trailing && !/^[;,)}\]]*$/.test(trailing)) {
          isClosed = false;
        }
      }
    }
  }

  if (!isClosed) {
    const extractedLines = lines.slice(startLine - 1, Math.min(endLine, lines.length));
    const truncated = extractedLines.join("\n");
    return {
      definition: truncated,
      lines: extractedLines.length,
      bytes: Buffer.byteLength(truncated, "utf8"),
      extractionMode: "incomplete"
    };
  }

  const lineCount = endLine - startLine + 1;

  if (lineCount <= 30) {
    const fullBody = lines.slice(startLine - 1, endLine).join("\n");
    const buf = Buffer.from(fullBody, "utf8");
    if (buf.length <= MAX_SNIPPET_BYTES) {
      return {
        definition: fullBody,
        lines: lineCount,
        bytes: buf.length,
        extractionMode: "full_body"
      };
    }
  }

  const extracted = [];
  let headerEnded = false;
  const GUARD_REGEX = /\b(?:if\s*\(.*?\)\s*(?:return|throw)\b|\breturn\b|\bthrow\b|\braise\b|\bassert\b|isMapValueDefault|\bcheck\b|\bvalidate\b|\bguard\b)/i;

  for (let i = startLine - 1; i < endLine - 1; i++) {
    const l = lines[i];
    if (!headerEnded) {
      extracted.push(l);
      if (isPythonDef ? l.includes(":") : l.includes("{")) headerEnded = true;
      continue;
    }

    if (extracted.length < 25 || GUARD_REGEX.test(l)) {
      extracted.push(l);
    }

    if (extracted.length >= 55) break;
  }

  extracted.push(isPythonDef ? "    # ... [remainder of function body elided for context bounds] ..." : "    /* ... [remainder of function body elided for context bounds] ... */");
  extracted.push(lines[endLine - 1]);

  let finalLines = extracted.slice(0, MAX_SNIPPET_LINES);
  let truncated = finalLines.join("\n");
  let bytes = Buffer.byteLength(truncated, "utf8");

  if (bytes > MAX_SNIPPET_BYTES) {
    const headerLines = [];
    for (const line of finalLines) {
      if (Buffer.byteLength(headerLines.concat([line, isPythonDef ? "    # ... elided ..." : "    /* ... elided ... */", lines[endLine - 1]]).join("\n"), "utf8") < MAX_SNIPPET_BYTES - 50) {
        headerLines.push(line);
      } else {
        break;
      }
    }
    headerLines.push(isPythonDef ? "    # ... [remainder of function body elided for context bounds] ..." : "    /* ... [remainder of function body elided for context bounds] ... */");
    headerLines.push(lines[endLine - 1]);
    finalLines = headerLines;
    truncated = finalLines.join("\n");
    bytes = Buffer.byteLength(truncated, "utf8");

    if (bytes > MAX_SNIPPET_BYTES) {
      const rawBuf = Buffer.from(truncated, "utf8");
      truncated = truncateUtf8Safe(rawBuf, MAX_SNIPPET_BYTES);
      bytes = Buffer.byteLength(truncated, "utf8");
      finalLines = truncated.split("\n");
    }
  }

  return {
    definition: truncated,
    lines: finalLines.length,
    bytes,
    extractionMode: "signature_and_guards"
  };
}

/**
 * Finds macro definitions matching a symbol in source lines (#define symbol ...).
 *
 * @param {string[]} lines
 * @param {string} symbol
 * @returns {Array<{ type: string, startLine: number, endLine: number, snippet: object }>}
 */
export function findMacroDefinitions(lines, symbol) {
  if (!Array.isArray(lines) || !symbol || typeof symbol !== "string") return [];
  const matches = [];
  const escaped = symbol.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const macroRegex = new RegExp(`^\\s*#\\s*define\\s+${escaped}(?:\\(|\\s|$)`);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (macroRegex.test(line)) {
      const startLine = i + 1;
      let cur = i;
      while (cur < lines.length) {
        const l = lines[cur];
        const trimmedEnd = l.trimEnd();
        if (trimmedEnd.endsWith("\\") && cur + 1 < lines.length) {
          cur++;
        } else {
          break;
        }
      }
      const endLine = cur + 1;
      const snippetLines = lines.slice(startLine - 1, endLine);
      const defText = snippetLines.join("\n");
      matches.push({
        type: "macro",
        startLine,
        endLine,
        snippet: {
          definition: defText,
          lines: snippetLines.length,
          bytes: Buffer.byteLength(defText, "utf8"),
          extractionMode: "full_body"
        }
      });
    }
  }
  return matches;
}

/**
 * Finds function declarations / signatures ending in semicolon for a symbol (for headers).
 *
 * @param {string[]} lines
 * @param {string} symbol
 * @returns {Array<{ type: string, startLine: number, endLine: number, snippet: object }>}
 */
export function findFunctionDeclarations(lines, symbol) {
  if (!Array.isArray(lines) || !symbol || typeof symbol !== "string") return [];
  const matches = [];
  const escaped = symbol.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const cleanLines = stripCommentsPreservingLayout(lines);

  const DECL_START = new RegExp(
    `(?:` +
    `^(?:\\s*(?:[a-zA-Z0-9_<>*&]|::)+\\s+)+(?:[a-zA-Z0-9_]+::)?${escaped}\\s*(?:<[^()]+>\\s*)?\\(|` +
    `^\\s*(?:(?:extern|static|virtual|inline)\\s+)+.*\\b${escaped}\\s*(?:<[^()]+>\\s*)?\\(|` +
    `^\\s*declare\\s+function\\s+${escaped}\\s*\\(` +
    `)`
  );

  const CONTROL_START = /^\s*(?:if|while|for|switch|catch|with|return|throw|delete|typeof|sizeof|case|else\s+if)\b/;

  for (let i = 0; i < cleanLines.length; i++) {
    const line = cleanLines[i];
    if (!line.includes(symbol)) continue;
    if (CONTROL_START.test(line)) continue;

    let hasStart = DECL_START.test(line);
    let startIdx = i;
    if (!hasStart && i > 0) {
      for (let prev = i - 1; prev >= Math.max(0, i - 2); prev--) {
        const prefix = cleanLines.slice(prev, i).map(l => l.trim()).join(" ");
        if (prefix && DECL_START.test(`${prefix} ${line.trim()}`)) {
          hasStart = true;
          startIdx = prev;
          break;
        }
      }
    }
    if (!hasStart) continue;

    let foundSemi = false;
    let endIdx = -1;
    let parenDepth = 0;
    let seenOpen = false;

    for (let j = i; j < Math.min(i + 15, cleanLines.length); j++) {
      const scanLine = cleanLines[j];
      const braceIdx = scanLine.indexOf("{");
      const semiIdx = scanLine.indexOf(";");

      if (braceIdx !== -1 && (semiIdx === -1 || braceIdx < semiIdx)) {
        break;
      }

      for (let k = 0; k < scanLine.length; k++) {
        if (scanLine[k] === "(") { parenDepth++; seenOpen = true; }
        else if (scanLine[k] === ")") { if (parenDepth > 0) parenDepth--; }
      }

      const lastSemi = scanLine.lastIndexOf(";");
      const lastCloseParen = scanLine.lastIndexOf(")");
      if (lastSemi !== -1 && seenOpen && parenDepth === 0 && (j > i || lastSemi > lastCloseParen)) {
        foundSemi = true;
        endIdx = j;
        break;
      }
    }

    if (foundSemi && endIdx !== -1) {
      const startLine = startIdx + 1;
      const endLine = endIdx + 1;
      const snippetLines = lines.slice(startLine - 1, endLine);
      const defText = snippetLines.join("\n");
      matches.push({
        type: "signature",
        startLine,
        endLine,
        snippet: {
          definition: defText,
          lines: snippetLines.length,
          bytes: Buffer.byteLength(defText, "utf8"),
          extractionMode: "signature"
        }
      });
    }
  }

  return matches;
}

/**
 * Finds type definitions (struct, class, enum, interface, typedef, type alias) for a symbol.
 *
 * @param {string[]} lines
 * @param {string} symbol
 * @returns {Array<{ type: string, startLine: number, endLine: number, snippet: object }>}
 */
export function findTypeDefinitions(lines, symbol) {
  if (!Array.isArray(lines) || !symbol || typeof symbol !== "string") return [];
  const matches = [];
  const escaped = symbol.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const cleanLines = stripCommentsPreservingLayout(lines);

  const TYPE_DECL = new RegExp(
    `(?:` +
    `^\\s*(?:typedef\\s+)?(?:struct|class|enum|union|interface)\\s+${escaped}\\b|` +
    `^\\s*(?:export\\s+)?(?:default\\s+)?class\\s+${escaped}\\b|` +
    `^\\s*(?:export\\s+)?(?:interface)\\s+${escaped}\\b|` +
    `^\\s*(?:export\\s+)?(?:type)\\s+${escaped}\\s*(?:<[^>]+>)?\\s*=|` +
    `^\\s*typedef\\s+.*\\b${escaped}\\s*;` +
    `)`
  );

  const TYPEDEF_END = new RegExp(`\\}\\s*(?:\\*\\s*)?${escaped}\\s*;`);

  for (let i = 0; i < cleanLines.length; i++) {
    const line = cleanLines[i];
    if (!line.includes(symbol)) continue;

    // Check for typedef struct/enum/union { ... } Symbol;
    if (TYPEDEF_END.test(line)) {
      let startIdx = -1;
      for (let prev = i; prev >= Math.max(0, i - 100); prev--) {
        if (/^\s*typedef\s+(?:struct|union|enum)\b/.test(cleanLines[prev])) {
          startIdx = prev;
          break;
        }
      }
      if (startIdx !== -1) {
        const startLine = startIdx + 1;
        const endLine = i + 1;
        const snippetLines = lines.slice(startLine - 1, endLine);
        const defText = snippetLines.join("\n");
        matches.push({
          type: "type",
          startLine,
          endLine,
          snippet: {
            definition: defText,
            lines: snippetLines.length,
            bytes: Buffer.byteLength(defText, "utf8"),
            extractionMode: "full_body"
          }
        });
        continue;
      }
    }

    if (!TYPE_DECL.test(line)) continue;

    let hasBrace = false;
    let braceLineIdx = -1;
    for (let j = i; j < Math.min(i + 5, cleanLines.length); j++) {
      if (cleanLines[j].includes("{")) {
        hasBrace = true;
        braceLineIdx = j;
        break;
      }
      if (cleanLines[j].includes(";")) {
        break;
      }
    }

    if (hasBrace && braceLineIdx !== -1) {
      const endLine = findBraceScopeEnd(cleanLines, braceLineIdx);
      if (endLine !== -1 && endLine >= i + 1) {
        const startLine = i + 1;
        const snippetLines = lines.slice(startLine - 1, endLine);
        const defText = snippetLines.join("\n");
        matches.push({
          type: "type",
          startLine,
          endLine,
          snippet: {
            definition: defText,
            lines: snippetLines.length,
            bytes: Buffer.byteLength(defText, "utf8"),
            extractionMode: "full_body"
          }
        });
      }
    } else {
      let endIdx = -1;
      for (let j = i; j < Math.min(i + 10, cleanLines.length); j++) {
        if (cleanLines[j].includes(";")) {
          endIdx = j;
          break;
        }
      }
      if (endIdx !== -1) {
        const startLine = i + 1;
        const endLine = endIdx + 1;
        const snippetLines = lines.slice(startLine - 1, endLine);
        const defText = snippetLines.join("\n");
        matches.push({
          type: "type",
          startLine,
          endLine,
          snippet: {
            definition: defText,
            lines: snippetLines.length,
            bytes: Buffer.byteLength(defText, "utf8"),
            extractionMode: "full_body"
          }
        });
      }
    }
  }

  return matches;
}

/**
 * Searches for all symbol definition candidates (function, macro, type, signature) in source lines.
 *
 * @param {string[]} lines
 * @param {string} symbol
 * @param {object} [options={}]
 * @returns {Array<{ type: string, startLine: number, endLine: number, snippet: object }>}
 */
export function findSymbolDefinitionsInSource(lines, symbol, options = {}) {
  if (!Array.isArray(lines) || !symbol || typeof symbol !== "string") return [];
  const matches = [];

  // 1. Function definitions (with body)
  const fnDefs = findFunctionDefinitions(lines, symbol);
  for (const fd of fnDefs) {
    const snip = extractBoundedFunctionSnippet(lines, fd.startLine, fd.endLine);
    matches.push({
      type: "function",
      startLine: fd.startLine,
      endLine: fd.endLine,
      snippet: snip
    });
  }

  // 2. Macro definitions (#define symbol ...)
  const macroDefs = findMacroDefinitions(lines, symbol);
  for (const md of macroDefs) {
    matches.push(md);
  }

  // 3. Type definitions (struct, class, enum, typedef, interface, type)
  const typeDefs = findTypeDefinitions(lines, symbol);
  for (const td of typeDefs) {
    matches.push(td);
  }

  // 4. Function declarations / signatures (if enabled and no full function definition was found)
  if (matches.length === 0 && options.allowSignature) {
    const decls = findFunctionDeclarations(lines, symbol);
    for (const d of decls) {
      matches.push(d);
    }
  }

  return matches;
}

/**
 * Extracts direct relative include/import paths from source content.
 * Enforces repository path containment fail-closed.
 *
 * @param {string} fileContent
 * @param {string} callingFilePath
 * @returns {string[]} Normalized repository-relative paths
 */
export function extractDirectIncludePaths(fileContent, callingFilePath) {
  if (!fileContent || typeof fileContent !== "string") return [];
  const paths = [];
  const seen = new Set();
  const callingDir = path.posix.dirname((callingFilePath || "").replace(/\\/g, "/"));

  function addCandidate(specifier) {
    if (!specifier || typeof specifier !== "string") return;
    const clean = specifier.replace(/\\/g, "/").trim();
    if (!clean || clean.includes("\0")) return;
    if (/^[a-zA-Z]+:\/\//.test(clean)) return;

    const candidates = [];
    if (clean.startsWith("./") || clean.startsWith("../")) {
      const resolved = path.posix.normalize(path.posix.join(callingDir, clean));
      candidates.push(resolved);
    } else {
      const relToCalling = path.posix.normalize(path.posix.join(callingDir, clean));
      candidates.push(relToCalling);
      const relToRoot = path.posix.normalize(clean);
      if (relToRoot !== relToCalling) {
        candidates.push(relToRoot);
      }
      if (!clean.startsWith("include/")) {
        const inInclude = path.posix.normalize(path.posix.join("include", clean));
        candidates.push(inInclude);
      }
    }

    for (const cand of candidates) {
      if (cand.startsWith("..") || path.posix.isAbsolute(cand) || cand === "." || cand === "") {
        continue;
      }
      if (!seen.has(cand)) {
        seen.add(cand);
        paths.push(cand);
      }
      if (!path.posix.extname(cand)) {
        for (const ext of [".js", ".mjs", ".ts", ".tsx", ".jsx", ".h", ".hpp"]) {
          const withExt = cand + ext;
          if (!seen.has(withExt)) {
            seen.add(withExt);
            paths.push(withExt);
          }
        }
      }
    }
  }

  // 1. C/C++ quoted includes: #include "..."
  const incRegex = /^\s*#\s*include\s*"([^"]+)"/gm;
  let m;
  while ((m = incRegex.exec(fileContent)) !== null) {
    addCandidate(m[1]);
  }

  // 2. JS/TS imports: import ... from "..." or require("...")
  const importRegex = /(?:import\s+(?:[\s\S]*?from\s+)?|require\s*\(\s*)['"]([^'"]+)['"]/g;
  while ((m = importRegex.exec(fileContent)) !== null) {
    const spec = m[1];
    if (spec.startsWith(".") || spec.startsWith("src/") || spec.startsWith("lib/") || spec.includes("/")) {
      addCandidate(spec);
    }
  }

  return paths;
}

/**
 * 3-Tier Cross-File Symbol Resolver (Spec §2 Option A).
 * Resolves unresolved callee symbols against PR changeSet siblings (Tier 2)
 * and direct included headers / imports at exact HEAD (Tier 3).
 *
 * @param {string} symbol
 * @param {string} targetFile
 * @param {string} fileContent
 * @param {object} candidate
 * @param {object} [options={}]
 * @returns {{ resolved: boolean, ambiguous?: boolean, count?: number, tier?: number, callee?: object }}
 */
export function resolveCrossFileSymbol(symbol, targetFile, fileContent, candidate, options = {}) {
  const normTarget = normalizeCanonicalPath(targetFile);

  // ----------------------------------------------------
  // Tier 2: PR ChangeSet Sibling Resolution
  // ----------------------------------------------------
  const siblingFiles = Array.isArray(options.siblingFiles) ? options.siblingFiles : [];
  const siblingMatches = [];

  for (const sibling of siblingFiles) {
    if (!sibling || !sibling.path || !sibling.content) continue;
    const normSiblingPath = normalizeCanonicalPath(sibling.path);
    if (normSiblingPath === normTarget) continue;

    // Check if sibling definition was deleted by patch
    const deletedInSibling = new Set();
    if (sibling.diff && typeof sibling.diff === "string") {
      const hLines = sibling.diff.split(/\r?\n/);
      for (const hLine of hLines) {
        if (hLine.startsWith("-") && !hLine.startsWith("---")) {
          const deletedText = hLine.slice(1);
          const delMatch = deletedText.match(/^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function(?:\s+([a-zA-Z_][a-zA-Z0-9_]*))\s*\(/) ||
            deletedText.match(/^\s*(?:export\s+)?(?:const|let|var)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[a-zA-Z0-9_$]+)?\s*=>/) ||
            deletedText.match(/^\s*(?:async\s+)?def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/) ||
            deletedText.match(/^\s*(?:(?:[a-zA-Z0-9_<>*&]|::)+\s+)+(?:[a-zA-Z0-9_]+::)?([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:<[^()]+>)?\s*\(/) ||
            deletedText.match(/^\s*#\s*define\s+([a-zA-Z_][a-zA-Z0-9_]*)\b/);
          if (delMatch && delMatch[1]) {
            deletedInSibling.add(delMatch[1]);
          }
        }
      }
    }

    if (deletedInSibling.has(symbol)) {
      continue;
    }

    const sLines = sibling.content.split(/\r?\n/);
    const defs = findSymbolDefinitionsInSource(sLines, symbol, { allowSignature: false });
    for (const d of defs) {
      siblingMatches.push({
        ...d,
        file: sibling.path
      });
    }
  }

  if (siblingMatches.length > 1) {
    return {
      resolved: false,
      ambiguous: true,
      count: siblingMatches.length,
      matches: siblingMatches
    };
  }

  if (siblingMatches.length === 1) {
    const match = siblingMatches[0];
    return {
      resolved: true,
      tier: 2,
      callee: {
        symbol,
        ...(candidate?.qualifier ? { qualifier: candidate.qualifier } : {}),
        file: match.file,
        callingFile: targetFile,
        definition: match.snippet.definition,
        lines: match.snippet.lines,
        bytes: match.snippet.bytes,
        startLine: match.startLine,
        endLine: match.endLine,
        extractionMode: match.snippet.extractionMode,
        isSensitive: candidate?.isSensitive,
        category: candidate?.category
      }
    };
  }

  // ----------------------------------------------------
  // Tier 3: Direct Header / Import Resolution at HEAD
  // ----------------------------------------------------
  const repoRoot = options.repositoryRoot || null;
  const headSha = options.headSha || null;
  const includePaths = extractDirectIncludePaths(fileContent, targetFile);

  const headerMatches = [];

  for (const incPath of includePaths) {
    let headerContent = options.fileContents?.[incPath] ?? null;

    if (headerContent === null && headSha && repoRoot) {
      headerContent = getExactHeadFileContent(repoRoot, headSha, incPath);
    }

    if (headerContent === null && repoRoot) {
      const readRes = safeReadWorkingTreeFile(repoRoot, incPath);
      if (readRes.ok && readRes.exists && readRes.content !== null) {
        headerContent = readRes.content;
      }
    }

    if (!headerContent || typeof headerContent !== "string") {
      continue;
    }

    const hLines = headerContent.split(/\r?\n/);
    const defs = findSymbolDefinitionsInSource(hLines, symbol, { allowSignature: true });
    for (const d of defs) {
      headerMatches.push({
        ...d,
        file: incPath
      });
    }
  }

  if (headerMatches.length > 1) {
    return {
      resolved: false,
      ambiguous: true,
      count: headerMatches.length,
      matches: headerMatches
    };
  }

  if (headerMatches.length === 1) {
    const match = headerMatches[0];
    return {
      resolved: true,
      tier: 3,
      callee: {
        symbol,
        ...(candidate?.qualifier ? { qualifier: candidate.qualifier } : {}),
        file: match.file,
        callingFile: targetFile,
        isHeaderCallee: true,
        definition: match.snippet.definition,
        lines: match.snippet.lines,
        bytes: match.snippet.bytes,
        startLine: match.startLine,
        endLine: match.endLine,
        extractionMode: match.snippet.extractionMode,
        isSensitive: candidate?.isSensitive,
        category: candidate?.category
      }
    };
  }

  return {
    resolved: false,
    ambiguous: false
  };
}

/**
 * Extracts local callees and context gaps for a target file from exact-head source content.
 *
 * @param {string} fileContent - Source content at exact HEAD
 * @param {string} diffHunks - Unified diff text
 * @param {string} targetFile - Normalized path of target file
 * @param {object} [options={}] - Options
 * @returns {{ callees: Array<object>, unresolvedCallees: Array<object>, contextGaps: Array<object> }}
 */
export function extractLocalCalleeContext(fileContent, diffHunks, targetFile, options = {}) {
  const callees = [];
  const unresolvedCallees = [];
  const contextGaps = [];

  if (!fileContent || typeof fileContent !== "string") {
    return { callees, unresolvedCallees, contextGaps };
  }

  if (!targetFile || NON_CODE_FILE_REGEX.test(targetFile) || targetFile.startsWith("tests/") || targetFile.startsWith("test/")) {
    return { callees, unresolvedCallees, contextGaps };
  }

  const candidateCalls = extractCandidateCallSymbols(diffHunks, { fileContent, targetFile });
  if (candidateCalls.length === 0) {
    return { callees, unresolvedCallees, contextGaps };
  }

  const lines = fileContent.split(/\r?\n/);
  const runningTotal = options.extractedCalleesCount || 0;
  let fileCalleesCount = 0;

  // Extract imported symbols and aliases from module imports (C8 / C9)
  const importedSymbols = new Set();
  const importAliases = new Map(); // localAlias -> originalSymbol
  const deletedLocalDefinitions = new Set();

  function recordImportSpecifier(specifier) {
    const namedMatch = specifier.match(/\{([\s\S]*?)\}/);
    if (namedMatch) {
      const parts = namedMatch[1].split(",");
      for (const part of parts) {
        const trimmed = part.trim();
        if (!trimmed) continue;
        const aliasMatch = trimmed.match(/^([a-zA-Z_][a-zA-Z0-9_]*)\s+as\s+([a-zA-Z_][a-zA-Z0-9_]*)$/);
        if (aliasMatch) {
          const originalSym = aliasMatch[1];
          const localAlias = aliasMatch[2];
          importedSymbols.add(localAlias);
          importAliases.set(localAlias, originalSym);
        } else {
          const symMatch = trimmed.match(/^([a-zA-Z_][a-zA-Z0-9_]*)$/);
          if (symMatch) {
            importedSymbols.add(symMatch[1]);
          }
        }
      }
    }
    const defaultMatch = specifier.match(/import\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+(?:from|,)/);
    if (defaultMatch && defaultMatch[1] !== "type") {
      importedSymbols.add(defaultMatch[1]);
    }
  }

  const importRegex = /import\s+(?:\{[\s\S]*?\}|[a-zA-Z0-9_$,\s*]+)\s+from\s+['"][^'"]+['"]/g;
  let matchImport;
  while ((matchImport = importRegex.exec(fileContent)) !== null) {
    recordImportSpecifier(matchImport[0]);
    const symMatches = matchImport[0].match(/\b([a-zA-Z_][a-zA-Z0-9_]*)\b/g) || [];
    for (const s of symMatches) {
      if (s !== "import" && s !== "from" && s !== "as" && s !== "default") {
        importedSymbols.add(s);
      }
    }
  }

  const requireRegex = /(?:const|let|var)\s+(?:\{([\s\S]*?)\}|([a-zA-Z0-9_$]+))\s*=\s*require\s*\(/g;
  let matchRequire;
  while ((matchRequire = requireRegex.exec(fileContent)) !== null) {
    if (matchRequire[1]) {
      const parts = matchRequire[1].split(",");
      for (const p of parts) {
        const trimmed = p.trim();
        const aliasMatch = trimmed.match(/^([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*([a-zA-Z_][a-zA-Z0-9_]*)$/);
        if (aliasMatch) {
          importedSymbols.add(aliasMatch[2]);
          importAliases.set(aliasMatch[2], aliasMatch[1]);
        } else {
          const s = trimmed.match(/^([a-zA-Z_][a-zA-Z0-9_]*)$/);
          if (s) importedSymbols.add(s[1]);
        }
      }
    } else if (matchRequire[2]) {
      importedSymbols.add(matchRequire[2]);
    }
  }

  const pyFromImportRegex = /(?:from\s+[a-zA-Z0-9_.]+\s+)?import\s+([a-zA-Z0-9_,\s*()]+)/g;
  let matchPyFrom;
  while ((matchPyFrom = pyFromImportRegex.exec(fileContent)) !== null) {
    const symMatches = matchPyFrom[1].match(/\b([a-zA-Z_][a-zA-Z0-9_]*)\b/g) || [];
    for (const s of symMatches) {
      if (s !== "as" && s !== "import" && s !== "from") {
        importedSymbols.add(s);
      }
    }
  }

  // Scan diffHunks for patch-added imports and patch-deleted local definitions (C9)
  if (diffHunks && typeof diffHunks === "string") {
    const hunkLines = diffHunks.split(/\r?\n/);
    for (const hLine of hunkLines) {
      if (hLine.startsWith("+") && !hLine.startsWith("+++")) {
        const addedText = hLine.slice(1);
        if (/import\s+/.test(addedText)) {
          recordImportSpecifier(addedText);
          const syms = addedText.match(/\b([a-zA-Z_][a-zA-Z0-9_]*)\b/g) || [];
          for (const s of syms) {
            if (s !== "import" && s !== "from" && s !== "as" && s !== "default") importedSymbols.add(s);
          }
        }
        if (/require\s*\(/.test(addedText)) {
          const m = addedText.match(/(?:const|let|var)\s+(?:\{([\s\S]*?)\}|([a-zA-Z0-9_$]+))\s*=\s*require/);
          if (m) {
            if (m[1]) {
              for (const p of m[1].split(",")) {
                const t = p.trim();
                const a = t.match(/^([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*([a-zA-Z_][a-zA-Z0-9_]*)$/);
                if (a) {
                  importedSymbols.add(a[2]);
                  importAliases.set(a[2], a[1]);
                } else {
                  const s = t.match(/^([a-zA-Z_][a-zA-Z0-9_]*)$/);
                  if (s) importedSymbols.add(s[1]);
                }
              }
            } else if (m[2]) {
              importedSymbols.add(m[2]);
            }
          }
        }
      } else if (hLine.startsWith("-") && !hLine.startsWith("---")) {
        const deletedText = hLine.slice(1);
        const delMatch = deletedText.match(/^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function(?:\s+([a-zA-Z_][a-zA-Z0-9_]*))\s*\(/) ||
          deletedText.match(/^\s*(?:export\s+)?(?:const|let|var)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[a-zA-Z0-9_$]+)?\s*=>/) ||
          deletedText.match(/^\s*(?:async\s+)?def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/);
        if (delMatch && delMatch[1]) {
          deletedLocalDefinitions.add(delMatch[1]);
        }
      }
    }
  }

  for (const candidate of candidateCalls) {
    // Preserve sensitivity from import aliases (C8)
    const originalSymbol = importAliases.get(candidate.symbol) || candidate.symbol;
    if (!candidate.isSensitive) {
      const aliasCat = classifySensitiveCategory(originalSymbol);
      if (aliasCat) {
        candidate.isSensitive = true;
        candidate.category = aliasCat;
      }
    }

    const isCandidateImpacted = Boolean(candidate.isAdded || candidate.isControlFlowModified);

    if (candidate.lexicalStateUncertain && candidate.isSensitive) {
      contextGaps.push({
        symbol: candidate.symbol,
        ...(candidate.qualifier ? { qualifier: candidate.qualifier } : {}),
        reason: "HUNK_LEXICAL_STATE_UNCERTAIN",
        file: targetFile,
        line: candidate.line,
        category: candidate.category || "security",
        impact: `Lexical state at hunk boundary uncertain; unverified whether sensitive call '${candidate.symbol}' is inside block comment or template`
      });
    }

    if (candidate.isUnterminated) {
      const unresolvedEntry = {
        symbol: candidate.symbol,
        ...(candidate.qualifier ? { qualifier: candidate.qualifier } : {}),
        reason: "EXTERNAL_CALLEE_UNRESOLVED",
        file: targetFile,
        line: candidate.line
      };
      unresolvedCallees.push(unresolvedEntry);
      if (candidate.isSensitive && isCandidateImpacted) {
        contextGaps.push({
          ...unresolvedEntry,
          category: candidate.category || "input_validation",
          impact: `Unclosed or unterminated multiline generic call '${candidate.qualifier ? candidate.qualifier + "." : ""}${candidate.symbol}' fails closed on sensitive execution path`
        });
      }
      continue;
    }

    const isImported = importedSymbols.has(candidate.symbol) ||
      importedSymbols.has(originalSymbol) ||
      (Array.isArray(candidate.qualifiers) && candidate.qualifiers.some(q => q !== "this" && importedSymbols.has(q))) ||
      Boolean(candidate.qualifier && candidate.qualifier !== "this" && importedSymbols.has(candidate.qualifier));

    if (isImported) {
      // Attempt Tier 2 / Tier 3 cross-file resolution if siblingFiles, repoRoot, or fileContents are supplied
      let crossRes = { resolved: false, ambiguous: false };
      if (options.siblingFiles || options.repositoryRoot || options.fileContents) {
        crossRes = resolveCrossFileSymbol(candidate.symbol, targetFile, fileContent, candidate, options);
      }

      if (crossRes.resolved && crossRes.callee) {
        if (fileCalleesCount >= MAX_CALLEES_PER_FILE || runningTotal + callees.length >= MAX_CALLEES_TOTAL) {
          if (candidate.isSensitive && isCandidateImpacted) {
            contextGaps.push({
              symbol: candidate.symbol,
              ...(candidate.qualifier ? { qualifier: candidate.qualifier } : {}),
              reason: "EXTRACTION_QUOTA_EXCEEDED",
              category: candidate.category || "input_validation",
              file: targetFile,
              line: candidate.line,
              impact: `Extraction quota exceeded; sensitive callee '${candidate.symbol}' on critical execution path not extracted.`
            });
          }
          continue;
        }
        callees.push(crossRes.callee);
        fileCalleesCount++;
        const isHeaderSignature = crossRes.callee.isHeaderCallee === true && crossRes.callee.extractionMode === "signature";
        if (!isHeaderSignature && crossRes.callee.extractionMode !== "full_body" && candidate.isSensitive) {
          contextGaps.push({
            symbol: candidate.symbol,
            ...(candidate.qualifier ? { qualifier: candidate.qualifier } : {}),
            reason: "CALLEE_TRUNCATED_ELIDED",
            category: candidate.category || "input_validation",
            file: crossRes.callee.file,
            line: crossRes.callee.startLine,
            impact: `Sensitive callee '${candidate.qualifier ? candidate.qualifier + "." : ""}${candidate.symbol}' body was truncated (${crossRes.callee.extractionMode}) due to budget limits; implementation completeness unverified on sensitive execution path`
          });
        }
        continue;
      } else if (crossRes.ambiguous) {
        const unresolvedEntry = {
          symbol: candidate.symbol,
          ...(candidate.qualifier ? { qualifier: candidate.qualifier } : {}),
          reason: "AMBIGUOUS_SYMBOL",
          file: targetFile,
          line: candidate.line
        };
        unresolvedCallees.push(unresolvedEntry);
        if (candidate.isSensitive && isCandidateImpacted) {
          contextGaps.push({
            ...unresolvedEntry,
            category: candidate.category || "input_validation",
            impact: `Ambiguous overload (${crossRes.count} definitions found across files) on sensitive execution path`
          });
        }
        continue;
      } else {
        const unresolvedEntry = {
          symbol: candidate.symbol,
          ...(candidate.qualifier ? { qualifier: candidate.qualifier } : {}),
          reason: "EXTERNAL_CALLEE_UNRESOLVED",
          file: targetFile,
          line: candidate.line
        };
        unresolvedCallees.push(unresolvedEntry);
        if (candidate.isSensitive && isCandidateImpacted) {
          contextGaps.push({
            ...unresolvedEntry,
            category: candidate.category || "input_validation",
            impact: `External imported callee definition unavailable on sensitive execution path`
          });
        }
        continue;
      }
    }

    if (fileCalleesCount >= MAX_CALLEES_PER_FILE || runningTotal + callees.length >= MAX_CALLEES_TOTAL) {
      if (candidate.isSensitive && isCandidateImpacted) {
        contextGaps.push({
          symbol: candidate.symbol,
          ...(candidate.qualifier ? { qualifier: candidate.qualifier } : {}),
          reason: "EXTRACTION_QUOTA_EXCEEDED",
          category: candidate.category || "input_validation",
          file: targetFile,
          line: candidate.line,
          impact: `Extraction quota exceeded; sensitive callee '${candidate.symbol}' on critical execution path not extracted.`
        });
      }
      continue;
    }

    const { symbol, line, isSensitive, category } = candidate;

    // 1. Check for Macro Definition
    const macroRegex = new RegExp(`^\\s*#\\s*define\\s+${symbol}\\b`, "m");
    if (macroRegex.test(fileContent)) {
      const unresolvedEntry = {
        symbol,
        ...(candidate.qualifier ? { qualifier: candidate.qualifier } : {}),
        reason: "MACRO_OR_DYNAMIC",
        file: targetFile,
        line
      };
      unresolvedCallees.push(unresolvedEntry);
      if (isSensitive && isCandidateImpacted) {
        contextGaps.push({
          ...unresolvedEntry,
          category: category || "default_values",
          impact: "Unresolved macro definition on sensitive execution path"
        });
      }
      continue;
    }

    // 2. Find function definitions in same file
    let defMatches = [];
    if (deletedLocalDefinitions.has(symbol)) {
      // Definition was deleted by patch; cannot treat deleted HEAD definition as valid implementation (C9)
      defMatches = [];
    } else if (candidate.isQualified) {
      if (candidate.qualifier && candidate.qualifier !== "this" && candidate.qualifier !== "self") {
        defMatches = findQualifiedFunctionDefinitions(lines, candidate.qualifier, symbol, { callLine: line, candidate });
      } else if (candidate.qualifier === "this" || candidate.qualifier === "self") {
        defMatches = findFunctionDefinitions(lines, symbol);
      } else {
        defMatches = [];
      }
    } else {
      defMatches = findFunctionDefinitions(lines, symbol);
    }

    if (defMatches.length === 0) {
      let crossRes = { resolved: false, ambiguous: false };
      if (options.siblingFiles || options.repositoryRoot || options.fileContents) {
        crossRes = resolveCrossFileSymbol(symbol, targetFile, fileContent, candidate, options);
      }

      if (crossRes.resolved && crossRes.callee) {
        callees.push(crossRes.callee);
        fileCalleesCount++;
        const isHeaderSignature = crossRes.callee.isHeaderCallee === true && crossRes.callee.extractionMode === "signature";
        if (!isHeaderSignature && crossRes.callee.extractionMode !== "full_body" && isSensitive) {
          contextGaps.push({
            symbol,
            ...(candidate.qualifier ? { qualifier: candidate.qualifier } : {}),
            reason: "CALLEE_TRUNCATED_ELIDED",
            category: category || "input_validation",
            file: crossRes.callee.file,
            line: crossRes.callee.startLine,
            impact: `Sensitive callee '${candidate.qualifier ? candidate.qualifier + "." : ""}${symbol}' body was truncated (${crossRes.callee.extractionMode}) due to budget limits; implementation completeness unverified on sensitive execution path`
          });
        }
        continue;
      }

      if (crossRes.ambiguous) {
        const unresolvedEntry = {
          symbol,
          ...(candidate.qualifier ? { qualifier: candidate.qualifier } : {}),
          reason: "AMBIGUOUS_SYMBOL",
          file: targetFile,
          line
        };
        unresolvedCallees.push(unresolvedEntry);
        if (isSensitive && isCandidateImpacted) {
          contextGaps.push({
            ...unresolvedEntry,
            category: category || "input_validation",
            impact: `Ambiguous overload (${crossRes.count} definitions found across files) on sensitive execution path`
          });
        }
        continue;
      }

      const isDynamic = Boolean(candidate.lineText && (candidate.lineText.includes(`->${symbol}`) || candidate.lineText.includes(`virtual`)));
      const reason = isDynamic
        ? "MACRO_OR_DYNAMIC"
        : ((candidate.isQualified && candidate.qualifier !== "this" && candidate.qualifier !== "self") || candidate.hasTypeArguments || deletedLocalDefinitions.has(symbol)
            ? "EXTERNAL_CALLEE_UNRESOLVED"
            : "UNRESOLVED_SYMBOL");
      const unresolvedEntry = {
        symbol,
        ...(candidate.qualifier ? { qualifier: candidate.qualifier } : {}),
        reason,
        file: targetFile,
        line
      };
      unresolvedCallees.push(unresolvedEntry);
      if (isSensitive && isCandidateImpacted) {
        contextGaps.push({
          ...unresolvedEntry,
          category: category || "input_validation",
          impact: candidate.isQualified
            ? `Referenced qualified callee '${candidate.qualifier ? candidate.qualifier + "." : ""}${symbol}' definition not found in modified file on sensitive execution path`
            : (candidate.hasTypeArguments
                ? `Referenced generic callee '${symbol}' definition not found in modified file on sensitive execution path`
                : (deletedLocalDefinitions.has(symbol)
                    ? `Local definition of callee '${symbol}' deleted by patch and external implementation unavailable on sensitive execution path`
                    : "Referenced callee definition not found in modified file on sensitive execution path"))
        });
      }
      continue;
    } else if (defMatches.length > 1) {
      const unresolvedEntry = {
        symbol,
        ...(candidate.qualifier ? { qualifier: candidate.qualifier } : {}),
        reason: "AMBIGUOUS_SYMBOL",
        file: targetFile,
        line
      };
      unresolvedCallees.push(unresolvedEntry);
      if (isSensitive && isCandidateImpacted) {
        contextGaps.push({
          ...unresolvedEntry,
          category: category || "input_validation",
          impact: `Ambiguous overload (${defMatches.length} definitions found in same file) on sensitive execution path`
        });
      }
      continue;
    } else {
      const match = defMatches[0];
      const snippet = extractBoundedFunctionSnippet(lines, match.startLine, match.endLine);
      callees.push({
        symbol,
        ...(candidate.qualifier ? { qualifier: candidate.qualifier } : {}),
        file: targetFile,
        definition: snippet.definition,
        lines: snippet.lines,
        bytes: snippet.bytes,
        startLine: match.startLine,
        endLine: match.endLine,
        extractionMode: snippet.extractionMode,
        isSensitive,
        category
      });
      fileCalleesCount++;

      // Emit context gap if sensitive callee is truncated or incomplete (C7)
      if (snippet.extractionMode !== "full_body" && isSensitive) {
        contextGaps.push({
          symbol,
          ...(candidate.qualifier ? { qualifier: candidate.qualifier } : {}),
          reason: "CALLEE_TRUNCATED_ELIDED",
          category: category || "input_validation",
          file: targetFile,
          line: match.startLine,
          impact: `Sensitive callee '${candidate.qualifier ? candidate.qualifier + "." : ""}${symbol}' body was truncated (${snippet.extractionMode}) due to budget limits; implementation completeness unverified on sensitive execution path`
        });
      }
    }
  }

  return { callees, unresolvedCallees, contextGaps };
}

/**
 * Extracts Layer 2 module imports, exports, and top-level constants.
 * @param {string} fileContent
 * @returns {{ imports: string[], exports: string[], topLevelConstants: string[] }}
 */
export function extractModuleScope(fileContent) {
  if (!fileContent || typeof fileContent !== "string") {
    return { imports: [], exports: [], topLevelConstants: [] };
  }

  const imports = [];
  const exports = [];
  const topLevelConstants = [];

  const lines = fileContent.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (/^\s*(?:import\s+|const\s+.*\s*=\s*require\()/i.test(trimmed)) {
      if (imports.length < 20) imports.push(trimmed);
    }
    if (/^\s*(?:export\s+|module\.exports\s*=|exports\.)/i.test(trimmed)) {
      if (exports.length < 20) exports.push(trimmed);
    }
    if (/^\s*(?:export\s+)?(?:const|let)\s+[A-Z0-9_]{3,}\s*=/i.test(trimmed)) {
      if (topLevelConstants.length < 15) topLevelConstants.push(trimmed);
    }
  }

  return { imports, exports, topLevelConstants };
}

/**
 * Extracts Layer 3 Call-Graph caller and callee references.
 * @param {string} fileContent
 * @param {string} [targetFile=""]
 * @param {object} [workspaceFiles={}]
 * @returns {{ callers: Array<object>, callees: Array<object> }}
 */
export function extractCallGraphContext(fileContent, targetFile = "", workspaceFiles = {}) {
  const callees = [];
  const callers = [];

  if (!fileContent) return { callers, callees };

  // Detect callee calls inside modified content
  const callRegex = /\b([a-zA-Z0-9_$]+)\s*(?:\?\.\s*)?(?:<[^()]+>\s*)?(?:\?\.\s*)?\(/g;
  const knownKeywords = new Set(["if", "for", "while", "switch", "catch", "with", "function", "return", "typeof", "delete", "require", "import", "super"]);
  const seenCallees = new Set();

  let match;
  while ((match = callRegex.exec(fileContent)) !== null) {
    const fnName = match[1];
    if (!knownKeywords.has(fnName) && !seenCallees.has(fnName)) {
      seenCallees.add(fnName);
      callees.push({
        functionName: fnName,
        signature: `${fnName}(...)`
      });
      if (callees.length >= 10) break;
    }
  }

  // Cross-file caller detection when workspace files are supplied
  if (workspaceFiles && typeof workspaceFiles === "object") {
    const baseName = path.basename(targetFile, path.extname(targetFile));
    for (const [wPath, wContent] of Object.entries(workspaceFiles)) {
      if (wPath === targetFile || typeof wContent !== "string") continue;
      if (wContent.includes(baseName)) {
        callers.push({
          file: normalizeCanonicalPath(wPath),
          line: 1,
          callerName: `referenced in ${path.basename(wPath)}`
        });
        if (callers.length >= 5) break;
      }
    }
  }

  return { callers, callees };
}

/**
 * Deterministically budgets and evicts context layers according to RFC-027-01 hierarchy.
 * @param {object} rawLayers
 * @param {object} [config=DEFAULT_BUDGET_CONFIG]
 * @returns {{ layers: object, budgetAccounting: object }}
 */
export function allocateContextBudget(rawLayers, config = DEFAULT_BUDGET_CONFIG) {
  const maxInputBytes = config.maxInputBytes || DEFAULT_BUDGET_CONFIG.maxInputBytes;
  const frameBytes = config.frameBytes || DEFAULT_BUDGET_CONFIG.frameBytes;
  const availBudget = Math.max(maxInputBytes - frameBytes, 1024);

  const budget0 = Math.floor(availBudget * (config.layer0Ratio || 0.50));
  const budget1 = Math.floor(availBudget * (config.layer1Ratio || 0.30));
  const budget2 = Math.floor(availBudget * (config.layer2Ratio || 0.10));
  const budget3 = Math.floor(availBudget * (config.layer3Ratio || 0.10));

  const evictedLayers = [];

  // Layer 0: Diff
  const layer0 = rawLayers.layer0Diff || { rawHunks: "", byteLength: 0, additions: 0, deletions: 0 };
  let layer0Bytes = Buffer.byteLength(layer0.rawHunks || "", "utf8");

  // Layer 3: Call-Graph (evicted first if over budget)
  let layer3 = rawLayers.layer3CallGraph || { callers: [], callees: [] };
  let layer3Json = JSON.stringify(layer3);
  let layer3Bytes = Buffer.byteLength(layer3Json, "utf8");
  if (layer3Bytes > budget3) {
    evictedLayers.push("layer3CallGraph");
    layer3 = { callers: [], callees: [] };
    layer3Bytes = 0;
  }

  // Layer 2: Module Scope (trimmed second if over budget)
  let layer2 = rawLayers.layer2ModuleScope || { imports: [], exports: [], topLevelConstants: [] };
  let layer2Json = JSON.stringify(layer2);
  let layer2Bytes = Buffer.byteLength(layer2Json, "utf8");
  if (layer2Bytes > budget2) {
    layer2 = {
      imports: (layer2.imports || []).slice(0, 5),
      exports: (layer2.exports || []).slice(0, 5),
      topLevelConstants: []
    };
    layer2Json = JSON.stringify(layer2);
    layer2Bytes = Buffer.byteLength(layer2Json, "utf8");
    if (layer2Bytes > budget2) {
      evictedLayers.push("layer2ModuleScope");
      layer2 = { imports: [], exports: [], topLevelConstants: [] };
      layer2Bytes = 0;
    }
  }

  // Layer 1: AST Enclosure (trimmed third if over budget)
  // Must respect both budget1 AND GLOBAL_AST_CONTEXT_CEILING_BYTES (8,000 bytes)
  const maxAstAllowed = Math.min(budget1, GLOBAL_AST_CONTEXT_CEILING_BYTES);
  let layer1 = rawLayers.layer1AstEnclosure || {
    adapterName: "builtin-semantic",
    enclosingFunctions: [],
    enclosingClasses: [],
    callees: [],
    unresolvedCallees: []
  };
  let layer1Json = JSON.stringify(layer1);
  let layer1Bytes = Buffer.byteLength(layer1Json, "utf8");
  const evictedCallees = [];

  if (layer1Bytes > maxAstAllowed) {
    layer1 = {
      ...layer1,
      enclosingFunctions: (layer1.enclosingFunctions || []).slice(0, 5).map(fn => ({
        ...fn,
        bodySnippet: "/* ... body collapsed for budget ... */"
      })),
      enclosingClasses: (layer1.enclosingClasses || []).slice(0, 2),
      unresolvedCallees: (layer1.unresolvedCallees || []).slice(0, 15)
    };
    layer1Json = JSON.stringify(layer1);
    layer1Bytes = Buffer.byteLength(layer1Json, "utf8");

    if (layer1Bytes > maxAstAllowed) {
      let calleesList = [...(layer1.callees || [])];
      calleesList.sort((a, b) => {
        if (a.isSensitive && !b.isSensitive) return 1;
        if (!a.isSensitive && b.isSensitive) return -1;
        return 0;
      });
      while (calleesList.length > 0 && Buffer.byteLength(JSON.stringify({ ...layer1, callees: calleesList }), "utf8") > maxAstAllowed) {
        const popped = calleesList.shift();
        if (popped) {
          evictedCallees.push(popped);
        }
      }
      layer1.callees = calleesList;
      layer1Json = JSON.stringify(layer1);
      layer1Bytes = Buffer.byteLength(layer1Json, "utf8");
    }

    if (layer1Bytes > maxAstAllowed) {
      evictedLayers.push("layer1AstEnclosure");
      if (layer1.callees?.length > 0) {
        evictedCallees.push(...layer1.callees);
      }
      layer1 = {
        adapterName: "builtin-semantic",
        enclosingFunctions: [],
        enclosingClasses: [],
        callees: [],
        unresolvedCallees: [...(layer1.unresolvedCallees || [])]
      };
      layer1Bytes = Buffer.byteLength(JSON.stringify(layer1), "utf8");

      while (layer1Bytes > maxAstAllowed && layer1.unresolvedCallees.length > 0) {
        layer1.unresolvedCallees.pop();
        layer1Bytes = Buffer.byteLength(JSON.stringify(layer1), "utf8");
      }
    }
  }

  const consumedBytes = layer0Bytes + layer1Bytes + layer2Bytes + layer3Bytes + frameBytes;

  return {
    layers: {
      layer0Diff: layer0,
      layer1AstEnclosure: layer1,
      layer2ModuleScope: layer2,
      layer3CallGraph: layer3
    },
    budgetAccounting: {
      allocatedBytes: maxInputBytes,
      consumedBytes,
      layer0Bytes,
      layer1Bytes,
      layer2Bytes,
      layer3Bytes,
      evictedLayers,
      evictedCallees
    }
  };
}

/**
 * Generates an authoritative FileCoverageManifest from a ChangeSet (Spec §2.6).
 * Enforces mandatory inspected: true, exactHeadAvailable semantics, and path canonicalization.
 *
 * @param {object} changeSet
 * @param {object} [options={}]
 * @returns {Array<object>}
 */
export function buildFileCoverageManifest(changeSet, options = {}) {
  if (!changeSet || typeof changeSet !== "object") {
    const err = new Error("Invalid changeSet: changeSet must be an object");
    err.code = "INVALID_CHANGESET_SPEC";
    throw err;
  }
  if (!Array.isArray(changeSet.files)) {
    const err = new Error("Invalid changeSet: files must be an array");
    err.code = "INVALID_CHANGESET_SPEC";
    throw err;
  }
  if (changeSet.files.length === 0) {
    const err = new Error("Empty changeSet: files array must not be empty");
    err.code = "EMPTY_CHANGESET_SPEC";
    throw err;
  }

  const manifest = [];
  const seenPaths = new Set();
  const rawMode = changeSet.scopeMode || options.scopeMode || "working_tree";
  const scopeMode = normalizeScopeMode(rawMode);

  for (const entry of changeSet.files) {
    if (!entry) {
      const err = new Error("Invalid changeSet file entry: null or undefined");
      err.code = "INVALID_CHANGESET_ENTRY";
      throw err;
    }
    const rawPath = typeof entry === "string" ? entry : (entry.path || entry.canonicalPath || entry.file);
    if (typeof rawPath !== "string" || !rawPath.trim()) {
      const err = new Error("Invalid changeSet file entry: path must be non-empty string");
      err.code = "INVALID_CHANGESET_ENTRY";
      throw err;
    }

    const canonicalPath = normalizeGitPath(rawPath);
    if (seenPaths.has(canonicalPath)) {
      const err = new Error(`Duplicate changeSet entry: ${canonicalPath}`);
      err.code = "DUPLICATE_CHANGESET_ENTRY";
      throw err;
    }
    seenPaths.add(canonicalPath);

    const changeType = entry.changeType || (entry.deleted ? "D" : (entry.untracked || entry.added ? "A" : "M"));

    // exactHeadAvailable semantics (Spec §2.2)
    let exactHeadAvailable = false;
    if (scopeMode === "revision_range") {
      exactHeadAvailable = changeType !== "D";
    } else {
      exactHeadAvailable = false;
    }

    manifest.push({
      file: canonicalPath,
      inspected: true,
      exactHeadAvailable,
      ...(exactHeadAvailable ? {} : { exactHeadUnavailable: true }),
      changeType,
      calleesExtracted: Array.isArray(entry.calleesExtracted) ? [...entry.calleesExtracted] : [],
      unresolvedCallees: Array.isArray(entry.unresolvedCallees) ? [...entry.unresolvedCallees] : [],
      contextGaps: Array.isArray(entry.contextGaps) ? [...entry.contextGaps] : []
    });
  }

  return manifest;
}

/**
 * Computes authoritative 8-tuple cache key for trusted registry (Spec §2.3).
 *
 * @param {object} params
 * @returns {string} SHA-256 hex string
 */
export function getTrustedRegistryKey(params = {}) {
  const repoId = String(params.repoId || params.repositoryRoot || "").replace(/\\/g, "/");
  const rawMode = params.scopeMode || params.changeSet?.scopeMode || "working_tree";
  const scopeMode = normalizeScopeMode(rawMode);
  const baseSha = params.baseSha || params.changeSet?.baseSha || params.changeSet?.repository?.baseSha || null;
  const headSha = params.headSha || params.changeSet?.headSha || params.changeSet?.repository?.headSha || null;

  // digest(S_CS)
  const rawFiles = params.files || params.changeSet?.files || [];
  const canonicalFiles = rawFiles.map(f => {
    const raw = typeof f === "string" ? f : (f?.path || f?.canonicalPath || f?.file || "");
    return normalizeGitPath(raw);
  });
  canonicalFiles.sort();
  const filesDigest = crypto.createHash("sha256").update(canonicalFiles.join("\n"), "utf8").digest("hex");

  // digest(diffHunks)
  const diffHunks = params.diffHunks || params.changeSet?.diffHunks || "";
  const normalizedHunks = diffHunks.replace(/\r\n/g, "\n");
  const diffHunksDigest = crypto.createHash("sha256").update(normalizedHunks, "utf8").digest("hex");

  const snapshotHash = params.snapshotHash || params.mutationSnapshotHash || params.changeSet?.mutationSnapshotHash || "";
  const schemaVersion = "2.0.0";

  const tuple = [
    repoId,
    scopeMode,
    baseSha,
    headSha,
    filesDigest,
    diffHunksDigest,
    snapshotHash,
    schemaVersion
  ];

  const canonicalJson = canonicalJsonStringify(tuple);
  return crypto.createHash("sha256").update(canonicalJson, "utf8").digest("hex");
}

/**
 * Builds a canonical ContextPackage for a target file within a ChangeSet.
 * @param {object} changeSet
 * @param {string} targetFile
 * @param {object} [options={}]
 * @returns {object} ContextPackage
 */
export function buildContextPackage(changeSet, targetFile, options = {}) {
  const isV2 = options.schemaVersion === "2.0.0" || options.strictRole === true;
  const filesList = Array.isArray(changeSet?.files) ? changeSet.files : [];

  // Schema v2 TargetFile Mutual Exclusion Enforcement (Spec §2.4)
  if (isV2) {
    if (targetFile === undefined || targetFile === null || targetFile === "") {
      const err = new Error("Missing targetFile role in Schema v2 ContextPackage");
      err.code = "MISSING_TARGET_FILE_ROLE";
      throw err;
    }
    const normalizedFiles = filesList.map(f => normalizeGitPath(typeof f === "string" ? f : (f.path || f.canonicalPath || f.file)));
    if (normalizedFiles.length === 1) {
      if (targetFile === "multi-file" || normalizeGitPath(targetFile) !== normalizedFiles[0]) {
        const err = new Error(`Mutual exclusion violation: single-file ChangeSet requires targetFile: '${normalizedFiles[0]}', got '${targetFile}'`);
        err.code = "MUTUAL_EXCLUSION_VIOLATION";
        throw err;
      }
    } else if (normalizedFiles.length > 1) {
      if (targetFile !== "multi-file") {
        const err = new Error(`Mutual exclusion violation: multi-file ChangeSet requires targetFile: 'multi-file', got '${targetFile}'`);
        err.code = "MUTUAL_EXCLUSION_VIOLATION";
        throw err;
      }
    }
  }

  const isMultiFile = targetFile === "multi-file" || !targetFile || Array.isArray(targetFile) || options.allFiles === true;

  if (isMultiFile) {
    const runId = options.runId || crypto.randomUUID();
    const headSha = options.headSha || changeSet?.headSha || changeSet?.repository?.headSha || null;
    const repoRoot = options.repositoryRoot || changeSet?.repository?.root || options.cwd || null;
    const fullDiffHunks = changeSet?.diffHunks || "";

    const isRealRepo = Boolean(repoRoot && isGitRepo(repoRoot));
    const isHeadInRepo = Boolean(isRealRepo && headSha && isCommitInRepo(repoRoot, headSha));

    const rawFilesList = Array.isArray(targetFile)
      ? targetFile
      : (Array.isArray(changeSet?.files) ? changeSet.files : []);
    const filePaths = rawFilesList
      .map(f => (typeof f === "string" ? f : f?.path))
      .filter(Boolean);
    const knownPaths = filePaths.map(p => normalizeCanonicalPath(p));
    const fileDiffMap = splitDiffByFiles(fullDiffHunks, knownPaths);

    const aggregatedCallees = [];
    const aggregatedUnresolvedCallees = [];
    const aggregatedContextGaps = [];
    const fileCoverageManifest = [];
    let totalCalleeBytes = 0;
    const enclosingFunctions = [];
    const enclosingClasses = [];
    let totalAdditions = 0;
    let totalDeletions = 0;
    const perFileData = [];
    let hasPathEscape = false;
    let pathEscapeReason = "";

    const filesContextList = [];
    for (const f of rawFilesList) {
      const fileObj = typeof f === "object" ? f : { path: f };
      const actualFilePath = fileObj.path || f;
      const normPath = normalizeCanonicalPath(actualFilePath);
      const additions = fileObj.additions || 0;
      const deletions = fileObj.deletions || 0;
      totalAdditions += additions;
      totalDeletions += deletions;

      const fileDiff = fileDiffMap.get(normPath) || (fileDiffMap.size === 0 && rawFilesList.length === 1 ? fullDiffHunks : "");
      const effectiveDiff = fileDiff;
      const changedSpans = extractChangedLineSpans(effectiveDiff);

      const isNonCodeOrTest = NON_CODE_FILE_REGEX.test(actualFilePath) ||
        actualFilePath.startsWith("tests/") ||
        actualFilePath.startsWith("test/");

      let callerSuppliedContent = options.fileContents?.[actualFilePath] ??
        options.fileContents?.[normPath] ??
        null;
      let fileContent = callerSuppliedContent;
      let exactHeadUnavailable = false;
      let exactHeadMismatch = false;
      let fileHasPathEscape = false;
      let fileEscapeReason = "";

      if (headSha) {
        if (!isHeadInRepo) {
          exactHeadUnavailable = true;
        } else {
          const exactHeadContent = getExactHeadFileContent(repoRoot, headSha, actualFilePath) ??
            getExactHeadFileContent(repoRoot, headSha, normPath) ??
            null;
          if (exactHeadContent === null) {
            exactHeadUnavailable = true;
          } else if (callerSuppliedContent !== null) {
            const normCaller = callerSuppliedContent.replace(/\r\n/g, "\n");
            const normGit = exactHeadContent.replace(/\r\n/g, "\n");
            if (normCaller !== normGit) {
              exactHeadUnavailable = true;
              exactHeadMismatch = true;
              fileContent = callerSuppliedContent;
            } else {
              fileContent = exactHeadContent;
            }
          } else {
            fileContent = exactHeadContent;
          }
        }
      } else if (fileContent === null && repoRoot) {
        const readRes = safeReadWorkingTreeFile(repoRoot, actualFilePath);
        if (!readRes.ok) {
          hasPathEscape = true;
          fileHasPathEscape = true;
          fileEscapeReason = readRes.error || "File path escapes repository boundary or exceeds size limit";
          pathEscapeReason = pathEscapeReason || fileEscapeReason;
          exactHeadUnavailable = true;
          fileContent = "";
        } else if (readRes.exists && readRes.content !== null) {
          fileContent = readRes.content;
        }
      }
      if (fileContent === null) {
        fileContent = "";
      }

      const fileGaps = [];
      if (fileHasPathEscape) {
        fileGaps.push({
          symbol: normPath,
          code: "REPOSITORY_PATH_ESCAPE",
          reason: "REPOSITORY_PATH_ESCAPE",
          category: "security_boundary",
          file: actualFilePath || normPath,
          impact: fileEscapeReason || `File path escapes repository root boundary or exceeds size limit; content read blocked (Fail-Closed).`
        });
      } else if (exactHeadMismatch) {
        fileGaps.push({
          symbol: normPath,
          file: actualFilePath || normPath,
          reason: "EXACT_HEAD_CONTENT_MISMATCH",
          category: "exact_head_source",
          impact: `Caller-supplied fileContents differs from committed Git object at head ${headSha}; exact-head authority revoked.`
        });
      } else if (exactHeadUnavailable) {
        fileGaps.push({
          symbol: normPath,
          file: actualFilePath || normPath,
          reason: "EXACT_HEAD_CONTENT_UNAVAILABLE",
          category: "exact_head_source",
          impact: `Exact-head file content at commit ${headSha} could not be retrieved; callee definitions and AST context unavailable.`
        });
      }

      const sourceDigest = fileContent
        ? crypto.createHash("sha256").update(fileContent.replace(/\r\n/g, "\n")).digest("hex")
        : null;

      filesContextList.push({
        fileObj,
        actualFilePath,
        normPath,
        effectiveDiff,
        changedSpans,
        isNonCodeOrTest,
        fileContent,
        exactHeadUnavailable,
        fileGaps,
        sourceDigest
      });
    }

    for (const item of filesContextList) {
      const siblingFiles = filesContextList
        .filter(other => other.normPath !== item.normPath)
        .map(other => ({ path: other.actualFilePath, content: other.fileContent, diff: other.effectiveDiff }));

      const fileOptions = {
        ...options,
        siblingFiles,
        repositoryRoot: repoRoot,
        headSha
      };

      const astEnc = item.isNonCodeOrTest
        ? { enclosingFunctions: [], enclosingClasses: [] }
        : extractAstEnclosures(item.fileContent, item.changedSpans);
      for (const fn of astEnc.enclosingFunctions) {
        if (!fn.file) fn.file = item.actualFilePath;
      }
      for (const cls of astEnc.enclosingClasses) {
        if (!cls.file) cls.file = item.actualFilePath;
      }
      enclosingFunctions.push(...astEnc.enclosingFunctions);
      enclosingClasses.push(...astEnc.enclosingClasses);

      const { callees, unresolvedCallees, contextGaps } = extractLocalCalleeContext(
        item.fileContent,
        item.effectiveDiff,
        item.actualFilePath,
        fileOptions
      );

      item.fileGaps.push(...contextGaps);
      aggregatedUnresolvedCallees.push(...unresolvedCallees);

      perFileData.push({
        actualFilePath: item.actualFilePath,
        normPath: item.normPath,
        isNonCodeOrTest: item.isNonCodeOrTest,
        exactHeadUnavailable: item.exactHeadUnavailable,
        callees,
        unresolvedCallees,
        fileGaps: item.fileGaps,
        sourceDigest: item.sourceDigest
      });
    }

    // Two-pass global AST callee aggregation: prioritize sensitive callees
    const allCandidateCallees = [];
    for (const item of perFileData) {
      allCandidateCallees.push(...item.callees);
    }

    allCandidateCallees.sort((a, b) => {
      if (a.isSensitive && !b.isSensitive) return -1;
      if (!a.isSensitive && b.isSensitive) return 1;
      return 0;
    });

    const acceptedCalleesSet = new Set();
    const ceilingGapsByFile = new Map();

    for (const callee of allCandidateCallees) {
      const calleeBytes = Buffer.byteLength(callee.definition || callee.snippet || "", "utf8");
      if (
        aggregatedCallees.length < MAX_CALLEES_TOTAL &&
        totalCalleeBytes + calleeBytes <= GLOBAL_AST_CONTEXT_CEILING_BYTES
      ) {
        aggregatedCallees.push(callee);
        acceptedCalleesSet.add(callee);
        totalCalleeBytes += calleeBytes;
      } else if (callee.isSensitive) {
        const gap = {
          symbol: callee.symbol || callee.name || "unknown",
          file: callee.file,
          reason: "GLOBAL_AST_CONTEXT_CEILING_EXCEEDED",
          category: callee.category || "budget_ceiling",
          impact: `Global 8 KB AST context ceiling reached (${totalCalleeBytes} bytes used); sensitive callee omitted.`
        };
        aggregatedContextGaps.push(gap);
        if (!ceilingGapsByFile.has(callee.file)) ceilingGapsByFile.set(callee.file, []);
        ceilingGapsByFile.get(callee.file).push(gap);
      }
    }

    for (const item of perFileData) {
      const fileAccepted = item.callees.filter(c => acceptedCalleesSet.has(c));
      const fileGaps = [...item.fileGaps, ...(ceilingGapsByFile.get(item.actualFilePath) || [])];
      aggregatedContextGaps.push(...item.fileGaps);

      fileCoverageManifest.push({
        file: item.actualFilePath,
        inspected: true,
        exactHeadAvailable: !item.exactHeadUnavailable,
        ...(item.exactHeadUnavailable ? { exactHeadUnavailable: true } : {}),
        ...(item.sourceDigest ? { sourceDigest: item.sourceDigest } : {}),
        calleesExtracted: fileAccepted.map(c => c.symbol || c.name),
        unresolvedCallees: item.unresolvedCallees,
        contextGaps: fileGaps
      });
    }

    const rawLayer0 = {
      rawHunks: fullDiffHunks,
      byteLength: Buffer.byteLength(fullDiffHunks, "utf8"),
      additions: totalAdditions,
      deletions: totalDeletions
    };

    const rawLayer1 = {
      adapterName: "builtin-semantic",
      enclosingFunctions,
      enclosingClasses,
      callees: aggregatedCallees,
      unresolvedCallees: aggregatedUnresolvedCallees
    };

    const rawLayer2 = { adapterName: "builtin-semantic", imports: [], exports: [] };
    const rawLayer3 = { callGraphEdges: [] };

    const budgeted = allocateContextBudget({
      layer0Diff: rawLayer0,
      layer1AstEnclosure: rawLayer1,
      layer2ModuleScope: rawLayer2,
      layer3CallGraph: rawLayer3
    }, options.budgetConfig || DEFAULT_BUDGET_CONFIG);

    if (budgeted.budgetAccounting?.evictedCallees?.length > 0) {
      for (const evicted of budgeted.budgetAccounting.evictedCallees) {
        if (evicted.isSensitive) {
          const gapEntry = {
            symbol: evicted.symbol || evicted.name || "unknown",
            file: evicted.file || "unknown",
            reason: "GLOBAL_AST_CONTEXT_CEILING_EXCEEDED",
            category: evicted.category || "budget_ceiling",
            impact: `Global 8 KB AST context ceiling reached; sensitive callee omitted during budget allocation.`
          };
          aggregatedContextGaps.push(gapEntry);
        }
      }
      const retainedSymbols = new Set(
        (budgeted.layers?.layer1AstEnclosure?.callees || []).map(c => c.symbol || c.name)
      );
      for (const manifest of fileCoverageManifest) {
        manifest.calleesExtracted = (manifest.calleesExtracted || []).filter(s => retainedSymbols.has(s));
        for (const evicted of budgeted.budgetAccounting.evictedCallees) {
          if (evicted.isSensitive && evicted.file && (evicted.file === manifest.file || normalizeCanonicalPath(evicted.file) === normalizeCanonicalPath(manifest.file))) {
            manifest.contextGaps.push({
              symbol: evicted.symbol || evicted.name || "unknown",
              file: manifest.file,
              reason: "GLOBAL_AST_CONTEXT_CEILING_EXCEEDED",
              category: evicted.category || "budget_ceiling",
              impact: `Global 8 KB AST context ceiling reached; sensitive callee omitted during budget allocation.`
            });
          }
        }
      }
    }

    const contentDigest = crypto.createHash("sha256").update(fullDiffHunks).digest("hex");
    const isWindows = process.platform === "win32";
    const requiresStdin = isWindows && (budgeted.budgetAccounting.consumedBytes > SAFE_ARGV_THRESHOLD_BYTES);

    const resultPackage = {
      schemaVersion: options.schemaVersion || "1.0.0",
      ok: !hasPathEscape,
      ...(hasPathEscape ? {
        error: {
          code: "REPOSITORY_PATH_ESCAPE",
          message: pathEscapeReason || "Repository path containment violation: file escapes repository root or exceeds size ceiling"
        }
      } : {}),
      runId,
      targetFile: filePaths.length === 1 ? (() => {
        try { return normalizeGitPath(filePaths[0], repoRoot); }
        catch { return normalizeCanonicalPath(filePaths[0]); }
      })() : "multi-file",
      ...(headSha ? { headSha } : {}),
      ...(repoRoot ? { repositoryRoot: repoRoot } : {}),
      scopeMode: changeSet?.scopeMode || "working-tree",
      contentDigest,
      layers: budgeted.layers,
      contextGaps: aggregatedContextGaps,
      fileCoverageManifest,
      budgetAccounting: budgeted.budgetAccounting,
      transportPlan: {
        isWindows,
        requiresStdin,
        safeArgvThresholdBytes: SAFE_ARGV_THRESHOLD_BYTES
      }
    };
    const hasPhysicalGit = Boolean(
      !hasPathEscape &&
      isHeadInRepo &&
      fileCoverageManifest.length > 0 &&
      fileCoverageManifest.every(m => m && m.exactHeadAvailable === true && !m.exactHeadUnavailable)
    );

    if (hasPhysicalGit) {
      registerTrustedContextPackage(resultPackage, {
        repositoryRoot: repoRoot,
        headSha,
        diffHunks: fullDiffHunks,
        changeSet,
        verifiedBy: "context-builder",
        workflowAuthority: typeof _internalContextBuilderWorkflowMinter === "function"
          ? _internalContextBuilderWorkflowMinter("context-builder", {
              contentDigest,
              headSha
            })
          : null
      });
    }
    return deepFreeze(resultPackage);
  }

  // Single-file mode
  const headSha = options.headSha || changeSet?.headSha || changeSet?.repository?.headSha || null;
  const repoRoot = options.repositoryRoot || changeSet?.repository?.root || options.cwd || null;
  let normTarget;
  try {
    normTarget = normalizeGitPath(targetFile, repoRoot);
  } catch {
    normTarget = normalizeCanonicalPath(targetFile);
  }
  const rawDiffHunks = changeSet?.diffHunks || "";
  const runId = options.runId || crypto.randomUUID();

  // Find file stats in changeSet
  const fileMeta = (changeSet?.files || []).find(f => {
    const p = typeof f === "string" ? f : f?.path;
    try {
      return normalizeGitPath(p, repoRoot) === normTarget;
    } catch {
      return normalizeCanonicalPath(p) === normTarget;
    }
  });

  const actualFilePath = (typeof fileMeta === "string" ? fileMeta : fileMeta?.path) ||
    targetFile.replace(/\\/g, "/").replace(/^\.\//, "");
  normTarget = normTarget || normalizeCanonicalPath(actualFilePath);

  // Isolate single-file diff hunks if changeSet contains multi-file diff (C12)
  let diffHunks = rawDiffHunks;
  let diffFileMismatch = false;
  if (rawDiffHunks && actualFilePath) {
    const fileDiffMap = splitDiffByFiles(rawDiffHunks, [normTarget]);
    const isolated = fileDiffMap.get(normTarget);
    if (isolated !== undefined) {
      diffHunks = isolated;
    } else {
      const hasFileBoundaries = fileDiffMap.size > 0 ||
        /^(?:diff --git |--- [ab]\/|\+\+\+ [ab]\/)/m.test(rawDiffHunks);
      if (hasFileBoundaries) {
        diffHunks = "";
        diffFileMismatch = true;
      }
    }
  }

  const additions = fileMeta?.additions || 0;
  const deletions = fileMeta?.deletions || 0;

  // Extract changed line spans from isolated diff
  const changedSpans = extractChangedLineSpans(diffHunks);

  const isNonCodeOrTest = NON_CODE_FILE_REGEX.test(actualFilePath) ||
    actualFilePath.startsWith("tests/") ||
    actualFilePath.startsWith("test/");

  let callerSuppliedContent = options.fileContents?.[actualFilePath] ??
    options.fileContents?.[normTarget] ??
    options.fileContents?.[targetFile] ??
    null;
  let fileContent = callerSuppliedContent;

  const isRealRepo = Boolean(repoRoot && isGitRepo(repoRoot));
  const isHeadInRepo = Boolean(isRealRepo && headSha && isCommitInRepo(repoRoot, headSha));

  let exactHeadUnavailable = false;
  let exactHeadMismatch = false;
  let hasPathEscape = false;
  let pathEscapeReason = "";

  if (headSha) {
    if (!isHeadInRepo) {
      exactHeadUnavailable = true;
    } else {
      const exactHeadContent = getExactHeadFileContent(repoRoot, headSha, actualFilePath) ??
        getExactHeadFileContent(repoRoot, headSha, normTarget) ??
        null;
      if (exactHeadContent === null) {
        exactHeadUnavailable = true;
      } else if (callerSuppliedContent !== null) {
        const normCaller = callerSuppliedContent.replace(/\r\n/g, "\n");
        const normGit = exactHeadContent.replace(/\r\n/g, "\n");
        if (normCaller !== normGit) {
          exactHeadUnavailable = true;
          exactHeadMismatch = true;
          fileContent = callerSuppliedContent;
        } else {
          fileContent = exactHeadContent;
        }
      } else {
        fileContent = exactHeadContent;
      }
    }
  } else if (fileContent === null && repoRoot) {
    const readRes = safeReadWorkingTreeFile(repoRoot, actualFilePath);
    if (!readRes.ok) {
      hasPathEscape = true;
      pathEscapeReason = readRes.error || "File path escapes repository boundary or exceeds size limit";
      exactHeadUnavailable = true;
      fileContent = "";
    } else if (readRes.exists && readRes.content !== null) {
      fileContent = readRes.content;
    }
  }
  if (fileContent === null) {
    fileContent = "";
  }

  const rawLayer0 = {
    rawHunks: diffHunks,
    byteLength: Buffer.byteLength(diffHunks, "utf8"),
    additions,
    deletions
  };

  const rawLayer1 = isNonCodeOrTest
    ? { adapterName: "builtin-semantic", enclosingFunctions: [], enclosingClasses: [], callees: [], unresolvedCallees: [] }
    : extractAstEnclosures(fileContent, changedSpans);
  if (rawLayer1?.enclosingFunctions) {
    for (const fn of rawLayer1.enclosingFunctions) {
      if (!fn.file) fn.file = actualFilePath;
    }
  }
  if (rawLayer1?.enclosingClasses) {
    for (const cls of rawLayer1.enclosingClasses) {
      if (!cls.file) cls.file = actualFilePath;
    }
  }
  let siblingFiles = options.siblingFiles;
  if (!siblingFiles) {
    siblingFiles = [];
    if (Array.isArray(changeSet?.files)) {
      for (const f of changeSet.files) {
        const p = typeof f === "string" ? f : f?.path;
        if (!p) continue;
        let norm;
        try {
          norm = normalizeGitPath(p, repoRoot);
        } catch {
          norm = normalizeCanonicalPath(p);
        }
        if (norm !== normTarget) {
          const sContent = options.fileContents?.[p] ??
            options.fileContents?.[norm] ??
            (isHeadInRepo ? getExactHeadFileContent(repoRoot, headSha, p) : null) ??
            (repoRoot ? safeReadWorkingTreeFile(repoRoot, p).content : null) ??
            null;
          let sDiff = "";
          if (rawDiffHunks) {
            const fileDiffMap = splitDiffByFiles(rawDiffHunks, [norm, p]);
            sDiff = fileDiffMap.get(norm) ?? fileDiffMap.get(p) ?? "";
          }
          siblingFiles.push({ path: p, content: sContent, diff: sDiff });
        }
      }
    } else if (options.fileContents && typeof options.fileContents === "object") {
      for (const [filePath, content] of Object.entries(options.fileContents)) {
        let norm;
        try {
          norm = normalizeGitPath(filePath, repoRoot);
        } catch {
          norm = normalizeCanonicalPath(filePath);
        }
        if (norm !== normTarget) {
          siblingFiles.push({ path: filePath, content });
        }
      }
    }
  }

  const singleFileOptions = {
    ...options,
    siblingFiles: siblingFiles || [],
    repositoryRoot: options.repositoryRoot || repoRoot,
    headSha: options.headSha || headSha
  };

  const { callees, unresolvedCallees, contextGaps } = extractLocalCalleeContext(
    fileContent,
    diffHunks,
    actualFilePath,
    singleFileOptions
  );

  if (hasPathEscape) {
    contextGaps.push({
      symbol: normTarget,
      code: "REPOSITORY_PATH_ESCAPE",
      reason: "REPOSITORY_PATH_ESCAPE",
      category: "security_boundary",
      file: actualFilePath || normTarget,
      impact: pathEscapeReason || `File path escapes repository root boundary or exceeds size limit; content read blocked (Fail-Closed).`
    });
  } else if (exactHeadMismatch) {
    contextGaps.push({
      symbol: normTarget,
      file: actualFilePath || normTarget,
      reason: "EXACT_HEAD_CONTENT_MISMATCH",
      category: "exact_head_source",
      impact: `Caller-supplied fileContents differs from committed Git object at head ${headSha}; exact-head authority revoked.`
    });
  } else if (exactHeadUnavailable) {
    contextGaps.push({
      symbol: normTarget,
      file: actualFilePath || normTarget,
      reason: "EXACT_HEAD_CONTENT_UNAVAILABLE",
      category: "exact_head_source",
      impact: `Exact-head file content at commit ${headSha} could not be retrieved; callee definitions and AST context unavailable.`
    });
  }

  if (diffFileMismatch) {
    contextGaps.push({
      symbol: normTarget,
      file: actualFilePath || normTarget,
      code: "DIFF_TARGET_FILE_NOT_FOUND",
      reason: "DIFF_TARGET_FILE_NOT_FOUND",
      category: "scope_boundary",
      impact: `Supplied diff contains structured file boundaries, but target file '${actualFilePath}' was not found in diff hunks; fallback to multi-file raw diff rejected.`
    });
  }

  rawLayer1.callees = callees;
  rawLayer1.unresolvedCallees = unresolvedCallees;

  const rawLayer2 = extractModuleScope(fileContent);
  const rawLayer3 = extractCallGraphContext(fileContent, normTarget, options.fileContents || {});

  const budgeted = allocateContextBudget({
    layer0Diff: rawLayer0,
    layer1AstEnclosure: rawLayer1,
    layer2ModuleScope: rawLayer2,
    layer3CallGraph: rawLayer3
  }, options.budgetConfig || DEFAULT_BUDGET_CONFIG);

  if (budgeted.budgetAccounting?.evictedCallees?.length > 0) {
    for (const evicted of budgeted.budgetAccounting.evictedCallees) {
      if (evicted.isSensitive) {
        contextGaps.push({
          symbol: evicted.symbol || evicted.name || "unknown",
          file: actualFilePath || normTarget,
          reason: "GLOBAL_AST_CONTEXT_CEILING_EXCEEDED",
          category: evicted.category || "budget_ceiling",
          impact: `Global 8 KB AST context ceiling reached; sensitive callee omitted during budget allocation.`
        });
      }
    }
  }

  const retainedSymbols = new Set(
    (budgeted.layers?.layer1AstEnclosure?.callees || []).map(c => c.symbol || c.name)
  );

  const contentDigest = crypto.createHash("sha256").update(diffHunks).digest("hex");
  const sourceDigest = fileContent
    ? crypto.createHash("sha256").update(fileContent.replace(/\r\n/g, "\n")).digest("hex")
    : null;
  const isWindows = process.platform === "win32";
  const requiresStdin = isWindows && (budgeted.budgetAccounting.consumedBytes > SAFE_ARGV_THRESHOLD_BYTES);

  const resultPackage = {
    schemaVersion: options.schemaVersion || "1.0.0",
    ok: !hasPathEscape,
    ...(hasPathEscape ? {
      error: {
        code: "REPOSITORY_PATH_ESCAPE",
        message: pathEscapeReason || "Repository path containment violation: file escapes repository root or exceeds size ceiling"
      }
    } : {}),
    runId,
    targetFile: normTarget,
    ...(headSha ? { headSha } : {}),
    ...(repoRoot ? { repositoryRoot: repoRoot } : {}),
    scopeMode: changeSet?.scopeMode || "working-tree",
    contentDigest,
    layers: budgeted.layers,
    contextGaps,
    fileCoverageManifest: [
      {
        file: actualFilePath,
        inspected: true,
        exactHeadAvailable: !exactHeadUnavailable && !hasPathEscape,
        ...(exactHeadUnavailable || hasPathEscape ? { exactHeadUnavailable: true } : {}),
        ...(sourceDigest ? { sourceDigest } : {}),
        calleesExtracted: callees.map(c => c.name || c.symbol).filter(s => retainedSymbols.has(s)),
        unresolvedCallees,
        contextGaps
      }
    ],
    budgetAccounting: budgeted.budgetAccounting,
    transportPlan: {
      isWindows,
      requiresStdin,
      safeArgvThresholdBytes: SAFE_ARGV_THRESHOLD_BYTES
    }
  };
  const hasPhysicalGit = Boolean(
    !hasPathEscape &&
    isHeadInRepo &&
    !exactHeadUnavailable
  );

  if (hasPhysicalGit) {
    registerTrustedContextPackage(resultPackage, {
      repositoryRoot: repoRoot,
      headSha,
      diffHunks,
      changeSet,
      verifiedBy: "context-builder",
      workflowAuthority: typeof _internalContextBuilderWorkflowMinter === "function"
        ? _internalContextBuilderWorkflowMinter("context-builder", {
            contentDigest: resultPackage.contentDigest,
            headSha
          })
        : null
    });
  }
  return deepFreeze(resultPackage);
}
