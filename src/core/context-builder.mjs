/**
 * Triad-Flow Review Context & AST Enclosure Builder (RFC-027-01)
 *
 * Implements zero-dependency, 4-layer context extraction, deterministic byte budgeting,
 * and Windows ARG_MAX safe transport planning.
 */

import crypto from "node:crypto";
import path from "node:path";
import { normalizeCanonicalPath } from "./scoring.mjs";
import { getExactHeadFileContent } from "./git-collector.mjs";

export const SAFE_ARGV_THRESHOLD_BYTES = 8192;
export const GLOBAL_AST_CONTEXT_CEILING_BYTES = 8000;
export const MAX_CALLEES_PER_FILE = 5;
export const MAX_CALLEES_TOTAL = 10;
export const MAX_SNIPPET_LINES = 60;
export const MAX_SNIPPET_BYTES = 2000;

export const DEFAULT_BUDGET_CONFIG = Object.freeze({
  maxInputBytes: 524288,     // 512 KB Total Budget
  frameBytes: 16384,         // 16 KB reserved for prompts and checklists
  layer0Ratio: 0.50,         // 50% for Layer 0 (Diff hunks)
  layer1Ratio: 0.30,         // 30% for Layer 1 (AST Enclosing Scope)
  layer2Ratio: 0.10,         // 10% for Layer 2 (Module Imports & Exports)
  layer3Ratio: 0.10          // 10% for Layer 3 (Call Graph & Flow References)
});

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
      classes.push({
        name: className,
        startLine: lineNum,
        endLine: endLine
      });
      continue;
    }

    // Check Function Declaration
    const fnMatch = line.match(fnDeclRegex);
    if (fnMatch) {
      const fnName = fnMatch[1] || `anonymous_L${lineNum}`;
      const params = (fnMatch[2] || "").split(",").map(p => p.trim()).filter(Boolean);
      const endLine = findBraceScopeEnd(lines, i);
      functions.push({
        name: fnName,
        kind: "function",
        startLine: lineNum,
        endLine: endLine,
        parameters: params,
        headerCode: line.trim(),
        bodySnippet: lines.slice(i, Math.min(i + 4, endLine)).join("\n").trim()
      });
      continue;
    }

    // Check Method Definition
    const methodMatch = line.match(methodRegex);
    if (methodMatch) {
      const methodName = methodMatch[1];
      const params = (methodMatch[2] || "").split(",").map(p => p.trim()).filter(Boolean);
      const endLine = findBraceScopeEnd(lines, i);
      functions.push({
        name: methodName,
        kind: "method",
        startLine: lineNum,
        endLine: endLine,
        parameters: params,
        headerCode: line.trim(),
        bodySnippet: lines.slice(i, Math.min(i + 4, endLine)).join("\n").trim()
      });
      continue;
    }

    // Check Arrow Assignment
    const arrowMatch = line.match(arrowRegex);
    if (arrowMatch) {
      const arrowName = arrowMatch[1];
      const params = (arrowMatch[2] || arrowMatch[3] || "").split(",").map(p => p.trim()).filter(Boolean);
      const endLine = findBraceScopeEnd(lines, i);
      functions.push({
        name: arrowName,
        kind: "arrow",
        startLine: lineNum,
        endLine: endLine,
        parameters: params,
        headerCode: line.trim(),
        bodySnippet: lines.slice(i, Math.min(i + 4, endLine)).join("\n").trim()
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
 * Handles single-line comments, multi-line comments, and string literals.
 * @param {string[]} lines
 * @param {number} startIndex 0-indexed line index
 * @returns {number} 1-indexed end line
 */
export function findBraceScopeEnd(lines, startIndex) {
  let depth = 0;
  let started = false;
  let inBlockComment = false;

  for (let i = startIndex; i < lines.length; i++) {
    const line = lines[i];
    let inString = false;
    let stringChar = null;

    for (let charIdx = 0; charIdx < line.length; charIdx++) {
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
        continue;
      }

      if (c === "{") {
        depth++;
        started = true;
      } else if (c === "}") {
        depth--;
        if (started && depth <= 0) {
          return i + 1;
        }
      }
    }
  }
  return lines.length;
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

  const DEF_REGEX = new RegExp(
    `(?:` +
    `^(?:\\s*(?:[a-zA-Z0-9_<>:&*]+\\s+)+)?(?:[a-zA-Z0-9_]+::)?${escapedSym}\\s*\\(|` +
    `^\\s*(?:export\\s+)?(?:default\\s+)?(?:async\\s+)?function(?:\\s+${escapedSym})?\\s*\\(|` +
    `^\\s*(?:static\\s+)?(?:async\\s+)?${escapedSym}\\s*\\(|` +
    `^\\s*(?:export\\s+)?(?:const|let|var)?\\s*${escapedSym}\\s*=\\s*(?:async\\s*)?(?:\\([^)]*\\)|[a-zA-Z0-9_$]+)?\\s*(?:=>|function)|` +
    `^\\s*def\\s+${escapedSym}\\s*\\(` +
    `)`
  );

  const CONTROL_START = /^\s*(?:if|while|for|switch|catch|with|return|throw|delete|typeof|sizeof|case|else\s+if)\b/;
  const CALL_EXPR_DISQUALIFIERS = /(?:==|!=|&&|\|\||return\s+|throw\s+|new\s+)/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (!line.includes(symbol)) continue;
    if (CONTROL_START.test(line)) continue;
    if (!DEF_REGEX.test(line)) continue;

    if (line.includes("=") && !line.includes("=>") && !line.includes("function") && !line.includes("{")) {
      continue;
    }

    if (CALL_EXPR_DISQUALIFIERS.test(line) && !line.includes("=>") && !line.includes("{")) {
      continue;
    }

    let hasBrace = false;
    let braceLineIdx = -1;
    let isDeclarationOnly = false;

    for (let j = i; j < Math.min(i + 15, lines.length); j++) {
      const scanLine = lines[j];
      const braceIdx = scanLine.indexOf("{");
      const semiIdx = scanLine.indexOf(";");

      if (semiIdx !== -1 && (braceIdx === -1 || semiIdx < braceIdx)) {
        isDeclarationOnly = true;
        break;
      }

      if (braceIdx !== -1) {
        hasBrace = true;
        braceLineIdx = j;
        break;
      }
    }

    if (isDeclarationOnly || !hasBrace || braceLineIdx === -1) {
      continue;
    }

    const endLine = findBraceScopeEnd(lines, braceLineIdx);
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
 * Classifies a token or text fragment into a sensitive category according to RFC-027-01.
 * Evaluates default_values ahead of input_validation to ensure default-handling macros
 * and routines (such as CHECK_MAP_DEFAULT or isMapValueDefault) receive appropriate prioritization.
 *
 * @param {string} text
 * @returns {"default_values" | "input_validation" | "error_handling" | "security" | null}
 */
export function classifySensitiveCategory(text) {
  if (!text || typeof text !== "string") return null;

  const SENSITIVE_PATTERNS = [
    { category: "default_values", regex: /(?:^|_|\b)(?:default|fallback|isMapValueDefault|missing|absent|zero|optional)\w*/i },
    { category: "input_validation", regex: /(?:^|_|\b)(?:valid|check|assert|verify|sanitize|parse|bounds?|range|empty|null|param|limit)\w*/i },
    { category: "error_handling", regex: /(?:^|_|\b)(?:error|err|fail|throw|catch|reject|abort|except|status|try|drop)\w*/i },
    { category: "security", regex: /(?:^|_|\b)(?:auth|permit|allow|deny|token|secret|privilege|guard|secure)\w*/i }
  ];

  for (const { category, regex } of SENSITIVE_PATTERNS) {
    if (regex.test(text)) {
      return category;
    }
  }

  return null;
}

/**
 * Extracts candidate function call symbols from diff hunks.
 * Prioritizes added lines over context lines, computes target file line numbers,
 * and excludes language keywords.
 *
 * @param {string} diffHunks
 * @returns {Array<{ symbol: string, isAdded: boolean, line: number, lineText: string, isSensitive: boolean, category: string|null }>}
 */
export function extractCandidateCallSymbols(diffHunks) {
  if (!diffHunks || typeof diffHunks !== "string") return [];

  const lines = diffHunks.split(/\r?\n/);
  const candidates = [];
  const seen = new Set();

  const CALL_REGEX = /\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/g;
  const KEYWORDS = new Set([
    "if", "else", "for", "while", "do", "switch", "case", "default", "break", "continue",
    "return", "throw", "try", "catch", "finally", "goto", "function", "async", "await",
    "class", "extends", "super", "this", "import", "export", "from", "require", "typeof",
    "instanceof", "new", "delete", "void", "sizeof", "alignof", "decltype", "typeid",
    "static_cast", "dynamic_cast", "const_cast", "reinterpret_cast", "defined", "template",
    "typename", "explicit", "noexcept", "virtual", "override", "final", "inline", "static",
    "const", "constexpr", "auto", "assert", "static_assert", "int", "char", "bool", "float",
    "double", "long", "short", "unsigned", "signed", "struct", "enum", "union"
  ]);

  let currentTargetLine = 1;
  const HUNK_HEADER_REGEX = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/;

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];

    const hunkMatch = rawLine.match(HUNK_HEADER_REGEX);
    if (hunkMatch) {
      currentTargetLine = parseInt(hunkMatch[1], 10);
      continue;
    }

    if (rawLine.startsWith("---") || rawLine.startsWith("+++") || rawLine.startsWith("diff ") || rawLine.startsWith("index ")) {
      continue;
    }

    if (rawLine.startsWith("-")) {
      continue;
    }

    const isAdded = rawLine.startsWith("+");
    const lineText = isAdded ? rawLine.slice(1) : (rawLine.startsWith(" ") ? rawLine.slice(1) : rawLine);
    const lineNum = currentTargetLine;
    currentTargetLine++;

    const lineCategory = classifySensitiveCategory(lineText);
    const isSensitiveLine = Boolean(lineCategory);

    let match;
    CALL_REGEX.lastIndex = 0;
    while ((match = CALL_REGEX.exec(lineText)) !== null) {
      const sym = match[1];
      if (KEYWORDS.has(sym)) continue;

      const symCat = classifySensitiveCategory(sym);
      const isSensitive = Boolean(symCat || isSensitiveLine);
      const symCategory = symCat || lineCategory;

      if (!seen.has(sym)) {
        seen.add(sym);
        candidates.push({
          symbol: sym,
          isAdded,
          line: lineNum,
          lineText: lineText.trim(),
          isSensitive,
          category: symCategory
        });
      } else if (isAdded) {
        const existing = candidates.find(c => c.symbol === sym);
        if (existing && !existing.isAdded) {
          existing.isAdded = true;
          existing.line = lineNum;
          existing.lineText = lineText.trim();
          if (isSensitive) {
            existing.isSensitive = true;
            existing.category = symCategory;
          }
        }
      }
    }
  }

  candidates.sort((a, b) => {
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
  const GUARD_REGEX = /\b(?:if\s*\(.*?\)\s*(?:return|throw)\b|\breturn\b|\bthrow\b|\bassert\b|isMapValueDefault|\bcheck\b|\bvalidate\b|\bguard\b)/i;

  for (let i = startLine - 1; i < endLine - 1; i++) {
    const l = lines[i];
    if (!headerEnded) {
      extracted.push(l);
      if (l.includes("{")) headerEnded = true;
      continue;
    }

    if (extracted.length < 25 || GUARD_REGEX.test(l)) {
      extracted.push(l);
    }

    if (extracted.length >= 55) break;
  }

  extracted.push("    /* ... [remainder of function body elided for context bounds] ... */");
  extracted.push(lines[endLine - 1]);

  let finalLines = extracted.slice(0, MAX_SNIPPET_LINES);
  let truncated = finalLines.join("\n");
  let bytes = Buffer.byteLength(truncated, "utf8");

  if (bytes > MAX_SNIPPET_BYTES) {
    const headerLines = [];
    for (const line of finalLines) {
      if (Buffer.byteLength(headerLines.concat([line, "    /* ... elided ... */", lines[endLine - 1]]).join("\n"), "utf8") < MAX_SNIPPET_BYTES - 50) {
        headerLines.push(line);
      } else {
        break;
      }
    }
    headerLines.push("    /* ... [remainder of function body elided for context bounds] ... */");
    headerLines.push(lines[endLine - 1]);
    finalLines = headerLines;
    truncated = finalLines.join("\n");
    bytes = Buffer.byteLength(truncated, "utf8");
  }

  return {
    definition: truncated,
    lines: finalLines.length,
    bytes,
    extractionMode: "signature_and_guards"
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

  const candidateCalls = extractCandidateCallSymbols(diffHunks);
  if (candidateCalls.length === 0) {
    return { callees, unresolvedCallees, contextGaps };
  }

  const lines = fileContent.split(/\r?\n/);
  const runningTotal = options.extractedCalleesCount || 0;
  let fileCalleesCount = 0;

  for (const candidate of candidateCalls) {
    if (fileCalleesCount >= MAX_CALLEES_PER_FILE || runningTotal + callees.length >= MAX_CALLEES_TOTAL) {
      break;
    }

    const { symbol, line, isAdded, isSensitive, category } = candidate;

    // 1. Check for Macro Definition
    const macroRegex = new RegExp(`^\\s*#\\s*define\\s+${symbol}\\b`, "m");
    if (macroRegex.test(fileContent)) {
      const unresolvedEntry = {
        symbol,
        reason: "MACRO_OR_DYNAMIC",
        file: targetFile,
        line
      };
      unresolvedCallees.push(unresolvedEntry);
      if (isSensitive) {
        contextGaps.push({
          ...unresolvedEntry,
          category: category || "default_values",
          impact: "Unresolved macro definition on sensitive execution path"
        });
      }
      continue;
    }

    // 2. Find function definitions in same file
    const defMatches = findFunctionDefinitions(lines, symbol);

    if (defMatches.length === 0) {
      const isDynamic = candidate.lineText && (candidate.lineText.includes(`->${symbol}`) || candidate.lineText.includes(`virtual`));
      const reason = isDynamic ? "MACRO_OR_DYNAMIC" : "UNRESOLVED_SYMBOL";
      const unresolvedEntry = {
        symbol,
        reason,
        file: targetFile,
        line
      };
      unresolvedCallees.push(unresolvedEntry);
      if (isSensitive) {
        contextGaps.push({
          ...unresolvedEntry,
          category: category || "input_validation",
          impact: "Referenced callee definition not found in modified file on sensitive execution path"
        });
      }
    } else if (defMatches.length > 1) {
      const unresolvedEntry = {
        symbol,
        reason: "AMBIGUOUS_SYMBOL",
        file: targetFile,
        line
      };
      unresolvedCallees.push(unresolvedEntry);
      if (isSensitive) {
        contextGaps.push({
          ...unresolvedEntry,
          category: category || "input_validation",
          impact: `Ambiguous overload (${defMatches.length} definitions found in same file) on sensitive execution path`
        });
      }
    } else {
      const match = defMatches[0];
      const snippet = extractBoundedFunctionSnippet(lines, match.startLine, match.endLine);
      callees.push({
        symbol,
        definition: snippet.definition,
        lines: snippet.lines,
        bytes: snippet.bytes,
        startLine: match.startLine,
        endLine: match.endLine,
        extractionMode: snippet.extractionMode
      });
      fileCalleesCount++;
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
  const callRegex = /\b([a-zA-Z0-9_$]+)\s*\(/g;
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

  if (layer1Bytes > maxAstAllowed) {
    let calleesList = [...(layer1.callees || [])];
    while (calleesList.length > 0 && Buffer.byteLength(JSON.stringify({ ...layer1, callees: calleesList }), "utf8") > maxAstAllowed) {
      calleesList.pop();
    }

    layer1 = {
      ...layer1,
      enclosingFunctions: (layer1.enclosingFunctions || []).map(fn => ({
        ...fn,
        bodySnippet: "/* ... body collapsed for budget ... */"
      })),
      enclosingClasses: (layer1.enclosingClasses || []).slice(0, 2),
      callees: calleesList
    };
    layer1Json = JSON.stringify(layer1);
    layer1Bytes = Buffer.byteLength(layer1Json, "utf8");

    if (layer1Bytes > maxAstAllowed) {
      evictedLayers.push("layer1AstEnclosure");
      layer1 = {
        adapterName: "builtin-semantic",
        enclosingFunctions: [],
        enclosingClasses: [],
        callees: [],
        unresolvedCallees: layer1.unresolvedCallees || []
      };
      layer1Bytes = Buffer.byteLength(JSON.stringify(layer1), "utf8");
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
      evictedLayers
    }
  };
}

/**
 * Builds a canonical ContextPackage for a target file within a ChangeSet.
 * @param {object} changeSet
 * @param {string} targetFile
 * @param {object} [options={}]
 * @returns {object} ContextPackage
 */
export function buildContextPackage(changeSet, targetFile, options = {}) {
  const normTarget = normalizeCanonicalPath(targetFile);
  const diffHunks = changeSet?.diffHunks || "";
  const runId = options.runId || crypto.randomUUID();

  // Find file stats in changeSet
  const fileMeta = (changeSet?.files || []).find(f => {
    const p = typeof f === "string" ? f : f?.path;
    return normalizeCanonicalPath(p) === normTarget;
  });

  const actualFilePath = (typeof fileMeta === "string" ? fileMeta : fileMeta?.path) ||
    targetFile.replace(/\\/g, "/").replace(/^\.\//, "");

  const additions = fileMeta?.additions || 0;
  const deletions = fileMeta?.deletions || 0;

  // Extract changed line spans from diff
  const changedSpans = extractChangedLineSpans(diffHunks);

  // Exact-Head file content retrieval:
  // Strictly avoid reading from working tree filesystem!
  let fileContent = options.fileContents?.[actualFilePath] ||
    options.fileContents?.[normTarget] ||
    options.fileContents?.[targetFile] ||
    "";
  const headSha = options.headSha || changeSet?.headSha || changeSet?.repository?.headSha || null;
  const repoRoot = options.repositoryRoot || changeSet?.repository?.root || null;

  if (!fileContent && repoRoot && headSha) {
    fileContent = getExactHeadFileContent(repoRoot, headSha, actualFilePath) ||
      getExactHeadFileContent(repoRoot, headSha, normTarget) ||
      "";
  }

  // Extract layers
  const rawLayer0 = {
    rawHunks: diffHunks,
    byteLength: Buffer.byteLength(diffHunks, "utf8"),
    additions,
    deletions
  };

  const rawLayer1 = extractAstEnclosures(fileContent, changedSpans);
  const { callees, unresolvedCallees, contextGaps } = extractLocalCalleeContext(
    fileContent,
    diffHunks,
    actualFilePath,
    options
  );

  rawLayer1.callees = callees;
  rawLayer1.unresolvedCallees = unresolvedCallees;

  const rawLayer2 = extractModuleScope(fileContent);
  const rawLayer3 = extractCallGraphContext(fileContent, normTarget, options.fileContents || {});

  // Apply budgeting
  const budgeted = allocateContextBudget({
    layer0Diff: rawLayer0,
    layer1AstEnclosure: rawLayer1,
    layer2ModuleScope: rawLayer2,
    layer3CallGraph: rawLayer3
  }, options.budgetConfig || DEFAULT_BUDGET_CONFIG);

  const contentDigest = crypto.createHash("sha256").update(diffHunks).digest("hex");

  // Check Windows Safe Argv requirement
  const isWindows = process.platform === "win32";
  const requiresStdin = isWindows && (budgeted.budgetAccounting.consumedBytes > SAFE_ARGV_THRESHOLD_BYTES);

  return {
    schemaVersion: "1.0.0",
    runId,
    targetFile: normTarget,
    ...(headSha ? { headSha } : {}),
    scopeMode: changeSet?.scopeMode || "working-tree",
    contentDigest,
    layers: budgeted.layers,
    contextGaps,
    budgetAccounting: budgeted.budgetAccounting,
    transportPlan: {
      isWindows,
      requiresStdin,
      safeArgvThresholdBytes: SAFE_ARGV_THRESHOLD_BYTES
    }
  };
}
