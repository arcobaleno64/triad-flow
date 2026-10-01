/**
 * Triad-Flow Review Context & AST Enclosure Builder (RFC-027-01)
 *
 * Implements zero-dependency, 4-layer context extraction, deterministic byte budgeting,
 * and Windows ARG_MAX safe transport planning.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { normalizeCanonicalPath } from "./scoring.mjs";

export const SAFE_ARGV_THRESHOLD_BYTES = 8192;

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
 * @param {string[]} lines
 * @param {number} startIndex
 * @returns {number} 1-indexed end line
 */
function findBraceScopeEnd(lines, startIndex) {
  let depth = 0;
  let started = false;

  for (let i = startIndex; i < lines.length; i++) {
    const line = lines[i];
    for (let charIdx = 0; charIdx < line.length; charIdx++) {
      const c = line[charIdx];
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
  let layer1 = rawLayers.layer1AstEnclosure || { adapterName: "builtin-semantic", enclosingFunctions: [], enclosingClasses: [] };
  let layer1Json = JSON.stringify(layer1);
  let layer1Bytes = Buffer.byteLength(layer1Json, "utf8");
  if (layer1Bytes > budget1) {
    layer1 = {
      ...layer1,
      enclosingFunctions: (layer1.enclosingFunctions || []).map(fn => ({
        ...fn,
        bodySnippet: "/* ... body collapsed for budget ... */"
      })),
      enclosingClasses: (layer1.enclosingClasses || []).slice(0, 2)
    };
    layer1Json = JSON.stringify(layer1);
    layer1Bytes = Buffer.byteLength(layer1Json, "utf8");
    if (layer1Bytes > budget1) {
      evictedLayers.push("layer1AstEnclosure");
      layer1 = { adapterName: "builtin-semantic", enclosingFunctions: [], enclosingClasses: [] };
      layer1Bytes = 0;
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
    const p = typeof f === "string" ? f : f.path;
    return normalizeCanonicalPath(p) === normTarget;
  });

  const additions = fileMeta?.additions || 0;
  const deletions = fileMeta?.deletions || 0;

  // Extract changed line spans from diff
  const changedSpans = extractChangedLineSpans(diffHunks);

  // Read or obtain target file source code if provided in options or readable from disk
  let fileContent = options.fileContents?.[normTarget] || "";
  if (!fileContent && options.repositoryRoot && fs.existsSync(path.join(options.repositoryRoot, normTarget))) {
    try {
      fileContent = fs.readFileSync(path.join(options.repositoryRoot, normTarget), "utf8");
    } catch {
      fileContent = "";
    }
  }

  // Extract layers
  const rawLayer0 = {
    rawHunks: diffHunks,
    byteLength: Buffer.byteLength(diffHunks, "utf8"),
    additions,
    deletions
  };

  const rawLayer1 = extractAstEnclosures(fileContent, changedSpans);
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
    scopeMode: changeSet?.scopeMode || "working-tree",
    contentDigest,
    layers: budgeted.layers,
    budgetAccounting: budgeted.budgetAccounting,
    transportPlan: {
      isWindows,
      requiresStdin,
      safeArgvThresholdBytes: SAFE_ARGV_THRESHOLD_BYTES
    }
  };
}
