/**
 * Triad-Flow Semantic Parser Adapter Architecture (M3 / v2.5)
 *
 * Implements Layer 2 Pluggable Semantic & AST Analysis for Anti-Evasion Guard.
 *
 * Governing Invariant:
 * "Optional capability must never silently become trusted authority."
 *
 * Architecture:
 * BaseAstAdapter
 *  ├─ BuiltinSemanticAdapter
 *  │    analysisKind = "structural-semantic"
 *  │    astBacked = false
 *  │    authority = "additive"
 *  │
 *  ├─ AcornAstAdapter
 *  │    analysisKind = "ast"
 *  │    astBacked = true
 *  │    authority = "additive"
 *  │
 *  └─ BabelAstAdapter
 *       analysisKind = "ast"
 *       astBacked = true
 *       authority = "additive"
 */

import { createRequire } from "node:module";
import { BaseAstAdapter, EVASION_VIOLATION_TYPES } from "./anti-evasion-guard.mjs";

export const AST_ADAPTER_NAMES = Object.freeze({
  NONE: "none",
  BUILTIN: "builtin",
  ACORN: "acorn",
  BABEL: "babel",
  AUTO: "auto"
});

/**
 * Thrown when an explicitly requested AST adapter is unavailable in the environment.
 * Enforces Fail-Closed semantics: no silent downgrade to builtin when a specific AST engine was requested.
 */
export class AstAdapterUnavailableError extends Error {
  constructor(message, adapterName) {
    super(message);
    this.name = "AstAdapterUnavailableError";
    this.adapterName = adapterName;
  }
}

/**
 * Zero-dependency Builtin Semantic Adapter.
 * Performs structural, token-aware semantic analysis on unified diffs.
 * Truthfully reports analysisKind = "structural-semantic" and astBacked = false.
 */
export class BuiltinSemanticAdapter extends BaseAstAdapter {
  constructor(options = {}) {
    super("builtin-semantic");
    this.analysisKind = "structural-semantic";
    this.authority = "additive";
    this.engine = "builtin";
    this.astBacked = false;
    this.options = options;
  }

  /**
   * Truthful capability probe.
   * @returns {{ name: string, available: boolean, analysisKind: string, engine: string, engineVersion: string, astBacked: boolean, authority: string, reason: string | null }}
   */
  probe() {
    return {
      name: this.name,
      available: true,
      analysisKind: this.analysisKind,
      engine: this.engine,
      engineVersion: process.version,
      astBacked: this.astBacked,
      authority: this.authority,
      reason: null
    };
  }

  /**
   * Parses unified diff lines and extracts added code statements.
   * @param {string} diffText
   * @returns {{ addedLines: string[], deletedLines: string[] }}
   */
  _extractLines(diffText) {
    const addedLines = [];
    const deletedLines = [];
    const lines = diffText.split(/\r?\n/);
    for (const line of lines) {
      if (line.startsWith("+++") || line.startsWith("---")) continue;
      if (line.startsWith("+")) {
        addedLines.push(line.slice(1));
      } else if (line.startsWith("-")) {
        deletedLines.push(line.slice(1));
      }
    }
    return { addedLines, deletedLines };
  }

  /**
   * Analyzes context for semantic anti-evasion violations.
   *
   * @param {{ diff: string, targetFile?: string, preCode?: string, postCode?: string }} context
   * @returns {{ ok: boolean, violations: Array<{ type: string, description: string, line?: string }>, capabilityReceipt: object }}
   */
  analyze(context = {}) {
    const diffText = context.diff || "";
    const violations = [];

    if (!diffText.trim()) {
      return {
        ok: true,
        violations: [],
        capabilityReceipt: {
          adapterName: this.name,
          analysisKind: this.analysisKind,
          astBacked: this.astBacked,
          verified: true,
          status: "verified"
        }
      };
    }

    const { addedLines, deletedLines } = this._extractLines(diffText);

    // 1. Ternary and Constant Condition Branch Bypasses
    // Examples: `const x = true ? val : fallback;`, `return false ? a : b;`, `if (true)`, `while (false)`
    const CONSTANT_BRANCH_PATTERNS = [
      {
        pattern: /\b(?:true|false|!0|!1)\s*\?/,
        description: "Structural-semantic analysis detected ternary constant condition bypass."
      },
      {
        pattern: /\b(?:if|while)\s*\(\s*(?:true|false|!0|!1|1|0)\s*\)/,
        description: "Structural-semantic analysis detected constant conditional branch bypass."
      }
    ];

    for (const line of addedLines) {
      const trimmed = line.trim();
      // Skip pure comments
      if (trimmed.startsWith("//") || trimmed.startsWith("/*") || trimmed.startsWith("*")) continue;

      for (const rule of CONSTANT_BRANCH_PATTERNS) {
        if (rule.pattern.test(trimmed)) {
          violations.push({
            type: EVASION_VIOLATION_TYPES.AST_SEMANTIC_VIOLATION,
            description: rule.description,
            line: trimmed
          });
        }
      }
    }

    // 2. Empty or Comment-Only Catch Block Swallowing
    // Check single-line or aggregated block additions
    const combinedAdded = addedLines.join("\n");
    const EMPTY_CATCH_REGEX = /\bcatch\s*(?:\([^)]*\))?\s*\{\s*(?:\/\/[^\n]*|\/\*[\s\S]*?\*\/)*\s*\}/g;
    let match;
    while ((match = EMPTY_CATCH_REGEX.exec(combinedAdded)) !== null) {
      violations.push({
        type: EVASION_VIOLATION_TYPES.AST_SEMANTIC_VIOLATION,
        description: "Structural-semantic analysis detected empty catch block swallowing errors.",
        line: match[0].slice(0, 80)
      });
    }

    // 3. Security Call Weakening (evidence-bounded)
    const SECURITY_CALL_REGEX = /\b(?:jwt\.verify|validateToken|checkPermission|sanitizeInput|verifySignature)\s*\(/;
    if (typeof context.preCode === "string" && typeof context.postCode === "string") {
      const preMatches = (context.preCode.match(new RegExp(SECURITY_CALL_REGEX, "g")) || []).length;
      const postMatches = (context.postCode.match(new RegExp(SECURITY_CALL_REGEX, "g")) || []).length;
      if (preMatches > 0 && postMatches === 0) {
        violations.push({
          type: EVASION_VIOLATION_TYPES.AST_SEMANTIC_VIOLATION,
          description: "Structural-semantic analysis detected removal or complete elimination of security validation calls."
        });
      }
    } else {
      // In diff-only mode: check deleted lines vs added lines for security validation call removal
      const deletedHasSecurity = deletedLines.some(l => SECURITY_CALL_REGEX.test(l));
      const addedHasSecurity = addedLines.some(l => SECURITY_CALL_REGEX.test(l));
      if (deletedHasSecurity && !addedHasSecurity) {
        violations.push({
          type: EVASION_VIOLATION_TYPES.AST_SEMANTIC_VIOLATION,
          description: "Structural-semantic analysis detected removal of security validation call without affirmative replacement."
        });
      }
    }

    return {
      ok: violations.length === 0,
      violations,
      capabilityReceipt: {
        adapterName: this.name,
        analysisKind: this.analysisKind,
        astBacked: this.astBacked,
        verified: true,
        status: "verified"
      }
    };
  }
}

/**
 * Traverses an ESTree or Babel AST recursively.
 * @param {object} node
 * @param {(node: object) => void} visitor
 */
export function traverseAst(node, visitor) {
  if (!node || typeof node !== "object") return;
  visitor(node);
  for (const key of Object.keys(node)) {
    if (key === "parent" || key === "loc" || key === "range" || key === "comments" || key === "tokens") continue;
    const child = node[key];
    if (Array.isArray(child)) {
      for (const item of child) traverseAst(item, visitor);
    } else if (child && typeof child === "object" && typeof child.type === "string") {
      traverseAst(child, visitor);
    }
  }
}

/**
 * Checks whether an AST test expression represents a constant boolean condition.
 * @param {object} testNode
 * @returns {boolean}
 */
export function isAstConstantCondition(testNode) {
  if (!testNode) return false;
  // ESTree: Literal (boolean, 0, or 1)
  if (testNode.type === "Literal") {
    return typeof testNode.value === "boolean" || testNode.value === 0 || testNode.value === 1;
  }
  // Babel: BooleanLiteral, NumericLiteral
  if (testNode.type === "BooleanLiteral") return true;
  if (testNode.type === "NumericLiteral" && (testNode.value === 0 || testNode.value === 1)) return true;
  // Unary !0, !1, !true, !false
  if (testNode.type === "UnaryExpression" && testNode.operator === "!") {
    return isAstConstantCondition(testNode.argument);
  }
  return false;
}

/**
 * Base class for external AST parsers (Acorn, Babel, etc.) loaded dynamically.
 */
export class ExternalAstAdapter extends BaseAstAdapter {
  constructor(name, moduleName, options = {}) {
    super(name);
    this.moduleName = moduleName;
    this.analysisKind = "ast";
    this.authority = "additive";
    this.engine = moduleName;
    this.astBacked = true;
    this.options = options;
    this._probeResult = null;
    this._parserInstance = options.parserModule || null;
  }

  /**
   * Probes environment for optional module presence without throwing.
   */
  probe() {
    if (this._probeResult) return this._probeResult;

    if (this.options.parserModule) {
      this._probeResult = {
        name: this.name,
        available: true,
        analysisKind: this.analysisKind,
        engine: this.engine,
        engineVersion: this.options.parserVersion || "mock-1.0.0",
        astBacked: this.astBacked,
        authority: this.authority,
        reason: null
      };
      return this._probeResult;
    }

    const require = createRequire(import.meta.url);
    let available = false;
    let engineVersion = null;
    let reason = null;

    try {
      require.resolve(this.moduleName);
      available = true;
      try {
        const pkgPath = require.resolve(`${this.moduleName}/package.json`);
        const pkg = require(pkgPath);
        engineVersion = pkg.version || "unknown";
      } catch {
        engineVersion = "installed";
      }
    } catch {
      available = false;
      reason = `Optional AST parser module '${this.moduleName}' is not installed in environment.`;
    }

    this._probeResult = {
      name: this.name,
      available,
      analysisKind: this.analysisKind,
      engine: this.engine,
      engineVersion,
      astBacked: this.astBacked,
      authority: this.authority,
      reason
    };

    return this._probeResult;
  }

  /**
   * Loads parser module instance dynamically.
   * @returns {object}
   */
  _loadParser() {
    if (this._parserInstance) return this._parserInstance;
    const probe = this.probe();
    if (!probe.available) {
      throw new AstAdapterUnavailableError(probe.reason, this.name);
    }
    const require = createRequire(import.meta.url);
    this._parserInstance = require(this.moduleName);
    return this._parserInstance;
  }

  /**
   * Parses code into AST. Must be implemented by concrete subclasses or custom parseFn.
   * @param {string} code
   * @param {string} [filename]
   * @returns {object}
   */
  parse(code, filename) {
    if (typeof this.options.parseFn === "function") {
      return this.options.parseFn(code, filename);
    }
    const parser = this._loadParser();
    if (typeof parser.parse === "function") {
      return parser.parse(code, { ecmaVersion: "latest", sourceType: "module", locations: true });
    }
    throw new Error(`[ExternalAstAdapter] '${this.name}' does not provide a valid parse() method.`);
  }

  /**
   * Traverses AST and collects semantic violations on AST nodes.
   * @param {object} ast
   * @param {Array<object>} violations
   */
  _checkAstNodes(ast, violations) {
    traverseAst(ast, (node) => {
      // 1. AST Constant conditional branch bypass: if(true), while(false), do...while(false)
      if (node.type === "IfStatement" || node.type === "WhileStatement" || node.type === "DoWhileStatement") {
        if (isAstConstantCondition(node.test)) {
          violations.push({
            type: EVASION_VIOLATION_TYPES.AST_SEMANTIC_VIOLATION,
            description: `AST analysis detected constant conditional branch bypass in ${node.type}.`,
            nodeType: node.type
          });
        }
      }

      // 2. AST Ternary constant condition: true ? a : b
      if (node.type === "ConditionalExpression") {
        if (isAstConstantCondition(node.test)) {
          violations.push({
            type: EVASION_VIOLATION_TYPES.AST_SEMANTIC_VIOLATION,
            description: "AST analysis detected ternary constant condition bypass.",
            nodeType: node.type
          });
        }
      }

      // 3. AST Empty Catch block swallowing errors
      if (node.type === "CatchClause") {
        if (node.body && node.body.type === "BlockStatement" && Array.isArray(node.body.body)) {
          if (node.body.body.length === 0) {
            violations.push({
              type: EVASION_VIOLATION_TYPES.AST_SEMANTIC_VIOLATION,
              description: "AST analysis detected empty catch block swallowing errors.",
              nodeType: node.type
            });
          }
        }
      }
    });
  }

  /**
   * Performs real AST analysis if engine is available; otherwise reports honest unavailability.
   *
   * @param {{ diff?: string, targetFile?: string, preCode?: string, postCode?: string, code?: string }} context
   * @returns {{ ok: boolean, violations: Array<object>, capabilityReceipt: object }}
   */
  analyze(context = {}) {
    const probe = this.probe();
    if (!probe.available) {
      return {
        ok: true,
        violations: [],
        capabilityReceipt: {
          adapterName: this.name,
          analysisKind: this.analysisKind,
          astBacked: this.astBacked,
          verified: false,
          status: "unavailable",
          reason: probe.reason
        }
      };
    }

    let codeToParse = "";
    if (typeof context.postCode === "string") {
      codeToParse = context.postCode;
    } else if (typeof context.code === "string") {
      codeToParse = context.code;
    } else if (typeof context.diff === "string") {
      const addedLines = [];
      for (const line of context.diff.split(/\r?\n/)) {
        if (line.startsWith("+++") || line.startsWith("---")) continue;
        if (line.startsWith("+")) addedLines.push(line.slice(1));
      }
      codeToParse = addedLines.join("\n");
    }

    if (!codeToParse.trim()) {
      return {
        ok: true,
        violations: [],
        capabilityReceipt: {
          adapterName: this.name,
          analysisKind: this.analysisKind,
          astBacked: this.astBacked,
          verified: true,
          status: "verified"
        }
      };
    }

    let ast;
    try {
      ast = this.parse(codeToParse, context.targetFile);
    } catch (err) {
      if (this.options.required !== false) {
        throw new AstAdapterUnavailableError(
          `AST Parser failed during analysis of '${context.targetFile || "patch"}': ${err.message}`,
          this.name
        );
      }
      return {
        ok: false,
        violations: [{
          type: EVASION_VIOLATION_TYPES.AST_SEMANTIC_VIOLATION,
          description: `AST Parser failed: ${err.message}`
        }],
        capabilityReceipt: {
          adapterName: this.name,
          analysisKind: this.analysisKind,
          astBacked: true,
          verified: false,
          status: "incomplete",
          reason: err.message
        }
      };
    }

    const violations = [];
    this._checkAstNodes(ast, violations);

    return {
      ok: violations.length === 0,
      violations,
      capabilityReceipt: {
        adapterName: this.name,
        analysisKind: this.analysisKind,
        astBacked: true,
        verified: true,
        status: "verified"
      }
    };
  }
}

export class AcornAstAdapter extends ExternalAstAdapter {
  constructor(options = {}) {
    super("acorn-ast", "acorn", options);
  }

  parse(code, filename) {
    if (typeof this.options.parseFn === "function") {
      return this.options.parseFn(code, filename);
    }
    const acorn = this._loadParser();
    try {
      return acorn.parse(code, { ecmaVersion: "latest", sourceType: "module", locations: true });
    } catch {
      return acorn.parse(code, { ecmaVersion: "latest", sourceType: "script", locations: true });
    }
  }
}

export class BabelAstAdapter extends ExternalAstAdapter {
  constructor(options = {}) {
    super("babel-ast", "@babel/parser", options);
  }

  parse(code, filename) {
    if (typeof this.options.parseFn === "function") {
      return this.options.parseFn(code, filename);
    }
    const babel = this._loadParser();
    const parseFn = babel.parse || babel.default?.parse || babel;
    return parseFn(code, { sourceType: "unambiguous", plugins: ["typescript", "jsx"] });
  }
}

/**
 * Resolves requested AST adapter with explicit vs auto probe separation.
 *
 * Rules:
 * 1. resolveAstAdapter("babel") -> Babel missing -> throws AstAdapterUnavailableError (Fail-Closed).
 * 2. resolveAstAdapter("acorn") -> Acorn missing -> throws AstAdapterUnavailableError (Fail-Closed).
 * 3. resolveAstAdapter("builtin") -> BuiltinSemanticAdapter (Zero-dependency, structural-semantic).
 * 4. resolveAstAdapter("auto") -> Probes Babel, then Acorn; if none installed, falls back to BuiltinSemanticAdapter
 *    without throwing and reports truthful capabilities.
 * 5. resolveAstAdapter("none") -> Returns null.
 *
 * @param {string} [name="builtin"]
 * @param {object} [options]
 * @param {boolean} [options.required]
 * @param {boolean} [options.preferAstOnly]
 * @returns {BaseAstAdapter | null}
 */
export function resolveAstAdapter(name = "builtin", options = {}) {
  const norm = String(name || "builtin").trim().toLowerCase();

  if (norm === AST_ADAPTER_NAMES.NONE || norm === "off" || norm === "false") {
    return null;
  }

  if (norm === AST_ADAPTER_NAMES.BUILTIN || norm === "default") {
    return new BuiltinSemanticAdapter(options);
  }

  if (norm === AST_ADAPTER_NAMES.ACORN) {
    const adapter = new AcornAstAdapter(options);
    const probe = adapter.probe();
    if (!probe.available && options.required !== false) {
      throw new AstAdapterUnavailableError(
        `Requested AST adapter '${name}' is unavailable: ${probe.reason} Silent fallback is prohibited by governing invariant.`,
        name
      );
    }
    return adapter;
  }

  if (norm === AST_ADAPTER_NAMES.BABEL) {
    const adapter = new BabelAstAdapter(options);
    const probe = adapter.probe();
    if (!probe.available && options.required !== false) {
      throw new AstAdapterUnavailableError(
        `Requested AST adapter '${name}' is unavailable: ${probe.reason} Silent fallback is prohibited by governing invariant.`,
        name
      );
    }
    return adapter;
  }

  if (norm === AST_ADAPTER_NAMES.AUTO) {
    // 1. Proactively probe optional true AST engines
    const babel = new BabelAstAdapter(options);
    if (babel.probe().available) return babel;

    const acorn = new AcornAstAdapter(options);
    if (acorn.probe().available) return acorn;

    // 2. If caller requested strict AST-only (preferAstOnly), return unavailable external adapter without throwing
    if (options.preferAstOnly) {
      return babel;
    }

    // 3. Fallback to zero-dependency structural-semantic adapter with honest capability metadata
    return new BuiltinSemanticAdapter(options);
  }

  throw new Error(`Unsupported AST adapter: '${name}'. Supported: 'builtin', 'acorn', 'babel', 'auto', 'none'.`);
}
