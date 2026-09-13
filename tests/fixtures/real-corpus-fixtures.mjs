/**
 * Triad-Flow Real Benchmark Corpus v0 (TF-RBC-v0) Fixtures & Workspace Generator
 *
 * Implements 15 frozen, human-adjudicated real-world code cases across risk tiers
 * aligned with docs/real-benchmark-corpus-v0.md:
 * - 12 Vulnerable cases (Tier 1 OWASP/CWE security defects with ground-truth labels)
 * - 3 Clean negative control cases (Tier 2/3 refactors, algorithms, documentation)
 *
 * Provides isolated disposable Git workspace generation and mock adapter simulation.
 */

import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { assertRepoImmutability } from "./disposable-pilot-repo.mjs";
import { buildChangeSet } from "../../src/core/git-collector.mjs";
import { CliReviewAdapter } from "../../src/adapters/cli-transport.mjs";
import { normalizeCanonicalPath } from "../../src/core/scoring.mjs";

export { assertRepoImmutability };

/**
 * 15 Frozen Human-Adjudicated Real Benchmark Corpus Cases (TF-RBC-v0)
 */
export const TF_RBC_V0_CASES = Object.freeze([
  // 1. BENCH-REAL-001: SQL Injection
  {
    id: "BENCH-REAL-001",
    title: "SQL Injection in User Query Handler",
    riskTier: 1,
    category: "vulnerable",
    targetFile: "src/db/user-repo.js",
    description: "Raw string concatenation in SQL user lookup allowing arbitrary query execution",
    expectedGateDecision: "block",
    lineTolerance: 50,
    goldenFindings: [
      {
        cwe: "CWE-89",
        type: "sql-injection",
        file: "src/db/user-repo.js",
        line: 8,
        severity: "critical",
        rationale: "Direct SQL query concatenation with user-supplied parameter allows arbitrary SQL injection"
      }
    ],
    baseFiles: {
      "src/db/user-repo.js": [
        "export class UserRepository {",
        "  constructor(db) {",
        "    this.db = db;",
        "  }",
        "",
        "  async findUserById(id) {",
        "    // Safe parameterized query",
        "    const query = \"SELECT id, username, email FROM users WHERE id = ?\";",
        "    return this.db.query(query, [id]);",
        "  }",
        "}",
        ""
      ].join("\n")
    },
    headFiles: {
      "src/db/user-repo.js": [
        "export class UserRepository {",
        "  constructor(db) {",
        "    this.db = db;",
        "  }",
        "",
        "  async findUserById(id) {",
        "    // Vulnerable raw string concatenation",
        "    const query = \"SELECT id, username, email FROM users WHERE id = '\" + id + \"'\";",
        "    return this.db.query(query);",
        "  }",
        "}",
        ""
      ].join("\n")
    }
  },

  // 2. BENCH-REAL-002: Hardcoded Secret & Verification Bypass
  {
    id: "BENCH-REAL-002",
    title: "Hardcoded JWT Secret and Verification Bypass",
    riskTier: 1,
    category: "vulnerable",
    targetFile: "src/auth/jwt-service.js",
    description: "Hardcoded JWT signing secret and skipped signature verification",
    expectedGateDecision: "block",
    lineTolerance: 50,
    goldenFindings: [
      {
        cwe: "CWE-798",
        type: "hardcoded-credentials",
        file: "src/auth/jwt-service.js",
        line: 1,
        severity: "critical",
        rationale: "Hardcoded secret key embedded in source and bypassed signature verification"
      }
    ],
    baseFiles: {
      "src/auth/jwt-service.js": [
        "import jwt from \"jsonwebtoken\";",
        "",
        "export function verifySessionToken(token) {",
        "  const secret = process.env.JWT_SIGNING_SECRET;",
        "  if (!secret) throw new Error(\"JWT_SIGNING_SECRET not configured\");",
        "  return jwt.verify(token, secret);",
        "}",
        ""
      ].join("\n")
    },
    headFiles: {
      "src/auth/jwt-service.js": [
        "const JWT_SECRET = \"super_secret_jwt_token_key_123456789_triad_pilot\";",
        "",
        "export function verifySessionToken(token) {",
        "  // CWE-798 / CWE-347: Hardcoded cryptographic key and unverified token decode",
        "  const parts = token.split(\".\");",
        "  if (parts.length !== 3) throw new Error(\"Invalid token format\");",
        "  return JSON.parse(Buffer.from(parts[1], \"base64\").toString(\"utf8\"));",
        "}",
        ""
      ].join("\n")
    }
  },

  // 3. BENCH-REAL-003: Path Traversal
  {
    id: "BENCH-REAL-003",
    title: "Path Traversal in File Fetcher",
    riskTier: 1,
    category: "vulnerable",
    targetFile: "src/storage/file-fetcher.js",
    description: "Path traversal via unsanitized filename input allowing arbitrary file reads",
    expectedGateDecision: "block",
    lineTolerance: 50,
    goldenFindings: [
      {
        cwe: "CWE-22",
        type: "path-traversal",
        file: "src/storage/file-fetcher.js",
        line: 6,
        severity: "critical",
        rationale: "Unsanitized path concatenation allows directory traversal outside storage root"
      }
    ],
    baseFiles: {
      "src/storage/file-fetcher.js": [
        "import fs from \"node:fs/promises\";",
        "import path from \"node:path\";",
        "",
        "export async function readStorageFile(baseDir, userInputFilename) {",
        "  const safeName = path.basename(userInputFilename);",
        "  const target = path.resolve(baseDir, safeName);",
        "  if (!target.startsWith(path.resolve(baseDir))) {",
        "    throw new Error(\"Access denied: path traversal detected\");",
        "  }",
        "  return fs.readFile(target, \"utf8\");",
        "}",
        ""
      ].join("\n")
    },
    headFiles: {
      "src/storage/file-fetcher.js": [
        "import fs from \"node:fs/promises\";",
        "import path from \"node:path\";",
        "",
        "export async function readStorageFile(baseDir, userInputFilename) {",
        "  // CWE-22: Unchecked path.join allows directory traversal via ../",
        "  const target = path.join(baseDir, userInputFilename);",
        "  return fs.readFile(target, \"utf8\");",
        "}",
        ""
      ].join("\n")
    }
  },

  // 4. BENCH-REAL-004: DOM/Stored XSS
  {
    id: "BENCH-REAL-004",
    title: "Stored and DOM XSS in Profile Render",
    riskTier: 1,
    category: "vulnerable",
    targetFile: "src/views/profile-render.js",
    description: "Unescaped innerHTML insertion in client-side renderer allowing XSS",
    expectedGateDecision: "block",
    lineTolerance: 50,
    goldenFindings: [
      {
        cwe: "CWE-79",
        type: "cross-site-scripting",
        file: "src/views/profile-render.js",
        line: 3,
        severity: "high",
        rationale: "Direct assignment of untrusted user input to innerHTML permits script execution"
      }
    ],
    baseFiles: {
      "src/views/profile-render.js": [
        "export function renderUserProfile(container, user) {",
        "  const bioElement = document.createElement(\"div\");",
        "  bioElement.className = \"user-bio\";",
        "  bioElement.textContent = user.bio || \"\";",
        "  container.appendChild(bioElement);",
        "}",
        ""
      ].join("\n")
    },
    headFiles: {
      "src/views/profile-render.js": [
        "export function renderUserProfile(container, user) {",
        "  // CWE-79: Cross-site scripting via unescaped innerHTML insertion",
        "  container.innerHTML = `<div class=\"user-bio\">${user.bio || \"\"}</div>`;",
        "}",
        ""
      ].join("\n")
    }
  },

  // 5. BENCH-REAL-005: IDOR / Broken Access Control
  {
    id: "BENCH-REAL-005",
    title: "IDOR in Invoice Handler",
    riskTier: 1,
    category: "vulnerable",
    targetFile: "src/api/invoice-handler.js",
    description: "Insecure Direct Object Reference (missing tenant authorization check)",
    expectedGateDecision: "block",
    lineTolerance: 50,
    goldenFindings: [
      {
        cwe: "CWE-639",
        type: "insecure-direct-object-reference",
        file: "src/api/invoice-handler.js",
        line: 4,
        severity: "high",
        rationale: "Missing tenant ownership verification allows unauthorized access to arbitrary invoices"
      }
    ],
    baseFiles: {
      "src/api/invoice-handler.js": [
        "export async function getInvoice(req, res, db) {",
        "  const { invoiceId } = req.params;",
        "  const currentTenantId = req.user.tenantId;",
        "",
        "  const invoice = await db.invoices.findById(invoiceId);",
        "  if (!invoice || invoice.tenantId !== currentTenantId) {",
        "    return res.status(403).json({ error: \"Access denied\" });",
        "  }",
        "  return res.json(invoice);",
        "}",
        ""
      ].join("\n")
    },
    headFiles: {
      "src/api/invoice-handler.js": [
        "export async function getInvoice(req, res, db) {",
        "  const { invoiceId } = req.params;",
        "  // CWE-639: Removed tenant check, allowing any user to view any invoice",
        "  const invoice = await db.invoices.findById(invoiceId);",
        "  if (!invoice) return res.status(404).json({ error: \"Not found\" });",
        "  return res.json(invoice);",
        "}",
        ""
      ].join("\n")
    }
  },

  // 6. BENCH-REAL-006: Server-Side Request Forgery (SSRF)
  {
    id: "BENCH-REAL-006",
    title: "SSRF via Webhook Dispatcher",
    riskTier: 1,
    category: "vulnerable",
    targetFile: "src/webhook/dispatcher.js",
    description: "Server-Side Request Forgery via unfiltered outbound webhook URL",
    expectedGateDecision: "block",
    lineTolerance: 50,
    goldenFindings: [
      {
        cwe: "CWE-918",
        type: "server-side-request-forgery",
        file: "src/webhook/dispatcher.js",
        line: 3,
        severity: "critical",
        rationale: "Unfiltered outbound HTTP requests to user-controlled URLs permit SSRF to internal network"
      }
    ],
    baseFiles: {
      "src/webhook/dispatcher.js": [
        "import { isPublicIp } from \"./network-validator.js\";",
        "",
        "export async function dispatchWebhook(targetUrl, payload) {",
        "  const url = new URL(targetUrl);",
        "  if (url.protocol !== \"https:\") throw new Error(\"Only HTTPS allowed\");",
        "  if (!await isPublicIp(url.hostname)) throw new Error(\"Private IP rejected\");",
        "  return fetch(targetUrl, { method: \"POST\", body: JSON.stringify(payload) });",
        "}",
        ""
      ].join("\n")
    },
    headFiles: {
      "src/webhook/dispatcher.js": [
        "export async function dispatchWebhook(targetUrl, payload) {",
        "  // CWE-918: Unrestricted outbound fetch to arbitrary user-supplied target URL",
        "  return fetch(targetUrl, {",
        "    method: \"POST\",",
        "    headers: { \"Content-Type\": \"application/json\" },",
        "    body: JSON.stringify(payload)",
        "  });",
        "}",
        ""
      ].join("\n")
    }
  },

  // 7. BENCH-REAL-007: OS Command Injection
  {
    id: "BENCH-REAL-007",
    title: "OS Command Injection via Exec",
    riskTier: 1,
    category: "vulnerable",
    targetFile: "src/tools/pdf-generator.js",
    description: "OS Command injection via child_process.exec with unsanitized arguments",
    expectedGateDecision: "block",
    lineTolerance: 50,
    goldenFindings: [
      {
        cwe: "CWE-78",
        type: "command-injection",
        file: "src/tools/pdf-generator.js",
        line: 8,
        severity: "critical",
        rationale: "Passing unsanitized user arguments directly to child_process.exec allows OS command injection"
      }
    ],
    baseFiles: {
      "src/tools/pdf-generator.js": [
        "import { execFile } from \"node:child_process\";",
        "import { promisify } from \"node:util\";",
        "",
        "const execFileAsync = promisify(execFile);",
        "",
        "export async function generatePdf(inputFile, outputFile) {",
        "  return execFileAsync(\"pandoc\", [inputFile, \"-o\", outputFile]);",
        "}",
        ""
      ].join("\n")
    },
    headFiles: {
      "src/tools/pdf-generator.js": [
        "import { exec } from \"node:child_process\";",
        "import { promisify } from \"node:util\";",
        "",
        "const execAsync = promisify(exec);",
        "",
        "export async function generatePdf(inputFile, outputFile) {",
        "  // CWE-78: Unescaped string passed to shell execution",
        "  const command = `pandoc ${inputFile} -o ${outputFile}`;",
        "  return execAsync(command);",
        "}",
        ""
      ].join("\n")
    }
  },

  // 8. BENCH-REAL-008: Deserialization of Untrusted Data
  {
    id: "BENCH-REAL-008",
    title: "Deserialization of Untrusted Data",
    riskTier: 1,
    category: "vulnerable",
    targetFile: "src/cache/session-store.js",
    description: "Unsafe evaluation/deserialization of untrusted session payload",
    expectedGateDecision: "block",
    lineTolerance: 50,
    goldenFindings: [
      {
        cwe: "CWE-502",
        type: "deserialization",
        file: "src/cache/session-store.js",
        line: 4,
        severity: "critical",
        rationale: "Deserialization of untrusted data via eval permits arbitrary code execution"
      }
    ],
    baseFiles: {
      "src/cache/session-store.js": [
        "export function deserializeSession(serializedData) {",
        "  if (!serializedData) return null;",
        "  return JSON.parse(serializedData);",
        "}",
        ""
      ].join("\n")
    },
    headFiles: {
      "src/cache/session-store.js": [
        "export function deserializeSession(serializedData) {",
        "  if (!serializedData) return null;",
        "  // CWE-502: Unsafe deserialization using eval on serialized payload",
        "  return eval(`(${serializedData})`);",
        "}",
        ""
      ].join("\n")
    }
  },

  // 9. BENCH-REAL-009: Missing Rate Limiting / Brute Force
  {
    id: "BENCH-REAL-009",
    title: "Authentication Bypass via Disabled Rate Limiter",
    riskTier: 1,
    category: "vulnerable",
    targetFile: "src/auth/login-limiter.js",
    description: "Authentication bypass via disabled brute-force limiter",
    expectedGateDecision: "block",
    lineTolerance: 50,
    goldenFindings: [
      {
        cwe: "CWE-307",
        type: "authentication",
        file: "src/auth/login-limiter.js",
        line: 8,
        severity: "high",
        rationale: "Disabled rate limiting check permits brute-force credential stuffing"
      }
    ],
    baseFiles: {
      "src/auth/login-limiter.js": [
        "export class LoginRateLimiter {",
        "  constructor(cache) {",
        "    this.cache = cache;",
        "  }",
        "",
        "  async checkLimit(ip, username) {",
        "    const attempts = await this.cache.get(`login:${ip}:${username}`) || 0;",
        "    if (attempts >= 5) {",
        "      throw new Error(\"Too many failed attempts. Account locked.\");",
        "    }",
        "    return true;",
        "  }",
        "}",
        ""
      ].join("\n")
    },
    headFiles: {
      "src/auth/login-limiter.js": [
        "export class LoginRateLimiter {",
        "  constructor(cache) {",
        "    this.cache = cache;",
        "  }",
        "",
        "  async checkLimit(ip, username) {",
        "    // CWE-307: Rate limit check disabled, permitting unlimited password guessing",
        "    if (false) {",
        "      const attempts = await this.cache.get(`login:${ip}:${username}`) || 0;",
        "      if (attempts >= 5) throw new Error(\"Too many attempts\");",
        "    }",
        "    return true;",
        "  }",
        "}",
        ""
      ].join("\n")
    }
  },

  // 10. BENCH-REAL-010: Prototype Pollution
  {
    id: "BENCH-REAL-010",
    title: "Prototype Pollution in Deep Assign",
    riskTier: 1,
    category: "vulnerable",
    targetFile: "src/utils/deep-assign.js",
    description: "Prototype pollution via unfiltered recursive __proto__ property copy",
    expectedGateDecision: "block",
    lineTolerance: 50,
    goldenFindings: [
      {
        cwe: "CWE-1321",
        type: "prototype-pollution",
        file: "src/utils/deep-assign.js",
        line: 4,
        severity: "high",
        rationale: "Unrestricted property assignment allows prototype pollution via __proto__"
      }
    ],
    baseFiles: {
      "src/utils/deep-assign.js": [
        "export function deepMerge(target, source) {",
        "  for (const key of Object.keys(source)) {",
        "    if (key === \"__proto__\" || key === \"constructor\" || key === \"prototype\") {",
        "      continue; // Prevent prototype pollution",
        "    }",
        "    if (source[key] && typeof source[key] === \"object\") {",
        "      target[key] = deepMerge(target[key] || {}, source[key]);",
        "    } else {",
        "      target[key] = source[key];",
        "    }",
        "  }",
        "  return target;",
        "}",
        ""
      ].join("\n")
    },
    headFiles: {
      "src/utils/deep-assign.js": [
        "export function deepMerge(target, source) {",
        "  for (const key of Object.keys(source)) {",
        "    // CWE-1321: Removed prototype protection guard",
        "    if (source[key] && typeof source[key] === \"object\") {",
        "      target[key] = deepMerge(target[key] || {}, source[key]);",
        "    } else {",
        "      target[key] = source[key];",
        "    }",
        "  }",
        "  return target;",
        "}",
        ""
      ].join("\n")
    }
  },

  // 11. BENCH-REAL-011: Race Condition TOCTOU
  {
    id: "BENCH-REAL-011",
    title: "Race Condition (TOCTOU) in Account Balance Debit",
    riskTier: 1,
    category: "vulnerable",
    targetFile: "src/finance/transfer.js",
    description: "Race condition (TOCTOU) in account balance debit allowing double-spending",
    expectedGateDecision: "block",
    lineTolerance: 50,
    goldenFindings: [
      {
        cwe: "CWE-362",
        type: "race-condition",
        file: "src/finance/transfer.js",
        line: 3,
        severity: "high",
        rationale: "Non-atomic check and delayed update creates time-of-check to time-of-use flaw"
      }
    ],
    baseFiles: {
      "src/finance/transfer.js": [
        "export async function debitAccount(db, accountId, amount) {",
        "  return db.transaction(async (tx) => {",
        "    // Atomic conditional update",
        "    const res = await tx.query(",
        "      \"UPDATE accounts SET balance = balance - ? WHERE id = ? AND balance >= ?\",",
        "      [amount, accountId, amount]",
        "    );",
        "    if (res.affectedRows === 0) throw new Error(\"Insufficient funds\");",
        "    return true;",
        "  });",
        "}",
        ""
      ].join("\n")
    },
    headFiles: {
      "src/finance/transfer.js": [
        "export async function debitAccount(db, accountId, amount) {",
        "  // CWE-362: Non-atomic TOCTOU balance check",
        "  const account = await db.query(\"SELECT balance FROM accounts WHERE id = ?\", [accountId]);",
        "  if (account.balance < amount) {",
        "    throw new Error(\"Insufficient funds\");",
        "  }",
        "  // Artificial async delay window opens concurrency race condition",
        "  await new Promise((resolve) => setTimeout(resolve, 50));",
        "  await db.query(\"UPDATE accounts SET balance = balance - ? WHERE id = ?\", [amount, accountId]);",
        "  return true;",
        "}",
        ""
      ].join("\n")
    }
  },

  // 12. BENCH-REAL-012: Timing Attack in HMAC Verification
  {
    id: "BENCH-REAL-012",
    title: "Timing Attack in HMAC Secret Verification",
    riskTier: 1,
    category: "vulnerable",
    targetFile: "src/crypto/hmac-verify.js",
    description: "Non-constant-time secret comparison allowing timing attack for secret recovery",
    expectedGateDecision: "block",
    lineTolerance: 50,
    goldenFindings: [
      {
        cwe: "CWE-208",
        type: "timing-attack",
        file: "src/crypto/hmac-verify.js",
        line: 4,
        severity: "high",
        rationale: "Non-constant-time string comparison allows timing attack for cryptographic secret recovery"
      }
    ],
    baseFiles: {
      "src/crypto/hmac-verify.js": [
        "import crypto from \"node:crypto\";",
        "",
        "export function verifyHmacSignature(signature, expectedSignature) {",
        "  const a = Buffer.from(signature, \"utf8\");",
        "  const b = Buffer.from(expectedSignature, \"utf8\");",
        "  if (a.length !== b.length) return false;",
        "  return crypto.timingSafeEqual(a, b);",
        "}",
        ""
      ].join("\n")
    },
    headFiles: {
      "src/crypto/hmac-verify.js": [
        "export function verifyHmacSignature(signature, expectedSignature) {",
        "  // CWE-208: Early return string comparison leaks timing side-channel",
        "  if (signature.length !== expectedSignature.length) return false;",
        "  return signature === expectedSignature;",
        "}",
        ""
      ].join("\n")
    }
  },

  // 13. BENCH-REAL-013: Clean - Vector Math Algorithmic Optimization
  {
    id: "BENCH-REAL-013",
    title: "Vector Math Algorithmic Optimization",
    riskTier: 2,
    category: "clean",
    targetFile: "src/math/vector-calc.js",
    description: "Algorithmic optimization of vector dot product (inlined allocation-free loop)",
    expectedGateDecision: "approve",
    lineTolerance: 50,
    goldenFindings: [],
    baseFiles: {
      "src/math/vector-calc.js": [
        "export function dotProduct(a, b) {",
        "  if (a.length !== b.length) throw new Error(\"Vectors must have same length\");",
        "  const products = a.map((val, idx) => val * b[idx]);",
        "  return products.reduce((acc, curr) => acc + curr, 0);",
        "}",
        ""
      ].join("\n")
    },
    headFiles: {
      "src/math/vector-calc.js": [
        "export function dotProduct(a, b) {",
        "  if (a.length !== b.length) throw new Error(\"Vectors must have same length\");",
        "  // Clean algorithmic optimization: zero allocation loop",
        "  let sum = 0;",
        "  for (let i = 0; i < a.length; i++) {",
        "    sum += a[i] * b[i];",
        "  }",
        "  return sum;",
        "}",
        ""
      ].join("\n")
    }
  },

  // 14. BENCH-REAL-014: Clean - UI Table Flexbox & CSS Refactor
  {
    id: "BENCH-REAL-014",
    title: "UI Table Flexbox & CSS Refactor",
    riskTier: 2,
    category: "clean",
    targetFile: "src/ui/table-layout.js",
    description: "Pure CSS class names and flexbox formatting updates",
    expectedGateDecision: "approve",
    lineTolerance: 50,
    goldenFindings: [],
    baseFiles: {
      "src/ui/table-layout.js": [
        "export function createTableLayout() {",
        "  return {",
        "    containerClass: \"old-table-container\",",
        "    rowClass: \"old-table-row\",",
        "    cellClass: \"old-table-cell\"",
        "  };",
        "}",
        ""
      ].join("\n")
    },
    headFiles: {
      "src/ui/table-layout.js": [
        "export function createTableLayout() {",
        "  return {",
        "    containerClass: \"ui-flex-table-wrapper display-flex\",",
        "    rowClass: \"ui-flex-row align-items-center\",",
        "    cellClass: \"ui-flex-cell flex-1 p-2\"",
        "  };",
        "}",
        ""
      ].join("\n")
    }
  },

  // 15. BENCH-REAL-015: Clean - Technical Documentation Updates
  {
    id: "BENCH-REAL-015",
    title: "Technical Documentation Updates",
    riskTier: 3,
    category: "clean",
    targetFile: "docs/architecture.md",
    description: "Technical documentation typo fixes and specification clarification",
    expectedGateDecision: "approve",
    lineTolerance: 50,
    goldenFindings: [],
    baseFiles: {
      "docs/architecture.md": [
        "# Triad-Flow Architecture",
        "",
        "This document describes the highlevel overview of the pipeline.",
        ""
      ].join("\n")
    },
    headFiles: {
      "docs/architecture.md": [
        "# Triad-Flow Architecture Specification",
        "",
        "This document describes the high-level overview of the verification pipeline.",
        "All review providers operate strictly under Default-Deny and read-only invariants.",
        ""
      ].join("\n")
    }
  }
]);

/**
 * Synthesizes a deterministic canonical ChangeSet for a corpus case without spawning git child processes.
 *
 * @param {object} caseDef - Corpus case definition.
 * @param {string} [repoRoot=""] - Optional repository root path.
 * @returns {object} Fully validated canonical ChangeSet object.
 */
export function buildSynthesizedChangeSet(caseDef, repoRoot = "") {
  const target = caseDef.targetFile;
  const baseText = caseDef.baseFiles?.[target] || "";
  const headText = caseDef.headFiles?.[target] || "";

  const baseLines = baseText ? baseText.split("\n") : [];
  const headLines = headText ? headText.split("\n") : [];

  const diffHunk = [
    `--- a/${target}`,
    `+++ b/${target}`,
    `@@ -1,${baseLines.length} +1,${headLines.length} @@`,
    ...baseLines.map(l => `-${l}`),
    ...headLines.map(l => `+${l}`)
  ].join("\n");

  const contentDigest = crypto.createHash("sha256").update(diffHunk, "utf8").digest("hex");

  return {
    ok: true,
    schemaVersion: "1.0.0",
    scopeMode: "revision-range",
    repository: {
      root: repoRoot || process.cwd(),
      hasHead: true,
      baseSha: "1000000000000000000000000000000000000001",
      headSha: "2000000000000000000000000000000000000002"
    },
    contentDigest,
    totalFiles: 1,
    totalAdditions: headLines.length,
    totalDeletions: baseLines.length,
    files: [
      {
        path: target,
        oldPath: null,
        renamed: false,
        additions: headLines.length,
        deletions: baseLines.length,
        binary: false,
        unreadable: false,
        largeFile: false
      }
    ],
    diffHunks: diffHunk
  };
}

/**
 * Creates an isolated disposable Git repository workspace with base and head commits.
 *
 * @param {object} caseDef - Benchmark case definition object.
 * @param {object} [options] - Workspace options.
 * @param {boolean} [options.commit=true] - Whether to commit changes as head commit.
 * @param {boolean} [options.virtual=false] - If true, returns an in-memory virtual workspace without git spawn.
 * @returns {{ dir: string, caseId: string, caseDef: object, baseSha: string, headSha: string|null, changeSet: object, cleanup: Function, assertImmutability: Function }}
 */
export function createCorpusCaseWorkspace(caseDef, options = {}) {
  if (!caseDef || typeof caseDef !== "object" || !caseDef.id) {
    throw new Error("Invalid caseDef: must be a valid corpus case definition with an 'id'.");
  }

  // Fast virtual workspace (zero git spawn overhead for ultra-fast offline test suites)
  if (options.virtual) {
    const changeSet = buildSynthesizedChangeSet(caseDef);
    return {
      dir: process.cwd(),
      caseId: caseDef.id,
      caseDef,
      baseSha: changeSet.repository.baseSha,
      headSha: changeSet.repository.headSha,
      changeSet,
      cleanup: () => {},
      assertImmutability: () => true
    };
  }

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), `triad-corpus-${caseDef.id.toLowerCase()}-`));
  const commit = options.commit !== false;

  const gitExec = (args) => execFileSync("git", args, {
    cwd: tmpDir,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });

  // 1. Initialize git repository
  gitExec(["init", "-q"]);

  // 2. Base files setup
  const baseFiles = {
    "package.json": JSON.stringify({
      name: `corpus-${caseDef.id.toLowerCase()}`,
      version: "1.0.0",
      type: "module"
    }, null, 2) + "\n",
    ...(caseDef.baseFiles || {})
  };

  for (const [relPath, content] of Object.entries(baseFiles)) {
    const fullPath = path.join(tmpDir, relPath);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, content, "utf8");
  }

  gitExec(["add", "."]);
  gitExec(["-c", "user.email=corpus@triad.flow", "-c", "user.name=Corpus Generator", "-c", "core.autocrlf=false", "commit", "-q", "-m", `chore: base commit for ${caseDef.id}`]);
  const baseSha = gitExec(["rev-parse", "HEAD"]).trim();

  // 3. Head files (modifications under test)
  if (caseDef.headFiles) {
    for (const [relPath, content] of Object.entries(caseDef.headFiles)) {
      const fullPath = path.join(tmpDir, relPath);
      fs.mkdirSync(path.dirname(fullPath), { recursive: true });
      fs.writeFileSync(fullPath, content, "utf8");
    }
  }

  let headSha = null;
  if (commit) {
    gitExec(["add", "."]);
    gitExec(["-c", "user.email=corpus@triad.flow", "-c", "user.name=Corpus Generator", "-c", "core.autocrlf=false", "commit", "-q", "-m", `feat: apply diff for ${caseDef.id}`]);
    headSha = gitExec(["rev-parse", "HEAD"]).trim();
  }

  const changeSet = commit
    ? buildChangeSet(tmpDir, { base: baseSha, head: headSha })
    : buildChangeSet(tmpDir);

  const cleanup = () => {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup error on windows file locks
    }
  };

  return {
    dir: tmpDir,
    caseId: caseDef.id,
    caseDef,
    baseSha,
    headSha,
    changeSet,
    cleanup,
    assertImmutability: () => assertRepoImmutability(tmpDir, headSha)
  };
}

/**
 * Retrieves a corpus case by its identifier (case-insensitive).
 *
 * @param {string} id - e.g. "BENCH-REAL-001"
 * @returns {object|null}
 */
export function getCorpusCaseById(id) {
  if (!id || typeof id !== "string") return null;
  const norm = id.trim().toLowerCase();
  return TF_RBC_V0_CASES.find(c => c.id.toLowerCase() === norm) || null;
}

/**
 * Lists corpus cases with optional filtering.
 *
 * @param {object} [filter]
 * @param {"vulnerable"|"clean"} [filter.category]
 * @param {number} [filter.riskTier]
 * @param {string|string[]} [filter.id]
 * @param {number} [filter.limit]
 * @returns {object[]}
 */
export function listCorpusCases(filter = {}) {
  let cases = [...TF_RBC_V0_CASES];

  if (filter.category) {
    cases = cases.filter(c => c.category === filter.category);
  }

  if (filter.riskTier !== undefined) {
    cases = cases.filter(c => c.riskTier === filter.riskTier);
  }

  if (filter.id) {
    const ids = Array.isArray(filter.id) ? filter.id.map(s => s.toLowerCase()) : [filter.id.toLowerCase()];
    cases = cases.filter(c => ids.includes(c.id.toLowerCase()));
  }

  if (filter.limit && Number.isFinite(filter.limit) && filter.limit > 0) {
    cases = cases.slice(0, filter.limit);
  }

  return cases;
}

/**
 * Creates high-fidelity mock CliReviewAdapters for offline evaluation of the 15 corpus cases.
 *
 * @param {object} [options]
 * @param {string[]} [options.macroMisses=[]] - Array of case IDs that macro sentry fails to catch.
 * @param {string[]} [options.microMisses=[]] - Array of case IDs that micro sentry fails to catch.
 * @param {string[]} [options.macroFalseBlocks=[]] - Array of clean case IDs that macro falsely blocks.
 * @param {string[]} [options.microFalseBlocks=[]] - Array of clean case IDs that micro falsely blocks.
 * @param {number} [options.basePromptTokens=320]
 * @param {number} [options.baseCompletionTokens=40]
 * @returns {{ macro: CliReviewAdapter, micro: CliReviewAdapter }}
 */
export function createMockCorpusAdapters(options = {}) {
  const macroMisses = new Set((options.macroMisses || []).map(id => id.toUpperCase()));
  const microMisses = new Set((options.microMisses || []).map(id => id.toUpperCase()));
  const macroFalseBlocks = new Set((options.macroFalseBlocks || []).map(id => id.toUpperCase()));
  const microFalseBlocks = new Set((options.microFalseBlocks || []).map(id => id.toUpperCase()));

  function findCaseForInput(input) {
    const filePaths = (input.changeSet?.files || []).map(f => normalizeCanonicalPath(f.path));
    for (const c of TF_RBC_V0_CASES) {
      const normTarget = normalizeCanonicalPath(c.targetFile);
      if (filePaths.includes(normTarget)) {
        return c;
      }
    }
    return null;
  }

  function createSimulatedExecFn(role) {
    const misses = role === "macro" ? macroMisses : microMisses;
    const falseBlocks = role === "macro" ? macroFalseBlocks : microFalseBlocks;

    return async ({ input }) => {
      const c = findCaseForInput(input);
      const coveredFiles = (input.changeSet?.files || []).map(f => f.path);

      let findings = [];
      if (c) {
        const caseId = c.id.toUpperCase();
        if (c.category === "clean") {
          if (falseBlocks.has(caseId)) {
            // Simulated false block
            findings.push({
              title: "Suspicious pattern in refactor",
              severity: "high",
              file: c.targetFile,
              line_start: 5,
              line_end: 5,
              recommendation: "Review code formatting"
            });
          }
        } else if (c.category === "vulnerable") {
          if (!misses.has(caseId)) {
            // Emit caught golden findings
            findings = (c.goldenFindings || []).map(g => ({
              title: `Detected ${g.type} (${g.cwe})`,
              severity: g.severity,
              file: g.file,
              line_start: g.line,
              line_end: g.line,
              cwe: g.cwe,
              type: g.type,
              recommendation: g.rationale
            }));
          }
        }
      }

      const promptTokens = options.basePromptTokens || 320;
      const completionTokens = findings.length > 0 ? (options.baseCompletionTokens || 50) : 20;

      return {
        stdout: JSON.stringify({
          findings,
          coverage: {
            coveredFiles,
            omittedFiles: []
          },
          usage: {
            promptTokens,
            completionTokens,
            totalTokens: promptTokens + completionTokens
          }
        })
      };
    };
  }

  const macro = new CliReviewAdapter({
    command: "agy",
    providerName: "agy",
    modelName: "gemini-2.5-flash",
    execFn: createSimulatedExecFn("macro")
  });

  const micro = new CliReviewAdapter({
    command: "claude",
    providerName: "claude",
    modelName: "claude-3-5-sonnet",
    execFn: createSimulatedExecFn("micro")
  });

  return { macro, micro };
}
