/**
 * Triad-Flow Auditable Receipt & Provenance: Canonicalization & Digest Engine
 *
 * Implements Contract 3 (Canonicalization & Digest Specification) and
 * Contract 2 (Separation of Stable Identity vs Run Metadata) from TF-SPEC-RECEIPT-v1.0.0:
 * - Character Encoding: UTF-8 without BOM.
 * - Line Endings: LF (\n, 0x0A). CRLF (\r\n) and lone CR (\r) normalized to LF before hashing.
 * - Path Normalization: Repository-relative POSIX paths using forward slashes (/).
 *   Leading slashes, drive letters, and '.' segments removed.
 * - Key Ordering: All object keys sorted lexicographically (keys.sort()).
 * - JSON Serialization: Deterministic canonical JSON (no extraneous whitespace, standard escaping).
 * - Hash Algorithm: SHA-256 lowercase hex prefixed with "sha256:".
 * - Split Prompt Digests: promptTemplateDigest and renderedPromptDigest.
 * - Strict Invariant: Timestamps, machine names, process IDs, and transient file paths
 *   are strictly prohibited from contributing to caseDigest or corpusDigest.
 */

import crypto from "node:crypto";

/**
 * Default corpus version identifier.
 */
export const DEFAULT_CORPUS_VERSION = "TF-RBC-v0";

/**
 * Standard benchmark prompt template frozen contract.
 */
export const BENCHMARK_PROMPT_TEMPLATE = Object.freeze([
  "You are a strict read-only code review sentry ({{ROLE}} role).",
  "Review the following code changes for security vulnerabilities, bugs, and defects.",
  "",
  "Scope: {{SCOPE}}",
  "Content Digest: {{CONTENT_DIGEST}}",
  "Files Changed:",
  "{{FILES_CHANGED}}",
  "{{TRUNCATED_NOTICE}}",
  "Diff:",
  "```",
  "{{DIFF_HUNKS}}",
  "```",
  "",
  "Respond ONLY with a JSON object in this exact format, with no preamble or commentary:",
  "{",
  '  "findings": [',
  "    {",
  '      "title": "Concise issue title",',
  '      "severity": "critical|high|medium|low|info",',
  '      "file": "path/to/file",',
  '      "line_start": 1,',
  '      "line_end": 1,',
  '      "recommendation": "Actionable fix instruction",',
  '      "ruleId": "RULE-ID-OPTIONAL",',
  '      "cwe": "CWE-OPTIONAL",',
  '      "type": "TYPE-OPTIONAL"',
  "    }",
  "  ],",
  '  "coverage": {',
  '    "coveredFiles": ["path/to/file"],',
  '    "omittedFiles": []',
  "  },",
  '  "usage": {',
  '    "promptTokens": null,',
  '    "completionTokens": null,',
  '    "totalTokens": null',
  "  }",
  "}"
].join("\n"));

/**
 * Transient property keys strictly prohibited from contributing to identity digests.
 */
export const PROHIBITED_IDENTITY_KEYS = Object.freeze([
  "runId",
  "timestamp",
  "timestamps",
  "startedAt",
  "finishedAt",
  "hostname",
  "host",
  "machine",
  "platform",
  "arch",
  "nodeVersion",
  "environment",
  "repoDir",
  "dir",
  "tempDir",
  "temporaryPath",
  "workspaceDir",
  "workspacePath",
  "cwd",
  "root",
  "pid",
  "processId",
  "latencyMs",
  "latency",
  "status",
  "executionStatus",
  "evalResult",
  "actualFindings",
  "actualGateDecision",
  "gateReason",
  "results",
  "usage",
  "tokenCostRatio",
  "isFalseBlock",
  "isRecallCaught",
  "detectionPass",
  "gatePolicyPass",
  "executionComplete",
  "passed"
]);

const PROHIBITED_KEY_SET = new Set(PROHIBITED_IDENTITY_KEYS);

/**
 * Normalizes string line endings to LF (\n) and strips UTF-8 BOM if present.
 * Supports string or Buffer input.
 *
 * @param {string|Buffer} input
 * @returns {string}
 */
export function normalizeLineEndings(input) {
  if (input === null || input === undefined) {
    return "";
  }

  if (Array.isArray(input)) {
    const hasNL = input.some(line => /[\r\n]/.test(String(line ?? "")));
    return input.map(line => normalizeLineEndings(line)).join(hasNL ? "" : "\n");
  }

  let text;
  if (Buffer.isBuffer(input)) {
    // Strip UTF-8 BOM (0xEF, 0xBB, 0xBF)
    if (input.length >= 3 && input[0] === 0xEF && input[1] === 0xBB && input[2] === 0xBF) {
      text = input.subarray(3).toString("utf8");
    } else {
      text = input.toString("utf8");
    }
  } else if (typeof input === "string") {
    text = input;
    if (text.charCodeAt(0) === 0xFEFF) {
      text = text.slice(1);
    }
  } else {
    text = String(input);
  }

  // Normalize CRLF and CR to LF
  return text.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
}

/**
 * Normalizes a file path to a repository-relative POSIX path using forward slashes (/).
 * Strips leading slashes, backslashes, drive letters (e.g. C:), and '.' segments.
 *
 * @param {string} filePath
 * @returns {string}
 */
export function normalizeRelativePath(filePath) {
  if (typeof filePath !== "string" || !filePath) {
    return "";
  }

  // Remove null characters and normalize NFC
  let p = filePath.replace(/\0/g, "").normalize("NFC");

  // Convert Windows backslashes to POSIX slashes
  p = p.replace(/\\/g, "/");

  // Strip Windows drive letters (e.g. "C:", "d:/")
  p = p.replace(/^[a-zA-Z]:/, "");

  // Strip leading slashes
  p = p.replace(/^\/+/, "");

  // Split segments, resolve '.' and '..' within relative bounds
  const segments = p.split("/");
  const resolved = [];

  for (const seg of segments) {
    if (!seg || seg === ".") {
      continue;
    }
    if (seg === "..") {
      if (resolved.length > 0 && resolved[resolved.length - 1] !== "..") {
        resolved.pop();
      }
    } else {
      resolved.push(seg);
    }
  }

  return resolved.join("/");
}

/**
 * Deterministically serializes a JavaScript value to canonical JSON:
 * - Object keys are sorted lexicographically at every depth.
 * - Array element order is strictly preserved.
 * - Undefined, function, and symbol properties in objects are omitted (matching JSON.stringify).
 * - Undefined, function, and symbol items in arrays are stringified as null (matching JSON.stringify).
 * - Objects with toJSON() methods (e.g. Date) are serialized via their toJSON() output.
 * - Throws TypeError on circular references (matching JSON.stringify).
 * - No extraneous whitespace.
 *
 * @param {*} val
 * @param {WeakSet} [seen]
 * @returns {string|undefined}
 */
export function canonicalJsonStringify(val, seen = new WeakSet()) {
  if (val === undefined || typeof val === "function" || typeof val === "symbol") {
    return undefined;
  }

  if (val === null || typeof val !== "object") {
    return JSON.stringify(val);
  }

  // Handle toJSON() methods (e.g. Date)
  if (typeof val.toJSON === "function") {
    return canonicalJsonStringify(val.toJSON(), seen);
  }

  if (seen.has(val)) {
    throw new TypeError("Converting circular structure to JSON");
  }
  seen.add(val);

  try {
    if (Array.isArray(val)) {
      const items = val.map(item => {
        if (item === undefined || typeof item === "function" || typeof item === "symbol") {
          return "null";
        }
        const res = canonicalJsonStringify(item, seen);
        return res === undefined ? "null" : res;
      });
      return `[${items.join(",")}]`;
    }

    // Plain object: filter out undefined, function, symbol values and sort keys lexicographically
    const validKeys = Object.keys(val).filter(k => {
      const v = val[k];
      return v !== undefined && typeof v !== "function" && typeof v !== "symbol";
    }).sort();

    const entries = validKeys.map(k => `${JSON.stringify(k)}:${canonicalJsonStringify(val[k], seen)}`);
    return `{${entries.join(",")}}`;
  } finally {
    seen.delete(val);
  }
}

/**
 * Computes the SHA-256 hash of the input, returning lowercase hex prefixed with "sha256:".
 * Accepts string, Buffer, or JavaScript object (canonicalized to JSON).
 *
 * @param {string|Buffer|object} content
 * @returns {string} e.g. "sha256:..."
 */
export function computeDigest(content) {
  let buf;
  if (Buffer.isBuffer(content)) {
    buf = content;
  } else if (typeof content === "string") {
    buf = Buffer.from(content, "utf8");
  } else {
    buf = Buffer.from(canonicalJsonStringify(content), "utf8");
  }

  const hex = crypto.createHash("sha256").update(buf).digest("hex").toLowerCase();
  return `sha256:${hex}`;
}

/**
 * Alias for computeDigest.
 */
export const sha256Digest = computeDigest;

/**
 * Canonicalizes a map of file paths to contents:
 * - Paths normalized to repository-relative POSIX paths.
 * - Contents normalized to UTF-8 with LF line endings.
 * - Keys sorted lexicographically.
 *
 * @param {Record<string, string|Buffer>} fileMap
 * @returns {Record<string, string>}
 */
export function canonicalizeFileMap(fileMap) {
  if (!fileMap || typeof fileMap !== "object") {
    return {};
  }

  const normalized = {};
  for (const [rawPath, rawContent] of Object.entries(fileMap)) {
    const normPath = normalizeRelativePath(rawPath);
    if (!normPath) continue;
    const content = normalizeLineEndings(rawContent);
    if (normalized[normPath] !== undefined && normalized[normPath] !== content) {
      throw new Error(`File map path collision after normalization: '${rawPath}' and normalized '${normPath}' have conflicting contents.`);
    }
    normalized[normPath] = content;
  }

  const sorted = {};
  for (const k of Object.keys(normalized).sort()) {
    sorted[k] = normalized[k];
  }
  return sorted;
}

/**
 * Computes digest of a file map.
 *
 * @param {Record<string, string|Buffer>} fileMap
 * @returns {string} "sha256:..."
 */
export function digestFileMap(fileMap) {
  return computeDigest(canonicalJsonStringify(canonicalizeFileMap(fileMap)));
}

/**
 * Canonicalizes case files (baseFiles and headFiles).
 *
 * @param {object} input - Either { baseFiles, headFiles } or a single fileMap
 * @returns {object} Canonical file structure
 */
export function canonicalizeCaseFiles(input) {
  if (!input || typeof input !== "object") {
    return { baseFiles: {}, headFiles: {} };
  }

  if (input.baseFiles || input.headFiles) {
    return {
      baseFiles: canonicalizeFileMap(input.baseFiles || {}),
      headFiles: canonicalizeFileMap(input.headFiles || {})
    };
  }

  return canonicalizeFileMap(input);
}

/**
 * Computes digest of case files.
 *
 * @param {object} input
 * @returns {string} "sha256:..."
 */
export function digestCaseFiles(input) {
  return computeDigest(canonicalJsonStringify(canonicalizeCaseFiles(input)));
}

/**
 * Canonicalizes a single golden finding item.
 *
 * @param {object} finding
 * @returns {object}
 */
export function canonicalizeGoldenFinding(finding) {
  if (!finding || typeof finding !== "object") {
    return {};
  }

  return {
    cwe: finding.cwe ? String(finding.cwe).toUpperCase().trim() : null,
    file: normalizeRelativePath(finding.file || ""),
    line: typeof finding.line === "number" ? finding.line : null,
    rationale: finding.rationale ? String(finding.rationale).trim() : "",
    severity: finding.severity ? String(finding.severity).toLowerCase().trim() : "unknown",
    type: finding.type ? String(finding.type).toLowerCase().trim() : null
  };
}

/**
 * Canonicalizes a changeset for deterministic hashing:
 * - Excludes runtime/transient fields (repoRoot, tempDir, cwd, timestamps, runId).
 * - Sorts files by relative POSIX path.
 * - Normalizes diffHunks line endings to LF.
 *
 * @param {object} changeSet
 * @returns {object}
 */
export function canonicalizeChangeSet(changeSet) {
  if (!changeSet || typeof changeSet !== "object") {
    return {
      diffHunks: "",
      files: [],
      scopeMode: "working-tree",
      totalAdditions: 0,
      totalDeletions: 0,
      totalFiles: 0
    };
  }

  const files = Array.isArray(changeSet.files)
    ? changeSet.files.map(f => ({
        additions: Number(f.additions || 0),
        binary: Boolean(f.binary),
        deletions: Number(f.deletions || 0),
        largeFile: Boolean(f.largeFile),
        oldPath: f.oldPath ? normalizeRelativePath(f.oldPath) : null,
        path: normalizeRelativePath(f.path || ""),
        renamed: Boolean(f.renamed),
        unreadable: Boolean(f.unreadable)
      }))
    : [];

  files.sort((a, b) => {
    const pathCmp = a.path.localeCompare(b.path);
    if (pathCmp !== 0) return pathCmp;
    return canonicalJsonStringify(a).localeCompare(canonicalJsonStringify(b));
  });

  const totalAdditions = files.reduce((sum, f) => sum + f.additions, 0);
  const totalDeletions = files.reduce((sum, f) => sum + f.deletions, 0);

  const canonical = {
    diffHunks: normalizeLineEndings(changeSet.diffHunks || ""),
    files,
    scopeMode: String(changeSet.scopeMode || "working-tree"),
    totalAdditions,
    totalDeletions,
    totalFiles: files.length
  };

  // Only include repository identity if present without local file paths
  if (changeSet.repository && typeof changeSet.repository === "object") {
    canonical.repository = {
      branch: changeSet.repository.branch ? String(changeSet.repository.branch) : null,
      commitSha: changeSet.repository.commitSha ? String(changeSet.repository.commitSha) : null,
      url: changeSet.repository.url ? String(changeSet.repository.url) : null
    };
  }

  return canonical;
}

/**
 * Computes digest of a changeset.
 *
 * @param {object} changeSet
 * @returns {string} "sha256:..."
 */
export function digestChangeSet(changeSet) {
  return computeDigest(canonicalJsonStringify(canonicalizeChangeSet(changeSet)));
}

/**
 * Canonicalizes a prompt template string.
 *
 * @param {string} template
 * @returns {string}
 */
export function canonicalizePromptTemplate(template) {
  return normalizeLineEndings(template);
}

/**
 * Computes promptTemplateDigest (SHA-256 of frozen benchmark prompt template).
 *
 * @param {string} [template=BENCHMARK_PROMPT_TEMPLATE]
 * @returns {string} "sha256:..."
 */
export function digestPromptTemplate(template = BENCHMARK_PROMPT_TEMPLATE) {
  return computeDigest(canonicalizePromptTemplate(template));
}

/**
 * Canonicalizes a fully-rendered prompt.
 *
 * @param {string} prompt
 * @returns {string}
 */
export function canonicalizeRenderedPrompt(prompt) {
  return normalizeLineEndings(prompt);
}

/**
 * Computes renderedPromptDigest (SHA-256 of fully-rendered prompt).
 *
 * @param {string} prompt
 * @returns {string} "sha256:..."
 */
export function digestRenderedPrompt(prompt) {
  return computeDigest(canonicalizeRenderedPrompt(prompt));
}

/**
 * Computes split prompt digests (promptTemplateDigest and renderedPromptDigest).
 *
 * @param {string} promptTemplate
 * @param {string} renderedPrompt
 * @returns {{ promptTemplateDigest: string, renderedPromptDigest: string }}
 */
export function splitPromptDigests(promptTemplate, renderedPrompt) {
  return {
    promptTemplateDigest: digestPromptTemplate(promptTemplate),
    renderedPromptDigest: digestRenderedPrompt(renderedPrompt)
  };
}

/**
 * Canonicalizes a benchmark case definition:
 * - Retains ONLY immutable benchmark inputs.
 * - Strictly strips all runtime/transient fields (timestamps, runId, hostname, temporary paths).
 * - Normalizes file paths, file contents, line endings, and golden findings.
 *
 * @param {object} caseDef
 * @returns {object} Canonical case definition
 */
export function canonicalizeCase(caseDef) {
  if (!caseDef || typeof caseDef !== "object") {
    throw new Error("Invalid caseDef: must be an object.");
  }
  if (!caseDef.id) {
    throw new Error("Invalid caseDef: missing required 'id'.");
  }

  // Canonicalize golden findings
  const goldenFindings = Array.isArray(caseDef.goldenFindings)
    ? caseDef.goldenFindings.map(canonicalizeGoldenFinding)
    : [];

  goldenFindings.sort((a, b) => {
    const fileCmp = (a.file || "").localeCompare(b.file || "");
    if (fileCmp !== 0) return fileCmp;
    const lineCmp = (a.line || 0) - (b.line || 0);
    if (lineCmp !== 0) return lineCmp;
    const cweCmp = (a.cwe || "").localeCompare(b.cwe || "");
    if (cweCmp !== 0) return cweCmp;
    const typeCmp = (a.type || "").localeCompare(b.type || "");
    if (typeCmp !== 0) return typeCmp;
    const sevCmp = (a.severity || "").localeCompare(b.severity || "");
    if (sevCmp !== 0) return sevCmp;
    const ratCmp = (a.rationale || "").localeCompare(b.rationale || "");
    if (ratCmp !== 0) return ratCmp;
    return canonicalJsonStringify(a).localeCompare(canonicalJsonStringify(b));
  });

  const canonical = {
    baseFiles: canonicalizeFileMap(caseDef.baseFiles || {}),
    category: String(caseDef.category || "unknown"),
    description: String(caseDef.description || "").trim(),
    expectedGateDecision: String(caseDef.expectedGateDecision || "block").toLowerCase().trim(),
    goldenFindings,
    headFiles: canonicalizeFileMap(caseDef.headFiles || {}),
    id: String(caseDef.id).trim(),
    lineTolerance: typeof caseDef.lineTolerance === "number" ? caseDef.lineTolerance : 50,
    riskTier: typeof caseDef.riskTier === "number" ? caseDef.riskTier : 1,
    targetFile: normalizeRelativePath(caseDef.targetFile || ""),
    title: String(caseDef.title || "").trim()
  };

  // If changeSet is attached, canonicalize it without transient paths
  if (caseDef.changeSet && typeof caseDef.changeSet === "object") {
    canonical.changeSet = canonicalizeChangeSet(caseDef.changeSet);
  }

  return canonical;
}

/**
 * Computes caseDigest for a benchmark case.
 *
 * @param {object} caseDef
 * @returns {string} "sha256:..."
 */
export function digestCase(caseDef) {
  return computeDigest(canonicalJsonStringify(canonicalizeCase(caseDef)));
}

/**
 * Canonicalizes an entire corpus and generates its immutable Identity block:
 * - Computes deterministic caseDigest for each case.
 * - Sorts caseDigests lexicographically by case ID.
 * - Derives corpusDigest from { caseDigests, corpusVersion }.
 * - Prohibits all timestamps, run IDs, hostnames, and temporary paths from participating.
 *
 * @param {object[]|{ cases: object[], corpusVersion?: string }} corpusInput
 * @param {object} [options]
 * @param {string} [options.corpusVersion]
 * @returns {{ corpusVersion: string, corpusDigest: string, caseDigests: Record<string, string> }}
 */
export function createCorpusIdentity(corpusInput, options = {}) {
  let cases;
  let corpusVersion = options.corpusVersion;

  if (Array.isArray(corpusInput)) {
    cases = corpusInput;
  } else if (corpusInput && typeof corpusInput === "object") {
    cases = Array.isArray(corpusInput.cases) ? corpusInput.cases : [];
    if (!corpusVersion && corpusInput.corpusVersion) {
      corpusVersion = corpusInput.corpusVersion;
    }
  } else {
    throw new Error("Invalid corpusInput: must be an array of cases or an object containing 'cases'.");
  }

  corpusVersion = String(corpusVersion || DEFAULT_CORPUS_VERSION);

  const rawDigests = {};
  for (const c of cases) {
    if (!c || !c.id) {
      throw new Error("Corpus case missing required 'id'.");
    }
    const caseId = String(c.id).trim();
    if (rawDigests[caseId]) {
      throw new Error(`Duplicate case ID in corpus: '${caseId}'. Case IDs must be unique.`);
    }
    rawDigests[caseId] = digestCase(c);
  }

  const caseDigests = {};
  for (const id of Object.keys(rawDigests).sort()) {
    caseDigests[id] = rawDigests[id];
  }

  // Derive corpusDigest strictly from immutable identity components
  const identityPayload = {
    caseDigests,
    corpusVersion
  };

  const corpusDigest = computeDigest(canonicalJsonStringify(identityPayload));

  return {
    caseDigests,
    corpusDigest,
    corpusVersion
  };
}

/**
 * Canonicalizes a corpus (alias for createCorpusIdentity).
 */
export const canonicalizeCorpus = createCorpusIdentity;

/**
 * Computes corpusDigest for an entire benchmark corpus.
 *
 * @param {object[]|object} corpusInput
 * @param {object} [options]
 * @returns {string} "sha256:..."
 */
export function digestCorpus(corpusInput, options = {}) {
  const identity = createCorpusIdentity(corpusInput, options);
  return identity.corpusDigest;
}
