/**
 * Triad-Flow Auditable Receipt & Provenance: Schema, Validator & Builder
 *
 * Implements TF-SPEC-RECEIPT-v1.0.0 Contracts:
 * - Contract 1: Receipt Schema Versioning (schemaVersion: "1.0.0", fail-closed UnsupportedReceiptSchemaError when major !== 1).
 * - Contract 2: Separation of Stable Identity vs Run Metadata (identity vs run vs systemProvenance/providerProvenance/results).
 * - Contract 4: Provider Provenance & Source Trust Tiers (cli | runtime | reported | inferred | unavailable, actualModel default, null tokens).
 * - Contract 5: Baseline Artifact Manifest support.
 */

import {
  canonicalJsonStringify,
  computeDigest,
  PROHIBITED_IDENTITY_KEYS
} from "./canonical-digest.mjs";
import { TOOL_VERSION } from "./review-run-report.mjs";

/**
 * Normative receipt schema version.
 */
export const CURRENT_RECEIPT_SCHEMA_VERSION = "1.0.0";

/**
 * Expected schema major version supported by this reader.
 */
export const SUPPORTED_RECEIPT_SCHEMA_MAJOR = 1;

/**
 * Source trust tiers per Contract 4.
 */
export const SOURCE_TRUST_TIERS = Object.freeze({
  CLI: "cli",
  RUNTIME: "runtime",
  REPORTED: "reported",
  INFERRED: "inferred",
  UNAVAILABLE: "unavailable"
});

export const VALID_SOURCE_TRUST_TIERS = new Set(Object.values(SOURCE_TRUST_TIERS));

/**
 * Token usage sources per Contract 4.
 */
export const USAGE_SOURCES = Object.freeze({
  AUTHORITATIVE: "authoritative",
  UNAVAILABLE: "unavailable"
});

export const VALID_USAGE_SOURCES = new Set(Object.values(USAGE_SOURCES));

/**
 * Normative SHA-256 lowercase hex string format prefixed with 'sha256:'.
 */
export const SHA256_HEX_REGEX = /^sha256:[a-f0-9]{64}$/;

/**
 * Error thrown when an audit receipt contains an unsupported schema major version.
 */
export class UnsupportedReceiptSchemaError extends Error {
  constructor(version, message) {
    const msg = message || `Unsupported receipt schema version: '${version}'. Reader requires major version ${SUPPORTED_RECEIPT_SCHEMA_MAJOR} (1.x.y).`;
    super(msg);
    this.name = "UnsupportedReceiptSchemaError";
    this.version = version;
    this.code = "ERR_UNSUPPORTED_RECEIPT_SCHEMA";
  }
}

/**
 * Error thrown when an audit receipt violates structural or contract invariants.
 */
export class ReceiptValidationError extends Error {
  constructor(errors, message) {
    const errorList = Array.isArray(errors) ? errors : [errors];
    const msg = message || `Receipt validation failed with ${errorList.length} error(s):\n  - ${errorList.join("\n  - ")}`;
    super(msg);
    this.name = "ReceiptValidationError";
    this.errors = errorList;
    this.code = "ERR_RECEIPT_VALIDATION_FAILED";
  }
}

/**
 * Extracts and parses the major version from a semver version string.
 *
 * @param {string} versionStr
 * @returns {number|null} Major version number or null if unparseable
 */
export function parseSchemaMajorVersion(versionStr) {
  if (typeof versionStr !== "string" || !versionStr.trim()) {
    return null;
  }
  const clean = versionStr.trim().replace(/^v/i, "");
  const match = clean.match(/^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?$/);
  if (!match) {
    return null;
  }
  return parseInt(match[1], 10);
}

/**
 * Returns default actualModel structure per Contract 4.
 *
 * @returns {{ value: null, source: "unavailable" }}
 */
export function createDefaultActualModel() {
  return {
    source: SOURCE_TRUST_TIERS.UNAVAILABLE,
    value: null
  };
}

/**
 * Normalizes actualModel representation with strict trust tier verification.
 *
 * @param {object|string|null} modelInput
 * @returns {{ value: string|null, source: string }}
 */
export function normalizeActualModel(modelInput) {
  if (!modelInput || typeof modelInput !== "object") {
    return createDefaultActualModel();
  }

  const rawValue = typeof modelInput.value === "string" ? modelInput.value.trim() : null;
  const rawSource = typeof modelInput.source === "string" ? modelInput.source.toLowerCase().trim() : null;

  const source = VALID_SOURCE_TRUST_TIERS.has(rawSource) ? rawSource : SOURCE_TRUST_TIERS.UNAVAILABLE;
  const value = rawValue && rawValue.length > 0 ? rawValue : null;

  return {
    source: value ? source : SOURCE_TRUST_TIERS.UNAVAILABLE,
    value
  };
}

/**
 * Normalizes token usage preserving null values without coercion to 0.
 *
 * @param {object|null} usageInput
 * @returns {{ usageSource: string, promptTokens: number|null, completionTokens: number|null, totalTokens: number|null }}
 */
export function normalizeReceiptUsage(usageInput) {
  if (!usageInput || typeof usageInput !== "object") {
    return {
      completionTokens: null,
      promptTokens: null,
      totalTokens: null,
      usageSource: USAGE_SOURCES.UNAVAILABLE
    };
  }

  const promptTokens = Number.isFinite(usageInput.promptTokens) ? Number(usageInput.promptTokens) : null;
  const completionTokens = Number.isFinite(usageInput.completionTokens) ? Number(usageInput.completionTokens) : null;
  let totalTokens = Number.isFinite(usageInput.totalTokens) ? Number(usageInput.totalTokens) : null;

  if (totalTokens === null && promptTokens !== null && completionTokens !== null) {
    totalTokens = promptTokens + completionTokens;
  }

  let usageSource = USAGE_SOURCES.UNAVAILABLE;
  if (usageInput.usageSource === USAGE_SOURCES.AUTHORITATIVE || (usageInput.available && totalTokens !== null)) {
    usageSource = USAGE_SOURCES.AUTHORITATIVE;
  }

  return {
    completionTokens,
    promptTokens,
    totalTokens,
    usageSource
  };
}

/**
 * Normalizes provider provenance entries adhering to Contract 4.
 *
 * @param {Record<string, object>} rawProviders
 * @returns {Record<string, object>}
 */
export function normalizeProviderProvenance(rawProviders = {}) {
  if (!rawProviders || typeof rawProviders !== "object") {
    return {};
  }

  const normalized = {};
  for (const [providerKey, p] of Object.entries(rawProviders)) {
    if (!p || typeof p !== "object") continue;

    const actualModel = normalizeActualModel(p.actualModel);
    const usage = normalizeReceiptUsage(p.usage || p);

    normalized[providerKey] = {
      actualModel,
      completionTokens: usage.completionTokens,
      modelName: p.modelName || p.configuredModel || "unknown",
      promptTokens: usage.promptTokens,
      providerName: p.providerName || providerKey,
      totalTokens: usage.totalTokens,
      usageSource: usage.usageSource,
      version: p.version || null
    };

    if (p.reviewProfileReady !== undefined) {
      normalized[providerKey].reviewProfileReady = Boolean(p.reviewProfileReady);
    }
  }

  return normalized;
}

/**
 * Builds an auditable receipt structure adhering to Contract 2.
 *
 * @param {object} params
 * @param {object} params.identity - Identity tier: { corpusVersion, corpusDigest, caseDigests }
 * @param {object} [params.run] - Execution session metadata
 * @param {object} [params.systemProvenance] - Git commit, branch, tool versions
 * @param {object} [params.providerProvenance] - Model and provider evidence
 * @param {object} [params.results] - Benchmark or review results
 * @returns {object} Formatted audit receipt object
 */
export function buildAuditReceipt({
  identity,
  run = {},
  systemProvenance = {},
  providerProvenance = {},
  results = {}
} = {}) {
  if (!identity || typeof identity !== "object") {
    throw new Error("Cannot build audit receipt: missing required 'identity' tier.");
  }
  if (!identity.corpusVersion || !identity.corpusDigest || !identity.caseDigests) {
    throw new Error("Cannot build audit receipt: 'identity' must contain 'corpusVersion', 'corpusDigest', and 'caseDigests'.");
  }

  // Contract 2 Guard: Assert identity does not contain runtime keys
  for (const key of Object.keys(identity)) {
    if (PROHIBITED_IDENTITY_KEYS.includes(key)) {
      throw new Error(`Contract 2 Violation: Identity tier contains prohibited runtime key '${key}'.`);
    }
  }

  const runSection = {
    environment: {
      arch: run.environment?.arch || process.arch,
      nodeVersion: run.environment?.nodeVersion || process.version,
      platform: run.environment?.platform || process.platform,
      ...(run.environment || {})
    },
    finishedAt: run.finishedAt || null,
    runId: run.runId || `run-${Date.now()}-${Math.random().toString(16).slice(2, 10)}`,
    startedAt: run.startedAt || new Date().toISOString()
  };

  const sysSection = {
    branch: systemProvenance.branch || "unknown",
    commitSha: systemProvenance.commitSha || "unknown",
    triadFlowVersion: systemProvenance.triadFlowVersion || TOOL_VERSION,
    ...(systemProvenance || {})
  };

  const provSection = normalizeProviderProvenance(providerProvenance);

  return {
    identity: {
      caseDigests: { ...identity.caseDigests },
      corpusDigest: String(identity.corpusDigest),
      corpusVersion: String(identity.corpusVersion)
    },
    providerProvenance: provSection,
    results: { ...results },
    run: runSection,
    schemaVersion: CURRENT_RECEIPT_SCHEMA_VERSION,
    systemProvenance: sysSection
  };
}

/**
 * Validates an audit receipt against normative contracts:
 * - Contract 1: schemaVersion exists and major === 1 (Throws UnsupportedReceiptSchemaError on major mismatch).
 * - Contract 2: identity contains only stable immutable inputs and no runtime metadata.
 * - Contract 4: actualModel and usage conform to source trust tiers.
 *
 * @param {object} receipt
 * @returns {{ valid: boolean, errors: string[], receipt: object }}
 */
export function validateAuditReceipt(receipt) {
  if (!receipt || typeof receipt !== "object") {
    throw new UnsupportedReceiptSchemaError(undefined, "Receipt must be a valid non-null object.");
  }

  // Contract 1: Schema major version check (Fail-closed)
  const major = parseSchemaMajorVersion(receipt.schemaVersion);
  if (major !== SUPPORTED_RECEIPT_SCHEMA_MAJOR) {
    throw new UnsupportedReceiptSchemaError(
      receipt.schemaVersion,
      `Unsupported receipt schema version: '${receipt.schemaVersion}'. Reader requires major version ${SUPPORTED_RECEIPT_SCHEMA_MAJOR} (1.x.y).`
    );
  }

  const errors = [];

  // Contract 2: Identity Tier Validation
  if (!receipt.identity || typeof receipt.identity !== "object" || Array.isArray(receipt.identity)) {
    errors.push("Missing or invalid 'identity' tier: must be an object.");
  } else {
    if (!receipt.identity.corpusVersion || typeof receipt.identity.corpusVersion !== "string") {
      errors.push("identity.corpusVersion must be a non-empty string.");
    }
    if (!receipt.identity.corpusDigest || !SHA256_HEX_REGEX.test(String(receipt.identity.corpusDigest))) {
      errors.push("identity.corpusDigest must be a valid lowercase SHA-256 hex string prefixed with 'sha256:'.");
    }
    if (!receipt.identity.caseDigests || typeof receipt.identity.caseDigests !== "object" || Array.isArray(receipt.identity.caseDigests)) {
      errors.push("identity.caseDigests must be an object mapping case IDs to digests.");
    } else {
      for (const [caseId, d] of Object.entries(receipt.identity.caseDigests)) {
        if (!SHA256_HEX_REGEX.test(String(d))) {
          errors.push(`identity.caseDigests['${caseId}'] must be a valid lowercase SHA-256 hex string prefixed with 'sha256:'.`);
        }
      }
    }

    // Strict invariant: verify identity tier does not leak runtime noise
    for (const key of Object.keys(receipt.identity)) {
      if (PROHIBITED_IDENTITY_KEYS.includes(key)) {
        errors.push(`Contract 2 Violation: identity tier contains prohibited runtime key '${key}'.`);
      }
    }
  }

  // Contract 2: Run Tier Validation
  if (!receipt.run || typeof receipt.run !== "object" || Array.isArray(receipt.run)) {
    errors.push("Missing or invalid 'run' tier: must be an object.");
  } else {
    if (!receipt.run.runId || typeof receipt.run.runId !== "string") {
      errors.push("run.runId must be a non-empty string.");
    }
    if (!receipt.run.startedAt || typeof receipt.run.startedAt !== "string") {
      errors.push("run.startedAt must be a valid timestamp string.");
    }
    if (!receipt.run.environment || typeof receipt.run.environment !== "object" || Array.isArray(receipt.run.environment)) {
      errors.push("run.environment must be an object specifying execution platform details.");
    }
  }

  // System Provenance
  if (!receipt.systemProvenance || typeof receipt.systemProvenance !== "object" || Array.isArray(receipt.systemProvenance)) {
    errors.push("Missing or invalid 'systemProvenance': must be an object.");
  }

  // Contract 4: Provider Provenance Validation
  if (!receipt.providerProvenance || typeof receipt.providerProvenance !== "object" || Array.isArray(receipt.providerProvenance)) {
    errors.push("Missing or invalid 'providerProvenance': must be an object.");
  } else {
    for (const [pKey, p] of Object.entries(receipt.providerProvenance)) {
      if (!p || typeof p !== "object" || Array.isArray(p)) {
        errors.push(`providerProvenance['${pKey}'] must be a valid non-null object.`);
        continue;
      }

      if (p.actualModel === undefined) {
        errors.push(`providerProvenance['${pKey}'] must record 'actualModel'.`);
      } else if (!p.actualModel || typeof p.actualModel !== "object" || Array.isArray(p.actualModel)) {
        errors.push(`providerProvenance['${pKey}'].actualModel must be an object.`);
      } else {
        if (!VALID_SOURCE_TRUST_TIERS.has(p.actualModel.source)) {
          errors.push(`providerProvenance['${pKey}'].actualModel.source '${p.actualModel.source}' is not a valid trust tier.`);
        }
        if (p.actualModel.value !== null && typeof p.actualModel.value !== "string") {
          errors.push(`providerProvenance['${pKey}'].actualModel.value must be a string or null.`);
        }
        if (p.actualModel.value === null && p.actualModel.source !== SOURCE_TRUST_TIERS.UNAVAILABLE) {
          errors.push(`providerProvenance['${pKey}'].actualModel.source must be 'unavailable' when value is null.`);
        }
      }

      if (p.usageSource !== undefined && !VALID_USAGE_SOURCES.has(p.usageSource)) {
        errors.push(`providerProvenance['${pKey}'].usageSource '${p.usageSource}' is not a valid usage source.`);
      }

      // Check tokens are non-negative integers or null
      for (const tokenKey of ["promptTokens", "completionTokens", "totalTokens"]) {
        const val = p[tokenKey];
        if (val !== undefined && val !== null) {
          if (!Number.isInteger(val) || val < 0) {
            errors.push(`providerProvenance['${pKey}'].${tokenKey} must be a non-negative integer or null.`);
          }
        }
      }

      // Total tokens consistency check if both prompt and completion are provided
      if (Number.isInteger(p.promptTokens) && Number.isInteger(p.completionTokens) && Number.isInteger(p.totalTokens)) {
        if (p.totalTokens !== p.promptTokens + p.completionTokens) {
          errors.push(`providerProvenance['${pKey}'].totalTokens (${p.totalTokens}) does not equal promptTokens (${p.promptTokens}) + completionTokens (${p.completionTokens}).`);
        }
      }

      if (p.reviewProfileReady !== undefined && typeof p.reviewProfileReady !== "boolean") {
        errors.push(`providerProvenance['${pKey}'].reviewProfileReady must be a boolean.`);
      }
    }
  }

  // Results
  if (!receipt.results || typeof receipt.results !== "object" || Array.isArray(receipt.results)) {
    errors.push("Missing or invalid 'results': must be an object.");
  }

  return {
    errors,
    receipt,
    valid: errors.length === 0
  };
}

/**
 * Parses and validates an audit receipt from JSON string or object.
 * Throws UnsupportedReceiptSchemaError if major !== 1, or ReceiptValidationError if invalid.
 *
 * @param {string|object} input
 * @param {object} [options]
 * @param {boolean} [options.strict=true]
 * @returns {object} Validated receipt object
 */
export function parseAuditReceipt(input, options = {}) {
  let parsed;
  if (typeof input === "string") {
    try {
      parsed = JSON.parse(input);
    } catch (err) {
      throw new ReceiptValidationError([`Failed to parse audit receipt JSON: ${err.message}`]);
    }
  } else if (input && typeof input === "object") {
    parsed = input;
  } else {
    throw new UnsupportedReceiptSchemaError(undefined, "Input must be a JSON string or receipt object.");
  }

  const validation = validateAuditReceipt(parsed);
  if (!validation.valid && options.strict !== false) {
    throw new ReceiptValidationError(validation.errors);
  }

  return parsed;
}

/**
 * Computes deterministic receiptDigest of an audit receipt.
 * Fails closed if the receipt violates schema or contract invariants.
 *
 * @param {object} receipt
 * @returns {string} "sha256:..."
 */
export function computeReceiptDigest(receipt) {
  if (!receipt || typeof receipt !== "object") {
    throw new Error("Invalid receipt: must be an object.");
  }

  // Validate receipt schema and contract invariants (fail-closed)
  const validation = validateAuditReceipt(receipt);
  if (!validation.valid) {
    throw new ReceiptValidationError(validation.errors);
  }

  return computeDigest(canonicalJsonStringify(receipt));
}

/**
 * Constructs an immutable Contract 5 Baseline Artifact Manifest.
 *
 * @param {object} params
 * @param {Record<string, string>} params.artifacts - Map of filename to SHA-256 digest
 * @param {object} params.metadata - Metadata (runId, commitSha, corpusDigest, receiptDigest, resultsDigest)
 * @returns {object} artifact-manifest.json structure
 */
export function buildArtifactManifest({ artifacts = {}, metadata = {} } = {}) {
  const sortedArtifacts = {};
  for (const k of Object.keys(artifacts).sort()) {
    sortedArtifacts[k] = artifacts[k];
  }

  return {
    artifacts: sortedArtifacts,
    metadata: {
      commitSha: metadata.commitSha || "unknown",
      corpusDigest: metadata.corpusDigest || null,
      receiptDigest: metadata.receiptDigest || null,
      resultsDigest: metadata.resultsDigest || null,
      runId: metadata.runId || "unknown",
      ...(metadata || {})
    },
    schemaVersion: CURRENT_RECEIPT_SCHEMA_VERSION
  };
}

/**
 * Validates an artifact manifest structure.
 *
 * @param {object} manifest
 * @returns {{ valid: boolean, errors: string[] }}
 */
export function validateArtifactManifest(manifest) {
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) {
    throw new UnsupportedReceiptSchemaError(undefined, "Manifest must be a non-null object.");
  }

  const major = parseSchemaMajorVersion(manifest.schemaVersion);
  if (major !== SUPPORTED_RECEIPT_SCHEMA_MAJOR) {
    throw new UnsupportedReceiptSchemaError(
      manifest.schemaVersion,
      `Unsupported artifact manifest schema version: '${manifest.schemaVersion}'. Reader requires major version ${SUPPORTED_RECEIPT_SCHEMA_MAJOR}.`
    );
  }

  const errors = [];
  if (!manifest.artifacts || typeof manifest.artifacts !== "object" || Array.isArray(manifest.artifacts)) {
    errors.push("Missing or invalid 'artifacts' map: must be an object.");
  } else {
    for (const [filename, d] of Object.entries(manifest.artifacts)) {
      if (!SHA256_HEX_REGEX.test(String(d))) {
        errors.push(`Artifact '${filename}' digest must be a valid lowercase SHA-256 hex string prefixed with 'sha256:'.`);
      }
    }
  }

  if (!manifest.metadata || typeof manifest.metadata !== "object" || Array.isArray(manifest.metadata)) {
    errors.push("Missing or invalid 'metadata' object.");
  } else {
    for (const digestKey of ["corpusDigest", "receiptDigest", "resultsDigest"]) {
      const d = manifest.metadata[digestKey];
      if (d !== undefined && d !== null && !SHA256_HEX_REGEX.test(String(d))) {
        errors.push(`metadata.${digestKey} must be a valid lowercase SHA-256 hex string prefixed with 'sha256:'.`);
      }
    }
  }

  return {
    errors,
    valid: errors.length === 0
  };
}

export {
  formatSummaryMarkdown,
  generateManifestBundle,
  verifyManifestBundle
} from "./manifest-bundle.mjs";
