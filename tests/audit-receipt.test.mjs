/**
 * Test Suite: Audit Receipt Schema & Validator (Phase 1 Alpha)
 *
 * Validates Contract 1, 2, 4, and 5 of TF-SPEC-RECEIPT-v1.0.0:
 * - Contract 1: Schema Versioning (major === 1 enforced, fails-closed with UnsupportedReceiptSchemaError)
 * - Contract 2: Strict Two-Tier Separation (identity vs run vs systemProvenance/providerProvenance/results)
 * - Contract 4: Provider Provenance & Source Trust Tiers (actualModel defaults, null token preservation)
 * - Contract 5: Baseline Artifact Manifest bundle and validation
 * - Receipt round-trip serialization and deterministic receiptDigest computation
 */

import test from "node:test";
import assert from "node:assert/strict";

import {
  CURRENT_RECEIPT_SCHEMA_VERSION,
  SUPPORTED_RECEIPT_SCHEMA_MAJOR,
  SOURCE_TRUST_TIERS,
  USAGE_SOURCES,
  UnsupportedReceiptSchemaError,
  ReceiptValidationError,
  parseSchemaMajorVersion,
  createDefaultActualModel,
  normalizeActualModel,
  normalizeReceiptUsage,
  normalizeProviderProvenance,
  buildAuditReceipt,
  validateAuditReceipt,
  parseAuditReceipt,
  computeReceiptDigest,
  buildArtifactManifest,
  validateArtifactManifest
} from "../src/core/audit-receipt.mjs";

import { createCorpusIdentity } from "../src/core/canonical-digest.mjs";
import { TF_RBC_V0_CASES } from "./fixtures/real-corpus-fixtures.mjs";

const VALID_IDENTITY = Object.freeze(createCorpusIdentity(TF_RBC_V0_CASES.slice(0, 3), { corpusVersion: "TF-RBC-v0" }));

test("Contract 1: Schema Major Version Parsing", () => {
  assert.equal(parseSchemaMajorVersion("1.0.0"), 1);
  assert.equal(parseSchemaMajorVersion("1.2.3"), 1);
  assert.equal(parseSchemaMajorVersion("1.0.0-rc.1"), 1);
  assert.equal(parseSchemaMajorVersion("v1.5.0"), 1);
  assert.equal(parseSchemaMajorVersion("2.0.0"), 2);
  assert.equal(parseSchemaMajorVersion("0.9.0"), 0);

  assert.equal(parseSchemaMajorVersion(""), null);
  assert.equal(parseSchemaMajorVersion(null), null);
  assert.equal(parseSchemaMajorVersion("invalid-version"), null);
});

test("Contract 1: Reader fails-closed with UnsupportedReceiptSchemaError on major !== 1", () => {
  const baseValidReceipt = {
    schemaVersion: "1.0.0",
    identity: VALID_IDENTITY,
    run: {
      runId: "run-001",
      startedAt: "2026-09-29T07:10:00.000Z",
      finishedAt: "2026-09-29T07:12:00.000Z",
      environment: { platform: "win32", arch: "x64", nodeVersion: "v22.16.0" }
    },
    systemProvenance: { commitSha: "3af1e6d", branch: "main", triadFlowVersion: "2.2.0" },
    providerProvenance: {},
    results: {}
  };

  // Major version 2 -> must throw UnsupportedReceiptSchemaError
  assert.throws(
    () => validateAuditReceipt({ ...baseValidReceipt, schemaVersion: "2.0.0" }),
    (err) => {
      assert.ok(err instanceof UnsupportedReceiptSchemaError);
      assert.equal(err.name, "UnsupportedReceiptSchemaError");
      assert.equal(err.version, "2.0.0");
      assert.match(err.message, /Unsupported receipt schema version/);
      return true;
    }
  );

  // Major version 0 (pre-1.0 draft) -> must throw UnsupportedReceiptSchemaError
  assert.throws(
    () => validateAuditReceipt({ ...baseValidReceipt, schemaVersion: "0.9.0" }),
    (err) => {
      assert.ok(err instanceof UnsupportedReceiptSchemaError);
      assert.equal(err.version, "0.9.0");
      return true;
    }
  );

  // Missing or undefined schemaVersion -> must throw UnsupportedReceiptSchemaError
  assert.throws(
    () => validateAuditReceipt({ ...baseValidReceipt, schemaVersion: undefined }),
    UnsupportedReceiptSchemaError
  );

  // Non-object input -> must throw UnsupportedReceiptSchemaError
  assert.throws(
    () => validateAuditReceipt(null),
    UnsupportedReceiptSchemaError
  );

  // parseAuditReceipt throws UnsupportedReceiptSchemaError on invalid major
  assert.throws(
    () => parseAuditReceipt(JSON.stringify({ ...baseValidReceipt, schemaVersion: "3.0.0" })),
    UnsupportedReceiptSchemaError
  );
});

test("Contract 1: Reader permits backward-compatible minor/patch versions (1.x.y)", () => {
  const receipt11 = buildAuditReceipt({
    identity: VALID_IDENTITY,
    run: {
      runId: "run-002",
      startedAt: "2026-09-29T07:10:00.000Z",
      environment: { platform: "linux", arch: "x64", nodeVersion: "v20.10.0" }
    }
  });

  // 1.0.0 is valid
  const res10 = validateAuditReceipt(receipt11);
  assert.equal(res10.valid, true);

  // 1.1.0 is valid
  receipt11.schemaVersion = "1.1.0";
  const res11 = validateAuditReceipt(receipt11);
  assert.equal(res11.valid, true);

  // 1.2.4-alpha is valid
  receipt11.schemaVersion = "1.2.4-alpha";
  const res12 = validateAuditReceipt(receipt11);
  assert.equal(res12.valid, true);
});

test("Contract 2: Strict separation of stable identity vs run metadata", () => {
  // 1. Valid receipt correctly separates identity and run tiers
  const validReceipt = buildAuditReceipt({
    identity: VALID_IDENTITY,
    run: {
      runId: "run-20260929-151000-abc1",
      startedAt: "2026-09-29T07:10:00.000Z",
      finishedAt: "2026-09-29T07:15:30.000Z",
      environment: { platform: "win32", arch: "x64", nodeVersion: "v22.16.0" }
    },
    systemProvenance: {
      branch: "main",
      commitSha: "3af1e6d8b0",
      triadFlowVersion: "2.2.0"
    }
  });

  const valResult = validateAuditReceipt(validReceipt);
  assert.equal(valResult.valid, true);
  assert.equal(valResult.errors.length, 0);

  // 2. Build receipt rejects runtime keys inside identity tier
  assert.throws(
    () => buildAuditReceipt({
      identity: {
        ...VALID_IDENTITY,
        runId: "leaked-run-id"
      }
    }),
    /Contract 2 Violation: Identity tier contains prohibited runtime key 'runId'/
  );

  // 3. Validator detects Contract 2 violation if runtime keys leak into identity
  const contaminatedIdentityReceipt = {
    ...validReceipt,
    identity: {
      ...validReceipt.identity,
      timestamp: "2026-09-29T07:10:00.000Z",
      tempDir: "C:\\Temp\\scratch"
    }
  };

  const contaminatedValidation = validateAuditReceipt(contaminatedIdentityReceipt);
  assert.equal(contaminatedValidation.valid, false);
  assert.ok(contaminatedValidation.errors.some(e => e.includes("Contract 2 Violation")));
});

test("Contract 4: Source trust tiers and model identity rules", () => {
  // 1. Default actualModel must be { value: null, source: "unavailable" }
  const defaultModel = createDefaultActualModel();
  assert.deepEqual(defaultModel, { value: null, source: SOURCE_TRUST_TIERS.UNAVAILABLE });

  // 2. normalizeActualModel defaults to unavailable when unverified or empty
  assert.deepEqual(normalizeActualModel(null), { value: null, source: "unavailable" });
  assert.deepEqual(normalizeActualModel({}), { value: null, source: "unavailable" });
  assert.deepEqual(normalizeActualModel({ value: "" }), { value: null, source: "unavailable" });

  // 3. Valid source trust tiers accepted
  const verifiedRuntime = normalizeActualModel({ value: "gemini-1.5-pro", source: "runtime" });
  assert.deepEqual(verifiedRuntime, { value: "gemini-1.5-pro", source: "runtime" });

  const verifiedCli = normalizeActualModel({ value: "claude-3-7-sonnet", source: "cli" });
  assert.deepEqual(verifiedCli, { value: "claude-3-7-sonnet", source: "cli" });

  // 4. Invalid source trust tiers fallback to unavailable
  const invalidTier = normalizeActualModel({ value: "model-x", source: "guessed" });
  assert.deepEqual(invalidTier, { value: "model-x", source: "unavailable" });
});

test("Contract 4: Token usage preserves nulls without synthetic zero coercion", () => {
  // 1. Missing tokens remain null, NOT coerced to 0
  const emptyUsage = normalizeReceiptUsage({});
  assert.equal(emptyUsage.promptTokens, null);
  assert.equal(emptyUsage.completionTokens, null);
  assert.equal(emptyUsage.totalTokens, null);
  assert.equal(emptyUsage.usageSource, USAGE_SOURCES.UNAVAILABLE);

  // 2. Partial tokens preserve unobserved nulls
  const partialUsage = normalizeReceiptUsage({ promptTokens: 350 });
  assert.equal(partialUsage.promptTokens, 350);
  assert.equal(partialUsage.completionTokens, null);
  assert.equal(partialUsage.totalTokens, null); // Cannot assume completion is 0!

  // 3. Authoritative full tokens
  const fullUsage = normalizeReceiptUsage({
    available: true,
    completionTokens: 50,
    promptTokens: 400,
    usageSource: "authoritative"
  });
  assert.equal(fullUsage.promptTokens, 400);
  assert.equal(fullUsage.completionTokens, 50);
  assert.equal(fullUsage.totalTokens, 450);
  assert.equal(fullUsage.usageSource, USAGE_SOURCES.AUTHORITATIVE);
});

test("Contract 4: Provider provenance normalization and validation", () => {
  const rawProviders = {
    agy: {
      providerName: "agy",
      configuredModel: "gemini-1.5-flash",
      actualModel: { value: null, source: "unavailable" }, // unverified
      version: "1.1.0",
      usage: { promptTokens: null, completionTokens: null }
    },
    claude: {
      providerName: "claude",
      modelName: "claude-3-7-sonnet",
      actualModel: { value: "claude-3-7-sonnet-20250219", source: "runtime" }, // verified
      version: "0.2.14",
      usage: { promptTokens: 620, completionTokens: 85, usageSource: "authoritative" },
      reviewProfileReady: true
    }
  };

  const normalized = normalizeProviderProvenance(rawProviders);

  assert.equal(normalized.agy.actualModel.value, null);
  assert.equal(normalized.agy.actualModel.source, "unavailable");
  assert.equal(normalized.agy.promptTokens, null);
  assert.equal(normalized.agy.usageSource, "unavailable");

  assert.equal(normalized.claude.actualModel.value, "claude-3-7-sonnet-20250219");
  assert.equal(normalized.claude.actualModel.source, "runtime");
  assert.equal(normalized.claude.promptTokens, 620);
  assert.equal(normalized.claude.totalTokens, 705);
  assert.equal(normalized.claude.usageSource, "authoritative");
  assert.equal(normalized.claude.reviewProfileReady, true);
});

test("Receipt Round-Trip: Serialization, parsing, and computeReceiptDigest", () => {
  const receipt = buildAuditReceipt({
    identity: VALID_IDENTITY,
    run: {
      runId: "run-roundtrip-test-01",
      startedAt: "2026-09-29T10:00:00.000Z",
      finishedAt: "2026-09-29T10:05:00.000Z",
      environment: { platform: "win32", arch: "x64", nodeVersion: "v22.16.0" }
    },
    systemProvenance: {
      branch: "main",
      commitSha: "a1b2c3d4e5",
      triadFlowVersion: "2.2.0"
    },
    providerProvenance: {
      agy: {
        providerName: "agy",
        actualModel: { value: null, source: "unavailable" }
      }
    },
    results: {
      passed: true,
      recallRate: 1.0,
      falseBlockRate: 0.0
    }
  });

  const jsonString = JSON.stringify(receipt, null, 2);

  // Parse back
  const parsed = parseAuditReceipt(jsonString);
  assert.deepEqual(parsed.identity, receipt.identity);
  assert.deepEqual(parsed.run, receipt.run);
  assert.deepEqual(parsed.results, receipt.results);

  // Compute deterministic digest
  const digest1 = computeReceiptDigest(receipt);
  const digest2 = computeReceiptDigest(parsed);

  assert.match(digest1, /^sha256:[a-f0-9]{64}$/);
  assert.equal(digest1, digest2);

  // Modifying run metadata changes receiptDigest (while leaving corpusDigest intact)
  const modifiedReceipt = {
    ...receipt,
    run: {
      ...receipt.run,
      runId: "run-different-id"
    }
  };

  const modifiedDigest = computeReceiptDigest(modifiedReceipt);
  assert.notEqual(modifiedDigest, digest1);
  // Corpus digest remains identical
  assert.equal(modifiedReceipt.identity.corpusDigest, receipt.identity.corpusDigest);
});

test("Contract 5: Baseline Artifact Manifest generation and validation", () => {
  const manifest = buildArtifactManifest({
    artifacts: {
      "audit-receipt.json": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      "benchmark-results.json": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
      "summary.md": "sha256:3333333333333333333333333333333333333333333333333333333333333333"
    },
    metadata: {
      commitSha: "abcdef123456",
      corpusDigest: "sha256:4444444444444444444444444444444444444444444444444444444444444444",
      receiptDigest: "sha256:5555555555555555555555555555555555555555555555555555555555555555",
      resultsDigest: "sha256:6666666666666666666666666666666666666666666666666666666666666666",
      runId: "run-manifest-001"
    }
  });

  assert.equal(manifest.schemaVersion, "1.0.0");
  assert.equal(Object.keys(manifest.artifacts).length, 3);
  // Lexicographical ordering of artifacts
  assert.deepEqual(Object.keys(manifest.artifacts), [
    "audit-receipt.json",
    "benchmark-results.json",
    "summary.md"
  ]);

  const validation = validateArtifactManifest(manifest);
  assert.equal(validation.valid, true);

  // Manifest validator fails-closed on unknown major version
  assert.throws(
    () => validateArtifactManifest({ ...manifest, schemaVersion: "2.0.0" }),
    UnsupportedReceiptSchemaError
  );
});

test("Contract 2 & Receipt Digest: computeReceiptDigest fails-closed on invalid receipts", () => {
  // Missing identity tier throws ReceiptValidationError
  assert.throws(
    () => computeReceiptDigest({ schemaVersion: "1.0.0" }),
    (err) => {
      assert.ok(err instanceof ReceiptValidationError);
      assert.ok(err.errors.length > 0);
      return true;
    }
  );

  // Leaked runtime field into identity throws ReceiptValidationError
  const invalidReceipt = {
    schemaVersion: "1.0.0",
    identity: {
      ...VALID_IDENTITY,
      runId: "leaked-run-id"
    },
    run: {
      runId: "run-001",
      startedAt: "2026-09-29T00:00:00.000Z",
      environment: { platform: "linux" }
    },
    systemProvenance: {},
    providerProvenance: {},
    results: {}
  };

  assert.throws(
    () => computeReceiptDigest(invalidReceipt),
    ReceiptValidationError
  );
});

test("Contract 3: validateAuditReceipt enforces strict SHA-256 lowercase hex pattern", () => {
  const baseValidReceipt = buildAuditReceipt({
    identity: VALID_IDENTITY,
    run: {
      runId: "run-sha-check",
      startedAt: "2026-09-29T00:00:00.000Z",
      environment: { platform: "win32" }
    }
  });

  // Short fake hash
  const invalidCorpusDigest = {
    ...baseValidReceipt,
    identity: {
      ...baseValidReceipt.identity,
      corpusDigest: "sha256:fake"
    }
  };
  const val1 = validateAuditReceipt(invalidCorpusDigest);
  assert.equal(val1.valid, false);
  assert.ok(val1.errors.some(e => e.includes("identity.corpusDigest must be a valid lowercase SHA-256")));

  // Upper-case or invalid character hash
  const invalidCaseDigest = {
    ...baseValidReceipt,
    identity: {
      ...baseValidReceipt.identity,
      caseDigests: {
        "CASE-1": "sha256:GHIJKLMNOPQRSTUVWXYZ0123456789abcdef0123456789abcdef0123456789abcdef"
      }
    }
  };
  const val2 = validateAuditReceipt(invalidCaseDigest);
  assert.equal(val2.valid, false);
  assert.ok(val2.errors.some(e => e.includes("must be a valid lowercase SHA-256")));
});

test("Contract 4: validateAuditReceipt strictly validates actualModel and source trust tiers", () => {
  const validBase = buildAuditReceipt({
    identity: VALID_IDENTITY,
    run: {
      runId: "run-prov-check",
      startedAt: "2026-09-29T00:00:00.000Z",
      environment: { platform: "win32" }
    }
  });

  // 1. Missing actualModel
  const missingModel = {
    ...validBase,
    providerProvenance: {
      agy: { providerName: "agy" }
    }
  };
  const valMissing = validateAuditReceipt(missingModel);
  assert.equal(valMissing.valid, false);
  assert.ok(valMissing.errors.some(e => e.includes("must record 'actualModel'")));

  // 2. actualModel.value is not string or null
  const numericModel = {
    ...validBase,
    providerProvenance: {
      agy: {
        actualModel: { value: 12345, source: "runtime" }
      }
    }
  };
  const valNumeric = validateAuditReceipt(numericModel);
  assert.equal(valNumeric.valid, false);
  assert.ok(valNumeric.errors.some(e => e.includes("actualModel.value must be a string or null")));

  // 3. actualModel.value is null but source is not 'unavailable'
  const nullWithValueSource = {
    ...validBase,
    providerProvenance: {
      agy: {
        actualModel: { value: null, source: "runtime" }
      }
    }
  };
  const valNullSource = validateAuditReceipt(nullWithValueSource);
  assert.equal(valNullSource.valid, false);
  assert.ok(valNullSource.errors.some(e => e.includes("actualModel.source must be 'unavailable' when value is null")));
});

test("Contract 4: validateAuditReceipt rejects negative tokens and token sum mismatches", () => {
  const validBase = buildAuditReceipt({
    identity: VALID_IDENTITY,
    run: {
      runId: "run-token-check",
      startedAt: "2026-09-29T00:00:00.000Z",
      environment: { platform: "win32" }
    }
  });

  // Negative tokens
  const negTokens = {
    ...validBase,
    providerProvenance: {
      agy: {
        actualModel: { value: null, source: "unavailable" },
        promptTokens: -100
      }
    }
  };
  const valNeg = validateAuditReceipt(negTokens);
  assert.equal(valNeg.valid, false);
  assert.ok(valNeg.errors.some(e => e.includes("promptTokens must be a non-negative integer")));

  // Sum mismatch (prompt: 100, completion: 50, total: 300)
  const sumMismatch = {
    ...validBase,
    providerProvenance: {
      claude: {
        actualModel: { value: "claude-3-7-sonnet", source: "runtime" },
        promptTokens: 100,
        completionTokens: 50,
        totalTokens: 300
      }
    }
  };
  const valSum = validateAuditReceipt(sumMismatch);
  assert.equal(valSum.valid, false);
  assert.ok(valSum.errors.some(e => e.includes("does not equal promptTokens (100) + completionTokens (50)")));
});

test("Contract 5: validateArtifactManifest rejects invalid SHA-256 digests in artifacts and metadata", () => {
  const badManifest = {
    schemaVersion: "1.0.0",
    artifacts: {
      "audit-receipt.json": "sha256:not-a-valid-hash"
    },
    metadata: {
      runId: "run-01",
      corpusDigest: "sha256:also-bad"
    }
  };

  const val = validateArtifactManifest(badManifest);
  assert.equal(val.valid, false);
  assert.ok(val.errors.some(e => e.includes("Artifact 'audit-receipt.json' digest must be a valid lowercase SHA-256")));
  assert.ok(val.errors.some(e => e.includes("metadata.corpusDigest must be a valid lowercase SHA-256")));
});

test("Receipt Reader: parseAuditReceipt throws ReceiptValidationError on malformed JSON", () => {
  assert.throws(
    () => parseAuditReceipt("{ invalid json content ]"),
    ReceiptValidationError
  );
});

