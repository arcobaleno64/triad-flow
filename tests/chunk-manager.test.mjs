import test from "node:test";
import assert from "node:assert/strict";
import {
  getSafeChunkLimit,
  splitDiffByFiles,
  partitionChangeSetIntoChunks,
  CHUNK_LIMIT_WINDOWS_BYTES,
  CHUNK_LIMIT_POSIX_BYTES
} from "../src/core/chunk-manager.mjs";
import { RISK_TIERS } from "../src/core/graph-router.mjs";

test("getSafeChunkLimit respects platform ceilings", () => {
  assert.equal(getSafeChunkLimit("win32"), CHUNK_LIMIT_WINDOWS_BYTES);
  assert.equal(getSafeChunkLimit("linux"), CHUNK_LIMIT_POSIX_BYTES);
  assert.equal(getSafeChunkLimit("darwin"), CHUNK_LIMIT_POSIX_BYTES);
});

test("splitDiffByFiles separates git diff into per-file segments", () => {
  const diff = [
    "diff --git a/src/auth.js b/src/auth.js",
    "--- a/src/auth.js",
    "+++ b/src/auth.js",
    "@@ -1,2 +1,3 @@",
    "+ const jwt = require('jsonwebtoken');",
    "diff --git a/docs/readme.md b/docs/readme.md",
    "--- a/docs/readme.md",
    "+++ b/docs/readme.md",
    "@@ -10 +10 @@",
    "- old",
    "+ new"
  ].join("\n");

  const map = splitDiffByFiles(diff);
  assert.equal(map.size, 2);
  assert.ok(map.has("src/auth.js"));
  assert.ok(map.has("docs/readme.md"));
});

test("partitionChangeSetIntoChunks prioritizes Tier 1 (Critical) files first", () => {
  const diff = [
    "diff --git a/docs/readme.md b/docs/readme.md",
    "+ docs update",
    "diff --git a/src/auth/jwt.js b/src/auth/jwt.js",
    "+ const secret = 'key';",
    "diff --git a/src/utils.js b/src/utils.js",
    "+ export function help() {}"
  ].join("\n");

  const cs = {
    files: [
      { path: "docs/readme.md" },
      { path: "src/auth/jwt.js" },
      { path: "src/utils.js" }
    ],
    diffHunks: diff
  };

  // Force small chunk limit so each file gets its own chunk
  const chunks = partitionChangeSetIntoChunks(cs, { maxChunkBytes: 50 });
  assert.ok(chunks.length >= 2);

  // The first chunk must contain Tier 1 (auth/jwt.js)
  assert.equal(chunks[0].priorityTier, RISK_TIERS.TIER_1_CRITICAL);
  assert.ok(chunks[0].targetFiles.includes("src/auth/jwt.js"));

  // Every chunk must have deterministic ID and SHA-256 digest
  for (const c of chunks) {
    assert.match(c.chunkId, /^chunk-[a-f0-9-]+-\d{3}$/);
    assert.match(c.contentDigest, /^[a-f0-9]{64}$/);
    assert.ok(c.totalChunks === chunks.length);
  }
});
