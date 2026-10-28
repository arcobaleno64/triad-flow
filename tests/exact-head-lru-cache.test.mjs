import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { execFileSync } from "node:child_process";
import {
  ExactHeadLruCache,
  exactHeadContentCache,
  getExactHeadFileContent,
  clearExactHeadCache
} from "../src/core/git-collector.mjs";

test("G5-P2-04 (A): ExactHeadLruCache enforces maxEntries bound with LRU eviction", () => {
  const cache = new ExactHeadLruCache({ maxEntries: 3, maxBytes: 1024 * 1024 });

  cache.set("k1", "val-1");
  cache.set("k2", "val-2");
  cache.set("k3", "val-3");
  assert.equal(cache.size, 3);

  // Access k1, making k2 the oldest (LRU) entry
  assert.equal(cache.get("k1"), "val-1");

  // Insert k4, should evict k2
  cache.set("k4", "val-4");
  assert.equal(cache.size, 3);
  assert.equal(cache.has("k2"), false, "k2 must be evicted as LRU");
  assert.equal(cache.has("k1"), true);
  assert.equal(cache.has("k3"), true);
  assert.equal(cache.has("k4"), true);
});

test("G5-P2-04 (B): ExactHeadLruCache enforces maxBytes bound with byte-aware eviction", () => {
  const cache = new ExactHeadLruCache({ maxEntries: 10, maxBytes: 30 });

  // 10 bytes each
  cache.set("k1", "1234567890"); // 10 bytes
  cache.set("k2", "1234567890"); // 10 bytes
  assert.equal(cache.size, 2);
  assert.equal(cache.bytes, 20);

  // Add 15 bytes -> total would be 35 > 30, evicts k1
  cache.set("k3", "123456789012345"); // 15 bytes
  assert.equal(cache.has("k1"), false, "k1 must be evicted to stay within maxBytes");
  assert.equal(cache.has("k2"), true);
  assert.equal(cache.has("k3"), true);
  assert.equal(cache.bytes, 25);
  assert.ok(cache.bytes <= 30);
});

test("G5-P2-04 (C): ExactHeadLruCache rejects single payload exceeding maxBytes without evicting others", () => {
  const cache = new ExactHeadLruCache({ maxEntries: 5, maxBytes: 20 });
  cache.set("k1", "small");
  assert.equal(cache.has("k1"), true);

  // Giant payload > 20 bytes
  cache.set("k_giant", "this-is-a-very-long-string-that-exceeds-max-bytes");
  assert.equal(cache.has("k_giant"), false, "Oversized payload must not be stored");
  assert.equal(cache.has("k1"), true, "Existing entries must not be evicted for rejected item");
});

test("G5-P2-04 (D): ExactHeadLruCache refuses to store null or undefined (negative cache prevention)", () => {
  const cache = new ExactHeadLruCache({ maxEntries: 5, maxBytes: 100 });
  cache.set("k_null", null);
  cache.set("k_undef", undefined);

  assert.equal(cache.has("k_null"), false);
  assert.equal(cache.has("k_undef"), false);
  assert.equal(cache.size, 0);
});

test("G5-P2-04 (E): getExactHeadFileContent does not cache failed lookups, allowing subsequent retrieval without manual cache clear", () => {
  clearExactHeadCache();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tf-exact-head-g5-"));

  try {
    execFileSync("git", ["init"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "test@triad.flow"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "Triad Tester"], { cwd: tmpDir, stdio: "ignore" });

    // Initial commit with file1
    fs.writeFileSync(path.join(tmpDir, "file1.txt"), "hello v1", "utf8");
    execFileSync("git", ["add", "file1.txt"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "commit 1"], { cwd: tmpDir, stdio: "ignore" });
    const head1 = execFileSync("git", ["rev-parse", "HEAD"], { cwd: tmpDir, encoding: "utf8" }).trim();

    // 1. Query file2 which does not exist in commit 1 -> returns null
    const miss = getExactHeadFileContent(tmpDir, head1, "file2.txt");
    assert.equal(miss, null);

    // Verify negative cache is NOT present in exactHeadContentCache
    const normRepo = path.resolve(tmpDir).replace(/\\/g, "/");
    const cacheKey = `${normRepo}:${head1}:file2.txt`;
    assert.equal(exactHeadContentCache.has(cacheKey), false, "Failed lookup must not be cached as null");

    // 2. Query file1 which DOES exist in commit 1 -> returns content and caches it
    const hit = getExactHeadFileContent(tmpDir, head1, "file1.txt");
    assert.equal(hit, "hello v1");
    const hitKey = `${normRepo}:${head1}:file1.txt`;
    assert.equal(exactHeadContentCache.has(hitKey), true, "Successful lookup must be cached");

    // 3. Update file2 in a new commit
    fs.writeFileSync(path.join(tmpDir, "file2.txt"), "hello v2", "utf8");
    execFileSync("git", ["add", "file2.txt"], { cwd: tmpDir, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "commit 2"], { cwd: tmpDir, stdio: "ignore" });
    const head2 = execFileSync("git", ["rev-parse", "HEAD"], { cwd: tmpDir, encoding: "utf8" }).trim();

    // Query file2 at head2 -> succeeds immediately without manual clearExactHeadCache()
    const hit2 = getExactHeadFileContent(tmpDir, head2, "file2.txt");
    assert.equal(hit2, "hello v2");
  } finally {
    clearExactHeadCache();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
