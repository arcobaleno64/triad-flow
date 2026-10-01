/**
 * Triad-Flow Semantic Chunk Manager (RFC-027-01)
 *
 * Implements risk-priority diff chunking, Windows ARG_MAX safe chunk sizing,
 * and chunk manifest generation.
 */

import crypto from "node:crypto";
import { classifyFileRisk, RISK_TIERS } from "./graph-router.mjs";
import { normalizeCanonicalPath } from "./scoring.mjs";

export const CHUNK_LIMIT_WINDOWS_BYTES = 8192;   // 8 KB ceiling on Windows
export const CHUNK_LIMIT_POSIX_BYTES = 65536;    // 64 KB ceiling on POSIX

/**
 * Returns the maximum safe chunk payload size in bytes for the host platform.
 * @param {string} [platform=process.platform]
 * @returns {number}
 */
export function getSafeChunkLimit(platform = process.platform) {
  return platform === "win32" ? CHUNK_LIMIT_WINDOWS_BYTES : CHUNK_LIMIT_POSIX_BYTES;
}

/**
 * Splits a unified diff text into individual per-file diff blocks.
 * @param {string} diffText
 * @returns {Map<string, string>} Mapping of filePath -> fileDiffHunks
 */
export function splitDiffByFiles(diffText) {
  const fileDiffs = new Map();
  if (!diffText || typeof diffText !== "string") return fileDiffs;

  const lines = diffText.split(/\r?\n/);
  let currentFile = null;
  let currentLines = [];

  const flush = () => {
    if (currentFile && currentLines.length > 0) {
      fileDiffs.set(currentFile, currentLines.join("\n"));
    }
    currentLines = [];
  };

  for (const line of lines) {
    // Detect diff header: diff --git a/path b/path
    const gitMatch = line.match(/^diff --git a\/(.+?) b\/(.+?)$/);
    if (gitMatch) {
      flush();
      currentFile = normalizeCanonicalPath(gitMatch[2]);
      currentLines.push(line);
      continue;
    }

    // Detect fallback diff header: +++ b/path
    const plusMatch = line.match(/^\+\+\+ b\/(.+?)$/);
    if (plusMatch && (!currentFile || !currentLines.some(l => l.startsWith("diff --git")))) {
      if (currentFile && currentFile !== normalizeCanonicalPath(plusMatch[1])) {
        flush();
      }
      currentFile = normalizeCanonicalPath(plusMatch[1]);
    }

    if (currentFile) {
      currentLines.push(line);
    }
  }

  flush();
  return fileDiffs;
}

/**
 * Partitions a ChangeSet into coherent semantic chunks ordered by risk tier.
 * @param {object} changeSet
 * @param {object} [options={}]
 * @returns {Array<object>} Array of SemanticChunk objects
 */
export function partitionChangeSetIntoChunks(changeSet, options = {}) {
  const runId = options.runId || crypto.randomUUID();
  const maxChunkBytes = options.maxChunkBytes || getSafeChunkLimit(options.platform || process.platform);
  const diffHunks = changeSet?.diffHunks || "";
  const files = changeSet?.files || [];

  if (!diffHunks || files.length === 0) {
    return [];
  }

  const fileDiffMap = splitDiffByFiles(diffHunks);

  // Group files by risk tier (Tier 1: Critical -> Tier 2: Source -> Tier 3: Docs)
  const tierBuckets = {
    [RISK_TIERS.TIER_1_CRITICAL]: [],
    [RISK_TIERS.TIER_2_SOURCE]: [],
    [RISK_TIERS.TIER_3_DOCS]: [],
    [RISK_TIERS.TIER_IGNORED]: []
  };

  for (const f of files) {
    const filePath = typeof f === "string" ? f : f.path;
    const tier = classifyFileRisk(filePath);
    if (tierBuckets[tier]) {
      tierBuckets[tier].push(f);
    } else {
      tierBuckets[RISK_TIERS.TIER_2_SOURCE].push(f);
    }
  }

  const rawChunks = [];

  // Process tiers in strict priority order: 1 -> 2 -> 3
  const tiersToProcess = [
    RISK_TIERS.TIER_1_CRITICAL,
    RISK_TIERS.TIER_2_SOURCE,
    RISK_TIERS.TIER_3_DOCS
  ];

  for (const tier of tiersToProcess) {
    const tierFiles = tierBuckets[tier];
    if (tierFiles.length === 0) continue;

    let currentChunkFiles = [];
    let currentChunkHunks = [];
    let currentChunkBytes = 0;

    for (const f of tierFiles) {
      const filePath = normalizeCanonicalPath(typeof f === "string" ? f : f.path);
      const fileHunks = fileDiffMap.get(filePath) || "";
      const fileBytes = Buffer.byteLength(fileHunks, "utf8");

      // If single file diff exceeds maxChunkBytes, it becomes its own chunk (or partitioned)
      if (fileBytes > maxChunkBytes && currentChunkFiles.length > 0) {
        // Flush existing accumulated chunk first
        rawChunks.push({
          priorityTier: tier,
          targetFiles: currentChunkFiles,
          diffHunks: currentChunkHunks.join("\n\n")
        });
        currentChunkFiles = [];
        currentChunkHunks = [];
        currentChunkBytes = 0;
      }

      if (fileBytes > maxChunkBytes) {
        // Massive file: Put into standalone chunk with warning notice
        rawChunks.push({
          priorityTier: tier,
          targetFiles: [filePath],
          diffHunks: fileHunks
        });
        continue;
      }

      // Check if adding this file exceeds chunk limit
      if (currentChunkBytes + fileBytes > maxChunkBytes && currentChunkFiles.length > 0) {
        rawChunks.push({
          priorityTier: tier,
          targetFiles: currentChunkFiles,
          diffHunks: currentChunkHunks.join("\n\n")
        });
        currentChunkFiles = [filePath];
        currentChunkHunks = [fileHunks];
        currentChunkBytes = fileBytes;
      } else {
        currentChunkFiles.push(filePath);
        currentChunkHunks.push(fileHunks);
        currentChunkBytes += fileBytes;
      }
    }

    if (currentChunkFiles.length > 0) {
      rawChunks.push({
        priorityTier: tier,
        targetFiles: currentChunkFiles,
        diffHunks: currentChunkHunks.join("\n\n")
      });
    }
  }

  // If no chunks were formed but diffHunks exists, fallback to single chunk
  if (rawChunks.length === 0 && diffHunks) {
    rawChunks.push({
      priorityTier: RISK_TIERS.TIER_2_SOURCE,
      targetFiles: files.map(f => normalizeCanonicalPath(typeof f === "string" ? f : f.path)),
      diffHunks
    });
  }

  // Format into final SemanticChunk objects with indexes and digests
  const totalChunks = rawChunks.length;
  return rawChunks.map((chunk, idx) => {
    const chunkIndex = idx + 1;
    const chunkId = `chunk-${runId}-${String(chunkIndex).padStart(3, "0")}`;
    const contentDigest = crypto.createHash("sha256").update(chunk.diffHunks).digest("hex");
    const byteLength = Buffer.byteLength(chunk.diffHunks, "utf8");

    return {
      chunkId,
      runId,
      chunkIndex,
      totalChunks,
      priorityTier: chunk.priorityTier,
      targetFiles: chunk.targetFiles,
      diffHunks: chunk.diffHunks,
      contentDigest,
      byteLength
    };
  });
}
