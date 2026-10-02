/**
 * Triad-Flow Semantic Chunk Manager (RFC-027-01)
 *
 * Implements risk-priority diff chunking, Windows ARG_MAX safe chunk sizing,
 * and chunk manifest generation.
 */

import crypto from "node:crypto";
import { classifyFileRisk, RISK_TIERS } from "./graph-router.mjs";
import { normalizeCanonicalPath } from "./scoring.mjs";
import { decodeGitCStyleString } from "./git-numstat.mjs";

export const CHUNK_LIMIT_WINDOWS_BYTES = 6000;   // Safe ceiling on Windows accounting for prompt wrapper overhead
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
 * Parses Git diff headers supporting quoted and C-style escaped paths.
 * @param {string} line
 * @returns {{ fileA: string, fileB: string } | null}
 */
export function parseGitDiffHeader(line) {
  if (!line || typeof line !== "string" || !line.startsWith("diff --git ")) return null;
  const rest = line.slice("diff --git ".length).trim();
  let rawA = null;
  let rawB = null;
  let wasQuotedA = false;
  let wasQuotedB = false;

  if (rest.startsWith('"')) {
    let escape = false;
    let endQuoteIdx = -1;
    for (let i = 1; i < rest.length; i++) {
      if (escape) {
        escape = false;
      } else if (rest[i] === "\\") {
        escape = true;
      } else if (rest[i] === '"') {
        endQuoteIdx = i;
        break;
      }
    }
    if (endQuoteIdx !== -1) {
      rawA = rest.slice(0, endQuoteIdx + 1);
      rawB = rest.slice(endQuoteIdx + 1).trim();
      wasQuotedA = true;
      wasQuotedB = rawB.startsWith('"') && rawB.endsWith('"');
    }
  } else {
    // Unquoted rawA: match standard git pattern "a/<pathA> b/<pathB>" where paths may contain spaces
    const gitMatch = rest.match(/^a\/(.+?)\s+b\/(.+)$/);
    if (gitMatch) {
      rawA = `a/${gitMatch[1]}`;
      rawB = `b/${gitMatch[2]}`;
      wasQuotedA = false;
      wasQuotedB = rawB.startsWith('"') && rawB.endsWith('"');
    } else {
      const spaceIdx = rest.indexOf(" ");
      if (spaceIdx !== -1) {
        rawA = rest.slice(0, spaceIdx);
        rawB = rest.slice(spaceIdx + 1).trim();
        wasQuotedA = false;
        wasQuotedB = rawB.startsWith('"') && rawB.endsWith('"');
      }
    }
  }

  if (!rawA || !rawB) return null;

  const unquotePath = (p, prefix, wasQuoted) => {
    let unquoted = p;
    if (wasQuoted && unquoted.startsWith('"') && unquoted.endsWith('"')) {
      unquoted = unquoted.slice(1, -1);
    }
    if (unquoted.startsWith(prefix)) {
      unquoted = unquoted.slice(prefix.length);
    }
    if (wasQuoted) {
      unquoted = decodeGitCStyleString(`"${unquoted}"`);
    }
    return unquoted;
  };

  return {
    fileA: unquotePath(rawA, "a/", wasQuotedA),
    fileB: unquotePath(rawB, "b/", wasQuotedB)
  };
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
    // Detect diff header: diff --git a/path b/path or diff --git "a/path" "b/path"
    const gitMatch = parseGitDiffHeader(line);
    if (gitMatch) {
      flush();
      const target = (gitMatch.fileB === "/dev/null" || gitMatch.fileB === "dev/null")
        ? gitMatch.fileA
        : gitMatch.fileB;
      currentFile = normalizeCanonicalPath(target);
      currentLines.push(line);
      continue;
    }

    // Detect fallback diff header: +++ b/path or +++ "b/path"
    const plusMatch = line.match(/^\+\+\+ (?:"b\/(.+?)"|b\/(.+?))$/);
    if (plusMatch && (!currentFile || !currentLines.some(l => l.startsWith("diff --git")))) {
      const isQuoted = Boolean(plusMatch[1]);
      const rawTarget = plusMatch[1] || plusMatch[2];
      const target = isQuoted ? decodeGitCStyleString(`"${rawTarget}"`) : rawTarget;
      if (currentFile && currentFile !== normalizeCanonicalPath(target)) {
        flush();
      }
      currentFile = normalizeCanonicalPath(target);
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
        // Massive file: partition across hunks, and sub-partition oversized hunks by lines
        const hunks = fileHunks.split(/(?=^@@ )/m);
        const header = hunks.length > 1 ? hunks[0] : "";
        const hunkList = hunks.length > 1 ? hunks.slice(1) : hunks;

        let subHunks = [];
        let subBytes = Buffer.byteLength(header, "utf8");

        for (const h of hunkList) {
          const hBytes = Buffer.byteLength(h, "utf8");

          if (hBytes > maxChunkBytes) {
            // First flush accumulated subHunks if any
            if (subHunks.length > 0) {
              rawChunks.push({
                priorityTier: tier,
                targetFiles: [filePath],
                diffHunks: header + subHunks.join("")
              });
              subHunks = [];
              subBytes = Buffer.byteLength(header, "utf8");
            }

            // Split this oversized hunk by lines
            const lines = h.split("\n");
            const hunkHeader = lines[0].startsWith("@@") ? lines[0] : "@@ -1,1 +1,1 @@";
            const bodyLines = lines[0].startsWith("@@") ? lines.slice(1) : lines;
            let currentLineGroup = [];
            let currentGroupBytes = Buffer.byteLength(header + hunkHeader + "\n", "utf8");

            for (const line of bodyLines) {
              const lineBytes = Buffer.byteLength(line + "\n", "utf8");
              if (currentGroupBytes + lineBytes > maxChunkBytes && currentLineGroup.length > 0) {
                rawChunks.push({
                  priorityTier: tier,
                  targetFiles: [filePath],
                  diffHunks: header + hunkHeader + "\n" + currentLineGroup.join("\n")
                });
                currentLineGroup = [line];
                currentGroupBytes = Buffer.byteLength(header + hunkHeader + "\n" + line + "\n", "utf8");
              } else {
                currentLineGroup.push(line);
                currentGroupBytes += lineBytes;
              }
            }
            if (currentLineGroup.length > 0) {
              rawChunks.push({
                priorityTier: tier,
                targetFiles: [filePath],
                diffHunks: header + hunkHeader + "\n" + currentLineGroup.join("\n")
              });
            }
          } else if (subBytes + hBytes > maxChunkBytes && subHunks.length > 0) {
            rawChunks.push({
              priorityTier: tier,
              targetFiles: [filePath],
              diffHunks: header + subHunks.join("")
            });
            subHunks = [h];
            subBytes = Buffer.byteLength(header, "utf8") + hBytes;
          } else {
            subHunks.push(h);
            subBytes += hBytes;
          }
        }

        if (subHunks.length > 0) {
          rawChunks.push({
            priorityTier: tier,
            targetFiles: [filePath],
            diffHunks: header + subHunks.join("")
          });
        }
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
