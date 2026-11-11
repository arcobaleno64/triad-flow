/**
 * Triad-Flow Distributed Swarm Orchestrator (v2.12 Pillar 2)
 *
 * Implements:
 * 1. Dependency-Aware ChangeSet Partitioning (AST cross-file symbol correlation, call graph & module clustering)
 * 2. Cryptographic Intermediate Receipt Hash Chain (SHA-256 forward hash linking & anti-tampering verification)
 * 3. Fail-Closed Circuit Breaker with Timeout & Fallback (UNINSPECTED_CHUNK marking, zero silent swallowing)
 *
 * Invariants:
 * - Strict Zero External Dependencies (Node.js Core APIs only: node:crypto, node:path)
 * - Strict Fail-Closed Semantics: Worker timeout or disruption never emits false approval.
 */

import crypto from "node:crypto";
import path from "node:path";
import { canonicalJsonStringify, computeDigest } from "./canonical-digest.mjs";
import { classifyFileRisk, RISK_TIERS } from "./graph-router.mjs";
import { normalizeCanonicalPath } from "./scoring.mjs";
import { splitDiffByFiles, getSafeChunkLimit } from "./chunk-manager.mjs";
import { TaxonomyQuorumCalibrator } from "./taxonomy-quorum.mjs";

/**
 * Genesis receipt hash constant (64 zeros prefixed with sha256:).
 */
export const GENESIS_RECEIPT_HASH = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/**
 * Circuit Breaker States.
 */
export const CIRCUIT_BREAKER_STATES = Object.freeze({
  CLOSED: "CLOSED",
  OPEN: "OPEN",
  HALF_OPEN: "HALF_OPEN"
});

/**
 * Partition & Chunk Statuses.
 */
export const CHUNK_STATUS = Object.freeze({
  INSPECTED: "INSPECTED",
  UNINSPECTED_CHUNK: "UNINSPECTED_CHUNK"
});

/**
 * Swarm Consensus Verdicts.
 */
export const SWARM_VERDICTS = Object.freeze({
  APPROVE: "approve",
  WARNING: "warning",
  NEEDS_ATTENTION: "needs-attention",
  ERROR: "error"
});

/**
 * Error thrown when a cryptographic receipt chain is tampered with,
 * broken, or contains mismatched hashes.
 */
export class ReceiptChainTamperedError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = "ReceiptChainTamperedError";
    this.details = details;
  }
}

/**
 * Error thrown when an operation is rejected because a worker's circuit breaker is OPEN.
 */
export class CircuitBreakerOpenError extends Error {
  constructor(message, workerId = null) {
    super(message);
    this.name = "CircuitBreakerOpenError";
    this.workerId = workerId;
  }
}

/**
 * Error thrown when a worker execution times out.
 */
export class SwarmTimeoutError extends Error {
  constructor(message, timeoutMs = null) {
    super(message);
    this.name = "SwarmTimeoutError";
    this.timeoutMs = timeoutMs;
  }
}

/**
 * Disjoint Set Union (Union-Find) structure for clustering files with dependency edges.
 */
export class UnionFind {
  constructor(elements = []) {
    this.parent = new Map();
    for (const elem of elements) {
      this.parent.set(elem, elem);
    }
  }

  find(item) {
    if (!this.parent.has(item)) {
      this.parent.set(item, item);
      return item;
    }
    let root = item;
    while (this.parent.get(root) !== root) {
      root = this.parent.get(root);
    }
    // Path compression
    let curr = item;
    while (curr !== root) {
      const next = this.parent.get(curr);
      this.parent.set(curr, root);
      curr = next;
    }
    return root;
  }

  union(a, b) {
    const rootA = this.find(a);
    const rootB = this.find(b);
    if (rootA !== rootB) {
      this.parent.set(rootB, rootA);
      return true;
    }
    return false;
  }

  getClusters() {
    const clusters = new Map();
    for (const item of this.parent.keys()) {
      const root = this.find(item);
      if (!clusters.has(root)) {
        clusters.set(root, []);
      }
      clusters.get(root).push(item);
    }
    return Array.from(clusters.values());
  }
}

/**
 * Extracts declared imports, requires, and call/symbol references across diff hunks.
 *
 * @param {Map<string, string>} fileDiffMap - Map of filePath -> diff text
 * @param {string[]} allFiles - Canonical paths of all files in ChangeSet
 * @returns {{ dependencyEdges: Array<{ from: string, to: string, kind: string, symbol?: string }>, symbolMap: Map<string, string[]> }}
 */
export function extractCrossFileDependencies(fileDiffMap, allFiles = []) {
  const normalizedKnownFiles = allFiles.map(f => normalizeCanonicalPath(f));
  const fileBasenameMap = new Map();
  for (const f of normalizedKnownFiles) {
    const base = path.basename(f).replace(/\.[^.]+$/, "");
    if (!fileBasenameMap.has(base)) {
      fileBasenameMap.set(base, []);
    }
    fileBasenameMap.get(base).push(f);
  }

  const dependencyEdges = [];
  const definedSymbolsPerFile = new Map();

  // Step 1: Detect symbol definitions in added/modified lines (+)
  // Regexes for function, class, and variable definitions
  const DEF_REGEXES = [
    /(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([a-zA-Z0-9_$]+)\s*\(/g,
    /(?:export\s+)?(?:default\s+)?class\s+([a-zA-Z0-9_$]+)/g,
    /(?:export\s+)?(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[a-zA-Z0-9_$]+)?\s*=>/g,
    /(?:async\s+)?def\s+([a-zA-Z0-9_$]+)\s*\(/g,
    /(?:func|type)\s+([a-zA-Z0-9_$]+)\b/g
  ];

  for (const [filePath, diffText] of fileDiffMap.entries()) {
    const symbols = new Set();
    const addedLines = diffText
      .split(/\r?\n/)
      .filter(line => line.startsWith("+") && !line.startsWith("+++"))
      .map(line => line.slice(1));

    for (const line of addedLines) {
      for (const regex of DEF_REGEXES) {
        regex.lastIndex = 0;
        let match;
        while ((match = regex.exec(line)) !== null) {
          const sym = match[1];
          if (sym && sym.length > 2 && !["if", "for", "while", "return", "catch", "switch"].includes(sym)) {
            symbols.add(sym);
          }
        }
      }
    }
    definedSymbolsPerFile.set(filePath, Array.from(symbols));
  }

  // Step 2: Detect imports, requires and symbol references from file A to file B
  const IMPORT_REGEXES = [
    /(?:import|from)\s+['"]([^'"]+)['"]/g,
    /require\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
    /#include\s+["<]([^">]+)[">]/g
  ];

  for (const [sourceFile, diffText] of fileDiffMap.entries()) {
    // 2a. Import/Require target matching
    for (const regex of IMPORT_REGEXES) {
      regex.lastIndex = 0;
      let match;
      while ((match = regex.exec(diffText)) !== null) {
        const importTarget = match[1];
        const targetClean = importTarget.replace(/^[./\\]+/, "");
        const targetBase = path.basename(targetClean).replace(/\.[^.]+$/, "");

        // Match against known ChangeSet files
        for (const candidate of normalizedKnownFiles) {
          if (candidate === sourceFile) continue;
          if (
            candidate.endsWith(targetClean) ||
            candidate.includes(targetClean) ||
            (targetBase && fileBasenameMap.get(targetBase)?.includes(candidate))
          ) {
            dependencyEdges.push({
              from: sourceFile,
              to: candidate,
              kind: "import"
            });
          }
        }
      }
    }

    // 2b. Cross-file Symbol Call-Graph references
    for (const [targetFile, definedSymbols] of definedSymbolsPerFile.entries()) {
      if (targetFile === sourceFile) continue;
      for (const sym of definedSymbols) {
        // Look for symbol invocation or reference in diff lines of sourceFile
        const symRefRegex = new RegExp(`\\b${sym}\\b(?:\\s*\\()`);
        if (symRefRegex.test(diffText)) {
          dependencyEdges.push({
            from: sourceFile,
            to: targetFile,
            kind: "call_reference",
            symbol: sym
          });
        }
      }
    }
  }

  return {
    dependencyEdges,
    symbolMap: definedSymbolsPerFile
  };
}

/**
 * Partitions a ChangeSet using dependency-aware module clustering.
 *
 * Files with mutual dependencies (imports, call references, symbol definitions)
 * are placed into the same partition cluster whenever possible, preventing
 * splitting interdependent functions across arbitrary boundaries.
 *
 * @param {object} changeSet
 * @param {object} [options={}]
 * @returns {Array<object>} Array of SwarmPartition objects
 */
export function partitionChangeSetWithDependencies(changeSet, options = {}) {
  const runId = options.runId || crypto.randomUUID();
  const maxChunkBytes = options.maxChunkBytes || getSafeChunkLimit(options.platform || process.platform);
  const diffHunks = changeSet?.diffHunks || "";
  const files = changeSet?.files || [];

  if (!diffHunks || files.length === 0) {
    return [];
  }

  const filePaths = files.map(f => normalizeCanonicalPath(typeof f === "string" ? f : f.path)).filter(Boolean);
  const fileDiffMap = splitDiffByFiles(diffHunks, filePaths);

  // 1. Extract cross-file AST / Call-graph symbol dependencies
  const { dependencyEdges, symbolMap } = extractCrossFileDependencies(fileDiffMap, filePaths);

  // Add explicit caller dependencies if provided
  if (Array.isArray(options.dependencyEdges)) {
    dependencyEdges.push(...options.dependencyEdges);
  }
  if (options.dependencyGraph && typeof options.dependencyGraph === "object") {
    for (const [src, targets] of Object.entries(options.dependencyGraph)) {
      const srcNorm = normalizeCanonicalPath(src);
      const targetList = Array.isArray(targets) ? targets : [targets];
      for (const t of targetList) {
        dependencyEdges.push({
          from: srcNorm,
          to: normalizeCanonicalPath(t),
          kind: "explicit_graph"
        });
      }
    }
  }

  // 2. Perform graph clustering via Union-Find
  const uf = new UnionFind(filePaths);
  for (const edge of dependencyEdges) {
    if (filePaths.includes(edge.from) && filePaths.includes(edge.to)) {
      uf.union(edge.from, edge.to);
    }
  }

  const clusters = uf.getClusters();

  // 3. For each cluster, determine priority tier and build partition hunks
  const partitions = [];
  let clusterIndex = 0;

  for (const clusterFiles of clusters) {
    clusterIndex += 1;
    const clusterId = `cluster-${String(clusterIndex).padStart(3, "0")}`;

    // Priority tier is the highest priority (lowest number) among files in the cluster
    let highestPriority = RISK_TIERS.TIER_3_DOCS;
    for (const f of clusterFiles) {
      const tier = classifyFileRisk(f);
      if (tier < highestPriority) {
        highestPriority = tier;
      }
    }

    // Collect all diff hunks for cluster
    const clusterFileDiffs = [];
    let clusterBytes = 0;
    for (const f of clusterFiles) {
      const diff = fileDiffMap.get(f) || "";
      clusterFileDiffs.push({ file: f, diff });
      clusterBytes += Buffer.byteLength(diff, "utf8");
    }

    // If cluster fits within maxChunkBytes, emit as a single cohesive partition
    if (clusterBytes <= maxChunkBytes || clusterFiles.length === 1) {
      const combinedDiff = clusterFileDiffs.map(d => d.diff).filter(Boolean).join("\n\n");
      const clusterEdges = dependencyEdges.filter(
        e => clusterFiles.includes(e.from) && clusterFiles.includes(e.to)
      );

      partitions.push({
        clusterId,
        priorityTier: highestPriority,
        targetFiles: clusterFiles,
        diffHunks: combinedDiff,
        dependencyEdges: clusterEdges,
        subChunkIndex: 1,
        clusterTotalSubChunks: 1
      });
    } else {
      // Cluster exceeds maxChunkBytes: partition into cohesive sub-chunks
      let currentSubFiles = [];
      let currentSubDiffs = [];
      let currentSubBytes = 0;
      const subChunks = [];

      for (const { file, diff } of clusterFileDiffs) {
        const fileBytes = Buffer.byteLength(diff, "utf8");
        if (currentSubBytes + fileBytes > maxChunkBytes && currentSubFiles.length > 0) {
          subChunks.push({
            files: currentSubFiles,
            diff: currentSubDiffs.join("\n\n")
          });
          currentSubFiles = [file];
          currentSubDiffs = [diff];
          currentSubBytes = fileBytes;
        } else {
          currentSubFiles.push(file);
          currentSubDiffs.push(diff);
          currentSubBytes += fileBytes;
        }
      }
      if (currentSubFiles.length > 0) {
        subChunks.push({
          files: currentSubFiles,
          diff: currentSubDiffs.join("\n\n")
        });
      }

      const totalSub = subChunks.length;
      for (let sIdx = 0; sIdx < totalSub; sIdx++) {
        const sub = subChunks[sIdx];
        const subEdges = dependencyEdges.filter(
          e => sub.files.includes(e.from) && sub.files.includes(e.to)
        );
        partitions.push({
          clusterId,
          priorityTier: highestPriority,
          targetFiles: sub.files,
          diffHunks: sub.diff,
          dependencyEdges: subEdges,
          subChunkIndex: sIdx + 1,
          clusterTotalSubChunks: totalSub
        });
      }
    }
  }

  // Sort partitions by priorityTier (Tier 1 Critical first, then Tier 2, then Tier 3)
  partitions.sort((a, b) => a.priorityTier - b.priorityTier);

  // 4. Construct final SwarmPartition objects with deterministic digests and IDs
  const totalPartitions = partitions.length;
  return partitions.map((p, idx) => {
    const partitionIndex = idx + 1;
    const partitionId = `partition-${runId}-${String(partitionIndex).padStart(3, "0")}`;
    const contentDigest = computeDigest(p.diffHunks);
    const byteLength = Buffer.byteLength(p.diffHunks, "utf8");

    return {
      partitionId,
      runId,
      partitionIndex,
      totalPartitions,
      clusterId: p.clusterId,
      priorityTier: p.priorityTier,
      targetFiles: p.targetFiles,
      diffHunks: p.diffHunks,
      dependencyEdges: p.dependencyEdges,
      subChunkIndex: p.subChunkIndex,
      clusterTotalSubChunks: p.clusterTotalSubChunks,
      contentDigest,
      byteLength
    };
  });
}

/**
 * Creates an immutable cryptographic intermediate receipt for a processed partition.
 * Implements SHA-256 hash chaining to guarantee sequence integrity and tamper evidence.
 *
 * @param {object} params
 * @param {object} params.partition - The SwarmPartition being inspected
 * @param {object} params.workerResult - Review findings, coverage and metadata returned by worker
 * @param {string} params.previousReceiptHash - SHA-256 hash of the preceding receipt
 * @param {string} params.workerId - Identifier of the assigned worker
 * @param {number} params.sequenceNumber - 1-based order index in the hash chain
 * @param {string} [params.status=CHUNK_STATUS.INSPECTED] - Inspection status
 * @param {string} [params.timestamp] - ISO timestamp
 * @returns {object} Immutable Intermediate Receipt
 */
export function createIntermediateReceipt({
  partition,
  workerResult,
  previousReceiptHash,
  workerId,
  sequenceNumber,
  status = CHUNK_STATUS.INSPECTED,
  timestamp = new Date().toISOString(),
  hmacKey = null,
  privateKey = null
}) {
  if (!partition || typeof partition !== "object") {
    throw new TypeError("Partition is required to create intermediate receipt.");
  }
  if (!previousReceiptHash || typeof previousReceiptHash !== "string") {
    throw new TypeError("previousReceiptHash must be a non-empty sha256 string.");
  }
  if (!workerId || typeof workerId !== "string") {
    throw new TypeError("workerId is required to create intermediate receipt.");
  }

  const receiptId = `rcpt-${partition.runId || "run"}-${String(sequenceNumber).padStart(4, "0")}`;
  const targetFiles = Array.isArray(partition.targetFiles) ? [...partition.targetFiles].sort() : [];
  const contentDigest = partition.contentDigest || computeDigest(partition.diffHunks || "");

  // Deterministically canonicalize and digest workerResult
  const sanitizedResult = {
    status,
    findings: Array.isArray(workerResult?.findings) ? workerResult.findings : [],
    coverage: {
      coveredFiles: Array.isArray(workerResult?.coverage?.coveredFiles)
        ? [...workerResult.coverage.coveredFiles].sort()
        : (status === CHUNK_STATUS.INSPECTED ? targetFiles : []),
      omittedFiles: Array.isArray(workerResult?.coverage?.omittedFiles)
        ? workerResult.coverage.omittedFiles
        : []
    },
    providerIdentity: workerResult?.providerIdentity || { workerId },
    error: workerResult?.error ? String(workerResult.error) : null
  };
  const resultDigest = computeDigest(sanitizedResult);

  // Compute canonical receipt hash for cryptographic chain
  const chainPayload = {
    contentDigest,
    partitionId: partition.partitionId,
    previousReceiptHash,
    receiptId,
    resultDigest,
    sequenceNumber,
    status,
    targetFiles,
    timestamp,
    workerId
  };
  const receiptHash = computeDigest(chainPayload);

  // Cryptographic signature (HMAC-SHA256 or Ed25519)
  let signature = null;
  let signatureAlgorithm = null;
  if (hmacKey) {
    signatureAlgorithm = "hmac-sha256";
    signature = crypto.createHmac("sha256", hmacKey).update(receiptHash).digest("hex");
  } else if (privateKey) {
    signatureAlgorithm = "ed25519";
    signature = crypto.sign(null, Buffer.from(receiptHash), privateKey).toString("hex");
  }

  return Object.freeze({
    receiptId,
    sequenceNumber,
    partitionId: partition.partitionId,
    clusterId: partition.clusterId,
    workerId,
    status,
    targetFiles,
    contentDigest,
    resultDigest,
    previousReceiptHash,
    receiptHash,
    signature,
    signatureAlgorithm,
    timestamp,
    findings: sanitizedResult.findings,
    coverage: sanitizedResult.coverage,
    providerIdentity: sanitizedResult.providerIdentity,
    error: sanitizedResult.error
  });
}

/**
 * Validates the cryptographic integrity and anti-tamper guarantee of a receipt chain.
 *
 * @param {Array<object>} receipts - Array of intermediate receipts
 * @param {object} [options={}] - Verification options (optional hmacKey or publicKey)
 * @returns {{ valid: boolean, chainLength: number, rootHash: string }}
 * @throws {ReceiptChainTamperedError} If any receipt is corrupted, reordered or hash invalid
 */
export function verifyReceiptChain(receipts, options = {}) {
  if (!Array.isArray(receipts)) {
    throw new ReceiptChainTamperedError("Receipt chain must be an array.");
  }

  if (receipts.length === 0) {
    return { valid: true, chainLength: 0, rootHash: GENESIS_RECEIPT_HASH };
  }

  let expectedPreviousHash = GENESIS_RECEIPT_HASH;

  for (let i = 0; i < receipts.length; i++) {
    const rcpt = receipts[i];
    const expectedSeq = i + 1;

    if (!rcpt || typeof rcpt !== "object") {
      throw new ReceiptChainTamperedError(`Corrupted receipt at index ${i}: not an object.`);
    }

    if (rcpt.sequenceNumber !== expectedSeq) {
      throw new ReceiptChainTamperedError(
        `Sequence discontinuity at index ${i}: expected seq ${expectedSeq}, got ${rcpt.sequenceNumber}.`,
        { index: i, expectedSeq, actualSeq: rcpt.sequenceNumber }
      );
    }

    if (rcpt.previousReceiptHash !== expectedPreviousHash) {
      throw new ReceiptChainTamperedError(
        `Broken hash chain at receipt ${rcpt.receiptId}: previousReceiptHash mismatch.`,
        {
          receiptId: rcpt.receiptId,
          expectedPreviousHash,
          actualPreviousHash: rcpt.previousReceiptHash
        }
      );
    }

    // Recompute and verify payload hash
    const chainPayload = {
      contentDigest: rcpt.contentDigest,
      partitionId: rcpt.partitionId,
      previousReceiptHash: rcpt.previousReceiptHash,
      receiptId: rcpt.receiptId,
      resultDigest: rcpt.resultDigest,
      sequenceNumber: rcpt.sequenceNumber,
      status: rcpt.status,
      targetFiles: rcpt.targetFiles,
      timestamp: rcpt.timestamp,
      workerId: rcpt.workerId
    };
    const expectedReceiptHash = computeDigest(chainPayload);

    if (rcpt.receiptHash !== expectedReceiptHash) {
      throw new ReceiptChainTamperedError(
        `Tampered receipt detected at ${rcpt.receiptId}: hash signature mismatch.`,
        {
          receiptId: rcpt.receiptId,
          expectedHash: expectedReceiptHash,
          actualHash: rcpt.receiptHash
        }
      );
    }

    // Verify optional cryptographic signature (HMAC-SHA256 or Ed25519)
    if (options.hmacKey) {
      if (!rcpt.signature) {
        throw new ReceiptChainTamperedError(
          `Missing HMAC signature at receipt ${rcpt.receiptId}: HMAC verification required.`,
          { receiptId: rcpt.receiptId }
        );
      }
      const expectedSig = crypto.createHmac("sha256", options.hmacKey).update(expectedReceiptHash).digest("hex");
      if (rcpt.signature !== expectedSig) {
        throw new ReceiptChainTamperedError(
          `Tampered receipt signature at ${rcpt.receiptId}: HMAC signature verification failed.`,
          { receiptId: rcpt.receiptId, expectedSig, actualSig: rcpt.signature }
        );
      }
    } else if (options.publicKey) {
      if (!rcpt.signature) {
        throw new ReceiptChainTamperedError(
          `Missing Ed25519 signature at receipt ${rcpt.receiptId}: public key verification required.`,
          { receiptId: rcpt.receiptId }
        );
      }
      const verified = crypto.verify(null, Buffer.from(expectedReceiptHash), options.publicKey, Buffer.from(rcpt.signature, "hex"));
      if (!verified) {
        throw new ReceiptChainTamperedError(
          `Tampered receipt signature at ${rcpt.receiptId}: Ed25519 public key verification failed.`,
          { receiptId: rcpt.receiptId }
        );
      }
    }

    expectedPreviousHash = rcpt.receiptHash;
  }

  return {
    valid: true,
    chainLength: receipts.length,
    rootHash: expectedPreviousHash
  };
}

/**
 * Verifies that all files in the ChangeSet are covered by inspected receipts
 * or valid omissions.
 *
 * @param {object} changeSet
 * @param {Array<object>} receipts
 * @returns {{ complete: boolean, coveredFiles: string[], omittedFiles: object[], uninspectedFiles: string[], missingFiles: string[] }}
 */
export function verifyCoverageCompleteness(changeSet, receipts = []) {
  const allFiles = (changeSet?.files || [])
    .map(f => normalizeCanonicalPath(typeof f === "string" ? f : f.path))
    .filter(Boolean);

  const coveredFiles = new Set();
  const omittedFiles = [];
  const uninspectedFiles = new Set();

  for (const rcpt of receipts) {
    if (rcpt.status === CHUNK_STATUS.UNINSPECTED_CHUNK) {
      for (const f of rcpt.targetFiles || []) {
        const norm = normalizeCanonicalPath(f);
        if (norm) uninspectedFiles.add(norm);
      }
    } else {
      for (const f of rcpt.coverage?.coveredFiles || []) {
        const norm = normalizeCanonicalPath(f);
        if (norm) coveredFiles.add(norm);
      }
      for (const o of rcpt.coverage?.omittedFiles || []) {
        omittedFiles.push(o);
      }
    }
  }

  const missingFiles = allFiles.filter(f => !coveredFiles.has(f) && !uninspectedFiles.has(f));
  const complete = uninspectedFiles.size === 0 && missingFiles.length === 0;

  return {
    complete,
    coveredFiles: Array.from(coveredFiles).sort(),
    omittedFiles,
    uninspectedFiles: Array.from(uninspectedFiles).sort(),
    missingFiles: missingFiles.sort()
  };
}

/**
 * Worker-level Circuit Breaker with Fail-Closed semantics,
 * consecutive failure tracking, configurable timeout, and reset cooling period.
 */
export class CircuitBreaker {
  constructor(options = {}) {
    this.workerId = options.workerId || "default-worker";
    this.failureThreshold = options.failureThreshold || 3;
    this.resetTimeoutMs = options.resetTimeoutMs || 5000;
    this.state = CIRCUIT_BREAKER_STATES.CLOSED;
    this.failureCount = 0;
    this.lastFailureTime = 0;
    this.successCount = 0;
  }

  getState() {
    if (this.state === CIRCUIT_BREAKER_STATES.OPEN) {
      const now = Date.now();
      if (now - this.lastFailureTime >= this.resetTimeoutMs) {
        this.state = CIRCUIT_BREAKER_STATES.HALF_OPEN;
      }
    }
    return this.state;
  }

  recordSuccess() {
    this.failureCount = 0;
    this.state = CIRCUIT_BREAKER_STATES.CLOSED;
    this.successCount += 1;
  }

  recordFailure() {
    this.failureCount += 1;
    this.lastFailureTime = Date.now();
    if (this.failureCount >= this.failureThreshold || this.state === CIRCUIT_BREAKER_STATES.HALF_OPEN) {
      this.state = CIRCUIT_BREAKER_STATES.OPEN;
    }
  }

  reset() {
    this.state = CIRCUIT_BREAKER_STATES.CLOSED;
    this.failureCount = 0;
    this.lastFailureTime = 0;
  }

  /**
   * Executes a worker task under circuit breaker protection and timeout envelope.
   *
   * @param {Function} taskFn - () => Promise<any>
   * @param {object} [execOptions={}]
   * @param {number} [execOptions.timeoutMs=5000]
   * @param {number} [execOptions.maxRetries=0]
   * @returns {Promise<any>}
   */
  async execute(taskFn, execOptions = {}) {
    const currentState = this.getState();

    if (currentState === CIRCUIT_BREAKER_STATES.OPEN) {
      throw new CircuitBreakerOpenError(
        `Circuit breaker is OPEN for worker '${this.workerId}'. Fast-failing task.`,
        this.workerId
      );
    }

    const timeoutMs = execOptions.timeoutMs || 5000;
    const maxRetries = execOptions.maxRetries || 0;

    let attempt = 0;
    let lastError = null;

    while (attempt <= maxRetries) {
      try {
        let timer = null;
        const timeoutPromise = new Promise((_, reject) => {
          timer = setTimeout(() => {
            reject(new SwarmTimeoutError(`Worker '${this.workerId}' timed out after ${timeoutMs}ms`, timeoutMs));
          }, timeoutMs);
        });

        const result = await Promise.race([taskFn(), timeoutPromise]).finally(() => {
          if (timer) clearTimeout(timer);
        });

        // Worker succeeded
        this.recordSuccess();
        return result;
      } catch (err) {
        lastError = err;
        attempt += 1;
        if (attempt <= maxRetries) {
          // Retry
          continue;
        }
      }
    }

    // All attempts exhausted
    this.recordFailure();
    throw lastError;
  }
}

/**
 * Distributed Swarm Orchestrator (Pillar 2 Core Class)
 *
 * Coordinates multi-worker swarm review with:
 * - Dependency-aware partitioning (prevents breaking inter-dependent symbols)
 * - Parallel worker dispatch with concurrency limits
 * - Cryptographic intermediate receipts & tamper-evident hash chaining
 * - Fail-closed circuit breaker protection and timeout fallback
 */
export class DistributedSwarmOrchestrator {
  /**
   * @param {object} [options={}]
   * @param {Array<object|Function>} [options.workers=[]] - Available worker adapters or worker functions
   * @param {number} [options.maxConcurrency=4] - Maximum concurrent worker tasks
   * @param {number} [options.timeoutMs=5000] - Per-partition worker timeout
   * @param {number} [options.maxRetries=1] - Retry attempts before fail-closed fallback
   * @param {object} [options.circuitBreaker] - Circuit breaker options { failureThreshold, resetTimeoutMs }
   * @param {boolean} [options.strictFailClosed=true] - Always fail closed on uninspected chunks
   */
  constructor(options = {}) {
    this.maxConcurrency = options.maxConcurrency || 4;
    this.timeoutMs = options.timeoutMs || 5000;
    this.maxRetries = options.maxRetries ?? 1;
    this.strictFailClosed = options.strictFailClosed !== false;

    this.circuitBreakerOptions = {
      failureThreshold: options.circuitBreaker?.failureThreshold || 3,
      resetTimeoutMs: options.circuitBreaker?.resetTimeoutMs || 5000
    };

    this.workers = new Map();
    this.circuitBreakers = new Map();

    if (Array.isArray(options.workers)) {
      options.workers.forEach((w, idx) => {
        const id = w.id || w.name || w.providerName || `worker-${idx + 1}`;
        this.registerWorker(id, w);
      });
    } else if (options.workers && typeof options.workers === "object") {
      for (const [id, w] of Object.entries(options.workers)) {
        this.registerWorker(id, w);
      }
    }
  }

  registerWorker(workerId, worker) {
    if (!workerId || typeof workerId !== "string") {
      throw new TypeError("workerId must be a non-empty string.");
    }
    this.workers.set(workerId, worker);
    if (!this.circuitBreakers.has(workerId)) {
      this.circuitBreakers.set(
        workerId,
        new CircuitBreaker({
          workerId,
          ...this.circuitBreakerOptions
        })
      );
    }
  }

  unregisterWorker(workerId) {
    this.workers.delete(workerId);
    this.circuitBreakers.delete(workerId);
  }

  getCircuitBreakerStatus(workerId) {
    const cb = this.circuitBreakers.get(workerId);
    if (!cb) return null;
    return {
      workerId,
      state: cb.getState(),
      failureCount: cb.failureCount,
      successCount: cb.successCount
    };
  }

  resetCircuitBreaker(workerId) {
    const cb = this.circuitBreakers.get(workerId);
    if (cb) {
      cb.reset();
    }
  }

  /**
   * Partitions the ChangeSet using AST cross-file dependency awareness.
   */
  partition(changeSet, options = {}) {
    return partitionChangeSetWithDependencies(changeSet, options);
  }

  /**
   * Executes a partition on a worker under circuit breaker protection.
   *
   * @private
   */
  async _invokeWorker(workerId, worker, partition, options = {}) {
    const cb = this.circuitBreakers.get(workerId);
    const timeoutMs = options.timeoutMs || this.timeoutMs;
    const maxRetries = options.maxRetries ?? this.maxRetries;

    return cb.execute(async () => {
      if (typeof worker === "function") {
        return await worker(partition, options);
      }
      if (worker && typeof worker.executeReview === "function") {
        return await worker.executeReview(partition, options);
      }
      if (worker && typeof worker.review === "function") {
        return await worker.review(partition, options);
      }
      throw new TypeError(`Worker '${workerId}' does not implement executeReview() or function interface.`);
    }, { timeoutMs, maxRetries });
  }

  /**
   * Dispatches the ChangeSet across distributed workers with dependency-aware
   * partitioning, cryptographic receipt verification, and fail-closed circuit breakers.
   *
   * @param {object} changeSet - ChangeSet object with files and diffHunks
   * @param {object} [options={}] - Execution options
   * @returns {Promise<object>} Synthesized Swarm Consensus Result
   */
  async dispatch(changeSet, options = {}) {
    const runId = options.runId || crypto.randomUUID();
    const partitions = this.partition(changeSet, { runId, ...options });

    if (partitions.length === 0) {
      return {
        ok: true,
        verdict: SWARM_VERDICTS.APPROVE,
        findings: [],
        coverage: { coveredFiles: [], omittedFiles: [], uninspectedFiles: [] },
        receiptChain: [],
        rootReceiptHash: GENESIS_RECEIPT_HASH,
        stats: {
          totalPartitions: 0,
          inspectedPartitions: 0,
          uninspectedPartitions: 0
        }
      };
    }

    const availableWorkerIds = Array.from(this.workers.keys());
    if (availableWorkerIds.length === 0) {
      throw new Error("No workers registered in DistributedSwarmOrchestrator.");
    }

    // Worker round-robin assignment mapping
    const partitionTaskPlan = partitions.map((p, idx) => {
      const assignedWorkerId = availableWorkerIds[idx % availableWorkerIds.length];
      return {
        partition: p,
        workerId: assignedWorkerId,
        worker: this.workers.get(assignedWorkerId)
      };
    });

    // Concurrency controlled execution queue
    const executionResults = new Array(partitions.length);
    const maxConcurrency = options.maxConcurrency || this.maxConcurrency;
    let nextIdx = 0;

    const workerLoop = async () => {
      while (nextIdx < partitionTaskPlan.length) {
        const curIdx = nextIdx++;
        const item = partitionTaskPlan[curIdx];
        try {
          const rawResult = await this._invokeWorker(item.workerId, item.worker, item.partition, options);
          executionResults[curIdx] = {
            success: true,
            status: CHUNK_STATUS.INSPECTED,
            workerId: item.workerId,
            result: rawResult,
            partition: item.partition
          };
        } catch (err) {
          // Fail-closed fallback: mark partition as UNINSPECTED_CHUNK
          executionResults[curIdx] = {
            success: false,
            status: CHUNK_STATUS.UNINSPECTED_CHUNK,
            workerId: item.workerId,
            error: err.message || String(err),
            partition: item.partition
          };
        }
      }
    };

    const runners = [];
    for (let c = 0; c < Math.min(maxConcurrency, partitionTaskPlan.length); c++) {
      runners.push(workerLoop());
    }
    await Promise.all(runners);

    // Build the cryptographic intermediate receipt chain in sequence
    const receipts = [];
    let prevHash = GENESIS_RECEIPT_HASH;

    for (let i = 0; i < executionResults.length; i++) {
      const exec = executionResults[i];
      const seqNum = i + 1;

      const receipt = createIntermediateReceipt({
        partition: exec.partition,
        workerResult: exec.success ? exec.result : { error: exec.error },
        previousReceiptHash: prevHash,
        workerId: exec.workerId,
        sequenceNumber: seqNum,
        status: exec.status,
        hmacKey: options.hmacKey || null,
        privateKey: options.privateKey || null
      });

      receipts.push(receipt);
      prevHash = receipt.receiptHash;
    }

    // Step 4: Verify the cryptographic receipt chain
    const chainVerification = verifyReceiptChain(receipts, {
      hmacKey: options.hmacKey,
      publicKey: options.publicKey
    });

    // Step 5: Verify coverage completeness
    const coverageEval = verifyCoverageCompleteness(changeSet, receipts);

    // Step 6: Central Consensus Synthesis & Fail-Closed Gate Evaluation
    const allFindings = [];
    let uninspectedChunkCount = 0;

    for (const rcpt of receipts) {
      if (rcpt.status === CHUNK_STATUS.UNINSPECTED_CHUNK) {
        uninspectedChunkCount += 1;
        allFindings.push({
          title: `Uninspected ChangeSet Partition: ${rcpt.partitionId}`,
          severity: "critical",
          file: rcpt.targetFiles[0] || "unknown",
          recommendation: `Worker failure on partition '${rcpt.partitionId}'. Requires fail-closed manual or automated rescan.`,
          type: "UNINSPECTED_CHUNK",
          ruleId: "FAIL_CLOSED_ORCHESTRATION",
          details: {
            workerId: rcpt.workerId,
            error: rcpt.error,
            targetFiles: rcpt.targetFiles
          }
        });
      } else {
        if (Array.isArray(rcpt.findings)) {
          allFindings.push(...rcpt.findings);
        }
      }
    }

    // Verdict determination with strict fail-closed invariants
    let verdict = SWARM_VERDICTS.APPROVE;
    let ok = true;

    if (uninspectedChunkCount > 0 || !coverageEval.complete) {
      // Fail-closed gate: Any uninspected chunk strictly prohibits approval
      verdict = SWARM_VERDICTS.ERROR;
      ok = false;
    } else {
      const hasCritical = allFindings.some(f => f.severity === "critical");
      const hasHigh = allFindings.some(f => f.severity === "high");
      const hasMedium = allFindings.some(f => f.severity === "medium");

      if (hasCritical || hasHigh) {
        verdict = SWARM_VERDICTS.ERROR;
        ok = false;
      } else if (hasMedium) {
        verdict = SWARM_VERDICTS.WARNING;
        ok = true;
      }
    }

    // Step 7: Taxonomy Quorum Calibration with Domain Weights & Physical Proof Override
    let quorumDecision = null;
    if (options.calibrateQuorum !== false && (options.taxonomyCalibrator || options.calibrateQuorum || options.physicalProof)) {
      const calibrator = options.taxonomyCalibrator || new TaxonomyQuorumCalibrator();
      const reports = receipts.map(rcpt => ({
        id: rcpt.workerId,
        provider: rcpt.workerId,
        family: rcpt.providerIdentity?.family || (rcpt.workerId.includes("claude") ? "anthropic" : (rcpt.workerId.includes("agy") ? "google" : (rcpt.workerId.includes("codex") ? "openai" : undefined))),
        status: rcpt.status === CHUNK_STATUS.INSPECTED ? "SUCCESS" : "ERROR",
        healthy: rcpt.status === CHUNK_STATUS.INSPECTED,
        findings: rcpt.findings || [],
        receiptHash: rcpt.receiptHash
      }));

      quorumDecision = calibrator.calibrateQuorum({
        reports,
        files: changeSet.files || [],
        physicalProof: options.physicalProof || null,
        riskTier: options.riskTier
      });

      if (!quorumDecision.quorumReached || quorumDecision.verdict === "error") {
        verdict = SWARM_VERDICTS.ERROR;
        ok = false;
      } else if (quorumDecision.verdict === "needs-attention" && verdict !== SWARM_VERDICTS.ERROR) {
        verdict = SWARM_VERDICTS.NEEDS_ATTENTION;
        ok = false;
      }
    }

    // Snapshot circuit breaker states
    const cbStates = {};
    for (const [id, cb] of this.circuitBreakers.entries()) {
      cbStates[id] = cb.getState();
    }

    return {
      ok,
      verdict,
      runId,
      findings: allFindings,
      coverage: {
        complete: coverageEval.complete,
        coveredFiles: coverageEval.coveredFiles,
        omittedFiles: coverageEval.omittedFiles,
        uninspectedFiles: coverageEval.uninspectedFiles,
        missingFiles: coverageEval.missingFiles
      },
      receiptChain: receipts,
      rootReceiptHash: chainVerification.rootHash,
      quorumDecision: quorumDecision || null,
      consensusProof: quorumDecision?.consensusProof || null,
      stats: {
        totalPartitions: partitions.length,
        inspectedPartitions: partitions.length - uninspectedChunkCount,
        uninspectedPartitions: uninspectedChunkCount,
        chainLength: chainVerification.chainLength
      },
      circuitBreakerStates: cbStates
    };
  }
}
