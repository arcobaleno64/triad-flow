# LOOP2-SYSTEMIC-REMEDIATION-006 Specification
## AGY Transport & Staged Timeout Reliability Architecture

**Status:** APPROVED FOR IMPLEMENTATION  
**Classification:** LOOP 2 (Systemic Remediation)  
**Issue Reference:** GitHub Issue #37  
**Authority Mode:** SHADOW_DOGFOOD (Advisory Only, Runtime Authority: NONE)  
**Origin Audit:** TF-AUDIT-PROMOTION-0001 (PR #36, merged at `757e340`)  
**Frozen Baseline:** Phase 4.4 Fresh Cohort `CYCLE-0025..0039` (15/15 cycles, 0 FA, 0 FH, 3 timeout cycles = 20.0% failure)  
**Primary Learning Owner:** Transport Layer (`CliReviewAdapter`), Staged Scheduler (`executeStagedReview`), Dogfood Telemetry  

---

## 1. Governance Context & Problem Statement

In `TF-AUDIT-PROMOTION-0001`, Triad-Flow completed the Phase 4.4 live empirical shadow dogfood cohort (15 fresh cycles post-REMEDIATION-005, 0 False Advances, 0 False Holds). However, the cohort **failed** the reliability gate:
- **Observed Timeout-Cycle Rate:** 3 / 15 = 20.0%
- **Target Threshold:** < 5.0%
- **Governance Result:** Gate Out FAIL, `PROMOTION_REVIEW_ELIGIBLE = FALSE`, `SHADOW_TO_ADVISORY = STRICT_HOLD`, `RUNTIME_AUTHORITY = NONE`.

In accordance with strict audit immutability, historical receipts in `docs/benchmarks/dogfood-receipts.jsonl` remain permanently frozen and cannot be amended or reclassified. `REMEDIATION-006` is established under GitHub Issue #37 to eliminate the root causes of provider and staged chunk timeouts.

---

## 2. Root Cause Analysis (Workstream 006-A)

Analysis of full execution records from the 15 fresh Phase 4.4 cycles isolates two distinct failure modes:

### 2.1 Single Provider Wall-Clock Timeout (`CYCLE-0028`)
- **Target:** `netty/netty#17475` (Commit `f3d7ce5c5c`)
- **Observed Metrics:** `stagedFallbackUsed: false`, `timeoutCount: 1`, duration: 315,992 ms
- **Root Cause:** Single provider (`agy`) call on a small diff (2 files, 3 additions, 2 deletions) exceeded the 300,000 ms CLI transport budget. This was a pure provider wall-clock latency exhaustion, **not** a staged chunk timeout.
- **Classification:** Top-level provider latency timeout.

### 2.2 Staged Chunk Cascading Timeout (`CYCLE-0033` & `CYCLE-0037`)
- **`CYCLE-0033`:** `rust-lang/rust#163058` (71 files, 532 additions, 34 deletions)
  - `stagedFallbackUsed: true`, 28 chunks, 27 chunk timeouts, duration: 298,908 ms
- **`CYCLE-0037`:** `nodejs/node#65370` (6 files, 579 additions, 0 deletions)
  - `stagedFallbackUsed: true`, 8 chunks, 5 chunk timeouts, duration: 296,358 ms
- **Root Cause Chain:**
  1. **Premature Chunking on Windows:** Canonical `agy` had `supportsStdin: false`. When prompt bytes exceeded `SAFE_ARGV_THRESHOLD_BYTES` (8 KB) or Windows argv limit (30,000 chars), `CliReviewAdapter` failed with `PAYLOAD_TOO_LARGE`, forcing medium and large diffs into staged chunking.
  2. **Equal-Split Budget Starvation:** `src/adapters/staged-review.mjs` divided the 300,000 ms global budget equally across chunks: `nominalChunkBudgetMs = min(60000, floor(totalBudgetMs / chunks.length))`. For 28 chunks, this allocated only **10,714 ms** per chunk.
  3. **Sequential Execution Bottleneck:** Chunks were processed strictly sequentially (1 at a time). Because `agy` cold execution latency on Windows typically requires 15–25 seconds, every single chunk timed out sequentially, exhausting the 300s budget.

---

## 3. Architecture Specification

### 3.1 Workstream 006-B: Transport-First Payload Mitigation (`agy` Stream-JSON)
Physical testing on Windows verified that the installed `agy.cmd` binary natively supports stdin streaming when invoked with:
```text
agy --mode=plan --disable-slash-commands --input-format=stream-json --output-format=stream-json
```
- **Input Protocol:** Writes newline-delimited JSON (NDJSON) to `stdin`:
  ```json
  {"event": "user", "message": {"content": "<full prompt text>"}}\n
  ```
- **Output Protocol:** Emits NDJSON events ending in a final result event:
  ```json
  {"event": "result", "result": {"status": "SUCCESS", "response": "<model text output>"}}
  ```
- **Transport Adaptation:**
  - `CliReviewAdapter` supports opt-in `streamJson: true`.
  - When `streamJson: true` is enabled on `agy`, `supportsStdin` is promoted to `true`, `--print` is omitted, and prompt streaming bypasses the Windows 32 KB command-line limit entirely.
  - Payloads exceeding 8 KB or 30 KB flow directly over `stdin` without triggering `PAYLOAD_TOO_LARGE` or requiring staged chunking.

### 3.2 Workstream 006-C: Modern Staged Scheduler & Bounded Worker Pool
For diffs that truly require chunking (e.g., repository-wide multi-file changes):
1. **Pre-flight Feasibility Check:**
   - Evaluates `minViableChunkBudgetMs` (10,000 ms) and `maxConcurrency`.
   - If `ceil(chunks.length / maxConcurrency) * minViableChunkBudgetMs > totalBudgetMs`, records a feasibility warning without silently altering budget or fabricating coverage.
2. **Bounded Worker Pool (`maxConcurrency = 2` default):**
   - Configurable bounded worker pool (`maxConcurrency: 2` default in dogfood review, configurable via `options.concurrency` or `options.maxConcurrency`).
   - Executes chunks with controlled parallelism while avoiding rate-limiting or machine resource exhaustion.
3. **Dynamic Wave Budgeting:**
   - Instead of static `totalBudgetMs / chunks.length`, budget per wave is allocated based on remaining global deadline and remaining waves:
     `wavesRemaining = ceil((totalChunks - completedChunks) / maxConcurrency)`
     `nominalChunkBudget = min(60000, max(minChunkBudget, floor(remainingGlobalMs / wavesRemaining)))`
4. **Deterministic Reduction by `chunkIndex`:**
   - Worker results are gathered in an array indexed by `chunkIndex`.
   - Accumulation of findings, coverage set updates, cross-chunk contradiction checks, and checkpoint persistence are strictly executed in sequential `chunkIndex` order (0 to N-1).
5. **Fail-Closed & Leak Prevention:**
   - Global deadline and `options.signal` cancellation abort all active chunk controllers immediately, preventing orphaned child processes.
   - Unreached chunks fail closed with `COVERAGE_OMISSION_CODES.TIMEOUT`.

### 3.3 Workstream 006-A: Structured Telemetry Schema
Telemetry metrics are enriched to decouple cycle-level status from raw chunk event counts:
- `telemetryMetrics.providerTimeoutCount`: Top-level provider timeouts.
- `telemetryMetrics.chunkTimeoutCount`: Staged chunk timeout count.
- `telemetryMetrics.timeoutCycle`: Boolean flag (`timeoutCount > 0`).
- `telemetryMetrics.phaseMetrics`: Structured breakdown containing `platform`, `transport`, `budgetAllocatedMs`, `globalDeadlineRemainingMs`, `stagedFallbackUsed`, `chunkCount`, `maxConcurrency`, and `feasibility`.

---

## 4. Test & Verification Plan (Workstream 006-D)

Comprehensive deterministic tests in `tests/loop2-systemic-remediation-006.test.mjs`:
1. `agy` stream-json transport via stdin with mock/synthetic subprocesses.
2. Large payload (>30 KB) delivery without `PAYLOAD_TOO_LARGE` failure when stream-json is active.
3. Bounded worker pool with `maxConcurrency = 2` completing out of order and verifying deterministic result assembly in `chunkIndex` order.
4. Dynamic chunk budget allocation and pre-flight feasibility reporting.
5. Strict cross-chunk contradiction detection under concurrent execution.
6. AbortSignal and global deadline cancellation cleanly terminating worker tasks without orphan processes.
7. Zero regressions against existing test suite (all 650 baseline tests pass).
