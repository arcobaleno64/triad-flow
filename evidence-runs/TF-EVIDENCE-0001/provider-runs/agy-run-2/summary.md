# Triad-Flow Benchmark Audit Summary

## Cryptographic Provenance & Manifest
- **Run ID**: `run-bench-1790729507453-9e6aae7c`
- **Git Commit**: `a4d0b92f06859e75223225fce72b0c3d0b25d23d`
- **Corpus Version**: `TF-RBC-v0`
- **Corpus Digest**: `sha256:cf9c4596cca5910bf1c493590e16a4333782defea779a39488fa95f6b16fb82b`
- **Receipt Digest**: `sha256:f4cf02ddadad6a29e94f948a5638e0f126152b5d40a123fbcce2fdc6cf4bd7e1`
- **Results Digest**: `sha256:ec3251a754c124ade96cbf27c3ca3048809496eb7ce8804ecf728cffe6032d5d`

## Execution Environment
- **Framework**: Triad-Flow Real Benchmark Corpus v0 (TF-RBC-v0)
- **Evaluation Mode**: `single`
- **Execution Mode**: `live`
- **Workspace Mode**: `physical`
- **Environment**: `win32 (x64)` | Node `v24.14.1`
- **Started At**: 2026-09-30T00:51:47.453Z
- **Finished At**: 2026-09-30T00:51:47.453Z

## Benchmark Quality & Performance Metrics
| Metric | Value |
|---|---|
| Total Cases | 1 |
| Vulnerable Cases | 1 |
| Clean Controls | 0 |
| Recall Rate | 100.0% |
| Precision | 100.0% |
| False Block Rate | N/A |
| Latency P50 | 51568 ms |
| Latency P95 | 51568 ms |
| Authoritative Token Usage | null (unreported / unavailable) |

## Cryptographic Artifact Bundle
The following artifacts are recorded in `artifact-manifest.json`:

- `benchmark-results.json`: `sha256:ec3251a754c124ade96cbf27c3ca3048809496eb7ce8804ecf728cffe6032d5d`
- `audit-receipt.json`: `sha256:dad3a4eb086ed6905cc5d363a3a8ede420c55fa35bd7bf2988ec60318095023d` (canonical: `sha256:f4cf02ddadad6a29e94f948a5638e0f126152b5d40a123fbcce2fdc6cf4bd7e1`)

To verify the integrity of this bundle:
```bash
node scripts/verify-artifact-manifest.mjs .
```
