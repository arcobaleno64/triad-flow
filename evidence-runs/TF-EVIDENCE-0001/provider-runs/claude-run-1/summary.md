# Triad-Flow Benchmark Audit Summary

## Cryptographic Provenance & Manifest
- **Run ID**: `run-bench-1790729532349-487fe592`
- **Git Commit**: `a4d0b92f06859e75223225fce72b0c3d0b25d23d`
- **Corpus Version**: `TF-RBC-v0`
- **Corpus Digest**: `sha256:cf9c4596cca5910bf1c493590e16a4333782defea779a39488fa95f6b16fb82b`
- **Receipt Digest**: `sha256:56f98e0df3d05a1c9a18b78e1e70b8f1828393577b5ddf01c1f35bfdc6da7741`
- **Results Digest**: `sha256:2e8f07f446932a678066ccd9f557096d7f4f69114e648fe8a68b6d9b1d076e5c`

## Execution Environment
- **Framework**: Triad-Flow Real Benchmark Corpus v0 (TF-RBC-v0)
- **Evaluation Mode**: `single`
- **Execution Mode**: `live`
- **Workspace Mode**: `physical`
- **Environment**: `win32 (x64)` | Node `v24.14.1`
- **Started At**: 2026-09-30T00:52:12.349Z
- **Finished At**: 2026-09-30T00:52:12.348Z

## Benchmark Quality & Performance Metrics
| Metric | Value |
|---|---|
| Total Cases | 1 |
| Vulnerable Cases | 1 |
| Clean Controls | 0 |
| Recall Rate | 100.0% |
| Precision | 25.0% |
| False Block Rate | N/A |
| Latency P50 | 19549 ms |
| Latency P95 | 19549 ms |
| Authoritative Token Usage | null (unreported / unavailable) |

## Cryptographic Artifact Bundle
The following artifacts are recorded in `artifact-manifest.json`:

- `benchmark-results.json`: `sha256:2e8f07f446932a678066ccd9f557096d7f4f69114e648fe8a68b6d9b1d076e5c`
- `audit-receipt.json`: `sha256:897bed2220e08fce548c39004c1ec663a310282104a764e0345d0fecab5795c4` (canonical: `sha256:56f98e0df3d05a1c9a18b78e1e70b8f1828393577b5ddf01c1f35bfdc6da7741`)

To verify the integrity of this bundle:
```bash
node scripts/verify-artifact-manifest.mjs .
```
