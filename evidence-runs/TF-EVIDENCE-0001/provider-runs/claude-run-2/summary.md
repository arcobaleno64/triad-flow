# Triad-Flow Benchmark Audit Summary

## Cryptographic Provenance & Manifest
- **Run ID**: `run-bench-1790729554835-d392ada6`
- **Git Commit**: `a4d0b92f06859e75223225fce72b0c3d0b25d23d`
- **Corpus Version**: `TF-RBC-v0`
- **Corpus Digest**: `sha256:cf9c4596cca5910bf1c493590e16a4333782defea779a39488fa95f6b16fb82b`
- **Receipt Digest**: `sha256:998546938963c7c7b36beeabd736b5780338fbe5688ce12c128f756a02f13b88`
- **Results Digest**: `sha256:b38358a48be1318f57d4e7b36507b144d84f22c7e558d85dea03c481b70e785f`

## Execution Environment
- **Framework**: Triad-Flow Real Benchmark Corpus v0 (TF-RBC-v0)
- **Evaluation Mode**: `single`
- **Execution Mode**: `live`
- **Workspace Mode**: `physical`
- **Environment**: `win32 (x64)` | Node `v24.14.1`
- **Started At**: 2026-09-30T00:52:34.835Z
- **Finished At**: 2026-09-30T00:52:34.834Z

## Benchmark Quality & Performance Metrics
| Metric | Value |
|---|---|
| Total Cases | 1 |
| Vulnerable Cases | 1 |
| Clean Controls | 0 |
| Recall Rate | 100.0% |
| Precision | 33.3% |
| False Block Rate | N/A |
| Latency P50 | 18197 ms |
| Latency P95 | 18197 ms |
| Authoritative Token Usage | null (unreported / unavailable) |

## Cryptographic Artifact Bundle
The following artifacts are recorded in `artifact-manifest.json`:

- `benchmark-results.json`: `sha256:b38358a48be1318f57d4e7b36507b144d84f22c7e558d85dea03c481b70e785f`
- `audit-receipt.json`: `sha256:161e4d962f066e8d397ce9e00bc1d0c53b39a604d68d90ec2f95885e5f34769c` (canonical: `sha256:998546938963c7c7b36beeabd736b5780338fbe5688ce12c128f756a02f13b88`)

To verify the integrity of this bundle:
```bash
node scripts/verify-artifact-manifest.mjs .
```
