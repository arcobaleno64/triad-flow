# Triad-Flow Benchmark Audit Summary

## Cryptographic Provenance & Manifest
- **Run ID**: `run-bench-1790729451810-5f1f8318`
- **Git Commit**: `a4d0b92f06859e75223225fce72b0c3d0b25d23d`
- **Corpus Version**: `TF-RBC-v0`
- **Corpus Digest**: `sha256:cf9c4596cca5910bf1c493590e16a4333782defea779a39488fa95f6b16fb82b`
- **Receipt Digest**: `sha256:4656bc8b37cfb3f0a6d5fc8a27171525347e86d61831b04d50b5562165225803`
- **Results Digest**: `sha256:eeb61e874185a9f29ff6addd43f2c4a4701738999007cc57173044b33134a8c4`

## Execution Environment
- **Framework**: Triad-Flow Real Benchmark Corpus v0 (TF-RBC-v0)
- **Evaluation Mode**: `single`
- **Execution Mode**: `live`
- **Workspace Mode**: `physical`
- **Environment**: `win32 (x64)` | Node `v24.14.1`
- **Started At**: 2026-09-30T00:50:51.810Z
- **Finished At**: 2026-09-30T00:50:51.809Z

## Benchmark Quality & Performance Metrics
| Metric | Value |
|---|---|
| Total Cases | 1 |
| Vulnerable Cases | 1 |
| Clean Controls | 0 |
| Recall Rate | 100.0% |
| Precision | 100.0% |
| False Block Rate | N/A |
| Latency P50 | 20282 ms |
| Latency P95 | 20282 ms |
| Authoritative Token Usage | null (unreported / unavailable) |

## Cryptographic Artifact Bundle
The following artifacts are recorded in `artifact-manifest.json`:

- `benchmark-results.json`: `sha256:eeb61e874185a9f29ff6addd43f2c4a4701738999007cc57173044b33134a8c4`
- `audit-receipt.json`: `sha256:a64737f830ba144f6161ed5cb10161c11ebd955bfeb47058649ac66bb1dbb182` (canonical: `sha256:4656bc8b37cfb3f0a6d5fc8a27171525347e86d61831b04d50b5562165225803`)

To verify the integrity of this bundle:
```bash
node scripts/verify-artifact-manifest.mjs .
```
