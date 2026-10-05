# Triad-Flow Shadow Dogfood Observation

> **Authority boundary:** `dogfood-receipts.jsonl` is the canonical append-only observation ledger. This Markdown file is a derived projection only, may be deleted and regenerated, and has no independent evidence authority.

## Operational Baseline

- Release: `v2.7.0`
- Canonical release commit: `fdcabf861368edbe552a0427efcb89da47fd4cb7`
- Stage: `SHADOW_DOGFOOD`
- Runtime merge authority: `NONE`
- Maturity target: `SHADOW -> ADVISORY` after 20–30 qualifying real change cycles

## Scorecard

- Ledger receipts: **3**
- Maturity-counting cycles: **2 / 20–30**
- False advance: **0**
- False hold: **0**
- Timeout-cycle rate: **0.0%**
- Average wall-clock latency: **74748 ms**

False-advance/false-hold rates use only binary autonomous Triad outcomes (`APPROVE` / `BLOCK`). `DEGRADED`, `INCOMPLETE`, and `HUMAN_REVIEW_REQUIRED` never enter those rates automatically.

> **Legacy observation:** `CYCLE-0001` remains preserved as real shadow observation, but predates producer-authoritative `executionMode` / `runStartedAt` and therefore does not count toward the maturity denominator.

## Cycle Receipts

| Cycle | Mode | Counts | Human | Triad | Discrepancy | Verify | Family | Recurrence | Escalation |
|---|---|---:|---|---|---|---|---|---:|---|
| CYCLE-0001 | live | no | APPROVE | DEGRADED | NEUTRAL_DISAGREEMENT | SUCCESS | ledger-path-collision | 0 | NONE |
| CYCLE-0002 | live | yes | APPROVE | APPROVE | MATCH | NOT_ATTEMPTED | NONE | 0 | NONE |
| CYCLE-0003 | live | yes | REQUEST_CHANGES | BLOCK | MATCH | SUCCESS | NONE | 0 | NONE |

## Active Failure Families

| Failure family | Qualifying occurrences |
|---|---:|
| _none yet_ | 0 |

## SHADOW -> ADVISORY Maturity Gate

- [ ] At least 20 qualifying real change cycles (target range 20–30).
- [x] No observed false advance in the qualifying sample.
- [ ] No known systemic false-approve path.
- [ ] No new P0/P1 authority, provenance, or coverage truthfulness family.
- [ ] PASS / BLOCK / DEGRADED / INCOMPLETE / HUMAN_REVIEW_REQUIRED classification is operationally stable.
- [ ] False-hold / override / latency / cost baseline has been reviewed by human authority.

Promotion remains a human governance decision. This projection never promotes Triad-Flow automatically.
