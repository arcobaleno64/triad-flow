# Triad-Flow Shadow Dogfood Observation

> **Authority boundary:** `dogfood-receipts.jsonl` is the canonical append-only observation ledger. This Markdown file is a derived projection only, may be deleted and regenerated, and has no independent evidence authority.

## Operational Baseline

- Release: `v2.7.0`
- Canonical release commit: `fdcabf861368edbe552a0427efcb89da47fd4cb7`
- Stage: `SHADOW_DOGFOOD`
- Runtime merge authority: `NONE`
- Maturity target: `SHADOW -> ADVISORY` after 20–30 qualifying real change cycles

## Scorecard

- Ledger receipts: **27**
- Maturity-counting cycles: **26 / 20–30**
- False advance: **3**
- False hold: **3**
- Timeout-cycle rate: **0.0%**
- Average wall-clock latency: **65839 ms**

False-advance/false-hold rates use only binary autonomous Triad outcomes (`APPROVE` / `BLOCK`). `DEGRADED`, `INCOMPLETE`, and `HUMAN_REVIEW_REQUIRED` never enter those rates automatically.

> **Legacy observation:** `CYCLE-0001` remains preserved as real shadow observation, but predates producer-authoritative `executionMode` / `runStartedAt` and therefore does not count toward the maturity denominator.

## Cycle Receipts

| Cycle | Mode | Counts | Human | Triad | Discrepancy | Verify | Family | Recurrence | Escalation |
|---|---|---:|---|---|---|---|---|---:|---|
| CYCLE-0001 | live | no | APPROVE | DEGRADED | NEUTRAL_DISAGREEMENT | SUCCESS | ledger-path-collision | 0 | NONE |
| CYCLE-0002 | live | yes | APPROVE | APPROVE | MATCH | NOT_ATTEMPTED | NONE | 0 | NONE |
| CYCLE-0003 | live | yes | REQUEST_CHANGES | BLOCK | MATCH | SUCCESS | NONE | 0 | NONE |
| CYCLE-0004 | live | yes | APPROVE | APPROVE | MATCH | NOT_ATTEMPTED | NONE | 0 | NONE |
| CYCLE-0005 | live | yes | REQUEST_CHANGES | BLOCK | MATCH | SUCCESS | NONE | 0 | NONE |
| CYCLE-0006 | live | yes | APPROVE | APPROVE | MATCH | NOT_ATTEMPTED | NONE | 0 | NONE |
| CYCLE-0007 | live | yes | APPROVE | APPROVE | MATCH | NOT_ATTEMPTED | NONE | 0 | NONE |
| CYCLE-0008 | live | yes | APPROVE | BLOCK | FALSE_HOLD | SUCCESS | NONE | 0 | RELIABILITY_PRIORITY |
| CYCLE-0009 | live | yes | APPROVE | BLOCK | FALSE_HOLD | SUCCESS | NONE | 0 | RELIABILITY_PRIORITY |
| CYCLE-0010 | live | yes | APPROVE | APPROVE | MATCH | SUCCESS | NONE | 0 | NONE |
| CYCLE-0011 | live | yes | APPROVE | BLOCK | FALSE_HOLD | SUCCESS | false-hold | 1 | RELIABILITY_PRIORITY |
| CYCLE-0012 | live | yes | APPROVE | APPROVE | MATCH | NOT_ATTEMPTED | NONE | 0 | NONE |
| CYCLE-0013 | live | yes | APPROVE | DEGRADED | NEUTRAL_DISAGREEMENT | NOT_ATTEMPTED | NONE | 0 | NONE |
| CYCLE-0014 | live | yes | APPROVE | APPROVE | MATCH | NOT_ATTEMPTED | NONE | 0 | NONE |
| CYCLE-0015 | live | yes | APPROVE | APPROVE | MATCH | NOT_ATTEMPTED | NONE | 0 | NONE |
| CYCLE-0016 | live | yes | APPROVE | APPROVE | MATCH | NOT_ATTEMPTED | NONE | 0 | NONE |
| CYCLE-0017 | live | yes | APPROVE | APPROVE | MATCH | NOT_ATTEMPTED | NONE | 0 | NONE |
| CYCLE-0018 | live | yes | APPROVE | APPROVE | MATCH | NOT_ATTEMPTED | NONE | 0 | NONE |
| CYCLE-0019 | live | yes | APPROVE | APPROVE | MATCH | NOT_ATTEMPTED | NONE | 0 | NONE |
| CYCLE-0020 | live | yes | APPROVE | APPROVE | MATCH | NOT_ATTEMPTED | NONE | 0 | NONE |
| CYCLE-0021 | live | yes | REQUEST_CHANGES | APPROVE | FALSE_ADVANCE | SUCCESS | false-advance | 1 | IMMEDIATE_BLOCKER |
| CYCLE-0022 | live | yes | REQUEST_CHANGES | APPROVE | FALSE_ADVANCE | NOT_ATTEMPTED | false-advance | 2 | IMMEDIATE_BLOCKER |
| CYCLE-0023 | live | yes | APPROVE | APPROVE | MATCH | NOT_ATTEMPTED | NONE | 0 | NONE |
| CYCLE-0024 | live | yes | REQUEST_CHANGES | APPROVE | FALSE_ADVANCE | NOT_ATTEMPTED | false-advance | 3 | IMMEDIATE_BLOCKER |
| CYCLE-0025 | live | yes | REQUEST_CHANGES | DEGRADED | NEUTRAL_DISAGREEMENT | SUCCESS | NONE | 0 | NONE |
| CYCLE-0026 | live | yes | APPROVE | APPROVE | MATCH | NOT_ATTEMPTED | NONE | 0 | NONE |
| CYCLE-0027 | live | yes | APPROVE | APPROVE | MATCH | NOT_ATTEMPTED | NONE | 0 | NONE |

## Active Failure Families

| Failure family | Qualifying occurrences |
|---|---:|
| false-advance | 3 |
| false-hold | 1 |

## SHADOW -> ADVISORY Maturity Gate

- [x] At least 20 qualifying real change cycles (target range 20–30).
- [ ] No observed false advance in the qualifying sample.
- [ ] No known systemic false-approve path.
- [ ] No new P0/P1 authority, provenance, or coverage truthfulness family.
- [ ] PASS / BLOCK / DEGRADED / INCOMPLETE / HUMAN_REVIEW_REQUIRED classification is operationally stable.
- [ ] False-hold / override / latency / cost baseline has been reviewed by human authority.

Promotion remains a human governance decision. This projection never promotes Triad-Flow automatically.
