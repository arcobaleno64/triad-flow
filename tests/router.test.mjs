import test from "node:test";
import assert from "node:assert/strict";
import { classifyFileRisk, evaluateDiffScale, RISK_TIERS } from "../src/core/router.mjs";

test("classifyFileRisk correctly tags Tier 1 Security / CI files", () => {
  assert.equal(classifyFileRisk("src/auth/login.ts"), RISK_TIERS.TIER_1_CRITICAL);
  assert.equal(classifyFileRisk(".github/workflows/ci.yml"), RISK_TIERS.TIER_1_CRITICAL);
  assert.equal(classifyFileRisk("Dockerfile"), RISK_TIERS.TIER_1_CRITICAL);
});

test("classifyFileRisk correctly tags Tier 3 documentation / lockfiles", () => {
  assert.equal(classifyFileRisk("README.md"), RISK_TIERS.TIER_3_DOCS);
  assert.equal(classifyFileRisk("docs/architecture.md"), RISK_TIERS.TIER_3_DOCS);
  assert.equal(classifyFileRisk("package-lock.json"), RISK_TIERS.TIER_3_DOCS);
});

test("evaluateDiffScale routes small source diff to single-agent mode", () => {
  const plan = evaluateDiffScale([
    { path: "src/utils/math.ts", additions: 15, deletions: 5 }
  ]);
  assert.equal(plan.mode, "single");
  assert.equal(plan.subagents.length, 0);
});

test("evaluateDiffScale triggers hierarchical subagents for Tier 1 auth files", () => {
  const plan = evaluateDiffScale([
    { path: "src/auth/jwt.ts", additions: 10, deletions: 2 }
  ]);
  assert.equal(plan.mode, "hierarchical");
  assert.ok(plan.subagents.includes("micro-pen-tester"));
});
