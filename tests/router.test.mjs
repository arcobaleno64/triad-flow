import test from "node:test";
import assert from "node:assert/strict";
import { classifyFileRisk, evaluateDiffScale, RISK_TIERS } from "../src/core/router.mjs";

test("classifyFileRisk correctly tags Tier 1 Security / CI files with Windows & POSIX paths", () => {
  assert.equal(classifyFileRisk("src/auth/login.ts"), RISK_TIERS.TIER_1_CRITICAL);
  assert.equal(classifyFileRisk("src\\auth\\login.ts"), RISK_TIERS.TIER_1_CRITICAL);
  assert.equal(classifyFileRisk(".github/workflows/ci.yml"), RISK_TIERS.TIER_1_CRITICAL);
  assert.equal(classifyFileRisk("Dockerfile"), RISK_TIERS.TIER_1_CRITICAL);
});

test("classifyFileRisk prioritizes docs and prevents false critical on docs/login.md", () => {
  assert.equal(classifyFileRisk("docs/how-to-login.md"), RISK_TIERS.TIER_3_DOCS);
  assert.equal(classifyFileRisk("README-auth.md"), RISK_TIERS.TIER_3_DOCS);
  assert.equal(classifyFileRisk("package-lock.json"), RISK_TIERS.TIER_IGNORED);
  assert.equal(classifyFileRisk("dist/bundle.js"), RISK_TIERS.TIER_IGNORED);
});

test("classifyFileRisk downgrades test files to Tier 2 to prevent token blowout", () => {
  assert.equal(classifyFileRisk("tests/auth.test.ts"), RISK_TIERS.TIER_2_SOURCE);
  assert.equal(classifyFileRisk("src/__tests__/jwt.spec.ts"), RISK_TIERS.TIER_2_SOURCE);
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
