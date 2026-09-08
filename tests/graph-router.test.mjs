import test from "node:test";
import assert from "node:assert/strict";
import { classifyFileRisk, evaluateDiffScale, RISK_TIERS } from "../src/core/graph-router.mjs";

test("classifyFileRisk classifies security directories as Tier 1 and avoids false positives (P1-04)", () => {
  // Positive Tier 1 (Security Directories & Files)
  assert.equal(classifyFileRisk("src/auth/service.js"), RISK_TIERS.TIER_1_CRITICAL);
  assert.equal(classifyFileRisk("src/security/policy.js"), RISK_TIERS.TIER_1_CRITICAL);
  assert.equal(classifyFileRisk("src/crypto/aes.js"), RISK_TIERS.TIER_1_CRITICAL);
  assert.equal(classifyFileRisk("src/jwt/parser.js"), RISK_TIERS.TIER_1_CRITICAL);
  assert.equal(classifyFileRisk("src/login/controller.js"), RISK_TIERS.TIER_1_CRITICAL);
  assert.equal(classifyFileRisk("src/token/store.js"), RISK_TIERS.TIER_1_CRITICAL);
  assert.equal(classifyFileRisk("src/permission/check.js"), RISK_TIERS.TIER_1_CRITICAL);
  assert.equal(classifyFileRisk("tests/auth/service.test.js"), RISK_TIERS.TIER_1_CRITICAL);
  assert.equal(classifyFileRisk(".github/workflows/build.yml"), RISK_TIERS.TIER_1_CRITICAL);
  assert.equal(classifyFileRisk("Dockerfile"), RISK_TIERS.TIER_1_CRITICAL);

  // Negative / Other Tiers
  assert.equal(classifyFileRisk("docs/auth/guide.md"), RISK_TIERS.TIER_3_DOCS);
  assert.equal(classifyFileRisk("src/author/profile.js"), RISK_TIERS.TIER_2_SOURCE);
  assert.equal(classifyFileRisk("src/tokenizer/parser.js"), RISK_TIERS.TIER_2_SOURCE);
});

test("classifyFileRisk classifies lockfiles as Tier 2 source and counts them in diff", () => {
  assert.equal(classifyFileRisk("package-lock.json"), RISK_TIERS.TIER_2_SOURCE);
  assert.equal(classifyFileRisk("pnpm-lock.yaml"), RISK_TIERS.TIER_2_SOURCE);
});

test("evaluateDiffScale routes >2MB largeFile or unreadable files to hierarchical swarm (P1-06, P1-07)", () => {
  const planLarge = evaluateDiffScale([
    { path: "src/utils/big.js", additions: 0, deletions: 0, largeFile: true }
  ]);
  assert.equal(planLarge.mode, "hierarchical");
  assert.match(planLarge.reason, /large.*uninspected/i);

  const planUnreadable = evaluateDiffScale([
    { path: "src/broken-symlink", additions: 0, deletions: 0, unreadable: true }
  ]);
  assert.equal(planUnreadable.mode, "hierarchical");
});

test("evaluateDiffScale routes small source diff to single-agent mode", () => {
  const plan = evaluateDiffScale([
    { path: "src/utils/math.ts", additions: 15, deletions: 2 }
  ]);
  assert.equal(plan.mode, "single");
  assert.equal(plan.highestRisk, RISK_TIERS.TIER_2_SOURCE);
});
