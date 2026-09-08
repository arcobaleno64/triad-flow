import test from "node:test";
import assert from "node:assert/strict";
import { checkFactoryReadiness, runFactoryPipeline, FACTORY_STATUS } from "../src/core/factory.mjs";

test("checkFactoryReadiness reports every missing adapter", () => {
  const res = checkFactoryReadiness({});
  assert.equal(res.status, FACTORY_STATUS.UNCONFIGURED);
  assert.equal(res.ready, false);
  assert.deepEqual(res.missing, ["remediator", "macroSentry", "microSentry"]);

  const partial = checkFactoryReadiness({ remediator: {}, macroSentry: {} });
  assert.deepEqual(partial.missing, ["microSentry"]);
  assert.equal(partial.ready, false);
});

test("checkFactoryReadiness reports ready only when all three adapters are present", () => {
  const res = checkFactoryReadiness({ remediator: {}, macroSentry: {}, microSentry: {} });
  assert.equal(res.status, FACTORY_STATUS.READY);
  assert.equal(res.ready, true);
  assert.deepEqual(res.missing, []);
});

test("runFactoryPipeline never mutates code and always halts while unconfigured", () => {
  const res = runFactoryPipeline({});
  assert.equal(res.halted, true);
  assert.equal(res.mutated, false);
  assert.match(res.lines.join(""), /Unconfigured Factory Adapters/);
  assert.match(res.lines.join(""), /Enforcing Fail-Closed/);
});

test("runFactoryPipeline still fails closed when adapters are configured but no execution path exists", () => {
  const res = runFactoryPipeline({ remediator: {}, macroSentry: {}, microSentry: {} });
  assert.equal(res.halted, true, "Must not claim a run it cannot perform");
  assert.equal(res.mutated, false);
});
