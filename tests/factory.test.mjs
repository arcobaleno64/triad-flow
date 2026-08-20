import test from "node:test";
import assert from "node:assert/strict";
import { SpanTracer } from "../src/core/telemetry.mjs";
import { calculateMutationScore, verifyHeldOutBaseline } from "../src/core/eval.mjs";

test("SpanTracer tracks execution spans and exports timing summary", () => {
  const tracer = new SpanTracer("test-service");
  const span = tracer.startSpan("unit-step", { file: "test.ts" });
  span.end("ok", { customMetric: 42 });

  const summary = tracer.exportSummary();
  assert.equal(summary.totalSpans, 1);
  assert.equal(summary.spans[0].name, "unit-step");
  assert.equal(summary.spans[0].status, "ok");
  assert.equal(summary.spans[0].attributes.customMetric, 42);
});

test("calculateMutationScore computes killed percentage accurately", () => {
  assert.equal(calculateMutationScore(20, 19), 95.0);
  assert.equal(calculateMutationScore(0, 0), 100.0);
});

test("verifyHeldOutBaseline calculates recall against golden CVE list", () => {
  const findings = [
    { file: "src/auth/jwt.ts", title: "Unvalidated Token Expiry" }
  ];
  const goldens = [
    { id: "CVE-AUTH-1", type: "Token", file: "jwt.ts" },
    { id: "CVE-SQL-2", type: "SQL Injection", file: "db.ts" }
  ];

  const evalResult = verifyHeldOutBaseline(findings, goldens);
  assert.equal(evalResult.caughtGoldens, 1);
  assert.equal(evalResult.recallRate, "50%");
  assert.equal(evalResult.passed, false); // < 90%
});
