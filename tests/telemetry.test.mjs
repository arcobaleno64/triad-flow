import test from "node:test";
import assert from "node:assert/strict";
import { SpanTracer } from "../src/core/telemetry.mjs";

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
