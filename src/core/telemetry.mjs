/**
 * Observability Engineering: Ultra-Lean Distributed Span Tracer
 */

export class SpanTracer {
  constructor(serviceName = "triad-flow") {
    this.serviceName = serviceName;
    this.traceId = `tr-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
    this.spans = [];
  }

  startSpan(name, attributes = {}) {
    const spanId = `sp-${this.spans.length + 1}-${Date.now().toString(36)}`;
    const span = {
      traceId: this.traceId,
      spanId,
      name,
      attributes,
      startTime: Date.now(),
      endTime: null,
      durationMs: null,
      status: "running"
    };
    this.spans.push(span);
    return {
      end: (status = "ok", extraAttrs = {}) => {
        span.endTime = Date.now();
        span.durationMs = Math.max(0, span.endTime - span.startTime);
        span.status = status;
        span.attributes = { ...span.attributes, ...extraAttrs };
        return span;
      }
    };
  }

  exportSummary() {
    const totalDuration = this.spans.reduce((sum, s) => sum + (s.durationMs || 0), 0);
    return {
      traceId: this.traceId,
      totalSpans: this.spans.length,
      totalDurationMs: totalDuration,
      spans: this.spans
    };
  }
}
