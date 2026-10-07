import test from "node:test";
import assert from "node:assert/strict";
import {
  TAXONOMY_CHECKLISTS,
  selectChecklists,
  buildEvidenceReviewPrompt,
  buildReviewPrompt
} from "../src/adapters/review-prompts.mjs";

test("LOOP2-005: TAXONOMY_CHECKLISTS defines STATE_INVARIANT_CONCURRENCY checklist", () => {
  const item = TAXONOMY_CHECKLISTS.STATE_INVARIANT_CONCURRENCY;
  assert.ok(item, "STATE_INVARIANT_CONCURRENCY must exist");
  assert.equal(item.id, "CHECKLIST-CWE-362-400");
  assert.ok(item.title.includes("State Machine, Concurrency & Resource Accounting"));
  assert.ok(Array.isArray(item.rules) && item.rules.length >= 5);
  assert.ok(item.rules.some(r => r.includes("Extract protected invariant")));
  assert.ok(item.rules.some(r => r.includes("4 paths")));
  assert.ok(item.rules.some(r => r.includes("check-and-reserve atomicity")));
  assert.ok(item.rules.some(r => r.includes("interleaving counterexample")));
  assert.ok(item.rules.some(r => r.includes("failure rollback")));
});

test("LOOP2-005: selectChecklists triggers STATE_INVARIANT_CONCURRENCY on resource/pool/counter diffs", () => {
  const csRedis = {
    files: [{ path: "redis/connection.py" }],
    diffHunks: `
- self._created_connections += 1
+ connection = self.connection_class(**kwargs)
+ self._created_connections += 1
`
  };
  const checklists = selectChecklists(csRedis);
  assert.ok(checklists.some(c => c.id === "CHECKLIST-CWE-362-400"), "Must select CHECKLIST-CWE-362-400 for pool/counter diff");
});

test("LOOP2-005: buildEvidenceReviewPrompt includes STATE MUTATION & INVARIANT PRESERVATION RUBRIC", () => {
  const cs = {
    scopeMode: "working-tree",
    contentDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    files: [{ path: "redis/connection.py" }],
    diffHunks: "+ self._created_connections += 1"
  };

  const prompt = buildEvidenceReviewPrompt(cs, "macro");
  assert.match(prompt, /\[STATE MUTATION & INVARIANT PRESERVATION RUBRIC\]/);
  assert.match(prompt, /When a patch changes when, where, or whether state is mutated/);
  assert.match(prompt, /1\. Invariant Extraction/);
  assert.match(prompt, /2\. Mutation-Relocation 4-Path Evaluation/);
  assert.match(prompt, /Success Path/);
  assert.match(prompt, /Failure & Rollback Path/);
  assert.match(prompt, /Concurrent Interference Path/);
  assert.match(prompt, /Retry & Cancellation Path/);
  assert.match(prompt, /A patch MUST NOT fix a failure-path leak by destroying reservation atomicity on the concurrent interference path/);
  assert.match(prompt, /3\. Interleaving Counterexample Obligation/);
  assert.match(prompt, /Can Actor 1 and Actor 2 both observe the precondition/);
  assert.match(prompt, /reserve first, rollback in an exception handler upon failure/);
  assert.match(prompt, /4\. Precision Discipline/);
});

test("LOOP2-005 Contract A: Prompt enforces check-and-reserve atomicity over post-construction counting (CYCLE-0024 pattern)", () => {
  const cs = {
    scopeMode: "working-tree",
    contentDigest: "abc123digest",
    files: [{ path: "redis/connection.py" }],
    diffHunks: `
@@ -3414,7 +3414,6 @@
         if self._created_connections >= self.max_connections:
             raise MaxConnectionsError("Too many connections")
-        self._created_connections += 1
+        connection = self.connection_class(**kwargs)
+        self._created_connections += 1
`
  };

  const prompt = buildEvidenceReviewPrompt(cs, "macro", undefined, null, {
    patchObjective: "Prevent connection-construction failures from permanently consuming connection-pool capacity while preserving max_connections accounting."
  });

  assert.match(prompt, /Core Analytical Principle:/);
  assert.match(prompt, /Concurrent Interference Path/);
  assert.match(prompt, /reserve first, rollback in an exception handler/);
  assert.match(prompt, /INVARIANT_VIOLATION/);
});

test("LOOP2-005 Contract B: Safe rollback pattern (reserve first, rollback on error) is protected by precision discipline", () => {
  const cs = {
    scopeMode: "working-tree",
    contentDigest: "def456digest",
    files: [{ path: "pool.py" }],
    diffHunks: `
+ self.count += 1
+ try:
+     conn = create_connection()
+ except Exception:
+     self.count -= 1
+     raise
`
  };

  const prompt = buildEvidenceReviewPrompt(cs, "macro");
  assert.match(prompt, /Precision Discipline:/);
  assert.match(prompt, /Do NOT flag patterns that already hold synchronization locks across the check-and-mutation or safely use atomic compare-and-swap/);
});

test("LOOP2-005 Contract C: Pure local counter relocation on unshared state is protected by precision discipline", () => {
  const cs = {
    scopeMode: "working-tree",
    contentDigest: "789digest",
    files: [{ path: "util.py" }],
    diffHunks: `
 def count_items(items):
-    total = 0
     for x in items:
         process(x)
+    total = len(items)
     return total
`
  };

  const prompt = buildEvidenceReviewPrompt(cs, "macro");
  assert.match(prompt, /Do NOT flag thread-local or purely unshared variables where concurrency is impossible/);
});

test("LOOP2-005 Contract D: Ownership transfer rubric requires failure and cancellation path integrity", () => {
  const cs = {
    scopeMode: "working-tree",
    contentDigest: "ownership123",
    files: [{ path: "resource_manager.cpp" }],
    diffHunks: `
+ auto res = acquire_resource();
+ target->set_resource(std::move(res));
`
  };

  const prompt = buildEvidenceReviewPrompt(cs, "macro");
  assert.match(prompt, /allocated resources have exactly one owner and are freed on all exit paths/);
});

test("LOOP2-005 Contract E: Bounded resource ceiling requires interleaving counterexample reasoning", () => {
  const cs = {
    scopeMode: "working-tree",
    contentDigest: "ceiling123",
    files: [{ path: "quota.js" }],
    diffHunks: `
+ if (current < limit) {
+   await doSlowWork();
+   current++;
+ }
`
  };

  const prompt = buildEvidenceReviewPrompt(cs, "macro");
  assert.match(prompt, /Can Actor 1 and Actor 2 both observe the precondition/);
  assert.match(prompt, /the capacity ceiling is violated/);
});

test("LOOP2-005 Contract F: Retry and cancellation path requires invariant restoration before retry", () => {
  const cs = {
    scopeMode: "working-tree",
    contentDigest: "retry123",
    files: [{ path: "client.py" }],
    diffHunks: `
+ while retries > 0:
+     retries -= 1
+     do_attempt()
`
  };

  const prompt = buildEvidenceReviewPrompt(cs, "macro");
  assert.match(prompt, /Retry & Cancellation Path: Aborted operations restore the invariant before subsequent attempts/);
});
