import test from "node:test";
import assert from "node:assert/strict";
import {
  TAXONOMY_CHECKLISTS,
  selectChecklists,
  formatChecklistsXml,
  formatContextPackageXml,
  buildEvidenceReviewPrompt,
  buildReviewPrompt
} from "../src/adapters/review-prompts.mjs";

test("TAXONOMY_CHECKLISTS defines all 5 required vulnerability categories", () => {
  const keys = Object.keys(TAXONOMY_CHECKLISTS);
  assert.ok(keys.includes("PROTOTYPE_POLLUTION"));
  assert.ok(keys.includes("REDOS"));
  assert.ok(keys.includes("CODE_INJECTION"));
  assert.ok(keys.includes("COMMAND_INJECTION"));
  assert.ok(keys.includes("PATH_TRAVERSAL"));

  for (const key of keys) {
    const item = TAXONOMY_CHECKLISTS[key];
    assert.ok(item.id.startsWith("CHECKLIST-"));
    assert.ok(item.title);
    assert.ok(Array.isArray(item.rules) && item.rules.length > 0);
  }
});

test("selectChecklists selects applicable checklists based on diff cues", () => {
  // Prototype pollution cue
  const csProto = {
    files: [{ path: "lib/merge.js" }],
    diffHunks: "+ target.__proto__ = source;"
  };
  const listProto = selectChecklists(csProto);
  assert.ok(listProto.some(c => c.id === "CHECKLIST-CWE-1321"));

  // ReDoS cue
  const csRedos = {
    files: [{ path: "src/parser.js" }],
    diffHunks: "+ const regex = /([a-z]+)+/;"
  };
  const listRedos = selectChecklists(csRedos);
  assert.ok(listRedos.some(c => c.id === "CHECKLIST-CWE-1333"));

  // Command injection cue
  const csCmd = {
    files: [{ path: "src/runner.js" }],
    diffHunks: "+ child_process.exec(`echo ${userArg}`);"
  };
  const listCmd = selectChecklists(csCmd);
  assert.ok(listCmd.some(c => c.id === "CHECKLIST-CWE-78"));

  // Path traversal cue
  const csPath = {
    files: [{ path: "src/server.js" }],
    diffHunks: "+ fs.readFileSync(path.join(__dirname, req.query.file));"
  };
  const listPath = selectChecklists(csPath);
  assert.ok(listPath.some(c => c.id === "CHECKLIST-CWE-22"));
});

test("buildEvidenceReviewPrompt renders XML sections and Default-Deny instructions", () => {
  const cs = {
    scopeMode: "working-tree",
    contentDigest: "abc123digest",
    files: [{ path: "src/index.js", additions: 5, deletions: 1 }],
    diffHunks: "+ function merge(a, b) { return Object.assign(a, b); }"
  };

  const prompt = buildEvidenceReviewPrompt(cs, "macro");
  assert.match(prompt, /\[SYSTEM IDENTITY & ROLE CONTRACT\]/);
  assert.match(prompt, /Default-Deny/);
  assert.match(prompt, /<security_checklists>/);
  assert.match(prompt, /<checklist id="CHECKLIST-CWE-1321"/);
  assert.match(prompt, /\[UNTRUSTED CODE MODIFICATIONS \(DIFF\)\]/);
  assert.match(prompt, /\[RESPONSE FORMAT SPECIFICATION\]/);
  assert.match(prompt, /"evidenceSnippet"/);
});

test("buildReviewPrompt maintains backward compatibility with legacy consumers", () => {
  const cs = {
    scopeMode: "working-tree",
    contentDigest: "hash456",
    files: [{ path: "src/legacy.js", additions: 2, deletions: 0 }],
    diffHunks: "+ const x = 42;"
  };

  const legacyPrompt = buildReviewPrompt(cs, "micro");
  assert.match(legacyPrompt, /Scope: working-tree/);
  assert.match(legacyPrompt, /src\/legacy\.js/);
  assert.match(legacyPrompt, /\+ const x = 42;/);
});
