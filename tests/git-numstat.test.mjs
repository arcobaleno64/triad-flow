import test from "node:test";
import assert from "node:assert/strict";
import { resolveRenamePath, parseNumstat, parseNumstatZ } from "../src/core/git-numstat.mjs";

test("resolveRenamePath parses brace rename syntax correctly", () => {
  const res = resolveRenamePath("src/{old => new}/app.js");
  assert.equal(res.path, "src/new/app.js");
  assert.equal(res.oldPath, "src/old/app.js");
  assert.equal(res.renamed, true);
});

test("resolveRenamePath decodes C-style quoted paths with spaces", () => {
  const res = resolveRenamePath('"src/My Folder/App.js"');
  assert.equal(res.path, '"src/My Folder/App.js"');
});

test("parseNumstat preserves filenames containing spaces and parses tab fields", () => {
  const input = "10\t5\tsrc/auth/jwt handler.js\n-\t-\tassets/logo image.png\n";
  const parsed = parseNumstat(input);

  assert.equal(parsed.length, 2);
  assert.equal(parsed[0].path, "src/auth/jwt handler.js");
  assert.equal(parsed[0].additions, 10);
  assert.equal(parsed[0].deletions, 5);
  assert.equal(parsed[0].binary, false);

  assert.equal(parsed[1].path, "assets/logo image.png");
  assert.equal(parsed[1].binary, true);
  assert.equal(parsed[1].additions, 0);
  assert.equal(parsed[1].deletions, 0);
});

test("parseNumstat returns empty array on empty input", () => {
  assert.deepEqual(parseNumstat(""), []);
  assert.deepEqual(parseNumstatZ(""), []);
});

test("parseNumstatZ correctly handles NUL-delimited diff with rename", () => {
  const raw = "10\t5\t\0src/old.js\0src/new.js\0 20\t0\tsrc/added.js\0";
  const parsed = parseNumstatZ(raw);

  assert.equal(parsed.length, 2);
  assert.equal(parsed[0].path, "src/new.js");
  assert.equal(parsed[0].oldPath, "src/old.js");
  assert.equal(parsed[0].renamed, true);
  assert.equal(parsed[0].additions, 10);
  assert.equal(parsed[0].deletions, 5);

  assert.equal(parsed[1].path, "src/added.js");
  assert.equal(parsed[1].renamed, false);
});

test("parseNumstatZ preserves POSIX backslash characters in filenames (P1-05)", () => {
  const raw = "5\t2\tauth\\file.js\0";
  const parsed = parseNumstatZ(raw);
  assert.equal(parsed.length, 1);
  assert.equal(parsed[0].path, "auth\\file.js");
});
