import test from "node:test";
import assert from "node:assert/strict";
import {
  computeIndent,
  stripPythonLineComment,
  findPythonScopeEnd,
  findFunctionDefinitions,
  extractBoundedFunctionSnippet,
  extractLocalCalleeContext
} from "../src/core/context-builder.mjs";

test("G5-P2-05: computeIndent correctly computes space and tab indentations", () => {
  assert.equal(computeIndent(""), 0);
  assert.equal(computeIndent("def foo():"), 0);
  assert.equal(computeIndent("  def foo():"), 2);
  assert.equal(computeIndent("    def foo():"), 4);
  assert.equal(computeIndent("\tdef foo():"), 4);
  assert.equal(computeIndent("\t\tdef foo():"), 8);
  assert.equal(computeIndent(" \tdef foo():"), 4); // 1 space + tab -> next tab stop (4)
});

test("G5-P2-05: stripPythonLineComment strips trailing comments while preserving strings", () => {
  assert.equal(stripPythonLineComment("x = 1 # comment"), "x = 1 ");
  assert.equal(stripPythonLineComment('msg = "# not a comment" # real comment'), 'msg = "# not a comment" ');
  assert.equal(stripPythonLineComment("def foo():"), "def foo():");
});

test("G5-P2-05: findPythonScopeEnd resolves standard indented function boundaries (rTXZk / rhwE4)", () => {
  const code = [
    "def validate_token(token):",
    "    if not token:",
    "        return False",
    "    return True",
    "",
    "def next_func():",
    "    pass"
  ];
  const endLine = findPythonScopeEnd(code, 0);
  assert.equal(endLine, 4, "Should span lines 1-4 without needing curly braces");
});

test("G5-P2-05: findPythonScopeEnd does not prematurely truncate on dict or set literals (sUDZJ)", () => {
  const code = [
    "def check_permission(user):",
    '    roles = {"admin": True, "editor": False}',
    "    if not roles.get(user.role):",
    '        raise PermissionError("Access denied")',
    "    return True",
    "",
    "def next_func():",
    "    pass"
  ];
  const endLine = findPythonScopeEnd(code, 0);
  assert.equal(endLine, 5, "Must include all lines up to return True, ignoring internal dict braces");
});

test("G5-P2-05: findPythonScopeEnd handles multiline signatures with type annotations and comments", () => {
  const code = [
    "async def fetch_user_permissions(",
    "    user_id: str,",
    '    default_role: str = "guest",  # fallback role',
    '    options: dict = {"cache": True}',
    ") -> dict[str, Any]:",
    '    """Fetches user permissions."""',
    "    record = await db.find(user_id)",
    "    return record.get('permissions', options)"
  ];
  const endLine = findPythonScopeEnd(code, 0);
  assert.equal(endLine, 8, "Must handle multiline async signature with type hints, defaults, and docstrings");
});

test("G5-P2-05: findPythonScopeEnd handles single-line function definitions", () => {
  const code = [
    "def is_admin(user): return user.role == 'admin'",
    "def next_func():",
    "    pass"
  ];
  const endLine = findPythonScopeEnd(code, 0);
  assert.equal(endLine, 1, "Single-line function ends on line 1");
});

test("G5-P2-05: findPythonScopeEnd rejects unclosed or empty body function definitions (fail closed)", () => {
  const unclosed = [
    "def broken_fn(x):"
  ];
  assert.equal(findPythonScopeEnd(unclosed, 0), -1, "Function with no body must return -1");

  const unclosedSig = [
    "def broken_sig(x, y:"
  ];
  assert.equal(findPythonScopeEnd(unclosedSig, 0), -1, "Function with unclosed signature must return -1");
});

test("G5-P2-05: findPythonScopeEnd handles class methods and respects class indentation", () => {
  const code = [
    "class SecurityService:",
    "    def authorize(self, token):",
    "        if not token:",
    "            return False",
    "        return True",
    "",
    "    def revoke(self, token):",
    "        pass"
  ];
  const endLine = findPythonScopeEnd(code, 1);
  assert.equal(endLine, 5, "Class method must end at line 5 before next method at line 7");
});

test("G5-P2-05: findFunctionDefinitions extracts Python functions without braces (rTXZk / rhwE4)", () => {
  const code = [
    "def sanitize_input(val):",
    "    return val.strip()",
    "",
    "async def authorize_user(user):",
    "    return True"
  ];
  const defs1 = findFunctionDefinitions(code, "sanitize_input");
  assert.equal(defs1.length, 1);
  assert.deepEqual(defs1[0], { startLine: 1, endLine: 2 });

  const defs2 = findFunctionDefinitions(code, "authorize_user");
  assert.equal(defs2.length, 1);
  assert.deepEqual(defs2[0], { startLine: 4, endLine: 5 });
});

test("G5-P2-05: extractBoundedFunctionSnippet marks closed Python function as full_body", () => {
  const lines = [
    "def validate_signature(sig):",
    '    if not sig.startswith("v1="):',
    "        raise ValueError('Invalid signature')",
    "    return True"
  ];
  const snippet = extractBoundedFunctionSnippet(lines, 1, 4);
  assert.equal(snippet.extractionMode, "full_body");
  assert.equal(snippet.lines, 4);
  assert.equal(snippet.definition, lines.join("\n"));
});

test("G5-P2-05: End-to-end extractLocalCalleeContext extracts Python callee and emits 0 gaps (sUDZJ / rTXZk / rhwE4)", () => {
  const fileContent = [
    "def check_permission(user):",
    '    roles = {"admin": True, "editor": False}',
    "    if not roles.get(user.role):",
    '        raise PermissionError("Access denied")',
    "    return True",
    "",
    "def handle_request(req):",
    "    check_permission(req.user)",
    "    return True"
  ].join("\n");

  const diffHunks = [
    "@@ -6,3 +6,4 @@",
    " def handle_request(req):",
    "+    check_permission(req.user)",
    "     return True"
  ].join("\n");

  const result = extractLocalCalleeContext(fileContent, diffHunks, "backend/auth.py");
  assert.equal(result.callees.length, 1, "Must extract check_permission as authoritative callee");
  assert.equal(result.callees[0].symbol, "check_permission");
  assert.equal(result.callees[0].startLine, 1);
  assert.equal(result.callees[0].endLine, 5);
  assert.equal(result.callees[0].extractionMode, "full_body");
  assert.equal(result.unresolvedCallees.length, 0, "No unresolved callees");
  assert.equal(result.contextGaps.length, 0, "No context gaps emitted");
});

test("G5-P2-05: extractLocalCalleeContext marks patch-deleted Python def as deleted local definition", () => {
  const fileContent = [
    "def handle_request(req):",
    "    legacy_check(req.user)",
    "    return True"
  ].join("\n");

  const diffHunks = [
    "@@ -1,5 +1,2 @@",
    "-def legacy_check(user):",
    "-    return True",
    " def handle_request(req):",
    "+    legacy_check(req.user)",
    "     return True"
  ].join("\n");

  const result = extractLocalCalleeContext(fileContent, diffHunks, "backend/auth.py");
  assert.equal(result.callees.length, 0, "Deleted local definition cannot be extracted");
  assert.equal(result.unresolvedCallees.length, 1);
  assert.equal(result.unresolvedCallees[0].symbol, "legacy_check");
});
