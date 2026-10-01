/**
 * OpenAI Codex Provider Profile & Transport Security Tests (RFC-027-02 Section 18.1)
 */

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import {
  PROVIDER_PROFILES,
  CodexProfileSchema,
  resolveProviderProfile,
  assembleProviderArgs,
  resolveNativeWindowsBinary
} from "../src/adapters/provider-profiles.mjs";
import { CliReviewAdapter } from "../src/adapters/cli-transport.mjs";
import { EXECUTION_STATUS } from "../src/adapters/provider-contract.mjs";

test("test_codex_profile_canonical_definition: PROVIDER_PROFILES.codex specifies canonical invariants", () => {
  assert.ok(PROVIDER_PROFILES.codex);
  assert.equal(PROVIDER_PROFILES.codex.id, "codex");
  assert.equal(PROVIDER_PROFILES.codex.command, "codex");
  assert.equal(PROVIDER_PROFILES.codex.family, "openai");
  assert.equal(PROVIDER_PROFILES.codex.model, "gpt-6.1-sol");
  assert.equal(PROVIDER_PROFILES.codex.reviewProfileReady, true);
  assert.equal(PROVIDER_PROFILES.codex.profileStatus, "canonical");
  assert.equal(PROVIDER_PROFILES.codex.supportsStdin, true);
  assert.equal(PROVIDER_PROFILES.codex.inputChannel, "stdin");
  assert.equal(PROVIDER_PROFILES.codex.outputChannel, "file");
  assert.equal(PROVIDER_PROFILES.codex.outputFileFlag, "-o");
  assert.ok(PROVIDER_PROFILES.codex.mandatorySafetyArgs.includes("--sandbox=read-only"));
  assert.ok(PROVIDER_PROFILES.codex.args.includes("--sandbox=read-only"));
  assert.ok(PROVIDER_PROFILES.codex.readOnlyFlags.includes("--sandbox=read-only"));

  assert.equal(CodexProfileSchema, PROVIDER_PROFILES.codex);

  // Object immutability
  assert.throws(() => {
    PROVIDER_PROFILES.codex.model = "gpt-4o";
  }, TypeError);
});

test("test_codex_native_binary_resolution_windows: resolves executable without batch wrapper", () => {
  const resolved = resolveNativeWindowsBinary("codex");
  assert.ok(resolved);
  assert.equal(typeof resolved.command, "string");
  assert.equal(resolved.useShell, false);
  assert.ok(!resolved.command.endsWith(".cmd"), "Windows resolution must never return .cmd wrapper (EINVAL hazard)");
  assert.ok(["NATIVE_EXE", "NODE_SCRIPT", "PATH_LOOKUP", "NATIVE_POSIX"].includes(resolved.resolvedType));

  // Non-codex command returns DEFAULT
  const otherResolved = resolveNativeWindowsBinary("some-custom-tool");
  assert.equal(otherResolved.useShell, false);
});

test("test_codex_mandatory_arg_neutralization: strips hostile arguments and preserves sandbox", () => {
  const profile = resolveProviderProfile("codex");
  const hostileArgs = [
    "--dangerously-bypass-approvals-and-sandbox",
    "-s",
    "workspace-write",
    "apply",
    "--approve-for-me",
    "--sandbox=workspace-write"
  ];

  const merged = assembleProviderArgs(profile, hostileArgs);
  assert.ok(merged.includes("--sandbox=read-only"), "Mandatory --sandbox=read-only must be retained");
  assert.ok(!merged.includes("--sandbox=workspace-write"), "Hostile sandbox override must be stripped");
  assert.ok(!merged.includes("--dangerously-bypass-approvals-and-sandbox"), "Bypass flag must be stripped");
});

test("test_codex_tempfile_isolation: extracts pure JSON from -o tempfile despite noisy stdout banner", async () => {
  const mockExec = async ({ command, args, outputFile }) => {
    assert.ok(outputFile, "Temp output file path must be passed to execFn");
    assert.ok(args.includes("-o"), "Args must include -o flag for codex");
    assert.ok(args.includes(outputFile), "Args must include temp outputFile path");

    // Write valid review report into outputFile
    const payload = JSON.stringify({
      findings: [
        {
          id: "codex-01",
          title: "Prototype Pollution in merge",
          severity: "high",
          file: "lib/utils.js",
          line_start: 12,
          cwe: "CWE-1321"
        }
      ],
      coverage: { coveredFiles: ["lib/utils.js"], omittedFiles: [] }
    });
    fs.writeFileSync(outputFile, payload, "utf8");

    // Return stdout contaminated with noisy banner and hook logs
    return {
      code: 0,
      stdout: "=== OpenAI Codex CLI v0.12.0 ===\n[HOOK] telemetry sent\nTokens: 412\n",
      stderr: ""
    };
  };

  const adapter = new CliReviewAdapter({
    command: "codex",
    execFn: mockExec
  });

  const res = await adapter.executeReview({
    runId: "run-test-01",
    role: "codex-reviewer",
    policyId: "test-policy",
    changeSet: {
      ok: true,
      schemaVersion: "1.0.0",
      contentDigest: "a".repeat(64),
      repository: { root: process.cwd() },
      files: [{ path: "lib/utils.js" }],
      diffHunks: "+ Object.assign(target, source);"
    },
    timeoutMs: 5000,
    limits: { maxOutputBytes: 1024 * 1024 }
  });

  assert.equal(res.executionStatus, EXECUTION_STATUS.SUCCESS);
  assert.equal(res.findings.length, 1);
  assert.equal(res.findings[0].title, "Prototype Pollution in merge");
  assert.equal(res.findings[0].severity, "high");
});

test("test_codex_env_allowlist: scrubs non-allowlisted environment variables", async () => {
  let capturedEnv = null;
  const mockExec = async ({ env }) => {
    capturedEnv = env;
    return {
      code: 0,
      stdout: JSON.stringify({ findings: [], coverage: { coveredFiles: [], omittedFiles: [] } }),
      stderr: ""
    };
  };

  const adapter = new CliReviewAdapter({
    command: "codex",
    execFn: mockExec,
    env: {
      PATH: "C:\\Windows;C:\\bin",
      OPENAI_API_KEY: "sk-test-secret",
      HOSTILE_SECRET_TOKEN: "do-not-leak-this-secret",
      SYSTEMROOT: "C:\\Windows"
    }
  });

  await adapter.executeReview({
    runId: "run-test-env",
    role: "codex-reviewer",
    policyId: "test-policy",
    changeSet: {
      ok: true,
      schemaVersion: "1.0.0",
      contentDigest: "b".repeat(64),
      repository: { root: process.cwd() },
      files: [],
      diffHunks: ""
    },
    timeoutMs: 5000,
    limits: { maxOutputBytes: 1024 * 1024 }
  });

  assert.ok(capturedEnv);
  assert.equal(capturedEnv.PATH, "C:\\Windows;C:\\bin");
  assert.equal(capturedEnv.OPENAI_API_KEY, "sk-test-secret");
  assert.equal(capturedEnv.SYSTEMROOT, "C:\\Windows");
  assert.equal(capturedEnv.HOSTILE_SECRET_TOKEN, undefined, "Un-allowlisted variables must be scrubbed");
});
