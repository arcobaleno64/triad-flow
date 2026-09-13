import test from "node:test";
import assert from "node:assert/strict";
import {
  PROVIDER_PROFILES,
  SAFE_ARGV_THRESHOLD_BYTES,
  resolveProviderProfile,
  assembleProviderArgs
} from "../src/adapters/provider-profiles.mjs";
import { CliReviewAdapter } from "../src/adapters/cli-transport.mjs";
import { EXECUTION_STATUS } from "../src/adapters/provider-contract.mjs";

test("PROVIDER_PROFILES specifies frozen canonical profiles for agy and claude", () => {
  assert.ok(PROVIDER_PROFILES.agy, "agy profile must exist");
  assert.equal(PROVIDER_PROFILES.agy.id, "agy");
  assert.equal(PROVIDER_PROFILES.agy.family, "google");
  assert.equal(PROVIDER_PROFILES.agy.inputChannel, "argv");
  assert.equal(PROVIDER_PROFILES.agy.supportsStdin, false);
  assert.deepEqual(PROVIDER_PROFILES.agy.readOnlyFlags, ["--mode=plan", "--disable-slash-commands"]);
  assert.deepEqual(PROVIDER_PROFILES.agy.args, ["--mode=plan", "--disable-slash-commands", "--print"]);

  assert.ok(PROVIDER_PROFILES.claude, "claude profile must exist");
  assert.equal(PROVIDER_PROFILES.claude.id, "claude");
  assert.equal(PROVIDER_PROFILES.claude.family, "anthropic");
  assert.equal(PROVIDER_PROFILES.claude.supportsStdin, true);
  assert.deepEqual(PROVIDER_PROFILES.claude.readOnlyFlags, ["--tools="]);
  assert.deepEqual(PROVIDER_PROFILES.claude.args, ["-p", "--tools="]);

  // Immutability checks
  assert.throws(() => {
    PROVIDER_PROFILES.agy.args.push("--mutated");
  }, TypeError);
  assert.throws(() => {
    PROVIDER_PROFILES.agy.readOnlyFlags.push("--mutated");
  }, TypeError);
  assert.throws(() => {
    PROVIDER_PROFILES.claude.args.push("--mutated");
  }, TypeError);
});

test("SAFE_ARGV_THRESHOLD_BYTES guarantees Windows CreateProcess safety", () => {
  if (process.platform === "win32") {
    assert.equal(SAFE_ARGV_THRESHOLD_BYTES, 8 * 1024);
    assert.ok(SAFE_ARGV_THRESHOLD_BYTES < 32767, "Must be strictly below Windows lpCommandLine limit");
  } else {
    assert.equal(SAFE_ARGV_THRESHOLD_BYTES, 64 * 1024);
  }
});

test("resolveProviderProfile handles null, undefined, empty, and exact binary names", () => {
  // 1. Defaults
  const def1 = resolveProviderProfile();
  assert.equal(def1.id, "agy");
  assert.equal(def1.family, "google");

  const def2 = resolveProviderProfile("");
  assert.equal(def2.id, "agy");

  const def3 = resolveProviderProfile(null);
  assert.equal(def3.id, "agy");

  // 2. Exact agy and path variations
  const agy1 = resolveProviderProfile("agy");
  assert.equal(agy1.id, "agy");
  assert.equal(agy1.family, "google");
  assert.equal(agy1.supportsStdin, false);

  const agy2 = resolveProviderProfile("C:\\Users\\test\\AppData\\Local\\agy\\bin\\agy.exe");
  assert.equal(agy2.id, "agy");
  assert.equal(agy2.family, "google");

  // 3. Exact claude and path variations
  const claude1 = resolveProviderProfile("claude");
  assert.equal(claude1.id, "claude");
  assert.equal(claude1.family, "anthropic");
  assert.equal(claude1.supportsStdin, true);

  const claude2 = resolveProviderProfile("claude.exe");
  assert.equal(claude2.id, "claude");

  // 4. Token boundary matching vs non-matching
  const wrappedAgy = resolveProviderProfile("my-agy-runner");
  assert.equal(wrappedAgy.id, "agy");

  const legacyScan = resolveProviderProfile("legacy-scan");
  assert.notEqual(legacyScan.id, "agy", "legacy-scan must NOT match agy profile");
  assert.equal(legacyScan.id, "legacy-scan");

  // 5. Array cloning ensures profile cannot be corrupted by mutations
  const p1 = resolveProviderProfile("agy");
  p1.args.push("--tampered");
  const p2 = resolveProviderProfile("agy");
  assert.equal(p2.args.includes("--tampered"), false, "resolveProviderProfile must return fresh args clone");
});

test("CliReviewAdapter resolves canonical profile and respects family and read-only defaults", () => {
  const agyAdapter = new CliReviewAdapter({ command: "agy" });
  assert.equal(agyAdapter.providerName, "agy");
  assert.equal(agyAdapter.family, "google");
  assert.equal(agyAdapter.supportsStdin, false);
  assert.deepEqual(agyAdapter.args, ["--mode=plan", "--disable-slash-commands", "--print"]);

  const claudeAdapter = new CliReviewAdapter({ command: "claude" });
  assert.equal(claudeAdapter.providerName, "claude");
  assert.equal(claudeAdapter.family, "anthropic");
  assert.equal(claudeAdapter.supportsStdin, true);
  assert.deepEqual(claudeAdapter.args, ["-p", "--tools="]);
});

test("CliReviewAdapter fails closed when stdin requested for argv-only provider", async () => {
  const cs = {
    ok: true,
    schemaVersion: "1.0.0",
    scopeMode: "working-tree",
    repository: { root: "/repo", hasHead: true, currentBranch: "main" },
    contentDigest: "a".repeat(64),
    totalFiles: 1,
    files: [{ path: "test.js", additions: 1, deletions: 0 }],
    diffHunks: "+ const a = 1;"
  };

  const adapter = new CliReviewAdapter({ command: "agy", useStdin: true });
  const res = await adapter.executeReview({
    runId: "r-stdin-guard",
    role: "macro",
    changeSet: cs,
    policyId: "SINGLE_SENTRY",
    timeoutMs: 5000,
    limits: { maxInputBytes: 100000, maxOutputBytes: 100000, defaultTimeoutMs: 5000 }
  });

  assert.equal(res.ok, false);
  assert.equal(res.executionStatus, EXECUTION_STATUS.ERROR);
  assert.match(res.error, /operates strictly via argv/i);
});

test("assembleProviderArgs enforces mandatory safety flags and blocks override attempts", () => {
  const agyProfile = resolveProviderProfile("agy");
  const claudeProfile = resolveProviderProfile("claude");

  // 1. Default without user args
  assert.deepEqual(assembleProviderArgs(agyProfile), ["--mode=plan", "--disable-slash-commands", "--print"]);
  assert.deepEqual(assembleProviderArgs(claudeProfile), ["-p", "--tools="]);

  // 2. Empty user args cannot strip mandatory flags
  assert.deepEqual(assembleProviderArgs(agyProfile, []), ["--mode=plan", "--disable-slash-commands", "--print"]);
  assert.deepEqual(assembleProviderArgs(claudeProfile, []), ["-p", "--tools="]);

  // 3. Augmenting with safe user args preserves mandatory flags
  const augmentedAgy = assembleProviderArgs(agyProfile, ["--verbose", "--custom=123"]);
  assert.ok(augmentedAgy.includes("--mode=plan"));
  assert.ok(augmentedAgy.includes("--disable-slash-commands"));
  assert.ok(augmentedAgy.includes("--print"));
  assert.ok(augmentedAgy.includes("--verbose"));
  assert.ok(augmentedAgy.includes("--custom=123"));

  // 4. Hostile override attempts (e.g. --mode=accept-edits or --tools=bash) are neutralized
  const hostileAgy = assembleProviderArgs(agyProfile, ["--mode=accept-edits", "--danger"]);
  assert.ok(hostileAgy.includes("--mode=plan"));
  assert.ok(!hostileAgy.includes("--mode=accept-edits"));
  assert.ok(hostileAgy.includes("--danger"));

  const hostileClaude = assembleProviderArgs(claudeProfile, ["--tools=bash,write_file"]);
  assert.ok(hostileClaude.includes("--tools="));
  assert.ok(!hostileClaude.includes("--tools=bash,write_file"));

  // 5. Space-separated token override attempts (e.g. --mode code, --tools bash) are neutralized
  const tokenHostileAgy = assembleProviderArgs(agyProfile, ["--mode", "code", "--other-safe"]);
  assert.ok(tokenHostileAgy.includes("--mode=plan"));
  assert.ok(!tokenHostileAgy.includes("--mode"));
  assert.ok(!tokenHostileAgy.includes("code"));
  assert.ok(tokenHostileAgy.includes("--other-safe"));

  const tokenHostileClaude = assembleProviderArgs(claudeProfile, ["--tools", "bash", "--safe-arg"]);
  assert.ok(tokenHostileClaude.includes("--tools="));
  assert.ok(!tokenHostileClaude.includes("--tools"));
  assert.ok(!tokenHostileClaude.includes("bash"));
  assert.ok(tokenHostileClaude.includes("--safe-arg"));

  // 6. CliReviewAdapter applies assembleProviderArgs automatically
  const safeAdapter = new CliReviewAdapter({ command: "agy", args: ["--custom-arg"] });
  assert.ok(safeAdapter.args.includes("--mode=plan"));
  assert.ok(safeAdapter.args.includes("--disable-slash-commands"));
  assert.ok(safeAdapter.args.includes("--custom-arg"));
});

test("CliReviewAdapter fails closed when configured with non-existent working directory (cwd)", async () => {
  const adapter = new CliReviewAdapter({
    command: "agy",
    cwd: "C:\\nonexistent_workspace_path_triad_test"
  });

  const res = await adapter.executeReview({
    runId: "test-cwd-fail",
    role: "macro",
    policyId: "SINGLE_SENTRY",
    changeSet: {
      ok: true,
      schemaVersion: "1.0.0",
      contentDigest: "b".repeat(64),
      files: [{ path: "sample.js", additions: 1, deletions: 0 }]
    }
  });

  assert.equal(res.ok, false);
  assert.equal(res.executionStatus, EXECUTION_STATUS.ERROR);
  assert.match(res.error, /Configured working directory \(cwd\) does not exist/);
});
