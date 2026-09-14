import test from "node:test";
import assert from "node:assert/strict";
import {
  probeInstalledReviewers,
  evaluateQuorumReadiness,
  isReviewerProfileReady,
  collectDoctorReport,
  formatDoctorReport,
  getFamilyDisplayName,
  QUORUM_STATUS,
  DEFAULT_PROBE_TARGETS,
  DEFAULT_PROBE_TIMEOUT_MS
} from "../src/core/doctor.mjs";

test("DEFAULT_PROBE_TARGETS and constants are frozen and specify canonical defaults", () => {
  assert.deepEqual(DEFAULT_PROBE_TARGETS, ["agy", "claude", "codex"]);
  assert.equal(DEFAULT_PROBE_TIMEOUT_MS, 1500);
  assert.equal(QUORUM_STATUS.BINARY_QUORUM_READY, "BINARY_QUORUM_READY");
  assert.equal(QUORUM_STATUS.READY, "BINARY_QUORUM_READY");
  assert.equal(QUORUM_STATUS.PARTIAL, "PARTIAL");
  assert.equal(QUORUM_STATUS.STANDALONE, "STANDALONE");
  assert.throws(() => {
    DEFAULT_PROBE_TARGETS.push("extra");
  }, TypeError);
});

test("getFamilyDisplayName correctly capitalizes known and custom provider families", () => {
  assert.equal(getFamilyDisplayName("google"), "Google");
  assert.equal(getFamilyDisplayName("anthropic"), "Anthropic");
  assert.equal(getFamilyDisplayName("openai"), "OpenAI");
  assert.equal(getFamilyDisplayName("custom_vendor"), "Custom_vendor");
  assert.equal(getFamilyDisplayName(""), "Unknown");
  assert.equal(getFamilyDisplayName(null), "Unknown");
});

test("Test 1: probeInstalledReviewers supports custom mock execFn and parses versions and profiles", () => {
  const mockExec = (cmd, args, opts) => {
    assert.deepEqual(args, ["--version"]);
    assert.equal(opts.timeout, 1500);

    if (cmd === "agy") {
      return { status: 0, stdout: "1.2.2\n", stderr: "", error: null };
    }
    if (cmd === "claude") {
      return { status: 0, stdout: "2.1.270 (Claude Code)\n", stderr: "", error: null };
    }
    if (cmd === "codex") {
      return { status: null, stdout: "", stderr: "", error: new Error("spawnSync codex ENOENT") };
    }
    return { status: 127, stdout: "", stderr: "command not found" };
  };

  const results = probeInstalledReviewers({ execFn: mockExec });

  assert.equal(results.length, 3);

  // agy
  const agy = results.find(r => r.id === "agy");
  assert.ok(agy);
  assert.equal(agy.installed, true);
  assert.equal(agy.available, true);
  assert.equal(agy.family, "google");
  assert.equal(agy.version, "1.2.2");
  assert.equal(agy.rawVersion, "1.2.2");
  assert.deepEqual(agy.readOnlyFlags, ["--mode=plan", "--disable-slash-commands"]);
  assert.equal(agy.reviewProfileReady, true);
  assert.equal(agy.profileStatus, "canonical");
  assert.ok(agy.profile);

  // claude
  const claude = results.find(r => r.id === "claude");
  assert.ok(claude);
  assert.equal(claude.installed, true);
  assert.equal(claude.available, true);
  assert.equal(claude.family, "anthropic");
  assert.equal(claude.version, "2.1.270");
  assert.equal(claude.rawVersion, "2.1.270 (Claude Code)");
  assert.deepEqual(claude.readOnlyFlags, ["--tools="]);
  assert.equal(claude.reviewProfileReady, true);
  assert.equal(claude.profileStatus, "canonical");

  // codex (not installed)
  const codex = results.find(r => r.id === "codex");
  assert.ok(codex);
  assert.equal(codex.installed, false);
  assert.equal(codex.available, false);
  assert.equal(codex.family, "openai");
  assert.equal(codex.version, null);
  assert.equal(codex.reviewProfileReady, false);
  assert.equal(codex.profileStatus, "generic");
  assert.match(codex.error, /ENOENT/);
});

test("Test 2: evaluateQuorumReadiness accurately classifies STANDALONE, PARTIAL, and READY states", () => {
  // 1. STANDALONE (0 reviewers or all unavailable)
  const resEmpty = evaluateQuorumReadiness([]);
  assert.equal(resEmpty.status, QUORUM_STATUS.STANDALONE);
  assert.equal(resEmpty.ready, false);
  assert.equal(resEmpty.canRunDualQuorum, false);
  assert.equal(resEmpty.canRunSingle, false);

  const resUnavail = evaluateQuorumReadiness([
    { id: "agy", family: "google", installed: false, available: false },
    { id: "claude", family: "anthropic", installed: false, available: false }
  ]);
  assert.equal(resUnavail.status, QUORUM_STATUS.STANDALONE);
  assert.equal(resUnavail.ready, false);

  // 2. PARTIAL (1 vendor family)
  const resSingle = evaluateQuorumReadiness([
    { id: "agy", family: "google", installed: true, available: true }
  ]);
  assert.equal(resSingle.status, QUORUM_STATUS.PARTIAL);
  assert.equal(resSingle.ready, false);
  assert.equal(resSingle.canRunDualQuorum, false);
  assert.equal(resSingle.canRunSingle, true);
  assert.deepEqual(resSingle.families, ["google"]);
  assert.deepEqual(resSingle.familyNames, ["Google"]);
  assert.equal(resSingle.summary, "PARTIAL (Google)");
  assert.ok(resSingle.note, "PARTIAL status must include version check note");

  // Same-family collision (e.g. two tools belonging to Google) must NOT satisfy Heterogeneous Quorum
  const resSameFamily = evaluateQuorumReadiness([
    { id: "agy", family: "google", installed: true, available: true },
    { id: "gemini-cli", family: "google", installed: true, available: true }
  ]);
  assert.equal(resSameFamily.status, QUORUM_STATUS.PARTIAL);
  assert.equal(resSameFamily.ready, false);
  assert.equal(resSameFamily.canRunDualQuorum, false);
  assert.deepEqual(resSameFamily.families, ["google"]);

  // 3. READY (>= 2 distinct vendor families: Google + Anthropic)
  const resDual = evaluateQuorumReadiness([
    { id: "agy", family: "google", installed: true, available: true },
    { id: "claude", family: "anthropic", installed: true, available: true },
    { id: "codex", family: "openai", installed: false, available: false }
  ]);
  assert.equal(resDual.status, QUORUM_STATUS.BINARY_QUORUM_READY);
  assert.equal(resDual.ready, true);
  assert.equal(resDual.stage, "PROFILED");
  assert.equal(resDual.canRunDualQuorum, true);
  assert.equal(resDual.canRunSingle, true);
  assert.deepEqual(resDual.families, ["google", "anthropic"]);
  assert.deepEqual(resDual.familyNames, ["Google", "Anthropic"]);
  assert.equal(resDual.summary, "BINARY_QUORUM_READY (Google + Anthropic)");

  // 4. Generic fallback profile (e.g. Codex) does NOT count toward dual quorum
  const resAgyCodex = evaluateQuorumReadiness([
    { id: "agy", family: "google", installed: true, available: true },
    { id: "codex", family: "openai", installed: true, available: true }
  ]);
  assert.equal(resAgyCodex.status, QUORUM_STATUS.PARTIAL);
  assert.equal(resAgyCodex.ready, false);
  assert.equal(resAgyCodex.canRunDualQuorum, false);
  assert.equal(resAgyCodex.canRunSingle, true);
  assert.deepEqual(resAgyCodex.families, ["google"]);

  // 5. Dual quorum satisfied by canonical profiles (agy + claude) even if generic Codex is also present
  const resTripleWithGeneric = evaluateQuorumReadiness([
    { id: "agy", family: "google", installed: true, available: true },
    { id: "claude", family: "anthropic", installed: true, available: true },
    { id: "codex", family: "openai", installed: true, available: true }
  ]);
  assert.equal(resTripleWithGeneric.status, QUORUM_STATUS.BINARY_QUORUM_READY);
  assert.equal(resTripleWithGeneric.ready, true);
  assert.equal(resTripleWithGeneric.canRunDualQuorum, true);
  assert.deepEqual(resTripleWithGeneric.families, ["google", "anthropic"]);
  assert.equal(resTripleWithGeneric.summary, "BINARY_QUORUM_READY (Google + Anthropic)");

  // 6. READY with 3 distinct families when all 3 have reviewProfileReady: true
  const resTripleCanonical = evaluateQuorumReadiness([
    { id: "agy", family: "google", installed: true, available: true, reviewProfileReady: true },
    { id: "claude", family: "anthropic", installed: true, available: true, reviewProfileReady: true },
    { id: "custom-openai", family: "openai", installed: true, available: true, reviewProfileReady: true }
  ]);
  assert.equal(resTripleCanonical.status, QUORUM_STATUS.BINARY_QUORUM_READY);
  assert.equal(resTripleCanonical.ready, true);
  assert.equal(resTripleCanonical.stage, "PROFILED");
  assert.deepEqual(resTripleCanonical.families, ["google", "anthropic", "openai"]);
  assert.equal(resTripleCanonical.summary, "BINARY_QUORUM_READY (Google + Anthropic + OpenAI)");

  // 7. Generic-only reviewer (e.g. only Codex active) results in STANDALONE while retaining activeReviewers
  const resCodexOnly = evaluateQuorumReadiness([
    { id: "codex", family: "openai", installed: true, available: true }
  ]);
  assert.equal(resCodexOnly.status, QUORUM_STATUS.STANDALONE);
  assert.equal(resCodexOnly.ready, false);
  assert.equal(resCodexOnly.canRunDualQuorum, false);
  assert.equal(resCodexOnly.canRunSingle, false);
  assert.deepEqual(resCodexOnly.activeReviewers, ["codex"]);
  assert.deepEqual(resCodexOnly.families, []);

  // 8. isReviewerProfileReady accurately evaluates canonical vs generic profiles
  assert.equal(isReviewerProfileReady({ id: "agy" }), true);
  assert.equal(isReviewerProfileReady({ id: "claude" }), true);
  assert.equal(isReviewerProfileReady({ id: "codex" }), false);
  assert.equal(isReviewerProfileReady({ id: "custom", reviewProfileReady: true }), true);
  assert.equal(isReviewerProfileReady({ id: "custom", reviewProfileReady: false }), false);
});

test("Test 3: collectDoctorReport gathers all required capability fields deterministically offline", () => {
  const mockGit = {
    ok: true,
    repository: { currentBranch: "feature/doctor-upgrade", root: "/mock/repo" }
  };
  const mockEnv = {
    ANTHROPIC_API_KEY: "mock-anthropic-key",
    GEMINI_API_KEY: "",
    OPENAI_API_KEY: ""
  };
  const mockExec = (cmd) => {
    if (cmd === "agy") return { status: 0, stdout: "1.2.2" };
    return { status: -1, error: new Error("not found") };
  };

  const report = collectDoctorReport({
    getGitState: () => mockGit,
    env: mockEnv,
    execFn: mockExec,
    timestamp: "2026-09-13T12:00:00.000Z"
  });

  assert.equal(report.schemaVersion, "1.0.0");
  assert.equal(report.timestamp, "2026-09-13T12:00:00.000Z");

  // runtime
  assert.ok(report.runtime.nodeVersion);
  assert.ok(report.runtime.platform);
  assert.ok(report.runtime.arch);

  // git
  assert.equal(report.git.ok, true);
  assert.equal(report.git.currentBranch, "feature/doctor-upgrade");
  assert.equal(report.git.root, "/mock/repo");
  assert.equal(report.git.error, null);

  // safetyCore
  assert.equal(report.safetyCore.loaded, true);
  assert.equal(report.safetyCore.status, "active");
  assert.deepEqual(report.safetyCore.components, ["Harness", "Loop", "Graph"]);

  // reviewers & quorum
  assert.equal(report.reviewers.length, 3);
  assert.equal(report.quorum.status, QUORUM_STATUS.PARTIAL);

  // envKeys
  assert.equal(report.envKeys.anthropic, true);
  assert.equal(report.envKeys.gemini, false);
  assert.equal(report.envKeys.openai, false);
});

test("Test 4: formatDoctorReport formats clean JSON and text reports with checkmarks", () => {
  const sampleReport = {
    schemaVersion: "1.0.0",
    timestamp: "2026-09-13T12:00:00.000Z",
    runtime: { nodeVersion: "v24.14.1", platform: "win32", arch: "x64" },
    git: { ok: true, currentBranch: "main", root: "/repo", error: null },
    safetyCore: { loaded: true, components: ["Harness", "Loop", "Graph"] },
    reviewers: [
      {
        id: "agy",
        command: "agy",
        family: "google",
        installed: true,
        available: true,
        version: "1.2.2",
        readOnlyFlags: ["--mode=plan", "--disable-slash-commands"]
      },
      {
        id: "claude",
        command: "claude",
        family: "anthropic",
        installed: true,
        available: true,
        version: "2.1.270",
        readOnlyFlags: ["--tools="]
      },
      {
        id: "codex",
        command: "codex",
        family: "openai",
        installed: false,
        available: false,
        version: null,
        readOnlyFlags: []
      }
    ],
    quorum: {
      status: "BINARY_QUORUM_READY",
      ready: true,
      stage: "PROFILED",
      families: ["google", "anthropic"],
      familyNames: ["Google", "Anthropic"],
      summary: "BINARY_QUORUM_READY (Google + Anthropic)"
    },
    envKeys: {
      anthropic: true,
      gemini: false,
      openai: false
    }
  };

  // 1. JSON format
  const jsonStr = formatDoctorReport(sampleReport, "json");
  const parsed = JSON.parse(jsonStr);
  assert.equal(parsed.schemaVersion, "1.0.0");
  assert.equal(parsed.quorum.status, "BINARY_QUORUM_READY");
  assert.equal(parsed.reviewers.length, 3);

  // 2. Text format
  const textStr = formatDoctorReport(sampleReport, "text");
  assert.match(textStr, /Triad-Flow • Environment & Capability Doctor/);
  assert.match(textStr, /Node\.js Runtime: v24\.14\.1/);
  assert.match(textStr, /✔ Git Repository: Detected and active/);
  assert.match(textStr, /✔ Deterministic Safety Core: Loaded \(Harness \+ Loop \+ Graph\)/);
  assert.match(textStr, /✔ Google agy: v1\.2\.2 \(Profile: read-only \[--mode=plan, --disable-slash-commands\]\)/);
  assert.match(textStr, /✔ Anthropic claude: v2\.1\.270 \(Profile: read-only \[--tools=\]\)/);
  assert.match(textStr, /⚠️ OpenAI codex: Not detected \/ Inactive/);
  assert.match(textStr, /✔ Heterogeneous Quorum: BINARY_QUORUM_READY \(Google \+ Anthropic\)/);
  assert.match(textStr, /version check only; operational review readiness requires authenticated probe/);
  assert.match(textStr, /ℹ Anthropic Key: Configured/);
  assert.match(textStr, /ℹ Google Gemini Key: Unset/);
});

test("Test 5: probeInstalledReviewers fail-safe handling of timeouts and throwing execFn", () => {
  // 1. Timeout simulation
  const timeoutExec = () => ({
    status: null,
    signal: "SIGTERM",
    error: new Error("Process timed out after 1500ms")
  });
  const timeoutRes = probeInstalledReviewers({ execFn: timeoutExec });
  assert.equal(timeoutRes[0].installed, false);
  assert.equal(timeoutRes[0].available, false);
  assert.match(timeoutRes[0].error, /timed out/i);

  // 2. Throwing execFn (catastrophic failure must not crash doctor)
  const throwExec = () => {
    throw new Error("Unexpected synchronous I/O crash");
  };
  const throwRes = probeInstalledReviewers({ execFn: throwExec });
  assert.equal(throwRes[0].installed, false);
  assert.equal(throwRes[0].available, false);
  assert.match(throwRes[0].error, /Unexpected synchronous I\/O crash/);
});

test("formatDoctorReport handles unreadable Git state and PARTIAL quorum in text mode", () => {
  const unreadableGitReport = {
    runtime: { nodeVersion: "v24.14.1" },
    git: { ok: false, error: "fatal: not a git repository" },
    safetyCore: { loaded: true, components: ["Harness", "Loop", "Graph"] },
    reviewers: [
      { id: "agy", command: "agy", family: "google", installed: true, version: "1.2.2", readOnlyFlags: [] }
    ],
    quorum: { status: "PARTIAL", summary: "PARTIAL (Google)" },
    envKeys: { anthropic: false, gemini: false, openai: false }
  };

  const textStr = formatDoctorReport(unreadableGitReport, "text");
  assert.match(textStr, /⚠️ Git Repository: Not detected or unreadable \(fatal: not a git repository\)/);
  assert.match(textStr, /⚠️ Heterogeneous Quorum: PARTIAL \(Google\)/);
});

test("Test 6: evaluateQuorumReadiness normalizes family casing and blocks same-family collisions", () => {
  const resMixedCase = evaluateQuorumReadiness([
    { id: "gemini", family: "Google", installed: true, available: true },
    { id: "agy", family: "google", installed: true, available: true }
  ]);
  assert.equal(resMixedCase.status, QUORUM_STATUS.PARTIAL);
  assert.equal(resMixedCase.ready, false);
  assert.equal(resMixedCase.canRunDualQuorum, false);
  assert.deepEqual(resMixedCase.families, ["google"]);
  assert.deepEqual(resMixedCase.familyNames, ["Google"]);
});

test("Test 7: evaluateQuorumReadiness excludes reviewers where available is false despite installed true", () => {
  const res = evaluateQuorumReadiness([
    { id: "agy", family: "google", installed: true, available: true },
    { id: "claude", family: "anthropic", installed: true, available: false }
  ]);
  assert.equal(res.status, QUORUM_STATUS.PARTIAL);
  assert.equal(res.ready, false);
  assert.deepEqual(res.families, ["google"]);
});

test("Test 8: probeInstalledReviewers rejects targets with shell metacharacters", () => {
  const results = probeInstalledReviewers({ reviewers: ["agy; whoami", "claude | dir"] });
  assert.equal(results.length, 2);
  assert.equal(results[0].installed, false);
  assert.match(results[0].error, /unsafe characters/);
  assert.equal(results[1].installed, false);
  assert.match(results[1].error, /unsafe characters/);
});

test("Test 9: collectDoctorReport correctly preserves string git error", () => {
  const report = collectDoctorReport({
    getGitState: () => ({ ok: false, error: "fatal: not a git repo" }),
    execFn: () => ({ status: 0, stdout: "1.0.0" })
  });
  assert.equal(report.git.ok, false);
  assert.equal(report.git.error, "fatal: not a git repo");
});

test("Test 10: formatDoctorReport safely handles null/empty reports without throwing", () => {
  const textNull = formatDoctorReport(null);
  assert.match(textNull, /Triad-Flow • Environment & Capability Doctor/);
  assert.match(textNull, /No external reviewers probed/);

  const jsonNull = formatDoctorReport(null, "json");
  assert.equal(jsonNull.trim(), "null");

  const textEmpty = formatDoctorReport({});
  assert.match(textEmpty, /Triad-Flow • Environment & Capability Doctor/);
});

