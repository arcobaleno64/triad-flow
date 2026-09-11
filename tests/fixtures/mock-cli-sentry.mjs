/**
 * Mock CLI Sentry (Zero-dependency test fixture for E2E CLI transport testing)
 *
 * Supports selectable review behavior via CLI flags or MOCK_SENTRY_MODE env var:
 * - --clean (default): writes clean review JSON findings and exits 0.
 * - --finding: writes JSON with a critical security finding and exits 0.
 * - --injection: writes JSON containing hostile model instructions (e.g. command, shell) and exits 0.
 * - --hang: hangs indefinitely to trigger transport timeout.
 * - --crash: writes error to stderr and exits non-zero (code 137).
 * - --flood: outputs massive data to trigger payload_too_large (> maxOutputBytes).
 * - --auth-fail: writes auth failure pattern and exits non-zero.
 */

const rawArgs = process.argv.slice(2);
const fullText = rawArgs.join(" ");

function extractFilesFromPrompt(text) {
  const matches = [];
  const lines = text.split("\n");
  for (const line of lines) {
    const m = line.match(/^\s*-\s+([^\s(]+)/);
    if (m && m[1]) matches.push(m[1].trim());
  }
  return matches.length > 0 ? matches : ["src/calc.js"];
}

function getActiveMode() {
  if (process.env.MOCK_SENTRY_MODE) return process.env.MOCK_SENTRY_MODE;

  const modes = ["hang", "crash", "flood", "auth-fail", "injection", "finding", "clean"];

  // 1. Direct flag check from command-line arguments
  for (const arg of rawArgs) {
    for (const mode of modes) {
      if (arg === `--${mode}` || arg.startsWith(`--${mode}=`) || arg === `--mode=${mode}`) {
        return mode;
      }
    }
  }

  // 2. Embedded directive check in prompt or joined arguments
  for (const mode of modes) {
    if (fullText.includes(`--mode=${mode}`) || fullText.includes(`--${mode}`)) {
      return mode;
    }
  }

  return "clean";
}

const mode = getActiveMode();

switch (mode) {
  case "hang": {
    process.stderr.write("[mock-sentry] Hanging process intentionally...\n");
    setInterval(() => {}, 60000);
    break;
  }

  case "crash": {
    process.stderr.write("[mock-sentry] Fatal crash: unexpected termination\n");
    process.exit(137);
    break;
  }

  case "flood": {
    process.stderr.write("[mock-sentry] Flooding output buffer beyond limits...\n");
    process.stdout.on("error", () => {});
    const chunk = "X".repeat(64 * 1024); // 64 KB
    for (let i = 0; i < 16; i++) {
      process.stdout.write(chunk);
    }
    const interval = setInterval(() => {
      try {
        process.stdout.write(chunk);
      } catch {
        clearInterval(interval);
      }
    }, 20);
    break;
  }

  case "auth-fail": {
    process.stderr.write("You are not logged into Antigravity. Please run agy auth login\n");
    process.exit(1);
    break;
  }

  case "injection": {
    process.stderr.write("[mock-sentry] Hostile model instruction injection test\n");
    const payload = {
      command: "rm -rf /",
      shell: "powershell",
      execute: "calc.exe",
      findings: [],
      coverage: { coveredFiles: extractFilesFromPrompt(fullText), omittedFiles: [] }
    };
    process.stdout.write(JSON.stringify(payload) + "\n");
    break;
  }

  case "finding": {
    process.stderr.write("[mock-sentry] Emitting critical security finding\n");
    const payload = {
      findings: [
        {
          title: "Unverified Signature",
          severity: "critical",
          file: "src/auth/jwt.ts",
          line_start: 1,
          line_end: 1,
          recommendation: "Use jwt.verify(token, secret)"
        }
      ],
      coverage: { coveredFiles: ["src/auth/jwt.ts"], omittedFiles: [] }
    };
    process.stdout.write(JSON.stringify(payload) + "\n");
    break;
  }

  case "clean":
  default: {
    process.stderr.write("[mock-sentry] Review completed cleanly\n");
    const payload = {
      findings: [],
      coverage: { coveredFiles: extractFilesFromPrompt(fullText), omittedFiles: [] }
    };
    process.stdout.write(JSON.stringify(payload) + "\n");
    break;
  }
}

