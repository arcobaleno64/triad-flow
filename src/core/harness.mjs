/**
 * Hardened Harness Engineering: Safety Scaffolding, Secret Redaction & SARIF Compliance
 */

import path from "node:path";

export const SECRET_PATTERNS = [
  // Google API Keys (AIza followed by 20 to 45 chars)
  /\bAIza[0-9A-Za-z-_]{20,45}\b/g,
  // OpenAI Keys (Legacy sk-, Project sk-proj-, Admin sk-admin-)
  /\bsk-(?:proj-|admin-)?[a-zA-Z0-9_\-]{20,}\b/g,
  // Anthropic Keys
  /\bsk-ant-[a-zA-Z0-9_\-]{20,}\b/g,
  // GitHub Tokens (Classic ghp_, Fine-grained github_pat_, OAuth gho_, Server ghs_, etc.)
  /\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}\b/g,
  /\bgithub_pat_[a-zA-Z0-9_]{50,}\b/g,
  // AWS Access Key ID
  /\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/g,
  // JWT Tokens (Both Bearer-prefixed and standalone raw JWTs)
  /\b(?:bearer\s+)?eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\b/gi,
  // PEM Private Keys (RSA, EC, OPENSSH, DSA, ENCRYPTED, PKCS#8)
  /-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY(?: BLOCK)?-----[\s\S]+?-----END (?:[A-Z0-9_-]+ )?PRIVATE KEY(?: BLOCK)?-----/g
];

export function redactSecrets(text = "") {
  if (typeof text !== "string") return text;
  let sanitized = text;
  for (const pattern of SECRET_PATTERNS) {
    sanitized = sanitized.replace(pattern, "[REDACTED_SECRET]");
  }
  return sanitized;
}

export function isPathSafe(targetPath, workspaceRoot) {
  if (typeof targetPath !== "string" || typeof workspaceRoot !== "string") return false;
  if (targetPath.includes("\0") || workspaceRoot.includes("\0")) return false;

  const rootResolved = path.resolve(workspaceRoot);
  const resolved = path.resolve(rootResolved, targetPath);

  const rel = path.relative(rootResolved, resolved);
  const isWin = process.platform === "win32";
  const relNorm = isWin ? rel.toLowerCase() : rel;

  // Sibling folder escape & traversal check
  if (relNorm.startsWith(".." + path.sep) || relNorm === ".." || path.isAbsolute(rel)) {
    return false;
  }

  const normalizedRoot = rootResolved.endsWith(path.sep) ? rootResolved : rootResolved + path.sep;
  const isInside = isWin
    ? (resolved + path.sep).toLowerCase().startsWith(normalizedRoot.toLowerCase()) || resolved.toLowerCase() === rootResolved.toLowerCase()
    : (resolved + path.sep).startsWith(normalizedRoot) || resolved === rootResolved;

  return isInside;
}

export function evaluateGateDecision(findings = [], options = {}) {
  const { strict = false, sentryHealth = { quorumReached: true } } = options;

  // Fail-Closed on Quorum Failure
  if (!sentryHealth.quorumReached) {
    return {
      decision: "block",
      reason: "Quorum Failure: Sentries encountered errors or timeouts. Fail-closed enforced.",
      criticals: []
    };
  }

  const criticals = findings.filter(f => /critical|high/i.test(f.severity || ""));

  if (criticals.length > 0) {
    return {
      decision: "block",
      reason: `Found ${criticals.length} critical/high severity findings. Merge blocked.`,
      criticals
    };
  }

  if (findings.length > 0 && strict) {
    return {
      decision: "block",
      reason: `Strict mode enabled: ${findings.length} findings must be resolved.`,
      criticals: []
    };
  }

  return {
    decision: "approve",
    reason: "No blocking vulnerabilities found. CI/CD Gate passed.",
    criticals: []
  };
}

function sanitizeText(str) {
  if (typeof str !== "string") return "";
  return str
    .replace(/\u001b\[[0-9;]*[a-zA-Z]/g, "") // Strip ANSI escape codes
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, ""); // Strip control characters
}

function sanitizeUri(uri) {
  if (typeof uri !== "string") return "unknown";
  const clean = uri.trim().replace(/\\/g, "/");
  // Reject dangerous URI schemes
  if (/^(?:javascript|data|vbscript|file):/i.test(clean)) {
    return "invalid-uri-scheme";
  }
  return clean.replace(/^[\/\\]+/, "");
}

export function formatSarifReport(findings = [], metadata = {}) {
  return {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Triad-Flow Sentry",
            version: "2.0.0",
            informationUri: "https://github.com/arcobaleno64/triad-flow",
            rules: findings.map(f => ({
              id: (f.title || "ADVERSARIAL_FINDING").replace(/[^a-zA-Z0-9]/g, "_").toLowerCase(),
              shortDescription: { text: sanitizeText(f.title || "Adversarial Finding") }
            }))
          }
        },
        results: findings.map(f => {
          const title = sanitizeText(String(f?.title || "Security Finding"));
          const body = sanitizeText(String(f?.body || f?.summary || "Security finding reported."));
          const startLine = Math.max(1, Math.floor(Number(f?.line_start) || 1));
          const endLine = Math.max(startLine, Math.floor(Number(f?.line_end) || startLine));
          const uri = sanitizeUri(f?.file);

          return {
            ruleId: title.replace(/[^a-zA-Z0-9]/g, "_").toLowerCase() || "ADVERSARIAL_FINDING",
            level: /critical|high/i.test(String(f?.severity || "")) ? "error" : "warning",
            message: { text: body },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri },
                  region: {
                    startLine,
                    endLine
                  }
                }
              }
            ]
          };
        })
      }
    ]
  };
}
