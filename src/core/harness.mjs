/**
 * Harness Engineering: Safety Scaffolding, Secret Redaction & SARIF Compliance
 */

import path from "node:path";

const SECRET_PATTERNS = [
  /(?:AIza[0-9A-Za-z-_]{10,})/g,                          // Google API Key
  /(?:sk-[a-zA-Z0-9]{20,})/g,                             // OpenAI Key
  /(?:ghp_[a-zA-Z0-9]{20,})/g,                             // GitHub PAT
  /(?:bearer\s+[a-zA-Z0-9_\-\.]{15,})/gi,                 // Bearer Tokens
  /(?:-----BEGIN (?:RSA )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA )?PRIVATE KEY-----)/g // Private Keys
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
  const resolved = path.resolve(workspaceRoot, targetPath);
  const rootResolved = path.resolve(workspaceRoot);
  return resolved.startsWith(rootResolved);
}

export function evaluateGateDecision(findings = [], options = {}) {
  const { strict = false } = options;
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
            informationUri: "https://github.com/arcobaleno64/triad-flow"
          }
        },
        results: findings.map(f => ({
          ruleId: f.title?.replace(/[^a-zA-Z0-9]/g, "_").toLowerCase() || "ADVERSARIAL_FINDING",
          level: /critical|high/i.test(f.severity || "") ? "error" : "warning",
          message: { text: f.body || f.summary || "Security finding reported." },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.file || "unknown" },
                region: {
                  startLine: f.line_start || 1,
                  endLine: f.line_end || f.line_start || 1
                }
              }
            }
          ]
        }))
      }
    ]
  };
}
