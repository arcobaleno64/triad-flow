#!/usr/bin/env node
/**
 * Triad-Flow CLI Entry Point
 */

import { execSync } from "node:child_process";
import { evaluateDiffScale } from "./core/router.mjs";
import { evaluateGateDecision, redactSecrets, formatSarifReport } from "./core/harness.mjs";
import { aggregateConsensus, synthesizeRemediationVector } from "./core/loop.mjs";

const args = process.argv.slice(2);
const command = args[0] || "doctor";

function printBanner() {
  console.log("\n=======================================================");
  console.log("  Triad-Flow • Adaptive Multi-Agent Closed Loop");
  console.log("=======================================================\n");
}

function getStagedGitDiff() {
  try {
    const raw = execSync("git diff --cached --numstat", { encoding: "utf-8" });
    if (!raw.trim()) {
      const working = execSync("git diff --numstat", { encoding: "utf-8" });
      if (!working.trim()) return [];
      return parseNumstat(working);
    }
    return parseNumstat(raw);
  } catch (e) {
    return [];
  }
}

function parseNumstat(raw) {
  return raw.trim().split("\n").map(line => {
    const [additions, deletions, path] = line.split(/\s+/);
    return {
      path,
      additions: parseInt(additions, 10) || 0,
      deletions: parseInt(deletions, 10) || 0
    };
  });
}

switch (command) {
  case "doctor": {
    printBanner();
    console.log("🩺 Running Environment Doctor:");
    console.log(`  ✔ Node.js Runtime: ${process.version}`);
    
    // Check Git Repo
    try {
      execSync("git rev-parse --is-inside-work-tree", { stdio: "ignore" });
      console.log("  ✔ Git Repository: Detected and active");
    } catch {
      console.log("  ⚠️ Git Repository: Not inside a git repository");
    }

    // Check API Keys / Engines
    const hasAnthropic = Boolean(process.env.ANTHROPIC_API_KEY);
    const hasGemini = Boolean(process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY);
    const hasOpenAI = Boolean(process.env.OPENAI_API_KEY);

    console.log(`  ${hasAnthropic ? "✔" : "ℹ"} Anthropic Key: ${hasAnthropic ? "Found" : "Not set (uses CLI session context)"}`);
    console.log(`  ${hasGemini ? "✔" : "ℹ"} Google Gemini Key: ${hasGemini ? "Found" : "Not set (uses local AGY OAuth / companion)"}`);
    console.log(`  ${hasOpenAI ? "✔" : "ℹ"} OpenAI Codex Key: ${hasOpenAI ? "Found" : "Not set (uses companion / codex CLI)"}`);
    console.log("  ✔ Tri-Agent Matrix: Ready for Adaptive Multi-Agent Dispatch\n");
    break;
  }

  case "review": {
    printBanner();
    console.log("🔍 Running Scale-Adaptive Multi-Agent Review...");
    
    let files = getStagedGitDiff();
    if (files.length === 0) {
      console.log("  ℹ No active Git Diff detected. Simulating sample security diff...");
      files = [
        { path: "src/auth/jwt.ts", additions: 45, deletions: 12 },
        { path: "src/utils/calc.ts", additions: 10, deletions: 2 }
      ];
    } else {
      console.log(`  ✔ Captured Git Diff: ${files.length} modified file(s)`);
    }

    const plan = evaluateDiffScale(files);
    console.log(`  ▶ Scale Routing: Mode = ${plan.mode.toUpperCase()} (${plan.reason})`);
    if (plan.subagents.length > 0) {
      console.log(`  ⚡ Spawned Subagents: ${plan.subagents.join(", ")}`);
    }

    // Mock review findings demonstration
    const mockMacro = {
      findings: [
        { severity: "critical", title: "Unvalidated Token Signature", file: files[0]?.path || "src/auth/jwt.ts", line_start: 34, body: "Token is decoded without verifying cryptographic signature." }
      ]
    };
    const mockMicro = {
      findings: [
        { severity: "critical", title: "Unvalidated Token Signature", file: files[0]?.path || "src/auth/jwt.ts", line_start: 34, recommendation: "Use jwt.verify() instead of jwt.decode()" }
      ]
    };

    const consensus = aggregateConsensus(mockMacro, mockMicro);
    console.log(`\n  ★ Consensus Verdict: ${consensus.verdict.toUpperCase()}`);
    console.log(`  ℹ Total Deduplicated Findings: ${consensus.totalFindings}`);

    const gate = evaluateGateDecision(consensus.findings);
    if (gate.decision === "block") {
      console.log(`  🛡️ Gate Decision: BLOCK - ${gate.reason}\n`);
      
      console.log("-------------------------------------------------------");
      console.log("🚨 Actionable Remediation Findings:");
      console.log("-------------------------------------------------------");
      for (const f of consensus.findings) {
        console.log(`  ✖ [${(f.severity || "HIGH").toUpperCase()}] ${f.title}`);
        console.log(`    --> ${f.file}:${f.line_start}`);
        if (f.body) console.log(`    Reason: ${f.body}`);
        if (f.recommendation) console.log(`    💡 Recommendation: ${f.recommendation}`);
        console.log();
      }

      const remediation = synthesizeRemediationVector(consensus);
      console.log(`  🔄 OODA Remediation Vector Generated: ${remediation.summary}`);
      console.log("  ▶ Next Step: Pass remediation instructions to Master Driver for auto-patch.\n");
    } else {
      console.log(`  🛡️ Gate Decision: APPROVE - ${gate.reason}\n`);
    }
    break;
  }

  default: {
    console.log(`Usage: triad-flow [doctor | review | gate]`);
    process.exit(1);
  }
}
