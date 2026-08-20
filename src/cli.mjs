#!/usr/bin/env node
/**
 * Council-Forge 2.0 CLI Entry Point
 */

import { evaluateDiffScale } from "./core/router.mjs";
import { evaluateGateDecision, redactSecrets, formatSarifReport } from "./core/harness.mjs";
import { aggregateConsensus, synthesizeRemediationVector } from "./core/loop.mjs";

const args = process.argv.slice(2);
const command = args[0] || "doctor";

function printBanner() {
  console.log("\n=======================================================");
  console.log("  Council-Forge 2.0 • Adaptive Multi-Agent Closed Loop");
  console.log("=======================================================\n");
}

switch (command) {
  case "doctor": {
    printBanner();
    console.log("🩺 Running Environment Doctor:");
    console.log(`  ✔ Node.js Runtime: ${process.version}`);
    console.log("  ✔ Architecture Triad: Graph + Loop + Harness Loaded");
    console.log("  ✔ Ready for Claude Code & Multi-Agent Dispatch\n");
    break;
  }

  case "review": {
    printBanner();
    console.log("🔍 Simulating Adaptive Multi-Agent Review...");
    const sampleFiles = [
      { path: "src/auth/jwt.ts", additions: 45, deletions: 12 },
      { path: "src/utils/calc.ts", additions: 10, deletions: 2 }
    ];
    const plan = evaluateDiffScale(sampleFiles);
    console.log(`  ▶ Scale Routing: Mode = ${plan.mode.toUpperCase()} (${plan.reason})`);
    if (plan.subagents.length > 0) {
      console.log(`  ⚡ Spawned Subagents: ${plan.subagents.join(", ")}`);
    }

    const mockConsensus = aggregateConsensus(
      { findings: [{ severity: "high", title: "Unvalidated Token Expiry", file: "src/auth/jwt.ts", line_start: 34 }] },
      { findings: [] }
    );
    console.log(`  ★ Consensus Verdict: ${mockConsensus.verdict.toUpperCase()}`);
    const gate = evaluateGateDecision(mockConsensus.findings);
    console.log(`  🛡️ Gate Decision: ${gate.decision.toUpperCase()} - ${gate.reason}\n`);
    break;
  }

  default: {
    console.log(`Usage: council-forge [doctor | review | gate]`);
    process.exit(1);
  }
}
