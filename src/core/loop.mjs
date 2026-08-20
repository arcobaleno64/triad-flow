/**
 * Loop Engineering: Closed-Loop Consensus Resolution & OODA Remediation
 */

export function aggregateConsensus(macroReport = {}, microReport = {}) {
  const macroFindings = macroReport.findings || [];
  const microFindings = microReport.findings || [];

  const combined = [...macroFindings, ...microFindings];
  const deduplicated = [];
  const seen = new Set();

  for (const finding of combined) {
    const key = `${finding.file || ""}:${finding.line_start || 0}:${finding.title || ""}`.toLowerCase();
    if (!seen.has(key)) {
      seen.add(key);
      deduplicated.push(finding);
    }
  }

  const hasBlockers = deduplicated.some(f => /critical|high/i.test(f.severity || ""));
  const verdict = hasBlockers ? "needs-attention" : (deduplicated.length > 0 ? "warning" : "approve");

  return {
    verdict,
    totalFindings: deduplicated.length,
    findings: deduplicated,
    consensusProof: hasBlockers
      ? "Consensus reached: Blocking vulnerabilities identified by heterogeneous sentries."
      : "Consensus reached: Clean diff or minor non-blocking suggestions."
  };
}

export function synthesizeRemediationVector(consensusReport) {
  if (consensusReport.verdict === "approve") {
    return { needsFix: false, instructions: [], autoPatchContext: null };
  }

  const instructions = consensusReport.findings.map((f, idx) => ({
    step: idx + 1,
    targetFile: f.file,
    severity: f.severity,
    issue: f.title,
    action: f.recommendation || `Fix ${f.title} in ${f.file}`
  }));

  return {
    needsFix: true,
    summary: `Remediation required for ${instructions.length} finding(s).`,
    instructions,
    autoPatchContext: {
      criticalCount: consensusReport.findings.filter(f => /critical|high/i.test(f.severity || "")).length,
      filesToTouch: [...new Set(consensusReport.findings.map(f => f.file))]
    }
  };
}
