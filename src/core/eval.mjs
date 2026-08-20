/**
 * Eval & Benchmark Engineering: Ultra-Lean Verification & Mutation Scoring
 */

export function calculateMutationScore(totalMutants = 0, killedMutants = 0) {
  if (totalMutants <= 0) return 100.0;
  return parseFloat(((killedMutants / totalMutants) * 100).toFixed(1));
}

export function verifyHeldOutBaseline(actualFindings = [], goldenVulnerabilities = []) {
  const caught = new Set();
  for (const golden of goldenVulnerabilities) {
    const gFile = (golden.file || "").toLowerCase().trim();
    const gCwe = (golden.cwe || "").toLowerCase().trim();
    const gType = (golden.type || "").toLowerCase().trim();

    const matched = actualFindings.some(f => {
      const fFile = (f.file || "").toLowerCase();
      const fTitle = (f.title || "").toLowerCase();

      const fileMatch = gFile ? fFile.includes(gFile) : false;
      const cweMatch = gCwe ? fTitle.includes(gCwe) : false;
      const typeMatch = gType ? fTitle.includes(gType) : false;

      return (fileMatch && (cweMatch || typeMatch)) || (cweMatch || typeMatch);
    });

    if (matched) caught.add(golden.id || golden.type);
  }

  const recall = goldenVulnerabilities.length > 0
    ? parseFloat(((caught.size / goldenVulnerabilities.length) * 100).toFixed(1))
    : 100.0;

  return {
    totalGoldens: goldenVulnerabilities.length,
    caughtGoldens: caught.size,
    recallRate: `${recall}%`,
    passed: recall >= 90.0
  };
}
