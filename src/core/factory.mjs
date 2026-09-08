/**
 * Factory Pipeline: Autonomous remediation pipeline pre-flight and fail-closed gate.
 *
 * The pipeline requires live provider adapters (remediator + sentries). Until those are
 * configured it MUST halt without mutating code — an unconfigured factory that "succeeds"
 * would be a fabricated claim (CLAUDE.md §2 Zero Fabricated Claims).
 */

export const FACTORY_STATUS = Object.freeze({
  UNCONFIGURED: "unconfigured",
  READY: "ready"
});

/**
 * Pre-flight check for the factory pipeline.
 * @param {object} adapters - { remediator, macroSentry, microSentry } — each truthy when configured.
 * @returns {{status: string, ready: boolean, missing: string[], reason: string}}
 */
export function checkFactoryReadiness(adapters = {}) {
  const required = ["remediator", "macroSentry", "microSentry"];
  const missing = required.filter(key => !adapters[key]);

  if (missing.length > 0) {
    return {
      status: FACTORY_STATUS.UNCONFIGURED,
      ready: false,
      missing,
      reason: "Unconfigured Factory Adapters: Real auto-remediation requires live provider adapter hooks."
    };
  }

  return {
    status: FACTORY_STATUS.READY,
    ready: true,
    missing: [],
    reason: "All factory adapters configured."
  };
}

/**
 * Run the factory pipeline. Fails closed while adapters are unconfigured.
 * @returns {{halted: boolean, mutated: boolean, readiness: object, lines: string[]}}
 */
export function runFactoryPipeline(adapters = {}) {
  const readiness = checkFactoryReadiness(adapters);
  const lines = ["1️⃣  [Pre-flight] Checking Remediator & Provider Adapters...\n"];

  if (!readiness.ready) {
    lines.push(`  ⚠️ ${readiness.reason}\n`);
    lines.push("  🛡️ Enforcing Fail-Closed: Autonomous factory halted safely without unverified code mutation.\n\n");
    return { halted: true, mutated: false, readiness, lines };
  }

  // No live adapter execution path exists yet; fail closed rather than claim a run.
  lines.push("  🛡️ Enforcing Fail-Closed: Factory execution path not implemented for configured adapters.\n\n");
  return { halted: true, mutated: false, readiness, lines };
}
