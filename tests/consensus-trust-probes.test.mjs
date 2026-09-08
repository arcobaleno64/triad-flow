import test from "node:test";
import assert from "node:assert/strict";
import {
  isTrustedConsensus,
  validateConsensusSemantics,
  issueConsensusFromEvidence
} from "../src/core/consensus-state.mjs";
import { aggregateConsensus, OodaLoopController } from "../src/core/loop.mjs";
import { evaluateGateDecision } from "../src/core/harness.mjs";

test("Round 5 Probe 1 (Proxy Trap Probe): Proxy object wrapping trusted consensus loses capability", () => {
  const realTrusted = aggregateConsensus({ macro: { findings: [] }, micro: { findings: [] } });
  assert.equal(isTrustedConsensus(realTrusted), true);

  const proxyTrap = new Proxy(realTrusted, {
    get(target, prop) {
      if (prop === "verdict") return "approve";
      return Reflect.get(target, prop);
    }
  });

  assert.equal(isTrustedConsensus(proxyTrap), false, "Proxy must not inherit WeakSet reference identity");
  assert.equal(evaluateGateDecision(proxyTrap).decision, "block");
});

test("Round 5 Probe 2 (Prototype Inheritance Probe): Object.create(trusted) does not inherit authority", () => {
  const realTrusted = aggregateConsensus({ macro: { findings: [] }, micro: { findings: [] } });
  const protoInherited = Object.create(realTrusted);

  assert.equal(protoInherited.verdict, "approve", "Prototype chain delegates properties");
  assert.equal(isTrustedConsensus(protoInherited), false, "Prototype delegation must not mint capability");
  assert.equal(evaluateGateDecision(protoInherited).decision, "block");
});

test("Round 5 Probe 3 (Throwing Getter Probe): Hostile object with throwing getters fails closed safely", () => {
  const hostileObject = {
    get verdict() {
      throw new Error("Malicious getter trap triggered");
    },
    get quorumReached() {
      return true;
    }
  };

  assert.equal(isTrustedConsensus(hostileObject), false);
  const gateRes = evaluateGateDecision(hostileObject);
  assert.equal(gateRes.decision, "block");

  const semRes = validateConsensusSemantics(hostileObject);
  assert.equal(semRes.ok, false);
});

test("Round 5 Probe 4 (Stale Invocation ID Probe): Stale report ID from Invocation A rejected in Invocation B", () => {
  let capturedIdFromInvA = null;

  // Invocation A: Capture ID
  const policyA = (meta) => {
    const ids = Object.keys(meta);
    capturedIdFromInvA = ids[0];
    return {
      quorumReached: true,
      selectedReportIds: ids
    };
  };
  const resA = aggregateConsensus({ macro: { findings: [] }, micro: { findings: [] } }, { policy: policyA });
  assert.equal(resA.quorumReached, true);
  assert.ok(capturedIdFromInvA);

  // Invocation B: Malicious policy attempts to return capturedIdFromInvA
  const policyB = () => ({
    quorumReached: true,
    selectedReportIds: [capturedIdFromInvA]
  });

  const resB = aggregateConsensus({ macro: { findings: [] }, micro: { findings: [] } }, { policy: policyB });
  assert.equal(resB.quorumReached, false);
  assert.equal(resB.verdict, "error");
  assert.match(resB.consensusProof, /unknown to current invocation|stale/i);
});

test("Round 5 Probe 5 (Controller Oscillation Reset Probe): OODA controller lifecycle reset clears stale oscillation history", () => {
  const ooda = new OodaLoopController({ maxIterations: 3 });

  // Simulate first task oscillation
  const blocker = aggregateConsensus({
    macro: { findings: [{ title: "Flaw", severity: "high", file: "a.js" }] },
    micro: { findings: [{ title: "Flaw", severity: "high", file: "a.js" }] }
  });

  ooda.step(blocker, "diff 1");
  ooda.step(blocker, "diff 2");
  assert.equal(ooda.currentIteration, 2);

  // Reset for new cycle
  ooda.reset();
  assert.equal(ooda.currentIteration, 0);
  assert.equal(ooda.historyFingerprints.length, 0);
  assert.equal(ooda.patchHashes.size, 0);
});

test("Round 5 Probe 6 (Deep Import Mint Probe): issueConsensusFromEvidence rejects plain objects without validated evidence map", () => {
  // Deep-imported issuer rejects plain objects or missing invocation context
  assert.throws(() => {
    issueConsensusFromEvidence({
      validatedReportsMap: null,
      quorumResult: { quorumReached: true, selectedReportIds: [] },
      invocationNonce: "test",
      verdict: "approve"
    });
  }, TypeError);

  assert.throws(() => {
    issueConsensusFromEvidence({
      validatedReportsMap: new Map(),
      quorumResult: null,
      invocationNonce: "test",
      verdict: "approve"
    });
  }, TypeError);

  assert.throws(() => {
    issueConsensusFromEvidence({
      validatedReportsMap: new Map(),
      quorumResult: { quorumReached: true, selectedReportIds: [] },
      invocationNonce: null,
      verdict: "approve"
    });
  }, TypeError);
});

test("Round 5 Probe 7 (Corrupted Audit JSON Probe): Serialized JSON reloaded as consensus fails closed in Gate and OODA", () => {
  const realTrusted = aggregateConsensus({ macro: { findings: [] }, micro: { findings: [] } });
  const auditJsonString = JSON.stringify(realTrusted);
  const auditRecord = JSON.parse(auditJsonString);

  // Audit record retains semantic fields for auditing
  assert.equal(auditRecord.verdict, "approve");
  assert.equal(auditRecord.quorumReached, true);

  // But loses execution authority completely
  assert.equal(isTrustedConsensus(auditRecord), false);
  assert.equal(evaluateGateDecision(auditRecord).decision, "block");

  const ooda = new OodaLoopController();
  const oodaRes = ooda.step(auditRecord);
  assert.equal(oodaRes.action, "escalate_to_human");
  assert.match(oodaRes.reason, /UNTRUSTED_CONSENSUS/i);
});
