import test from "node:test";
import assert from "node:assert/strict";
import {
  validateConsensusSemantics,
  isTrustedConsensus,
  assertTrustedConsensus,
  hasBlockingFindings,
  getBlockingFindings,
  deepFreeze,
  ALLOWED_VERDICTS,
  BLOCKING_SEVERITIES
} from "../src/core/consensus-state.mjs";
import { evaluateGateDecision } from "../src/core/harness.mjs";
import { OodaLoopController, aggregateConsensus } from "../src/core/loop.mjs";

test("hasBlockingFindings correctly identifies critical and high severities", () => {
  assert.equal(hasBlockingFindings([{ severity: "critical" }]), true);
  assert.equal(hasBlockingFindings([{ severity: "high" }]), true);
  assert.equal(hasBlockingFindings([{ severity: "medium" }]), false);
  assert.equal(hasBlockingFindings([{ severity: "low" }]), false);
  assert.equal(hasBlockingFindings([{ severity: "info" }]), false);
  assert.equal(hasBlockingFindings([]), false);
  assert.equal(hasBlockingFindings(null), false);
});

test("validateConsensusSemantics validates schema, types, counts and invariants without granting capability authority", () => {
  // 1. Invalid root object
  assert.equal(validateConsensusSemantics(null).valid, false);
  assert.equal(validateConsensusSemantics("valid").valid, false);
  assert.equal(validateConsensusSemantics([]).valid, false);

  // 2. Invalid quorumReached type
  assert.equal(validateConsensusSemantics({ quorumReached: "true", verdict: "approve", findings: [] }).valid, false);

  // 3. Invalid verdict enum
  assert.equal(validateConsensusSemantics({ quorumReached: true, verdict: "super_pass", findings: [] }).valid, false);

  // 4. Count mismatch contradiction
  const countMismatch = validateConsensusSemantics({
    quorumReached: true,
    verdict: "warning",
    totalFindings: 5,
    findings: [{ severity: "low", title: "Test issue" }]
  });
  assert.equal(countMismatch.valid, false);
  assert.equal(countMismatch.code, "CONTRADICTION_TOTAL_FINDINGS_MISMATCH");

  // 5. Approve with blocking findings contradiction
  const approveWithBlocker = validateConsensusSemantics({
    quorumReached: true,
    verdict: "approve",
    totalFindings: 1,
    findings: [{ severity: "critical", title: "RCE Vulnerability" }]
  });
  assert.equal(approveWithBlocker.valid, false);
  assert.equal(approveWithBlocker.code, "CONTRADICTION_APPROVE_WITH_BLOCKING_FINDINGS");

  // 6. Valid semantic consensus is valid for diagnostic, but is NOT trusted capability!
  const validSemanticCandidate = {
    quorumReached: true,
    verdict: "approve",
    totalFindings: 0,
    findings: [],
    selectedReportIds: ["forged:macro", "forged:micro"],
    consensusProof: "clean"
  };
  const semRes = validateConsensusSemantics(validSemanticCandidate);
  assert.equal(semRes.valid, true);
  assert.equal(isTrustedConsensus(validSemanticCandidate), false, "Semantic validation must NEVER mint trusted authority!");
  assert.equal(isTrustedConsensus(semRes.value), false, "Semantic validation output value must NOT be trusted capability!");
});

test("Capability Forgery Matrix (CF-01..CF-08): Plain objects, clones, and fake flags are untrusted", () => {
  const validMacro = { name: "macro", findings: [] };
  const validMicro = { name: "micro", findings: [] };
  const realTrusted = aggregateConsensus(validMacro, validMicro);

  assert.equal(isTrustedConsensus(realTrusted), true, "Real aggregation output must possess trusted capability");
  assert.doesNotThrow(() => assertTrustedConsensus(realTrusted));

  // CF-01: Plain Object
  const plain = { quorumReached: true, verdict: "approve", totalFindings: 0, findings: [] };
  assert.equal(isTrustedConsensus(plain), false);
  assert.throws(() => assertTrustedConsensus(plain));

  // CF-02: Spread Clone
  const spreadClone = { ...realTrusted };
  assert.equal(isTrustedConsensus(spreadClone), false);

  // CF-03: JSON Round-trip
  const jsonClone = JSON.parse(JSON.stringify(realTrusted));
  assert.equal(isTrustedConsensus(jsonClone), false);

  // CF-04: structuredClone
  const structured = structuredClone(realTrusted);
  assert.equal(isTrustedConsensus(structured), false);

  // CF-05: Object.assign
  const assigned = Object.assign({}, realTrusted);
  assert.equal(isTrustedConsensus(assigned), false);

  // CF-06: Copied Metadata
  const copiedMetadata = {
    quorumReached: realTrusted.quorumReached,
    verdict: realTrusted.verdict,
    totalFindings: realTrusted.totalFindings,
    findings: [...realTrusted.findings],
    selectedReportIds: [...realTrusted.selectedReportIds],
    consensusProof: realTrusted.consensusProof
  };
  assert.equal(isTrustedConsensus(copiedMetadata), false);

  // CF-07: Fake Trust Flag
  const fakeFlag = { ...realTrusted, trusted: true, isTrusted: true, verified: true };
  assert.equal(isTrustedConsensus(fakeFlag), false);

  // CF-08: Copied Symbols
  const symObj = {};
  for (const sym of Object.getOwnPropertySymbols(realTrusted)) {
    symObj[sym] = realTrusted[sym];
  }
  Object.assign(symObj, realTrusted);
  assert.equal(isTrustedConsensus(symObj), false);
});

test("Deep Immutability: Issued trusted consensus cannot be mutated", () => {
  const realTrusted = aggregateConsensus({
    macro: { findings: [{ title: "XSS", severity: "high", file: "a.js" }] },
    micro: { findings: [{ title: "XSS", severity: "high", file: "a.js" }] }
  });

  assert.throws(() => {
    realTrusted.verdict = "approve";
  }, TypeError);

  assert.throws(() => {
    realTrusted.findings.push({ title: "Fake", severity: "info", file: "b.js" });
  }, TypeError);

  assert.throws(() => {
    realTrusted.findings[0].severity = "info";
  }, TypeError);
});
