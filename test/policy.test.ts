import assert from "node:assert/strict";
import { test } from "node:test";
import { FrozenClock } from "../src/clock.js";
import { evaluatePolicy, loadPolicyFile } from "../src/policy.js";
import type { PolicyFacts } from "../src/policy.js";

const clock = new FrozenClock(new Date("2026-09-02T12:00:00Z"));

function facts(over: Partial<{ claim: Partial<PolicyFacts["claim"]>; challenge: Partial<PolicyFacts["challenge"]>; link: Partial<PolicyFacts["link"]> }> = {}): PolicyFacts {
  return {
    claim: {
      fresh: true,
      revoked: false,
      expired: false,
      issuerOrgId: "org-helios",
      audienceOrgId: "org-northwind",
      linkId: "link-rest-payments",
      assertions: { incidentClosed: true, keysRotated: true },
      challengeBound: true,
      ...over.claim,
    },
    challenge: {
      satisfied: true,
      nonceMatch: true,
      expired: false,
      ...over.challenge,
    },
    link: {
      kind: "rest",
      state: "claim",
      neverSkipQuarantine: true,
      requiredAssertionsMet: true,
      ...over.link,
    },
  };
}

test("REST policy quarantines a fresh challenged claim", () => {
  const policy = loadPolicyFile("rest-payments.policy.json");
  const decision = evaluatePolicy(policy, facts(), clock);
  assert.equal(decision.effect, "quarantine");
  assert.equal(decision.ruleId, "quarantine-fresh-claim");
});

test("REST policy refuses a revoked claim", () => {
  const policy = loadPolicyFile("rest-payments.policy.json");
  const decision = evaluatePolicy(policy, facts({ claim: { fresh: false, revoked: true } }), clock);
  assert.equal(decision.effect, "refuse");
  assert.equal(decision.ruleId, "refuse-revoked-or-stale");
});

test("REST policy refuses an unbound challenge", () => {
  const policy = loadPolicyFile("rest-payments.policy.json");
  const decision = evaluatePolicy(
    policy,
    facts({ claim: { challengeBound: false }, challenge: { satisfied: false, nonceMatch: false } }),
    clock,
  );
  assert.equal(decision.effect, "refuse");
  assert.equal(decision.ruleId, "refuse-unbound-challenge");
});

test("REST policy refuses incomplete assertions", () => {
  const policy = loadPolicyFile("rest-payments.policy.json");
  const decision = evaluatePolicy(policy, facts({ link: { requiredAssertionsMet: false } }), clock);
  assert.equal(decision.effect, "refuse");
  assert.equal(decision.ruleId, "refuse-missing-assertions");
});

test("SFTP policy default is refuse when nothing matches", () => {
  const policy = loadPolicyFile("sftp-settlement.policy.json");
  const empty = facts({
    claim: { fresh: false, revoked: false, expired: false, challengeBound: true },
    challenge: { satisfied: true },
    link: { requiredAssertionsMet: true },
  });
  const decision = evaluatePolicy(policy, empty, clock);
  assert.equal(decision.effect, "refuse");
});

test("policy evaluation is deterministic across repeats", () => {
  const policy = loadPolicyFile("rest-payments.policy.json");
  const a = evaluatePolicy(policy, facts(), clock);
  const b = evaluatePolicy(policy, facts(), clock);
  assert.deepEqual(a, b);
});
