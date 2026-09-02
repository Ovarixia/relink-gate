import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { verifyAuditTrace } from "../src/audit.js";
import { FrozenClock } from "../src/clock.js";
import { generateOrgKeys } from "../src/crypto.js";
import { runDemo } from "../src/demo.js";
import { ReLinkGate, restRequirements, sftpRequirements } from "../src/gate.js";
import type { RestorationClaim, SealedAuditTrace, TransportRequest } from "../src/types.js";
import { GateError } from "../src/types.js";

const NW = "org-northwind";
const HE = "org-helios";
const REST = "link-rest-payments";
const SFTP = "link-sftp-settlement";

function assertions(): RestorationClaim["assertions"] {
  return {
    incidentClosed: true,
    keysRotated: true,
    malwareCleared: true,
    changeWindowApproved: true,
    inboxRebuilt: true,
  };
}

function setup(clock = new FrozenClock(new Date("2026-09-02T12:00:00Z"))): ReLinkGate {
  const gate = new ReLinkGate({ clock });
  const nw = generateOrgKeys(NW);
  const he = generateOrgKeys(HE);
  gate.registerOrg(
    { id: NW, name: "Northwind Bank", role: "relying-party", keyId: nw.keyId, publicKeyPem: nw.publicKeyPem },
    nw,
  );
  gate.registerOrg(
    { id: HE, name: "Helios Payments", role: "supplier", keyId: he.keyId, publicKeyPem: he.publicKeyPem },
    he,
  );
  gate.loadBundledPolicies();
  gate.registerLink({
    id: REST,
    name: "REST payments",
    kind: "rest",
    supplierOrgId: HE,
    relyingOrgId: NW,
    requirements: restRequirements(),
    cutReason: "incident",
  });
  gate.registerLink({
    id: SFTP,
    name: "SFTP settlement",
    kind: "sftp",
    supplierOrgId: HE,
    relyingOrgId: NW,
    requirements: sftpRequirements(),
    cutReason: "incident",
  });
  return gate;
}

function reopen(gate: ReLinkGate, linkId: string): void {
  const challenge = gate.issueChallenge(linkId, NW);
  const claim = gate.createClaim(linkId, HE, assertions(), challenge.challengeId);
  const bound = gate.bindClaimToChallenge(claim, challenge.challengeId);
  const decision = gate.submitClaim(bound, challenge.challengeId);
  assert.equal(decision.effect, "quarantine");
}

test("quarantine proxy refuses full REST access", () => {
  const gate = setup();
  reopen(gate, REST);
  const res = gate.send(REST, {
    op: "rest.payment.create",
    path: "/v1/payments",
    amount: 9_000,
    body: { kind: "production", amount: 9000 },
  });
  assert.equal(res.ok, false);
  assert.match(String(res.deniedReason), /not allowed in quarantine/);
});

test("canary then ramp allows increasing rights", () => {
  const gate = setup();
  reopen(gate, REST);
  const receipt = gate.runCanary(REST);
  assert.equal(receipt.payload.passed, true);
  assert.equal(gate.getLink(REST).state, "ramp");

  const small: TransportRequest = {
    op: "rest.payment.small",
    path: "/v1/payments",
    amount: 5,
    bytes: 100,
    body: { kind: "limited", amount: 5, destination: "customer-account" },
  };
  assert.equal(gate.send(REST, small).ok, true);

  const big: TransportRequest = {
    op: "rest.payment.create",
    path: "/v1/payments",
    amount: 5_000,
    bytes: 100,
    body: { kind: "production", amount: 5000, destination: "customer-account" },
  };
  const denied = gate.send(REST, big);
  assert.equal(denied.ok, false);

  gate.advanceRamp(REST);
  gate.advanceRamp(REST);
  assert.equal(gate.send(REST, big).ok, true);
});

test("SFTP canary writes only under the quarantine prefix", () => {
  const gate = setup();
  reopen(gate, SFTP);
  const blocked = gate.send(SFTP, {
    op: "sftp.put.settlement",
    path: "/inbox/settlement/day.xml",
    amount: 10,
    bytes: 200,
    body: { kind: "production" },
  });
  assert.equal(blocked.ok, false);
  const receipt = gate.runCanary(SFTP);
  assert.equal(receipt.payload.passed, true);
  assert.ok(receipt.payload.observed.path.startsWith("/quarantine/canary/"));
  assert.equal(gate.sftpInbox.files.has(receipt.payload.observed.path), true);
});

test("incomplete assertions are refused and the link returns to cut", () => {
  const gate = setup();
  const challenge = gate.issueChallenge(REST, NW);
  const claim = gate.createClaim(REST, HE, { incidentClosed: true }, challenge.challengeId);
  const bound = gate.bindClaimToChallenge(claim, challenge.challengeId);
  const decision = gate.submitClaim(bound, challenge.challengeId);
  assert.equal(decision.effect, "refuse");
  assert.equal(gate.getLink(REST).state, "cut");
});

test("revoking the claim pulls the handbrake", () => {
  const gate = setup();
  reopen(gate, REST);
  gate.runCanary(REST);
  const claimId = gate.getLink(REST).activeClaimId;
  assert.ok(claimId);
  gate.revokeClaim(claimId, NW, "operator handbrake");
  assert.equal(gate.getLink(REST).state, "revoked");
  const res = gate.send(REST, {
    op: "rest.payment.canary",
    path: "/v1/payments",
    amount: 1,
    body: { kind: "canary", amount: 1, destination: "northwind-canary-sink" },
  });
  assert.equal(res.ok, false);
});

test("stale claim during ramp is rolled back", () => {
  const clock = new FrozenClock(new Date("2026-09-02T12:00:00Z"));
  const gate = setup(clock);
  reopen(gate, REST);
  gate.runCanary(REST);
  clock.advance(901_000);
  assert.equal(gate.expireIfStale(REST), true);
  assert.equal(gate.getLink(REST).state, "revoked");
});

test("advanceRamp is rejected outside ramp", () => {
  const gate = setup();
  assert.throws(() => gate.advanceRamp(REST), GateError);
});

test("sealed reconnection audit verifies; tampering does not", () => {
  const gate = setup();
  reopen(gate, REST);
  reopen(gate, SFTP);
  gate.runCanary(REST);
  gate.runCanary(SFTP);
  gate.advanceRamp(REST);
  gate.advanceRamp(REST);
  gate.advanceRamp(SFTP);
  gate.advanceRamp(SFTP);
  const sealed = gate.seal();
  const ok = verifyAuditTrace(sealed, gate.publicKeys());
  assert.equal(ok.ok, true);
  assert.ok(sealed.signatures.length >= 2);

  const tampered: SealedAuditTrace = structuredClone(sealed);
  const event = tampered.trace.events[3];
  assert.ok(event);
  event.detail.tamper = true;
  const bad = verifyAuditTrace(tampered, gate.publicKeys());
  assert.equal(bad.ok, false);
});

test("demo writes a dual-signed verifiable audit trace", () => {
  const dir = mkdtempSync(join(tmpdir(), "relink-"));
  const { auditPath } = runDemo(dir);
  const sealed = JSON.parse(readFileSync(auditPath, "utf8")) as SealedAuditTrace;
  const result = verifyAuditTrace(sealed, sealed.trace.publicKeys);
  assert.equal(result.ok, true);
  const states = Object.fromEntries(sealed.trace.links.map((l) => [l.id, l.state]));
  assert.equal(states[REST], "ramp");
  assert.equal(states[SFTP], "ramp");
  assert.ok(sealed.trace.events.some((e) => e.type === "canary.passed"));
  assert.ok(sealed.trace.events.some((e) => e.type === "policy.decision"));
  assert.equal(sealed.signatures.length, 2);
});
