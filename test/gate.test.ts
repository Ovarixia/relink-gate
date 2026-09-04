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
import type { AuditTrustPolicy, RestorationClaim, SealedAuditTrace, TransportRequest } from "../src/types.js";
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

function setup(
  clock = new FrozenClock(new Date("2026-09-02T12:00:00Z")),
  demo = true,
): ReLinkGate {
  const gate = new ReLinkGate({ clock, demo });
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

test("authorization and REST dispatch consume one canonical operation", () => {
  const gate = setup();
  reopen(gate, REST);
  const before = gate.restSink.received.length;
  const disguised = gate.send(REST, {
    op: "rest.health",
    path: "/v1/payments",
    method: "DELETE",
    amount: 1,
    bytes: 0,
    body: { kind: "production", amount: 999_999, destination: "customer-account" },
  });
  assert.equal(disguised.ok, false);
  assert.match(String(disguised.deniedReason), /payments require POST|does not match canonical/);
  assert.equal(gate.restSink.received.length, before);
});

test("quarantine canary labels cannot redirect a production-sized payment", () => {
  const gate = setup();
  reopen(gate, REST);
  const before = gate.restSink.received.length;
  const denied = gate.send(REST, {
    op: "rest.payment.canary",
    path: "/v1/payments",
    labels: ["canary"],
    body: { kind: "canary", amount: 999_999, destination: "customer-account" },
  });
  assert.equal(denied.ok, false);
  assert.match(String(denied.deniedReason), /does not match the link's required/);
  assert.equal(gate.restSink.received.length, before);
});

test("ramp caps use body-derived amount and measured bytes", () => {
  const gate = setup();
  reopen(gate, REST);
  gate.runCanary(REST);

  const understatedAmount = gate.send(REST, {
    op: "rest.payment.small",
    path: "/v1/payments",
    amount: 1,
    bytes: 1,
    body: { kind: "limited", amount: 5_000, destination: "customer-account" },
  });
  assert.equal(understatedAmount.ok, false);
  assert.match(String(understatedAmount.deniedReason), /claimed amount does not match/);

  const oversizedCanary = gate.send(REST, {
    op: "rest.payment.canary",
    path: "/v1/payments",
    amount: 1,
    bytes: 0,
    labels: ["canary"],
    body: {
      kind: "canary",
      amount: 1,
      destination: "northwind-canary-sink",
      padding: "x".repeat(40_000),
    },
  });
  assert.equal(oversizedCanary.ok, false);
  assert.match(String(oversizedCanary.deniedReason), /handbrake/);
});

test("forwarding uses an immutable JSON snapshot of the validated body", () => {
  const gate = setup();
  reopen(gate, REST);
  const body = { kind: "canary", amount: 1, destination: "northwind-canary-sink" };
  const response = gate.send(REST, {
    op: "rest.payment.canary",
    path: "/v1/payments",
    labels: ["canary"],
    body,
  });
  assert.equal(response.ok, true);
  body.kind = "production";
  body.amount = 999_999;
  const forwarded = gate.restSink.received.at(-1)?.body as Record<string, unknown>;
  assert.equal(forwarded.kind, "canary");
  assert.equal(forwarded.amount, 1);
  assert.notEqual(forwarded, body);
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

test("caller-labeled SFTP canaries cannot escape or traverse the quarantine prefix", () => {
  const gate = setup();
  reopen(gate, SFTP);
  for (const path of [
    "/inbox/settlement/disguised.xml",
    "/quarantine/canary/../settlement/disguised.xml",
  ]) {
    const denied = gate.send(SFTP, {
      op: "sftp.put.canary",
      path,
      amount: 1,
      bytes: 0,
      body: { kind: "canary", amount: 1, destination: "northwind-settlement-canary" },
    });
    assert.equal(denied.ok, false, path);
    assert.equal(gate.sftpInbox.files.has(path), false);
  }
});

test("SFTP read handbrakes account for projected response bytes", () => {
  const gate = setup();
  reopen(gate, SFTP);
  gate.runCanary(SFTP);
  gate.advanceRamp(SFTP);
  gate.advanceRamp(SFTP);
  const path = "/inbox/settlement/preexisting-large.xml";
  gate.sftpInbox.files.set(path, {
    bytes: 1_000_000,
    body: { payload: "preexisting file body is represented out of band" },
    putAt: "2026-09-02T11:00:00.000Z",
  });
  const denied = gate.send(SFTP, { op: "sftp.get", path, bytes: 0 });
  assert.equal(denied.ok, false);
  assert.match(String(denied.deniedReason), /handbrake/);
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

test("truthy non-boolean assertion values are refused", () => {
  const gate = setup();
  const challenge = gate.issueChallenge(REST, NW);
  const claim = gate.createClaim(
    REST,
    HE,
    {
      incidentClosed: "false",
      keysRotated: "no",
      malwareCleared: 1,
      changeWindowApproved: "denied",
    },
    challenge.challengeId,
  );
  const decision = gate.submitClaim(claim, challenge.challengeId);
  assert.equal(decision.effect, "refuse");
  assert.equal(gate.getLink(REST).state, "cut");
});

test("production mode never exposes the gate as a supplier signing oracle", () => {
  const gate = setup(new FrozenClock(new Date("2026-09-02T12:00:00Z")), false);
  const challenge = gate.issueChallenge(REST, NW);
  assert.throws(
    () => gate.createClaim(REST, HE, assertions(), challenge.challengeId),
    (error: unknown) => error instanceof GateError && error.code === "DEMO_SIGNING_DISABLED",
  );
});

test("challenge and envelope participant bindings fail closed", () => {
  const gate = setup();
  assert.throws(
    () => gate.issueChallenge(REST, HE),
    (error: unknown) => error instanceof GateError && error.code === "CHALLENGE_ISSUER",
  );
  assert.throws(
    () => gate.issueChallenge(REST, NW, 301),
    (error: unknown) => error instanceof GateError && error.code === "CHALLENGE_TTL",
  );

  const challenge = gate.issueChallenge(REST, NW);
  const wrongEnvelope = gate.createClaim(REST, HE, assertions(), challenge.challengeId);
  wrongEnvelope.orgId = NW;
  assert.throws(
    () => gate.submitClaim(wrongEnvelope, challenge.challengeId),
    (error: unknown) => error instanceof GateError && error.code === "CLAIM_ENVELOPE",
  );

  const wrongNonce = gate.createClaim(REST, HE, assertions(), challenge.challengeId);
  wrongNonce.payload.challengeNonce = "attacker-nonce";
  assert.throws(
    () => gate.submitClaim(wrongNonce, challenge.challengeId),
    (error: unknown) => error instanceof GateError && error.code === "CHALLENGE_BINDING",
  );
  assert.equal(gate.getLink(REST).state, "cut");
});

test("link snapshots cannot mutate authoritative gate state", () => {
  const gate = setup();
  const snapshot = gate.getLink(REST);
  snapshot.state = "ramp";
  snapshot.requirements.requiredAssertions.length = 0;
  assert.equal(gate.getLink(REST).state, "cut");
  assert.ok(gate.getLink(REST).requirements.requiredAssertions.length > 0);
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

test("stale claims are denied at send and ramp boundaries with rollback", () => {
  const clock = new FrozenClock(new Date("2026-09-02T12:00:00Z"));
  const gate = setup(clock);
  reopen(gate, REST);
  gate.runCanary(REST);
  clock.advance(901_000);
  const denied = gate.send(REST, {
    op: "rest.health",
    path: "/health",
    method: "GET",
  });
  assert.equal(denied.ok, false);
  assert.match(String(denied.deniedReason), /handbrake/);
  assert.equal(gate.getLink(REST).state, "revoked");

  const second = setup(clock);
  reopen(second, REST);
  second.runCanary(REST);
  clock.advance(901_000);
  assert.throws(() => second.advanceRamp(REST), GateError);
  assert.equal(second.getLink(REST).state, "revoked");
});

test("an expired challenge rolls back before canary execution", () => {
  const clock = new FrozenClock(new Date("2026-09-02T12:00:00Z"));
  const gate = setup(clock);
  reopen(gate, REST);
  clock.advance(301_000);
  assert.throws(() => gate.runCanary(REST), GateError);
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
  const trust = gate.auditTrustPolicy();
  const ok = verifyAuditTrace(sealed, trust);
  assert.equal(ok.ok, true);
  assert.ok(sealed.signatures.length >= 2);

  const tampered: SealedAuditTrace = structuredClone(sealed);
  const event = tampered.trace.events[3];
  assert.ok(event);
  event.detail.tamper = true;
  const bad = verifyAuditTrace(tampered, trust);
  assert.equal(bad.ok, false);

  const duplicate: SealedAuditTrace = structuredClone(sealed);
  const first = duplicate.signatures[0];
  assert.ok(first);
  duplicate.signatures = [first, structuredClone(first)];
  assert.equal(verifyAuditTrace(duplicate, trust).ok, false);

  const changedTrust = structuredClone(trust);
  const changedSigner = changedTrust.requiredSigners[0];
  assert.ok(changedSigner);
  changedSigner.keyId = "unexpected-key";
  assert.equal(verifyAuditTrace(sealed, changedTrust).ok, false);
});

test("demo writes a dual-signed verifiable audit trace", () => {
  const dir = mkdtempSync(join(tmpdir(), "relink-"));
  const { auditPath, trustPath } = runDemo(dir, { quiet: true });
  const sealed = JSON.parse(readFileSync(auditPath, "utf8")) as SealedAuditTrace;
  const trust = JSON.parse(readFileSync(trustPath, "utf8")) as AuditTrustPolicy;
  const result = verifyAuditTrace(sealed, trust);
  assert.equal(result.ok, true);
  const states = Object.fromEntries(sealed.trace.links.map((l) => [l.id, l.state]));
  assert.equal(states[REST], "ramp");
  assert.equal(states[SFTP], "ramp");
  assert.ok(sealed.trace.events.some((e) => e.type === "canary.passed"));
  assert.ok(sealed.trace.events.some((e) => e.type === "policy.decision"));
  assert.equal(sealed.signatures.length, 2);
});
