import assert from "node:assert/strict";
import { test } from "node:test";
import { AuditLog, verifyAuditTrace, verifyHashChain } from "../src/audit.js";
import { FrozenClock } from "../src/clock.js";
import { generateOrgKeys } from "../src/crypto.js";
import type { AuditTrustPolicy, Link, Org } from "../src/types.js";
import { restRequirements } from "../src/gate.js";

test("empty log has an intact genesis chain", () => {
  const log = new AuditLog(new FrozenClock(new Date("2026-09-02T00:00:00Z")));
  assert.equal(verifyHashChain(log.events).ok, true);
});

test("seal is dual-signed and rejects a flipped signature", () => {
  const clock = new FrozenClock(new Date("2026-09-02T00:00:00Z"));
  const log = new AuditLog(clock);
  log.append({ type: "org.registered", actorOrgId: "a", detail: {} });
  log.append({ type: "link.cut", actorOrgId: "a", linkId: "l", toState: "cut", detail: {} });
  const ka = generateOrgKeys("a");
  const kb = generateOrgKeys("b");
  const orgs: Org[] = [
    { id: "a", name: "A", role: "relying-party", keyId: ka.keyId, publicKeyPem: ka.publicKeyPem },
    { id: "b", name: "B", role: "supplier", keyId: kb.keyId, publicKeyPem: kb.publicKeyPem },
  ];
  const links: Link[] = [
    {
      id: "l",
      name: "n",
      kind: "rest",
      supplierOrgId: "b",
      relyingOrgId: "a",
      state: "cut",
      requirements: restRequirements(),
      rampStageIndex: 0,
    },
  ];
  const sealed = log.seal(orgs, links, [ka, kb]);
  const trust: AuditTrustPolicy = {
    protocol: "relink-gate-audit-trust-v1",
    requiredSigners: orgs.map((org) => ({
      orgId: org.id,
      role: org.role,
      keyId: org.keyId,
      alg: "Ed25519",
      publicKeyPem: org.publicKeyPem,
    })),
  };
  assert.equal(verifyAuditTrace(sealed, trust).ok, true);

  const flipped = structuredClone(sealed);
  const first = flipped.signatures[0];
  assert.ok(first);
  const raw = Buffer.from(first.signature, "base64");
  raw[0] = (raw[0] ?? 0) ^ 1;
  first.signature = raw.toString("base64");
  assert.equal(verifyAuditTrace(flipped, trust).ok, false);

  const sealedEventCount = sealed.trace.events.length;
  log.append({ type: "later.event", actorOrgId: "a", detail: {} });
  assert.equal(sealed.trace.events.length, sealedEventCount);
  assert.equal(verifyAuditTrace(sealed, trust).ok, true);

  const changedState = structuredClone(sealed);
  const link = changedState.trace.links[0];
  assert.ok(link);
  link.state = "ramp";
  assert.equal(verifyAuditTrace(changedState, trust).ok, false);
});
