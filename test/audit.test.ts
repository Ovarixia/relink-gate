import assert from "node:assert/strict";
import { test } from "node:test";
import { AuditLog, verifyAuditTrace, verifyHashChain } from "../src/audit.js";
import { FrozenClock } from "../src/clock.js";
import { generateOrgKeys } from "../src/crypto.js";
import type { Link, Org } from "../src/types.js";
import { restRequirements } from "../src/gate.js";

test("empty log has an intact genesis chain", () => {
  const log = new AuditLog(new FrozenClock(new Date("2026-09-02T00:00:00Z")));
  assert.equal(verifyHashChain(log.events).ok, true);
});

test("seal is dual-signed and rejects a flipped signature", () => {
  const clock = new FrozenClock(new Date("2026-09-02T00:00:00Z"));
  const log = new AuditLog(clock);
  log.append({ type: "org.registered", actorOrgId: "a", detail: {} });
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
  const keys = { a: ka.publicKeyPem, b: kb.publicKeyPem };
  assert.equal(verifyAuditTrace(sealed, keys).ok, true);

  const flipped = structuredClone(sealed);
  const first = flipped.signatures[0];
  assert.ok(first);
  const raw = Buffer.from(first.signature, "base64");
  raw[0] = (raw[0] ?? 0) ^ 1;
  first.signature = raw.toString("base64");
  assert.equal(verifyAuditTrace(flipped, keys).ok, false);
});
