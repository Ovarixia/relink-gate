import assert from "node:assert/strict";
import { test } from "node:test";
import { FrozenClock } from "../src/clock.js";
import { generateOrgKeys } from "../src/crypto.js";
import { issueClaim, requireFreshClaim, verifyClaim } from "../src/claims.js";
import { GateError } from "../src/types.js";

test("signed claim verifies and is fresh inside TTL", () => {
  const clock = new FrozenClock(new Date("2026-09-02T12:00:00Z"));
  const keys = generateOrgKeys("org-helios");
  const signed = issueClaim(
    {
      linkId: "link-rest-payments",
      issuerOrgId: "org-helios",
      audienceOrgId: "org-northwind",
      assertions: { keysRotated: true },
      ttlSeconds: 60,
    },
    keys,
    clock,
  );
  const status = verifyClaim(signed, keys.publicKeyPem, clock, new Set());
  assert.equal(status.fresh, true);
  assert.equal(status.signatureOk, true);
});

test("claim expires after TTL", () => {
  const clock = new FrozenClock(new Date("2026-09-02T12:00:00Z"));
  const keys = generateOrgKeys("org-helios");
  const signed = issueClaim(
    {
      linkId: "l",
      issuerOrgId: "org-helios",
      audienceOrgId: "org-northwind",
      assertions: {},
      ttlSeconds: 30,
    },
    keys,
    clock,
  );
  clock.advance(31_000);
  assert.throws(() => requireFreshClaim(signed, keys.publicKeyPem, clock, new Set()), (err: unknown) => {
    assert.ok(err instanceof GateError);
    assert.equal(err.code, "CLAIM_EXPIRED");
    return true;
  });
});

test("revoked claim is not fresh", () => {
  const clock = new FrozenClock(new Date("2026-09-02T12:00:00Z"));
  const keys = generateOrgKeys("org-helios");
  const signed = issueClaim(
    {
      linkId: "l",
      issuerOrgId: "org-helios",
      audienceOrgId: "org-northwind",
      assertions: {},
      ttlSeconds: 300,
    },
    keys,
    clock,
  );
  const revoked = new Set([signed.payload.claimId]);
  assert.throws(() => requireFreshClaim(signed, keys.publicKeyPem, clock, revoked), (err: unknown) => {
    assert.ok(err instanceof GateError);
    assert.equal(err.code, "CLAIM_REVOKED");
    return true;
  });
});

test("tampered payload fails signature check", () => {
  const clock = new FrozenClock(new Date("2026-09-02T12:00:00Z"));
  const keys = generateOrgKeys("org-helios");
  const signed = issueClaim(
    {
      linkId: "l",
      issuerOrgId: "org-helios",
      audienceOrgId: "org-northwind",
      assertions: { keysRotated: true },
      ttlSeconds: 300,
    },
    keys,
    clock,
  );
  signed.payload.assertions.keysRotated = false;
  const status = verifyClaim(signed, keys.publicKeyPem, clock, new Set());
  assert.equal(status.signatureOk, false);
  assert.equal(status.fresh, false);
});
