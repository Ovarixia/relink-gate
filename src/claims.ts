import { randomBytes } from "node:crypto";
import { addSeconds, iso } from "./clock.js";
import { signPayload, verifyPayload } from "./crypto.js";
import type { KeyPair } from "./crypto.js";
import type { Clock, RestorationClaim, SignedEnvelope } from "./types.js";
import { GateError } from "./types.js";

export function issueClaim(
  input: Omit<RestorationClaim, "claimId" | "issuedAt" | "expiresAt" | "nonce"> & {
    ttlSeconds: number;
  },
  keys: KeyPair,
  clock: Clock,
): SignedEnvelope<RestorationClaim> {
  const payload: RestorationClaim = {
    claimId: `clm_${randomBytes(8).toString("hex")}`,
    linkId: input.linkId,
    issuerOrgId: input.issuerOrgId,
    audienceOrgId: input.audienceOrgId,
    issuedAt: iso(clock),
    expiresAt: addSeconds(clock, input.ttlSeconds),
    nonce: randomBytes(16).toString("hex"),
    assertions: input.assertions,
    challengeId: input.challengeId,
  };
  return signPayload(payload, keys);
}

export function bindChallenge(
  signed: SignedEnvelope<RestorationClaim>,
  challengeId: string,
  keys: KeyPair,
): SignedEnvelope<RestorationClaim> {
  return signPayload({ ...signed.payload, challengeId }, keys);
}

export function verifyClaim(
  signed: SignedEnvelope<RestorationClaim>,
  publicKeyPem: string,
  clock: Clock,
  revokedIds: Set<string>,
): { fresh: boolean; expired: boolean; revoked: boolean; signatureOk: boolean } {
  const signatureOk = verifyPayload(signed, publicKeyPem);
  const expired = Date.parse(signed.payload.expiresAt) <= clock.now().getTime();
  const revoked = revokedIds.has(signed.payload.claimId);
  return {
    signatureOk,
    expired,
    revoked,
    fresh: signatureOk && !expired && !revoked,
  };
}

export function requireFreshClaim(
  signed: SignedEnvelope<RestorationClaim>,
  publicKeyPem: string,
  clock: Clock,
  revokedIds: Set<string>,
): void {
  const status = verifyClaim(signed, publicKeyPem, clock, revokedIds);
  if (!status.signatureOk) {
    throw new GateError("CLAIM_BAD_SIG", "Restoration claim signature is invalid");
  }
  if (status.revoked) {
    throw new GateError("CLAIM_REVOKED", "Restoration claim has been revoked");
  }
  if (status.expired) {
    throw new GateError("CLAIM_EXPIRED", "Restoration claim TTL has elapsed");
  }
}
