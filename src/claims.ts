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
    challengeNonce: input.challengeNonce,
  };
  return signPayload(payload, keys);
}

export function bindChallenge(
  signed: SignedEnvelope<RestorationClaim>,
  challengeId: string,
  challengeNonce: string,
  keys: KeyPair,
): SignedEnvelope<RestorationClaim> {
  return signPayload({ ...signed.payload, challengeId, challengeNonce }, keys);
}

export function verifyClaim(
  signed: SignedEnvelope<RestorationClaim>,
  publicKeyPem: string,
  clock: Clock,
  revokedIds: Set<string>,
  maxTtlSeconds?: number,
): { fresh: boolean; expired: boolean; revoked: boolean; signatureOk: boolean; timeValid: boolean } {
  let signatureOk = false;
  try {
    signatureOk = verifyPayload(signed, publicKeyPem);
  } catch {
    signatureOk = false;
  }
  const now = clock.now().getTime();
  const issuedAt = Date.parse(signed.payload.issuedAt);
  const expiresAt = Date.parse(signed.payload.expiresAt);
  const duration = expiresAt - issuedAt;
  const timeValid =
    Number.isFinite(issuedAt) &&
    Number.isFinite(expiresAt) &&
    issuedAt <= now &&
    duration > 0 &&
    (maxTtlSeconds === undefined || duration <= maxTtlSeconds * 1_000);
  const expired = Number.isFinite(expiresAt) && expiresAt <= now;
  const revoked = revokedIds.has(signed.payload.claimId);
  return {
    signatureOk,
    timeValid,
    expired,
    revoked,
    fresh: signatureOk && timeValid && !expired && !revoked,
  };
}

export function requireFreshClaim(
  signed: SignedEnvelope<RestorationClaim>,
  publicKeyPem: string,
  clock: Clock,
  revokedIds: Set<string>,
  maxTtlSeconds?: number,
): void {
  const status = verifyClaim(signed, publicKeyPem, clock, revokedIds, maxTtlSeconds);
  if (!status.signatureOk) {
    throw new GateError("CLAIM_BAD_SIG", "Restoration claim signature is invalid");
  }
  if (!status.timeValid) {
    throw new GateError("CLAIM_TIME_INVALID", "Restoration claim has an invalid issuance or TTL window");
  }
  if (status.revoked) {
    throw new GateError("CLAIM_REVOKED", "Restoration claim has been revoked");
  }
  if (status.expired) {
    throw new GateError("CLAIM_EXPIRED", "Restoration claim TTL has elapsed");
  }
}
