import { randomBytes } from "node:crypto";
import { iso } from "./clock.js";
import { signPayload, verifyPayload } from "./crypto.js";
import type { KeyPair } from "./crypto.js";
import type { CanaryReceipt, CanarySpec, Clock, Link, SignedEnvelope, TransportRequest } from "./types.js";
import { GateError } from "./types.js";

export interface CanaryIntent {
  canaryId: string;
  linkId: string;
  challengeNonce: string;
  spec: CanarySpec;
}

export function buildCanaryRequest(link: Link, challengeNonce: string): {
  intent: CanaryIntent;
  request: TransportRequest;
} {
  const spec = link.requirements.canary;
  const canaryId = `cny_${randomBytes(6).toString("hex")}`;
  const label = `CANARY-${challengeNonce}`;
  const path =
    link.kind === "sftp"
      ? `${spec.pathPrefix ?? "/quarantine/canary/"}${label}.xml`
      : "/v1/payments";

  const request: TransportRequest = {
    op: link.kind === "sftp" ? "sftp.put.canary" : "rest.payment.canary",
    path,
    method: link.kind === "rest" ? "POST" : "PUT",
    amount: spec.expectedAmount,
    bytes: 256,
    labels: ["canary", label],
    body: {
      kind: "canary",
      canaryId,
      amount: spec.expectedAmount,
      currency: spec.currency,
      reference: label,
      destination: spec.sink,
      challengeNonce,
    },
  };
  return { intent: { canaryId, linkId: link.id, challengeNonce, spec }, request };
}

export function evaluateCanary(
  link: Link,
  request: TransportRequest,
  responseOk: boolean,
  clock: Clock,
): CanaryReceipt {
  const spec = link.requirements.canary;
  const body = (request.body ?? {}) as Record<string, unknown>;
  const labels = request.labels ?? [];
  const amount = request.amount ?? (typeof body.amount === "number" ? body.amount : undefined);
  const sink = typeof body.destination === "string" ? body.destination : undefined;
  const isCanary = labels.includes("canary") || body.kind === "canary";
  const pathOk =
    link.kind === "sftp"
      ? request.path.startsWith(spec.pathPrefix ?? "/quarantine/canary/")
      : request.path === "/v1/payments";
  const amountOk = amount === spec.expectedAmount;
  const sinkOk = sink === spec.sink;
  const passed = Boolean(responseOk && isCanary && pathOk && amountOk && sinkOk);

  let reason = "canary path behaved as claimed";
  if (!responseOk) reason = "downstream rejected canary";
  else if (!isCanary) reason = "traffic was not labeled canary";
  else if (!pathOk) reason = "canary used unexpected path";
  else if (!amountOk) reason = "canary amount did not match requirement";
  else if (!sinkOk) reason = "canary sink did not match requirement";

  return {
    canaryId: String(body.canaryId ?? `cny_${randomBytes(4).toString("hex")}`),
    linkId: link.id,
    kind: link.kind,
    submittedAt: iso(clock),
    expected: spec,
    observed: {
      op: request.op,
      path: request.path,
      amount,
      sink,
      labels,
    },
    passed,
    reason,
  };
}

export function signCanaryReceipt(receipt: CanaryReceipt, keys: KeyPair): SignedEnvelope<CanaryReceipt> {
  return signPayload(receipt, keys);
}

export function verifyCanaryReceipt(
  signed: SignedEnvelope<CanaryReceipt>,
  publicKeyPem: string,
): void {
  if (!verifyPayload(signed, publicKeyPem)) {
    throw new GateError("CANARY_BAD_SIG", "Canary receipt signature is invalid");
  }
  if (!signed.payload.passed) {
    throw new GateError("CANARY_FAILED", signed.payload.reason);
  }
}
