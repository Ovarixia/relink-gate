import { eventHash, GENESIS_HASH, signBytes, verifyBytes, sha256Hex, canonicalJson } from "./crypto.js";
import type { KeyPair } from "./crypto.js";
import type {
  AuditEvent,
  AuditTrace,
  AuditTrustPolicy,
  Clock,
  Link,
  LinkState,
  Org,
  SealedAuditTrace,
} from "./types.js";
import { GateError } from "./types.js";
import { iso } from "./clock.js";

export class AuditLog {
  private readonly entries: AuditEvent[] = [];
  readonly startedAt: string;

  constructor(private readonly clock: Clock) {
    this.startedAt = iso(clock);
  }

  get events(): AuditEvent[] {
    return structuredClone(this.entries);
  }

  append(input: {
    type: string;
    actorOrgId: string;
    linkId?: string;
    fromState?: LinkState;
    toState?: LinkState;
    detail?: Record<string, unknown>;
  }): AuditEvent {
    const seq = this.entries.length;
    const prevHash = this.entries.at(-1)?.hash ?? GENESIS_HASH;
    const at = iso(this.clock);
    const rest = {
      at,
      type: input.type,
      actorOrgId: input.actorOrgId,
      linkId: input.linkId,
      fromState: input.fromState,
      toState: input.toState,
      detail: structuredClone(input.detail ?? {}),
    };
    const event: AuditEvent = {
      seq,
      prevHash,
      hash: eventHash(seq, prevHash, rest),
      ...rest,
    };
    this.entries.push(event);
    return structuredClone(event);
  }

  headHash(): string {
    return this.entries.at(-1)?.hash ?? GENESIS_HASH;
  }

  seal(orgs: Org[], links: Link[], keys: KeyPair[], demo = true): SealedAuditTrace {
    const publicKeys: Record<string, string> = {};
    for (const key of keys) {
      publicKeys[key.orgId] = key.publicKeyPem;
    }
    const trace: AuditTrace = {
      protocol: "relink-gate-audit-v2",
      demo,
      startedAt: this.startedAt,
      sealedAt: iso(this.clock),
      orgs: orgs.map(({ id, name, role, keyId }) => ({ id, name, role, keyId })),
      publicKeys,
      links: links.map(({ id, name, kind, state, supplierOrgId, relyingOrgId }) => ({
        id,
        name,
        kind,
        state,
        supplierOrgId,
        relyingOrgId,
      })),
      events: structuredClone(this.entries),
      headHash: this.headHash(),
    };
    const message = sealMessage(trace);
    const signatures = keys.map((key) => ({
      orgId: key.orgId,
      keyId: key.keyId,
      alg: "Ed25519" as const,
      signature: signBytes(key.privateKeyPem, message),
    }));
    return { trace, signatures };
  }
}

/** Audit v2 signs every trace field, including institutions, keys, links, states, and events. */
export function sealMessage(trace: AuditTrace): string {
  return canonicalJson(trace);
}

export function verifyHashChain(events: readonly AuditEvent[]): { ok: boolean; reason: string } {
  let prev = GENESIS_HASH;
  for (let index = 0; index < events.length; index += 1) {
    const event = events[index];
    if (!event) {
      return { ok: false, reason: `Missing event at index ${index}` };
    }
    if (event.seq !== index) {
      return { ok: false, reason: `Unexpected sequence ${event.seq} at index ${index}` };
    }
    if (event.prevHash !== prev) {
      return { ok: false, reason: `Broken prevHash at seq ${event.seq}` };
    }
    const rest = {
      at: event.at,
      type: event.type,
      actorOrgId: event.actorOrgId,
      linkId: event.linkId,
      fromState: event.fromState,
      toState: event.toState,
      detail: event.detail,
    };
    const expected = eventHash(event.seq, event.prevHash, rest);
    if (expected !== event.hash) {
      return { ok: false, reason: `Hash mismatch at seq ${event.seq}` };
    }
    prev = event.hash;
  }
  return { ok: true, reason: "hash chain intact" };
}

function verifyFinalStates(trace: AuditTrace): string[] {
  const reasons: string[] = [];
  for (const link of trace.links) {
    const transitions = trace.events.filter(
      (event) => event.linkId === link.id && event.toState !== undefined,
    );
    const finalState = transitions.at(-1)?.toState;
    if (finalState !== link.state) {
      reasons.push(`final state mismatch for ${link.id}`);
    }
  }
  return reasons;
}

export function verifyAuditTrace(
  sealed: SealedAuditTrace,
  trust: AuditTrustPolicy,
): { ok: boolean; reasons: string[] } {
  const reasons: string[] = [];
  if (sealed.trace.protocol !== "relink-gate-audit-v2") {
    reasons.push("unsupported audit protocol");
  }
  if (trust.protocol !== "relink-gate-audit-trust-v1") {
    reasons.push("unsupported audit trust protocol");
  }

  const chain = verifyHashChain(sealed.trace.events);
  if (!chain.ok) {
    reasons.push(chain.reason);
  }
  if (sealed.trace.headHash !== (sealed.trace.events.at(-1)?.hash ?? GENESIS_HASH)) {
    reasons.push("headHash does not match last event");
  }
  reasons.push(...verifyFinalStates(sealed.trace));

  const expected = new Map<string, AuditTrustPolicy["requiredSigners"][number]>();
  const expectedKeys = new Set<string>();
  const expectedPublicKeys = new Set<string>();
  for (const signer of trust.requiredSigners) {
    if (expected.has(signer.orgId)) {
      reasons.push(`duplicate trusted organization ${signer.orgId}`);
    }
    if (expectedKeys.has(signer.keyId)) {
      reasons.push(`duplicate trusted key id ${signer.keyId}`);
    }
    if (expectedPublicKeys.has(signer.publicKeyPem)) {
      reasons.push(`duplicate trusted public key for ${signer.orgId}`);
    }
    expected.set(signer.orgId, signer);
    expectedKeys.add(signer.keyId);
    expectedPublicKeys.add(signer.publicKeyPem);
  }
  if (expected.size < 2) {
    reasons.push("at least two distinct trusted organizations are required");
  }
  if (![...expected.values()].some((signer) => signer.role === "relying-party")) {
    reasons.push("trusted relying-party signer is required");
  }
  if (![...expected.values()].some((signer) => signer.role === "supplier")) {
    reasons.push("trusted supplier signer is required");
  }

  const traceOrgs = new Map(sealed.trace.orgs.map((org) => [org.id, org]));
  for (const signer of expected.values()) {
    const org = traceOrgs.get(signer.orgId);
    if (!org || org.role !== signer.role || org.keyId !== signer.keyId) {
      reasons.push(`trace organization metadata mismatch for ${signer.orgId}`);
    }
    if (sealed.trace.publicKeys[signer.orgId] !== signer.publicKeyPem) {
      reasons.push(`embedded key mismatch for ${signer.orgId}`);
    }
    if (signer.alg !== "Ed25519") {
      reasons.push(`unsupported trusted algorithm for ${signer.orgId}`);
    }
  }
  if (traceOrgs.size !== expected.size) {
    reasons.push("trace organization set does not match external trust policy");
  }
  if (
    Object.keys(sealed.trace.publicKeys).length !== expected.size ||
    Object.keys(sealed.trace.publicKeys).some((orgId) => !expected.has(orgId))
  ) {
    reasons.push("embedded key set does not match external trust policy");
  }
  for (const link of sealed.trace.links) {
    if (expected.get(link.relyingOrgId)?.role !== "relying-party") {
      reasons.push(`untrusted relying party for ${link.id}`);
    }
    if (expected.get(link.supplierOrgId)?.role !== "supplier") {
      reasons.push(`untrusted supplier for ${link.id}`);
    }
  }

  const message = sealMessage(sealed.trace);
  const seenOrgs = new Set<string>();
  const seenKeys = new Set<string>();
  for (const signature of sealed.signatures) {
    if (seenOrgs.has(signature.orgId)) {
      reasons.push(`duplicate signature organization ${signature.orgId}`);
      continue;
    }
    if (seenKeys.has(signature.keyId)) {
      reasons.push(`duplicate signature key ${signature.keyId}`);
      continue;
    }
    seenOrgs.add(signature.orgId);
    seenKeys.add(signature.keyId);
    const signer = expected.get(signature.orgId);
    if (!signer) {
      reasons.push(`unexpected signer ${signature.orgId}`);
      continue;
    }
    if (signature.alg !== signer.alg || signature.keyId !== signer.keyId) {
      reasons.push(`signature metadata mismatch for ${signature.orgId}`);
      continue;
    }
    try {
      if (!verifyBytes(signer.publicKeyPem, message, signature.signature)) {
        reasons.push(`invalid signature from ${signature.orgId}`);
      }
    } catch {
      reasons.push(`invalid key or signature from ${signature.orgId}`);
    }
  }
  for (const orgId of expected.keys()) {
    if (!seenOrgs.has(orgId)) {
      reasons.push(`missing signature from ${orgId}`);
    }
  }
  if (seenOrgs.size !== expected.size) {
    reasons.push("signature set does not match external trust policy");
  }

  return { ok: reasons.length === 0, reasons: reasons.length ? reasons : ["verified"] };
}

export function fingerprint(sealed: SealedAuditTrace): string {
  return sha256Hex(canonicalJson(sealed));
}

export function requireVerified(sealed: SealedAuditTrace, trust: AuditTrustPolicy): void {
  const result = verifyAuditTrace(sealed, trust);
  if (!result.ok) {
    throw new GateError("AUDIT_INVALID", result.reasons.join("; "));
  }
}
