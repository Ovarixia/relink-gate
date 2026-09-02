import { eventHash, GENESIS_HASH, signBytes, verifyBytes, sha256Hex, canonicalJson } from "./crypto.js";
import type { KeyPair } from "./crypto.js";
import type { AuditEvent, AuditTrace, Clock, Link, LinkState, Org, SealedAuditTrace } from "./types.js";
import { GateError } from "./types.js";
import { iso } from "./clock.js";

export class AuditLog {
  readonly events: AuditEvent[] = [];
  readonly startedAt: string;

  constructor(private readonly clock: Clock) {
    this.startedAt = iso(clock);
  }

  append(input: {
    type: string;
    actorOrgId: string;
    linkId?: string;
    fromState?: LinkState;
    toState?: LinkState;
    detail?: Record<string, unknown>;
  }): AuditEvent {
    const seq = this.events.length;
    const prevHash = this.events.at(-1)?.hash ?? GENESIS_HASH;
    const at = iso(this.clock);
    const rest = {
      at,
      type: input.type,
      actorOrgId: input.actorOrgId,
      linkId: input.linkId,
      fromState: input.fromState,
      toState: input.toState,
      detail: input.detail ?? {},
    };
    const event: AuditEvent = {
      seq,
      prevHash,
      hash: eventHash(seq, prevHash, rest),
      ...rest,
    };
    this.events.push(event);
    return event;
  }

  headHash(): string {
    return this.events.at(-1)?.hash ?? GENESIS_HASH;
  }

  seal(orgs: Org[], links: Link[], keys: KeyPair[]): SealedAuditTrace {
    const publicKeys: Record<string, string> = {};
    for (const k of keys) {
      publicKeys[k.orgId] = k.publicKeyPem;
    }
    const trace: AuditTrace = {
      protocol: "relink-gate-audit-v1",
      demo: true,
      startedAt: this.startedAt,
      sealedAt: iso(this.clock),
      orgs: orgs.map(({ id, name, role, keyId }) => ({ id, name, role, keyId })),
      publicKeys,
      links: links.map(({ id, name, kind, state }) => ({ id, name, kind, state })),
      events: this.events,
      headHash: this.headHash(),
    };
    const message = sealMessage(trace);
    const signatures = keys.map((k) => ({
      orgId: k.orgId,
      keyId: k.keyId,
      alg: "Ed25519" as const,
      signature: signBytes(k.privateKeyPem, message),
    }));
    return { trace, signatures };
  }
}

export function sealMessage(trace: AuditTrace): string {
  return canonicalJson({
    protocol: trace.protocol,
    startedAt: trace.startedAt,
    sealedAt: trace.sealedAt,
    headHash: trace.headHash,
    eventCount: trace.events.length,
    linkIds: trace.links.map((l) => l.id),
  });
}

export function verifyHashChain(events: AuditEvent[]): { ok: boolean; reason: string } {
  let prev = GENESIS_HASH;
  for (const event of events) {
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

export function verifyAuditTrace(
  sealed: SealedAuditTrace,
  publicKeys: Record<string, string>,
): { ok: boolean; reasons: string[] } {
  const reasons: string[] = [];
  const chain = verifyHashChain(sealed.trace.events);
  if (!chain.ok) {
    reasons.push(chain.reason);
  }
  if (sealed.trace.headHash !== (sealed.trace.events.at(-1)?.hash ?? GENESIS_HASH)) {
    reasons.push("headHash does not match last event");
  }
  const message = sealMessage(sealed.trace);
  if (sealed.signatures.length === 0) {
    reasons.push("no signatures");
  }
  for (const sig of sealed.signatures) {
    const pem = publicKeys[sig.orgId];
    if (!pem) {
      reasons.push(`missing public key for ${sig.orgId}`);
      continue;
    }
    if (!verifyBytes(pem, message, sig.signature)) {
      reasons.push(`invalid signature from ${sig.orgId}`);
    }
  }
  return { ok: reasons.length === 0, reasons: reasons.length ? reasons : ["verified"] };
}

export function fingerprint(sealed: SealedAuditTrace): string {
  return sha256Hex(canonicalJson({ head: sealed.trace.headHash, sigs: sealed.signatures }));
}

export function requireVerified(sealed: SealedAuditTrace, publicKeys: Record<string, string>): void {
  const result = verifyAuditTrace(sealed, publicKeys);
  if (!result.ok) {
    throw new GateError("AUDIT_INVALID", result.reasons.join("; "));
  }
}
