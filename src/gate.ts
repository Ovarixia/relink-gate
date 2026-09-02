import { randomBytes } from "node:crypto";
import { addSeconds, iso } from "./clock.js";
import { bindChallenge, issueClaim, requireFreshClaim, verifyClaim } from "./claims.js";
import type { KeyPair } from "./crypto.js";
import { AuditLog } from "./audit.js";
import { evaluateCanary, buildCanaryRequest, signCanaryReceipt, verifyCanaryReceipt } from "./canary.js";
import { transition } from "./machine.js";
import { evaluatePolicy, loadPolicyFile, type PolicyFacts } from "./policy.js";
import { AccessProxy, deniedResponse } from "./quarantine.js";
import { RestPaymentSink } from "./transports/rest.js";
import { SftpInbox } from "./transports/sftp.js";
import type {
  CanaryReceipt,
  Challenge,
  Clock,
  ConnectionRequirement,
  Link,
  LinkState,
  Org,
  PolicyDecision,
  PolicyDocument,
  RestorationClaim,
  SealedAuditTrace,
  SignedEnvelope,
  TransportRequest,
  TransportResponse,
} from "./types.js";
import { GateError } from "./types.js";

export interface GateOptions {
  clock: Clock;
  demo?: boolean;
}

export class ReLinkGate {
  readonly orgs = new Map<string, Org>();
  readonly keys = new Map<string, KeyPair>();
  readonly links = new Map<string, Link>();
  readonly claims = new Map<string, SignedEnvelope<RestorationClaim>>();
  readonly challenges = new Map<string, Challenge>();
  readonly policies = new Map<string, PolicyDocument>();
  readonly revokedClaimIds = new Set<string>();
  readonly restSink = new RestPaymentSink();
  readonly sftpInbox = new SftpInbox();
  readonly audit: AuditLog;
  readonly proxy: AccessProxy;
  readonly clock: Clock;
  private sealed: SealedAuditTrace | undefined;

  constructor(options: GateOptions) {
    this.clock = options.clock;
    this.audit = new AuditLog(options.clock);
    this.proxy = new AccessProxy(options.clock);
  }

  registerOrg(org: Org, keys: KeyPair): void {
    this.orgs.set(org.id, org);
    this.keys.set(org.id, keys);
    this.audit.append({
      type: "org.registered",
      actorOrgId: org.id,
      detail: { name: org.name, role: org.role, keyId: org.keyId },
    });
  }

  registerPolicy(policy: PolicyDocument): void {
    this.policies.set(policy.id, policy);
  }

  loadBundledPolicies(): void {
    this.registerPolicy(loadPolicyFile("rest-payments.policy.json"));
    this.registerPolicy(loadPolicyFile("sftp-settlement.policy.json"));
  }

  registerLink(link: Omit<Link, "state" | "rampStageIndex"> & { cutReason: string }): Link {
    const full: Link = {
      ...link,
      state: "cut",
      rampStageIndex: 0,
    };
    this.links.set(full.id, full);
    this.audit.append({
      type: "link.cut",
      actorOrgId: full.relyingOrgId,
      linkId: full.id,
      toState: "cut",
      detail: { kind: full.kind, reason: full.cutReason, name: full.name },
    });
    return full;
  }

  getLink(linkId: string): Link {
    const link = this.links.get(linkId);
    if (!link) {
      throw new GateError("UNKNOWN_LINK", `No link ${linkId}`);
    }
    return link;
  }

  issueChallenge(linkId: string, issuedByOrgId: string, ttlSeconds = 300): Challenge {
    const link = this.getLink(linkId);
    const challenge: Challenge = {
      challengeId: `chg_${randomBytes(8).toString("hex")}`,
      linkId,
      issuedByOrgId,
      issuedAt: iso(this.clock),
      expiresAt: addSeconds(this.clock, ttlSeconds),
      nonce: randomBytes(16).toString("hex"),
      requiredAssertions: link.requirements.requiredAssertions,
      canary: link.requirements.canary,
    };
    this.challenges.set(challenge.challengeId, challenge);
    link.activeChallengeId = challenge.challengeId;
    this.audit.append({
      type: "challenge.issued",
      actorOrgId: issuedByOrgId,
      linkId,
      detail: {
        challengeId: challenge.challengeId,
        requiredAssertions: challenge.requiredAssertions,
        canarySink: challenge.canary.sink,
      },
    });
    return challenge;
  }

  createClaim(
    linkId: string,
    issuerOrgId: string,
    assertions: RestorationClaim["assertions"],
    challengeId?: string,
  ): SignedEnvelope<RestorationClaim> {
    const link = this.getLink(linkId);
    const keys = this.requireKeys(issuerOrgId);
    const signed = issueClaim(
      {
        linkId,
        issuerOrgId,
        audienceOrgId: link.relyingOrgId,
        assertions,
        challengeId,
        ttlSeconds: link.requirements.claimTtlSeconds,
      },
      keys,
      this.clock,
    );
    this.claims.set(signed.payload.claimId, signed);
    this.audit.append({
      type: "claim.issued",
      actorOrgId: issuerOrgId,
      linkId,
      detail: {
        claimId: signed.payload.claimId,
        expiresAt: signed.payload.expiresAt,
        assertions,
        linkState: link.state,
      },
    });
    return signed;
  }

  bindClaimToChallenge(
    signed: SignedEnvelope<RestorationClaim>,
    challengeId: string,
  ): SignedEnvelope<RestorationClaim> {
    const keys = this.requireKeys(signed.payload.issuerOrgId);
    const bound = bindChallenge(signed, challengeId, keys);
    this.claims.set(bound.payload.claimId, bound);
    this.audit.append({
      type: "claim.bound",
      actorOrgId: bound.payload.issuerOrgId,
      linkId: bound.payload.linkId,
      detail: { claimId: bound.payload.claimId, challengeId },
    });
    return bound;
  }

  submitClaim(signed: SignedEnvelope<RestorationClaim>, challengeId: string): PolicyDecision {
    const link = this.getLink(signed.payload.linkId);
    const challenge = this.challenges.get(challengeId);
    if (!challenge) {
      throw new GateError("UNKNOWN_CHALLENGE", `No challenge ${challengeId}`);
    }
    if (challenge.linkId !== link.id) {
      throw new GateError("CHALLENGE_MISMATCH", "Challenge does not belong to this link");
    }

    if (link.state === "cut" || link.state === "revoked") {
      this.move(link, "claim", signed.payload.issuerOrgId, {
        claimId: signed.payload.claimId,
      });
    }

    const supplierKeys = this.requireKeys(signed.payload.issuerOrgId);
    const claimStatus = verifyClaim(signed, supplierKeys.publicKeyPem, this.clock, this.revokedClaimIds);
    const challengeExpired = Date.parse(challenge.expiresAt) <= this.clock.now().getTime();
    const nonceMatch = signed.payload.challengeId === challenge.challengeId;
    const requiredMet = link.requirements.requiredAssertions.every(
      (key) => Boolean(signed.payload.assertions[key]),
    );

    const facts: PolicyFacts = {
      claim: {
        fresh: claimStatus.fresh,
        revoked: claimStatus.revoked,
        expired: claimStatus.expired,
        issuerOrgId: signed.payload.issuerOrgId,
        audienceOrgId: signed.payload.audienceOrgId,
        linkId: signed.payload.linkId,
        assertions: signed.payload.assertions,
        challengeBound: nonceMatch && Boolean(signed.payload.challengeId),
      },
      challenge: {
        satisfied: nonceMatch && !challengeExpired && claimStatus.signatureOk,
        nonceMatch,
        expired: challengeExpired,
      },
      link: {
        kind: link.kind,
        state: link.state,
        neverSkipQuarantine: link.requirements.neverSkipQuarantine,
        requiredAssertionsMet: requiredMet,
      },
    };

    const policy = this.policies.get(link.requirements.policyId);
    if (!policy) {
      throw new GateError("UNKNOWN_POLICY", `No policy ${link.requirements.policyId}`);
    }

    let decision = evaluatePolicy(policy, facts, this.clock);
    if (decision.effect === "accept" && link.requirements.neverSkipQuarantine) {
      decision = {
        ...decision,
        effect: "quarantine",
        reason: `${decision.reason} (forced quarantine: this link never skips)`,
      };
    }

    this.audit.append({
      type: "policy.decision",
      actorOrgId: link.relyingOrgId,
      linkId: link.id,
      fromState: link.state,
      detail: {
        effect: decision.effect,
        ruleId: decision.ruleId,
        reason: decision.reason,
        claimId: signed.payload.claimId,
      },
    });

    if (decision.effect === "refuse") {
      this.move(link, link.state === "claim" ? "cut" : "revoked", link.relyingOrgId, {
        reason: decision.reason,
      });
      return decision;
    }

    link.activeClaimId = signed.payload.claimId;
    this.claims.set(signed.payload.claimId, signed);
    this.proxy.reset(link.id);

    if (decision.effect === "quarantine") {
      this.move(link, "quarantine", link.relyingOrgId, { reason: decision.reason });
    } else {
      this.move(link, "canary", link.relyingOrgId, { reason: decision.reason });
    }
    return decision;
  }

  send(linkId: string, request: TransportRequest): TransportResponse {
    const link = this.getLink(linkId);
    const stage = link.requirements.ramp.stages[link.rampStageIndex];
    const auth = this.proxy.authorize(link, request, stage);
    if (!auth.ok) {
      this.audit.append({
        type: "proxy.denied",
        actorOrgId: link.supplierOrgId,
        linkId,
        detail: { op: request.op, path: request.path, reason: auth.reason },
      });
      return deniedResponse(auth.reason);
    }

    this.proxy.record(link.id, request.bytes ?? 0);
    const response = this.dispatch(link, request);
    this.audit.append({
      type: "proxy.forwarded",
      actorOrgId: link.supplierOrgId,
      linkId,
      detail: {
        op: request.op,
        path: request.path,
        status: response.status,
        state: link.state,
        rampStage: stage?.name,
      },
    });
    return response;
  }

  runCanary(linkId: string): SignedEnvelope<CanaryReceipt> {
    const link = this.getLink(linkId);
    if (link.state !== "quarantine" && link.state !== "canary") {
      throw new GateError("CANARY_WRONG_STATE", `Cannot run canary from ${link.state}`);
    }
    const challenge = this.requireChallenge(link);
    if (link.state === "quarantine") {
      this.move(link, "canary", link.relyingOrgId, { challengeId: challenge.challengeId });
    }

    const { request } = buildCanaryRequest(link, challenge.nonce);
    const response = this.send(linkId, request);
    const receipt = evaluateCanary(link, request, response.ok, this.clock);
    const signed = signCanaryReceipt(receipt, this.requireKeys(link.relyingOrgId));

    this.audit.append({
      type: receipt.passed ? "canary.passed" : "canary.failed",
      actorOrgId: link.relyingOrgId,
      linkId,
      fromState: "canary",
      toState: receipt.passed ? "ramp" : "revoked",
      detail: {
        canaryId: receipt.canaryId,
        reason: receipt.reason,
        observed: receipt.observed,
      },
    });

    if (!receipt.passed) {
      this.rollback(linkId, receipt.reason, link.relyingOrgId);
      throw new GateError("CANARY_FAILED", receipt.reason);
    }

    verifyCanaryReceipt(signed, this.requireKeys(link.relyingOrgId).publicKeyPem);
    this.move(link, "ramp", link.relyingOrgId, { canaryId: receipt.canaryId });
    link.rampStageIndex = 0;
    this.proxy.reset(link.id);
    return signed;
  }

  advanceRamp(linkId: string): { stage: string; index: number; last: boolean } {
    const link = this.getLink(linkId);
    if (link.state !== "ramp") {
      throw new GateError("RAMP_WRONG_STATE", `Cannot ramp from ${link.state}`);
    }
    this.assertClaimStillFresh(link);
    const stages = link.requirements.ramp.stages;
    const current = stages[link.rampStageIndex];
    if (!current) {
      throw new GateError("RAMP_EMPTY", "No ramp stages");
    }
    const last = link.rampStageIndex >= stages.length - 1;
    if (!last) {
      link.rampStageIndex += 1;
      this.proxy.reset(link.id);
    }
    const next = stages[link.rampStageIndex];
    this.audit.append({
      type: last ? "ramp.complete" : "ramp.advanced",
      actorOrgId: link.relyingOrgId,
      linkId,
      fromState: "ramp",
      toState: "ramp",
      detail: {
        fromStage: current.name,
        toStage: next?.name,
        index: link.rampStageIndex,
        last,
      },
    });
    return { stage: next?.name ?? current.name, index: link.rampStageIndex, last };
  }

  revokeClaim(claimId: string, actorOrgId: string, reason: string): void {
    this.revokedClaimIds.add(claimId);
    const signed = this.claims.get(claimId);
    this.audit.append({
      type: "claim.revoked",
      actorOrgId,
      linkId: signed?.payload.linkId,
      detail: { claimId, reason },
    });
    if (signed) {
      const link = this.links.get(signed.payload.linkId);
      if (link && link.activeClaimId === claimId && link.state !== "cut" && link.state !== "revoked") {
        this.rollback(link.id, `claim ${claimId} revoked: ${reason}`, actorOrgId);
      }
    }
  }

  rollback(linkId: string, reason: string, actorOrgId?: string): Link {
    const link = this.getLink(linkId);
    const actor = actorOrgId ?? link.relyingOrgId;
    const from = link.state;
    if (from !== "revoked") {
      this.move(link, "revoked", actor, { reason, handbrake: true });
    }
    link.activeClaimId = undefined;
    this.proxy.reset(link.id);
    this.audit.append({
      type: "handbrake.pulled",
      actorOrgId: actor,
      linkId,
      fromState: from,
      toState: "revoked",
      detail: { reason },
    });
    return link;
  }

  expireIfStale(linkId: string): boolean {
    const link = this.getLink(linkId);
    if (!link.activeClaimId) {
      return false;
    }
    try {
      this.assertClaimStillFresh(link);
      return false;
    } catch (err) {
      const reason = err instanceof GateError ? err.message : String(err);
      this.rollback(linkId, reason, link.relyingOrgId);
      return true;
    }
  }

  seal(): SealedAuditTrace {
    const keys = [...this.keys.values()];
    this.audit.append({
      type: "audit.sealed",
      actorOrgId: "relink-gate",
      detail: { eventCount: this.audit.events.length },
    });
    this.sealed = this.audit.seal([...this.orgs.values()], [...this.links.values()], keys);
    return this.sealed;
  }

  lastSeal(): SealedAuditTrace | undefined {
    return this.sealed;
  }

  publicKeys(): Record<string, string> {
    const out: Record<string, string> = {};
    for (const [id, keys] of this.keys) {
      out[id] = keys.publicKeyPem;
    }
    return out;
  }

  snapshot(): { links: Array<{ id: string; state: LinkState; rampStage?: string }> } {
    return {
      links: [...this.links.values()].map((l) => ({
        id: l.id,
        state: l.state,
        rampStage: l.state === "ramp" ? l.requirements.ramp.stages[l.rampStageIndex]?.name : undefined,
      })),
    };
  }

  private dispatch(link: Link, request: TransportRequest): TransportResponse {
    if (link.kind === "rest") {
      return this.restSink.handle(request);
    }
    return this.sftpInbox.handle(request);
  }

  private move(link: Link, to: LinkState, actorOrgId: string, detail: Record<string, unknown>): void {
    const { from } = transition(link, to);
    this.audit.append({
      type: "state.transition",
      actorOrgId,
      linkId: link.id,
      fromState: from,
      toState: to,
      detail,
    });
  }

  private assertClaimStillFresh(link: Link): void {
    if (!link.activeClaimId) {
      throw new GateError("NO_CLAIM", "Link has no active restoration claim");
    }
    const signed = this.claims.get(link.activeClaimId);
    if (!signed) {
      throw new GateError("NO_CLAIM", "Active claim is missing from store");
    }
    const keys = this.requireKeys(signed.payload.issuerOrgId);
    requireFreshClaim(signed, keys.publicKeyPem, this.clock, this.revokedClaimIds);
  }

  private requireKeys(orgId: string): KeyPair {
    const keys = this.keys.get(orgId);
    if (!keys) {
      throw new GateError("UNKNOWN_ORG", `No keys for ${orgId}`);
    }
    return keys;
  }

  private requireChallenge(link: Link): Challenge {
    if (!link.activeChallengeId) {
      throw new GateError("NO_CHALLENGE", "No active partner challenge");
    }
    const challenge = this.challenges.get(link.activeChallengeId);
    if (!challenge) {
      throw new GateError("NO_CHALLENGE", "Challenge missing");
    }
    if (Date.parse(challenge.expiresAt) <= this.clock.now().getTime()) {
      throw new GateError("CHALLENGE_EXPIRED", "Partner challenge TTL elapsed");
    }
    return challenge;
  }
}

export function restRequirements(): ConnectionRequirement {
  return {
    requiredAssertions: ["incidentClosed", "keysRotated", "malwareCleared", "changeWindowApproved"],
    claimTtlSeconds: 900,
    requireChallenge: true,
    neverSkipQuarantine: true,
    requireCanary: true,
    canary: {
      kind: "payment",
      expectedAmount: 1,
      currency: "EUR",
      sink: "northwind-canary-sink",
    },
    quarantine: {
      allowedOps: ["rest.payment.canary", "rest.health"],
      maxRequestsPerWindow: 2,
      windowMs: 60_000,
      maxBytes: 4096,
    },
    ramp: {
      stages: [
        {
          name: "probe",
          throughputPerWindow: 3,
          allowedOps: ["rest.payment.canary", "rest.health", "rest.payment.small"],
          maxAmount: 10,
        },
        {
          name: "limited",
          throughputPerWindow: 8,
          allowedOps: ["rest.payment.canary", "rest.health", "rest.payment.small", "rest.payment.create"],
          maxAmount: 500,
        },
        {
          name: "standard",
          throughputPerWindow: 32,
          allowedOps: ["*"],
          maxAmount: 100_000,
        },
      ],
    },
    policyId: "rest-payments-reopen",
  };
}

export function sftpRequirements(): ConnectionRequirement {
  return {
    requiredAssertions: ["incidentClosed", "keysRotated", "malwareCleared", "inboxRebuilt"],
    claimTtlSeconds: 900,
    requireChallenge: true,
    neverSkipQuarantine: true,
    requireCanary: true,
    canary: {
      kind: "settlement-file",
      expectedAmount: 1,
      currency: "EUR",
      sink: "northwind-settlement-canary",
      pathPrefix: "/quarantine/canary/",
    },
    quarantine: {
      allowedOps: ["sftp.put.canary", "sftp.list.quarantine"],
      maxRequestsPerWindow: 2,
      windowMs: 60_000,
      maxBytes: 8192,
    },
    ramp: {
      stages: [
        {
          name: "probe",
          throughputPerWindow: 2,
          allowedOps: ["sftp.put.canary", "sftp.list.quarantine"],
          maxAmount: 1,
        },
        {
          name: "limited",
          throughputPerWindow: 6,
          allowedOps: ["sftp.put.canary", "sftp.put.settlement", "sftp.list"],
          maxAmount: 50,
        },
        {
          name: "standard",
          throughputPerWindow: 24,
          allowedOps: ["*"],
          maxAmount: 10_000,
        },
      ],
    },
    policyId: "sftp-settlement-reopen",
  };
}
