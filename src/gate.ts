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
import { normalizeTransportRequest } from "./transports/request.js";
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
  AuditTrustPolicy,
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
  private readonly orgs = new Map<string, Org>();
  private readonly keys = new Map<string, KeyPair>();
  private readonly links = new Map<string, Link>();
  private readonly claims = new Map<string, SignedEnvelope<RestorationClaim>>();
  private readonly challenges = new Map<string, Challenge>();
  private readonly policies = new Map<string, PolicyDocument>();
  private readonly revokedClaimIds = new Set<string>();
  readonly restSink = new RestPaymentSink();
  readonly sftpInbox = new SftpInbox();
  private readonly audit: AuditLog;
  private readonly proxy: AccessProxy;
  readonly clock: Clock;
  private readonly demo: boolean;
  private sealed: SealedAuditTrace | undefined;

  constructor(options: GateOptions) {
    this.clock = options.clock;
    this.demo = options.demo === true;
    this.audit = new AuditLog(options.clock);
    this.proxy = new AccessProxy(options.clock);
  }

  registerOrg(org: Org, keys: KeyPair): void {
    if (
      keys.orgId !== org.id ||
      keys.keyId !== org.keyId ||
      keys.publicKeyPem !== org.publicKeyPem
    ) {
      throw new GateError("ORG_KEY_MISMATCH", `Key material does not match organization ${org.id}`);
    }
    this.orgs.set(org.id, structuredClone(org));
    this.keys.set(org.id, { ...keys });
    this.audit.append({
      type: "org.registered",
      actorOrgId: org.id,
      detail: { name: org.name, role: org.role, keyId: org.keyId },
    });
  }

  registerPolicy(policy: PolicyDocument): void {
    this.policies.set(policy.id, structuredClone(policy));
  }

  loadBundledPolicies(): void {
    this.registerPolicy(loadPolicyFile("rest-payments.policy.json"));
    this.registerPolicy(loadPolicyFile("sftp-settlement.policy.json"));
  }

  registerLink(link: Omit<Link, "state" | "rampStageIndex"> & { cutReason: string }): Link {
    const supplier = this.requireOrg(link.supplierOrgId);
    const relying = this.requireOrg(link.relyingOrgId);
    if (supplier.role !== "supplier" || relying.role !== "relying-party") {
      throw new GateError("LINK_PARTICIPANT_ROLE", "Link participants have incompatible roles");
    }
    const full: Link = {
      ...structuredClone(link),
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
    return structuredClone(full);
  }

  getLink(linkId: string): Link {
    return structuredClone(this.requireLink(linkId));
  }

  private requireLink(linkId: string): Link {
    const link = this.links.get(linkId);
    if (!link) {
      throw new GateError("UNKNOWN_LINK", `No link ${linkId}`);
    }
    return link;
  }

  issueChallenge(linkId: string, issuedByOrgId: string, ttlSeconds = 300): Challenge {
    const link = this.requireLink(linkId);
    if (issuedByOrgId !== link.relyingOrgId) {
      throw new GateError("CHALLENGE_ISSUER", "Only the link's relying party can issue its challenge");
    }
    if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds <= 0 || ttlSeconds > 300) {
      throw new GateError("CHALLENGE_TTL", "Challenge TTL must be an integer from 1 to 300 seconds");
    }
    const challenge: Challenge = {
      challengeId: `chg_${randomBytes(8).toString("hex")}`,
      linkId,
      issuedByOrgId,
      issuedAt: iso(this.clock),
      expiresAt: addSeconds(this.clock, ttlSeconds),
      nonce: randomBytes(16).toString("hex"),
      requiredAssertions: [...link.requirements.requiredAssertions],
      canary: structuredClone(link.requirements.canary),
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
    return structuredClone(challenge);
  }

  createClaim(
    linkId: string,
    issuerOrgId: string,
    assertions: RestorationClaim["assertions"],
    challengeId?: string,
  ): SignedEnvelope<RestorationClaim> {
    this.requireDemoSigning();
    const link = this.requireLink(linkId);
    if (issuerOrgId !== link.supplierOrgId) {
      throw new GateError("CLAIM_ISSUER", "Only the link's supplier can issue its restoration claim");
    }
    const challenge = this.requireChallengeById(link, challengeId);
    const keys = this.requireKeys(issuerOrgId);
    const signed = issueClaim(
      {
        linkId,
        issuerOrgId,
        audienceOrgId: link.relyingOrgId,
        assertions,
        challengeId: challenge.challengeId,
        challengeNonce: challenge.nonce,
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
    this.requireDemoSigning();
    const link = this.requireLink(signed.payload.linkId);
    if (signed.payload.issuerOrgId !== link.supplierOrgId) {
      throw new GateError("CLAIM_ISSUER", "Only the link's supplier can bind its restoration claim");
    }
    this.assertEnvelopeIdentity(link, signed);
    const keys = this.requireKeys(signed.payload.issuerOrgId);
    requireFreshClaim(
      signed,
      keys.publicKeyPem,
      this.clock,
      this.revokedClaimIds,
      link.requirements.claimTtlSeconds,
    );
    const challenge = this.requireChallengeById(link, challengeId);
    const bound = bindChallenge(signed, challengeId, challenge.nonce, keys);
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
    const link = this.requireLink(signed.payload.linkId);
    if (link.state !== "cut" && link.state !== "revoked") {
      throw new GateError("CLAIM_WRONG_STATE", `Cannot submit a claim from ${link.state}`);
    }
    const { challenge, status: claimStatus } = this.assertClaimForLink(
      link,
      signed,
      challengeId,
      true,
    );
    this.move(link, "claim", signed.payload.issuerOrgId, {
      claimId: signed.payload.claimId,
    });
    const requiredMet = link.requirements.requiredAssertions.every(
      (key) => signed.payload.assertions[key] === true,
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
        challengeBound: true,
      },
      challenge: {
        satisfied: true,
        nonceMatch: true,
        expired: false,
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
      this.move(link, "cut", link.relyingOrgId, {
        reason: decision.reason,
      });
      link.activeChallengeId = undefined;
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
    const link = this.requireLink(linkId);
    if (link.state === "quarantine" || link.state === "canary" || link.state === "ramp") {
      try {
        this.assertClaimStillFresh(link, link.state !== "ramp");
      } catch (error) {
        const reason = error instanceof Error ? error.message : String(error);
        this.rollback(link.id, reason, link.relyingOrgId);
        return deniedResponse(`handbrake: ${reason}`);
      }
    }
    let normalized: TransportRequest;
    try {
      normalized = normalizeTransportRequest(link, request);
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      this.audit.append({
        type: "proxy.denied",
        actorOrgId: link.supplierOrgId,
        linkId,
        detail: { op: request.op, path: request.path, reason },
      });
      return deniedResponse(reason);
    }
    if (link.kind === "sftp" &&
        (normalized.op === "sftp.get" || normalized.op === "sftp.list" || normalized.op === "sftp.list.quarantine")) {
      const projectedResponseBytes = this.sftpInbox.projectedResponseBytes(normalized);
      const projectedTransferBytes = (normalized.bytes ?? 0) + projectedResponseBytes;
      normalized = { ...normalized, bytes: projectedTransferBytes };
    }
    const stage = link.requirements.ramp.stages[link.rampStageIndex];
    const auth = this.proxy.authorize(link, normalized, stage);
    if (!auth.ok) {
      this.audit.append({
        type: "proxy.denied",
        actorOrgId: link.supplierOrgId,
        linkId,
        detail: { op: normalized.op, path: normalized.path, reason: auth.reason },
      });
      return deniedResponse(auth.reason);
    }

    this.proxy.record(link.id, normalized.bytes ?? 0);
    const response = this.dispatch(link, normalized);
    this.audit.append({
      type: "proxy.forwarded",
      actorOrgId: link.supplierOrgId,
      linkId,
      detail: {
        op: normalized.op,
        path: normalized.path,
        status: response.status,
        state: link.state,
        rampStage: stage?.name,
      },
    });
    return response;
  }

  runCanary(linkId: string): SignedEnvelope<CanaryReceipt> {
    const link = this.requireLink(linkId);
    if (link.state !== "quarantine" && link.state !== "canary") {
      throw new GateError("CANARY_WRONG_STATE", `Cannot run canary from ${link.state}`);
    }
    let challenge: Challenge;
    try {
      this.assertClaimStillFresh(link, true);
      challenge = this.requireChallenge(link);
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      this.rollback(link.id, reason, link.relyingOrgId);
      throw error;
    }
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
    const link = this.requireLink(linkId);
    if (link.state !== "ramp") {
      throw new GateError("RAMP_WRONG_STATE", `Cannot ramp from ${link.state}`);
    }
    try {
      this.assertClaimStillFresh(link, false);
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      this.rollback(link.id, reason, link.relyingOrgId);
      throw error;
    }
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
    const link = this.requireLink(linkId);
    const actor = actorOrgId ?? link.relyingOrgId;
    const from = link.state;
    if (from !== "revoked") {
      this.move(link, "revoked", actor, { reason, handbrake: true });
    }
    link.activeClaimId = undefined;
    link.activeChallengeId = undefined;
    this.proxy.reset(link.id);
    this.audit.append({
      type: "handbrake.pulled",
      actorOrgId: actor,
      linkId,
      fromState: from,
      toState: "revoked",
      detail: { reason },
    });
    return structuredClone(link);
  }

  expireIfStale(linkId: string): boolean {
    const link = this.requireLink(linkId);
    if (!link.activeClaimId) {
      return false;
    }
    try {
      this.assertClaimStillFresh(link, link.state !== "ramp");
      return false;
    } catch (err) {
      const reason = err instanceof GateError ? err.message : String(err);
      this.rollback(linkId, reason, link.relyingOrgId);
      return true;
    }
  }

  seal(): SealedAuditTrace {
    const participantIds = new Set(
      [...this.links.values()].flatMap((link) => [link.relyingOrgId, link.supplierOrgId]),
    );
    const orgs = [...participantIds].map((orgId) => this.requireOrg(orgId));
    const keys = [...participantIds].map((orgId) => this.requireKeys(orgId));
    const links = [...this.links.values()];
    this.audit.append({
      type: "audit.sealed",
      actorOrgId: "relink-gate",
      detail: { eventCount: this.audit.events.length },
    });
    this.sealed = this.audit.seal(orgs, links, keys, this.demo);
    return structuredClone(this.sealed);
  }

  lastSeal(): SealedAuditTrace | undefined {
    return this.sealed ? structuredClone(this.sealed) : undefined;
  }

  auditTrustPolicy(): AuditTrustPolicy {
    const participantIds = new Set(
      [...this.links.values()].flatMap((link) => [link.relyingOrgId, link.supplierOrgId]),
    );
    return {
      protocol: "relink-gate-audit-trust-v1",
      requiredSigners: [...participantIds].map((orgId) => {
        const org = this.requireOrg(orgId);
        return {
          orgId,
          role: org.role,
          keyId: org.keyId,
          alg: "Ed25519",
          publicKeyPem: org.publicKeyPem,
        };
      }),
    };
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

  private assertClaimStillFresh(link: Link, requireChallengeFresh: boolean): void {
    if (!link.activeClaimId) {
      throw new GateError("NO_CLAIM", "Link has no active restoration claim");
    }
    const signed = this.claims.get(link.activeClaimId);
    if (!signed) {
      throw new GateError("NO_CLAIM", "Active claim is missing from store");
    }
    this.assertClaimForLink(
      link,
      signed,
      link.activeChallengeId,
      requireChallengeFresh,
    );
  }

  private assertClaimForLink(
    link: Link,
    signed: SignedEnvelope<RestorationClaim>,
    challengeId: string | undefined,
    requireChallengeFresh: boolean,
  ): { challenge: Challenge; status: ReturnType<typeof verifyClaim> } {
    this.assertEnvelopeIdentity(link, signed);
    if (!challengeId || challengeId !== link.activeChallengeId) {
      throw new GateError("CHALLENGE_NOT_ACTIVE", "Claim is not bound to the active challenge");
    }
    const challenge = this.requireChallengeById(link, challengeId, requireChallengeFresh);
    if (
      signed.payload.challengeId !== challenge.challengeId ||
      signed.payload.challengeNonce !== challenge.nonce
    ) {
      throw new GateError("CHALLENGE_BINDING", "Claim challenge ID or nonce does not match");
    }
    const supplierKeys = this.requireKeys(link.supplierOrgId);
    const status = verifyClaim(
      signed,
      supplierKeys.publicKeyPem,
      this.clock,
      this.revokedClaimIds,
      link.requirements.claimTtlSeconds,
    );
    requireFreshClaim(
      signed,
      supplierKeys.publicKeyPem,
      this.clock,
      this.revokedClaimIds,
      link.requirements.claimTtlSeconds,
    );
    return { challenge, status };
  }

  private assertEnvelopeIdentity(link: Link, signed: SignedEnvelope<RestorationClaim>): void {
    const supplier = this.requireOrg(link.supplierOrgId);
    if (signed.payload.linkId !== link.id) {
      throw new GateError("CLAIM_LINK", "Restoration claim targets another link");
    }
    if (signed.payload.issuerOrgId !== link.supplierOrgId) {
      throw new GateError("CLAIM_ISSUER", "Restoration claim issuer is not the link supplier");
    }
    if (signed.payload.audienceOrgId !== link.relyingOrgId) {
      throw new GateError("CLAIM_AUDIENCE", "Restoration claim audience is not the relying party");
    }
    if (
      signed.orgId !== link.supplierOrgId ||
      signed.keyId !== supplier.keyId ||
      signed.alg !== "Ed25519"
    ) {
      throw new GateError("CLAIM_ENVELOPE", "Signed envelope metadata does not match the supplier key");
    }
  }

  private requireKeys(orgId: string): KeyPair {
    const keys = this.keys.get(orgId);
    if (!keys) {
      throw new GateError("UNKNOWN_ORG", `No keys for ${orgId}`);
    }
    return keys;
  }

  private requireOrg(orgId: string): Org {
    const org = this.orgs.get(orgId);
    if (!org) {
      throw new GateError("UNKNOWN_ORG", `No organization ${orgId}`);
    }
    return org;
  }

  private requireDemoSigning(): void {
    if (!this.demo) {
      throw new GateError(
        "DEMO_SIGNING_DISABLED",
        "Gate-managed claim signing is disabled; the supplier must sign with caller-owned keys",
      );
    }
  }

  private requireChallengeById(
    link: Link,
    challengeId: string | undefined,
    requireFresh = true,
  ): Challenge {
    if (!challengeId) {
      throw new GateError("NO_CHALLENGE", "No partner challenge supplied");
    }
    if (challengeId !== link.activeChallengeId) {
      throw new GateError("CHALLENGE_NOT_ACTIVE", "Challenge is not active for this link");
    }
    const challenge = this.challenges.get(challengeId);
    if (!challenge) {
      throw new GateError("UNKNOWN_CHALLENGE", `No challenge ${challengeId}`);
    }
    if (challenge.linkId !== link.id || challenge.issuedByOrgId !== link.relyingOrgId) {
      throw new GateError("CHALLENGE_MISMATCH", "Challenge participants do not match the link");
    }
    const issuedAt = Date.parse(challenge.issuedAt);
    const expiresAt = Date.parse(challenge.expiresAt);
    const now = this.clock.now().getTime();
    if (
      !Number.isFinite(issuedAt) ||
      !Number.isFinite(expiresAt) ||
      issuedAt > now ||
      expiresAt <= issuedAt ||
      expiresAt - issuedAt > 300_000
    ) {
      throw new GateError("CHALLENGE_TIME_INVALID", "Partner challenge has an invalid time window");
    }
    if (requireFresh && expiresAt <= now) {
      throw new GateError("CHALLENGE_EXPIRED", "Partner challenge TTL elapsed");
    }
    return challenge;
  }

  private requireChallenge(link: Link): Challenge {
    return this.requireChallengeById(link, link.activeChallengeId, true);
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
