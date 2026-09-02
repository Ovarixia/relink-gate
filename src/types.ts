/** Link lifecycle. Every transition is recorded on the audit chain. */
export type LinkState =
  | "cut"
  | "claim"
  | "quarantine"
  | "canary"
  | "ramp"
  | "revoked";

export type PolicyEffect = "accept" | "refuse" | "quarantine";

export type TransportKind = "rest" | "sftp";

export interface Org {
  id: string;
  name: string;
  role: "relying-party" | "supplier";
  keyId: string;
  publicKeyPem: string;
}

export interface ConnectionRequirement {
  /** What must be true to reopen THIS link — not a generic checklist. */
  requiredAssertions: string[];
  claimTtlSeconds: number;
  requireChallenge: boolean;
  neverSkipQuarantine: boolean;
  requireCanary: boolean;
  canary: CanarySpec;
  quarantine: QuarantineSpec;
  ramp: RampSpec;
  policyId: string;
}

export interface CanarySpec {
  kind: "payment" | "settlement-file";
  expectedAmount: number;
  currency: string;
  sink: string;
  pathPrefix?: string;
}

export interface QuarantineSpec {
  allowedOps: string[];
  maxRequestsPerWindow: number;
  windowMs: number;
  maxBytes: number;
}

export interface RampStage {
  name: string;
  throughputPerWindow: number;
  allowedOps: string[];
  maxAmount: number;
}

export interface RampSpec {
  stages: RampStage[];
}

export interface Link {
  id: string;
  name: string;
  kind: TransportKind;
  supplierOrgId: string;
  relyingOrgId: string;
  state: LinkState;
  requirements: ConnectionRequirement;
  activeClaimId?: string;
  activeChallengeId?: string;
  rampStageIndex: number;
  cutReason?: string;
}

export interface RestorationClaim {
  claimId: string;
  linkId: string;
  issuerOrgId: string;
  audienceOrgId: string;
  issuedAt: string;
  expiresAt: string;
  nonce: string;
  assertions: Record<string, boolean | string | number>;
  challengeId?: string;
}

export interface Challenge {
  challengeId: string;
  linkId: string;
  issuedByOrgId: string;
  issuedAt: string;
  expiresAt: string;
  nonce: string;
  requiredAssertions: string[];
  canary: CanarySpec;
}

export interface SignedEnvelope<T> {
  payload: T;
  alg: "Ed25519";
  keyId: string;
  orgId: string;
  signature: string;
}

export interface PolicyCondition {
  path: string;
  op: "eq" | "neq" | "gt" | "gte" | "lt" | "lte" | "in" | "truthy" | "falsy";
  value?: unknown;
}

export interface PolicyRule {
  id: string;
  description: string;
  when: {
    all?: PolicyCondition[];
    any?: PolicyCondition[];
  };
  effect: PolicyEffect;
  reason: string;
}

export interface PolicyDocument {
  id: string;
  version: string;
  description: string;
  defaultEffect: PolicyEffect;
  rules: PolicyRule[];
}

export interface PolicyDecision {
  effect: PolicyEffect;
  ruleId: string;
  reason: string;
  evaluatedAt: string;
}

export interface TransportRequest {
  op: string;
  path: string;
  method?: string;
  body?: unknown;
  bytes?: number;
  amount?: number;
  labels?: string[];
}

export interface TransportResponse {
  ok: boolean;
  status: number;
  body: unknown;
  deniedReason?: string;
}

export interface CanaryReceipt {
  canaryId: string;
  linkId: string;
  kind: TransportKind;
  submittedAt: string;
  expected: CanarySpec;
  observed: {
    op: string;
    path: string;
    amount?: number;
    sink?: string;
    labels: string[];
  };
  passed: boolean;
  reason: string;
}

export interface AuditEvent {
  seq: number;
  prevHash: string;
  hash: string;
  at: string;
  type: string;
  actorOrgId: string;
  linkId?: string;
  fromState?: LinkState;
  toState?: LinkState;
  detail: Record<string, unknown>;
}

export interface AuditTrace {
  protocol: "relink-gate-audit-v1";
  demo: boolean;
  startedAt: string;
  sealedAt: string;
  orgs: Array<Pick<Org, "id" | "name" | "role" | "keyId">>;
  /** Relying-party and supplier public keys — enough to verify this file offline. */
  publicKeys: Record<string, string>;
  links: Array<Pick<Link, "id" | "name" | "kind" | "state">>;
  events: AuditEvent[];
  headHash: string;
}

export interface SealedAuditTrace {
  trace: AuditTrace;
  signatures: Array<{
    orgId: string;
    keyId: string;
    alg: "Ed25519";
    signature: string;
  }>;
}

export interface Clock {
  now(): Date;
}

export class GateError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "GateError";
    this.code = code;
  }
}
