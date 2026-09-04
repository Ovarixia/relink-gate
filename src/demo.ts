#!/usr/bin/env node
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyAuditTrace, fingerprint } from "./audit.js";
import { SystemClock } from "./clock.js";
import { generateOrgKeys } from "./crypto.js";
import { ReLinkGate, restRequirements, sftpRequirements } from "./gate.js";
import type { AuditTrustPolicy, RestorationClaim, TransportRequest } from "./types.js";

const NORTHWIND = "org-northwind";
const HELIOS = "org-helios";
const REST = "link-rest-payments";
const SFTP = "link-sftp-settlement";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..");

const useColor = process.env.NO_COLOR === undefined && process.stdout.isTTY;

function paint(code: string, s: string): string {
  return useColor ? `\x1b[${code}m${s}\x1b[0m` : s;
}

const c = {
  dim: (s: string) => paint("2", s),
  bold: (s: string) => paint("1", s),
  cyan: (s: string) => paint("36", s),
  green: (s: string) => paint("32", s),
  yellow: (s: string) => paint("33", s),
  red: (s: string) => paint("31", s),
  magenta: (s: string) => paint("35", s),
};

function banner(): void {
  console.log(`
${c.bold(c.cyan("ReLink Gate"))}  ${c.dim("executable reconnection — not a PDF + a call")}
${c.dim("─────────────────────────────────────────────────────────────────")}
After a cyber supplier cutoff, reopening a link is a proof:
  signed claim → partner challenge → policy → quarantine → canary → ramp
  with a handbrake that revokes the path when proofs go stale.
`);
}

function step(title: string): void {
  console.log(`\n${c.bold(c.magenta("▸"))} ${c.bold(title)}`);
}

function note(msg: string): void {
  console.log(`  ${c.dim(msg)}`);
}

function ok(msg: string): void {
  console.log(`  ${c.green("✓")} ${msg}`);
}

function no(msg: string): void {
  console.log(`  ${c.red("✗")} ${msg}`);
}

function goodAssertions(extra: Record<string, boolean> = {}): RestorationClaim["assertions"] {
  return {
    incidentClosed: true,
    keysRotated: true,
    malwareCleared: true,
    changeWindowApproved: true,
    inboxRebuilt: true,
    ...extra,
  };
}

function bootstrap(): ReLinkGate {
  const gate = new ReLinkGate({ clock: new SystemClock(), demo: true });
  const nwKeys = generateOrgKeys(NORTHWIND);
  const heKeys = generateOrgKeys(HELIOS);

  gate.registerOrg(
    {
      id: NORTHWIND,
      name: "Northwind Bank",
      role: "relying-party",
      keyId: nwKeys.keyId,
      publicKeyPem: nwKeys.publicKeyPem,
    },
    nwKeys,
  );
  gate.registerOrg(
    {
      id: HELIOS,
      name: "Helios Payments",
      role: "supplier",
      keyId: heKeys.keyId,
      publicKeyPem: heKeys.publicKeyPem,
    },
    heKeys,
  );
  gate.loadBundledPolicies();

  gate.registerLink({
    id: REST,
    name: "Helios → Northwind payment ingest (REST)",
    kind: "rest",
    supplierOrgId: HELIOS,
    relyingOrgId: NORTHWIND,
    requirements: restRequirements(),
    cutReason: "Helios SOC declared a supplier-side incident; Northwind pulled the link.",
  });
  gate.registerLink({
    id: SFTP,
    name: "Helios → Northwind daily settlement (SFTP)",
    kind: "sftp",
    supplierOrgId: HELIOS,
    relyingOrgId: NORTHWIND,
    requirements: sftpRequirements(),
    cutReason: "Same incident: settlement drop cut until executable proof exists.",
  });
  return gate;
}

function reconnectLink(gate: ReLinkGate, linkId: string): void {
  const link = gate.getLink(linkId);
  step(`${link.kind.toUpperCase()}  ${link.name}`);
  note(`state=${link.state}  required=${link.requirements.requiredAssertions.join(", ")}`);

  const challenge = gate.issueChallenge(linkId, NORTHWIND);
  ok(`Northwind issued challenge ${challenge.challengeId}`);
  note(`canary sink=${challenge.canary.sink}  nonce=${challenge.nonce.slice(0, 8)}…`);

  let claim = gate.createClaim(linkId, HELIOS, goodAssertions(), challenge.challengeId);
  claim = gate.bindClaimToChallenge(claim, challenge.challengeId);
  ok(`Helios signed restoration claim ${claim.payload.claimId} (TTL ${link.requirements.claimTtlSeconds}s)`);

  const decision = gate.submitClaim(claim, challenge.challengeId);
  if (decision.effect !== "quarantine") {
    throw new Error(`expected quarantine, got ${decision.effect}: ${decision.reason}`);
  }
  ok(`policy ${decision.ruleId} → ${c.yellow("QUARANTINE")}  ${c.dim(decision.reason)}`);

  const forbidden: TransportRequest =
    link.kind === "rest"
      ? {
          op: "rest.payment.create",
          path: "/v1/payments",
          method: "POST",
          amount: 50_000,
          bytes: 512,
          body: { kind: "production", amount: 50_000, destination: "customer-account" },
        }
      : {
          op: "sftp.put.settlement",
          path: "/inbox/settlement/2026-09-02.xml",
          amount: 50_000,
          bytes: 2048,
          body: { kind: "production", amount: 50_000, destination: "northwind-settlement" },
        };
  const blocked = gate.send(linkId, forbidden);
  if (blocked.ok) {
    throw new Error("quarantine proxy allowed full access — demo is broken");
  }
  no(`full-access attempt denied: ${blocked.deniedReason}`);

  const canary = gate.runCanary(linkId);
  ok(`signed canary ${canary.payload.canaryId}  ${canary.payload.reason}`);
  note(`observed path=${canary.payload.observed.path} amount=${canary.payload.observed.amount}`);

  const initialStage = gate.getLink(linkId).requirements.ramp.stages[0]?.name ?? "probe";
  ok(`ramp opens at ${initialStage} (restricted rights)`);
  for (;;) {
    const before = gate.getLink(linkId).rampStageIndex;
    const ramp = gate.advanceRamp(linkId);
    if (ramp.last && ramp.index === before) {
      ok(`ramp complete at ${ramp.stage}`);
      break;
    }
    ok(`ramp → ${ramp.stage} (stage ${ramp.index + 1})`);
    if (ramp.last) {
      break;
    }
  }

  const allowed: TransportRequest =
    link.kind === "rest"
      ? {
          op: "rest.payment.create",
          path: "/v1/payments",
          method: "POST",
          amount: 250,
          bytes: 320,
          body: { kind: "production", amount: 250, destination: "customer-account", reference: "post-ramp" },
        }
      : {
          op: "sftp.put.settlement",
          path: "/inbox/settlement/2026-09-02.xml",
          amount: 12,
          bytes: 1024,
          body: { kind: "production", amount: 12, destination: "northwind-settlement" },
        };
  const live = gate.send(linkId, allowed);
  if (!live.ok) {
    throw new Error(`ramped traffic denied: ${live.deniedReason}`);
  }
  ok(`post-ramp ${link.kind} traffic accepted (status ${live.status})`);
}

export function runDemo(artifactDir = join(repoRoot, "artifacts"), options?: { quiet?: boolean }): {
  auditPath: string;
  trustPath: string;
  fingerprint: string;
} {
  const log = options?.quiet ? () => undefined : console.log;
  const prevLog = console.log;
  if (options?.quiet) {
    console.log = log;
  }
  try {
    return runDemoBody(artifactDir);
  } finally {
    console.log = prevLog;
  }
}

function runDemoBody(artifactDir: string): {
  auditPath: string;
  trustPath: string;
  fingerprint: string;
} {
  banner();
  const gate = bootstrap();
  note("Two simulated institutions. REST and SFTP are in-process mocks, not bank rails.");

  reconnectLink(gate, REST);
  reconnectLink(gate, SFTP);

  step("Seal the reconnection audit");
  const sealed = gate.seal();
  const trust: AuditTrustPolicy = gate.auditTrustPolicy();
  const check = verifyAuditTrace(sealed, trust);
  if (!check.ok) {
    throw new Error(`audit verification failed: ${check.reasons.join("; ")}`);
  }
  const fp = fingerprint(sealed);
  mkdirSync(artifactDir, { recursive: true });
  const auditPath = join(artifactDir, "reconnection-audit.json");
  const trustPath = join(artifactDir, "reconnection-audit.trust.json");
  writeFileSync(auditPath, JSON.stringify(sealed, null, 2));
  writeFileSync(trustPath, JSON.stringify(trust, null, 2));
  const summaryPath = join(artifactDir, "reconnection-audit.txt");
  writeFileSync(
    summaryPath,
    [
      "ReLink Gate — sealed reconnection audit",
      `protocol: ${sealed.trace.protocol}`,
      `events:   ${sealed.trace.events.length}`,
      `head:     ${sealed.trace.headHash}`,
      `fingerprint: ${fp}`,
      `orgs:     ${sealed.trace.orgs.map((o) => o.name).join(" | ")}`,
      `links:    ${sealed.trace.links.map((l) => `${l.id}=${l.state}`).join(" | ")}`,
      `sigs:     ${sealed.signatures.map((s) => s.orgId).join(", ")}`,
      `verified: ${check.reasons.join(", ")}`,
      "",
      "Transitions:",
      ...sealed.trace.events
        .filter((e) => e.type === "state.transition" || e.type === "policy.decision" || e.type === "canary.passed")
        .map((e) => `  ${e.seq.toString().padStart(3, " ")}  ${e.at}  ${e.type}  ${e.linkId ?? ""}  ${e.fromState ?? ""}→${e.toState ?? ""}`),
    ].join("\n") + "\n",
  );

  ok(`wrote ${auditPath}`);
  ok(`wrote ${trustPath}`);
  ok(`full trace + dual Ed25519 signatures verified against external trust`);
  ok(`fingerprint ${fp}`);
  console.log(
    `\n${c.bold("Links:")} ${gate
      .snapshot()
      .links.map((l) => `${l.id} ${c.green(l.state)}${l.rampStage ? c.dim(`/${l.rampStage}`) : ""}`)
      .join("   ")}\n`,
  );

  step("Handbrake (claim revoke → rollback)");
  const rest = gate.getLink(REST);
  if (!rest.activeClaimId) {
    throw new Error("expected active REST claim");
  }
  gate.revokeClaim(rest.activeClaimId, NORTHWIND, "tabletop: operator pulled the handbrake");
  const after = gate.send(REST, {
    op: "rest.payment.create",
    path: "/v1/payments",
    amount: 10,
    bytes: 100,
    body: { kind: "production", amount: 10 },
  });
  no(`REST after revoke: ${after.deniedReason}`);
  ok(`REST state is now ${gate.getLink(REST).state}`);
  note("SFTP ramp is unchanged — revocation is per claim / per link.");

  console.log(`
${c.bold("Done.")} This is a lab / institutional-pilot protocol demo.
It does ${c.bold("not")} replace human or legal judgment, certify a control, or talk to a real bank.
Verify later with:  ${c.cyan("npm run verify -- artifacts/reconnection-audit.json artifacts/reconnection-audit.trust.json")}
`);

  return { auditPath, trustPath, fingerprint: fp };
}

const launchedDirectly = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (launchedDirectly) {
  try {
    runDemo();
  } catch (err) {
    console.error(err);
    process.exitCode = 1;
  }
}
