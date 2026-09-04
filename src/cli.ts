#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { runDemo } from "./demo.js";
import { verifyAuditTrace, fingerprint } from "./audit.js";
import type { AuditTrustPolicy, SealedAuditTrace } from "./types.js";

function usage(): void {
  console.log(`ReLink Gate — executable reconnection protocol

Usage:
  relink-gate demo [artifact-dir]  Run the two-org REST+SFTP reconnection demo
  relink-gate verify [file] [trust]  Verify a sealed audit trace against external trust
  relink-gate help              Show this help

Default paths:
  audit: artifacts/reconnection-audit.json
  trust: artifacts/reconnection-audit.trust.json
`);
}

function verifyFile(path: string, trustPath: string): void {
  const sealed = JSON.parse(readFileSync(path, "utf8")) as SealedAuditTrace;
  const trust = JSON.parse(readFileSync(trustPath, "utf8")) as AuditTrustPolicy;
  const result = verifyAuditTrace(sealed, trust);
  if (!result.ok) {
    console.error(`FAIL  ${path}`);
    for (const r of result.reasons) {
      console.error(`  ${r}`);
    }
    process.exit(1);
  }
  console.log(`OK    ${path}`);
  console.log(`      trust  ${trustPath}`);
  console.log(`      events ${sealed.trace.events.length}`);
  console.log(`      head   ${sealed.trace.headHash}`);
  console.log(`      sigs   ${sealed.signatures.map((s) => s.orgId).join(", ")}`);
  console.log(`      ${result.reasons.join("; ")}`);
  console.log(`      fingerprint ${fingerprint(sealed)}`);
}

const cmd = process.argv[2] ?? "help";

if (cmd === "help" || cmd === "--help" || cmd === "-h") {
  usage();
  process.exit(0);
}

if (cmd === "demo") {
  runDemo(process.argv[3]);
} else if (cmd === "verify") {
  const file = process.argv[3] ?? "artifacts/reconnection-audit.json";
  const trust = process.argv[4] ?? "artifacts/reconnection-audit.trust.json";
  verifyFile(file, trust);
} else {
  console.error(`Unknown command: ${cmd}`);
  usage();
  process.exit(1);
}
