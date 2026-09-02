#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { runDemo } from "./demo.js";
import { verifyAuditTrace, fingerprint } from "./audit.js";
import type { SealedAuditTrace } from "./types.js";

function usage(): void {
  console.log(`ReLink Gate — executable reconnection protocol

Usage:
  relink-gate demo              Run the two-org REST+SFTP reconnection demo
  relink-gate verify [file]     Verify a sealed audit trace (Ed25519 + hash chain)
  relink-gate help              Show this help

Default verify path: artifacts/reconnection-audit.json
`);
}

function verifyFile(path: string): void {
  const sealed = JSON.parse(readFileSync(path, "utf8")) as SealedAuditTrace;
  const keys = sealed.trace.publicKeys ?? {};
  const result = verifyAuditTrace(sealed, keys);
  if (!result.ok) {
    console.error(`FAIL  ${path}`);
    for (const r of result.reasons) {
      console.error(`  ${r}`);
    }
    process.exit(1);
  }
  if (sealed.signatures.length < 2) {
    console.error("FAIL  expected dual signatures (both institutions)");
    process.exit(1);
  }
  console.log(`OK    ${path}`);
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
  runDemo();
} else if (cmd === "verify") {
  const file = process.argv[3] ?? "artifacts/reconnection-audit.json";
  verifyFile(file);
} else {
  console.error(`Unknown command: ${cmd}`);
  usage();
  process.exit(1);
}
