# Contributing to ReLink Gate

Thanks for helping make reconnection an **executable proof** instead of a PDF and a phone call.

## Ground rules

- This repository is a **lab / institutional-pilot** protocol, not a bank product.
- Do not add language that claims regulatory certification, production readiness for live payment rails, or replacement of human/legal judgment.
- Keep transports simulated unless you are adding a clearly marked experimental adapter.
- Every state change must be append-only on the audit log (hash chain).

## Dev setup

```bash
git clone https://github.com/Ovarixia/relink-gate.git
cd relink-gate
npm install
npm test
npm run demo
```

Node 20.10+ is required (Ed25519 via `node:crypto`).

## Project map

| Path | Role |
| --- | --- |
| `src/gate.ts` | Orchestrator: claim → challenge → policy → proxy → canary → ramp → revoke |
| `src/machine.ts` | Allowed state transitions |
| `src/policy.ts` | Deterministic first-match policy engine |
| `policies/` | Example JSON policies for REST and SFTP links |
| `src/quarantine.ts` | Access proxy / handbrake |
| `src/canary.ts` | Signed canary transaction |
| `src/audit.ts` | Hash-chained, dual-signed audit trace |
| `src/demo.ts` | Two-org reconnection demo |
| `test/` | Node test runner (`tsx --test`) |

## Adding a policy

1. Copy an existing file in `policies/`.
2. Keep `defaultEffect` as `"refuse"`.
3. Put refuse rules **before** quarantine/accept rules (first match wins).
4. Never add a rule that skips quarantine for a high-value link unless `neverSkipQuarantine` is false **and** the demo/docs say so.
5. Cover the new policy with a test in `test/policy.test.ts`.

Condition paths are dotted lookups into the fact document (`claim.fresh`, `link.requiredAssertionsMet`, …). Operators: `eq`, `neq`, `gt`, `gte`, `lt`, `lte`, `in`, `truthy`, `falsy`. Combine with `when.all` / `when.any`.

## Adding a connection requirement

Requirements are **per link**, not global. If a REST payment ingest and an SFTP drop need different assertions or canary sinks, they must not share a single checklist. See `restRequirements()` and `sftpRequirements()` in `src/gate.ts`.

## Tests

```bash
npm test
npm run typecheck
npm run ci          # typecheck + tests + demo + audit verify
```

Please add a failing test before a behavior change.

## Pull requests

- Small, reviewable diffs.
- Update README non-claims if you change the threat model or scope.
- Do not commit `node_modules/`, `dist/`, or generated `artifacts/` from a local demo (CI uploads those separately).
