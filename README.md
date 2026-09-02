# ReLink Gate

**After a cyber supplier cutoff, reopening a link must be an executable proof — signed claim, partner challenge, quarantine, canary, ramp, and a handbrake — not a PDF and a call.**

ReLink Gate is a small TypeScript protocol for two simulated institutions (a relying party and a supplier) with **REST** and **SFTP** paths. It is meant for tabletop exercises and institutional pilots in a lab, not for live bank rails.

```
cut → claim → quarantine → canary → ramp
                              ↘ revoked  (stale proof, failed canary, or operator handbrake)
```

## The problem

When a supplier is cut after an incident, reconnection today is often:

1. a PDF letter (“we rotated keys, we are clean”),
2. a conference call,
3. a firewall change that restores **full** access.

That is not evidence that *this* link behaves as claimed. ReLink Gate makes reconnection a **state machine with proofs**:

| Step | What must be true |
| --- | --- |
| Connection requirements | Per-link assertions, TTL, canary sink, quarantine ops, ramp schedule |
| Restoration claim | Ed25519-signed, short TTL, revocable |
| Partner challenge | Nonce + expected canary bound into the claim |
| Policy | Deterministic JSON engine → **accept / refuse / quarantine** |
| Quarantine proxy | Allow-listed ops and rate limits — no full access at once |
| Canary | Signed transaction that must hit the claimed sink/path/amount |
| Ramp | Progressive rights and throughput |
| Handbrake | Revoke or TTL expiry rolls the link to `revoked` |
| Audit | Hash-chained, dual-signed trace of the whole reconnection |

## Run in under five minutes

Requires [Node.js](https://nodejs.org/) 20.10 or newer.

```bash
git clone https://github.com/Ovarixia/relink-gate.git
cd relink-gate
npm install
npm start
```

That single command (`npm start`) reconnects **two links** (REST payment ingest + SFTP settlement drop) between **Northwind Bank** and **Helios Payments**, then writes a verifiable audit:

- `artifacts/reconnection-audit.json` — sealed trace (hash chain + both orgs' Ed25519 signatures + public keys)
- `artifacts/reconnection-audit.txt` — human-readable summary

Verify it:

```bash
npm run verify -- artifacts/reconnection-audit.json
```

Run the tests:

```bash
npm test
```

## What the demo shows

1. Both links start **cut** after a supplier-side incident.
2. Northwind issues a **challenge** (nonce + required assertions + canary spec).
3. Helios issues a **fresh signed claim** and binds the challenge.
4. Policy evaluates to **quarantine** (never full accept on these links).
5. A production-shaped payment / settlement PUT is **denied** by the proxy.
6. A labeled **canary** is forwarded, verified, and signed.
7. Rights **ramp** probe → limited → standard.
8. The audit is **sealed** and verified.
9. Revoking the REST claim pulls the **handbrake**; SFTP is unchanged (per-link).

Policies live in [`policies/`](policies/) (`rest-payments.policy.json`, `sftp-settlement.policy.json`). First matching rule wins; default effect is `refuse`.

## Institutional-pilot framing

Use this as a **shared artifact** in a security/ops tabletop:

- “What would we require to reopen *this* ISO 20022 session / this file drop?”
- “Who signs the claim, who issues the challenge, who holds the handbrake?”
- “What does a canary look like so it cannot be confused with customer traffic?”

Bring the sealed JSON to the exercise. Re-run `npm run verify` on another laptop with this repo — no shared secret is required to check the chain and signatures (public keys travel with the trace).

A reasonable next step for a pilot is to map one real cutoff playbook onto `ConnectionRequirement` objects and walk the state machine on paper or in this lab — still without attaching live credentials.

## Honest non-claims

ReLink Gate **does not**:

- replace human, legal, or risk-committee judgment
- certify a regulatory control or constitute a SOC / PCI / DORA / NIS2 attestation
- talk to a real bank, payment switch, or SFTP daemon (REST and SFTP are **in-process simulations**)
- provide a complete zero-trust mesh, identity provider, or SIEM
- cover arbitrary protocols beyond the two simulated paths
- survive a compromised signing key (like any signature scheme)

Demo keypairs are generated at process start and thrown away. Treat audit files as lab transcripts.

## Architecture (library)

```ts
import { ReLinkGate, restRequirements } from "relink-gate";
```

`ReLinkGate` is the control plane: register orgs and links, issue challenges/claims, submit to policy, `send()` through the quarantine proxy, `runCanary()`, `advanceRamp()`, `revokeClaim()` / `rollback()`, `seal()`.

State transitions are explicit in `src/machine.ts`. Illegal hops throw.

## Development

```bash
npm run typecheck
npm test
npm run ci          # typecheck + tests + demo + verify
```

See [CONTRIBUTING.md](CONTRIBUTING.md). License: [MIT](LICENSE). Vulnerability reports: [SECURITY.md](SECURITY.md).

---

## Français (court)

**ReLink Gate** : après une coupure cyber d’un fournisseur, **rouvrir un lien** doit être une **preuve exécutable** (revendication signée, défi partenaire, quarantaine, canari, montée en charge, frein d’urgence) — pas un PDF et un appel.

Deux organisations simulées (banque vs. processeur), chemins **REST** et **SFTP**. En moins de cinq minutes :

```bash
npm install
npm start
```

La démo écrit une trace d’audit signée dans `artifacts/reconnection-audit.json`. Ce n’est **pas** un déploiement bancaire, **pas** une certification réglementaire, et cela **ne remplace pas** le jugement humain ou juridique.
