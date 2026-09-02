# Security policy

ReLink Gate is an **open-source protocol demo**. Demo keys are ephemeral and generated at runtime. Do not load production secrets into this repository.

## What this project is not responsible for

- Live payment, settlement, or bank-core systems
- Regulatory attestations or certified controls
- Confidentiality of data you paste into issues or traces

## Reporting a vulnerability

Please **do not** open a public issue for a security defect.

1. Use GitHub's private [Security Advisories](https://github.com/Ovarixia/relink-gate/security/advisories/new) if you have access.
2. Otherwise email the maintainers listed on the GitHub org/profile with:
   - a description of the issue
   - affected versions / commit
   - a minimal reproduction **without** exploit payloads against third-party systems
   - any idea of impact (e.g. audit-trace forgery, quarantine bypass in the simulated proxy)

We will acknowledge the report and work on a fix in a private branch when the issue is in this codebase.

## Demo hygiene

- Treat `artifacts/reconnection-audit.json` as a **lab transcript**. It contains public keys generated for that run, not production identities.
- If you fork this for an institutional tabletop, generate new keys and keep private keys off the audit file (this demo intentionally publishes public keys so the trace is independently verifiable).
