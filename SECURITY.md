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

- Treat `artifacts/reconnection-audit.json` as a **lab transcript**. Its embedded public keys are informational copies, not production identities.
- Audit v2 verification requires `artifacts/reconnection-audit.trust.json`. In a real pilot, pin and distribute that trust policy independently from the trace; accepting both from one untrusted source is self-authentication.
- Generate new keys for institutional table-tops and keep private keys outside both artifacts. Gate-managed claim signing is deliberately limited to explicit demo mode.
