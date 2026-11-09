# ONIOPS Security Posture

ONIOPS is an offensive tool **and** an LLM-driven application that executes commands.
It is built to the same standards it tests against. This document maps ONIOPS's own
design to recognized security frameworks and states the current posture honestly,
including gaps.

## Reporting a vulnerability
Open a private security advisory at `https://github.com/ares-369/oniops/security/advisories/new`
(or contact `@ares-369` via GitHub). Do not file public issues for exploitable bugs.

## Secure defaults
- **Scope allow-list (Rules of Engagement):** ONIOPS refuses any target outside
  `scope.allowed_cidrs`; there is no implicit internet scope. Excludes take
  precedence.
- **Non-destructive by default:** a command guard blocks data-destruction and
  DoS patterns before they reach the attack host (`scope.non_destructive`).
- **No secrets in the repo:** keys live in `.env` / `secrets/` (git-ignored);
  only `.example` files ship.
- **No shell string interpolation:** commands are built as argv arrays over
  paramiko; package names and search terms are regex-validated.
- **Least exposure:** optional HTTP Basic auth; startup warns when the UI is on
  a non-loopback address without auth.
- **SSH host-key verification:** trust-on-first-use with a saved `known_hosts`
  (changed keys rejected); `strict` mode available.

## Framework alignment

### OWASP LLM Top 10 (ONIOPS is an LLM application)
- **LLM01 Prompt Injection** — untrusted scan/tool output is fed to the model
  for *analysis only*; the model's text is never executed. Command execution is
  limited to an explicit, bounded tool dispatcher, all scope-guarded. (Hardening
  of the interactive agent loop is tracked for the agent-loop phase.)
- **LLM02 Insecure Output Handling** — model output is rendered as text/markdown,
  not evaluated; no eval/exec of model responses.
- **LLM06 Sensitive Information Disclosure** — provider keys come from env, are
  never logged, and are not sent to other providers.
- **LLM08 Excessive Agency** — the agent can only call a fixed set of scoped,
  non-destructive tools; it cannot run arbitrary shell by itself.
- **LLM10 Unbounded Consumption** — per-command timeouts; job concurrency capped.

### MITRE ATLAS
ONIOPS's AI-target assessments map findings to ATLAS tactics/techniques; ONIOPS's own
LLM usage follows ATLAS-informed input/output mediation (treat tool output as
adversarial).

### NIST AI RMF (Govern / Map / Measure / Manage)
Scope/RoE config, audit logging of every command, and the GRC reporting module
provide Map/Measure/Manage; Govern is the operator's authorized-use policy.

### NIST SSDF (secure development)
Pinned dependencies, lazy-loaded optional SDKs, no secrets in VCS, reproducible
config, code review before release.

### Google SAIF
Secure-by-default config, least privilege to the attack host, bounded automation,
and auditability reflect SAIF's foundational controls.

### OWASP ASVS / Top 10 (the web app)
- Security headers incl. CSP; `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`.
- Input validation on targets (scope resolve), profiles (allow-list), intel
  queries, and package names.
- Optional authentication; constant-time credential comparison.

## Known gaps (current)
- **Interactive agent loop prompt-injection hardening** — pending the agent-loop
  phase; today's chat dispatcher is bounded but not yet injection-audited.
- **No CSRF tokens** — acceptable while the JSON API is token/basic-auth and
  cookieless; will be revisited if cookie sessions are added.
- **No rate limiting** on the API yet.
- **Transport** — ONIOPS serves HTTP; run it behind a TLS-terminating, authenticating
  reverse proxy for any non-loopback deployment.
