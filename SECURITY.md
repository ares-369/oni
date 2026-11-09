# ONIOPS Security & Threat Model (`v0.3.1-beta`)

ONIOPS is an offensive security platform **and** an LLM-driven application that executes commands on an attack host. It is built to the same security standards it tests against. This document defines ONIOPS's **Threat Model**, **Deterministic Trust Boundaries**, **Cryptographic Evidence Provenance**, and **Framework Alignment**.

## Reporting a Vulnerability
Thank you for helping keep ONIOPS and its users safe. Please open a private security advisory at `https://github.com/ares-369/oniops/security/advisories/new` (or contact `@ares-369` via GitHub) rather than a public issue for exploitable bugs.

ONIOPS is maintained by one person in spare time, so responses are best-effort — I will aim to acknowledge a report within a week and keep you updated on a fix. Reporters are credited in the changelog unless they prefer otherwise.

---

## 1. Core Architectural Principle: Deterministic Policy, Probabilistic Reasoning

The LLM is **never** the authority that decides whether a target is in scope, whether a command is safe to execute, or whether a vulnerability is verified.

```text
[LLM Planner / Agent]  --(proposes JSON action)-->  [Deterministic Scope & Command Guard (oniops/scope.py)]
                                                              │
                                                              ▼
[Independent Validator (oniops/findings.py)]  <--(raw stdout)-- [SSH / Local Execution Plane (oniops/kali.py)]
        │
        ▼
[Secret Redaction + SHA-256 Evidence Hash + <untrusted_tool_output> Quarantine]
```

### Trust Boundaries & Defenses
1. **Strict Scope Allow-List (`oniops/scope.py`):**
   - ONIOPS refuses any target outside `scope.allowed_cidrs` and `scope.allowed_hosts`. Excluded hosts/CIDRs (`scope.exclude`) always take precedence.
   - `Scope.guard_command()` inspects every raw command string for IPv4 literals and blocks execution if any IP falls outside the authorized scope.
2. **Non-Destructive Command Guard (`oniops/scope.py`):**
   - Blocks destructive shell patterns, fork bombs, filesystem wipes (`rm -rf`, `mkfs`, `dd`), and unapproved exploitation flags before they reach the SSH channel.
   - Commands are constructed as explicit `argv` lists and quoted with `shlex.join()` — never raw string interpolation.
3. **Indirect Prompt-Injection Quarantine (`oniops/agent.py`):**
   - Malicious targets may embed adversarial instructions inside HTTP `Server` headers, HTML titles, or OpenAPI descriptions (e.g., `Ignore all previous instructions...` or `<|im_start|>system`).
   - `quarantine_output()` strips known prompt-injection directives, condenses noisy scanner output (`<= 2,200` chars), masks credentials, and wraps all tool output inside `<untrusted_tool_output tool="...">...</untrusted_tool_output>` delimiters with a system boundary rule instructing the model to treat the contents strictly as passive data.
4. **Pre-LLM Secret Redaction, SHA-256 Provenance & HMAC-Signed Manifests (`oniops/findings.py`):**
   - `redact_secrets()` masks Bearer tokens, cookies, OpenAI/GitHub/AWS keys, and password assignments **before** evidence is written to SQLite and **before** telemetry is sent to any external LLM provider (`webui.py`).
   - Every finding record stores a tamper-evident `evidence_sha256` digest and a category-calibrated `confidence` level (`HIGH` / `MEDIUM` / `LOW`).
   - Every assessment produces a canonical execution manifest (`build_assessment_manifest`) signed with `HMAC-SHA256` (`signature: hmac-sha256:...`) and verifiable via `verify_assessment_manifest()`.
   - SQLite persistence runs with `PRAGMA journal_mode=WAL` and `PRAGMA busy_timeout=5000` for lock-free concurrent reads and background job writes.
5. **Independent Finding & BOLA Content Validation (`oniops/findings.py`, `oniops/greybox.py`, `oniops/agent.py`):**
   - Agent-submitted findings (`report_finding`) and scanner outputs are checked by `validate_evidence()` against live HTTP status codes and expected response indicators before being marked `VERIFIED`.
   - OpenAPI BOLA/BFLA probes (`probe_openapi`) inspect both HTTP status codes and response bodies (`validate_bola_response_content`), automatically filtering out `HTTP 200` HTML login shells and empty JSON (`{}`, `[]`) stubs.
6. **Authentication, 3-Tier RBAC, Rate-Limiting & CSRF Guard (`oniops/auth.py`):**
   - Supports `none` (trusted network), `basic`, `local` (`PBKDF2-HMAC-SHA256` with **600,000** OWASP-recommended iterations), `oidc` (OpenID Connect SSO), and `proxy` (trusted reverse-proxy header with IP allow-list).
   - Enforces 3-tier Role-Based Access Control (`viewer` = read-only GETs + PDF export; `operator` = can run scans/agents/retests but cannot edit `config.yaml` or scope; `admin` = full control), a sliding-window `/login` brute-force limiter (`10 attempts / 60s` -> `HTTP 429`), and Same-Origin `Origin` CSRF validation on cookie-authenticated state-changing requests.

---

## 2. Framework Alignment

### OWASP LLM Top 10
- **LLM01 Prompt Injection** — mitigated via `quarantine_output()` regex stripping + `<untrusted_tool_output>` XML isolation + fixed 12-tool JSON action dispatcher (`oniops/agent.py`).
- **LLM02 Insecure Output Handling** — model output is rendered with HTML-escaped Markdown; model text is never passed to `eval`, `exec`, or a shell.
- **LLM06 Sensitive Information Disclosure** — API keys live in `.env` / `secrets/` (git-ignored), config responses redact secret fields, and `redact_secrets()` scrubs tool output prior to LLM reporting.
- **LLM08 Excessive Agency** — the autonomous agent can only invoke 12 registered reconnaissance/validation tools on in-scope targets.
- **LLM10 Unbounded Consumption** — per-command timeouts, 12-step agent budget cap, and cooperative job `pause`/`resume`/`cancel` controls (`oniops/jobs.py`).

### MITRE ATLAS & NIST AI RMF
- ONIOPS's AI red-team module (`oniops/aisec.py`) maps 14 built-in single-turn probes, 6 prompt converters, 3-turn Crescendo escalation, and declarative YAML probe packs (`playbooks/ai_probes/*.yaml`) to **OWASP LLM Top 10**, **MITRE ATLAS**, **NIST AI RMF**, and **Google SAIF / ISO 42001**.

---

## 3. Remaining Operational Considerations
- **Transport Encryption:** ONIOPS serves HTTP via Waitress; always place it behind a TLS-terminating reverse proxy (Nginx, Caddy, Traefik, or Nginx Proxy Manager) when exposed beyond `127.0.0.1`.
- **Attack Host Isolation:** Use a dedicated, least-privilege Kali VM or container for the SSH runner (`kali.host`) with key-based authentication and `known_hosts` verification (`tofu` or `strict`).
