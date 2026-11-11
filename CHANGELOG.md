# Changelog

All notable changes to OniOps are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). OniOps is pre-1.0 beta software, so
behaviour may still change between releases.

## [Unreleased]

## [0.4.7-beta] — 2026-11-12

### Added
- A labeled, loopback-only live fixture benchmark: `oniops benchmark --demo-evaluation`. It reports
  precision, recall, F1, negative checks, one-to-one finding matching and its explicit fixture-only
  limitations. Unverified detections do not count as true positives; duplicate alerts count as FPs.
- Optional Playwright browser discovery (`oniops crawl`) with bounded page/time budgets, in-scope
  request routing, read-only navigation and start-origin-only credential forwarding.
- Browser discovery now reports observed XHR/fetch status and content type plus value-free form
  metadata, and flags credential-like fields on GET or cleartext forms as observations.
- AWS password-policy findings now use an explicitly selected baseline. The AWS CIS-style profile
  checks composition and rotation; the NIST 800-63B-4 profile checks its single-factor length rule
  without requiring composition or periodic rotation.
- Disposable Docker worker mode for scanner commands with a non-root user, read-only filesystem,
  dropped Linux capabilities, resource limits and command timeouts; sample image in `Dockerfile.worker`.
- Docker workers now apply a fail-closed egress firewall using effective scope CIDRs, drop bootstrap
  capabilities before scanner execution, and reject built-in Docker network modes. They require a
  user-defined bridge so DNS stays on Docker's embedded resolver; IPv4-only kernels are handled
  explicitly while IPv6 scopes fail closed if IPv6 is unavailable. The bootstrap receives only the
  temporary network, UID/GID, and capability-management permissions needed before dropping them all.
- CI builds the worker image, exercises the firewall against allowed and denied container targets,
  and runs Nmap/Nuclei as a non-root user with a read-only filesystem; `.dockerignore` prevents
  unrelated workspace files from entering its build context.
- Offline Trivy scan of images already loaded on the attack host (`oniops container-scan`) and optional
  read-only AWS account/IAM, security-group, EKS endpoint and S3 policy/ACL/encryption checks
  (`oniops cloud-audit aws`).
- Semantic versions, pack metadata, nested discovery and SHA-256 source hashes for network playbooks
  and AI probe packs. See `docs/SECURITY_PACKS.md`.
- OpenAPI BOPLA analysis now follows nested local references, composition and arrays, and reads
  OpenAPI 2 body/form parameters plus OpenAPI 3 vendor JSON schemas without fetching external refs.
- Playbook tool requirements now include every executed binary. `sqlmap` and `hydra` packs require
  `safety: intrusive`, which remains disabled at assessment endpoints unless explicitly enabled in
  scope configuration.
- Scope enforcement now checks the full IPv4 CIDR and address range in nmap target arguments,
  including explicit exclusions, rather than checking only the first address.
- Network playbook steps are restricted to supported scanner commands and must include the assessed
  `{target}`, preventing a custom YAML pack from invoking arbitrary commands on the attack host.

### Fixed
- A low-privilege user's own object read no longer creates a second verified BOLA finding. Object
  ownership must be established; a peer-owned object read remains the verified horizontal BOLA proof.
- Agent finding replay now rejects non-origin-relative paths and malformed indicators, caps response
  size, disables redirects and only verifies successful command executions. Ledger write failures are
  surfaced instead of silently discarded.
- Agent-proposed findings and zero-token retests now require a supported category-specific proof rule
  and a matching claim title. A model-supplied expected string alone remains UNCONFIRMED; 5xx retests
  are also inconclusive rather than being called fixed.
- AWS security-group rules without TCP/UDP ports (such as ICMP) are no longer classified as exposing
  all ports; all-protocol and administrative-port rules retain their higher severity.

## [0.4.6-beta] — 2026-11-11

### Fixed
- **Horizontal (cross-user) BOLA on parameterised object routes was silently
  missed.** The grey-box OpenAPI probe filled every path parameter with the
  literal `1`, so a route like `/users/v1/{username}` became `/users/v1/1` — a
  non-existent object that returns 404 — and the cross-user check (which needs a
  real object) never ran. The probe now resolves a real identifier for a
  parameterised object route by mining its sibling collection endpoint
  (`/users/v1`), per identity, and falls back to the old placeholder only when
  nothing can be mined. For the horizontal cross-user check it selects an object
  the peer identity can see but the low-privilege identity does not own, then has
  the low-privilege identity request it; a 200 with the peer's object content is
  reported VERIFIED/HIGH, the replay stored as that identity (credential masked
  on display). When ownership cannot be established — for example an API that
  returns the full collection to every caller — the result is reported
  UNCONFIRMED for manual review rather than as a false positive. The zero-token
  retest treats such a finding as FIXED only when the peer-owned object is now
  denied (HTTP 403 or 404).

### Security
- **Forgeable signatures removed.** Earlier releases fell back to a built-in
  constant key (`oniops-default-manifest-key` / `oniops-webhook-key`) when no signing
  key was set, so anyone with the source could forge an assessment manifest or
  webhook signature. There is no fallback key any more. With no operator key
  configured, a manifest still carries its SHA-256 integrity hash but is marked
  `signed: false` with an `unsigned_reason`, and webhook alerts are sent with no
  signature header rather than a worthless one. `verify_assessment_manifest`
  now returns false for unsigned manifests, empty keys and the old constants;
  `manifest_verification_status` reports the reason. The web UI also no longer
  signs with Flask's per-process session key, which could never be verified
  after a restart. Set `ONIOPS_SECRET_KEY` (or `auth.secret_key`) to sign; `oniops
  doctor` now warns when no persistent key is set.
- **Retest could report a still-exploitable finding as FIXED.** Access-control
  findings (BOLA/BFLA and cross-user horizontal BOLA) are proven with a
  low-privilege or peer identity, but the zero-token retest replayed the stored
  request anonymously, got a 401, and wrongly concluded the issue was fixed. The
  retest now replays as the identity that proved the finding, and reports FIXED
  only on positive evidence that access is now denied (HTTP 403) or that the
  proof signature is gone. A credential that is simply rejected (401) yields
  UNCONFIRMED, never FIXED. Findings stored by 0.4.1–0.4.2 without their
  credential are not replayed at all; they ask for a fresh assessment. Replayed
  credentials are stored raw (a retest needs them) but masked in every display,
  export and webhook payload. SQLi/XSS/LFI/SSRF/RCE/GraphQL retests now re-run
  the proof check instead of trusting a clean exit code, and `cve`/`exploitdb`
  retests report UNCONFIRMED rather than VERIFIED on any output.
- **Scan rate limit is now enforced.** `scope.rate_limit_per_min` was shown in
  the settings screen but never applied. It now paces every command or request
  sent to a target, per target, at both the attack-host runner and the AI-probe
  HTTP path. The limit bounds launched commands/requests, not packets: one
  `nmap` or `nikto` run still sends many. On an HTTP 429 or 503 the AI-probe
  path backs off using `Retry-After` (capped at 60 seconds) or jittered
  exponential backoff, then records the probe as throttled — never as a pass —
  and the attack-host path puts a throttling target on a short cool-down.

### Added
- **`oniops demo` — a zero-setup first run.** `oniops demo` needs no config, no attack
  host, no SSH keys and no LLM. It starts a small, deliberately flawed practice
  target bound to loopback inside the process, runs the real probes and
  validators against it through a loopback-only local runner, and prints what it
  found with proof snippets, the fix-first score and a zero-token retest, then
  stops the target and deletes its temporary ledger. Everything is labelled
  DEMO and nothing is written to a real ledger or recorded as terms acceptance.
  Inspired by how projects like OWASP Juice Shop lower the barrier to a first
  run.
- **GraphQL introspection check in Web App PT.** The existing GraphQL
  introspection probe is now part of a `web_app_pt` assessment, and its finding
  can be retested.

### Fixed
- The AI security posture score no longer counts errored or throttled probes as
  passes; a run with no real answers is rated Inconclusive instead of Strong.

### Changed
- **Project renamed to OniOps.** The product and its documentation, web UI,
  generated reports and CLI help now use the name *OniOps*. The Python package,
  the `oniops` command, install paths and the systemd unit are unchanged, so
  existing deployments keep working. The repository moved to
  `github.com/ares-369/oniops` (the old URL redirects).

## [0.4.4-beta] — 2026-11-10

### Security
- **Reverse-proxy login could be forged.** With `auth.mode: proxy` and an empty
  `proxy_trusted_ips` (the example config's default), any client could send the
  identity header and log in as any user. Proxy mode now fails closed: OniOps
  refuses to start without a trusted-proxy list, and the request handler also
  rejects the header when no list is set.
- **Secure defaults.** The web UI now listens on `127.0.0.1` by default, and OniOps
  **refuses to start** when exposed on a network address without a login,
  unless you explicitly set `oniops.allow_unauthenticated_network: true` (or
  `ONIOPS_ALLOW_UNAUTHENTICATED_NETWORK=1`). Docker Compose now publishes the port
  on `127.0.0.1` only. New `ONIOPS_BIND_HOST` environment override.
- **Prompt-injection filter strengthened.** Tool output is now Unicode-normalised
  and stripped of invisible characters before scanning, base64-encoded
  instructions are decoded and checked, and many more phrasings and fake role
  tags are caught (17 of 17 adversarial cases, up from 6). A new test suite also
  verifies that a model which fully obeys an injection still cannot scan out of
  scope or run arbitrary or destructive commands.

### Upgrade notes
- If you reach OniOps from other machines, make sure `oniops.bind_host` is set
  (e.g. `"0.0.0.0"`) **and** a login is enabled (`auth.mode`), or OniOps will not
  start. If you use `auth.mode: proxy`, set `auth.proxy_trusted_ips` to your
  reverse proxy's IP.

## [0.4.3-beta] — 2026-11-10

### Fixed
- **Retest could mark a still-present vulnerability as FIXED.** Since
  0.4.1-beta, credentials in replay commands were masked *in the database*, so
  a retest of an authenticated finding sent `[REDACTED-TOKEN]`, got a 401, and
  reported the issue as fixed. Replay commands are stored intact again and
  secrets are masked wherever a finding leaves the server (UI, API, CLI, retest
  responses). Findings saved by 0.4.1-0.4.2 with a masked credential now refuse
  to retest, with a clear message, instead of guessing.
- A 401 on an *authenticated* retest now reports UNCONFIRMED ("credential
  rejected, it may have expired") instead of FIXED. Unauthenticated findings
  that start returning 401/403/404 are still reported as FIXED.
- If a retest cannot run at all (attack host unreachable, timeout, scope
  refusal), the finding's status is left unchanged instead of becoming FIXED.
- **Access control:** the full database backup (`/api/backup/download`) and the
  attack-host SSH check (`/api/doctor?runner=1`) are now admin-only. Previously
  the read-only `viewer` role could download the whole database.

### Changed
- The "benchmark" from 0.4.1-beta is renamed to **validator self-test**
  (`oniops selftest`, `GET /api/selftest`; the old names still work). It checks
  OniOps's own validators against built-in example inputs and reports pass/fail
  per check. It no longer reports precision / recall / F1, because those
  numbers described the examples, not detection accuracy on real targets.

## [0.4.2-beta] — 2026-11-09

### Fixed
- Workbench Recent Jobs bar was always empty (read `params` instead of job `meta`); it now also refreshes when the Workbench opens.
- Replay commands could expose bearer tokens/cookies in the Finding Detail Drawer; repro commands are now secret-redacted on storage and on display. *(Correction: masking in storage broke authenticated retests; fixed in 0.4.3-beta.)*
- Zero-token retest now treats 401/403/404 as FIXED for BOLA/BFLA findings. *(Correction: for authenticated findings a 401 now reports UNCONFIRMED; see 0.4.3-beta.)*
- Clicking a findings row now opens the Finding Detail Drawer reliably; long SHA-256 hashes wrap on mobile.

## [0.4.1-beta] — 2026-11-09

### Added
- **Finding Detail Drawer & Fix-First Priority Score**: Clicking any finding in
  the ledger opens a slide-over drawer showing the full captured evidence,
  SHA-256 provenance hash, deterministic replay command (with one-click copy and
  zero-token retest), CWE / OWASP / ATT&CK tags, step-by-step engineering
  remediation guidance (`get_remediation_guide`), and a `0-100` Fix-First
  Priority Score (`compute_priority_score`). Added `GET /api/findings/<id>`.
- **Validator self-test (`oniops benchmark`)**: 17 built-in checks
  (`oniops/benchmark.py`, `python -m oniops benchmark`, `GET /api/benchmark`) for the
  Web/API proof validators, BOLA/BOPLA analyzers, SAST sink detection, and
  prompt-injection quarantine. *(Correction: this was originally described as
  measuring recall, false-positive rate, precision and F1. It only checks OniOps's
  validators against built-in examples and does not measure detection accuracy
  on real targets. Renamed to `oniops selftest` in 0.4.3-beta.)*
- **Authenticated Assessment Enhancements**: `whatweb` and PoC service
  validation now honor the grey-box `auth_header` when testing behind login
  gates, and agent-reported findings persist secret-redacted `-H` replay
  commands and vulnerability categories.
- **Full Backend-to-Frontend Parity**: Wired Assessment Baseline Drift Diff
  (`/api/assessments/<id>/diff`), AI YAML Probe Packs & Crescendo toggles
  (`/api/aisec/probes`), White-Box SARIF v2.1.0 download & Semgrep/Gitleaks
  toggle (`/api/whitebox/scan`), Settings Self-Diagnostics (`GET /api/doctor`),
  in-browser Verification Benchmark runner, online SQLite `.sqlite` backup
  download (`GET /api/backup/download`), Horizontal BOLA Peer Header
  (`peer_auth_header`), and Background Job History / Re-attach (`/api/jobs`)
  directly into the web UI.

## [0.4.0-beta] — 2026-11-09

### Added
- **Confidence column** on findings (Certain / Firm / Tentative, inspired by
  Burp Suite), with filter chips and sorting by severity then confidence.
- **Step-by-step job timeline** in the Workbench (inspired by GitHub Actions):
  one row per stage with live status, duration and an expandable log.
  Progress events are now tagged with the job that produced them.
- **"Get OniOps ready" setup checklist** on the dashboard for new installs
  (inspired by Grafana and Tailscale onboarding): terms, attack host, AI model,
  scope, discovery, first assessment. Hides itself when complete.
- **Helpful empty states** (inspired by Stripe and Notion) for assessments,
  reports, findings, targets, the attack graph and CVE intel, each with a
  next-step button.

### Changed
- Progress messages say "attack host" instead of "Kali".

## [0.3.3-beta] — 2026-11-09

### Added
- `DISCLAIMER.md` responsible-use statement, also summarised in `NOTICE` and the
  README: OniOps is for authorized testing, is provided as-is, and the author is
  not responsible for misuse or for modified versions made by others.
- First-run "Authorized use only" dialog in the web UI. Each user must confirm
  authorized use and accept the terms before any scan, agent, AI test or
  retest can start; the server enforces this and records who accepted which
  version and when (shown in Settings -> About).

### Changed
- CONTRIBUTING and README rewritten to be friendlier for new contributors; the
  README now credits the tools and projects OniOps builds on.

### Fixed
- Page load no longer waits ~6s on SSH when the attack host is down: host and
  LLM health are checked in the background and shown as Checking / Online /
  Offline (load time 7.2s -> 1.1s).
- The sidebar card and AI operator greeting show the real host state instead
  of always saying "connected".
- Failed, stopped or timed-out Workbench runs no longer leave "Running..." on
  screen; an empty target is caught before anything is sent.
- Target pickers have a "Select a target" option and an empty state, and keep
  the user's choice across refreshes.
- An unknown `scope.mode` falls back to `active` with a warning, so Settings
  always shows the mode actually in effect.
- Phone: host/LLM status dots in the header and 44px touch targets.
- Accessibility labels for icon buttons and form fields; generic "attack host"
  wording instead of lab-specific names.
- The CLI version test now follows the package version, so release bumps no
  longer break CI.

## [0.3.2-beta] — 2026-11-09

### Fixed
- Finding validation no longer marks a finding VERIFIED just because a target
  returned output or a bare HTTP 2xx; a real indicator or a vulnerability-class
  proof pattern is now required (service exposure excepted).
- BOLA checks: an empty 200 response is only treated as confirmable when the
  server declares an API content type; a 401/403 -> 200 privilege difference
  is reported as a probable (unconfirmed) finding instead of being dropped.
- The agent's `report_finding` tool now captures the response body, so
  body-based indicators can match.

### Added
- Gitleaks allowlist for the fake credentials used as test fixtures.

## [0.3.1-beta] — 2026-11-09

### Added
- `oniops doctor` self-diagnostics, online SQLite backup/restore, CLI `assess` and
  `retest`, per-category confidence calibration, threat-model docs.
- Vulnerability-specific proof validators, horizontal BOLA / BOPLA / GraphQL
  checks, identity-aware attack graph, OWASP / ATT&CK coverage mapping, a
  verified-only CI gate and job de-duplication.

### Security
- Stronger DNS and command scope guards, login rate limiting, CSRF origin
  checks, PBKDF2 (600k iterations), 3-tier RBAC, SQLite WAL, signed execution
  manifests, and adversarial regression tests.

## [0.3.0-beta] — 2026-11-09

### Added
- CLI and CI/CD security gate with SARIF output, EPSS exploit-probability
  intel, SHA-256 evidence provenance, and a Semgrep / Gitleaks SAST adapter.

## [0.2.0-beta] — 2026-11-09

### Added
- Evidence ledger with zero-token retest, grey-box and white-box analysis,
  agent output quarantine and graph memory, AI red-team converters and
  multi-turn probes, YAML playbooks.
- Independent finding validator, BOLA / BFLA and JS route discovery,
  attack-path blast radius, drift diff and batch retest, YAML AI probe packs.
- Real browser screenshots in the README and end-to-end route tests.

## [0.1.0] — 2026-11-09

### Added
- Config-driven core, multi-provider LLM layer (Ollama, Anthropic, Gemini,
  OpenAI, OpenAI-compatible) and cross-platform packaging.
- Background job engine, web-app pentest track, attack-surface graph and
  autonomous tool-calling agent.
- Pluggable authentication (none / basic / local / OIDC / proxy), multi
  attack-host support and an editable Settings page.
- AI / LLM red-team and GRC module, PoC service validation, report export,
  offline CVE intelligence, PDF export, tests and CI.

[Unreleased]: https://github.com/ares-369/oniops/compare/v0.4.7-beta...HEAD
[0.4.7-beta]: https://github.com/ares-369/oniops/releases/tag/v0.4.7-beta
[0.4.6-beta]: https://github.com/ares-369/oniops/releases/tag/v0.4.6-beta
[0.4.4-beta]: https://github.com/ares-369/oniops/releases/tag/v0.4.4-beta
[0.4.3-beta]: https://github.com/ares-369/oniops/releases/tag/v0.4.3-beta
[0.4.2-beta]: https://github.com/ares-369/oniops/releases/tag/v0.4.2-beta
[0.4.1-beta]: https://github.com/ares-369/oniops/releases/tag/v0.4.1-beta
[0.4.0-beta]: https://github.com/ares-369/oniops/releases/tag/v0.4.0-beta
[0.3.3-beta]: https://github.com/ares-369/oniops/releases/tag/v0.3.3-beta
[0.3.2-beta]: https://github.com/ares-369/oniops/releases/tag/v0.3.2-beta
