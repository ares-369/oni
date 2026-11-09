# Changelog

All notable changes to ONIOPS are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). ONIOPS is pre-1.0 beta software, so
behaviour may still change between releases.

## [Unreleased]

## [0.4.2-beta] — 2026-11-09

### Fixed
- Workbench Recent Jobs bar was always empty (read `params` instead of job `meta`); it now also refreshes when the Workbench opens.
- Replay commands could expose bearer tokens/cookies in the Finding Detail Drawer; repro commands are now secret-redacted on storage and on display.
- Zero-token retest now treats 401/403/404 as FIXED for BOLA/BFLA findings.
- Clicking a findings row now opens the Finding Detail Drawer reliably; long SHA-256 hashes wrap on mobile.

## [0.4.1-beta] — 2026-11-09

### Added
- **Finding Detail Drawer & Fix-First Priority Score**: Clicking any finding in
  the ledger opens a slide-over drawer showing the full captured evidence,
  SHA-256 provenance hash, deterministic replay command (with one-click copy and
  zero-token retest), CWE / OWASP / ATT&CK tags, step-by-step engineering
  remediation guidance (`get_remediation_guide`), and a `0-100` Fix-First
  Priority Score (`compute_priority_score`). Added `GET /api/findings/<id>`.
- **Verification & False-Positive Benchmark Suite (`oniops benchmark`)**: Built-in
  17-case benchmark suite (`oniops/benchmark.py`, `python -m oniops benchmark`, and
  `GET /api/benchmark`) measuring true-positive recall, false-positive rate
  (FPR), precision, and F1 score across Web/API proof validators, BOLA/BOPLA
  analyzers, SAST sink detection, and prompt-injection quarantine.
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
- **"Get ONIOPS ready" setup checklist** on the dashboard for new installs
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
  README: ONIOPS is for authorized testing, is provided as-is, and the author is
  not responsible for misuse or for modified versions made by others.
- First-run "Authorized use only" dialog in the web UI. Each user must confirm
  authorized use and accept the terms before any scan, agent, AI test or
  retest can start; the server enforces this and records who accepted which
  version and when (shown in Settings -> About).

### Changed
- CONTRIBUTING and README rewritten to be friendlier for new contributors; the
  README now credits the tools and projects ONIOPS builds on.

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

[Unreleased]: https://github.com/ares-369/oniops/compare/v0.4.2-beta...HEAD
[0.4.2-beta]: https://github.com/ares-369/oniops/releases/tag/v0.4.2-beta
[0.4.1-beta]: https://github.com/ares-369/oniops/releases/tag/v0.4.1-beta
[0.4.0-beta]: https://github.com/ares-369/oniops/releases/tag/v0.4.0-beta
[0.3.3-beta]: https://github.com/ares-369/oniops/releases/tag/v0.3.3-beta
[0.3.2-beta]: https://github.com/ares-369/oniops/releases/tag/v0.3.2-beta
