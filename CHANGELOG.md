# Changelog

All notable changes to ONIOPS are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). ONIOPS is pre-1.0 beta software, so
behaviour may still change between releases.

## [Unreleased]

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

[Unreleased]: https://github.com/ares-369/oniops/compare/v0.3.2-beta...HEAD
[0.3.2-beta]: https://github.com/ares-369/oniops/releases/tag/v0.3.2-beta
