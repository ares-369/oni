# Contributing to ONIOPS

Thanks for your interest in ONIOPS — Offensive Neural Intelligence.

## Project name (fixed)

**The project name is `ONIOPS` (Offensive Neural Intelligence) and must not be
changed.** Forks and contributions may add features, providers, tools and
integrations, but the tool's name, and the `ONIOPS` branding in the UI and docs,
are not to be renamed or rebranded. Pull requests that rename the project will
not be accepted.

## Ground rules

- ONIOPS is an offensive security tool. Only contribute capabilities intended for
  authorized testing. Keep the scope allow-list, the non-destructive-by-default
  guard, and the authentication options intact.
- Secrets never go in the repo — use `.env` / `secrets/` (git-ignored).
- New tools, LLM providers and integrations should be additive and optional.

## Developing

- Config is loaded from `config.yaml` + `.env`; copy the `.example` files.
- Run locally with `python -m oniops`; see `docs/INSTALL.md` for deploy targets.
- Please keep changes scope-guarded and add a short note to the README/docs
  when you add a user-facing capability.
