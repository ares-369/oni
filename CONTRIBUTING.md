# Contributing to OniOps

Thank you for taking the time to look at OniOps. It is a small project that I maintain
on my own in my spare time, and every bug report, idea, doc fix or pull request genuinely
helps.

## Ways to help

- **Report a bug** — open an issue with what you ran, what you expected, and
  what happened. Logs and your OS / Python version make it much easier to fix.
- **Suggest an idea** — feature requests are welcome, including "this was
  confusing" feedback. There are no bad questions.
- **Improve the docs** — if something in the README or install guide tripped
  you up, it will trip up the next person too.
- **Send a pull request** — new tools, LLM providers, integrations, tests and
  UI fixes are all welcome. Small PRs are easiest to review.

## Getting started

1. Fork the repo and create a branch for your change.
2. Copy `config.example.yaml` to `config.yaml` and `.env.example` to `.env`.
3. Run OniOps locally with `python -m oniops` (see [`docs/INSTALL.md`](docs/INSTALL.md)).
4. Run the checks before opening a PR:

   ```bash
   pip install -r requirements.txt pytest ruff
   ruff check oniops/ webui.py tests/
   pytest tests/
   ```

5. If you add something users will see, a short note in the README or docs is
   appreciated.

## A few things I ask

OniOps is an offensive security tool, so a few guardrails matter more than usual:

- **Authorized testing only.** Please only contribute capabilities meant for
  testing systems you own or are permitted to test.
- **Keep the safety rails on by default.** The scope allow-list, the
  non-destructive guard and the authentication options protect users — new
  features should work with them, not around them.
- **No secrets in the repo.** Use `.env` and `secrets/` (both git-ignored). CI
  runs a secret scan on every push.
- **Prefer optional over required.** New tools, providers and integrations work
  best as add-ons that degrade gracefully when they are not configured.

## About the name

"OniOps" is simply the name this project goes by. You are free to fork and build
on the code under the Apache-2.0 license. If you publish a fork that changes
things significantly, giving it its own name helps avoid confusing users about
which project is which — that is all I ask. (The license itself does not grant
use of the project's name; see section 6 of [`LICENSE`](LICENSE).)

## Code of conduct

Please be kind and patient with each other. See
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## Security issues

Please do not open a public issue for a vulnerability in OniOps itself — see
[`SECURITY.md`](SECURITY.md) for how to report it privately.
