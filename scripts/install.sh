#!/usr/bin/env bash
# =====================================================================
#  OniOps - one-command local install (Linux / macOS / WSL)
#
#  Run from anywhere:   bash scripts/install.sh
#
#  What it does (safe to run again, never asks questions):
#    1. creates a virtualenv in ./venv (override: ONIOPS_VENV=/path)
#    2. installs the requirements, then the `oniops` command (editable)
#    3. copies config.example.yaml -> config.yaml and .env.example -> .env,
#       but only if they do not exist yet (existing files are never touched)
#    4. writes a random ONIOPS_SECRET_KEY into .env only if it is missing or empty
#    5. creates secrets/ and data/ and prints the next steps
#
#  It does not start a service, contact any target, or touch /opt/oniops.
#  Override the interpreter with PYTHON=python3.12 bash scripts/install.sh
#  ONIOPS_SKIP_PIP=1 skips the pip installs (offline machines, tests).
# =====================================================================
set -eu

case "${1:-}" in
  -h|--help)
    sed -n '3,17p' "$0" | sed 's/^# \{0,2\}//'
    exit 0 ;;
esac

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-python3}"
VENV="${ONIOPS_VENV:-venv}"

say() { printf '[OniOps install] %s\n' "$*"; }
die() { printf '[OniOps install] error: %s\n' "$*" >&2; exit 1; }

[ -f requirements.txt ] && [ -f config.example.yaml ] && [ -d oniops ] \
  || die "run this from an OniOps checkout (requirements.txt, config.example.yaml and oniops/ not found in $ROOT)"

command -v "$PYTHON" >/dev/null 2>&1 || die "$PYTHON not found. Install Python 3.10+ or set PYTHON=/path/to/python3"
"$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' \
  || die "Python 3.10+ is required (found $("$PYTHON" -V 2>&1))"

if [ -x "$VENV/bin/python" ]; then
  say "virtualenv $VENV already exists, reusing it"
else
  say "creating virtualenv in $VENV"
  rm -rf "$VENV"
  "$PYTHON" -m venv "$VENV" \
    || die "could not create the virtualenv (on Debian/Ubuntu: sudo apt install python3-venv)"
fi

if [ "${ONIOPS_SKIP_PIP:-0}" = "1" ]; then
  say "ONIOPS_SKIP_PIP=1: skipping pip installs (offline or test run)"
else
  say "installing requirements (needs network access to a package index)"
  "$VENV/bin/python" -m pip install --quiet --disable-pip-version-check -r requirements.txt \
    || die "pip install -r requirements.txt failed"

  # The `oniops` command is a convenience; `python -m oniops` works without it. The editable
  # install needs to fetch a build backend, so a failure here is only a warning.
  if "$VENV/bin/python" -m pip install --quiet --disable-pip-version-check --no-deps -e . 2>/dev/null; then
    say "installed the oniops command into $VENV/bin"
  else
    say "warning: could not install the oniops command (offline?). Use: $VENV/bin/python -m oniops"
  fi
fi

if [ -e config.yaml ]; then
  say "config.yaml already exists, leaving it alone"
else
  cp config.example.yaml config.yaml
  say "created config.yaml from config.example.yaml"
fi

if [ -e .env ]; then
  say ".env already exists, leaving its contents alone"
else
  [ -f .env.example ] && cp .env.example .env || : > .env
  say "created .env from .env.example"
fi
chmod 600 .env 2>/dev/null || true

mkdir -p secrets data

# Add ONIOPS_SECRET_KEY only when missing or empty. The key is never printed.
status="$("$VENV/bin/python" - <<'PY'
import re
import secrets
from pathlib import Path

path = Path(".env")
lines = path.read_text(encoding="utf-8").splitlines()
pat = re.compile(r"^\s*(?:export\s+)?ONIOPS_SECRET_KEY\s*=(.*)$")
for i, line in enumerate(lines):
    m = pat.match(line)
    if not m:
        continue
    value = re.split(r"(?:^|\s)#", m.group(1).strip(), maxsplit=1)[0].strip().strip("\"'")
    if value:
        print("kept")
        raise SystemExit
    lines[i] = "ONIOPS_SECRET_KEY=" + secrets.token_hex(32)
    break
else:
    lines.append("ONIOPS_SECRET_KEY=" + secrets.token_hex(32))
path.write_text("\n".join(lines) + "\n", encoding="utf-8")
print("generated")
PY
)"
case "$status" in
  generated) say "generated a random ONIOPS_SECRET_KEY in .env" ;;
  *)         say "ONIOPS_SECRET_KEY already set in .env, kept" ;;
esac

cat <<EOF

[OniOps install] Done. Next steps:

  1. Try it now, no config needed (practice target on 127.0.0.1 only):
       $VENV/bin/python -m oniops demo

  2. For real use, edit config.yaml:
       scope.allowed_cidrs   the network(s) you are authorized to test
       kali.host / kali.user / kali.ssh_key   your attack host
     and put the attack host's SSH private key in secrets/ (chmod 600).

  3. Check the setup, then start the web UI (http://127.0.0.1:8501):
       $VENV/bin/python -m oniops doctor
       $VENV/bin/python -m oniops

  The UI listens on 127.0.0.1 only. To open it to your network, set a login
  (auth.mode) in config.yaml first; OniOps refuses to start without one.
  To run it as a background service, see "Run as a systemd service" in README.md.
  Use OniOps only against systems you are authorized to test (DISCLAIMER.md).
EOF
