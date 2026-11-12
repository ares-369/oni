"""Where OniOps finds its web app, playbooks and data.

Two layouts are supported:

* **Source checkout** (``git clone`` + ``scripts/install.sh``, Docker, the systemd
  unit): ``webui.py``, ``templates/``, ``static/`` and ``playbooks/`` sit next to
  the ``oniops/`` package, and ``config.yaml``, ``.env`` and ``data/`` live in the
  checkout root. Nothing changes for this layout.
* **Installed wheel** (``pip install oniops`` / ``pipx install oniops``): the build
  copies those web files into ``oniops/_app/``, and user files (``config.yaml``,
  ``.env``, ``data/``) live in ``$ONIOPS_HOME`` (default ``~/.oniops``), created by
  ``oniops init``.
"""
from __future__ import annotations

import os
from pathlib import Path

PKG_DIR = Path(__file__).resolve().parent
REPO_ROOT = PKG_DIR.parent
BUNDLE_DIR = PKG_DIR / "_app"


def is_checkout() -> bool:
    """True when running from a source checkout (webui.py next to the package)."""
    return (REPO_ROOT / "webui.py").is_file()


def app_dir() -> Path:
    """Folder that holds webui.py, templates/, static/ and playbooks/."""
    if is_checkout() or not (BUNDLE_DIR / "webui.py").is_file():
        return REPO_ROOT
    return BUNDLE_DIR


def home_dir() -> Path:
    """Folder for config.yaml, .env and data/ (the checkout root, or ~/.oniops)."""
    env = os.getenv("ONIOPS_HOME", "").strip()
    if env:
        return Path(env).expanduser()
    if is_checkout():
        return REPO_ROOT
    return Path.home() / ".oniops"
