"""ONIOPS entrypoint — serves the Flask app with waitress (cross-platform).

    oniops            # console script (see pyproject [project.scripts])
    python -m oniops  # module form

The Flask app itself lives in ``webui.py`` at the repo root (ported onto the
oniops.* package in Phase 1). Importing it here keeps the WSGI server swappable.
"""

from __future__ import annotations

import sys

from .config import get_config


def _load_app():
    # webui.py exposes `app` (Flask). Kept at repo root for now; Phase 2 moves
    # it under oniops/web/.
    try:
        from webui import app  # type: ignore
        return app
    except ModuleNotFoundError as exc:  # pragma: no cover
        print(f"[ONIOPS] could not import the web app: {exc}", file=sys.stderr)
        raise


def main() -> None:
    cfg = get_config()
    app = _load_app()
    from waitress import serve

    print(f"[ONIOPS] {cfg.instance_name} serving on http://{cfg.bind_host}:{cfg.bind_port}", flush=True)
    print(f"[ONIOPS] scope: {', '.join(cfg.scope.allowed_cidrs)}  mode={cfg.scope.mode}", flush=True)

    # Security posture warning: an unauthenticated UI bound to a non-loopback
    # address lets anyone on the network drive the attack host.
    loopback = cfg.bind_host in ("127.0.0.1", "localhost", "::1")
    print(f"[ONIOPS] auth mode: {cfg.auth.mode}", flush=True)
    if cfg.auth.mode == "none" and not loopback:
        print("[ONIOPS][WARNING] Web UI is exposed on a non-loopback address with NO "
              "authentication (auth.mode=none). Set auth.mode (basic/local/oidc/proxy), "
              "bind to 127.0.0.1, or front ONIOPS with an authenticating reverse proxy.", flush=True)
    if cfg.auth.mode in ("basic", "local") and not (cfg.auth.password or cfg.auth.password_hash):
        print(f"[ONIOPS][WARNING] auth.mode={cfg.auth.mode} but no password/password_hash set; "
              "login will reject everyone until you set ONIOPS_AUTH_PASSWORD or auth.password_hash.",
              flush=True)

    serve(app, host=cfg.bind_host, port=cfg.bind_port, threads=8)


if __name__ == "__main__":
    main()
