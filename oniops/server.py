"""OniOps entrypoint — serves the Flask app with waitress (cross-platform).

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
    import sys

    from .paths import app_dir
    root = str(app_dir())
    if root not in sys.path:
        sys.path.insert(0, root)
    try:
        from webui import app  # type: ignore
        return app
    except ModuleNotFoundError as exc:  # pragma: no cover
        print(f"[OniOps] could not import the web app: {exc}", file=sys.stderr)
        raise


_LOOPBACK = ("127.0.0.1", "localhost", "::1")


def startup_security_check(cfg) -> tuple[list[str], list[str]]:
    """Return (fatal errors, warnings) for the deployment's security posture.

    OniOps drives an attack host, so a UI anyone on the network can reach without
    logging in is not allowed by default, and proxy mode must name the proxy
    that is allowed to assert user identities (otherwise anyone could).
    """
    errors: list[str] = []
    warnings: list[str] = []
    mode = cfg.auth.mode
    exposed = cfg.bind_host not in _LOOPBACK

    if mode == "none" and exposed:
        if getattr(cfg, "allow_unauthenticated_network", False):
            warnings.append(
                f"UI listens on {cfg.bind_host} with NO login (allowed by "
                "allow_unauthenticated_network). Make sure something else restricts access.")
        else:
            errors.append(
                f"The web UI would listen on {cfg.bind_host} with NO login (auth.mode=none), "
                "letting anyone on the network drive your attack host. Either set auth.mode "
                "(basic / local / oidc / proxy), set oniops.bind_host: 127.0.0.1, or - only if "
                "access is restricted another way - set oniops.allow_unauthenticated_network: true.")

    if mode == "proxy" and not cfg.auth.proxy_trusted_ips:
        errors.append(
            "auth.mode=proxy needs auth.proxy_trusted_ips (the IP of your reverse proxy). "
            "Without it, any client could send the identity header and log in as anyone.")

    if mode in ("basic", "local") and not (cfg.auth.password or cfg.auth.password_hash):
        warnings.append(
            f"auth.mode={mode} but no password/password_hash is set; login will reject "
            "everyone until you set ONIOPS_AUTH_PASSWORD or auth.password_hash.")
    return errors, warnings


def main() -> None:
    cfg = get_config()
    # Check the security posture BEFORE loading the app or opening the port.
    errors, warnings = startup_security_check(cfg)
    for w in warnings:
        print(f"[OniOps][WARNING] {w}", flush=True)
    if errors:
        for e in errors:
            print(f"[OniOps][ERROR] {e}", file=sys.stderr, flush=True)
        print("[OniOps] Refusing to start with an unsafe configuration. See config.example.yaml.",
              file=sys.stderr, flush=True)
        sys.exit(2)

    app = _load_app()
    from waitress import serve

    print(f"[OniOps] {cfg.instance_name} serving on http://{cfg.bind_host}:{cfg.bind_port}", flush=True)
    print(f"[OniOps] scope: {', '.join(cfg.scope.allowed_cidrs)}  mode={cfg.scope.mode}", flush=True)
    print(f"[OniOps] auth mode: {cfg.auth.mode}", flush=True)

    serve(app, host=cfg.bind_host, port=cfg.bind_port, threads=8)


if __name__ == "__main__":
    main()
