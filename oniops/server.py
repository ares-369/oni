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

    print(f"[ONIOPS] {cfg.instance_name} serving on http://{cfg.bind_host}:{cfg.bind_port}")
    print(f"[ONIOPS] scope: {', '.join(cfg.scope.allowed_cidrs)}  mode={cfg.scope.mode}")
    serve(app, host=cfg.bind_host, port=cfg.bind_port, threads=8)


if __name__ == "__main__":
    main()
