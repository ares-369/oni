"""Declarative YAML attack playbooks for OniOps.

Operators can drop `.yaml` playbooks into the `playbooks/` directory to add
custom assessment tracks without editing Python code. Every command is built
as an argv array (`{target}` substituted as a discrete argument) and checked
against `Scope.check_command` before running on the attack host.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

import yaml


def playbooks_dir() -> Path:
    env = os.getenv("ONIOPS_PLAYBOOKS_DIR")
    if env:
        return Path(env)
    return Path(__file__).resolve().parent.parent / "playbooks"


def validate_playbook(data: dict) -> dict:
    if not isinstance(data, dict):
        raise ValueError("Playbook must be a YAML mapping.")
    pid = str(data.get("id") or "").strip()
    if not re.match(r"^[a-z0-9_]{3,40}$", pid):
        raise ValueError(f"Playbook id '{pid}' must match ^[a-z0-9_]{{3,40}}$.")
    name = str(data.get("name") or pid).strip()[:80]
    desc = str(data.get("description") or "").strip()[:240]
    raw_steps = data.get("steps")
    if not isinstance(raw_steps, list) or not raw_steps:
        raise ValueError(f"Playbook '{pid}' must define a non-empty 'steps' list.")

    steps: list[dict] = []
    for idx, s in enumerate(raw_steps, start=1):
        if not isinstance(s, dict):
            raise ValueError(f"Step #{idx} in '{pid}' must be a mapping.")
        sname = str(s.get("name") or f"Step {idx}").strip()[:80]
        cmd = s.get("cmd")
        if not isinstance(cmd, list) or not cmd or not all(isinstance(x, str) and x.strip() for x in cmd):
            raise ValueError(f"Step '{sname}' in '{pid}' must have a non-empty string list 'cmd'.")
        timeout = max(5, min(int(s.get("timeout", 60) or 60), 180))
        steps.append({
            "name": sname,
            "cmd": [str(x) for x in cmd],
            "timeout": timeout,
            "parse_ports": bool(s.get("parse_ports", False)),
            "count_findings": bool(s.get("count_findings", False)),
        })
    return {"id": pid, "name": name, "description": desc, "steps": steps}


def load_playbooks(directory: Path | None = None) -> dict[str, dict]:
    d = directory or playbooks_dir()
    if not d.exists() or not d.is_dir():
        return {}
    out: dict[str, dict] = {}
    for fp in sorted(d.glob("*.yaml")):
        try:
            raw = yaml.safe_load(fp.read_text()) or {}
            pb = validate_playbook(raw)
            out[pb["id"]] = pb
        except Exception:
            continue
    return out


def render_step_cmd(cmd_template: list[str], target_ip: str) -> list[str]:
    """Substitute {target} in an argv template without shell interpolation."""
    return [arg.replace("{target}", target_ip) for arg in cmd_template]
