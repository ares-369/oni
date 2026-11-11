"""Declarative YAML attack playbooks for OniOps.

Operators can drop `.yaml` playbooks into the `playbooks/` directory to add
custom assessment tracks without editing Python code. Every command is built
as an argv array (`{target}` substituted as a discrete argument) and checked
against `Scope.check_command` before running on the attack host.
"""
from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

import yaml

_PLAYBOOK_COMMANDS = frozenset({
    "curl", "enum4linux-ng", "ffuf", "gobuster", "httpx", "hydra", "katana",
    "nikto", "nmap", "nuclei", "sqlmap", "sslscan", "wafw00f", "whatweb",
})
_INTRUSIVE_COMMANDS = frozenset({"hydra", "sqlmap"})


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
    version = str(data.get("version") or "1.0.0").strip()
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", version):
        raise ValueError(f"Playbook '{pid}' version must use semantic version syntax.")
    raw_pack = data.get("pack") or {}
    if not isinstance(raw_pack, dict):
        raise ValueError(f"Playbook '{pid}' pack metadata must be a mapping.")
    pack_id = str(raw_pack.get("id") or pid).strip()
    if not re.fullmatch(r"[a-z0-9_][a-z0-9_.-]{1,63}", pack_id):
        raise ValueError(f"Playbook '{pid}' pack id is invalid.")
    required_tools = data.get("required_tools") or []
    if not isinstance(required_tools, list) or any(
        not isinstance(t, str) or not re.fullmatch(r"[a-zA-Z0-9_.+-]{1,64}", t)
        for t in required_tools
    ):
        raise ValueError(f"Playbook '{pid}' required_tools must be a list of tool names.")
    safety = str(data.get("safety", "active")).strip().lower()
    if safety not in {"passive", "active", "intrusive"}:
        raise ValueError(f"Playbook '{pid}' safety must be passive, active, or intrusive.")
    raw_tags = data.get("tags") or []
    if not isinstance(raw_tags, list) or any(not isinstance(t, str) for t in raw_tags):
        raise ValueError(f"Playbook '{pid}' tags must be a list of strings.")
    raw_steps = data.get("steps")
    if not isinstance(raw_steps, list) or not raw_steps:
        raise ValueError(f"Playbook '{pid}' must define a non-empty 'steps' list.")

    steps: list[dict] = []
    command_tools: set[str] = set()
    for idx, s in enumerate(raw_steps, start=1):
        if not isinstance(s, dict):
            raise ValueError(f"Step #{idx} in '{pid}' must be a mapping.")
        sname = str(s.get("name") or f"Step {idx}").strip()[:80]
        cmd = s.get("cmd")
        if not isinstance(cmd, list) or not cmd or not all(isinstance(x, str) and x.strip() for x in cmd):
            raise ValueError(f"Step '{sname}' in '{pid}' must have a non-empty string list 'cmd'.")
        if cmd[0] not in _PLAYBOOK_COMMANDS:
            raise ValueError(
                f"Step '{sname}' in '{pid}' uses unsupported command '{cmd[0]}'. "
                f"Allowed network tools: {', '.join(sorted(_PLAYBOOK_COMMANDS))}."
            )
        command_tools.add(cmd[0])
        if cmd[0] in _INTRUSIVE_COMMANDS and safety != "intrusive":
            raise ValueError(
                f"Playbook '{pid}' uses {cmd[0]}, which requires safety: intrusive."
            )
        if not any("{target}" in arg for arg in cmd[1:]):
            raise ValueError(f"Step '{sname}' in '{pid}' must include the {{target}} placeholder.")
        timeout = max(5, min(int(s.get("timeout", 60) or 60), 180))
        steps.append({
            "name": sname,
            "cmd": [str(x) for x in cmd],
            "timeout": timeout,
            "parse_ports": bool(s.get("parse_ports", False)),
            "count_findings": bool(s.get("count_findings", False)),
        })
    return {
        "id": pid, "name": name, "description": desc, "version": version,
        "pack": {
            "id": pack_id,
            "author": str(raw_pack.get("author") or "").strip()[:100],
            "homepage": str(raw_pack.get("homepage") or "").strip()[:300],
        },
        # Do not let stale metadata hide a missing runtime dependency.
        "required_tools": sorted(set(required_tools) | command_tools), "safety": safety,
        "tags": sorted({t.strip().lower()[:40] for t in raw_tags if t.strip()}),
        "steps": steps,
    }


def load_playbooks(directory: Path | None = None, diagnostics: list[str] | None = None) -> dict[str, dict]:
    d = directory or playbooks_dir()
    if not d.exists() or not d.is_dir():
        return {}
    out: dict[str, dict] = {}
    for fp in sorted((*d.rglob("*.yaml"), *d.rglob("*.yml"))):
        if fp.relative_to(d).parts[:1] == ("ai_probes",):
            continue
        try:
            raw = yaml.safe_load(fp.read_text()) or {}
            pb = validate_playbook(raw)
            if pb["id"] in out:
                raise ValueError(f"Duplicate playbook id '{pb['id']}'.")
            pb["source"] = str(fp.relative_to(d))
            pb["content_sha256"] = hashlib.sha256(fp.read_bytes()).hexdigest()
            out[pb["id"]] = pb
        except Exception as exc:
            if diagnostics is not None:
                diagnostics.append(f"{fp}: {exc}")
            continue
    return out


def render_step_cmd(cmd_template: list[str], target_ip: str) -> list[str]:
    """Substitute {target} in an argv template without shell interpolation."""
    return [arg.replace("{target}", target_ip) for arg in cmd_template]
