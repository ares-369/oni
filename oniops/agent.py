"""Autonomous tool-calling agent loop.

A provider-agnostic ReAct loop: the model is given a scoped toolset and, each
step, replies with ONE JSON action. ONIOPS validates + executes it on the attack
host (scope-guarded, non-destructive), feeds the observation back, and repeats
until the model says it's finished or the step budget runs out.

Using a JSON action protocol (rather than a provider-specific tool-calling API)
keeps this working across Ollama, Claude, Gemini and OpenAI alike, and lets ONIOPS
validate every call before it runs. All registered tools are reconnaissance /
enumeration only — nothing destructive runs autonomously.
"""

from __future__ import annotations

import json
import re
from typing import Callable

from .scope import Scope, ScopeViolation


# ───────────────────────── tool executors ─────────────────────────
def _nmap(runner, ip, args):
    mode = str(args.get("mode", "fast")).lower()
    if mode == "full":
        cmd = ["nmap", "-sV", "--top-ports", "200", "-T4", "--open", ip]
    else:
        cmd = ["nmap", "-sV", "--version-light", "-F", "-T4", "--open", ip]
    return runner.run(cmd, timeout=90).out


def _whatweb(runner, ip, args):
    port = args.get("port")
    url = f"http://{ip}:{port}" if port else f"http://{ip}"
    return runner.run(["whatweb", "--color=never", "-a", "1", url], timeout=35).out


def _httpx(runner, ip, args):
    return runner.run(["httpx", "-u", f"http://{ip}", "-status-code", "-title",
                       "-tech-detect", "-silent"], timeout=40).out


def _nuclei(runner, ip, args):
    port = args.get("port")
    scheme = "https" if str(port) in ("443", "8443") else "http"
    url = f"{scheme}://{ip}:{port}" if port else f"http://{ip}"
    return runner.run(["nuclei", "-target", url, "-tags", "cve,misconfig,exposure",
                       "-silent", "-severity", "low,medium,high,critical"], timeout=75).out


def _ffuf(runner, ip, args):
    port = args.get("port")
    url = f"http://{ip}:{port}" if port else f"http://{ip}"
    out = runner.run(["ffuf", "-u", f"{url}/FUZZ", "-w", "/usr/share/wordlists/dirb/common.txt",
                      "-mc", "200,204,301,302,307,401,403", "-t", "40", "-s"], timeout=60).out
    paths = [l for l in out.splitlines() if l.strip()]
    if len(paths) > 60:
        return f"{len(paths)} paths (likely catch-all). First 30:\n" + "\n".join(paths[:30])
    return "\n".join(paths[:60]) or "(no paths)"


def _enum4linux(runner, ip, args):
    return runner.run(["enum4linux-ng", "-A", ip], timeout=60).out[:2000]


def _searchsploit(runner, ip, args):
    term = str(args.get("term", "")).strip()
    if not term or not re.match(r"^[\w.\- ]{2,60}$", term):
        return "Provide a valid 'term' (e.g. openssh, nginx, vsftpd 2.3.4)."
    return runner.run(["searchsploit", "--colour", term], timeout=25).out[:2000]


TOOLS: dict[str, dict] = {
    "nmap": {"needs_target": True,
             "desc": "Port & service scan. args: {target, mode: fast|full}", "fn": _nmap},
    "whatweb": {"needs_target": True,
                "desc": "Fingerprint a web app. args: {target, port?}", "fn": _whatweb},
    "httpx": {"needs_target": True,
              "desc": "Probe HTTP: status, title, tech. args: {target}", "fn": _httpx},
    "nuclei": {"needs_target": True,
               "desc": "CVE/misconfig scan of a web service. args: {target, port?}", "fn": _nuclei},
    "ffuf": {"needs_target": True,
             "desc": "Content/endpoint discovery. args: {target, port?}", "fn": _ffuf},
    "enum4linux": {"needs_target": True,
                   "desc": "Enumerate SMB/Samba shares & users. args: {target}", "fn": _enum4linux},
    "searchsploit": {"needs_target": False,
                     "desc": "Search Exploit-DB for a product/version. args: {term}", "fn": _searchsploit},
}


# ───────────────────────── JSON parsing ─────────────────────────
def _extract_json(text: str) -> dict | None:
    """Pull the first balanced {...} object out of a model reply (tolerating
    code fences and surrounding prose)."""
    if not text:
        return None
    t = re.sub(r"```(?:json)?", "", text).strip()
    start = t.find("{")
    if start < 0:
        return None
    depth = 0
    for i in range(start, len(t)):
        if t[i] == "{":
            depth += 1
        elif t[i] == "}":
            depth -= 1
            if depth == 0:
                frag = t[start:i + 1]
                for attempt in (frag, frag.replace("'", '"')):
                    try:
                        return json.loads(attempt)
                    except Exception:
                        continue
                return None
    return None


def _host_of(raw: str) -> str:
    """Extract a bare host/IP from whatever the model passed (it often supplies
    a full URL like http://10.0.0.5:8080/path)."""
    raw = str(raw).strip()
    raw = re.sub(r"^[a-zA-Z]+://", "", raw)   # strip scheme
    raw = raw.split("/")[0]                    # strip path
    raw = raw.rsplit(":", 1)[0] if raw.count(":") == 1 else raw  # strip :port (keep IPv6-ish alone)
    return raw.strip()


# ───────────────────────── the loop ─────────────────────────
def run_agent(objective: str, target: str, *, llm, scope: Scope, runner,
              emit: Callable[[str, str, str], None] | None = None,
              max_steps: int = 8, ctl=None) -> dict:
    emit = emit or (lambda *a, **k: None)
    tool_list = "\n".join(f"- {n}: {t['desc']}" for n, t in TOOLS.items())
    system = (
        "You are ONIOPS, an autonomous red-team operator running a scope-locked assessment. "
        f"Authorized scope: {', '.join(scope.cidrs)}. Work ONE step at a time.\n"
        f"Available tools:\n{tool_list}\n\n"
        "Reply with ONLY a single JSON object, nothing else:\n"
        '  {\"thought\": \"brief reasoning\", \"action\": \"<tool>\", \"args\": { ... }}\n'
        "When you have enough to report, reply instead with:\n"
        '  {\"thought\": \"...\", \"final\": \"a concise findings + risk summary with next steps\"}\n'
        "Rules: targets must be in scope; be efficient and finish within a few steps; "
        "do not repeat an identical tool call."
    )
    user = (f"Objective: {objective}\n"
            f"Primary target: {target or '(none given — pick an in-scope host or scan first)'}\n"
            "Begin. Respond with one JSON action.")
    messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
    transcript: list[dict] = []
    seen: set[str] = set()
    bound = llm.for_role("planner")

    emit("AGENT_START", "busy", f"Autonomous agent: {objective[:80]}")
    for step in range(1, max_steps + 1):
        if ctl is not None and not ctl.checkpoint():
            emit("AGENT_STOP", "ok", f"Stopped by user at step {step}")
            return {"objective": objective, "target": target, "steps": transcript,
                    "final": "Run stopped by the operator.", "completed": False, "stopped": True}
        res = bound.chat(messages, temperature=0.1, max_tokens=500)
        reply = res.text or ""
        if res.error:
            return {"objective": objective, "target": target, "steps": transcript,
                    "final": f"Agent stopped: LLM error ({res.error}).", "completed": False}
        act = _extract_json(reply)
        if not act:
            messages.append({"role": "assistant", "content": reply[:600]})
            messages.append({"role": "user", "content": "That was not valid JSON. Reply with ONLY one JSON action or a final object."})
            continue
        if "final" in act:
            emit("AGENT_DONE", "ok", f"Agent finished at step {step}")
            return {"objective": objective, "target": target, "steps": transcript,
                    "final": act.get("final", ""), "completed": True}

        tool = str(act.get("action", "")).lower().strip()
        targs = act.get("args") or {}
        thought = act.get("thought", "")

        call_key = f"{tool}:{json.dumps(targs, sort_keys=True)}"
        if tool not in TOOLS:
            obs = f"Unknown tool '{tool}'. Available: {', '.join(TOOLS)}."
        elif call_key in seen:
            obs = ("You already ran this exact call and it did not advance the assessment. "
                   "Choose a DIFFERENT tool or arguments, or return a final summary now.")
        else:
            seen.add(call_key)
            spec = TOOLS[tool]
            try:
                if spec["needs_target"]:
                    raw = targs.get("target") or target
                    if not raw:
                        obs = "No target provided and no default target set."
                    else:
                        ip = scope.resolve(_host_of(raw)).ip
                        emit("AGENT_STEP", "busy", f"[{step}] {tool} on {ip}")
                        obs = spec["fn"](runner, ip, targs)
                else:
                    emit("AGENT_STEP", "busy", f"[{step}] {tool}")
                    obs = spec["fn"](runner, None, targs)
            except ScopeViolation as exc:
                obs = f"Scope violation: {exc}"
            except Exception as exc:  # noqa: BLE001
                obs = f"Tool error: {exc}"

        obs = (obs or "(no output)")[:2000]
        transcript.append({"step": step, "thought": thought, "tool": tool, "args": targs, "observation": obs})
        messages.append({"role": "assistant", "content": reply[:600]})
        messages.append({"role": "user", "content": f"Observation from {tool}:\n{obs}\n\nNext JSON action, or a final object if done."})

    # Budget exhausted — ask for a wrap-up.
    emit("AGENT_WRAP", "busy", "Step budget reached; summarizing")
    summ = bound.chat(messages + [{"role": "user",
                      "content": 'Step budget reached. Reply with ONLY {"final": "summary of findings, risk, and recommended next steps"}.'}],
                      max_tokens=600)
    fin = _extract_json(summ.text or "") or {}
    return {"objective": objective, "target": target, "steps": transcript,
            "final": fin.get("final") or (summ.text or "No summary produced."), "completed": False}
