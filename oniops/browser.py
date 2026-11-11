"""Bounded browser discovery for authorized web-app assessments.

The crawler only navigates in-scope HTTP(S) URLs, never submits forms, blocks
mutating methods, and applies supplied credentials only to the starting origin.
Playwright is an optional dependency so the core CLI remains lightweight.
"""
from __future__ import annotations

import re
import time
from pathlib import Path
from urllib.parse import parse_qsl, urldefrag, urlencode, urljoin, urlsplit, urlunsplit

from .greybox import sanitize_auth_header
from .scope import Scope, ScopeViolation

_SECRET_QUERY_KEY = re.compile(
    r"token|secret|password|passwd|auth|session|cookie|api.?key|code|jwt|bearer|credential", re.I)


def _safe_url(url: str) -> str:
    """Redact credential-like query values before URLs enter a scan report."""
    p = urlsplit(url)
    query = [(key, "[REDACTED]" if _SECRET_QUERY_KEY.search(key) else value)
             for key, value in parse_qsl(p.query, keep_blank_values=True)]
    host = p.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    try:
        port = p.port
    except ValueError:
        port = None
    netloc = f"{host}:{port}" if port is not None else host
    return urlunsplit((p.scheme, netloc, p.path, urlencode(query, doseq=True), ""))


def _origin(url: str) -> tuple[str, str, int | None]:
    p = urlsplit(url)
    default_port = 443 if p.scheme.lower() == "https" else 80
    return p.scheme.lower(), (p.hostname or "").lower(), p.port or default_port


def _form_observations(page_url: str, forms: list[dict]) -> list[dict]:
    """Create value-free, evidence-backed observations from observed form metadata."""
    observations = []
    for form in forms:
        method = str(form.get("method") or "GET").upper()
        controls = form.get("controls") or []
        sensitive = [
            control for control in controls
            if str(control.get("type") or "").lower() == "password"
            or re.search(r"password|passwd|secret|token|credential|api.?key",
                         " ".join(str(control.get(k) or "") for k in ("name", "autocomplete")), re.I)
        ]
        if sensitive and method == "GET":
            observations.append({
                "check_id": "WEB-FORM-SENSITIVE-GET", "severity": "HIGH",
                "status": "OBSERVED", "url": _safe_url(page_url),
                "action": _safe_url(str(form.get("action") or page_url)),
                "evidence": "A form containing a credential-like field uses GET; submitted values may enter URLs and logs.",
            })
        action = str(form.get("action") or page_url)
        if sensitive and urlsplit(page_url).scheme.lower() == "http" and urlsplit(action).scheme.lower() == "http":
            observations.append({
                "check_id": "WEB-FORM-CLEARTEXT-CREDENTIALS", "severity": "HIGH",
                "status": "OBSERVED", "url": _safe_url(page_url),
                "action": _safe_url(action),
                "evidence": "A credential-like field is rendered on HTTP and its form action also uses HTTP.",
            })
    return observations


def _safe_form_details(page_url: str, forms: list[dict]) -> list[dict]:
    """Return form metadata with credential-like action query values redacted."""
    return [
        {**form, "action": _safe_url(str(form.get("action") or page_url))}
        for form in forms
    ]


def crawl_web_app(start_url: str, scope: Scope, *, max_pages: int = 50,
                  max_seconds: int = 90, auth_header: str = "",
                  storage_state: str = "", session=None) -> dict:
    """Render and discover pages in scope without submitting forms or mutating requests.

    ``session`` is an optional ``target_auth.TargetSession``: when given and no
    explicit ``auth_header`` is passed, the crawler forwards that session's
    CURRENT header to the start origin. The crawler itself does not log in or
    refresh; call ``session.refresh(run_fn)`` beforehand to mint a token. Only
    the resulting header is used, never any credential.
    """
    if session is not None and not auth_header:
        auth_header = session.header()
    start = urlsplit(start_url)
    if start.scheme.lower() not in {"http", "https"} or not start.hostname or start.username or start.password:
        raise ValueError("Start URL must be an HTTP(S) URL without embedded credentials.")
    # Resolve the start host once and pin Chromium's resolver to that in-scope
    # address, so the browser cannot re-resolve the name to an out-of-scope IP
    # between this check and navigation (DNS-rebinding / TOCTOU). Other in-scope
    # hosts reached during the crawl are still re-checked in check_url; a name
    # that rebinds mid-crawl to a fresh out-of-scope IP is the residual limit.
    _resolved_start = scope.resolve(start.hostname)
    _pinned_ip = getattr(_resolved_start, "ip", "")
    auth = sanitize_auth_header(auth_header) if auth_header else ""
    state_path = Path(storage_state).expanduser() if storage_state else None
    if state_path and not state_path.is_file():
        raise ValueError(f"Playwright storage-state file does not exist: {state_path}")
    auth_name, auth_value = auth.split(":", 1) if auth else ("", "")
    start_origin = _origin(start_url)
    max_pages = max(1, min(int(max_pages), 200))
    max_seconds = max(5, min(int(max_seconds), 300))
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError("Browser crawling needs Playwright: install with `pip install 'oniops[browser]'`.") from exc
    deadline = time.monotonic() + max_seconds
    queue = [urldefrag(start_url).url]
    seen: set[str] = set()
    pages: list[dict] = []
    api_requests: dict[tuple[str, str], dict] = {}
    blocked: list[dict] = []
    observations: list[dict] = []

    def check_url(url: str) -> tuple[bool, str]:
        p = urlsplit(url)
        if p.scheme.lower() not in {"http", "https"} or not p.hostname or p.username or p.password:
            return False, "unsupported scheme or embedded credentials"
        try:
            scope.resolve(p.hostname)
        except ScopeViolation as exc:
            return False, str(exc)
        return True, ""

    launch_args = []
    if _pinned_ip:
        # Pin only the start host; EXCLUDE nothing else so other hosts still
        # resolve normally and pass through check_url.
        launch_args.append(f"--host-resolver-rules=MAP {start.hostname} {_pinned_ip}")
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, args=launch_args)
        context = browser.new_context(
            service_workers="block", accept_downloads=False,
            storage_state=str(state_path) if state_path else None,
        )
        page = context.new_page()

        def record_response(response):
            request = response.request
            if request.resource_type not in {"xhr", "fetch"}:
                return
            key = (request.method.upper(), urldefrag(response.url).url)
            item = api_requests.setdefault(key, {"method": key[0], "url": key[1]})
            item["status"] = response.status
            item["content_type"] = str(response.headers.get("content-type") or "")[:100]

        page.on("response", record_response)

        def guard(route):
            request = route.request
            url = request.url
            allowed, reason = check_url(url)
            if not allowed:
                blocked.append({"url": _safe_url(url)[:500], "reason": reason})
                route.abort()
                return
            method = request.method.upper()
            if method not in {"GET", "HEAD", "OPTIONS"}:
                blocked.append({"url": _safe_url(url)[:500], "reason": f"mutating method {method} is not submitted by the crawler"})
                route.abort()
                return
            if request.resource_type in {"xhr", "fetch"}:
                key = (method, urldefrag(url).url)
                api_requests[key] = {"method": method, "url": urldefrag(url).url}
            if auth and _origin(url) == start_origin:
                headers = dict(request.headers)
                headers[auth_name.lower()] = auth_value.strip()
                route.continue_(headers=headers)
            else:
                route.continue_()

        page.route("**/*", guard)
        try:
            while queue and len(pages) < max_pages and time.monotonic() < deadline:
                url = queue.pop(0)
                if url in seen:
                    continue
                seen.add(url)
                allowed, reason = check_url(url)
                if not allowed:
                    blocked.append({"url": _safe_url(url)[:500], "reason": reason})
                    continue
                row = {"url": _safe_url(url), "status": None, "title": "", "links": 0,
                       "forms": 0, "forms_detail": [], "error": ""}
                try:
                    response = page.goto(url, wait_until="domcontentloaded",
                                         timeout=max(1000, int((deadline - time.monotonic()) * 1000)))
                    row["status"] = response.status if response else None
                    row["title"] = page.title()[:200]
                    links = page.locator("a[href]").evaluate_all("els => els.map(e => e.href)")
                    row["links"] = len(links)
                    raw_forms = page.locator("form").evaluate_all("""els => els.map(form => ({
                        action: form.action || location.href,
                        method: (form.method || 'GET').toUpperCase(),
                        controls: Array.from(form.elements).filter(e => e.name).slice(0, 100).map(e => ({
                            name: e.name.slice(0, 100), type: (e.type || '').slice(0, 30),
                            autocomplete: (e.autocomplete || '').slice(0, 50)
                        }))
                    }))""")
                    row["forms_detail"] = _safe_form_details(url, raw_forms)
                    row["forms"] = len(row["forms_detail"])
                    observations.extend(_form_observations(url, raw_forms))
                    # Record form destinations without submitting the forms.
                    form_actions = [item.get("action", "") for item in raw_forms]
                    for candidate in [*links, *form_actions]:
                        absolute = urldefrag(urljoin(url, str(candidate))).url
                        if absolute not in seen and absolute not in queue:
                            ok, _ = check_url(absolute)
                            if ok:
                                queue.append(absolute)
                except Exception as exc:
                    error = re.sub(r"https?://\S+", lambda m: _safe_url(m.group(0).rstrip("'\"),.")), str(exc))
                    row["error"] = error[:300]
                pages.append(row)
        finally:
            context.close()
            browser.close()

    return {
        "start_url": _safe_url(start_url),
        "pages_visited": len(pages),
        "pages_queued": len(queue),
        "timed_out": bool(queue and time.monotonic() >= deadline),
        "pages": pages,
        "api_requests": [{**item, "url": _safe_url(item["url"])} for item in api_requests.values()],
        "blocked_requests": blocked,
        "observations": observations,
        "forms_submitted": 0,
        "forms_seen": sum(page["forms"] for page in pages),
        "links_seen": sum(page["links"] for page in pages),
        "responses_2xx": sum(1 for page in pages if isinstance(page["status"], int) and 200 <= page["status"] < 300),
        "pages_with_errors": sum(1 for page in pages if page["error"]),
        "scope_cidrs": scope.cidrs,
    }
