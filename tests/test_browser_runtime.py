"""Optional browser integration checks against an ephemeral loopback application."""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest


def test_playwright_crawler_observes_forms_api_and_blocks_unsafe_requests():
    pytest.importorskip("playwright.sync_api")

    from oniops.browser import crawl_web_app
    from oniops.demo import demo_scope

    class Handler(BaseHTTPRequestHandler):
        posts_received = 0

        def log_message(self, *_args):
            pass

        def do_GET(self):
            if self.path == "/":
                body = b"""<!doctype html><title>Browser fixture</title>
                <form method=get action='/login?token=fixture-secret'>
                  <input type=password name=password autocomplete=current-password>
                </form>
                <a href='/next'>next</a>
                <script>
                  fetch('/api/status');
                  fetch('http://127.0.0.2/out-of-scope');
                  fetch('/mutate', {method:'POST'});
                </script>"""
                ctype = "text/html"
            else:
                body = b'{"ok":true}'
                ctype = "application/json"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            type(self).posts_received += 1
            self.send_response(200)
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/"
        result = crawl_web_app(url, demo_scope(), max_pages=5, max_seconds=15)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert result["pages_visited"] >= 2
    assert result["forms_submitted"] == 0
    assert result["forms_seen"] == 1
    assert {item["check_id"] for item in result["observations"]} == {
        "WEB-FORM-SENSITIVE-GET", "WEB-FORM-CLEARTEXT-CREDENTIALS",
    }
    assert "fixture-secret" not in str(result)
    assert any(item.get("status") == 200 for item in result["api_requests"])
    assert any("127.0.0.2" in item["url"] for item in result["blocked_requests"])
    assert any("POST" in item["reason"] for item in result["blocked_requests"])
    assert Handler.posts_received == 0
