"""`oniops demo`: zero-config first run, DEMO labelling, real ledger untouched,
loopback-only runner and target."""
from __future__ import annotations

import io
import shutil

import pytest

from oniops.cli import cli_main
from oniops.config import AuthConfig, Config, HostConfig, ScopeConfig
from oniops.demo import demo_scope, run_demo
from oniops.demo_target import DemoTarget, is_loopback_host
from oniops.local_runner import LocalRunner
from oniops.scope import Scope

needs_curl = pytest.mark.skipif(shutil.which("curl") is None, reason="curl binary not installed")


@pytest.fixture()
def no_config(tmp_path, monkeypatch):
    """No config.yaml anywhere reachable; a would-be real ledger path to watch."""
    import oniops.config as c
    monkeypatch.setenv("ONIOPS_CONFIG", str(tmp_path / "missing" / "config.yaml"))
    real_db = tmp_path / "real" / "oniops.sqlite"
    monkeypatch.setenv("ONIOPS_DB_PATH", str(real_db))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(c, "_CONFIG", None)
    return real_db


@needs_curl
def test_demo_cli_runs_with_no_config(no_config, capsys):
    rc = cli_main(["demo"])
    out = capsys.readouterr().out
    assert rc == 0
    lines = [ln for ln in out.splitlines() if ln.strip()]
    assert lines and all(ln.startswith("[DEMO]") for ln in lines)
    assert "VERIFIED" in out and "fix-first score" in out
    assert "after the demo target is switched to its fixed state: FIXED" in out
    assert "AI features are off in demo mode" in out
    assert not no_config.exists() and not no_config.parent.exists()   # real ledger untouched


@needs_curl
def test_demo_kept_db_is_separate(no_config, tmp_path):
    keep = tmp_path / "demo-keep.sqlite"
    buf = io.StringIO()
    assert run_demo(db_path=keep, out=buf, show_fixed=False) == 0
    assert keep.exists() and not no_config.exists()
    assert "fixed state" not in buf.getvalue()


def test_demo_refuses_real_ledger_path(no_config, capsys):
    no_config.parent.mkdir(parents=True)
    assert cli_main(["demo", "--db", str(no_config)]) == 2
    assert "Refusing" in capsys.readouterr().err
    assert not no_config.exists()


def test_local_runner_refuses_non_loopback_target():
    runner = LocalRunner(demo_scope())
    for url in ("http://10.0.0.5/", "http://192.168.1.1:8080/x", "http://example.com/"):
        res = runner.run(["curl", "-ksS", url])
        assert res.rc == 126, url
    assert runner.commands_run == []


def test_local_runner_refuses_non_curl_and_redirect_flags():
    runner = LocalRunner(demo_scope())
    assert runner.run(["nmap", "127.0.0.1"]).rc == 126
    assert runner.run(["curl", "-x", "http://10.0.0.5:3128", "http://127.0.0.1/"]).rc == 126
    assert runner.run(["curl", "-o", "/tmp/x", "http://127.0.0.1/"]).rc == 126
    assert runner.run(["curl", "-ksS"]).rc == 126   # no explicit target URL


def test_local_runner_refuses_non_loopback_scope():
    host = HostConfig(host="127.0.0.1")
    cfg = Config(raw={}, instance_name="t", external_url="", bind_host="127.0.0.1", bind_port=1,
                 scope=ScopeConfig(allowed_cidrs=["10.0.0.0/24"]), kali=host, hosts=[host],
                 auth=AuthConfig(), llm={}, integrations={}, path=None)
    with pytest.raises(ValueError):
        LocalRunner(Scope(cfg))


@pytest.mark.parametrize("addr", ["0.0.0.0", "10.0.0.5", "::", "192.168.1.10", "example.com"])
def test_demo_target_refuses_non_loopback_bind(addr):
    with pytest.raises(ValueError):
        DemoTarget(host=addr)


def test_demo_target_loopback_only_and_ephemeral():
    assert is_loopback_host("127.0.0.1") and is_loopback_host("::1") and not is_loopback_host("0.0.0.0")
    with DemoTarget() as t:
        assert t.ip == "127.0.0.1" and t.port > 0
        assert t.base_url.startswith("http://127.0.0.1:")
