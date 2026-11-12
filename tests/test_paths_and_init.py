"""Path resolution for checkout vs installed layouts, and `oniops init`."""
from pathlib import Path

from oniops import cli, paths


def test_checkout_layout_uses_repo_root(monkeypatch):
    monkeypatch.delenv("ONIOPS_HOME", raising=False)
    assert paths.is_checkout()
    assert paths.app_dir() == paths.REPO_ROOT
    assert paths.home_dir() == paths.REPO_ROOT


def test_installed_layout_uses_bundle_and_home(monkeypatch, tmp_path):
    bundle = tmp_path / "_app"
    bundle.mkdir()
    (bundle / "webui.py").write_text("")
    monkeypatch.setattr(paths, "BUNDLE_DIR", bundle)
    monkeypatch.setattr(paths, "is_checkout", lambda: False)
    monkeypatch.delenv("ONIOPS_HOME", raising=False)
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "user")
    assert paths.app_dir() == bundle
    assert paths.home_dir() == tmp_path / "user" / ".oniops"


def test_oniops_home_env_wins(monkeypatch, tmp_path):
    monkeypatch.setenv("ONIOPS_HOME", str(tmp_path / "h"))
    assert paths.home_dir() == tmp_path / "h"


def test_init_creates_files_and_never_overwrites(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("ONIOPS_HOME", str(tmp_path))
    assert cli._init() == 0
    cfg, env = tmp_path / "config.yaml", tmp_path / ".env"
    assert cfg.read_text() == (paths.REPO_ROOT / "config.example.yaml").read_text()
    key = env.read_text().strip().split("=", 1)[1]
    assert len(key) == 64
    assert (env.stat().st_mode & 0o777) == 0o600
    assert (tmp_path / "data").is_dir()
    assert key not in capsys.readouterr().out  # the key is never printed

    cfg.write_text("mine")
    env.write_text("ONIOPS_SECRET_KEY=keep")
    assert cli._init() == 0
    assert cfg.read_text() == "mine"
    assert env.read_text() == "ONIOPS_SECRET_KEY=keep"
