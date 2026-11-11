"""Install script, deploy files and CLI first-run UX."""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from oniops.cli import cli_main

ROOT = Path(__file__).resolve().parent.parent
SUBCOMMANDS = ["serve", "version", "playbooks", "doctor", "whitebox", "findings", "retest", "backup",
               "restore", "assess", "diff", "selftest", "benchmark", "demo", "crawl",
               "container-scan", "cloud-audit"]


def test_top_level_help_exits_zero(capsys):
    with pytest.raises(SystemExit) as exc:
        cli_main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for name in SUBCOMMANDS:
        assert name in out


@pytest.mark.parametrize("sub", SUBCOMMANDS)
def test_every_subcommand_help_exits_zero(sub, capsys):
    with pytest.raises(SystemExit) as exc:
        cli_main([sub, "--help"])
    assert exc.value.code == 0
    assert f"oniops {sub}" in capsys.readouterr().out


def test_missing_config_is_a_clean_error(monkeypatch, capsys):
    import oniops.cli as cli

    def boom(*a, **k):
        raise FileNotFoundError("No config.yaml found at /x/config.yaml. Copy config.example.yaml")

    monkeypatch.setattr(cli, "get_config", boom)
    assert cli_main(["doctor"]) == 2
    assert "config.yaml" in capsys.readouterr().err


def test_diff_on_empty_db_is_a_clean_error(tmp_path, capsys):
    assert cli_main(["diff", "1", "--db", str(tmp_path / "e.sqlite")]) == 2
    assert "no assessments" in capsys.readouterr().err


def test_restore_missing_backup_is_a_clean_error(tmp_path, capsys):
    assert cli_main(["restore", str(tmp_path / "nope.sqlite"), "--db", str(tmp_path / "t.sqlite")]) == 2
    assert "does not exist" in capsys.readouterr().err


def test_retest_needs_id_or_all(cfg_path, tmp_path, capsys):
    assert cli_main(["retest", "--db", str(tmp_path / "t.sqlite")]) == 2
    assert "--id" in capsys.readouterr().err


def test_assess_rejects_unknown_profile(cfg_path, capsys):
    assert cli_main(["assess", "127.0.0.1", "--profile", "webapp_pt"]) == 2
    err = capsys.readouterr().err
    assert "unknown profile" in err and "web_app_pt" in err


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_install_script_is_idempotent_and_never_overwrites(tmp_path):
    for name in ("requirements.txt", "config.example.yaml", ".env.example", "pyproject.toml"):
        shutil.copy(ROOT / name, tmp_path / name)
    (tmp_path / "oniops").mkdir()
    (tmp_path / "scripts").mkdir()
    shutil.copy(ROOT / "scripts" / "install.sh", tmp_path / "scripts" / "install.sh")
    env = {"PATH": "/usr/bin:/bin:/usr/local/bin", "PYTHON": sys.executable, "ONIOPS_SKIP_PIP": "1",
           "HOME": str(tmp_path)}

    def run():
        return subprocess.run(["bash", str(tmp_path / "scripts" / "install.sh")], cwd=tmp_path, env=env,
                              capture_output=True, text=True, timeout=120)

    first = run()
    if first.returncode != 0 and "virtualenv" in first.stderr:
        pytest.skip("venv module unavailable")
    assert first.returncode == 0, first.stderr
    assert (tmp_path / "config.yaml").read_text() == (ROOT / "config.example.yaml").read_text()
    env_text = (tmp_path / ".env").read_text()
    key_lines = [ln for ln in env_text.splitlines() if ln.startswith("ONIOPS_SECRET_KEY=")]
    assert len(key_lines) == 1 and len(key_lines[0].split("=", 1)[1]) == 64
    assert (tmp_path / "secrets").is_dir() and (tmp_path / "data").is_dir()

    # User edits must survive a second run.
    (tmp_path / "config.yaml").write_text("# mine\n")
    (tmp_path / ".env").write_text(env_text + "ANTHROPIC_API_KEY=keep\n")
    before = ((tmp_path / "config.yaml").read_text(), (tmp_path / ".env").read_text())
    second = run()
    assert second.returncode == 0, second.stderr
    assert ((tmp_path / "config.yaml").read_text(), (tmp_path / ".env").read_text()) == before


def test_compose_publishes_loopback_only_and_keeps_login_guard():
    text = (ROOT / "docker-compose.yml").read_text()
    assert '"127.0.0.1:8501:8501"' in text
    active = [ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    assert not any("ONIOPS_ALLOW_UNAUTHENTICATED_NETWORK" in ln for ln in active)


def test_dockerfile_ships_what_the_app_loads_at_runtime():
    text = (ROOT / "Dockerfile").read_text()
    for needed in ("COPY playbooks/", "COPY templates/", "COPY webui.py", "curl"):
        assert needed in text
    ignored = (ROOT / ".dockerignore").read_text().split()
    # The blanket "**" rule must re-include everything the controller image COPYs.
    for path in ("requirements.txt", "pyproject.toml", "oniops/", "webui.py", "playbooks/", "templates/", "static/"):
        assert f"!{path}" in ignored


def test_systemd_unit_matches_how_the_app_starts():
    unit = (ROOT / "deploy" / "systemd" / "oniops.service").read_text()
    assert "WorkingDirectory=/opt/oniops" in unit
    assert "Environment=ONIOPS_CONFIG=/opt/oniops/config.yaml" in unit
    assert "ExecStart=/opt/oniops/venv/bin/python -m oniops" in unit
