from __future__ import annotations

import hashlib

import pytest

from oniops.agent import _report_finding
from oniops.artifact_scan import scan_local_container_image
from oniops.cloud_audit import audit_aws_account
from oniops.config import HostConfig
from oniops.evaluation import POSITIVE_CASES, _score_findings, run_demo_evaluation
from oniops.kali import CmdResult, KaliRunner, docker_worker_argv
from oniops.playbooks import load_playbooks
from oniops.scope import ScopeViolation


def test_docker_worker_argv_is_bounded_and_non_root():
    host = HostConfig(
        host="10.0.0.9", execution_mode="docker", worker_image="oniops-worker:stable",
        worker_network="oniops-worker-net", worker_user="10001:10001",
    )
    cmd = docker_worker_argv(
        host, ["nmap", "-sV", "10.0.0.15"], timeout=45,
        scope_cidrs=["10.0.0.0/24"],
    )
    assert cmd[:5] == ["timeout", "-k", "5s", "45s", "docker"]
    assert "--read-only" in cmd
    assert "--cap-drop=ALL" in cmd
    assert "--cap-add=NET_ADMIN" in cmd
    assert "--cap-add=SETUID" in cmd
    assert "--cap-add=SETGID" in cmd
    assert "--security-opt=no-new-privileges" in cmd
    assert cmd[cmd.index("--env") + 1] == "HOME=/tmp"
    assert "ONIOPS_SCOPE_CIDRS=10.0.0.0/24" in cmd
    assert cmd[cmd.index("--entrypoint") + 1] == "/usr/local/sbin/oniops-worker-entrypoint"
    assert cmd[cmd.index("oniops-worker:stable") + 1:] == ["nmap", "-sV", "10.0.0.15"]


def test_docker_worker_requires_effective_scope_and_forbids_host_network():
    host = HostConfig(host="10.0.0.9", execution_mode="docker", worker_image="oniops-worker:stable")
    with pytest.raises(ValueError, match="effective in-scope CIDR"):
        docker_worker_argv(host, ["nmap", "10.0.0.15"])
    host.worker_network = "host"
    with pytest.raises(ValueError, match="built-in modes bypass"):
        docker_worker_argv(host, ["nmap", "10.0.0.15"], scope_cidrs=["10.0.0.0/24"])
    host.worker_network = "oniops-worker-net"
    with pytest.raises(ValueError, match="Invalid effective worker scope"):
        docker_worker_argv(host, ["nmap", "10.0.0.15"], scope_cidrs=["10.0.0.0/24; echo unsafe"])


def test_docker_worker_rejects_invalid_image_and_resources():
    host = HostConfig(host="10.0.0.9", execution_mode="docker", worker_image="bad;image")
    with pytest.raises(ValueError):
        docker_worker_argv(host, ["nmap", "10.0.0.15"])
    host.worker_image = "oniops-worker:stable"
    host.worker_memory_mb = 10
    with pytest.raises(ValueError):
        docker_worker_argv(host, ["nmap", "10.0.0.15"])


def test_docker_build_context_excludes_workspace_files():
    from pathlib import Path

    rules = Path(__file__).parents[1].joinpath(".dockerignore").read_text().splitlines()
    assert "**" in rules
    assert "!Dockerfile.worker" in rules
    assert "!scripts/oniops-worker-entrypoint" in rules


def test_scope_effective_cidrs_subtract_exclusions(scope):
    from ipaddress import ip_address, ip_network

    networks = [ip_network(cidr) for cidr in scope.effective_cidrs]
    assert not any(ip_address("10.0.0.1") in network for network in networks)
    assert any(ip_address("10.0.0.2") in network for network in networks)
    assert any(ip_address("192.168.50.200") in network for network in networks)


def test_kali_runner_passes_exclusion_aware_scope_to_docker_worker(scope, monkeypatch):
    from ipaddress import ip_address, ip_network

    host = HostConfig(
        host="10.0.0.9", execution_mode="docker", worker_image="oniops-worker:stable",
        worker_user="10001:10001", worker_network="oniops-worker-net",
    )
    runner = KaliRunner(host=host, scope=scope, limiter=type("NoWait", (), {"acquire": lambda *_: None,
                                                                              "penalize": lambda *_: None})())
    captured = {}
    monkeypatch.setattr(runner, "_exec", lambda command, timeout: captured.update(command=command) or CmdResult(0, "ok"))
    assert runner.run(["nmap", "10.0.0.2"]).ok
    command = captured["command"]
    cidrs = next(arg.split("=", 1)[1] for arg in command.split() if arg.startswith("ONIOPS_SCOPE_CIDRS="))
    networks = [ip_network(item.strip("'\"")) for item in cidrs.split(",")]
    assert not any(ip_address("10.0.0.1") in network for network in networks)


def test_worker_firewall_is_fail_closed_and_drops_privileges():
    from pathlib import Path

    script = Path(__file__).parents[1].joinpath("scripts/oniops-worker-entrypoint").read_text()
    assert "iptables -w -P OUTPUT DROP" in script
    assert "ip6tables -w -P OUTPUT DROP" in script
    assert "/proc/net/if_inet6" in script
    assert "require_command setpriv 123" in script
    assert 'require_command "$1" 124' in script
    assert "127.0.0.11/32" in script
    assert "--bounding-set=-all" in script
    assert "exec setpriv" in script


def test_nested_playbook_pack_metadata_and_hash(tmp_path):
    path = tmp_path / "community" / "cloud" / "audit.yaml"
    path.parent.mkdir(parents=True)
    content = """id: cloud_audit
version: 2.1.0
pack:
  id: community_cloud
  author: Test Author
required_tools: [nmap]
safety: passive
tags: [cloud, iam]
steps:
  - name: AWS identity posture
    cmd: [nmap, -sV, "{target}"]
"""
    path.write_text(content)
    pack = load_playbooks(tmp_path)["cloud_audit"]
    assert pack["version"] == "2.1.0"
    assert pack["pack"]["id"] == "community_cloud"
    assert pack["required_tools"] == ["nmap"]
    assert pack["source"] == "community/cloud/audit.yaml"
    assert pack["content_sha256"] == hashlib.sha256(content.encode()).hexdigest()


def test_playbook_loader_reports_duplicate_pack_ids(tmp_path):
    body = 'id: same_pack\nsteps:\n  - cmd: [nmap, -sV, "{target}"]\n'
    (tmp_path / "one.yaml").write_text(body)
    (tmp_path / "two.yaml").write_text(body)
    diagnostics = []
    loaded = load_playbooks(tmp_path, diagnostics=diagnostics)
    assert list(loaded) == ["same_pack"]
    assert any("Duplicate playbook id" in item for item in diagnostics)


def test_playbook_pack_cannot_run_arbitrary_remote_commands():
    from oniops.playbooks import validate_playbook

    with pytest.raises(ValueError, match="unsupported command"):
        validate_playbook({
            "id": "unsafe_pack", "steps": [{"cmd": ["python3", "-c", "print(1)"]}],
        })


def test_browser_crawl_refuses_out_of_scope_url_before_optional_import(scope):
    from oniops.browser import crawl_web_app

    with pytest.raises(ScopeViolation):
        crawl_web_app("http://example.com/", scope)


def test_browser_form_observations_never_include_values():
    from oniops.browser import _form_observations, _safe_form_details, _safe_url

    forms = [{
        "action": "http://app.test/login?token=secret", "method": "GET",
        "controls": [{"name": "password", "type": "password", "autocomplete": "current-password"}],
    }]
    observations = _form_observations("http://app.test/", forms)
    assert {o["check_id"] for o in observations} == {
        "WEB-FORM-SENSITIVE-GET", "WEB-FORM-CLEARTEXT-CREDENTIALS",
    }
    assert all("secret" not in str(item) for item in observations)
    assert all(item["status"] == "OBSERVED" for item in observations)
    safe = _safe_form_details("http://app.test/", forms)
    assert "secret" not in str(safe)
    assert "user:pass" not in _safe_url("http://user:pass@app.test/form?access_token=secret")
    assert "secret" not in _safe_url("http://user:pass@app.test/form?access_token=secret")


def test_agent_verifier_rejects_non_origin_relative_path():
    class Runner:
        def run(self, *_args, **_kwargs):
            raise AssertionError("unsafe path must be rejected before network execution")

    result = _report_finding(Runner(), "127.0.0.1", {"path": "//example.com/secret"})
    assert "origin-relative" in result


def test_agent_verifier_rejects_control_character_indicator():
    class Runner:
        def run(self, *_args, **_kwargs):
            raise AssertionError("invalid indicator must be rejected before network execution")

    result = _report_finding(Runner(), "127.0.0.1", {"expected_indicator": "safe\nunsafe"})
    assert "printable characters" in result


def test_cloud_audit_requires_explicit_account_id_before_credentials():
    with pytest.raises(ValueError, match="12 digits"):
        audit_aws_account("1234")


def test_cloud_audit_rejects_wrong_account_before_inventory(monkeypatch):
    import sys
    from types import ModuleType

    calls = []

    class FakeClientError(Exception):
        pass

    class Session:
        def client(self, service, **_kwargs):
            calls.append(service)
            if service == "sts":
                return type("STS", (), {"get_caller_identity": lambda _self: {"Account": "999999999999"}})()
            raise AssertionError("inventory API must not run after account mismatch")

    boto3 = ModuleType("boto3")
    boto3.Session = lambda **_kwargs: Session()
    botocore = ModuleType("botocore")
    botocore.__path__ = []
    exceptions = ModuleType("botocore.exceptions")
    exceptions.ClientError = FakeClientError
    monkeypatch.setitem(sys.modules, "boto3", boto3)
    monkeypatch.setitem(sys.modules, "botocore", botocore)
    monkeypatch.setitem(sys.modules, "botocore.exceptions", exceptions)

    with pytest.raises(PermissionError, match="No inventory checks were run"):
        audit_aws_account("123456789012")
    assert calls == ["sts"]


def test_aws_public_ingress_classifies_protocols_and_ports():
    from oniops.cloud_audit import _public_ingress_findings

    def check(permission):
        return _public_ingress_findings({
            "GroupId": "sg-demo", "IpPermissions": [{
                **permission, "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        })[0]

    icmp = check({"IpProtocol": "icmp", "FromPort": -1, "ToPort": -1})
    all_protocols = check({"IpProtocol": "-1"})
    ssh = check({"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22})
    assert icmp["severity"] == "MEDIUM"
    assert all_protocols["severity"] == "CRITICAL"
    assert ssh["severity"] == "HIGH"


def test_aws_identity_and_password_policy_controls():
    from oniops.cloud_audit import _account_control_findings

    findings = _account_control_findings({
        "AccountMFAEnabled": 0, "AccountAccessKeysPresent": 1,
    }, None, password_policy_missing=True)
    assert {item["check_id"] for item in findings} == {
        "AWS-IAM-ROOT-NO-MFA", "AWS-IAM-ROOT-ACCESS-KEY", "AWS-IAM-NO-PASSWORD-POLICY",
    }
    assert next(item for item in findings if item["check_id"] == "AWS-IAM-ROOT-ACCESS-KEY")["severity"] == "CRITICAL"
    assert not _account_control_findings({}, None)  # unreadable policy is not mislabeled as absent

    strong = {
        "MinimumPasswordLength": 14, "RequireUppercaseCharacters": True,
        "RequireLowercaseCharacters": True, "RequireNumbers": True,
        "RequireSymbols": True, "PasswordReusePrevention": 24, "MaxPasswordAge": 90,
    }
    assert not _account_control_findings({"AccountMFAEnabled": 1}, strong)


def test_nist_password_profile_does_not_flag_composition_or_periodic_rotation():
    from oniops.cloud_audit import _account_control_findings

    policy = {
        "MinimumPasswordLength": 15, "RequireUppercaseCharacters": False,
        "RequireLowercaseCharacters": False, "RequireNumbers": False,
        "RequireSymbols": False, "PasswordReusePrevention": 0, "MaxPasswordAge": 0,
    }
    assert not _account_control_findings(
        {"AccountMFAEnabled": 1}, policy, password_baseline="nist_800_63b4",
    )
    issues = _account_control_findings(
        {"AccountMFAEnabled": 1}, {**policy, "MinimumPasswordLength": 14},
        password_baseline="nist_800_63b4",
    )
    assert "below 15" in issues[0]["evidence"]


def test_aws_s3_acl_global_grants_are_findings():
    from oniops.cloud_audit import _public_acl_findings

    acl = {"Grants": [{
        "Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
        "Permission": "READ",
    }]}
    finding = _public_acl_findings("demo-bucket", acl)[0]
    assert finding["check_id"] == "AWS-S3-PUBLIC-ACL"
    assert finding["severity"] == "HIGH"
    assert _public_acl_findings("private-bucket", {"Grants": []}) == []


def test_eks_public_endpoint_severity_uses_allowed_cidrs():
    from oniops.cloud_audit import _eks_endpoint_findings

    base = {"name": "staging", "resourcesVpcConfig": {"endpointPublicAccess": True}}
    assert _eks_endpoint_findings(base)[0]["severity"] == "HIGH"
    base["resourcesVpcConfig"]["publicAccessCidrs"] = ["203.0.113.4/32"]
    assert _eks_endpoint_findings(base)[0]["severity"] == "MEDIUM"
    base["resourcesVpcConfig"]["endpointPublicAccess"] = False
    assert _eks_endpoint_findings(base) == []


def test_container_scan_only_uses_local_image_and_offline_trivy():
    class Result:
        def __init__(self, rc, out):
            self.rc = rc
            self.out = out

        @property
        def ok(self):
            return self.rc == 0

    class Runner:
        host = HostConfig(host="10.0.0.9")

        def __init__(self):
            self.commands = []

        def run(self, cmd, timeout):
            self.commands.append((cmd, timeout))
            if cmd[:3] == ["docker", "image", "inspect"]:
                return Result(0, "sha256:" + "a" * 64)
            return Result(0, '{"Results":[{"Vulnerabilities":[{"Severity":"HIGH"}]}]}')

    runner = Runner()
    result = scan_local_container_image("app:stable", runner)
    assert result["total_findings"] == 1
    assert result["counts_by_severity"]["HIGH"] == 1
    assert runner.commands[0][0][:3] == ["docker", "image", "inspect"]
    assert runner.commands[1][0][:5] == ["trivy", "image", "--image-src", "docker", "--skip-db-update"]
    assert all("pull" not in cmd for cmd, _ in runner.commands)


def test_demo_evaluation_reports_fixture_limits_and_false_positive():
    result = run_demo_evaluation()
    assert result["benchmark_class"] == "controlled_fixture"
    assert result["metrics"]["true_positive"] == len(result["positive_cases"])
    assert result["metrics"]["false_positive"] == 0
    assert result["metrics"]["false_negative"] == 0
    assert not result["known_false_positives"]
    assert "not an estimate" in result["limitation"]


def test_demo_evaluation_counts_duplicate_verified_alert_as_false_positive():
    title = next(iter(POSITIVE_CASES.values()))
    scored = _score_findings([
        {"title": title, "status": "VERIFIED"},
        {"title": title, "status": "VERIFIED"},
    ])
    assert scored["metrics"]["true_positive"] == 1
    assert scored["metrics"]["false_positive"] == 1
    assert scored["metrics"]["false_negative"] == len(POSITIVE_CASES) - 1
