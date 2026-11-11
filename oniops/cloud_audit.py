"""Read-only AWS identity and exposure checks for one explicitly selected account."""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone


def _public_ingress_findings(group: dict) -> list[dict]:
    """Classify public ingress without treating portless protocols as all ports."""
    findings = []
    gid = str(group.get("GroupId") or "unknown")
    for permission in group.get("IpPermissions", []):
        start, end = permission.get("FromPort"), permission.get("ToPort")
        protocol = str(permission.get("IpProtocol") or "").lower()
        public_ranges = [
            item.get("CidrIp") for item in (permission.get("IpRanges") or [])
            if item.get("CidrIp") == "0.0.0.0/0"
        ] + [
            item.get("CidrIpv6") for item in (permission.get("Ipv6Ranges") or [])
            if item.get("CidrIpv6") == "::/0"
        ]
        if not public_ranges:
            continue
        if protocol == "-1" or (start is not None and end is not None and start <= 0 and end >= 65535):
            severity, label = "CRITICAL", "all ports/protocols"
        elif start is None or end is None:
            severity, label = "MEDIUM", f"protocol {protocol or 'unknown'} (no TCP/UDP port range)"
        elif any(start <= port <= end for port in (22, 3389)):
            severity, label = "HIGH", f"administrative port range {start}-{end}"
        else:
            severity, label = "MEDIUM", f"port range {start}-{end}"
        findings.append({
            "check_id": "AWS-EC2-PUBLIC-INGRESS", "severity": severity,
            "resource": gid, "title": "Security group allows public ingress",
            "evidence": f"{label} from {', '.join(public_ranges)}.",
            "remediation": "Restrict ingress to approved source ranges and remove unused rules.",
        })
    return findings


def _account_control_findings(summary: dict, password_policy: dict | None,
                              *, password_policy_missing: bool = False,
                              password_baseline: str = "aws_cis") -> list[dict]:
    """Interpret IAM account summary and password-policy state as read-only checks."""
    findings = []
    if str(summary.get("AccountMFAEnabled", "1")) == "0":
        findings.append({
            "check_id": "AWS-IAM-ROOT-NO-MFA", "severity": "HIGH", "resource": "root",
            "title": "AWS root account has no MFA",
            "evidence": "IAM account summary reports AccountMFAEnabled=0.",
            "remediation": "Enable MFA for the root user and avoid routine root-user access.",
        })
    if int(summary.get("AccountAccessKeysPresent", 0) or 0) > 0:
        findings.append({
            "check_id": "AWS-IAM-ROOT-ACCESS-KEY", "severity": "CRITICAL", "resource": "root",
            "title": "AWS root account has access keys",
            "evidence": "IAM account summary reports one or more root access keys.",
            "remediation": "Delete root access keys and use least-privilege IAM roles or users.",
        })
    if password_policy_missing:
        findings.append({
            "check_id": "AWS-IAM-NO-PASSWORD-POLICY", "severity": "MEDIUM", "resource": "account",
            "title": "AWS account has no custom IAM password policy",
            "evidence": "GetAccountPasswordPolicy returned NoSuchEntity; ONIOPS cannot establish the effective password baseline.",
            "remediation": "If IAM console passwords are used, configure a policy that meets the selected baseline; otherwise prefer federation.",
        })
    elif password_policy is not None:
        weak = []
        if password_baseline == "aws_cis":
            baseline_name = "AWS CIS style"
            if int(password_policy.get("MinimumPasswordLength", 0) or 0) < 14:
                weak.append("minimum length below 14")
            for key, label in (("RequireUppercaseCharacters", "uppercase"),
                               ("RequireLowercaseCharacters", "lowercase"),
                               ("RequireNumbers", "numbers"),
                               ("RequireSymbols", "symbols")):
                if not password_policy.get(key, False):
                    weak.append(f"{label} requirement disabled")
            if int(password_policy.get("PasswordReusePrevention", 0) or 0) < 24:
                weak.append("reuse prevention below 24 passwords")
            max_age = password_policy.get("MaxPasswordAge")
            if max_age is not None and int(max_age) > 90:
                weak.append("maximum password age over 90 days")
        else:
            baseline_name = "NIST SP 800-63B-4 single-factor length"
            if int(password_policy.get("MinimumPasswordLength", 0) or 0) < 15:
                weak.append("minimum length below 15 for single-factor password use")
        if weak:
            findings.append({
                "check_id": "AWS-IAM-WEAK-PASSWORD-POLICY", "severity": "MEDIUM", "resource": "account",
                "title": f"AWS IAM password policy misses the {baseline_name} baseline",
                "evidence": f"Baseline={password_baseline}; " + "; ".join(weak) + ".",
                "remediation": "Review the selected baseline against your authentication and compliance requirements; prefer federation for workforce access.",
            })
    return findings


def _public_acl_findings(bucket: str, acl: dict) -> list[dict]:
    """Detect bucket ACL grants to the globally authenticated or anonymous groups."""
    groups = {
        "http://acs.amazonaws.com/groups/global/AllUsers": "AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers": "AuthenticatedUsers",
    }
    grants = []
    for grant in acl.get("Grants", []):
        grantee = grant.get("Grantee") or {}
        group = groups.get(str(grantee.get("URI") or ""))
        permission = str(grant.get("Permission") or "").upper()
        if group and permission in {"READ", "WRITE", "READ_ACP", "WRITE_ACP", "FULL_CONTROL"}:
            grants.append((group, permission))
    if not grants:
        return []
    if any(permission in {"WRITE", "FULL_CONTROL"} for _, permission in grants):
        severity = "CRITICAL"
    elif any(permission == "READ" for _, permission in grants):
        severity = "HIGH"
    else:
        severity = "MEDIUM"
    evidence = ", ".join(f"{group}:{permission}" for group, permission in grants)
    return [{
        "check_id": "AWS-S3-PUBLIC-ACL", "severity": severity, "resource": bucket,
        "title": "S3 bucket ACL grants access to a global group", "evidence": evidence,
        "remediation": "Remove global ACL grants and enable S3 Block Public Access and bucket-owner-enforced ownership.",
    }]


def _eks_endpoint_findings(cluster: dict) -> list[dict]:
    """Report public EKS API endpoints, distinguishing unrestricted CIDRs."""
    network = cluster.get("resourcesVpcConfig") or {}
    if not network.get("endpointPublicAccess"):
        return []
    cidrs = network.get("publicAccessCidrs")
    if not cidrs:
        # EKS defaults to an unrestricted IPv4 public endpoint when unset.
        cidrs = ["0.0.0.0/0"]
    cidrs = [str(value) for value in cidrs]
    unrestricted = False
    for value in cidrs:
        try:
            if ipaddress.ip_network(value, strict=False).prefixlen == 0:
                unrestricted = True
        except ValueError:
            continue
    name = str(cluster.get("name") or cluster.get("arn") or "unknown")
    return [{
        "check_id": "AWS-EKS-PUBLIC-API", "severity": "HIGH" if unrestricted else "MEDIUM",
        "resource": str(cluster.get("arn") or name),
        "title": "EKS Kubernetes API endpoint is public",
        "evidence": f"endpointPublicAccess=true; publicAccessCidrs={', '.join(cidrs)}.",
        "remediation": "Disable public endpoint access or restrict it to approved CIDRs and retain private endpoint access where required.",
    }]


def audit_aws_account(account_id: str, *, profile: str = "default", region: str = "us-east-1",
                      password_baseline: str = "aws_cis") -> dict:
    """Run bounded, read-only IAM, security-group and S3 checks with boto3.

    The caller must provide the expected 12-digit account ID. OniOps verifies
    STS identity before making any inventory calls, preventing profile mix-ups.
    """
    if not re.fullmatch(r"\d{12}", str(account_id or "")):
        raise ValueError("Expected AWS account ID must contain exactly 12 digits.")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", profile):
        raise ValueError("AWS profile name contains unsupported characters.")
    if not re.fullmatch(r"[a-z]{2}(?:-gov)?-[a-z]+-\d", region):
        raise ValueError("AWS region name is invalid.")
    if password_baseline not in {"aws_cis", "nist_800_63b4"}:
        raise ValueError("password_baseline must be 'aws_cis' or 'nist_800_63b4'.")
    try:
        import boto3
        from botocore.exceptions import ClientError
    except ImportError as exc:
        raise RuntimeError("AWS account auditing needs boto3: install with `pip install 'oniops[cloud]'`.") from exc

    session = boto3.Session(profile_name=profile, region_name=region)
    try:
        identity = session.client("sts").get_caller_identity()
    except Exception as exc:
        raise RuntimeError(f"Could not verify AWS caller identity before audit: {str(exc)[:300]}") from exc
    actual_account = str(identity.get("Account") or "")
    if actual_account != account_id:
        raise PermissionError(
            f"AWS credential profile resolved to account {actual_account or '(unknown)'}, "
            f"not the explicitly requested account {account_id}. No inventory checks were run."
        )

    findings: list[dict] = []
    errors: list[dict] = []

    def add(check_id: str, severity: str, resource: str, title: str, evidence: str, remediation: str):
        findings.append({
            "check_id": check_id, "severity": severity, "resource": resource,
            "title": title, "evidence": evidence, "remediation": remediation,
        })

    def record_error(service: str, operation: str, exc: Exception):
        code = "unknown"
        if isinstance(exc, ClientError):
            code = str(exc.response.get("Error", {}).get("Code") or "unknown")
        errors.append({"service": service, "operation": operation, "code": code, "message": str(exc)[:300]})

    # IAM: users without MFA and old active access keys.
    iam = session.client("iam")
    try:
        summary = iam.get_account_summary().get("SummaryMap", {})
    except Exception as exc:
        summary = {}
        record_error("iam", "get_account_summary", exc)
    password_policy = None
    password_policy_missing = False
    try:
        password_policy = iam.get_account_password_policy().get("PasswordPolicy", {})
    except ClientError as exc:
        code = str(exc.response.get("Error", {}).get("Code") or "")
        if code == "NoSuchEntity":
            password_policy_missing = True
        else:
            record_error("iam", "get_account_password_policy", exc)
    except Exception as exc:
        record_error("iam", "get_account_password_policy", exc)
    findings.extend(_account_control_findings(
        summary, password_policy, password_policy_missing=password_policy_missing,
        password_baseline=password_baseline,
    ))
    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page.get("Users", []):
                name = str(user.get("UserName") or "")
                arn = str(user.get("Arn") or name)
                try:
                    devices = iam.list_mfa_devices(UserName=name).get("MFADevices", [])
                    if not devices:
                        add("AWS-IAM-USER-NO-MFA", "HIGH", arn,
                            "IAM user has no MFA device", f"User {name!r} has no registered MFA device.",
                            "Require MFA or replace long-lived IAM users with federated roles.")
                except Exception as exc:
                    record_error("iam", "list_mfa_devices", exc)
                try:
                    for key in iam.list_access_keys(UserName=name).get("AccessKeyMetadata", []):
                        if key.get("Status") != "Active" or not key.get("CreateDate"):
                            continue
                        age_days = (datetime.now(timezone.utc) - key["CreateDate"].astimezone(timezone.utc)).days
                        if age_days > 90:
                            add("AWS-IAM-OLD-ACCESS-KEY", "MEDIUM", f"{arn}/{key.get('AccessKeyId', '')}",
                                "Active access key is older than 90 days", f"Active key age: {age_days} days.",
                                "Rotate the key or migrate the workload to short-lived role credentials.")
                except Exception as exc:
                    record_error("iam", "list_access_keys", exc)
    except Exception as exc:
        record_error("iam", "list_users", exc)

    # EC2: public ingress rules on administrative ports or all ports.
    ec2 = session.client("ec2", region_name=region)
    try:
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for group in page.get("SecurityGroups", []):
                findings.extend(_public_ingress_findings(group))
    except Exception as exc:
        record_error("ec2", "describe_security_groups", exc)

    # EKS: read-only regional Kubernetes control-plane endpoint exposure.
    eks = session.client("eks", region_name=region)
    try:
        paginator = eks.get_paginator("list_clusters")
        for page in paginator.paginate():
            for name in page.get("clusters", []):
                try:
                    cluster = eks.describe_cluster(name=name).get("cluster", {})
                    findings.extend(_eks_endpoint_findings(cluster))
                except Exception as exc:
                    record_error("eks", "describe_cluster", exc)
    except Exception as exc:
        record_error("eks", "list_clusters", exc)

    # S3: public-policy state and server-side encryption.
    s3 = session.client("s3")
    try:
        for bucket in s3.list_buckets().get("Buckets", []):
            name = str(bucket.get("Name") or "")
            try:
                status = s3.get_bucket_policy_status(Bucket=name).get("PolicyStatus", {})
                if status.get("IsPublic"):
                    add("AWS-S3-PUBLIC-POLICY", "HIGH", name, "S3 bucket policy is public",
                        "GetBucketPolicyStatus reports IsPublic=true.",
                        "Remove public principals and enable all S3 Block Public Access settings.")
            except ClientError as exc:
                code = str(exc.response.get("Error", {}).get("Code") or "")
                if code not in {"NoSuchBucketPolicy", "NoSuchBucketPolicyStatus"}:
                    record_error("s3", "get_bucket_policy_status", exc)
            except Exception as exc:
                record_error("s3", "get_bucket_policy_status", exc)
            try:
                findings.extend(_public_acl_findings(name, s3.get_bucket_acl(Bucket=name)))
            except Exception as exc:
                record_error("s3", "get_bucket_acl", exc)
            try:
                s3.get_bucket_encryption(Bucket=name)
            except ClientError as exc:
                code = str(exc.response.get("Error", {}).get("Code") or "")
                if code == "ServerSideEncryptionConfigurationNotFoundError":
                    add("AWS-S3-NO-DEFAULT-ENCRYPTION", "MEDIUM", name,
                        "S3 bucket has no default encryption configuration",
                        "GetBucketEncryption returned no server-side encryption configuration.",
                        "Enable default server-side encryption for the bucket.")
                else:
                    record_error("s3", "get_bucket_encryption", exc)
            except Exception as exc:
                record_error("s3", "get_bucket_encryption", exc)
    except Exception as exc:
        record_error("s3", "list_buckets", exc)

    rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    findings.sort(key=lambda item: (-rank.get(item["severity"], 0), item["check_id"], item["resource"]))
    return {
        "scanner": "oniops-aws-readonly-v1",
        "target_type": "aws_account",
        "account_id": account_id,
        "caller_arn": str(identity.get("Arn") or ""),
        "profile": profile,
        "region": region,
        "password_baseline": password_baseline,
        "read_only": True,
        "findings": findings,
        "finding_count": len(findings),
        "errors": errors,
        "partial": bool(errors),
    }
