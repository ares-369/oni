"""Local container-image assessment through tools on the configured attack host."""
from __future__ import annotations

import json
import re

from .kali import KaliRunner

_IMAGE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@:+-]{0,200}$")


def scan_local_container_image(image: str, runner: KaliRunner) -> dict:
    """Scan an image already present in the attack host's Docker daemon.

    The command never pulls an image. The operator must stage the image first;
    Trivy runs offline so evaluation results do not depend on a moving DB.
    """
    ref = (image or "").strip()
    if not _IMAGE_REF.fullmatch(ref) or ref.startswith(("-", "/")) or ".." in ref:
        raise ValueError("Image must be a local Docker image name or digest, not a URL or filesystem path.")
    if getattr(runner.host, "execution_mode", "ssh") == "docker":
        raise ValueError("Local image scanning needs SSH execution so ONIOPS can inspect the attack host's Docker daemon.")

    inspect = runner.run(["docker", "image", "inspect", "--format", "{{.Id}}", ref], timeout=20)
    if not inspect.ok or not inspect.out.strip().startswith("sha256:"):
        raise RuntimeError(f"Image {ref!r} is not present in the attack host's local Docker daemon.")

    result = runner.run([
        "trivy", "image", "--image-src", "docker", "--skip-db-update",
        "--scanners", "vuln,misconfig,secret", "--format", "json", ref,
    ], timeout=600)
    if not result.ok:
        raise RuntimeError(f"Trivy image scan failed (exit {result.rc}): {result.out[-1200:]}")
    raw = result.out
    start = raw.find("{")
    try:
        report = json.loads(raw[start:]) if start >= 0 else {}
    except json.JSONDecodeError as exc:
        raise RuntimeError("Trivy completed but did not return valid JSON.") from exc

    counts = {name: 0 for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")}
    results = report.get("Results") or []
    for target in results:
        for key in ("Vulnerabilities", "Misconfigurations", "Secrets"):
            for issue in target.get(key) or []:
                severity = str(issue.get("Severity") or "UNKNOWN").upper()
                counts[severity if severity in counts else "UNKNOWN"] += 1
    return {
        "scanner": "trivy",
        "target_type": "local_container_image",
        "image": ref,
        "image_id": inspect.out.strip().splitlines()[0],
        "offline_db": True,
        "counts_by_severity": counts,
        "total_findings": sum(counts.values()),
        "report": report,
    }
