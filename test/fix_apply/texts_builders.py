"""Item records and results of a line for the text tests."""

from __future__ import annotations

from typing import Any


def record(pkg: str, status: str = "applied", **fields: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "pkg": pkg,
        "class": "lang",
        "method": "dependabot",
        "status": status,
        "reason": None,
        "reason_code": None,
        "installed": ["1.0.0"],
        "planned": ["1.0.1"],
        "vulns": [f"CVE-{pkg}"],
        "severities": ["HIGH"],
        "changes": [],
        "files": [],
    }
    if status == "applied":
        base["changes"] = [
            {"name": pkg, "from": "1.0.0", "to": "1.0.2", "directory": "/"}
        ]
        base["files"] = ["package-lock.json"]
    if status == "manual":
        base.update(reason=f"why {pkg}", reason_code="gate_still_present")
    if status == "already_fixed":
        base.update(
            reason="already fixed on the branch (not_in_baseline)",
            reason_code="not_in_baseline",
        )
    return {**base, **fields}


def result(items: list[dict[str, Any]], **fields: Any) -> dict[str, Any]:
    return {
        "branch": "release-1.2",
        "ref": "1.2.3",
        "baseline_findings": 4,
        "baseline_ci": "success",
        "seconds": 5,
        "docker": {"status": "none", "changes": []},
        "items": items,
        "files": ["package-lock.json"],
        **fields,
    }
