"""Builders of plan items, Dependabot outcomes and fake tools for the applier tests."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from apply import Tools
from dependabot import Outcome
from scan import Finding


def item(
    pkg: str = "hono",
    method: str = "dependabot",
    fallback: str | None = "npm-override",
    ecosystem: str = "npm",
    installed: str = "2.0.12",
    target: str | None = "2.1.5",
    locations: tuple[str, ...] = ("package-lock.json",),
    cls: str = "lang",
    reason: str | None = None,
    reason_code: str | None = None,
) -> dict[str, Any]:
    return {
        "pkg": pkg,
        "class": cls,
        "ecosystem": ecosystem,
        "relationship": "indirect",
        "locations": list(locations),
        "where": ["source-1.2.3"],
        "targets": [{"installed": installed, "target": target, "evidence": "e"}],
        "method": method,
        "fallback": fallback,
        "reason": reason,
        "reason_code": reason_code,
        "vulns": [
            {
                "id": f"CVE-{pkg}",
                "names": [f"GHSA-{pkg}"],
                "severity": "HIGH",
                "dev": False,
                "fixed": target or "",
            }
        ],
    }


def line(*items: dict[str, Any], branch: str = "release-1.2") -> dict[str, Any]:
    return {
        "line": "1.2",
        "ref": "1.2.3",
        "kind": "release",
        "branch": branch,
        "partial": False,
        "items": list(items),
        "skipped": [],
        "dropped": {"severity": 0, "unfixable": 0, "dev": 0},
    }


def file(
    content: str, directory: str = "/", name: str = "package-lock.json"
) -> dict[str, Any]:
    return {"directory": directory, "name": name, "content": content, "deleted": False}


def outcome(*files: dict[str, Any], error: str | None = None) -> Outcome:
    return Outcome(
        files=list(files),
        dependencies=[
            {
                "name": "hono",
                "previous-version": "2.0.12",
                "version": "2.1.5",
                "directory": "/",
            }
        ],
        error=error,
        seconds=3,
    )


def finding(
    pkg: str = "hono",
    id: str | None = None,
    severity: str = "HIGH",
    version: str = "2.0.12",
) -> Finding:
    return Finding(pkg, version, id or f"CVE-{pkg}", severity)


def tools(
    dependabot: Callable[[Mapping[str, Any], str], Outcome],
    scans: list[set[Finding]],
    images: Callable[[Path, str], set[Finding]] | None = None,
    npm_install: Callable[[], str | None] = lambda: None,
    npm_ls: Callable[[str], list[tuple[str, str]]] = lambda pkg: [],
) -> Tools:
    """Fake tools: the tree scans answer from ``scans`` in order."""
    queue = list(scans)
    return Tools(
        dependabot=dependabot,
        scan_tree=lambda: queue.pop(0),
        scan_image=images or (lambda tree, path: set()),
        npm_install=npm_install,
        npm_ls=npm_ls,
        npm_version=lambda: "10.9.2",
    )
