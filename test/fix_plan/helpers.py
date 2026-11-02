"""Builders of minimal schema 4 reports for the planner tests."""

from __future__ import annotations

from typing import Any

from config import Config
from plan import build_plan
from reports import merge_reports

DEV_SOURCE = "source-development"


def target(
    id: str,
    kind: str = "fs",
    image: str | None = None,
    packages: int = 10,
    status: str = "ok",
) -> dict[str, Any]:
    return {
        "id": id,
        "scanner": "trivy",
        "kind": kind,
        "image": image,
        "status": status,
        "packages_scanned": packages,
    }


def record(
    pkg: str,
    installed: str | list[str],
    fixed: str,
    id: str | None = None,
    **fields: Any,
) -> dict[str, Any]:
    """A vulnerability record; ``fields`` override the defaults (class, severity,
    names, dev, where, ecosystem, relationship, locations, accepted).
    """
    rec_id = id or f"CVE-{pkg}-{fixed or 'none'}"
    base: dict[str, Any] = {
        "id": rec_id,
        "names": [rec_id],
        "pkg": pkg,
        "class": "lang",
        "severity": "HIGH",
        "fixed": fixed,
        "dev": False,
        "installed": [installed] if isinstance(installed, str) else installed,
        "where": ["source-1.2.3"],
        "ecosystem": "npm",
        "relationship": "direct",
        "locations": ["package-lock.json"],
        "accepted": None,
    }
    return {**base, **fields}


def inventory(pkg: str, installed: list[str], cls: str = "lang") -> dict[str, Any]:
    return {"pkg": pkg, "class": cls, "installed": installed, "where": [DEV_SOURCE]}


def version(
    ref: str,
    kind: str = "release",
    vulns: list[dict[str, Any]] | None = None,
    packages: list[dict[str, Any]] | None = None,
    targets: list[dict[str, Any]] | None = None,
    status: str = "ok",
) -> dict[str, Any]:
    own = targets if targets is not None else [target(f"source-{ref}")]
    return {
        "ref": ref,
        "kind": kind,
        "status": status,
        "targets": [t["id"] for t in own],
        "vulns": vulns or [],
        "packages": packages or [],
        "_targets": own,
    }


def development(
    vulns: list[dict[str, Any]] | None = None,
    packages: list[dict[str, Any]] | None = None,
    targets: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    own = targets if targets is not None else [target(DEV_SOURCE)]
    return version("development", "development", vulns, packages, own)


def report(
    *versions: dict[str, Any], repo: str = "o/r", **header: Any
) -> dict[str, Any]:
    clean = [{k: v for k, v in x.items() if k != "_targets"} for x in versions]
    return {
        "schema_version": 4,
        "repo": repo,
        "run_id": "1",
        "run_url": "https://example.test/1",
        "targets": [t for x in versions for t in x["_targets"]],
        "versions": clean,
        **header,
    }


def plan(*versions: dict[str, Any], config: Config | None = None) -> dict[str, Any]:
    """The plan of one report made of ``versions``."""
    return build_plan(merge_reports([report(*versions)]), config or Config())


def items(result: dict[str, Any], line: int = 0) -> dict[str, dict[str, Any]]:
    return {i["pkg"]: i for i in result["lines"][line]["items"]}
