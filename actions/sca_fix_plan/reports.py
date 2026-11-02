"""Load the schema 4 reports of one repo and merge their versions."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

SCHEMA_VERSION = 4


class ReportError(ValueError):
    """The reports cannot be planned from."""


@dataclass(frozen=True)
class Version:
    """One scanned version with the targets that belong to it (the Trivy entry of
    each target id: the OSV twin has no say about what a scan covered).
    """

    ref: str
    kind: str
    status: str
    vulns: Sequence[Mapping[str, Any]]
    packages: Sequence[Mapping[str, Any]]
    targets: Mapping[str, Mapping[str, Any]]


@dataclass(frozen=True)
class Reports:
    repo: str
    sources: list[dict[str, Any]]
    versions: list[Version]


def merge_reports(reports: Sequence[Mapping[str, Any]]) -> Reports:
    """Merge the ``versions[]`` of the reports by ``ref``.

    Every report must be schema 4 and of one repo, and a ref may be in one report
    only: two scans of the same ref would be two answers to one question.
    """
    if not reports:
        raise ReportError("no report given")
    repo = reports[0].get("repo")
    sources: list[dict[str, Any]] = []
    versions: list[Version] = []
    seen: set[str] = set()
    for report in reports:
        if report.get("schema_version") != SCHEMA_VERSION:
            raise ReportError(
                f"schema_version {report.get('schema_version')} is not supported, "
                f"{SCHEMA_VERSION} is expected"
            )
        if report.get("repo") != repo:
            raise ReportError(
                f"reports of different repos: {repo} and {report.get('repo')}"
            )
        trivy = {
            t["id"]: t for t in report.get("targets", []) if t.get("scanner") == "trivy"
        }
        refs = []
        for raw in report.get("versions", []):
            ref = raw["ref"]
            if ref in seen:
                raise ReportError(f"ref {ref} is in more than one report")
            seen.add(ref)
            refs.append(ref)
            versions.append(
                Version(
                    ref=ref,
                    kind=raw["kind"],
                    status=raw["status"],
                    vulns=raw.get("vulns", []),
                    packages=raw.get("packages", []),
                    targets={i: trivy[i] for i in raw.get("targets", []) if i in trivy},
                )
            )
        sources.append(
            {
                "run_id": report.get("run_id"),
                "run_url": report.get("run_url"),
                "refs": refs,
            }
        )
    return Reports(repo=str(repo), sources=sources, versions=versions)
