"""Load the schema 4 reports of one repo and merge their versions."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from . import plan_codes as codes
from .versions import line_of

SCHEMA_VERSION = 4


class ReportError(ValueError):
    """The reports cannot be planned from."""


@dataclass(frozen=True)
class Version:
    """One scanned version with the targets that belong to it (the Trivy entry of
    each target id) and the statuses of the other scanners' entries of the same ids
    (the OSV twins).
    """

    ref: str
    kind: str
    status: str
    vulns: Sequence[Mapping[str, Any]]
    packages: Sequence[Mapping[str, Any]]
    targets: Mapping[str, Mapping[str, Any]]
    twins: Mapping[str, tuple[str, ...]]


def commits(version: Version) -> set[str]:
    """The commits of the source targets a version was scanned at."""
    return {
        t["commit_sha"]
        for t in version.targets.values()
        if t.get("kind") == "fs" and t.get("commit_sha")
    }


@dataclass(frozen=True)
class Reports:
    repo: str
    sources: list[dict[str, Any]]
    versions: list[Version]


def development_version(reports: Reports) -> Version:
    found = [v for v in reports.versions if v.kind == "development"]
    if len(found) != 1:
        raise ReportError(
            f"exactly one development version is expected, found {len(found)}"
        )
    return found[0]


def merge_reports(reports: Sequence[Mapping[str, Any]]) -> Reports:
    """Merge the ``versions[]`` of the reports by ``ref``; the first report that has
    a version wins.

    Every report must be schema 4 and of one repo. A later report may repeat a ref
    only when both were scanned at the same source commit (two scans of one ref at
    different commits would be two answers to one question); the copy is ignored. A
    release line that an earlier report already gives is not taken from a later one
    either: a full-set run next to a run of one older tag must not replace the tag
    by a newer patch of the same line. Candidates are claimed apart from stable
    versions: a candidate never blocks a stable version of its line, and only the
    first candidate of a line is kept. Ignored copies are listed in the source entry.
    """
    if not reports:
        raise ReportError("no report given")
    repo = reports[0].get("repo")
    sources: list[dict[str, Any]] = []
    versions: list[Version] = []
    by_ref: dict[str, Version] = {}
    claimed_lines: set[tuple[str, int, int]] = set()
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
        twins: dict[str, list[str]] = {}
        for t in report.get("targets", []):
            if t.get("scanner") != "trivy":
                twins.setdefault(t["id"], []).append(t.get("status"))
        refs: list[str] = []
        ignored: list[dict[str, str]] = []
        lines: set[tuple[str, int, int]] = set()
        for raw in report.get("versions", []):
            version = Version(
                ref=raw["ref"],
                kind=raw["kind"],
                status=raw["status"],
                vulns=raw.get("vulns", []),
                packages=raw.get("packages", []),
                targets={i: trivy[i] for i in raw.get("targets", []) if i in trivy},
                twins={i: tuple(twins[i]) for i in raw.get("targets", []) if i in twins},
            )
            earlier = by_ref.get(version.ref)
            if earlier is not None:
                if not commits(earlier) or commits(earlier) != commits(version):
                    raise ReportError(
                        f"ref {version.ref} is in more than one report "
                        "and not at the same source commit"
                    )
                ignored.append(
                    {
                        "ref": version.ref,
                        "reason": "same ref and commit as an earlier report",
                        "reason_code": codes.SAME_REF_SAME_COMMIT,
                    }
                )
                continue
            parsed = line_of(version.ref) if version.kind != "development" else None
            line = (version.kind, *parsed) if parsed else None
            if line is not None and line in claimed_lines:
                ignored.append(
                    {
                        "ref": version.ref,
                        "reason": f"line {parsed[0]}.{parsed[1]} is given by an earlier report",
                        "reason_code": codes.LINE_IN_EARLIER_REPORT,
                    }
                )
                continue
            if line:
                lines.add(line)
            by_ref[version.ref] = version
            refs.append(version.ref)
            versions.append(version)
        claimed_lines |= lines
        source: dict[str, Any] = {
            "run_id": report.get("run_id"),
            "run_url": report.get("run_url"),
            "refs": refs,
        }
        if ignored:
            source["ignored_refs"] = ignored
        sources.append(source)
    return Reports(repo=str(repo), sources=sources, versions=versions)
