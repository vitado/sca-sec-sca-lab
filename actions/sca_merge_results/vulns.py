"""``versions[]`` of report.json: the vulnerability records of every scanned version.

The findings of both scanners and of all targets of a version merge into one record
per vulnerability of a package (see ``build_versions``); the counts of the version
are computed from its records.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from normalize import SEVERITIES, PackageSet, norm

Finding = Mapping[str, Any]

COUNT_KEYS = dict(zip(SEVERITIES, ("c", "h", "m", "l", "unknown")))
# Trivy result type -> OSV ecosystem name
OSV_ECOSYSTEMS = {
    **dict.fromkeys(("pip", "pipenv", "poetry", "uv", "python-pkg"), "PyPI"),
    **dict.fromkeys(("npm", "yarn", "pnpm", "node-pkg"), "npm"),
    **dict.fromkeys(("jar", "pom", "gradle"), "Maven"),
    **dict.fromkeys(("gomod", "gobinary"), "Go"),
    "cargo": "crates.io",
    "nuget": "NuGet",
}
VERSION = re.compile(r"(\d+(?:\.\d+)*)(-.+)?")


def version_order(version: str) -> tuple[int, Any]:
    """development first, then releases from the newest (a release candidate after
    its final version), then whatever is not a version, alphabetically.
    """
    if version == "development":
        return 0, ()
    if m := VERSION.fullmatch(version):
        return 1, (tuple(-int(n) for n in m[1].split(".")), m[2] is not None, m[2])
    return 2, version


def versions_of(report: Mapping[str, Any]) -> list[tuple[str, set[str]]]:
    """(version, ids of its targets) in display order. The source and the images of
    one version agree on it: a git tag may carry a ``v`` that a registry tag lacks.
    A target without a ref (its resolution failed) belongs to no version.
    """
    ids: dict[str, set[str]] = {}
    for t in report["targets"]:
        if t["ref"]:
            ids.setdefault(t["ref"].removeprefix("v"), set()).add(t["id"])
    return sorted(ids.items(), key=lambda item: version_order(item[0]))


def is_release(ref: str, default_branch: str | None) -> bool:
    """A plain semver tag: not the default branch, not ``development``, not a
    pre-release, and not a ref that does not parse as semver.
    """
    if ref == default_branch or ref == "development":
        return False
    m = VERSION.fullmatch(ref)
    return m is not None and m[2] is None


KINDS = ("development", "release", "candidate")


def version_kind(ref: str, default_branch: str | None) -> str:
    """``development`` for the default branch or ``development``; ``candidate`` for a
    semver with a pre-release part (``0.50.0-rc.1``); ``release`` otherwise.
    """
    if ref == default_branch or ref == "development":
        return "development"
    m = VERSION.fullmatch(ref)
    if m and m[2] is not None:
        return "candidate"
    return "release"


def components(findings: Sequence[Finding]) -> list[list[Finding]]:
    """Findings of one package grouped by intersecting ``names`` (union-find, so the
    result does not depend on the order); each group keeps the order of its findings.
    """
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        while parent.setdefault(x, x) != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for f in findings:
        for name in f["names"]:
            parent[find(name)] = find(f["names"][0])
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        groups.setdefault(find(f["names"][0]), []).append(f)
    return list(groups.values())


def fixed_of(f: Finding) -> list[str]:
    return [x.strip() for x in f["fixed_version"].split(",") if x.strip()]


def pkg_of(fs: Sequence[Finding], source_ids: set[str]) -> str:
    """The package name as a source target spells it, else as the first finding."""
    return next((f for f in fs if f["target"] in source_ids), fs[0])["pkg"]


def ecosystem_of(fs: Sequence[Finding]) -> str | None:
    """The OSV ecosystem name: the one of an OSV finding, else the mapped Trivy type
    of a language finding, else None.
    """
    if osv := next((f for f in fs if f["scanner"] == "osv"), None):
        return osv["ecosystem"]
    if fs[0]["class"] == "lang":
        return OSV_ECOSYSTEMS.get(fs[0]["ecosystem"])
    return None


def relationship_of(fs: Sequence[Finding]) -> str | None:
    """``direct`` wins over ``indirect``, then the first known value."""
    found = [f["relationship"] for f in fs if f["relationship"]]
    for kind in ("direct", "indirect"):
        if kind in found:
            return kind
    return found[0] if found else None


def cvss_of(fs: Sequence[Finding]) -> dict[str, Any] | None:
    """The CVSS of the first finding that has a score, else of the first that has
    one at all (a vector without a score comes from OSV)."""
    found = [f["cvss"] for f in fs if f["cvss"]]
    scored = [c for c in found if c["score"] is not None]
    return (scored or found or [None])[0]


def record_of(fs: Sequence[Finding], source_ids: set[str]) -> dict[str, Any]:
    """The vulnerability record of one component of findings (Trivy first, then OSV,
    each by target and id).
    """
    ids = sorted(f["id"] for f in fs)
    vid = next((i for i in ids if i.startswith("CVE-")), ids[0])
    names = {n for f in fs for n in f["names"]}
    # the rating of Trivy wins; OSV rates a vulnerability Trivy does not report
    rated = [f for f in fs if f["scanner"] == "trivy"] or fs
    fixed = (x for f in fs for x in fixed_of(f))
    dates = [f["published"] for f in fs if f["published"]]
    untils = [f["accepted"]["until"] for f in fs if f.get("accepted")]
    pkg = pkg_of(fs, source_ids)
    return {
        "id": vid,
        "names": [vid, *sorted(names - {vid})],
        "pkg": pkg,
        "class": fs[0]["class"],
        "severity": min((f["severity"] for f in rated), key=SEVERITIES.index),
        "fixed": ", ".join(dict.fromkeys(fixed)),
        "dev": all(f["dev"] for f in fs),
        "installed": sorted({f["version"] for f in fs}),
        "where": sorted({f["target"] for f in fs}),
        "sources": [s for s in ("trivy", "osv") if any(f["scanner"] == s for f in fs)],
        "published": min(dates, default=None),
        "modified": max((f["modified"] for f in fs if f["modified"]), default=None),
        "cvss": cvss_of(fs),
        "aliases": sorted({a for f in fs for a in f["aliases"]} - names),
        "ecosystem": ecosystem_of(fs),
        "relationship": relationship_of(fs),
        "locations": sorted({loc for f in fs for loc in f["locations"]}),
        "accepted": {"until": min(untils)} if len(untils) == len(fs) else None,
        "pkg_key": norm(pkg),
        "src_pkg": next(
            (f["src_pkg"] for f in fs if f["scanner"] == "trivy" and f["src_pkg"]), None
        ),
        "title": title_of(fs),
    }


def title_of(fs: Sequence[Finding]) -> str | None:
    """The first non-empty title with whitespace collapsed: Trivy's ``Title`` of the
    findings, else the ``summary`` of an OSV advisory (never its details).
    """
    for f in sorted(fs, key=lambda f: f["scanner"] != "trivy"):
        text = " ".join((f["title"] if f["scanner"] == "trivy" else f["summary"] or "").split())
        if text:
            return text
    return None


def counts_of(vulns: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    """Severity counts, ``all`` and ``fixable`` of the records."""
    return {
        **{k: sum(v["severity"] == s for v in vulns) for s, k in COUNT_KEYS.items()},
        "all": len(vulns),
        "fixable": sum(bool(v["fixed"]) for v in vulns),
    }


def packages_of(
    ids: set[str],
    vulns: Sequence[Mapping[str, Any]],
    keys: Mapping[tuple[str, str], str],
    package_sets: Mapping[str, PackageSet],
    ok: set[str],
    sources: Mapping[tuple[str, str], str],
) -> list[dict[str, Any]]:
    """The ``packages`` of one version: per package of ``keys`` the versions installed
    in its targets and the targets. Trivy packages of ``ok`` targets (vulnerable or
    not) and the records of the version itself are the sources.
    """
    seen: dict[tuple[str, str], tuple[set[str], set[str]]]
    seen = {k: (set(), set()) for k in keys}
    for tid in ids & ok:
        for cls, name, installed in package_sets.get(tid, ()):
            if (cls, name) in seen:
                seen[cls, name][0].add(installed)
                seen[cls, name][1].add(tid)
    for v in vulns:
        installed, where = seen[v["class"], norm(v["pkg"])]
        installed.update(v["installed"])
        where.update(v["where"])
    return [
        {
            "pkg": keys[k],
            "class": k[0],
            "installed": sorted(installed),
            "where": sorted(where),
            "pkg_key": k[1],
            "src_pkg": sources.get(k),
        }
        for k, (installed, where) in sorted(seen.items())
    ]


def set_roles(versions: Sequence[dict[str, Any]]) -> None:
    """``role`` of every version (``versions`` is newest first): ``dev`` for each
    development version, ``rc`` for each candidate; of the release versions ``rel``
    for the newest of the newest release line (major.minor) and ``rel-1`` for the
    newest of the line before it; any other version, and a release whose ref has no
    major.minor, gets ``None``.
    """
    lines: list[tuple[int, ...]] = []
    for v in versions:
        role = {"development": "dev", "candidate": "rc"}.get(v["kind"])
        m = VERSION.fullmatch(v["ref"])
        if v["kind"] == "release" and m and "." in m[1]:
            line = tuple(int(n) for n in m[1].split(".")[:2])
            if line not in lines:
                lines.append(line)
                role = ("rel", "rel-1")[len(lines) - 1] if len(lines) <= 2 else None
        v["role"] = role


def build_versions(
    report: Mapping[str, Any],
    package_sets: Mapping[str, PackageSet],
    version_kinds: Mapping[str, str] | None = None,
) -> list[dict[str, Any]]:
    """One record per version of ``versions_of``, in that order: ``status`` (failed
    when a Trivy or an OSV scan of a target failed; a ``not_applicable`` target does
    not fail it), ``kind``, ``latest`` (the newest ``ok`` release), ``targets``, the
    ``vulns`` merged over the targets and scanners, and their ``counts``, then the
    ``packages`` (see ``packages_of``) of every package that has a record in any
    version. A failed version keeps what its ``ok`` targets found. ``version_kinds``
    (ref -> kind, from the producer) overrides the kind that ``version_kind`` derives
    from the spelling of the ref and decides ``latest`` for the versions it names; its
    keys are the refs of the targets as given (before the ``v`` strip of ``versions_of``);
    a ref without a target is ignored, a kind that is not one of ``KINDS`` raises
    ``ValueError``.
    """
    version_kinds = version_kinds or {}
    if bad := {r: k for r, k in version_kinds.items() if k not in KINDS}:
        raise ValueError(f"version_kinds: unknown kind {bad}; expected one of {KINDS}")
    default_branch = report["default_branch"]
    source_ids = {t["id"] for t in report["targets"] if t["kind"] == "fs"}
    findings = sorted(
        report["findings"],
        key=lambda f: (
            f["scanner"] != "trivy",
            f["target"],
            f["id"],
            f["pkg"],
            f["version"],
        ),
    )
    result = []
    named: set[str] = set()  # the versions whose kind the map gave
    for ref, ids in versions_of(report):
        given = sorted(
            {t["ref"] for t in report["targets"] if t["id"] in ids} & version_kinds.keys()
        )
        if given:
            named.add(ref)
        failed = any(
            t["status"] == "failed" for t in report["targets"] if t["id"] in ids
        )
        packages: dict[tuple[str, str], list[Finding]] = {}
        for f in findings:
            if f["target"] in ids:
                packages.setdefault((f["class"], norm(f["pkg"])), []).append(f)
        records = (
            record_of(c, source_ids) for fs in packages.values() for c in components(fs)
        )
        vulns = sorted(
            records,
            key=lambda v: (v["class"], norm(v["pkg"]), v["id"]),
        )
        result.append(
            {
                "ref": ref,
                "kind": version_kinds[given[0]] if given else version_kind(ref, default_branch),
                "latest": False,  # resolved below, once every status is known
                "status": "failed" if failed else "ok",
                "targets": sorted(ids),
                "counts": counts_of(vulns),
                "vulns": vulns,
            }
        )
    # the package spelling of the first version that has a record for it
    keys: dict[tuple[str, str], str] = {}
    for version in result:
        for v in version["vulns"]:
            keys.setdefault((v["class"], norm(v["pkg"])), v["pkg"])
    ok = {
        t["id"]
        for t in report["targets"]
        if t["scanner"] == "trivy" and t["status"] == "ok"
    }
    # the source package of an OS package, as the first version with a record states it
    sources: dict[tuple[str, str], str] = {}
    for version in result:
        for v in version["vulns"]:
            if v["src_pkg"]:
                sources.setdefault((v["class"], v["pkg_key"]), v["src_pkg"])
    for version in result:
        version["packages"] = packages_of(
            set(version["targets"]), version["vulns"], keys, package_sets, ok, sources
        )
    set_roles(result)
    ok_releases = (
        v
        for v in result
        if v["status"] == "ok"
        and (
            v["kind"] == "release"
            if v["ref"] in named
            else is_release(v["ref"], default_branch)
        )
    )
    if latest := next(ok_releases, None):
        latest["latest"] = True
    return result
