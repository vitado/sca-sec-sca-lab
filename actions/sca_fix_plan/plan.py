"""The planning rules: which records of which versions become fix items, with what
target version and by which method. A pure function of the reports and the config.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from config import Config
from reports import ReportError, Reports, Version
from versions import VersionError, compare, line_of, major, version_key

SCHEMA_VERSION = 1

_ECOSYSTEM_METHODS = {
    "npm": ("dependabot", "npm-override"),
    "PyPI": ("dependabot", "manual"),
    "Maven": ("dependabot", "manual"),
}

Record = Mapping[str, Any]


def norm(pkg: str) -> str:
    """The package key of the report: lowercase, each run of ``-``, ``_``, ``.`` as
    one ``-``.
    """
    return re.sub(r"[-_.]+", "-", pkg.lower())


def fixed_versions(record: Record) -> list[str]:
    """The fixed versions of a record (``fixed`` is a comma separated list)."""
    return [v.strip() for v in record["fixed"].split(",") if v.strip()]


def usable(target: Mapping[str, Any]) -> bool:
    return target.get("status") == "ok" and target.get("packages_scanned", 0) > 0


def development_version(reports: Reports) -> Version:
    found = [v for v in reports.versions if v.kind == "development"]
    if len(found) != 1:
        raise ReportError(
            f"exactly one development version is expected, found {len(found)}"
        )
    return found[0]


def select_lines(
    reports: Reports, count: int
) -> tuple[list[tuple[tuple[int, int], Version]], list[dict[str, str]]]:
    """The newest ``count`` release lines as ``((major, minor), newest version)``,
    newest line first, and the refs that could not be placed in a line.
    """
    newest: dict[tuple[int, int], Version] = {}
    skipped: list[dict[str, str]] = []
    for version in reports.versions:
        if version.kind not in ("release", "candidate"):
            continue
        line = line_of(version.ref)
        try:
            key = version_key(version.ref)
        except VersionError:
            line = None
        if line is None:
            skipped.append(
                {"ref": version.ref, "reason": "ref is not X.Y.Z or X.Y.Z-suffix"}
            )
            continue
        if line not in newest or key > version_key(newest[line].ref):
            newest[line] = version
    lines = sorted(newest.items(), key=lambda item: item[0], reverse=True)
    return lines[:count], sorted(skipped, key=lambda s: s["ref"])


def development_gap(record: Record, version: Version, dev: Version) -> str | None:
    """What is missing to trust the absence of ``record`` from development, or None.

    The absence counts only when development was scanned where the record lives: an
    ``ok`` source target for a library, an ``ok`` image target of the same image for
    an OS package, each with packages scanned.
    """
    if record["class"] == "lang":
        if any(t.get("kind") == "fs" and usable(t) for t in dev.targets.values()):
            return None
        return "no ok source target with packages scanned"
    images = sorted(
        {
            version.targets[i]["image"]
            for i in record["where"]
            if i in version.targets and version.targets[i].get("image")
        }
    )
    missing = [
        image
        for image in images
        if not any(t.get("image") == image and usable(t) for t in dev.targets.values())
    ]
    if missing or not images:
        return f"no ok image target for {', '.join(missing) or 'the record'}"
    return None


def choose_target(
    installed: str,
    records: Sequence[Record],
    dev_versions: Sequence[str],
    config: Config,
) -> tuple[str | None, str]:
    """The target version for one installed version: ``(target, evidence)`` or
    ``(None, reason)``. Raises ``VersionError`` for a version it cannot compare.
    """
    applicable = [r for r in records if installed in r["installed"]]
    fixes = sorted({f for r in applicable for f in fixed_versions(r)}, key=version_key)
    required: str | None = None
    for record in applicable:
        above = [f for f in fixed_versions(record) if compare(f, installed) > 0]
        if not above:
            continue
        lowest = min(above, key=version_key)
        if required is None or compare(lowest, required) > 0:
            required = lowest
    if required is None:
        return None, f"no fixed version above {installed}"
    same_major = major(installed)
    from_dev = sorted(
        (v for v in dev_versions if compare(v, required) >= 0), key=version_key
    )
    allowed = [
        v
        for v in from_dev
        if major(v) == same_major or config.allow_major == "dev-proven"
    ]
    if allowed:
        return allowed[0], f"development runs {allowed[0]}"
    reachable = [f for f in fixes if compare(f, required) >= 0]
    in_major = [f for f in reachable if major(f) == same_major]
    if in_major:
        return in_major[0], "lowest fixed version in the same major"
    note = (
        "development runs it, allow-major is none"
        if from_dev
        else "no development evidence"
    )
    return None, f"fix needs another major ({', '.join(reachable)}), {note}"


def choose_method(
    item_class: str,
    ecosystem: str | None,
    where: Sequence[str],
    version: Version,
    config: Config,
    hint: str = "",
) -> tuple[str, str | None, str | None]:
    """``(method, fallback, reason)`` of an item that has a target."""
    fallback: str | None
    if item_class == "os":
        if "docker-tag" not in config.methods:
            return "manual", None, f"rebuild the image to pick up the fixes{hint}"
        method, fallback = "docker-tag", "manual"
    elif not any(version.targets.get(i, {}).get("kind") == "fs" for i in where):
        return "manual", None, "only in the image, not in a manifest"
    elif ecosystem in _ECOSYSTEM_METHODS:
        method, fallback = _ECOSYSTEM_METHODS[ecosystem]
    else:
        return "manual", None, f"ecosystem {ecosystem} not supported"
    if method not in config.methods:
        return "manual", None, f"method {method} disabled"
    if fallback != "manual" and fallback not in config.methods:
        fallback = None
    return method, fallback, None


def newer_os(where: Sequence[str], version: Version, dev: Version) -> str:
    """The hint for an os item: the OS release of the development image of the same
    image when it is newer than the one of the release line, else an empty string.
    """
    for i in where:
        target = version.targets.get(i, {})
        os_now = target.get("os") or {}
        for other in dev.targets.values():
            os_dev = other.get("os") or {}
            if (
                other.get("image") != target.get("image")
                or not usable(other)
                or os_dev.get("family") != os_now.get("family")
                or not os_dev.get("name")
                or not os_now.get("name")
            ):
                continue
            try:
                newer = compare(os_dev["name"], os_now["name"]) > 0
            except VersionError:
                continue
            if newer:
                return (
                    f" (development image runs {os_dev['family']} {os_dev['name']},"
                    f" the line {os_now['name']}; a base tag of that release or"
                    " newer is a candidate)"
                )
    return ""


def build_item(
    records: Sequence[Record],
    version: Version,
    dev_versions: Sequence[str],
    config: Config,
    dev: Version,
) -> dict[str, Any]:
    """One item: every record of one package in one line."""
    installed = sorted({v for r in records for v in r["installed"]})
    where = sorted({i for r in records for i in r["where"]})
    relationships = {r["relationship"] for r in records}
    ecosystems = sorted({r["ecosystem"] for r in records if r["ecosystem"]})
    item: dict[str, Any] = {
        "pkg": records[0]["pkg"],
        "class": records[0]["class"],
        "ecosystem": ecosystems[0] if ecosystems else None,
        "relationship": next(
            (x for x in ("direct", "indirect") if x in relationships), None
        ),
        "locations": sorted({p for r in records for p in r["locations"]}),
        "where": where,
        "targets": [],
        "method": "manual",
        "fallback": None,
        "reason": None,
        "vulns": [
            {
                "id": r["id"],
                "names": list(r["names"]),
                "severity": r["severity"],
                "dev": r["dev"],
                "fixed": r["fixed"],
            }
            for r in sorted(records, key=lambda r: r["id"])
        ],
    }
    if item["class"] == "os":
        # a base image bump fixes it and the rescan proves it: distro versions are
        # not compared, the fixed versions are information only
        item["targets"] = [
            {
                "installed": current,
                "target": None,
                "fixed": sorted(
                    {r["fixed"] for r in records if current in r["installed"]}
                ),
                "evidence": "base image bump, verified by rescan",
            }
            for current in installed
        ]
        item["method"], item["fallback"], item["reason"] = choose_method(
            "os",
            item["ecosystem"],
            where,
            version,
            config,
            newer_os(where, version, dev),
        )
        return item
    reason: str | None = None
    try:
        for current in installed:
            target, text = choose_target(current, records, dev_versions, config)
            item["targets"].append(
                {
                    "installed": current,
                    "target": target,
                    "evidence": text if target else None,
                }
            )
            if target is None and reason is None:
                reason = text
    except VersionError as exc:
        item["targets"] = []
        item["reason"] = f"cannot compare versions {exc}"
        return item
    if not installed:
        item["reason"] = "no installed version in the record"
    elif reason:
        item["reason"] = reason
    else:
        item["method"], item["fallback"], item["reason"] = choose_method(
            item["class"], item["ecosystem"], where, version, config
        )
    return item


def plan_line(
    line: tuple[int, int],
    version: Version,
    severities: Sequence[str],
    dev: Version,
    config: Config,
) -> dict[str, Any]:
    """The items, skipped packages and drop counts of one release line."""
    dropped = {"severity": 0, "unfixable": 0, "dev": 0}
    dev_names: dict[str, set[str]] = {}
    for record in dev.vulns:
        dev_names.setdefault(record["class"], set()).update(record["names"])
    dev_installed = {(p["class"], norm(p["pkg"])): p["installed"] for p in dev.packages}
    skipped: dict[tuple[str, str, str], dict[str, Any]] = {}
    kept: dict[tuple[str, str], list[Record]] = {}

    def skip(record: Record, reason: str) -> None:
        key = (record["class"], norm(record["pkg"]), reason)
        entry = skipped.setdefault(
            key,
            {
                "pkg": record["pkg"],
                "class": record["class"],
                "ids": [],
                "reason": reason,
            },
        )
        entry["ids"].append(record["id"])

    for record in version.vulns:
        if record["accepted"]:
            skip(record, f"accepted until {record['accepted']['until']}")
        elif record["severity"] not in severities:
            dropped["severity"] += 1
        elif config.fixable_only and not record["fixed"]:
            dropped["unfixable"] += 1
        elif not config.include_dev and record["dev"]:
            dropped["dev"] += 1
        elif any(n in dev_names.get(record["class"], ()) for n in record["names"]):
            skip(record, "not fixed in development")
        elif gap := development_gap(record, version, dev):
            skip(record, f"development data incomplete: {gap}")
        else:
            kept.setdefault((record["class"], norm(record["pkg"])), []).append(record)

    for entry in skipped.values():
        entry["ids"].sort()
    return {
        "line": f"{line[0]}.{line[1]}",
        "ref": version.ref,
        "kind": version.kind,
        "branch": config.branch(*line),
        "partial": version.status != "ok",
        "items": [
            build_item(records, version, dev_installed.get(key, []), config, dev)
            for key, records in sorted(kept.items())
        ],
        "skipped": [skipped[k] for k in sorted(skipped)],
        "dropped": dropped,
    }


def build_plan(reports: Reports, config: Config) -> dict[str, Any]:
    """The fix plan of the newest release lines of one repo."""
    dev = development_version(reports)
    lines, skipped_refs = select_lines(reports, config.release_lines)
    plan: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "repo": reports.repo,
        "reports": reports.sources,
        "config": config.effective(),
        "lines": [
            plan_line(
                line,
                version,
                config.severities if index == 0 else config.previous_severities(),
                dev,
                config,
            )
            for index, (line, version) in enumerate(lines)
        ],
    }
    if skipped_refs:
        plan["skipped_refs"] = skipped_refs
    return plan
