"""The planning rules: which records of which versions become fix items, with what
target version and by which method. A pure function of the reports and the config.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from . import plan_codes as codes
from .config import Config
from .development import INCOMPLETE, OPEN, Development, key_of, usable
from .lines import select_lines
from .reports import Reports, Version, development_version
from .versions import VersionError, compare, major, version_key

SCHEMA_VERSION = 2

_ECOSYSTEM_METHODS = {
    "npm": ("dependabot", "npm-override"),
    "PyPI": ("dependabot", "manual"),
    "Maven": ("dependabot", "manual"),
}

Record = Mapping[str, Any]


def fixed_versions(record: Record) -> list[str]:
    """The fixed versions of a record (``fixed`` is a comma separated list)."""
    return [v.strip() for v in record["fixed"].split(",") if v.strip()]


def choose_target(
    installed: str,
    records: Sequence[Record],
    dev_versions: Sequence[str],
    config: Config,
) -> tuple[str | None, str, str | None]:
    """The target version for one installed version: ``(target, evidence, None)`` or
    ``(None, reason, reason_code)``. Raises ``VersionError`` for a version it cannot
    compare.
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
        return None, f"no fixed version above {installed}", codes.NO_FIXED_VERSION
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
        return allowed[0], f"development runs {allowed[0]}", None
    reachable = [f for f in fixes if compare(f, required) >= 0]
    in_major = [f for f in reachable if major(f) == same_major]
    if in_major:
        return in_major[0], "lowest fixed version in the same major", None
    note = (
        "development runs it, allow-major is none"
        if from_dev
        else "no development evidence"
    )
    text = f"fix needs another major ({', '.join(reachable)}), {note}"
    return None, text, codes.NEEDS_MAJOR


def choose_method(
    item_class: str,
    ecosystem: str | None,
    where: Sequence[str],
    version: Version,
    config: Config,
    hint: str = "",
) -> tuple[str, str | None, str | None, str | None]:
    """``(method, fallback, reason, reason_code)`` of an item that has a target."""
    fallback: str | None
    if item_class == "os":
        if "docker-tag" not in config.methods:
            text = f"rebuild the image to pick up the fixes{hint}"
            return "manual", None, text, codes.NEEDS_IMAGE_REBUILD
        method, fallback = "docker-tag", "manual"
    elif not any(version.targets.get(i, {}).get("kind") == "fs" for i in where):
        text = "only in the image, not in a manifest"
        return "manual", None, text, codes.ONLY_IN_IMAGE
    elif ecosystem in _ECOSYSTEM_METHODS:
        method, fallback = _ECOSYSTEM_METHODS[ecosystem]
    else:
        text = f"ecosystem {ecosystem} not supported"
        return "manual", None, text, codes.ECOSYSTEM_UNSUPPORTED
    if method not in config.methods:
        return "manual", None, f"method {method} disabled", codes.METHOD_DISABLED
    if fallback != "manual" and fallback not in config.methods:
        fallback = "manual"
    return method, fallback, None, None


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
    # an image scan has no dependency graph: only records of a source target say
    relationships = {
        r["relationship"]
        for r in records
        if any(version.targets.get(i, {}).get("kind") == "fs" for i in r["where"])
    } or {None}
    ecosystems = sorted({r["ecosystem"] for r in records if r["ecosystem"]})
    item: dict[str, Any] = {
        "pkg": records[0]["pkg"],
        "class": records[0]["class"],
        "ecosystem": ecosystems[0] if ecosystems else None,
        # unknown as soon as one record does not say
        "relationship": None
        if None in relationships
        else next((x for x in ("direct", "indirect") if x in relationships), None),
        "locations": sorted({p for r in records for p in r["locations"]}),
        "where": where,
        "targets": [],
        "method": "manual",
        "fallback": None,
        "reason": None,
        "reason_code": None,
        "vulns": [
            {
                "id": r["id"],
                "names": list(r["names"]),
                "severity": r["severity"],
                "dev": r["dev"],
                "fixed": r["fixed"],
                "aliases": sorted(r.get("aliases") or []),
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
        (
            item["method"],
            item["fallback"],
            item["reason"],
            item["reason_code"],
        ) = choose_method(
            "os",
            item["ecosystem"],
            where,
            version,
            config,
            newer_os(where, version, dev),
        )
        return item
    reason: str | None = None
    reason_code: str | None = None
    try:
        for current in installed:
            target, text, code = choose_target(current, records, dev_versions, config)
            item["targets"].append(
                {
                    "installed": current,
                    "target": target,
                    "evidence": text if target else None,
                }
            )
            if target is None and reason is None:
                reason, reason_code = text, code
    except VersionError as exc:
        item["targets"] = []
        item["reason"] = f"cannot compare versions {exc}"
        item["reason_code"] = codes.VERSION_UNPARSABLE
        return item
    if not installed:
        item["reason"] = "no installed version in the record"
        item["reason_code"] = codes.VERSION_UNPARSABLE
    elif reason:
        item["reason"], item["reason_code"] = reason, reason_code
    else:
        (
            item["method"],
            item["fallback"],
            item["reason"],
            item["reason_code"],
        ) = choose_method(item["class"], item["ecosystem"], where, version, config)
    return item


def plan_line(
    line: tuple[int, int],
    version: Version,
    severities: Sequence[str],
    dev: Version,
    config: Config,
) -> dict[str, Any]:
    """The items, skipped packages and drop counts of one release line."""
    dropped = {codes.SEVERITY: 0, codes.UNFIXABLE: 0, codes.DEV: 0}
    development = Development.of(dev)
    dev_installed = {key_of(p): p["installed"] for p in dev.packages}
    skipped: dict[tuple[str, str, str], dict[str, Any]] = {}  # per key and code
    kept: dict[tuple[str, str], list[Record]] = {}

    def skip(record: Record, reason: str, code: str) -> None:
        key = (*key_of(record), code)
        entry = skipped.setdefault(
            key,
            {
                "pkg": record["pkg"],
                "class": record["class"],
                "ids": [],
                "reason": reason,
                "reason_code": code,
            },
        )
        entry["ids"].append(record["id"])

    for record in version.vulns:
        if record["accepted"]:
            skip(
                record, f"accepted until {record['accepted']['until']}", codes.ACCEPTED
            )
        elif record["severity"] not in severities:
            dropped[codes.SEVERITY] += 1
        elif config.fixable_only and not record["fixed"]:
            dropped[codes.UNFIXABLE] += 1
        elif not config.include_dev and record["dev"]:
            dropped[codes.DEV] += 1
        else:
            state, gap = development.state(record, version)
            if state == INCOMPLETE:
                skip(
                    record,
                    f"development data incomplete: {gap}",
                    codes.DEVELOPMENT_DATA_INCOMPLETE,
                )
            elif state == OPEN:
                skip(record, "not fixed in development", codes.NOT_FIXED_IN_DEVELOPMENT)
            else:
                kept.setdefault(key_of(record), []).append(record)

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
    lines, skipped_refs = select_lines(reports, config)
    plan: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "repo": reports.repo,
        "reports": reports.sources,
        "config": config.effective(),
        "lines": [
            plan_line(
                line,
                version,
                config.severities if current else config.previous_severities(),
                dev,
                config,
            )
            for line, version, current in lines
        ],
    }
    if skipped_refs:
        plan["skipped_refs"] = skipped_refs
    return plan
