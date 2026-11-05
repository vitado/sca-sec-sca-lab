"""What development says about a release record: fixed, removed, open or unknown.

This is the one definition of "fixed in development"; the planner and the report
model share it through ``classify``.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .config import Config
from .lines import select_lines
from .reports import Reports, Version, development_version, merge_reports

Record = Mapping[str, Any]
Key = tuple[str, str]

FIXED, REMOVED, OPEN, INCOMPLETE = "fixed", "removed", "open", "incomplete"


def norm(pkg: str) -> str:
    """The package key of the report: lowercase, each run of ``-``, ``_``, ``.`` as
    one ``-``.
    """
    return re.sub(r"[-_.]+", "-", pkg.lower())


def key_of(record: Record) -> Key:
    """The package key ``(class, norm(pkg))`` of a record or a package entry."""
    return record["class"], norm(record["pkg"])


def identifiers(record: Record) -> set[str]:
    """``id``, ``names`` and ``aliases`` of a record."""
    return {record["id"], *record["names"], *(record.get("aliases") or [])}


def usable(target: Mapping[str, Any]) -> bool:
    return target.get("status") == "ok" and target.get("packages_scanned", 0) > 0


@dataclass(frozen=True)
class Development:
    """The development version with the packages it runs and the identifiers of its
    records, per package key.
    """

    version: Version
    runs: frozenset[Key]
    ids: Mapping[Key, frozenset[str]]

    @classmethod
    def of(cls, version: Version) -> Development:
        ids: dict[Key, set[str]] = {}
        for record in version.vulns:
            ids.setdefault(key_of(record), set()).update(identifiers(record))
        return cls(
            version,
            frozenset(key_of(p) for p in version.packages) | frozenset(ids),
            {k: frozenset(v) for k, v in ids.items()},
        )

    def gap(self, record: Record, version: Version) -> str | None:
        """What is missing to trust the absence of ``record`` from development, or
        None.

        The development version must be ``ok``. The absence counts only when
        development was scanned where the record lives: an ``ok`` source target for a
        library, an ``ok`` image target of the same image for an OS package, each with
        packages scanned.
        """
        if self.version.status != "ok":
            return f"development version status is {self.version.status}"
        targets = self.version.targets.values()
        if record["class"] == "lang":
            if any(t.get("kind") == "fs" and usable(t) for t in targets):
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
            if not any(t.get("image") == image and usable(t) for t in targets)
        ]
        if missing or not images:
            return f"no ok image target for {', '.join(missing) or 'the record'}"
        return None

    def state(self, record: Record, version: Version) -> tuple[str, str | None]:
        """``(state, gap)`` of a record of a release ``version``: ``incomplete`` with
        the missing part, ``open`` when a development record of the same package
        shares an identifier, ``removed`` when development does not run the package,
        else ``fixed``. A development record of another package never counts.
        """
        if gap := self.gap(record, version):
            return INCOMPLETE, gap
        key = key_of(record)
        if key not in self.runs:
            return REMOVED, None
        if identifiers(record) & self.ids.get(key, frozenset()):
            return OPEN, None
        return FIXED, None


def classify(reports: Reports | Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """The development state of every record of the planned lines.

    ``reports`` are the schema 4 reports of one repo (or the merged ``Reports``).
    Lines are selected with the default ``release-lines`` and ``include-candidate``;
    accepted records are left out and no severity, fixable or dev filter applies.
    One entry per record: ``{repo, line, ref, kind, class, key, pkg, ids, state}``,
    ``state`` one of ``fixed``, ``removed``, ``open``, ``incomplete``, sorted by repo,
    line order (the candidate first, then newest first), class, key and ids.
    """
    merged = reports if isinstance(reports, Reports) else merge_reports(reports)
    dev = Development.of(development_version(merged))
    entries: list[tuple[int, dict[str, Any]]] = []
    for order, planned in enumerate(select_lines(merged, Config())[0]):
        line, version = planned.line, planned.version
        for record in version.vulns:
            if record["accepted"]:
                continue
            entries.append(
                (
                    order,
                    {
                        "repo": merged.repo,
                        "line": f"{line[0]}.{line[1]}",
                        "ref": version.ref,
                        "kind": version.kind,
                        "class": record["class"],
                        "key": norm(record["pkg"]),
                        "pkg": record["pkg"],
                        "ids": sorted(identifiers(record)),
                        "state": dev.state(record, version)[0],
                    },
                )
            )
    entries.sort(
        key=lambda e: (e[1]["repo"], e[0], e[1]["class"], e[1]["key"], e[1]["ids"])
    )
    return [entry for _, entry in entries]
