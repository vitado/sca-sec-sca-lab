"""Which release lines are planned: the newest stable lines and, as an extra, the
candidate line that is newer than all of them.
"""

from __future__ import annotations

import re
from typing import NamedTuple

from . import plan_codes as codes
from .config import Config
from .reports import Reports, Version
from .versions import VersionError, line_of, version_key

_STABLE_REF = re.compile(r"^\d+\.\d+\.\d+$")
_CANDIDATE_REF = re.compile(r"^\d+\.\d+\.\d+-.+$")


class Line(NamedTuple):
    """A planned line: ``(major, minor)``, its representative version and whether it
    is the current line (the newest stable line or the candidate line).
    """

    line: tuple[int, int]
    version: Version
    current: bool


def placed(version: Version) -> tuple[int, int] | None:
    """The line of a ``release`` ref ``X.Y.Z`` or a ``candidate`` ref ``X.Y.Z-suffix``,
    or None for any other ref.
    """
    pattern = _STABLE_REF if version.kind == "release" else _CANDIDATE_REF
    if not pattern.match(version.ref):
        return None
    try:
        version_key(version.ref)
    except VersionError:
        return None
    return line_of(version.ref)


def select_lines(
    reports: Reports, config: Config
) -> tuple[list[Line], list[dict[str, str]]]:
    """The planned lines in plan order and the refs that could not be placed.

    Stable lines come from ``release`` versions ``X.Y.Z`` only: per ``(X, Y)`` the
    newest one represents the line and the newest ``release-lines`` lines are
    planned, newest first. A candidate ``X.Y.Z-suffix`` never counts toward them and
    never displaces one. With ``include-candidate``, the newest candidate whose line
    is newer than every stable line of the reports is planned first; a candidate of
    a line that has a stable release is not planned, the stable version stands for
    the line.
    """
    stable: dict[tuple[int, int], Version] = {}
    candidates: list[tuple[tuple[int, int], Version]] = []
    skipped: list[dict[str, str]] = []
    for version in reports.versions:
        if version.kind not in ("release", "candidate"):
            continue
        line = placed(version)
        if line is None:
            skipped.append(
                {
                    "ref": version.ref,
                    "reason": "ref is not X.Y.Z or X.Y.Z-suffix",
                    "reason_code": codes.REF_NOT_SEMVER,
                }
            )
        elif version.kind == "candidate":
            candidates.append((line, version))
        elif line not in stable or version_key(version.ref) > version_key(
            stable[line].ref
        ):
            stable[line] = version
    ordered = sorted(stable.items(), key=lambda item: item[0], reverse=True)
    planned = [
        Line(line, version, index == 0)
        for index, (line, version) in enumerate(ordered[: config.release_lines])
    ]
    newer = [c for c in candidates if all(c[0] > line for line in stable)]
    if config.include_candidate and newer:
        line, version = max(newer, key=lambda c: version_key(c[1].ref))
        planned.insert(0, Line(line, version, True))
    return planned, sorted(skipped, key=lambda s: s["ref"])
