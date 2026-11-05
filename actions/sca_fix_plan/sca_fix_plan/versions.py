"""Version comparison for the fix planner, standard library only.

One ordering for the versions of the scanned ecosystems (npm, PyPI, Maven, Alpine).
The limits are deliberate: a version this module does not understand raises
``VersionError`` and the planner leaves the item to a human, because a wrong order
would plan a downgrade or a version that does not fix anything.

  * The release part is the leading numeric components (``1.2.16``, the ``3.5.8`` of
    ``3.5.8-r0``); trailing zeros do not count (``1.2`` equals ``1.2.0``).
  * A pre-release qualifier sorts before the same release: ``dev`` and ``snapshot``,
    then ``alpha``/``a``, ``beta``/``b``, ``milestone``/``m``, ``rc``/``cr``. An
    unknown word after a hyphen (npm ``2.0.0-next.3``) is a pre-release too, ordered
    with ``alpha`` and among its kind by its text; this is the one place the order of
    two pre-releases can be approximate.
  * ``Final``, ``GA``, ``RELEASE`` and no qualifier are the release; ``postN`` sorts
    after it. The Alpine revision ``-rN`` is compared numerically after the release
    part.
  * Not understood: epochs, Debian and Ubuntu versions (``1.2-3ubuntu1``,
    ``1.35+dfsg-3``), build metadata (``+build5``), Alpine suffixes such as
    ``_p1``, and any other qualifier word.
"""

from __future__ import annotations

import re

VersionKey = tuple[tuple[int, ...], int, int, int, str]

_VERSION = re.compile(r"^v?(\d+(?:\.\d+)*)(.*)$", re.DOTALL)
_ALPINE_REVISION = re.compile(r"^-r(\d+)$")
_LINE_REF = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$")
_QUALIFIER = re.compile(r"^([-._]?)([A-Za-z]+)[-._]?(\d*)(.*)$", re.DOTALL)

_DEV, _PRE, _RELEASE, _POST = 0, 1, 5, 6
_STAGES = {
    "dev": _DEV,
    "snapshot": _DEV,
    "alpha": 1,
    "a": 1,
    "beta": 2,
    "b": 2,
    "milestone": 3,
    "m": 3,
    "rc": 4,
    "cr": 4,
    "final": _RELEASE,
    "ga": _RELEASE,
    "release": _RELEASE,
    "post": _POST,
}


class VersionError(ValueError):
    """A version the comparison does not understand."""


def release_part(version: str) -> tuple[int, ...]:
    """The leading numeric components: ``(3, 5, 8)`` for ``3.5.8-r0``."""
    match = _VERSION.match(version.strip())
    if not match:
        raise VersionError(version)
    return tuple(int(part) for part in match.group(1).split("."))


def version_key(version: str) -> VersionKey:
    """A sort key: ``(release, stage, qualifier number, revision, tail)``."""
    match = _VERSION.match(version.strip())
    if not match:
        raise VersionError(version)
    release = release_part(version)
    while len(release) > 1 and release[-1] == 0:
        release = release[:-1]
    rest = match.group(2)
    if not rest:
        return release, _RELEASE, 0, 0, ""
    revision = _ALPINE_REVISION.match(rest)
    if revision:
        return release, _RELEASE, 0, int(revision.group(1)), ""
    qualifier = _QUALIFIER.match(rest)
    if not qualifier:
        raise VersionError(version)
    separator, word, number, tail = qualifier.groups()
    word = word.lower()
    stage = _STAGES.get(word)
    if stage is None:
        if separator != "-":
            raise VersionError(version)
        return release, _PRE, 0, 0, rest.lower()
    return release, stage, int(number or 0), 0, tail.lower()


def line_of(ref: str) -> tuple[int, int] | None:
    """The release line ``(major, minor)`` of a ref ``X.Y.Z`` or ``X.Y.Z-suffix``, or
    None for a ref that is not one.
    """
    match = _LINE_REF.match(ref)
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2))


def compare(left: str, right: str) -> int:
    """Negative, zero or positive as ``left`` is older than, equal to or newer than
    ``right``.
    """
    a, b = version_key(left), version_key(right)
    return (a > b) - (a < b)


def major(version: str) -> tuple[int, ...]:
    """The major as a version scheme sees it: the first numeric component, or the
    first two when it is 0 (``0.3.x`` and ``0.4.x`` are different majors).
    """
    release = release_part(version)
    if release[0] != 0:
        return release[:1]
    return (release + (0,))[:2]
