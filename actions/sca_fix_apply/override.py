"""The npm-override step: node version of a branch, the ``overrides`` edit of the root
``package.json`` and the npm calls that prove it.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

LOCKFILE = "package-lock.json"
LTS_MAJORS = (18, 20, 22, 24)
OVERRIDE_VALUE = re.compile(r"(\^|~|>=|=)?(\d+\.\d+\.\d+)")


class OverrideError(RuntimeError):
    """The override cannot be written; the message is the reason of the item."""


def numbers(version: str) -> tuple[int, int, int]:
    a, b, c = ([*re.findall(r"\d+", version.split("-")[0]), "0", "0", "0"])[:3]
    return int(a), int(b), int(c)


def same_line(a: str, b: str) -> bool:
    """Both versions are in one major (one minor below 1.0, where a caret stops there)."""
    x, y = numbers(a), numbers(b)
    return x[0] == y[0] and (x[0] > 0 or x[1] == y[1])


def selector(installed: str) -> str:
    x = numbers(installed)
    return f"~0.{x[1]}.0" if x[0] == 0 else f"^{x[0]}.0.0"


def satisfies(version: tuple[int, int, int], spec: str) -> bool:
    """A subset of the semver ranges of ``engines.node``: ``||`` sets of comparators
    (``>=``, ``>``, ``<=``, ``<``, ``=``, ``^``, ``~``, partial versions, ``x``, ``*``).
    """

    def comparator(text: str) -> bool:
        m = re.fullmatch(
            r"(>=|<=|>|<|=|\^|~)?\s*v?(\d+|x|\*)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?",
            text,
        )
        if not m:
            return False
        op = m.group(1) or "="
        given = [int(g) for g in m.groups()[1:] if g and g.isdigit()]
        if not given:
            return True
        padded = (*given, 0, 0)[:3]
        head = version[: len(given)]
        if op == ">=":
            return version >= padded
        if op == ">":
            return head > tuple(given)
        if op == "<=":
            return head <= tuple(given)
        if op == "<":
            return version < padded
        if op == "=":
            return head == tuple(given)
        keep = 1 if op == "^" and given[0] > 0 else min(2, len(given))
        return version >= padded and version[:keep] == padded[:keep]

    return any(
        all(
            comparator(c)
            for c in re.findall(r"(?:[<>]=?|[=^~])?\s*v?[\dx*][\w.*]*", group)
        )
        for group in spec.split("||")
    )


def detect_node(tree: Path, dockerfiles: Sequence[str]) -> tuple[str, str] | None:
    """The node version of the branch and where it came from: ``.nvmrc``,
    ``.node-version``, ``volta.node``, ``engines.node`` (the lowest LTS major that
    satisfies it), the newest ``FROM node:`` of the Dockerfiles.
    """

    def text(name: str) -> str:
        path = tree / name
        return path.read_text(encoding="utf-8") if path.is_file() else ""

    for name in (".nvmrc", ".node-version"):
        m = re.match(r"v?(\d+(?:\.\d+){0,2})\s*$", text(name).strip())
        if m:
            return m.group(1), name
    try:
        package = json.loads(text("package.json"))
    except ValueError:
        package = {}
    volta = (package.get("volta") or {}).get("node")
    if isinstance(volta, str) and re.fullmatch(r"\d+(\.\d+){0,2}", volta):
        return volta, "package.json volta.node"
    engines = (package.get("engines") or {}).get("node")
    if isinstance(engines, str):
        for major in LTS_MAJORS:
            if satisfies((major, 0, 0), engines) or satisfies(
                (major, 999, 999), engines
            ):
                return str(major), "package.json engines.node"
    found = [
        (numbers(m), m, name)
        for name in dockerfiles
        for m in re.findall(
            r"(?im)^\s*FROM\s+(?:--\S+\s+)*node:v?(\d+(?:\.\d+){0,2})", text(name)
        )
    ]
    if found:
        _, version, name = max(found)
        return version, name
    return None


def skip(text: str, i: int) -> int:
    return len(text) - len(text[i:].lstrip())


def members(text: str, start: int) -> Iterator[tuple[str, int, int]]:
    """``(key, value start, value end)`` of the members of the object that opens at
    ``text[start]``.
    """
    decoder = json.JSONDecoder()
    i = skip(text, start + 1)
    while text[i] != "}":
        key, i = decoder.raw_decode(text, i)
        begin = skip(text, text.index(":", i) + 1)
        _, i = decoder.raw_decode(text, begin)
        yield key, begin, i
        i = skip(text, i)
        if text[i] == ",":
            i = skip(text, i + 1)


def locate(text: str, path: Sequence[str]) -> tuple[int, int]:
    begin, end = skip(text, 0), len(text)
    for key in path:
        begin, end = next((b, e) for k, b, e in members(text, begin) if k == key)
    return begin, end


def lead(text: str, pos: int) -> str:
    """The indentation of the line that holds ``text[pos]``."""
    line = text[text.rfind("\n", 0, pos) + 1 : pos]
    return line[: len(line) - len(line.lstrip())]


def body(entries: Sequence[tuple[str, str]], indent: str, nl: str) -> str:
    return f",{nl}".join(
        f"{indent}{json.dumps(k, ensure_ascii=False)}: {v}" for k, v in entries
    )


def append(
    text: str, start: int, entries: Sequence[tuple[str, str]], unit: str, nl: str
) -> str:
    """``text`` with ``entries`` (key, JSON text) added after the last member of the
    object that opens at ``text[start]``.
    """
    found = list(members(text, start))
    if found:
        end = found[-1][2]
        return (
            f"{text[:end]},{nl}{body(entries, lead(text, found[0][1]), nl)}{text[end:]}"
        )
    base = lead(text, start)
    return (
        f"{text[:start]}{{{nl}{body(entries, base + unit, nl)}{nl}{base}"
        f"{text[text.index('}', start) :]}"
    )


def existing(
    obj: Mapping[str, Any], pkg: str, path: tuple[str, ...] = ()
) -> list[tuple[tuple[str, ...], Any]]:
    """The entries of an ``overrides`` object that are for ``pkg``, in any form
    (plain, with a selector, nested under a parent).
    """
    out: list[tuple[tuple[str, ...], Any]] = []
    for key, value in obj.items():
        if key == pkg or key.startswith(f"{pkg}@"):
            out.append(((*path, key), value))
        elif isinstance(value, dict):
            out += existing(value, pkg, (*path, key))
    return out


def add_overrides(
    text: str, pkg: str, pairs: Sequence[tuple[str, str]]
) -> tuple[str, list[str]]:
    """``package.json`` text with the overrides that lift ``pkg`` from the installed
    versions to the targets (``pairs`` of installed and target), and the keys written.

    An existing entry for the package is raised to the target of its line when it
    can be without changing its form; otherwise the item is left to a human. New
    keys have one selector per installed line. The rest of the text stays as it is.
    """
    document = json.loads(text)
    overrides = document.get("overrides")
    if overrides is not None and not isinstance(overrides, dict):
        raise OverrideError("overrides of package.json is not an object")
    nl = "\r\n" if "\r\n" in text else "\n"
    indented = re.search(r"\n([ \t]+)\S", text)
    unit = indented.group(1) if indented else "  "
    found = existing(overrides or {}, pkg)
    if found:
        edits: list[tuple[int, int, str]] = []
        for path, value in found:
            m = OVERRIDE_VALUE.fullmatch(value) if isinstance(value, str) else None
            target = m and next((t for _, t in pairs if same_line(m.group(2), t)), None)
            if not m or not target:
                raise OverrideError(
                    f"existing override for {pkg} needs a manual change"
                )
            if numbers(m.group(2)) < numbers(target):
                begin, end = locate(text, ("overrides", *path))
                edits.append((begin, end, json.dumps((m.group(1) or "") + target)))
        if not edits:
            raise OverrideError(f"existing override for {pkg} needs a manual change")
        for begin, end, new in sorted(edits, reverse=True):
            text = text[:begin] + new + text[end:]
        return text, [" > ".join(p) for p, _ in found]
    wanted: dict[str, str] = {}
    for installed, target in pairs:
        key = f"{pkg}@{selector(installed)}"
        if numbers(wanted.get(key, "0").lstrip("^")) < numbers(target):
            wanted[key] = f"^{target}"
    entries = [(k, json.dumps(v)) for k, v in wanted.items()]
    root = skip(text, 0)
    if overrides is None:
        indent = lead(text, next(members(text, root))[1])
        inner = f"{{{nl}{body(entries, indent + unit, nl)}{nl}{indent}}}"
        return append(text, root, [("overrides", inner)], unit, nl), list(wanted)
    return append(text, locate(text, ("overrides",))[0], entries, unit, nl), list(
        wanted
    )


def lock_versions(text: str) -> dict[str, str]:
    """Install path -> version of the packages of a lockfile."""
    packages = json.loads(text).get("packages") or {}
    return {p: v["version"] for p, v in packages.items() if p and "version" in v}


def lock_format(text: str) -> object:
    return json.loads(text).get("lockfileVersion")


def changed_other(before: str, after: str, pkg: str) -> list[str]:
    """The packages other than ``pkg`` whose version the lockfile change moved, and
    the ones it added.
    """
    old, new = lock_versions(before), lock_versions(after)
    out = []
    for path in sorted(new):
        name = path.rsplit("node_modules/", 1)[-1]
        if name == pkg or old.get(path) == new[path]:
            continue
        out.append(
            f"{name} {old[path]} -> {new[path]}"
            if path in old
            else f"{name} {new[path]} (new)"
        )
    return out


def npm_install(tree: Path) -> str | None:
    """Update the lockfile from ``package.json``; the first error line, or None."""
    done = subprocess.run(
        [
            "npm",
            "install",
            "--package-lock-only",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
        ],
        cwd=tree,
        capture_output=True,
        check=False,
        text=True,
    )
    if done.returncode == 0:
        return None
    lines = [x for x in (done.stderr or done.stdout).splitlines() if x.strip()]
    return lines[0] if lines else f"npm exit {done.returncode}"


def npm_ls(tree: Path, pkg: str) -> list[tuple[str, str]]:
    """``(path, version)`` of every copy of ``pkg`` in the lockfile's tree."""
    done = subprocess.run(
        ["npm", "ls", pkg, "--all", "--json", "--package-lock-only"],
        cwd=tree,
        capture_output=True,
        check=False,
        text=True,
    )
    try:
        root = json.loads(done.stdout)
    except ValueError as exc:
        raise OverrideError(
            f"npm ls gave no JSON: {done.stderr.strip()[:200]}"
        ) from exc

    def walk(node: Mapping[str, Any], path: str) -> Iterator[tuple[str, str]]:
        for name, child in (node.get("dependencies") or {}).items():
            here = f"{path} > {name}" if path else name
            if name == pkg and child.get("version"):
                yield here, child["version"]
            yield from walk(child, here)

    return list(walk(root, ""))


def npm_version() -> str:
    done = subprocess.run(
        ["npm", "--version"], capture_output=True, check=False, text=True
    )
    return done.stdout.strip()
