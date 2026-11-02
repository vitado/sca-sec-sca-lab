"""The working tree changes: write what Dependabot produced, keep the way back."""

from __future__ import annotations

import base64
import difflib
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

Edit = tuple[int, int, tuple[str, ...]]


def event_path(file: Mapping[str, Any]) -> str:
    """The tree-relative path of an ``updated-dependency-files`` entry."""
    return f"{file['directory'].strip('/')}/{file['name']}".lstrip("/")


def file_text(file: Mapping[str, Any]) -> str:
    raw = file["content"]
    if file.get("content_encoding") == "base64":
        return base64.b64decode(raw).decode("utf-8")
    return str(raw)


def overlap(a: Edit, b: Edit) -> bool:
    if a == b:
        return False
    if a[0] == a[1] == b[0] == b[1]:
        return True
    return a[0] < b[1] and b[0] < a[1]


def merge_text(original: str, versions: Sequence[str]) -> tuple[str, int]:
    """The original with the line edits of every version applied, and how many
    versions were left out.

    Dependabot makes one change per dependency and directory, each as the whole file
    taken from the same original, so two changes to one file cannot be written one
    after the other. Their edits are merged instead; a version whose edits meet an
    edit of an earlier one in different text is left out.
    """
    lines = original.splitlines(keepends=True)
    accepted: list[Edit] = []
    skipped = 0
    for version in versions:
        new = version.splitlines(keepends=True)
        matcher = difflib.SequenceMatcher(None, lines, new, autojunk=False)
        edits = [
            (i1, i2, tuple(new[j1:j2]))
            for tag, i1, i2, j1, j2 in matcher.get_opcodes()
            if tag != "equal"
        ]
        if any(overlap(e, a) for e in edits for a in accepted):
            skipped += 1
            continue
        accepted.extend(e for e in edits if e not in accepted)
    for i1, i2, replacement in sorted(accepted, reverse=True):
        lines[i1:i2] = replacement
    return "".join(lines), skipped


class Journal:
    """Writes files into a tree and restores them on request."""

    def __init__(self, tree: Path) -> None:
        self.tree = tree
        self.originals: dict[str, bytes | None] = {}

    def paths(self) -> list[str]:
        """The files that differ from the start now."""
        return sorted(
            p for p, original in self.originals.items() if self.read(p) != original
        )

    def read(self, path: str) -> bytes | None:
        target = self.tree / path
        return target.read_bytes() if target.is_file() else None

    def write(self, path: str, content: str | None) -> None:
        self.originals.setdefault(path, self.read(path))
        target = self.tree / path
        if content is None:
            target.unlink(missing_ok=True)
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content.encode("utf-8"))

    def checkpoint(self) -> dict[str, bytes | None]:
        return {p: self.read(p) for p in self.originals}

    def restore(self, checkpoint: Mapping[str, bytes | None]) -> None:
        """Go back to ``checkpoint``: files first written after it return to their
        original state.
        """
        for path in list(self.originals):
            content = checkpoint[path] if path in checkpoint else self.originals[path]
            target = self.tree / path
            if content is None:
                target.unlink(missing_ok=True)
            else:
                target.write_bytes(content)

    def apply(self, files: Sequence[Mapping[str, Any]]) -> tuple[list[str], int]:
        """Write the files of Dependabot's events; return the paths that changed and
        the number of left-out versions.
        """
        grouped: dict[str, list[Mapping[str, Any]]] = {}
        for file in files:
            grouped.setdefault(event_path(file), []).append(file)
        changed: list[str] = []
        skipped = 0
        for path, versions in sorted(grouped.items()):
            before = self.read(path)
            if all(v.get("deleted") for v in versions):
                after: str | None = None
            elif len(versions) == 1 or before is None:
                after = file_text(versions[0])
            else:
                after, left_out = merge_text(
                    before.decode("utf-8"), [file_text(v) for v in versions]
                )
                skipped += left_out
            if (after.encode("utf-8") if after is not None else None) != before:
                self.write(path, after)
                changed.append(path)
        return changed, skipped
