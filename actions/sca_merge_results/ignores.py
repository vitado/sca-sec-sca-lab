"""Risk acceptance: the ``.trivyignore`` of the source and the rules of the pipeline.

The grammar of the file is the plain format of Trivy (``parseIgnore``): per line the
first field is the id, of the other fields only the first ``exp:YYYY-MM-DD`` matters.
The file never fails as a whole: a line with an unparsable date is flagged and does
not act. It is read from the source target of the default branch, else from the only
source target of the run (a version).

The rules are the optional ``acceptances`` of ``targets.json``, decisions that do not
live in the repository: ``targets`` (ids of Trivy targets), ``package``, optional
``class`` (``os`` or ``lang``: only that kind of package), ``ids`` (optional, empty: every
vulnerability of the package), ``reason``, ``expires`` and whatever the pipeline adds
about the approval. A rule marks the findings of its package in its targets
``accepted``; nothing is hidden. Like a line of the file it stops acting on the day
of its ``expires`` (UTC, the date of the report).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import date
from pathlib import Path
from typing import Any

from _sca_lib import read_json
from normalize import norm
from vulns import components

DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


def iso_date(text: object) -> str | None:
    """``text`` as an ISO date, None if it is not a real date."""
    if isinstance(text, str) and DATE.fullmatch(text):
        try:
            return date.fromisoformat(text).isoformat()
        except ValueError:
            pass
    return None


def parse_line(
    line: str, today: str, reason: str | None = None
) -> dict[str, Any] | None:
    """One ``ignores[]`` entry, None for a blank line or a comment. ``reason`` is
    the comment block above the line; it never acts.
    """
    fields = line.split()
    if not fields or fields[0].startswith("#"):
        return None
    exp = next((f[4:] for f in fields[1:] if f.startswith("exp:")), None)
    until = iso_date(exp)
    return {
        "id": fields[0],
        "until": until,
        # Trivy: ExpiredAt.Before(now), a line stops acting on the exp day itself
        "expired": until is not None and until <= today,
        "bad_expiry": exp is not None and until is None,
        "no_expiry": exp is None,
        "matched": False,
        "reason": reason,
    }


def read_ignores(
    report: Mapping[str, Any], parts_dir: Path
) -> tuple[list[dict[str, Any]] | None, str | None]:
    """``(ignores, ignores_error)``: the lines of the ignore file the workflow copied
    for the source target of the default branch, or for the only source target (a run
    whose ``ref`` is a version). The status file is read directly, a failed Trivy scan
    with a successful checkout still yields the file. A run without any source target
    (images only) has no file to read: ``(None, None)``.
    """
    sources = [
        t for t in report["targets"] if (t["scanner"], t["kind"]) == ("trivy", "fs")
    ]
    if not sources:
        return None, None
    tid = next(
        (t["id"] for t in sources if t["ref"] == report["default_branch"]),
        sources[0]["id"] if len(sources) == 1 else None,
    )
    if tid is None:
        return None, "no default-branch target in this run"
    trivy = parts_dir / "trivy"
    try:
        status = read_json(trivy / f"{tid}.status.json")
    except (OSError, ValueError):
        status = None
    if not isinstance(status, dict):
        return None, f"no readable status file for {tid}"
    if "ignorefile" not in status:
        return None, "the workflow does not pass the ignore file"
    state = status["ignorefile"]
    if state is None:
        return None, "checkout failed"
    if state == "absent":
        return [], None
    if state != "present":
        return None, f"unexpected ignorefile value: {state!r}"
    try:
        # a stray bad byte must not drop every acceptance
        text = (trivy / f"{tid}.trivyignore").read_text("utf-8", errors="replace")
    except OSError as e:
        return None, f"the ignore file of {tid} is unreadable: {e.strerror}"
    today = report["generated_utc"][:10]
    entries: list[dict[str, Any]] = []
    block: list[str] = []
    for line in text.split("\n"):
        if line.strip().startswith("#"):
            block.append(line.strip().lstrip("#").strip())
            continue
        reason = " ".join(filter(None, block)) or None
        if entry := parse_line(line, today, reason):
            entries.append(entry)
        block = []  # an ignore line or a blank line ends the block
    return entries, None


def rule_matches(rule: dict[str, Any], f: dict[str, Any], names: set[str]) -> bool:
    """Does a live ``rule`` accept finding ``f`` of a vulnerability with ``names``?"""
    if rule.get("class") not in (None, f["class"]) or f["target"] not in rule["targets"]:
        return False
    if f["class"] == "lang":  # PEP 503 names, as the merge matches them
        same = norm(rule["package"]) == norm(f["pkg"])
    else:  # an OS package is exactly what the distribution calls it (python3.12 is not python3-12)
        same = rule["package"] == f["pkg"]
    return same and (not rule.get("ids") or bool(set(rule["ids"]) & names))


def is_strings(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(v, str) for v in value)


def rule_is_bad(rule: object) -> bool:
    """A rule that is not a mapping of the documented shape: ``package`` a string,
    ``targets`` a list of strings, ``ids`` (optional, empty means every vulnerability
    of the package) a list of strings, ``class`` (optional) a string.
    """
    return not (
        isinstance(rule, dict)
        and isinstance(rule.get("package"), str)
        and is_strings(rule.get("targets"))
        and (rule.get("ids") is None or is_strings(rule["ids"]))
        and (rule.get("class") is None or isinstance(rule["class"], str))
    )


def add_acceptances(report: dict[str, Any], rules: list[Any]) -> None:
    """Set ``acceptances`` of the report: the rules with ``expired``, ``bad_expiry``,
    ``bad_rule`` and ``matched`` (the findings a live rule accepts); a rule of a wrong
    shape is kept with ``bad_rule: true`` (a non-mapping entry as ``{"rule": entry}``),
    never acts, and does not stop the report; and ``accepted`` on each of
    those findings: ``{"until", "reason", "rule"}`` of the rule with the earliest
    ``expires`` (``rule`` indexes ``acceptances``). A finding is matched by package
    (a language package as the merge normalizes it, an OS package exactly), by the
    ``class`` of the rule if it has one, and, when the rule has ``ids``, by the names
    of the vulnerability: those of all findings merged with it (same target, package
    and version, intersecting names), so an id of the OSV twin accepts the Trivy
    finding of the same vulnerability too.
    """
    today = report["generated_utc"][:10]
    audit = []
    for rule in rules:
        until = iso_date(rule.get("expires") if isinstance(rule, dict) else None)
        audit.append(
            {
                **(rule if isinstance(rule, dict) else {"rule": rule}),
                "expired": until is not None and until <= today,
                "bad_expiry": until is None,
                "bad_rule": rule_is_bad(rule),
                "matched": 0,
            }
        )
    live = [
        i
        for i, a in enumerate(audit)
        if not (a["expired"] or a["bad_expiry"] or a["bad_rule"])
    ]
    slots: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for f in report["findings"]:
        slots.setdefault((f["target"], norm(f["pkg"]), f["version"]), []).append(f)
    for slot in slots.values():
        for group in components(slot):
            names = {n for f in group for n in f["names"]}
            for f in group:
                hits = [i for i in live if rule_matches(audit[i], f, names)]
                for i in hits:
                    audit[i]["matched"] += 1
                if hits:
                    i = min(hits, key=lambda i: audit[i]["expires"])
                    f["accepted"] = {
                        "until": audit[i]["expires"],
                        "reason": audit[i].get("reason"),
                        "rule": i,
                    }
    report["acceptances"] = audit


def add_ignores(report: dict[str, Any], parts_dir: Path) -> None:
    """Set ``ignores`` and ``ignores_error`` of the report, ``accepted`` on every
    record (the earliest ``until`` of the acting lines that name it and of the rules
    that accept all its findings) and ``matched`` on the lines.
    """
    ignores, error = read_ignores(report, parts_dir)
    report["ignores"], report["ignores_error"] = ignores, error
    if ignores is None:
        return
    acting: dict[str, list[str]] = {}
    for e in ignores:
        if e["until"] and not e["expired"]:  # a bad expiry has no until
            acting.setdefault(e["id"], []).append(e["until"])
    seen: set[str] = set()
    for version in report["versions"]:
        for v in version["vulns"]:
            seen.update(v["names"])
            untils = [u for n in v["names"] for u in acting.get(n, ())]
            if v["accepted"]:  # accepted by the rules too: the earliest until, as of several lines
                untils.append(v["accepted"]["until"])
            v["accepted"] = {"until": min(untils)} if untils else None
    for e in ignores:
        e["matched"] = e["id"] in seen
