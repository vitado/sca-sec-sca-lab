"""summary.md of the SCA merge: the vulnerable packages of every scanned version."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from datetime import date, datetime, timedelta
from typing import Any

from normalize import SEVERITIES, norm
from vulns import COUNT_KEYS, VERSION, counts_of, fixed_of, pkg_of

# GitHub rejects a step summary over 1 MiB; the rest of the limit is left for the
# parts of the job summary that are not this one
STEP_SUMMARY_LIMIT_BYTES = 1024 * 1024 - 16 * 1024

# a row lists at most this many vulnerability ids (a curl row has about 27)
MAX_IDS_IN_CELL = 5

Finding = Mapping[str, Any]


def cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def short_time(value: str | None) -> str:
    return f"{value[:16]}Z" if value else "n/a"


def target_label(target: Mapping[str, Any], repo: str) -> str:
    """``src`` or the short name of the image (``chat``, ``bff``): where a package is
    seen within one version.
    """
    if target["kind"] == "fs":
        return "src"
    image = target["image"].split("/")[-1]
    if image == repo:
        return image.removeprefix("ai-dial-")
    return image.removeprefix(f"{repo}-")


def package_rows(
    findings: Sequence[Finding],
    source_ids: set[str],
    vulns: Sequence[Mapping[str, Any]],
    note: Callable[[Mapping[str, Any]], str],
) -> list[dict[str, Any]]:
    """One row per (class, normalized package name) - the version dropped for OS
    packages, which the scanners spell differently (dpkg epochs and revisions). Its
    vulnerabilities are the ``vulns`` records its findings belong to (id, severity
    and marks of the record; the fix from the row's own findings, a record spans the
    installed versions). Rows without a fix come last, development-only packages
    after the others, then worst severity first.
    """
    records = {(v["class"], norm(v["pkg"]), n): v for v in vulns for n in v["names"]}
    groups: dict[tuple[str, ...], list[Finding]] = {}
    for f in sorted(findings, key=lambda f: f["scanner"] != "trivy"):
        key = (f["class"], norm(f["pkg"]))
        groups.setdefault(key if key[0] == "os" else (*key, f["version"]), []).append(f)
    rows = []
    for key, fs in groups.items():
        found: dict[str, dict[str, Any]] = {}
        for f in fs:
            v = records[(f["class"], norm(f["pkg"]), f["id"])]
            if v["id"] not in found:
                found[v["id"]] = {**v, "url": f["url"], "note": note(v), "fixed": []}
            found[v["id"]]["fixed"] += fixed_of(f)
        ordered = sorted(
            found.values(), key=lambda v: (SEVERITIES.index(v["severity"]), v["id"])
        )
        with_chain = next((f for f in fs if f["chain"]), None)
        in_source = [
            loc for f in fs if f["target"] in source_ids for loc in f["locations"]
        ]
        fixed = ", ".join(dict.fromkeys(x for v in ordered for x in v["fixed"]))
        rows.append(
            {
                "class": key[0],
                "pkg": pkg_of(fs, source_ids),
                "version": fs[0]["version"] if key[0] == "os" else key[2],
                "vulns": ordered,
                "severity": ordered[0]["severity"],
                "fixed": fixed,
                "no_fix": not fixed,
                "chain": with_chain["chain"] if with_chain else [],
                "relationship": next(
                    (f["relationship"] for f in fs if f["relationship"]), None
                ),
                "dev": all(f["dev"] for f in fs),
                "where": in_source or [loc for f in fs for loc in f["locations"]],
                "targets": {f["target"] for f in fs},
                "scanners": "+".join(
                    s[0].upper()
                    for s in ("trivy", "osv")
                    if any(f["scanner"] == s for f in fs)
                ),
            }
        )
    return sorted(
        rows,
        key=lambda r: (
            r["no_fix"],
            r["dev"],
            SEVERITIES.index(r["severity"]),
            r["pkg"],
            r["version"],
        ),
    )


def where_cell(locations: Sequence[str]) -> str:
    parts = list(dict.fromkeys("/".join(loc.split("/")[-2:]) for loc in locations))
    return cell(
        ", ".join(parts[:2]) + (f" +{len(parts) - 2}" if len(parts) > 2 else "")
    )


def chain_cell(row: Mapping[str, Any]) -> str:
    chain = row["chain"]
    direct = "direct" if chain or row["relationship"] == "direct" else ""
    text = " → ".join(chain) if len(chain) > 1 else direct
    return cell(text)


def vulnerabilities_cell(row: Mapping[str, Any]) -> str:
    """The first ``MAX_IDS_IN_CELL`` records of the row, the rest as a count (the
    whole list is in ``report.json``); each links to its advisory by the record id.
    """
    mixed = len({v["severity"] for v in row["vulns"]}) > 1
    shown = row["vulns"][:MAX_IDS_IN_CELL]
    text = ", ".join(
        (v["severity"][0] + " " if mixed else "")
        + (f"[{cell(v['id'])}]({v['url']})" if v["url"] else cell(v["id"]))
        + cell(v["note"])
        for v in shown
    )
    more = len(row["vulns"]) - len(shown)
    return text + (f", +{more} more" if more else "")


def package_table(
    rows: Sequence[Mapping[str, Any]],
    columns: Sequence[tuple[str, str]],
    libraries: bool,
) -> list[str]:
    head = ["Package@version", "Sev", "Fixed", "Vulnerabilities"]
    head += ["Chain", "Where"] if libraries else []
    head += ["Seen in", "Scanner"]
    lines = ["| " + " | ".join(head) + " |", "|" + "|".join(["---"] * len(head)) + "|"]
    for r in rows:
        cells = [
            cell(f"{r['pkg']}@{r['version']}") + (" `dev`" if r["dev"] else ""),
            r["severity"][0],
            cell(r["fixed"] or "no fix"),
            vulnerabilities_cell(r),
        ]
        if libraries:
            cells += [chain_cell(r), where_cell(r["where"])]
        cells += [
            ", ".join(
                dict.fromkeys(label for label, tid in columns if tid in r["targets"])
            ),
            r["scanners"],
        ]
        lines.append("| " + " | ".join(cells) + " |")
    return lines


def plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def totals(libraries: Sequence[Any], os_rows: Sequence[Any]) -> str:
    fixable = sum(1 for r in [*libraries, *os_rows] if not r["no_fix"])
    return ", ".join(
        [
            plural(len(libraries), "library", "libraries"),
            plural(len(os_rows), "OS package", "OS packages"),
            f"{fixable} fixable",
        ]
    )


def scan_status(trivy: Mapping[str, Any], osv: Mapping[str, Any] | None) -> str:
    text = trivy["status"] + (f" ({trivy['reason']})" if trivy["reason"] else "")
    if trivy["status"] == "ok" and osv:
        if osv["status"] != "ok":
            detail = (
                f"failed: {osv['reason']}" if osv["status"] == "failed" else osv["status"]
            )
            text += f" · OSV {detail}"
        # an ok with a reason states an exclusion (the image scan disabled for the
        # repository); it must not read as a plain ok
        elif osv["reason"]:
            text += f" · OSV ok ({osv['reason']})"
    return text


def header(report: Mapping[str, Any]) -> list[str]:
    tools = report["tools"]
    parts = [
        f"commit `{(report['commit_sha'] or '')[:7]}`",
        f"default branch `{report['default_branch']}`",
        f"Trivy {tools['trivy']} (DB {short_time(tools['trivy_db'])}, "
        f"Java DB {short_time(tools['trivy_java_db'])})",
        f"osv-scanner {tools['osv_scanner']} (queried {tools['osv_queried_at'] or 'n/a'})",
    ]
    if report.get("engine"):
        parts.append(f"engine {report['engine']}")
    if report["run_url"]:
        parts.append(f"[run {report['run_id']}]({report['run_url']})")
    lines = [f"# SCA · {report['repo']}", "", " · ".join(parts), ""]
    notes = health(report)
    if scan_ref := report.get("scan_ref"):
        notes.insert(0, f"Focused on tag `{scan_ref}` (a manual run on one tag).")
    if report.get("forced_image_scan"):
        notes.insert(
            0,
            "The direct OSV image scan runs on this run although it is off for the "
            "repository.",
        )
    if report["ignores_error"] and not report.get("scan_ref"):
        notes.append(f"Risk acceptance not applied: {report['ignores_error']}.")
    return [*lines, *(f"- {n}" for n in notes), *([""] if notes else [])]


def stamp(value: str) -> datetime:
    return datetime.strptime(value[:19], "%Y-%m-%dT%H:%M:%S")


def health(report: Mapping[str, Any]) -> list[str]:
    """Warnings about the scan itself: a stale Trivy DB (over 48 hours at the time
    of the report) and an ``ok`` Trivy target that scanned no packages.
    """
    lines = []
    try:
        age = stamp(report["generated_utc"]) - stamp(report["tools"]["trivy_db"])
    except (TypeError, ValueError):
        age = timedelta(0)
    if age > timedelta(hours=48):
        lines.append(f"**Warning:** the Trivy DB is {age // timedelta(hours=1)} h old.")
    empty = [
        t["id"]
        for t in report["targets"]
        if (t["scanner"], t["status"], t["packages_scanned"]) == ("trivy", "ok", 0)
    ]
    if empty:
        lines.append(f"**Warning:** no packages scanned in {cell(', '.join(empty))}.")
    return lines


def scan_cell(report: Mapping[str, Any], ids: set[str]) -> str:
    """ok, or failed when any scan of the version failed, and what was scanned."""
    targets = [t for t in report["targets"] if t["id"] in ids]

    def of(scanner: str, status: str) -> set[str]:
        return {
            t["id"]
            for t in targets
            if t["scanner"] == scanner and t["status"] == status
        }

    failed, skipped = of("trivy", "failed"), of("trivy", "not_applicable")
    osv_failed = of("osv", "failed") - failed
    scanned = {t["id"]: t["kind"] for t in targets if t["id"] not in failed | skipped}
    parts = ["source"] if "fs" in scanned.values() else []
    if images := sum(1 for kind in scanned.values() if kind == "image"):
        parts.append(plural(images, "image", "images"))
    for n, what in ((failed, "failed"), (osv_failed, "OSV failed"), (skipped, "n/a")):
        if n:
            parts.append(f"{len(n)} {what}")
    return f"{'failed' if failed or osv_failed else 'ok'} ({', '.join(parts)})"


def ignores_audit(report: Mapping[str, Any]) -> list[str]:
    """What is wrong with the lines of ``.trivyignore``; nothing when all is well
    or the file was not read (the header says so).
    """
    checks = (
        ("Expired", lambda e: e["expired"]),
        ("Without expiry", lambda e: e["no_expiry"]),
        ("With a bad date", lambda e: e["bad_expiry"]),
        ("Matching nothing", lambda e: not e["matched"]),
    )
    lines = []
    for title, bad in checks:
        found = [
            e["id"] + (f" (until {e['until']})" if e["until"] else "")
            for e in report["ignores"] or []
            if bad(e)
        ]
        if found:
            lines.append(f"- {title}: {cell(', '.join(found))}")
    return lines


def acceptances_audit(report: Mapping[str, Any]) -> list[str]:
    """What is wrong with the acceptance rules of the pipeline; nothing when all is
    well or the run has none.
    """
    checks = (
        ("Expired", lambda a: a["expired"]),
        ("With a bad date", lambda a: a["bad_expiry"]),
        (
            "Matching nothing",
            lambda a: not (a["matched"] or a["expired"] or a["bad_expiry"]),
        ),
    )
    lines = []
    for title, bad in checks:
        found = [
            a["package"] + (f" (until {a.get('expires')})" if a.get("expires") else "")
            for a in report.get("acceptances") or []
            if bad(a)
        ]
        if found:
            lines.append(f"- {title}: {cell(', '.join(found))}")
    return lines


def count_cell(n: int) -> str:
    return str(n) if n else "-"


def table_lines(
    head: Sequence[str], rows: Sequence[Sequence[str]], text_columns: int = 1
) -> list[str]:
    """A table whose first ``text_columns`` columns are text, the rest numbers."""
    rule = "|" + "---|" * text_columns + "---:|" * (len(head) - text_columns)
    return [
        "| " + " | ".join(head) + " |",
        rule,
        *("| " + " | ".join(r) + " |" for r in rows),
    ]


def vulnerabilities_table(versions: Sequence[Mapping[str, Any]]) -> list[str]:
    """The ``counts`` of every version, and the unique vulnerabilities over all
    (the last row): the worst severity of a (class, package, id) key, fixable when
    any of its records has a fix.
    """
    unique: dict[tuple[str, str, str], dict[str, str]] = {}
    for v in versions:
        for r in v["vulns"]:
            key = (r["class"], norm(r["pkg"]), r["id"])
            u = unique.setdefault(key, {"severity": "UNKNOWN", "fixed": ""})
            u["severity"] = min(u["severity"], r["severity"], key=SEVERITIES.index)
            u["fixed"] = u["fixed"] or r["fixed"]
    partial = " (partial)"
    blocks = [
        (cell(v["ref"] + (partial if v["status"] == "failed" else "")), v["counts"])
        for v in versions
    ]
    any_failed = partial if any(v["status"] == "failed" for v in versions) else ""
    blocks.append((f"**All (unique)**{any_failed}", counts_of([*unique.values()])))
    unknown = any(c["unknown"] for _, c in blocks)
    shown = [s for s in SEVERITIES if s != "UNKNOWN" or unknown]

    def cells(c: Mapping[str, int]) -> list[str]:
        counts = (count_cell(c[COUNT_KEYS[s]]) for s in shown)
        return [*counts, count_cell(c["fixable"])]

    head = ["Branch / tag", *(s.capitalize() for s in shown), "Fixable"]
    rows = [[label, *cells(c)] for label, c in blocks]
    return [
        *table_lines(head, rows),
        "",
        "Each vulnerability counted once per row; one present in several branches/tags "
        "is counted once in the last row.",
    ]


def packages_table(
    report: Mapping[str, Any],
    versions: Sequence[Mapping[str, Any]],
    version_rows: Mapping[str, Sequence[Mapping[str, Any]]],
    unique: Sequence[Mapping[str, Any]],
) -> list[str]:
    unknown = any(r["severity"] == "UNKNOWN" for r in unique if r["class"] == "lang")
    severities = [s for s in SEVERITIES if s != "UNKNOWN" or unknown]

    def counts(rows: Sequence[Mapping[str, Any]]) -> list[str]:
        libs = [r for r in rows if r["class"] == "lang"]
        return [
            *(
                count_cell(sum(1 for r in libs if r["severity"] == s))
                for s in severities
            ),
            count_cell(len(rows) - len(libs)),
            count_cell(sum(1 for r in rows if not r["no_fix"])),
        ]

    head = ["Branch / tag", "Scan", *(s.capitalize() for s in severities)]
    head += ["OS packages", "Fixable"]
    rows = [
        [
            cell(v["ref"]),
            cell(scan_cell(report, set(v["targets"]))),
            *counts(version_rows[v["ref"]]),
        ]
        for v in versions
    ]
    rows.append(["**All (unique)**", "", *counts(unique)])
    lines = [
        *table_lines(head, rows, 2),
        "",
        "Vulnerable libraries by worst severity; a package in several branches/tags is "
        "counted once in the last row.",
    ]
    if any(v["note"] for r in unique for v in r["vulns"]):
        lines += [
            "",
            "new in DB: published within 14 days; accepted until D: a `.trivyignore` line "
            "or an acceptance rule of the caller accepts it until D; fixed in X: not found in release X, "
            "which has the same targets.",
        ]
    return lines


def version_section(
    version: str,
    rows: Sequence[Mapping[str, Any]],
    columns: Sequence[tuple[str, str]],
) -> list[str]:
    libraries = [r for r in rows if r["class"] == "lang"]
    os_rows = [r for r in rows if r["class"] == "os"]
    lines = [f"## {cell(version)} - {totals(libraries, os_rows)}", ""]
    if libraries:
        lines += ["<details><summary>Libraries</summary>", ""]
        lines += [*package_table(libraries, columns, True), "", "</details>", ""]
    if os_rows:
        lines += ["<details><summary>Base image (OS packages)</summary>", ""]
        lines += [*package_table(os_rows, columns, False), "", "</details>", ""]
    return lines


def results_by_target(report: Mapping[str, Any]) -> list[str]:
    by_id: dict[str, list[Mapping[str, Any]]] = {}
    for t in report["targets"]:
        by_id.setdefault(t["id"], []).append(t)
    lines = [
        "<details><summary>Scan details by target</summary>",
        "",
        "| Target | Type | Version | Scan | Packages scanned |",
        "|---|---|---|---|---:|",
    ]
    for tid, ts in by_id.items():
        trivy = next((t for t in ts if t["scanner"] == "trivy"), ts[0])
        osv = next((t for t in ts if t["scanner"] == "osv"), None)
        ref = trivy["ref"] or "—"
        if trivy["kind"] == "fs" and trivy["commit_sha"]:
            ref = f"{ref}@{trivy['commit_sha'][:7]}"
        packages = (
            "–" if trivy["packages_scanned"] is None else trivy["packages_scanned"]
        )
        kind = "source" if trivy["kind"] == "fs" else "image"
        lines.append(
            f"| {cell(tid)} | {kind} | {cell(ref)} | {cell(scan_status(trivy, osv))} | "
            f"{packages} |"
        )
    return [*lines, "", "</details>"]


def target_stems(
    report: Mapping[str, Any], version: Mapping[str, Any]
) -> set[str] | None:
    """Target ids without the ref suffix; None unless every Trivy scan is ok."""
    ts = [t for t in report["targets"] if t["id"] in version["targets"]]
    if any(
        t["status"] != "ok" or t["packages_scanned"] == 0
        for t in ts
        if t["scanner"] == "trivy"
    ):
        return None
    return {re.sub(f"-v?{re.escape(version['ref'])}$", "", t["id"]) for t in ts}


def build_summary(report: Mapping[str, Any]) -> str:
    short = report["repo"].split("/")[-1]
    columns, seen = [], set()
    for t in report["targets"]:
        if t["id"] not in seen:
            seen.add(t["id"])
            columns.append((target_label(t, short), t["id"]))
    source_ids = {t["id"] for t in report["targets"] if t["kind"] == "fs"}
    versions = report["versions"]
    day = date.fromisoformat(report["generated_utc"][:10])
    cutoff = (day - timedelta(14)).isoformat()
    li = next((i for i, v in enumerate(versions) if v["latest"]), None)
    newest = versions[li] if li is not None else {"vulns": []}
    newest_stems = target_stems(report, newest) if li is not None else None
    # the names of the newest release by class, whatever the package: a renamed
    # package must not look fixed
    newest_names = {(r["class"], n) for r in newest["vulns"] for n in r["names"]}
    version_rows = {}
    for i, version in enumerate(versions):
        # "fixed in": absent from the newest release, scanned the same way
        hint = bool(
            newest_stems is not None
            and i > li
            and version["kind"] != "development"
            and VERSION.fullmatch(version["ref"])
            and newest_stems == target_stems(report, version)
        )

        def note(r: Mapping[str, Any], hint: bool = hint) -> str:
            marks = []
            if (r["published"] or "")[:10] >= cutoff:
                marks.append("new in DB")
            if r["accepted"]:
                marks.append(f"accepted until {r['accepted']['until']}")
            if hint and not any((r["class"], n) in newest_names for n in r["names"]):
                marks.append(f"fixed in {newest['ref']}")
            return f" ({', '.join(marks)})" if marks else ""

        fs = [f for f in report["findings"] if f["target"] in version["targets"]]
        version_rows[version["ref"]] = package_rows(
            fs, source_ids, version["vulns"], note
        )
    # a package is one installed version: the rows of the versions, deduplicated
    # (the first version wins: development, then the newest)
    unique = {
        (r["class"], norm(r["pkg"]), r["version"]): r
        for vrows in reversed(version_rows.values())
        for r in vrows
    }.values()
    lines = header(report) + ["## Vulnerabilities", ""]
    lines += [*vulnerabilities_table(versions), ""]
    lines += ["## Packages to update", ""]
    lines += [*packages_table(report, versions, version_rows, [*unique]), ""]
    if audit := ignores_audit(report):
        lines += ["## Ignore file", "", *audit, ""]
    if audit := acceptances_audit(report):
        lines += ["## Acceptance rules", "", *audit, ""]
    for v in versions:
        if version_rows[v["ref"]]:
            lines += version_section(v["ref"], version_rows[v["ref"]], columns)
    lines += [*results_by_target(report), ""]
    lines += [
        "---",
        "Artifact `sca-report`: `report.json` plus native reports in "
        "`_native/trivy/` and `_native/osv/`.",
    ]
    return "\n".join(lines) + "\n"


def truncate_summary(text: str, run_url: str | None) -> str:
    """The summary as the job summary can take it: whole if it fits, else cut at a
    line, with the ``<details>`` the cut leaves open closed and a note on where the
    whole of it is.
    """
    data = text.encode("utf-8")
    if len(data) <= STEP_SUMMARY_LIMIT_BYTES:
        return text
    where = "the `sca-report` artifact of this run"
    if run_url:
        where = f"the `sca-report` artifact of [this run]({run_url})"
    note = (
        f"\n> The summary is cut: it is {len(data)} bytes and a job summary takes "
        f"1 MiB. The whole `summary.md` is in {where}.\n"
    )
    close = "</details>\n"
    room = STEP_SUMMARY_LIMIT_BYTES - len(note.encode("utf-8"))
    while True:
        kept = data[:room].decode("utf-8", errors="ignore")
        kept = kept[: kept.rfind("\n") + 1]
        closing = close * max(kept.count("<details") - kept.count("</details>"), 0)
        if len((kept + closing + note).encode("utf-8")) <= STEP_SUMMARY_LIMIT_BYTES:
            return kept + closing + note
        room -= len(close)
