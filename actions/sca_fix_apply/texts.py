"""The texts of the fix: the pull request body and the summary of all lines."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

import apply_codes as codes
from scan import norm

PROOF = (
    "Each change was rescanned with Trivy and OSV: the targeted vulnerabilities are "
    "gone and no new High or Critical appeared."
)
RED_BASELINE = (
    "The baseline is red: failures that were there before this change are not "
    "caused by it and the rescan gate does not look at them."
)
HEADER = ["Package", "Installed -> new", "Method", "Status", "Vulnerabilities", "Note"]
FOLD_AFTER = 15  # rows of the package table before the unfixed ones are folded
IDS_SHOWN = 5  # vulnerability ids listed before they are counted
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
STATUS_ORDER = {"fixed": 0, "already fixed": 1, "open": 2}


def cell(text: object) -> str:
    return str(text).replace("|", r"\|").replace("\n", " ")


def installed_to_new(record: Mapping[str, Any]) -> str:
    """``installed -> new`` of an applied record: what Dependabot did to the package,
    else the planned target.
    """
    done = [c for c in record["changes"] if norm(str(c["name"])) == norm(record["pkg"])]
    if done:
        return "; ".join(f"{c['from']} -> {c['to']}" for c in done)
    return "; ".join(
        f"{a} -> {b or '?'}"
        for a, b in zip(record["installed"], record["planned"], strict=True)
    )


def table(header: Sequence[str], rows: Sequence[Sequence[object]]) -> list[str]:
    out = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    out.extend("| " + " | ".join(cell(c) for c in row) + " |" for row in rows)
    return [*out, ""]


def method_of(record: Mapping[str, Any]) -> str:
    return str(record.get("method_used", record["method"]))


def vulnerabilities(record: Mapping[str, Any]) -> str:
    """The ids of the record; more than ``IDS_SHOWN`` become a count and the highest
    severity.
    """
    ids = record["vulns"]
    if len(ids) <= IDS_SHOWN:
        return ", ".join(ids)
    found = set(record["severities"])
    highest = next((s for s in SEVERITIES if s in found), "UNKNOWN")
    return f"{len(ids)} ids, highest {highest}"


def package_row(
    record: Mapping[str, Any], items: Mapping[str, Mapping[str, Any]]
) -> tuple[str, list[str]]:
    """The status and the cells of the package table for one item record."""
    ids = vulnerabilities(record)
    if record["status"] == "already_fixed":
        return "already fixed", [
            record["pkg"], "-", method_of(record), "already fixed", ids, "",
        ]  # fmt: skip
    if record["status"] == "manual":
        return "open", [
            record["pkg"], "-", method_of(record), "open", ids, record["reason"] or "",
        ]  # fmt: skip
    with_ = record.get("fixed_with")
    if with_:
        kept = items.get(with_[0], record)
        return "fixed", [
            record["pkg"], "-", method_of(kept), "fixed", ids,
            "fixed with " + ", ".join(with_),
        ]  # fmt: skip
    return "fixed", [
        record["pkg"], installed_to_new(record), method_of(record), "fixed", ids, "",
    ]  # fmt: skip


def package_tables(result: Mapping[str, Any]) -> list[str]:
    """One row per item: fixed, already fixed, open; by package inside. Above
    ``FOLD_AFTER`` rows the ones that are not fixed go into a collapsed block.
    """
    items = {r["pkg"]: r for r in result["items"]}
    rows = sorted(
        (STATUS_ORDER[status], cells[0], cells)
        for status, cells in (package_row(r, items) for r in result["items"])
    )
    fixed = [cells for rank, _, cells in rows if rank == 0]
    rest = [cells for rank, _, cells in rows if rank > 0]
    if len(rows) <= FOLD_AFTER or not rest:
        return table(HEADER, [cells for _, _, cells in rows])
    out = table(HEADER, fixed) if fixed else []
    out += [
        f"<details><summary>{len(rest)} more packages not fixed here</summary>",
        "",
        *table(HEADER, rest),
        "</details>",
        "",
    ]
    return out


def side_effects(result: Mapping[str, Any]) -> list[str]:
    """What the change did besides the fixes: packages npm changed on the way, versions
    of a file change left out, the tool that wrote a lockfile.
    """
    own = [
        r
        for r in result["items"]
        if r["status"] == "applied" and not r.get("fixed_with")
    ]
    out = [
        f"- {r['pkg']}: also changed by npm resolution: {'; '.join(r['changed_other'])}"
        for r in own
        if r.get("changed_other")
    ]
    out += [
        f"- {r['pkg']}: {r['left_out']} version(s) of a file change left out, "
        "their edits overlap with an earlier one"
        for r in own
        if r.get("left_out")
    ]
    out += [
        f"- {t['file']}: written by Poetry {t['to']}, was {t['from']}"
        for t in result.get("lockfile_tools", [])
    ]
    versions = {
        r["npm_version"] for r in own if r.get("method_used") == "npm-override"
    }
    out += [
        f"- package-lock.json: updated with npm {v}, lockfile format unchanged"
        for v in sorted(versions)
    ]
    return ["### Side effects", "", *out, ""] if out else []


def pr_body(
    line: Mapping[str, Any],
    result: Mapping[str, Any],
    baseline_ci: str,
    run_urls: Sequence[str] = (),
) -> str:
    out = [f"Security fixes for `{result['branch']}` ({result['ref']}).", ""]
    if run_urls:
        out += ["Scan: " + ", ".join(run_urls), ""]
    out += [PROOF, "", *package_tables(result), *side_effects(result)]
    out += [
        f"Baseline CI (informational): latest completed run on the branch before "
        f"this change: {baseline_ci}."
        + (
            f" {RED_BASELINE}"
            if baseline_ci.startswith(("failure", "cancelled", "timed_out"))
            else ""
        ),
        "",
    ]
    if line["skipped"]:
        out += ["<details><summary>Skipped by the planner</summary>", ""]
        out += [
            f"- {s['pkg']} ({s['class']}): {s['reason']}" for s in line["skipped"]
        ] + ["", "</details>", ""]
    return "\n".join(out)


def pr_note(result: Mapping[str, Any]) -> str:
    pr = result.get("pr")
    if not pr:
        return "not published"
    if pr["action"] == "none":
        edited = (
            "; the pull request is not edited"
            if pr.get("reason_code") == codes.BRANCH_HAS_MANUAL_CHANGES
            else ""
        )
        return f"no pull request ({pr.get('reason_code')}): {pr['reason']}{edited}"
    if pr["action"] == "failed":
        pushed = f"branch {pr['head']} pushed, " if pr.get("head") else ""
        return f"{pushed}pull request failed: {pr['reason']}"
    note = (
        " (branch unchanged, not pushed, pull request body updated)"
        if pr.get("reason_code") == codes.UNCHANGED
        else ""
    )
    return f"pull request {pr['action']}: {pr['url']}{note}"


def detail(record: Mapping[str, Any]) -> str:
    """The reason text of an item, else what was done for it."""
    if record["reason"]:
        return str(record["reason"])
    if record.get("fixed_with"):
        return "fixed with " + ", ".join(record["fixed_with"])
    return installed_to_new(record)


def summary(
    plan: Mapping[str, Any],
    results: Mapping[str, Mapping[str, Any]],
    missing: Sequence[str] = (),
) -> str:
    """Every line of the plan with its items, whether or not anything was applied;
    ``missing`` are the release branches the plan job did not find.
    """
    out = [f"# Fix run for {plan['repo']}", ""]
    if any(
        r.get("pr", {}).get("action") in ("created", "updated")
        and r.get("token_kind", "workflow") == "workflow"
        for r in results.values()
    ):
        out += [
            (
                "The pull requests were opened with the workflow token: GitHub does not "
                "start the pull request workflows of the repository for them."
            ),
            "",
        ]
    for line in plan["lines"]:
        out += [
            f"## Line {line['line']} ({line['ref']}), branch `{line['branch']}`",
            "",
        ]
        result = results.get(line["branch"])
        if result is None:
            automated = any(i["method"] != "manual" for i in line["items"])
            why = "branch missing" if line["branch"] in missing else "job failed"
            out += [f"not run ({why})" if automated else "no automated items", ""]
            out += [
                f"- {i['pkg']} ({i['class']}): manual, {i['reason']}"
                for i in line["items"]
                if i["method"] == "manual"
            ]
            out += [""]
            continue
        out += [
            pr_note(result),
            f"CI baseline: {result['baseline_ci']}, runtime {result['seconds']} s",
            "",
        ]
        out += table(
            ["Package", "Method", "Status", "Reason code", "Detail"],
            [
                [
                    r["pkg"],
                    r.get("method_used", r["method"]),
                    r["status"],
                    r.get("reason_code") or "",
                    detail(r),
                ]
                for r in result["items"]
            ],
        )
        out += [
            f"- skipped {s['pkg']} ({s['class']}): {s['reason']}"
            for s in line["skipped"]
        ] + [""]
    return "\n".join(out)
