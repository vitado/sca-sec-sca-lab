"""The texts of the fix: the pull request body and the summary of all lines."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from scan import norm

TEST_BED_NOTE = "Opened by the W4 test bed of the SCA fix delivery (a test run on a fork, not a production job)."


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


def pr_body(
    line: Mapping[str, Any], result: Mapping[str, Any], baseline_ci: str
) -> str:
    applied = [r for r in result["items"] if r["status"] == "applied"]
    manual = [r for r in result["items"] if r["status"] != "applied"]
    out = [
        f"Security fixes for `{result['branch']}` ({result['ref']}).",
        "",
        TEST_BED_NOTE,
        "",
    ]
    out += table(
        ["Package", "Installed -> new", "Method", "Vulnerabilities", "Evidence"],
        [
            [
                r["pkg"],
                installed_to_new(r),
                r["method"],
                ", ".join(r["vulns"]),
                "rescan: item vulnerabilities gone, no new HIGH or CRITICAL",
            ]
            for r in applied
        ],
    )
    docker = result["docker"]
    if docker["status"] == "applied":
        out += ["Base image changes (Dependabot, no major version):", ""]
        out += table(
            ["Image", "From", "To", "Directory"],
            [
                [c["name"], c["from"], c["to"], c["directory"]]
                for c in docker["changes"]
            ],
        )
    out += [
        "Rescan: Trivy on the changed tree"
        + (" and on the rebuilt images" if docker["status"] == "applied" else "")
        + f", baseline of the untouched branch had {result['baseline_findings']} findings. "
        f"CI of the latest completed run on the branch before this change: {baseline_ci}.",
        "",
    ]
    if manual:
        out += ["Not applied, left for a human:", ""]
        out += table(
            ["Package", "Method", "Reason"],
            [[r["pkg"], r["method"], r["reason"]] for r in manual],
        )
    if line["skipped"]:
        out += ["Skipped by the planner:", ""]
        out += [
            f"- {s['pkg']} ({s['class']}): {s['reason']}" for s in line["skipped"]
        ] + [""]
    return "\n".join(out)


def pr_note(result: Mapping[str, Any]) -> str:
    pr = result.get("pr")
    if not pr:
        return "not published"
    if pr["action"] == "none":
        return f"no pull request: {pr['reason']}"
    if pr["action"] == "failed":
        return f"branch {pr['head']} pushed, pull request failed: {pr['reason']}"
    return f"pull request {pr['action']}: {pr['url']}"


def summary(plan: Mapping[str, Any], results: Mapping[str, Mapping[str, Any]]) -> str:
    """Every line of the plan with its items, whether or not anything was applied."""
    out = [f"# Fix run for {plan['repo']}", ""]
    if any(
        r.get("pr", {}).get("action") in ("created", "updated")
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
            out += [
                "not run (branch missing or job failed)"
                if automated
                else "no automated items",
                "",
            ]
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
            ["Package", "Method", "Status", "Detail"],
            [
                [
                    r["pkg"],
                    r["method"],
                    "applied" if r["status"] == "applied" else "manual",
                    r["reason"] or installed_to_new(r),
                ]
                for r in result["items"]
            ],
        )
        out += [
            f"- skipped {s['pkg']} ({s['class']}): {s['reason']}"
            for s in line["skipped"]
        ] + [""]
    return "\n".join(out)
