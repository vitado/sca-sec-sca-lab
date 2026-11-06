"""The human-readable layer of the fix plan (``fix-plan.md``)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def cell(text: object) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def change(item: Mapping[str, Any]) -> str:
    return "; ".join(
        f"{t['installed']} -> {t['target'] or '?'}" for t in item["targets"]
    )


def render_markdown(plan: Mapping[str, Any]) -> str:
    """One section per line: a table of the items and the list of skipped packages."""
    out = [f"# Fix plan of {plan['repo']}", ""]
    for ref in plan.get("skipped_refs", []):
        out.append(f"Skipped version {ref['ref']}: {ref['reason']}.")
        out.append("")
    for line in plan["lines"]:
        partial = ", partial" if line["partial"] else ""
        out.append(
            f"## Line {line['line']} ({line['ref']}, {line['kind']}{partial}), "
            f"branch `{line['branch']}`"
        )
        out.append("")
        if line["items"]:
            out.append(
                "| Package | Class | Installed -> target | Method | Evidence or reason |"
            )
            out.append("|---|---|---|---|---|")
            for item in line["items"]:
                evidence = item["reason"] or "; ".join(
                    sorted({t["evidence"] for t in item["targets"]})
                )
                out.append(
                    f"| {cell(item['pkg'])} | {item['class']} | {cell(change(item))} "
                    f"| {item['method']} | {cell(evidence)} |"
                )
        else:
            out.append("No items.")
        out.append("")
        if line["skipped"]:
            out.append("Skipped:")
            out.append("")
            for skipped in line["skipped"]:
                ids = ", ".join(skipped["ids"])
                out.append(
                    f"- {skipped['pkg']} ({skipped['class']}): {skipped['reason']} ({ids})"
                )
            out.append("")
        dropped = line["dropped"]
        out.append(
            f"Dropped: {dropped['severity']} by severity, {dropped['unfixable']} "
            f"without a fix, {dropped['dev']} dev-only."
        )
        out.append("")
    return "\n".join(out)
