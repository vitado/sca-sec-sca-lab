"""Apply the items of one release line to a working tree and prove each of them."""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dependabot import JobError, Outcome, docker_job, job_directories, security_job
from files import Journal
from scan import Finding, ScanError, gate, new_serious

OVERRIDE_NOT_IMPLEMENTED = "npm-override not implemented yet (P3)"


@dataclass(frozen=True)
class Tools:
    """What the line needs from the outside, so the flow can be tested without the
    CLI, Trivy and Docker.
    """

    dependabot: Callable[[Mapping[str, Any], str], Outcome]
    scan_tree: Callable[[], set[Finding]]
    scan_image: Callable[[Path, str], set[Finding]]


def dockerfiles(tree: Path) -> list[str]:
    return sorted(
        p.relative_to(tree).as_posix()
        for p in tree.rglob("Dockerfile*")
        if p.is_file() and "node_modules" not in p.parts and ".git" not in p.parts
    )


def changes(outcome: Outcome) -> list[dict[str, Any]]:
    return [
        {
            "name": d.get("name"),
            "from": d.get("previous-version"),
            "to": d.get("version"),
            "directory": d.get("directory"),
        }
        for d in outcome.dependencies
    ]


def new_record(item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "pkg": item["pkg"],
        "class": item["class"],
        "ecosystem": item["ecosystem"],
        "method": item["method"],
        "installed": [t["installed"] for t in item["targets"]],
        "planned": [t["target"] for t in item["targets"]],
        "vulns": [v["id"] for v in item["vulns"]],
        "severities": sorted({v["severity"] for v in item["vulns"]}),
        "status": "manual",
        "reverted": False,
        "reason": item["reason"],
        "files": [],
        "changes": [],
        "seconds": 0,
    }


def fail(
    record: dict[str, Any], item: Mapping[str, Any], reason: str
) -> dict[str, Any]:
    """The item stays a recommendation. An npm item would go on to the override step
    (not built yet); the Dependabot reason is kept either way.
    """
    record["detail"] = reason
    record["reason"] = (
        OVERRIDE_NOT_IMPLEMENTED if item["fallback"] == "npm-override" else reason
    )
    return record


def apply_security(
    item: Mapping[str, Any],
    repo: str,
    branch: str,
    journal: Journal,
    tools: Tools,
    baseline: set[Finding],
    current: set[Finding],
) -> tuple[dict[str, Any], set[Finding]]:
    record = new_record(item)
    try:
        manager, directories = job_directories(journal.tree, item)
    except JobError as exc:
        return fail(record, item, str(exc)), current
    record["package_manager"], record["directories"] = manager, directories
    outcome = tools.dependabot(
        security_job(item, manager, repo, branch, directories), manager
    )
    record["seconds"] = outcome.seconds
    checkpoint = journal.checkpoint()
    changed, left_out = journal.apply(outcome.files)
    if not changed:
        return fail(
            record, item, outcome.error or "dependabot produced no change"
        ), current
    record["changes"], record["left_out"] = changes(outcome), left_out
    try:
        after = tools.scan_tree()
    except ScanError as exc:
        journal.restore(checkpoint)
        record["reverted"] = True
        return fail(record, item, f"rescan failed: {exc}"), current
    why = gate(item, current, after, baseline)
    if why:
        journal.restore(checkpoint)
        record["reverted"] = True
        return fail(record, item, f"rescan gate: {why}"), current
    record.update(status="applied", reason=None, files=changed)
    return record, after


def apply_docker(
    items: list[dict[str, Any]],
    repo: str,
    branch: str,
    journal: Journal,
    tools: Tools,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Bump the base images of the line once and let the image rescan decide per
    item. Returns the records of the items and the data of the step.
    """
    records = [new_record(i) for i in items]
    step: dict[str, Any] = {
        "status": "none",
        "changes": [],
        "files": [],
        "builds": [],
        "seconds": 0,
    }

    def all_manual(reason: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        for record in records:
            record["reason"] = reason
        return records, step

    files = dockerfiles(journal.tree)
    if not files:
        return all_manual("no Dockerfile in the tree")
    parents = {Path(f).parent.as_posix() for f in files}
    directories = sorted("/" if p == "." else f"/{p}" for p in parents)
    outcome = tools.dependabot(docker_job(repo, branch, directories), "docker")
    step["seconds"] = outcome.seconds
    checkpoint = journal.checkpoint()
    changed, _ = journal.apply(outcome.files)
    if not changed:
        return all_manual(outcome.error or "dependabot produced no change")
    journal.restore(checkpoint)
    built = [p for p in changed if p in files]
    if not built:
        return all_manual("dependabot changed no Dockerfile")
    step["changes"], step["files"] = changes(outcome), changed

    def scan_all(label: str) -> set[Finding]:
        found: set[Finding] = set()
        for path in built:
            started = time.monotonic()
            try:
                found |= tools.scan_image(journal.tree, path)
            except ScanError as exc:
                raise ScanError(f"{label} of {path}: {exc}") from exc
            finally:
                step["builds"].append(
                    {
                        "dockerfile": path,
                        "label": label,
                        "seconds": round(time.monotonic() - started),
                    }
                )
        return found

    try:
        before = scan_all("baseline build")
    except ScanError as exc:
        step["status"] = "none"
        return all_manual(f"image build failed: {exc}")
    journal.apply(outcome.files)
    try:
        after = scan_all("build after the bump")
    except ScanError as exc:
        journal.restore(checkpoint)
        step["status"] = "reverted"
        return all_manual(f"image build failed: {exc}")
    serious = new_serious(after, before)
    for record, item in zip(records, items, strict=True):
        why = (
            f"new HIGH or CRITICAL after the bump: {', '.join(serious)}"
            if serious
            else gate(item, before, after, before)
        )
        if why:
            record["reason"] = f"image rescan gate: {why}"
        else:
            record.update(
                status="applied", reason=None, files=changed, changes=step["changes"]
            )
    if any(r["status"] == "applied" for r in records):
        step["status"] = "applied"
    else:
        journal.restore(checkpoint)
        step["status"] = "reverted"
    return records, step


def process_line(
    line: Mapping[str, Any], repo: str, tree: Path, tools: Tools
) -> dict[str, Any]:
    """Run the automated items of a plan line; the result says what was applied
    (and the files it changed) and what stays manual, with the reason.
    """
    started = time.monotonic()
    journal = Journal(tree)
    items = list(line["items"])
    security = [i for i in items if i["method"] == "dependabot"]
    baseline = tools.scan_tree() if security else set()
    current = baseline
    records: dict[int, dict[str, Any]] = {}
    for index, item in enumerate(items):
        if item["method"] == "dependabot":
            records[index], current = apply_security(
                item, repo, line["branch"], journal, tools, baseline, current
            )
        elif item["method"] != "docker-tag":
            records[index] = new_record(item)
    docker = [
        (i, item) for i, item in enumerate(items) if item["method"] == "docker-tag"
    ]
    step: dict[str, Any] = {
        "status": "none",
        "changes": [],
        "files": [],
        "builds": [],
        "seconds": 0,
    }
    if docker:
        done, step = apply_docker(
            [item for _, item in docker], repo, line["branch"], journal, tools
        )
        records.update({i: record for (i, _), record in zip(docker, done, strict=True)})
    return {
        "line": line["line"],
        "ref": line["ref"],
        "branch": line["branch"],
        "baseline_findings": len(baseline),
        "items": [records[i] for i in sorted(records)],
        "docker": step,
        "files": journal.paths(),
        "seconds": round(time.monotonic() - started),
    }
