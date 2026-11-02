import json
from pathlib import Path
from typing import Any

import fix_apply
from builders import item, line
from texts import pr_body, summary


def result(**fields: Any) -> dict[str, Any]:
    record = {
        "pkg": "hono",
        "class": "lang",
        "method": "dependabot",
        "status": "applied",
        "reason": None,
        "installed": ["2.0.12"],
        "planned": ["2.1.5"],
        "vulns": ["CVE-hono"],
        "changes": [
            {"name": "hono", "from": "2.0.12", "to": "2.1.6", "directory": "/"}
        ],
    }
    manual = {
        **record,
        "pkg": "glob",
        "status": "manual",
        "reason": "why",
        "changes": [],
    }
    return {
        "branch": "release-1.2",
        "ref": "1.2.3",
        "baseline_findings": 4,
        "baseline_ci": "success",
        "seconds": 5,
        "docker": {"status": "none", "changes": []},
        "items": [record, manual],
        **fields,
    }


def test_pr_body_lists_applied_and_manual_items() -> None:
    body = pr_body(line(item()), result(), "success")
    assert "| hono | 2.0.12 -> 2.1.6 | dependabot | CVE-hono |" in body
    assert "| glob | dependabot | why |" in body
    assert "W4 test bed" in body
    assert "baseline of the untouched branch had 4 findings" in body


def test_summary_names_every_line() -> None:
    plan = {"repo": "o/r", "lines": [line(item()), line(item(), branch="release-1.1")]}
    text = summary(plan, {"release-1.2": result(pr={"action": "created", "url": "u"})})
    assert "pull request created: u" in text
    assert "not run (branch missing or job failed)" in text
    assert "workflow token" in text


def test_publish_without_files_opens_nothing(tmp_path: Path) -> None:
    (tmp_path / "result.json").write_text(
        json.dumps({"files": [], "branch": "b"}), encoding="utf-8"
    )
    code = fix_apply.main(
        [
            "publish",
            "--plan",
            "unused",
            "--branch",
            "b",
            "--tree",
            str(tmp_path),
            "--repo",
            "o/r",
            "--output-dir",
            str(tmp_path),
        ]
    )
    assert code == 0
    written = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))
    assert written["pr"] == {"action": "none", "reason": "nothing applied"}


def test_dry_run_publishes_nothing(tmp_path: Path) -> None:
    (tmp_path / "result.json").write_text(
        json.dumps({"files": ["f"], "branch": "b"}), encoding="utf-8"
    )
    fix_apply.main(
        [
            "publish",
            "--dry-run",
            "--plan",
            "unused",
            "--branch",
            "b",
            "--tree",
            str(tmp_path),
            "--repo",
            "o/r",
            "--output-dir",
            str(tmp_path),
        ]
    )
    written = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))
    assert written["pr"]["reason"] == "dry run"
