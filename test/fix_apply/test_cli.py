import json
from pathlib import Path
from typing import Any

import fix_apply
import pytest
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


def test_summary_notes_the_workflow_token_only_for_that_token() -> None:
    plan = {"repo": "o/r", "lines": [line(item())]}
    pr = {"action": "created", "url": "u"}
    for kind in ("app", "token"):
        text = summary(plan, {"release-1.2": result(pr=pr, token_kind=kind)})
        assert "workflow token" not in text
    text = summary(plan, {"release-1.2": result(pr=pr, token_kind="workflow")})
    assert "workflow token" in text
    text = summary(plan, {"release-1.2": result(pr={"action": "none", "reason": "r"})})
    assert "workflow token" not in text


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
            "--token-kind",
            "app",
        ]
    )
    assert code == 0
    written = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))
    assert written["pr"] == {"action": "none", "reason": "nothing applied"}
    assert written["token_kind"] == "app"


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


def test_pr_body_shows_overrides_and_already_fixed_items() -> None:
    applied = {
        **result()["items"][0],
        "pkg": "follow-redirects",
        "method_used": "npm-override",
        "override_keys": ["follow-redirects@^1.0.0"],
        "changed_other": ["ms 1.0.0 -> 1.0.1"],
        "changes": [],
    }
    fixed = {
        **applied,
        "pkg": "hono",
        "status": "already_fixed",
        "reason": "already fixed on the branch (x)",
    }
    body = pr_body(line(item()), result(items=[applied, fixed]), "success")
    assert "| follow-redirects | follow-redirects@^1.0.0 | ms 1.0.0 -> 1.0.1 |" in body
    assert "- hono: already fixed on the branch (x)" in body
    assert "Not applied" not in body


def test_node_command_writes_the_workflow_outputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / ".nvmrc").write_text("22\n", encoding="utf-8")
    out = tmp_path / "out.txt"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))
    assert fix_apply.main(["node", "--tree", str(tmp_path)]) == 0
    assert out.read_text(encoding="utf-8") == "version=22\nsource=.nvmrc\n"
