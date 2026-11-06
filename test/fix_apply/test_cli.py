import json
from pathlib import Path
from typing import Any

import fix_apply
import pytest
from builders import item, line
from texts import summary


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


def test_summary_names_every_line() -> None:
    plan = {"repo": "o/r", "lines": [line(item()), line(item(), branch="release-1.1")]}
    text = summary(plan, {"release-1.2": result(pr={"action": "created", "url": "u"})})
    assert "pull request created: u" in text
    assert "not run (job failed)" in text
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
    assert written["pr"] == {
        "action": "none",
        "reason": "nothing applied",
        "reason_code": "nothing_applied",
    }
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


def test_node_command_writes_the_workflow_outputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / ".nvmrc").write_text("22\n", encoding="utf-8")
    out = tmp_path / "out.txt"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))
    assert fix_apply.main(["node", "--tree", str(tmp_path)]) == 0
    assert out.read_text(encoding="utf-8") == "version=22\nsource=.nvmrc\n"


def result_file(tmp_path: Path, **fields: Any) -> None:
    (tmp_path / "result.json").write_text(
        json.dumps({"files": ["f"], "branch": "b", **fields}), encoding="utf-8"
    )


def publish_args(tmp_path: Path, *extra: str) -> list[str]:
    return [
        "publish",
        *extra,
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


def test_n7_1_dry_run_comes_before_nothing_applied(tmp_path: Path) -> None:
    result_file(tmp_path, files=[])
    fix_apply.main(publish_args(tmp_path, "--dry-run"))
    written = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))
    assert written["pr"]["reason_code"] == "dry_run"


def test_n10_2_a_publish_error_still_writes_the_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*args: Any) -> Any:
        raise fix_apply.PublishError("git push failed: denied")

    monkeypatch.setattr(fix_apply, "publish", broken)
    result_file(tmp_path)
    assert fix_apply.main(publish_args(tmp_path)) == 1
    written = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))
    assert written["pr"] == {
        "action": "failed",
        "reason": "git push failed: denied",
        "reason_code": "pr_failed",
    }
    plan = {"repo": "o/r", "lines": [line(item(), branch="b")]}
    assert "pull request failed: git push failed: denied" in summary(
        plan, {"b": {**result(), **written}}
    )


def test_n8_4_the_baseline_ci_is_read_with_its_own_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = {"schema_version": 2, "lines": [line(item(), branch="b")], "reports": []}
    (tmp_path / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
    seen: list[str] = []
    monkeypatch.setattr(fix_apply, "process_line", lambda *a: {"files": []})
    monkeypatch.setattr(
        fix_apply, "baseline_ci", lambda repo, branch, token: seen.append(token) or "x"
    )
    monkeypatch.setenv("GH_TOKEN", "app")
    monkeypatch.setenv("BASELINE_CI_TOKEN", "workflow")
    args = ["apply", "--plan", str(tmp_path / "plan.json"), "--branch", "b"]
    args += ["--tree", str(tmp_path), "--repo", "o/r", "--output-dir", str(tmp_path)]
    args += ["--dependabot", "d", "--updater-images", "{}", "--proxy-image", "p"]
    assert fix_apply.main(args) == 0
    assert seen == ["workflow"]


def test_n7_5_the_summary_tells_a_missing_branch_from_a_failed_job() -> None:
    plan = {
        "repo": "o/r",
        "lines": [line(item(), branch="gone"), line(item(), branch="failed")],
    }
    text = summary(plan, {}, ["gone"])
    gone, failed = text.split("branch `failed`")
    assert "not run (branch missing)" in gone
    assert "not run (job failed)" in failed
