import json
from pathlib import Path
from typing import Any

import fix_apply
from apply import lock_tools
from files import Journal
import pytest
from builders import item, line
from texts import pr_body, summary
from texts_builders import record, result

GOLDEN = Path(__file__).parent / "golden"
RUNS = [
    "https://github.com/o/r/actions/runs/11",
    "https://github.com/o/r/actions/runs/12",
]
SKIP = {
    "pkg": "glob",
    "class": "lang",
    "ids": ["CVE-glob"],
    "reason": "not fixed in development",
    "reason_code": "not_fixed_in_development",
}


def golden(name: str, text: str) -> None:
    assert text == (GOLDEN / name).read_bytes().decode("utf-8")


def few_rows() -> dict[str, Any]:
    return result(
        [
            record("hono"),
            record("axios", fixed_with=["hono"], changes=[], files=[]),
            record("debug", "already_fixed"),
            record("glob", "manual", method="manual"),
        ]
    )


def test_n7_4_body_few_rows() -> None:
    plan_line = {**line(item()), "skipped": [SKIP]}
    golden("body_few_rows.md", pr_body(plan_line, few_rows(), "success", RUNS))


def test_n7_4_body_more_than_15_rows_folds_non_fixed() -> None:
    items = [record(f"fixed-{i:02}") for i in range(6)]
    items += [record(f"done-{i}", "already_fixed") for i in range(3)]
    items += [record(f"open-{i:02}", "manual") for i in range(10)]
    items[-1]["vulns"] = [f"CVE-{i}" for i in range(7)]
    items[-1]["severities"] = ["LOW", "CRITICAL"]
    body = pr_body(line(item()), result(items), "success", RUNS[:1])
    golden("body_many_rows.md", body)
    assert body.count("<details>") == 1


def test_n7_4_body_15_rows_is_not_folded() -> None:
    items = [record(f"p{i:02}", "manual") for i in range(15)]
    assert "<details>" not in pr_body(line(item()), result(items), "success")


def test_n7_4_body_only_non_fixed_rows_above_15_have_no_empty_table() -> None:
    items = [record(f"p{i:02}", "manual") for i in range(16)]
    body = pr_body(line(item()), result(items), "success")
    assert "16 more packages not fixed here" in body
    assert body.count("| Package |") == 1


def test_n7_4_body_overrides_side_effects_and_red_baseline() -> None:
    items = [
        record(
            "follow-redirects",
            method_used="npm-override",
            override_keys=["follow-redirects@^1.0.0"],
            changed_other=["ms 1.0.0 -> 1.0.1", "debug 2.0.0 -> 2.0.1"],
            npm_version="10.9.2",
            changes=[],
        ),
        record("pyyaml", left_out=2),
        record("fixed-by-other", fixed_with=["pyyaml"], left_out=1, changes=[]),
    ]
    body = pr_body(
        line(item()),
        result(
            items,
            lockfile_tools=[{"file": "poetry.lock", "from": "1.8.3", "to": "2.1.0"}],
        ),
        "failure (commit status: ci/build)",
    )
    golden("body_overrides.md", body)


def test_n7_4_body_has_no_side_effects_section_when_empty() -> None:
    assert "Side effects" not in pr_body(line(item()), few_rows(), "success")


def test_n7_4_body_ids_above_five_are_counted_with_the_highest_severity() -> None:
    many = record(
        "lodash", vulns=[f"CVE-{i}" for i in range(6)], severities=["MEDIUM", "HIGH"]
    )
    five = record("zlib", vulns=[f"CVE-{i}" for i in range(5)])
    body = pr_body(line(item()), result([many, five]), "success")
    assert "| 6 ids, highest HIGH |" in body
    assert "| CVE-0, CVE-1, CVE-2, CVE-3, CVE-4 |" in body


def test_n7_4_body_has_no_test_text() -> None:
    body = pr_body(line(item()), few_rows(), "success", RUNS)
    assert "test bed" not in body.lower()


def test_n6_3_fixed_with_row_shows_fixed_with_the_kept_method() -> None:
    kept = record("hono", method_used="npm-override", npm_version="10.9.2", changes=[])
    other = record("axios", fixed_with=["hono", "glob"], changes=[], files=[])
    body = pr_body(line(item()), result([kept, other]), "success")
    row = "| axios | - | npm-override | fixed | CVE-axios | fixed with hono, glob |"
    assert row in body


def test_n7_1_no_pr_body_is_rendered_when_nothing_is_applied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = tmp_path / "plan.json"
    plan.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "repo": "o/r",
                "reports": [],
                "lines": [line(item())],
            }
        ),
        encoding="utf-8",
    )
    nothing = {**result([record("x", "manual")]), "files": []}
    monkeypatch.setattr(fix_apply, "process_line", lambda *a: nothing)
    monkeypatch.setattr(fix_apply, "baseline_ci", lambda *a: "none")
    argv = [
        "apply", "--plan", str(plan), "--branch", "release-1.2", "--tree", str(tmp_path),
        "--repo", "o/r", "--output-dir", str(tmp_path / "out"), "--dependabot", "d",
        "--updater-images", "{}", "--proxy-image", "p",
    ]  # fmt: skip
    assert fix_apply.main(argv) == 0
    assert (tmp_path / "out" / "result.json").is_file()
    assert not (tmp_path / "out" / "pr-body.md").exists()


def test_n7_4_body_header_names_the_report_runs() -> None:
    body = pr_body(line(item()), few_rows(), "success", RUNS)
    assert f"Scan: {RUNS[0]}, {RUNS[1]}" in body
    assert "Scan:" not in pr_body(line(item()), few_rows(), "success")


def summary_of(done: dict[str, Any]) -> str:
    plan_line = {**line(item()), "skipped": [SKIP]}
    return summary({"repo": "o/r", "lines": [plan_line]}, {"release-1.2": done})


def test_n7_5_summary_per_item_table_has_the_reason_code() -> None:
    pr = {"action": "created", "url": "u", "reason_code": None}
    golden("summary_items.md", summary_of({**few_rows(), "pr": pr, "token_kind": "app"}))


def test_n7_2_summary_says_manual_changes_and_that_the_pr_is_not_edited() -> None:
    pr = {
        "action": "none",
        "reason": "sca-fix/release-1.2 has commits of others, not pushed",
        "reason_code": "branch_has_manual_changes",
    }
    text = summary_of({**few_rows(), "pr": pr})
    assert (
        "no pull request (branch_has_manual_changes): sca-fix/release-1.2 has commits "
        "of others, not pushed; the pull request is not edited"
    ) in text


def test_n7_2_summary_says_unchanged_without_push_and_with_body_update() -> None:
    pr = {"action": "updated", "url": "u", "head": "h", "reason_code": "unchanged"}
    text = summary_of({**few_rows(), "pr": pr})
    assert (
        "pull request updated: u (branch unchanged, not pushed, pull request body updated)"
        in text
    )


def poetry(version: str) -> str:
    return f"# This file is automatically @generated by Poetry {version} and should not be changed by hand.\n"


def test_n7_4_lock_tools_names_a_poetry_lockfile_written_by_another_poetry(
    tmp_path: Path,
) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "poetry.lock").write_text(poetry("1.8.3"), encoding="utf-8")
    (tmp_path / "a" / "poetry.lock").write_text(poetry("2.1.0"), encoding="utf-8")
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    journal = Journal(tmp_path)
    journal.write("poetry.lock", poetry("2.1.0") + "x\n")
    journal.write("a/poetry.lock", poetry("2.1.0") + "x\n")
    journal.write("package-lock.json", "{ }")
    assert lock_tools(journal) == [{"file": "poetry.lock", "from": "1.8.3", "to": "2.1.0"}]
