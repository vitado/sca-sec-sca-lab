"""Reason codes of the applier (N9.2) and the result.json header (N10.2)."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

import apply_codes
import fix_apply
import pytest
from apply import process_line
from builders import file, finding, item, line, outcome, tools
from dependabot import TIMEOUT
from scan import Finding, ScanError
from test_apply import (
    NODE,
    PACKAGE,
    docker_tree,
    lock,
    lockfile_tree,
    os_item,
    override_tree,
    run_override,
    tree_with,
)

# N9.2: the code list of the spec, copied
N9_2_CODES = {
    "accepted",
    "not_fixed_in_development",
    "development_data_incomplete",
    "severity",
    "unfixable",
    "dev",
    "no_fixed_version",
    "needs_major",
    "version_unparsable",
    "needs_image_rebuild",
    "only_in_image",
    "ecosystem_unsupported",
    "method_disabled",
    "dependabot_refused",
    "dependabot_no_change",
    "dependabot_timeout",
    "dependabot_failed",
    "override_direct",
    "override_no_root_lockfile",
    "override_no_node",
    "override_needs_manual",
    "override_lockfile_format",
    "override_not_reached",
    "override_npm_failed",
    "property_form_unsupported",
    "property_shared",
    "property_resolution_failed",
    "property_not_reached",
    "property_side_major",
    "catalog_unsupported",
    "image_build_failed",
    "no_dockerfile",
    "no_dockerfile_changed",
    "rescan_failed",
    "gate_still_present",
    "gate_new_serious",
    "not_in_baseline",
    "dry_run",
    "nothing_applied",
    "unchanged",
    "branch_has_manual_changes",
    "pr_failed",
}
APPLY = Path(apply_codes.__file__).parent


def sub(root: Path, name: str) -> Path:
    """A fresh directory below ``root``."""
    path = root / name
    path.mkdir()
    return path


def code_of(result: dict[str, Any], index: int = 0) -> str | None:
    """The reason code of an item record, checked against the N9.2 list."""
    code = result["items"][index]["reason_code"]
    assert code is None or code in N9_2_CODES
    return code


def pip_item() -> dict[str, Any]:
    return item(
        "filelock", fallback="manual", ecosystem="PyPI", locations=("poetry.lock",)
    )


def run_pip(tmp_path: Path, error: str | None) -> dict[str, Any]:
    tree = tree_with(tmp_path, **{"poetry.lock": "old"})
    return process_line(
        line(pip_item()),
        "o/r",
        tree,
        tools(lambda job, manager: outcome(error=error), [{finding("filelock")}]),
    )


def test_n9_2_table_is_in_the_spec_list() -> None:
    assert apply_codes.CODES <= N9_2_CODES


def test_n9_2_codes_are_spelled_only_in_the_table() -> None:
    """No other module of the applier has a string literal that is a code."""
    for path in APPLY.glob("*.py"):
        if path.name == "apply_codes.py":
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                assert node.value not in apply_codes.CODES, (path.name, node.value)


def test_n9_2_applied_item_has_no_code(tmp_path: Path) -> None:
    result = process_line(
        line(item()),
        "o/r",
        lockfile_tree(tmp_path),
        tools(lambda job, manager: outcome(file("new")), [{finding()}, set()]),
    )
    assert result["items"][0]["status"] == "applied"
    assert code_of(result) is None


@pytest.mark.parametrize(
    ("error", "code"),
    [
        ("security_update_not_possible", "dependabot_refused"),
        ("security_update_dependency_not_found", "dependabot_refused"),
        (None, "dependabot_no_change"),
        (TIMEOUT, "dependabot_timeout"),
        ("dependabot failed (exit 1): boom", "dependabot_failed"),
        ("update_not_possible", "dependabot_failed"),
    ],
)
def test_n9_2_dependabot_outcomes(tmp_path: Path, error: str | None, code: str) -> None:
    result = run_pip(tmp_path, error)
    assert result["items"][0]["status"] == "manual"
    assert code_of(result) == code


def test_n9_2_unsupported_ecosystem(tmp_path: Path) -> None:
    go = item("lib", ecosystem="Go", fallback=None, locations=("go.sum",))
    result = process_line(
        line(go), "o/r", tmp_path, tools(lambda j, m: outcome(), [set()])
    )
    assert code_of(result) == "ecosystem_unsupported"


def test_n9_2_planned_manual_item_copies_the_plan_code(tmp_path: Path) -> None:
    manual = item(
        "x",
        method="manual",
        fallback=None,
        target=None,
        reason="fix needs another major",
        reason_code="needs_major",
    )
    result = process_line(line(manual), "o/r", tmp_path, tools(lambda j, m: outcome(), []))
    assert code_of(result) == "needs_major"


def test_n9_2_already_fixed_is_not_in_baseline(tmp_path: Path) -> None:
    not_needed = process_line(
        line(item()),
        "o/r",
        lockfile_tree(tmp_path),
        tools(
            lambda job, manager: outcome(error="security_update_not_needed"),
            [{finding()}],
        ),
    )
    assert not_needed["items"][0]["status"] == "already_fixed"
    assert code_of(not_needed) == "not_in_baseline"
    gone = process_line(
        line(item()),
        "o/r",
        lockfile_tree(tmp_path),
        tools(lambda job, manager: outcome(file("new")), [set(), set()]),
    )
    assert gone["items"][0]["status"] == "already_fixed"
    assert code_of(gone) == "not_in_baseline"


def test_n9_2_gate_codes(tmp_path: Path) -> None:
    vuln = finding()
    still = process_line(
        line(item(fallback="manual")),
        "o/r",
        lockfile_tree(tmp_path),
        tools(lambda job, manager: outcome(file("new")), [{vuln}, {vuln}]),
    )
    assert code_of(still) == "gate_still_present"
    serious = finding("other", severity="CRITICAL")
    new = process_line(
        line(item(fallback="manual")),
        "o/r",
        lockfile_tree(tmp_path),
        tools(lambda job, manager: outcome(file("new")), [{vuln}, {serious}]),
    )
    assert code_of(new) == "gate_new_serious"


def test_n9_2_rescan_failure(tmp_path: Path) -> None:
    def scans() -> set[Finding]:
        raise ScanError("boom")

    ready = tools(lambda job, manager: outcome(file("new")), [{finding()}])
    queue = [{finding()}]
    fake = type(ready)(
        dependabot=ready.dependabot,
        scan_tree=lambda: queue.pop(0) if queue else scans(),
        scan_image=ready.scan_image,
        npm_install=ready.npm_install,
        npm_ls=ready.npm_ls,
        npm_version=ready.npm_version,
    )
    result = process_line(
        line(item(fallback="manual")), "o/r", lockfile_tree(tmp_path), fake
    )
    assert code_of(result) == "rescan_failed"


def test_n9_2_override_failures_before_the_edit(tmp_path: Path) -> None:
    direct = run_override(override_tree(tmp_path), [{finding()}], relationship="direct")
    assert code_of(direct) == "override_direct"
    no_node = run_override(override_tree(sub(tmp_path, "n"), PACKAGE), [{finding()}])
    assert code_of(no_node) == "override_no_node"


def test_n9_2_override_without_root_lockfile(tmp_path: Path) -> None:
    tree = tree_with(tmp_path, **{"package.json": NODE})
    nested = item(locations=("web/package-lock.json",))
    result = process_line(
        line(nested),
        "o/r",
        tree,
        tools(lambda job, manager: outcome(error=TIMEOUT), [{finding()}]),
    )
    assert code_of(result) == "override_no_root_lockfile"


def test_n5_4_override_with_the_lockfile_listed_but_missing(tmp_path: Path) -> None:
    tree = tree_with(tmp_path, **{"package.json": NODE})
    result = process_line(
        line(item()),
        "o/r",
        tree,
        tools(lambda job, manager: outcome(error=TIMEOUT), [{finding()}]),
    )
    assert code_of(result) == "override_no_root_lockfile"


def test_n9_2_override_needs_a_human(tmp_path: Path) -> None:
    package = (
        '{\n  "overrides": {\n    "a": {\n      "hono": {"x": "1"}\n    }\n  },\n'
        '  "engines": {"node": ">=20"}\n}\n'
    )
    result = run_override(override_tree(tmp_path, package), [{finding()}])
    assert code_of(result) == "override_needs_manual"


def test_n9_2_override_npm_and_lockfile_failures(tmp_path: Path) -> None:
    broken = run_override(
        override_tree(sub(tmp_path, "a")), [{finding()}], install=lambda: "npm error"
    )
    assert code_of(broken) == "override_npm_failed"
    tree = override_tree(sub(tmp_path, "b"))

    def rewrite() -> str | None:
        (tree / "package-lock.json").write_text('{"lockfileVersion": 2}', encoding="utf-8")
        return None

    assert code_of(run_override(tree, [{finding()}], install=rewrite)) == (
        "override_lockfile_format"
    )


def test_n9_2_override_not_reached_and_gate(tmp_path: Path) -> None:
    short = run_override(
        override_tree(sub(tmp_path, "a")),
        [{finding()}],
        ls=lambda pkg: [("b > hono", "2.0.12")],
    )
    assert code_of(short) == "override_not_reached"
    vuln = finding()
    still = run_override(override_tree(sub(tmp_path, "b")), [{vuln}, {vuln}])
    assert code_of(still) == "gate_still_present"
    assert still["items"][0]["dependabot_result"] == "security_update_not_possible"
    new = run_override(
        override_tree(sub(tmp_path, "c")), [{vuln}, {finding("x", severity="HIGH")}]
    )
    assert code_of(new) == "gate_new_serious"
    gone = run_override(override_tree(sub(tmp_path, "d")), [set(), set()])
    assert code_of(gone) == "not_in_baseline"


def test_n9_2_override_rescan_failure(tmp_path: Path) -> None:
    tree = override_tree(tmp_path)
    queue: list[Any] = [{finding()}]

    def scan() -> set[Finding]:
        if queue:
            return queue.pop()
        raise ScanError("boom")

    def install() -> str | None:
        (tree / "package-lock.json").write_text(lock("2.1.5"), encoding="utf-8")
        return None

    ready = tools(lambda job, manager: outcome(error=TIMEOUT), [])
    fake = type(ready)(
        dependabot=ready.dependabot,
        scan_tree=scan,
        scan_image=ready.scan_image,
        npm_install=install,
        npm_ls=lambda pkg: [("hono", "2.1.5")],
        npm_version=ready.npm_version,
    )
    result = process_line(line(item()), "o/r", tree, fake)
    assert code_of(result) == "rescan_failed"
    assert result["items"][0]["dependabot_result"] == TIMEOUT


def test_n9_2_docker_codes(tmp_path: Path) -> None:
    vuln = finding("brotli-libs")
    bump = lambda job, manager: outcome(file("FROM a:2\n", "/", "Dockerfile"))  # noqa: E731

    def run(tree: Path, dependabot: Any, image: Any = lambda r, p: set()) -> Any:
        return process_line(line(os_item()), "o/r", tree, tools(dependabot, [], image))

    assert code_of(run(sub(tmp_path, "a"), lambda j, m: outcome())) == "no_dockerfile"
    no_change = run(docker_tree(sub(tmp_path, "b")), lambda j, m: outcome())
    assert code_of(no_change) == "dependabot_no_change"
    other = run(docker_tree(sub(tmp_path, "c")), lambda j, m: outcome(file("x")))
    assert code_of(other) == "no_dockerfile_changed"
    refused = run(
        docker_tree(sub(tmp_path, "d")),
        lambda j, m: outcome(error="security_update_not_possible"),
    )
    assert code_of(refused) == "dependabot_refused"

    def build_fails(root: Path, path: str) -> set[Finding]:
        if "a:2" in (root / path).read_text(encoding="utf-8"):
            raise ScanError("nope")
        return {vuln}

    failed = run(docker_tree(sub(tmp_path, "e")), bump, build_fails)
    assert code_of(failed) == "image_build_failed"
    still = run(docker_tree(sub(tmp_path, "f")), bump, lambda r, p: {vuln})
    assert code_of(still) == "gate_still_present"
    calls: list[str] = []

    def adds_serious(root: Path, path: str) -> set[Finding]:
        calls.append(path)
        extra = finding("x", severity="CRITICAL")
        return {vuln} if len(calls) == 1 else {extra}

    serious = run(docker_tree(sub(tmp_path, "g")), bump, adds_serious)
    assert code_of(serious) == "gate_new_serious"
    gone = run(docker_tree(sub(tmp_path, "h")), bump, lambda r, p: set())
    assert code_of(gone) == "not_in_baseline"


# result.json and the plan version


def plan_file(tmp_path: Path, version: int | None = 2) -> Path:
    plan = {
        "repo": "epam/r",
        "reports": [{"run_id": "11"}, {"run_id": "12"}],
        "lines": [line(item("x", method="manual", fallback=None, target=None))],
    }
    if version is not None:
        plan["schema_version"] = version
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan), encoding="utf-8")
    return path


def apply_args(tmp_path: Path, plan: Path) -> list[str]:
    return [
        "apply", "--plan", str(plan), "--branch", "release-1.2", "--tree", str(tmp_path),
        "--repo", "o/r", "--output-dir", str(tmp_path / "out"), "--dependabot", "d",
        "--updater-images", "{}", "--proxy-image", "p",
    ]  # fmt: skip


@pytest.mark.parametrize("version", [1, 3, None])
def test_n10_1_applier_rejects_another_plan_version(
    tmp_path: Path, version: int | None, capsys: pytest.CaptureFixture[str]
) -> None:
    plan = plan_file(tmp_path, version)
    with pytest.raises(SystemExit) as stop:
        fix_apply.main(apply_args(tmp_path, plan))
    assert "schema_version" in str(stop.value)
    summary = ["summary", "--plan", str(plan), "--results-dir", str(tmp_path)]
    with pytest.raises(SystemExit):
        fix_apply.main(summary)
    assert not (tmp_path / "out").exists()


def test_n10_2_result_header(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fix_apply, "baseline_ci", lambda repo, branch, token: "none")
    monkeypatch.setenv("GITHUB_RUN_ID", "777")
    assert fix_apply.main(apply_args(tmp_path, plan_file(tmp_path))) == 0
    written = json.loads((tmp_path / "out" / "result.json").read_text(encoding="utf-8"))
    assert written["schema_version"] == 1
    assert (written["repo"], written["run_id"]) == ("o/r", "777")
    assert written["report_run_ids"] == ["11", "12"]
    assert written["items"][0]["reason_code"] is None
    monkeypatch.delenv("GITHUB_RUN_ID")
    assert fix_apply.main(apply_args(tmp_path, plan_file(tmp_path))) == 0
    again = json.loads((tmp_path / "out" / "result.json").read_text(encoding="utf-8"))
    assert again["run_id"] is None


@pytest.mark.parametrize(
    ("files", "dry", "code"),
    [([], False, "nothing_applied"), (["f"], True, "dry_run")],
)
def test_n10_2_pr_reason_code(tmp_path: Path, files: list[str], dry: bool, code: str) -> None:
    (tmp_path / "result.json").write_text(
        json.dumps({"files": files, "branch": "b"}), encoding="utf-8"
    )
    args = [
        "publish", "--plan", "unused", "--branch", "b", "--tree", str(tmp_path),
        "--repo", "o/r", "--output-dir", str(tmp_path),
    ]  # fmt: skip
    assert fix_apply.main([*args, *(["--dry-run"] if dry else [])]) == 0
    written = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))
    assert written["pr"]["reason_code"] == code
    assert code in N9_2_CODES


def test_n9_2_pr_failed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "result.json").write_text(
        json.dumps({"files": ["f"], "branch": "b"}), encoding="utf-8"
    )
    failed = {"head": "sca-fix/b", "action": "failed", "reason": "boom"}
    monkeypatch.setattr(fix_apply, "publish", lambda *args: failed)
    args = [
        "publish", "--plan", "unused", "--branch", "b", "--tree", str(tmp_path),
        "--repo", "o/r", "--output-dir", str(tmp_path),
    ]  # fmt: skip
    assert fix_apply.main(args) == 1
    written = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))
    assert written["pr"]["reason_code"] == "pr_failed"
    assert "pr_failed" in N9_2_CODES
