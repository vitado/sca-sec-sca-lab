import subprocess
from pathlib import Path
from typing import Any

import publish as publish_module
import pytest
from publish import PublishError, baseline_ci, publish


def git(cwd: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=True
    )
    return done.stdout.strip()


@pytest.fixture
def clone(tmp_path: Path) -> Path:
    remote = tmp_path / "remote.git"
    git(tmp_path, "init", "--bare", "-b", "release-1.2", str(remote))
    work = tmp_path / "work"
    git(tmp_path, "clone", str(remote), str(work))
    (work / "lock").write_text("old", encoding="utf-8")
    git(work, "add", "lock")
    git(work, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-m", "base")
    git(work, "push", "origin", "HEAD:release-1.2")
    (work / "lock").write_text("new", encoding="utf-8")
    (work / "scratch").write_text("never committed", encoding="utf-8")
    return work


def test_pushes_the_fix_branch_with_only_the_applied_files(
    clone: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[Any, ...]] = []

    def opened(*args: Any) -> dict[str, Any]:
        calls.append(args)
        return {"head": args[2], "action": "created", "url": "u"}

    monkeypatch.setattr(publish_module, "open_pull_request", opened)
    result = publish(clone, "o/r", "release-1.2", ["lock"], "title", clone / "b", "")
    assert result["action"] == "created"
    assert calls[0][:3] == ("o/r", "release-1.2", "sca-fix/release-1.2")
    files = git(clone, "ls-tree", "-r", "--name-only", "origin/sca-fix/release-1.2")
    assert files == "lock"
    assert git(clone, "show", "origin/sca-fix/release-1.2:lock") == "new"
    assert (
        git(clone, "log", "-1", "--format=%s", "origin/sca-fix/release-1.2") == "title"
    )


def test_a_pull_request_failure_keeps_the_pushed_branch(
    clone: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refused(*args: Any) -> dict[str, Any]:
        raise PublishError("not permitted")

    monkeypatch.setattr(publish_module, "open_pull_request", refused)
    result = publish(clone, "o/r", "release-1.2", ["lock"], "title", clone / "b", "")
    assert result == {
        "head": "sca-fix/release-1.2",
        "action": "failed",
        "reason": "not permitted",
    }
    assert git(clone, "ls-remote", "--heads", "origin", "sca-fix/release-1.2")


APP = ("sca-app[bot]", "7+sca-app[bot]@users.noreply.github.com")
FIX = "sca-fix/release-1.2"


@pytest.fixture
def opened(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake(repo: str, branch: str, head: str, *rest: Any) -> dict[str, Any]:
        return {"head": head, "action": "updated", "url": "u"}

    monkeypatch.setattr(publish_module, "open_pull_request", fake)
    monkeypatch.setattr(publish_module, "closed_unmerged", lambda *args: False)


def run_fixer(work: Path, content: str = "new", who: tuple[str, str] = APP) -> Any:
    """One fixer run: a fresh checkout of the release branch with ``lock`` changed."""
    git(work, "checkout", "-f", "-q", "release-1.2")
    (work / "lock").write_text(content, encoding="utf-8")
    return publish(work, "o/r", "release-1.2", ["lock"], "t", work / "b", "", *who)


def remote_sha(work: Path) -> str:
    return git(work, "ls-remote", "--heads", "origin", FIX).split()[0]


def other_clone(work: Path) -> Path:
    other = work.parent / "other"
    git(work.parent, "clone", "-q", str(work.parent / "remote.git"), str(other))
    return other


def commit_as(repo: Path, email: str, text: str) -> None:
    (repo / "lock").write_text(text, encoding="utf-8")
    git(repo, "-c", "user.name=x", "-c", f"user.email={email}", "commit", "-qam", text)


def test_n7_2_identity_is_author_and_committer(clone: Path, opened: None) -> None:
    run_fixer(clone)
    assert git(clone, "log", "-1", "--format=%an %ae|%cn %ce", f"origin/{FIX}") == (
        f"{APP[0]} {APP[1]}|{APP[0]} {APP[1]}"
    )


def test_n7_2_changed_tree_of_an_owned_branch_is_pushed(
    clone: Path, opened: None
) -> None:
    run_fixer(clone, "new")
    first = remote_sha(clone)
    result = run_fixer(clone, "newer")
    assert remote_sha(clone) != first
    assert git(clone, "show", f"origin/{FIX}:lock") == "newer"
    assert "reason_code" not in result


def test_n7_2_same_tree_on_the_same_base_is_not_pushed(
    clone: Path, opened: None
) -> None:
    run_fixer(clone)
    first = remote_sha(clone)
    result = run_fixer(clone)
    assert remote_sha(clone) == first
    assert result == {
        "head": FIX,
        "action": "updated",
        "url": "u",
        "reason_code": "unchanged",
    }


def test_n7_2_the_workflow_bot_counts_as_a_fixer(clone: Path, opened: None) -> None:
    run_fixer(clone, who=(publish_module.BOT_NAME, publish_module.BOT_EMAIL))
    first = remote_sha(clone)
    assert run_fixer(clone)["reason_code"] == "unchanged"
    assert remote_sha(clone) == first


def test_n7_2_commit_of_a_human_on_top_stops_the_push(
    clone: Path, opened: None
) -> None:
    run_fixer(clone, "new")
    other = other_clone(clone)
    git(other, "checkout", "-q", FIX)
    commit_as(other, "dev@x", "hand")
    git(other, "push", "-q", "origin", FIX)
    before = remote_sha(clone)
    result = run_fixer(clone, "newer")
    assert remote_sha(clone) == before
    assert result["action"] == "none"
    assert result["reason_code"] == "branch_has_manual_changes"


def test_n7_2_commit_of_a_human_below_a_fixer_commit_stops_the_push(
    clone: Path, opened: None
) -> None:
    other = other_clone(clone)
    git(other, "checkout", "-q", "-b", FIX)
    commit_as(other, "dev@x", "hand")
    commit_as(other, APP[1], "fixer")
    git(other, "push", "-q", "origin", FIX)
    before = remote_sha(clone)
    result = run_fixer(clone)
    assert remote_sha(clone) == before
    assert result["reason_code"] == "branch_has_manual_changes"


def test_n7_2_a_moved_release_branch_gets_a_new_commit(
    clone: Path, opened: None
) -> None:
    run_fixer(clone)
    first = remote_sha(clone)
    other = other_clone(clone)
    (other / "more").write_text("x", encoding="utf-8")
    git(other, "add", "more")
    git(other, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "moved")
    git(other, "push", "-q", "origin", "HEAD:release-1.2")
    git(clone, "fetch", "-q", "origin")
    git(clone, "checkout", "-f", "-q", "-B", "release-1.2", "origin/release-1.2")
    (clone / "lock").write_text("new", encoding="utf-8")
    result = publish(clone, "o/r", "release-1.2", ["lock"], "t", clone / "b", "", *APP)
    assert remote_sha(clone) != first
    assert "reason_code" not in result
    assert git(clone, "rev-parse", f"origin/{FIX}^") == git(
        clone, "rev-parse", "origin/release-1.2"
    )


def test_n7_2_a_shallow_checkout_is_told_from_the_history(
    clone: Path, tmp_path: Path, opened: None
) -> None:
    run_fixer(clone)
    shallow = tmp_path / "shallow"
    git(tmp_path, "clone", "-q", "--depth", "1", "-b", "release-1.2",
        (tmp_path / "remote.git").as_uri(), str(shallow))
    (shallow / "lock").write_text("new", encoding="utf-8")
    before = remote_sha(clone)
    result = publish(shallow, "o/r", "release-1.2", ["lock"], "t", shallow / "b", "", *APP)
    assert remote_sha(clone) == before
    assert result["reason_code"] == "unchanged"


def test_baseline_ci_reports_a_failing_commit_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []

    def gh(cmd: list[str], cwd: Path | None = None, token: str = "") -> str:
        calls.append(cmd)
        return "ci/build, ci/lint" if "status" in cmd[2] else "success"

    monkeypatch.setattr(publish_module, "run", gh)
    assert (
        baseline_ci("o/r", "w/release-1.2", "t")
        == "failure (commit status: ci/build, ci/lint)"
    )
    assert calls[0][2] == "repos/o/r/commits/w/release-1.2/status"


def test_baseline_ci_falls_back_to_the_latest_workflow_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def gh(cmd: list[str], cwd: Path | None = None, token: str = "") -> str:
        return "" if "status" in cmd[2] else "cancelled"

    monkeypatch.setattr(publish_module, "run", gh)
    assert baseline_ci("o/r", "b", "t") == "cancelled"

    def refused(cmd: list[str], cwd: Path | None = None, token: str = "") -> str:
        raise PublishError("403")

    monkeypatch.setattr(publish_module, "run", refused)
    assert baseline_ci("o/r", "b", "t") == "unknown"


def test_n7_2_2_a_commit_of_a_human_on_a_fixer_authored_commit_is_not_owned(
    clone: Path, opened: None
) -> None:
    # `git commit --amend` by a human keeps the author: the committer tells
    run_fixer(clone, "new")
    other = other_clone(clone)
    git(other, "checkout", "-q", FIX)
    (other / "lock").write_text("amended", encoding="utf-8")
    git(
        other,
        "-c",
        "user.name=dev",
        "-c",
        "user.email=dev@x",
        "commit",
        "-qa",
        "--amend",
        "--no-edit",
        f"--author={APP[0]} <{APP[1]}>",
    )
    git(other, "push", "-q", "--force", "origin", FIX)
    before = remote_sha(clone)
    result = run_fixer(clone, "newer")
    assert remote_sha(clone) == before
    assert result["reason_code"] == "branch_has_manual_changes"


def test_n7_2_3_a_branch_of_another_token_kind_is_not_owned(
    clone: Path, opened: None
) -> None:
    run_fixer(clone, "new", who=("octo", "1+octo@users.noreply.github.com"))
    before = remote_sha(clone)
    result = run_fixer(clone, "newer", who=APP)
    assert remote_sha(clone) == before
    assert result["reason_code"] == "branch_has_manual_changes"


def test_n7_3_a_closed_pull_request_with_the_same_tree_is_not_reopened(
    clone: Path, opened: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_fixer(clone, "new")
    first = remote_sha(clone)
    monkeypatch.setattr(publish_module, "closed_unmerged", lambda *args: True)
    created: list[Any] = []
    monkeypatch.setattr(
        publish_module, "open_pull_request", lambda *args: created.append(args)
    )
    result = run_fixer(clone, "new")
    assert remote_sha(clone) == first
    assert created == []
    assert result["action"] == "none"
    assert result["reason_code"] == "closed_unchanged"


def test_n7_3_a_closed_pull_request_with_a_different_tree_gets_a_new_one(
    clone: Path, opened: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_fixer(clone, "new")
    first = remote_sha(clone)
    monkeypatch.setattr(publish_module, "closed_unmerged", lambda *args: True)
    result = run_fixer(clone, "newer")
    assert remote_sha(clone) != first
    assert result["action"] == "updated"
    assert "reason_code" not in result


def test_n7_3_closed_unmerged_reads_the_newest_pull_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    answers = iter(['[{"state": "CLOSED"}]', '[{"state": "MERGED"}]', "[]"])
    seen: list[list[str]] = []

    def gh(cmd: list[str], cwd: Path | None = None, token: str = "") -> str:
        seen.append(cmd)
        return next(answers)

    monkeypatch.setattr(publish_module, "run", gh)
    assert publish_module.closed_unmerged("o/r", "b", "h", "t") is True
    assert publish_module.closed_unmerged("o/r", "b", "h", "t") is False
    assert publish_module.closed_unmerged("o/r", "b", "h", "t") is False
    assert "--limit" in seen[0] and "all" in seen[0]
