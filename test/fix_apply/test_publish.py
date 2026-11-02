import subprocess
from pathlib import Path
from typing import Any

import publish as publish_module
import pytest
from publish import PublishError, publish


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
