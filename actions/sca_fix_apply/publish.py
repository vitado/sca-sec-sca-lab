"""Commit the applied files, push the fix branch and open or update the pull request."""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import apply_codes as codes

FAILING_STATUSES = (
    '[.statuses[] | select(.state == "failure" or .state == "error")'
    ' | .context] | join(", ")'
)
BOT_NAME = "github-actions[bot]"
BOT_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"


class PublishError(RuntimeError):
    pass


def run(cmd: Sequence[str], cwd: Path | None = None, token: str = "") -> str:
    done = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        check=False,
        text=True,
        env={**os.environ, "GH_TOKEN": token} if token else None,
    )
    if done.returncode != 0:
        raise PublishError(
            f"{' '.join(cmd[:3])} failed: {(done.stderr or done.stdout).strip()[-500:]}"
        )
    return done.stdout.strip()


def baseline_ci(repo: str, branch: str, token: str) -> str:
    """The CI state of the untouched branch: the conclusion of its latest completed
    workflow run (``none`` without one), or ``failure`` when a commit status on the tip
    is failing (CI systems that report statuses and not workflow runs).
    """
    try:
        failing = run(
            [
                "gh",
                "api",
                f"repos/{repo}/commits/{branch}/status",
                "--jq",
                FAILING_STATUSES,
            ],
            token=token,
        )
    except PublishError:
        failing = ""
    if failing:
        return f"failure (commit status: {failing})"
    try:
        out = run(
            [
                "gh",
                "api",
                f"repos/{repo}/actions/runs",
                "-X",
                "GET",
                "-f",
                f"branch={branch}",
                "-f",
                "status=completed",
                "-f",
                "per_page=1",
                "--jq",
                '.workflow_runs[0].conclusion // "none"',
            ],
            token=token,
        )
    except PublishError:
        return "unknown"
    return out or "none"


def remote_fix_branch(tree: Path, branch: str, head: str) -> bool:
    """Fetch the release branch and, when it exists, the fix branch into ``origin/<name>``
    (the whole history of a shallow checkout, to tell the commits of the fix branch
    from those of the release branch). True when the fix branch exists.
    """
    exists = bool(run(["git", "ls-remote", "--heads", "origin", head], tree))
    cmd = ["git", "fetch", "--no-tags"]
    if run(["git", "rev-parse", "--is-shallow-repository"], tree) == "true":
        cmd.append("--unshallow")
    refs = [branch, head] if exists else [branch]
    run([*cmd, "origin", *(f"+refs/heads/{r}:refs/remotes/origin/{r}" for r in refs)], tree)
    return exists


def owned(tree: Path, branch: str, head: str, email: str) -> bool:
    """True when every commit of ``origin/<head>`` that is not on ``origin/<branch>`` is
    authored by a fixer identity: the current one or the workflow bot.
    """
    authors = run(
        ["git", "log", "--format=%ae", f"origin/{branch}..origin/{head}"], tree
    ).split()
    return all(a.lower() in {email.lower(), BOT_EMAIL} for a in authors)


def publish(
    tree: Path,
    repo: str,
    branch: str,
    files: Sequence[str],
    title: str,
    body_file: Path,
    token: str,
    name: str = BOT_NAME,
    email: str = BOT_EMAIL,
) -> dict[str, Any]:
    """Force-push ``sca-fix/<branch>`` with one commit of ``files`` on the tip of the
    branch, authored by the fixer identity ``name`` / ``email``, and open or update the
    pull request. Nothing is pushed when the remote fix branch has commits of others
    (``branch_has_manual_changes``, the result has no pull request) or already holds
    the same tree on the same base (``unchanged``, the pull request is still
    updated). The branch stays pushed when the pull request cannot be opened (the
    result says ``failed`` with the reason).
    """
    head = f"sca-fix/{branch}"
    exists = remote_fix_branch(tree, branch, head)
    if exists and not owned(tree, branch, head, email):
        return {
            "action": "none",
            "reason": f"{head} has commits of others, not pushed",
            "reason_code": codes.BRANCH_HAS_MANUAL_CHANGES,
        }
    base = run(["git", "rev-parse", "HEAD"], tree)
    run(["git", "checkout", "-B", head], tree)
    run(["git", "add", "--all", "--", *files], tree)
    unchanged = (
        exists
        and run(["git", "rev-parse", f"origin/{head}^"], tree) == base
        and run(["git", "write-tree"], tree)
        == run(["git", "rev-parse", f"origin/{head}^{{tree}}"], tree)
    )
    if not unchanged:
        run(
            [
                "git",
                "-c",
                f"user.name={name}",
                "-c",
                f"user.email={email}",
                "commit",
                "-m",
                title,
            ],
            tree,
        )
        run(["git", "push", "--force", "origin", f"HEAD:refs/heads/{head}"], tree)
    try:
        pr = open_pull_request(repo, branch, head, title, body_file, token)
    except PublishError as exc:
        return {"head": head, "action": "failed", "reason": str(exc)}
    return {**pr, "reason_code": codes.UNCHANGED} if unchanged else pr


def open_pull_request(
    repo: str, branch: str, head: str, title: str, body_file: Path, token: str
) -> dict[str, Any]:
    """Update the open pull request from ``head`` or create one."""
    found = json.loads(
        run(
            [
                "gh",
                "pr",
                "list",
                "--repo",
                repo,
                "--head",
                head,
                "--base",
                branch,
                "--state",
                "open",
                "--json",
                "number,url",
            ],
            token=token,
        )
    )
    if found:
        number = str(found[0]["number"])
        run(
            [
                "gh",
                "pr",
                "edit",
                number,
                "--repo",
                repo,
                "--title",
                title,
                "--body-file",
                str(body_file),
            ],
            token=token,
        )
        return {"head": head, "action": "updated", "url": found[0]["url"]}
    url = run(
        [
            "gh",
            "pr",
            "create",
            "--repo",
            repo,
            "--base",
            branch,
            "--head",
            head,
            "--title",
            title,
            "--body-file",
            str(body_file),
        ],
        token=token,
    )
    return {"head": head, "action": "created", "url": url.splitlines()[-1]}
