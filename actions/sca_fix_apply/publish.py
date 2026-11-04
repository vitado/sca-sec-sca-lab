"""Commit the applied files, push the fix branch and open or update the pull request."""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

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


def publish(
    tree: Path,
    repo: str,
    branch: str,
    files: Sequence[str],
    title: str,
    body_file: Path,
    token: str,
) -> dict[str, Any]:
    """Force-push ``sca-fix/<branch>`` with one commit of ``files`` on the tip of the
    branch and open or update the pull request. The branch stays pushed when the pull
    request cannot be opened (the result says ``failed`` with the reason).
    """
    head = f"sca-fix/{branch}"
    run(["git", "checkout", "-B", head], tree)
    run(["git", "add", "--all", "--", *files], tree)
    run(
        [
            "git",
            "-c",
            f"user.name={BOT_NAME}",
            "-c",
            f"user.email={BOT_EMAIL}",
            "commit",
            "-m",
            title,
        ],
        tree,
    )
    run(["git", "push", "--force", "origin", f"HEAD:refs/heads/{head}"], tree)
    try:
        return open_pull_request(repo, branch, head, title, body_file, token)
    except PublishError as exc:
        return {"head": head, "action": "failed", "reason": str(exc)}


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
