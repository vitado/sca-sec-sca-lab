"""Commit the applied files, push the fix branch and open or update the pull request."""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

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
    """The conclusion of the latest completed workflow run on the branch, or ``none``."""
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
    branch; update the open pull request from it or create one.
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
