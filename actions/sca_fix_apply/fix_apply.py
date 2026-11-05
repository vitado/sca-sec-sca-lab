#!/usr/bin/env python3
"""Apply the planned fixes of a release line and deliver them as one pull request.

  apply    run the automated items of one plan line on a checked-out tree (Dependabot
           jobs, base image bump), rescan, and write ``result.json`` and
           ``pr-body.md``
  publish  commit the applied files, force-push ``sca-fix/<branch>`` and open or
           update the pull request (nothing when nothing was applied or on a dry run)
  node     the node version of the branch (workflow output ``version`` and ``source``,
           empty when none is found)
  summary  the job summary of all lines of a plan from the result files

Standard library only; it reads the plan of ``sca_fix_plan`` as JSON and shares no
code with it. Tools it calls: the Dependabot CLI, ``yq``, Trivy, Docker, ``git``
and ``gh``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from functools import partial
from pathlib import Path
from typing import Any

import apply_codes as codes
from apply import Tools, dockerfiles, process_line
from dependabot import JobError, Outcome, Settings, run_job
from override import detect_node, npm_install, npm_ls, npm_version
from publish import PublishError, baseline_ci, publish
from scan import ScanError, scan_image, scan_tree
from texts import pr_body, summary


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    text = json.dumps(data, indent=1, sort_keys=True, ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8", newline="\n")


PLAN_SCHEMA_VERSION = 2  # the fix-plan schema this applier reads
RESULT_SCHEMA_VERSION = 1  # the result.json schema it writes


def read_plan(path: Path) -> dict[str, Any]:
    """The plan of ``path``; any schema version but the one this applier reads ends
    the run.
    """
    plan = read_json(path)
    found = plan.get("schema_version")
    if found != PLAN_SCHEMA_VERSION:
        raise SystemExit(
            f"error: fix-plan schema_version {found} is not supported, "
            f"{PLAN_SCHEMA_VERSION} is expected"
        )
    return plan


def plan_line(plan: dict[str, Any], branch: str) -> dict[str, Any]:
    for line in plan["lines"]:
        if line["branch"] == branch:
            return dict(line)
    raise SystemExit(f"error: the plan has no line with branch {branch}")


def cmd_apply(args: argparse.Namespace) -> int:
    plan = read_plan(args.plan)
    line = plan_line(plan, args.branch)
    token = os.environ.get("GH_TOKEN", "")
    settings = Settings(
        args.dependabot,
        json.loads(args.updater_images),
        args.proxy_image,
        token,
        round(args.dependabot_timeout_minutes * 60),
    )
    tree = args.tree.resolve()

    def dependabot(job: Any, manager: str) -> Outcome:
        return run_job(job, tree, settings, manager)

    tools = Tools(
        dependabot=dependabot,
        scan_tree=partial(scan_tree, tree, args.lockfile_command),
        scan_image=partial(scan_image, build_args=args.docker_build_arg),
        npm_install=partial(npm_install, tree),
        npm_ls=partial(npm_ls, tree),
        npm_version=npm_version,
    )
    try:
        result = process_line(line, args.repo, tree, tools)
    except (ScanError, JobError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    result["baseline_ci"] = baseline_ci(args.repo, args.branch, token)
    result.update(
        schema_version=RESULT_SCHEMA_VERSION,
        repo=args.repo,
        run_id=os.environ.get("GITHUB_RUN_ID") or None,
        report_run_ids=[r["run_id"] for r in plan["reports"]],
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_json(args.output_dir / "result.json", result)
    body = pr_body(line, result, result["baseline_ci"])
    (args.output_dir / "pr-body.md").write_text(body, encoding="utf-8", newline="\n")
    return 0


def cmd_publish(args: argparse.Namespace) -> int:
    result = read_json(args.output_dir / "result.json")
    result["token_kind"] = args.token_kind
    if not result["files"]:
        result["pr"] = {
            "action": "none",
            "reason": "nothing applied",
            "reason_code": codes.NOTHING_APPLIED,
        }
    elif args.dry_run:
        result["pr"] = {
            "action": "none",
            "reason": "dry run",
            "reason_code": codes.DRY_RUN,
        }
    else:
        try:
            result["pr"] = {
                "reason_code": None,
                **publish(
                    args.tree.resolve(),
                    args.repo,
                    args.branch,
                    result["files"],
                    f"fix(deps): security fixes for {args.branch}",
                    args.output_dir / "pr-body.md",
                    os.environ.get("GH_TOKEN", ""),
                ),
            }
        except PublishError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
    write_json(args.output_dir / "result.json", result)
    print(json.dumps(result["pr"]))
    return 1 if result["pr"]["action"] == "failed" else 0


def cmd_node(args: argparse.Namespace) -> int:
    tree = args.tree.resolve()
    found = (
        detect_node(tree, dockerfiles(tree))
        if (tree / "package.json").is_file()
        else None
    )
    version, source = found or ("", "")
    print(f"node version: {version or 'not found'} ({source})")
    target = os.environ.get("GITHUB_OUTPUT")
    if target:
        with open(target, "a", encoding="utf-8", newline="\n") as f:
            f.write(f"version={version}\nsource={source}\n")
    return 0


def cmd_summary(args: argparse.Namespace) -> int:
    plan = read_plan(args.plan)
    results = {}
    for path in sorted(args.results_dir.rglob("result.json")):
        data = read_json(path)
        results[data["branch"]] = data
    text = summary(plan, results)
    print(text)
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    if target:
        with open(target, "a", encoding="utf-8", newline="\n") as f:
            f.write(text + "\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    plan = argparse.ArgumentParser(add_help=False)
    plan.add_argument("--plan", required=True, type=Path)
    line = argparse.ArgumentParser(add_help=False)
    line.add_argument("--branch", required=True)
    line.add_argument("--tree", required=True, type=Path)
    line.add_argument("--repo", required=True)
    line.add_argument("--output-dir", required=True, type=Path)
    apply_parser = sub.add_parser("apply", parents=[plan, line])
    apply_parser.add_argument("--dependabot", required=True, help="the Dependabot CLI")
    apply_parser.add_argument(
        "--updater-images", required=True, help="JSON: package manager -> updater image"
    )
    apply_parser.add_argument("--proxy-image", required=True)
    apply_parser.add_argument(
        "--lockfile-command",
        default="",
        help="shell command that writes the Gradle lockfiles into the tree it runs in",
    )
    apply_parser.add_argument("--docker-build-arg", action="append", default=[])
    apply_parser.add_argument(
        "--dependabot-timeout-minutes",
        type=float,
        default=8,
        help="time limit of one Dependabot job; a timeout counts as 'cannot'",
    )
    apply_parser.set_defaults(handler=cmd_apply)
    publish_parser = sub.add_parser("publish", parents=[plan, line])
    publish_parser.add_argument("--dry-run", action="store_true")
    publish_parser.add_argument(
        "--token-kind",
        choices=("workflow", "token", "app"),
        default="workflow",
        help="which token opens the pull request, as the summary tells it",
    )
    publish_parser.set_defaults(handler=cmd_publish)
    node_parser = sub.add_parser("node")
    node_parser.add_argument("--tree", required=True, type=Path)
    node_parser.set_defaults(handler=cmd_node)
    summary_parser = sub.add_parser("summary", parents=[plan])
    summary_parser.add_argument("--results-dir", required=True, type=Path)
    summary_parser.set_defaults(handler=cmd_summary)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    sys.exit(main())
