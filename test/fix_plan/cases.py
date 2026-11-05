#!/usr/bin/env python3
"""The real-report cases of the fix planner: cut the fixtures, run the full reports.

The cases are the 13 test-bed pairs of the W4 delivery plan: a report of one
vulnerable release (``c<N>/report.json``) and the full-set report of the same repo
(``dev-<repo>/report.json``), of which only the ``development`` version is used (its
release versions would add lines and, for C3, repeat a ref).

  cases.py cut  <testbed-dir>               write fixtures/<case>/ from the reports
  cases.py plan <testbed-dir> <output-dir>  plan every case from the uncut reports

A fixture keeps, per case, only the records, packages and targets of the case
packages, so it stays a few KB. The tests read the fixtures with ``load_case``.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"

# case -> (report directory, repo of the development report, packages to keep)
CASES: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "c1": ("c1", "ai-dial-chat", ("@hono/node-server",)),
    "c2": ("c2", "ai-dial-chat", ("glob", "minimatch")),
    "c3": ("c3", "ai-dial-chat", ("@hono/node-server", "glob")),
    "c4": ("c4", "ai-dial-core", ("io.opentelemetry:opentelemetry-api", "brotli-libs")),
    "c5": ("c5", "ai-dial-adapter-openai", ("filelock", "virtualenv", "setuptools")),
    "c6": ("c6", "ai-dial-admin-backend", ("org.bouncycastle:bcprov-jdk18on",)),
    "c7": (
        "c7",
        "ai-dial-admin-deployment-manager-backend",
        ("org.bouncycastle:bcprov-jdk18on", "org.bouncycastle:bcpkix-jdk18on"),
    ),
    "c8": (
        "c8",
        "ai-dial-admin-deployment-manager-backend",
        ("libcrypto3", "libssl3"),
    ),
    "c9a": ("c9a", "ai-dial-mind-map-backend", ("filelock",)),
    "c9b": ("c9b", "ai-dial-mind-map-backend", ("filelock",)),
    "c10": ("c10", "ai-dial-admin-frontend", ("dompurify", "next")),
    "c11": (
        "c11",
        "ai-dial-chat-themes",
        ("brotli-libs", "curl", "libcurl", "libexpat"),
    ),
    "c12": ("c12", "ai-dial-rag", ("cryptography", "setuptools", "pip")),
}


def norm(pkg: str) -> str:
    return re.sub(r"[-_.]+", "-", pkg.lower())


def development_only(report: dict[str, Any]) -> dict[str, Any]:
    """The report with the development version alone and its own targets."""
    versions = [v for v in report["versions"] if v["kind"] == "development"]
    ids = {i for v in versions for i in v["targets"]}
    return {
        **report,
        "versions": versions,
        "targets": [t for t in report["targets"] if t["id"] in ids],
    }


def cut(report: dict[str, Any], packages: tuple[str, ...]) -> dict[str, Any]:
    """Keep the header, the targets and, per version, the records and packages of
    ``packages``; the findings and the tool data are not needed.
    """
    keep = {norm(p) for p in packages}
    versions = [
        {
            **v,
            "vulns": [x for x in v["vulns"] if norm(x["pkg"]) in keep],
            "packages": [x for x in v["packages"] if norm(x["pkg"]) in keep],
        }
        for v in report["versions"]
    ]
    header = ("schema_version", "repo", "run_id", "run_url", "targets")
    return {**{k: report[k] for k in header}, "versions": versions}


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=1, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def source_paths(testbed: Path, case: str) -> tuple[Path, Path]:
    directory, repo, _ = CASES[case]
    return testbed / directory / "report.json", testbed / f"dev-{repo}" / "report.json"


def load_case(case: str) -> list[Path]:
    """The fixture reports of a case, release report first."""
    return [FIXTURES / case / "report.json", FIXTURES / case / "dev.json"]


def cut_all(testbed: Path) -> None:
    for case, (_, _, packages) in CASES.items():
        report_path, dev_path = source_paths(testbed, case)
        write(FIXTURES / case / "report.json", cut(load(report_path), packages))
        write(
            FIXTURES / case / "dev.json",
            cut(development_only(load(dev_path)), packages),
        )


def plan_all(testbed: Path, output: Path) -> None:
    from sca_fix_plan import cli as fix_plan

    for case in CASES:
        report_path, dev_path = source_paths(testbed, case)
        dev_only = output / "_input" / f"{case}-dev.json"
        write(dev_only, development_only(load(dev_path)))
        code = fix_plan.main(
            [
                "--reports",
                str(report_path),
                str(dev_only),
                "--output-dir",
                str(output / case),
            ]
        )
        if code:
            raise SystemExit(f"{case}: the planner failed")


if __name__ == "__main__":
    sys.path.insert(0, str(HERE.parents[1] / "actions" / "sca_fix_plan"))
    if len(sys.argv) == 3 and sys.argv[1] == "cut":
        cut_all(Path(sys.argv[2]))
    elif len(sys.argv) == 4 and sys.argv[1] == "plan":
        plan_all(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        raise SystemExit(__doc__)
