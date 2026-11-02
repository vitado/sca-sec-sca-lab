"""Each real-report case (see ``cases.py``) against the expected outcome of the
human-fixed packages. Other items of a plan are allowed.
"""

import json
from pathlib import Path
from typing import Any

import fix_plan
import pytest
from cases import CASES, load_case

DEV = "development runs "
SAME_MAJOR = "lowest fixed version in the same major"
BUMP = "base image bump, verified by rescan"

# case -> package -> (targets, method, fallback, evidence or reason fragment)
PLANNED: dict[
    str, dict[str, tuple[list[tuple[str, str | None]], str, str | None, str]]
] = {
    "c1": {
        "@hono/node-server": ([("2.0.12", "2.1.5")], "dependabot", "npm-override", DEV)
    },
    "c2": {
        "glob": (
            [("10.5.0", "14.0.3"), ("13.0.6", "14.0.3")],
            "dependabot",
            "npm-override",
            DEV,
        )
    },
    "c3": {
        "@hono/node-server": ([("2.0.12", "2.1.5")], "dependabot", "npm-override", DEV),
        "glob": (
            [("10.5.0", "14.0.3"), ("13.0.6", "14.0.3")],
            "dependabot",
            "npm-override",
            DEV,
        ),
    },
    "c4": {
        "io.opentelemetry:opentelemetry-api": (
            [("1.62.0", "1.67.0")],
            "dependabot",
            "manual",
            DEV,
        ),
        "brotli-libs": ([("1.2.0-r1", None)], "docker-tag", "manual", BUMP),
    },
    "c5": {
        "filelock": ([("3.32.7", "4.2.4")], "dependabot", "manual", DEV),
        "virtualenv": ([("21.14.12", "21.14.13")], "dependabot", "manual", DEV),
    },
    "c6": {
        "org.bouncycastle:bcprov-jdk18on": (
            [("1.84", "1.85")],
            "dependabot",
            "manual",
            SAME_MAJOR,
        )
    },
    "c7": {
        "org.bouncycastle:bcprov-jdk18on": (
            [("1.84", "1.85")],
            "dependabot",
            "manual",
            SAME_MAJOR,
        ),
        "org.bouncycastle:bcpkix-jdk18on": (
            [("1.79", "1.84")],
            "dependabot",
            "manual",
            SAME_MAJOR,
        ),
    },
    "c8": {
        "libcrypto3": ([("3.5.7-r0", None)], "docker-tag", "manual", BUMP),
        "libssl3": ([("3.5.7-r0", None)], "docker-tag", "manual", BUMP),
    },
    "c9a": {},
    "c9b": {},
    "c10": {
        "dompurify": ([("3.4.16", "3.4.17")], "dependabot", "npm-override", DEV),
        "next": ([("15.5.27", "15.5.28")], "dependabot", "npm-override", DEV),
    },
    "c11": {
        "brotli-libs": ([("1.2.0-r1", None)], "docker-tag", "manual", BUMP),
        "curl": ([("8.22.0-r0", None)], "docker-tag", "manual", BUMP),
        "libcurl": ([("8.22.0-r0", None)], "docker-tag", "manual", BUMP),
        # the spec expects "skipped: not fixed in development"; development is clean
        # of the records of the case (its libexpat findings are other, UNKNOWN ones)
        "libexpat": ([("2.8.5-r0", None)], "docker-tag", "manual", BUMP),
    },
    "c12": {
        "cryptography": ([("48.0.1", "50.0.0")], "dependabot", "manual", DEV),
    },
}

MANUAL: dict[str, dict[str, str]] = {
    "c9a": {"filelock": "fix needs another major (4.2.1), no development evidence"},
    "c9b": {"filelock": "fix needs another major (4.2.1), no development evidence"},
    "c12": {"pip": "only in the image, not in a manifest"},
}

SKIPPED: dict[str, dict[str, str]] = {
    "c2": {"minimatch": "not fixed in development"},
    "c12": {"setuptools": "not fixed in development"},
}


def run(case: str, tmp_path: Path) -> dict[str, Any]:
    reports = [str(p) for p in load_case(case)]
    assert fix_plan.main(["--reports", *reports, "--output-dir", str(tmp_path)]) == 0
    return json.loads((tmp_path / "fix-plan.json").read_text(encoding="utf-8"))


def lookup(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {i["pkg"]: i for line in result["lines"] for i in line["items"]}


def skipped(result: dict[str, Any]) -> dict[str, str]:
    return {s["pkg"]: s["reason"] for line in result["lines"] for s in line["skipped"]}


@pytest.mark.parametrize("case", CASES)
def test_case(case: str, tmp_path: Path) -> None:
    result = run(case, tmp_path)
    by_pkg = lookup(result)
    for pkg, (targets, method, fallback, evidence) in PLANNED[case].items():
        item = by_pkg[pkg]
        assert [(t["installed"], t["target"]) for t in item["targets"]] == targets, pkg
        assert (item["method"], item["fallback"]) == (method, fallback), pkg
        assert all(evidence in t["evidence"] for t in item["targets"]), pkg
    for pkg, reason in MANUAL.get(case, {}).items():
        assert by_pkg[pkg]["method"] == "manual", pkg
        assert reason in by_pkg[pkg]["reason"], pkg
    for pkg, reason in SKIPPED.get(case, {}).items():
        assert skipped(result)[pkg] == reason, pkg
        assert pkg not in by_pkg, pkg


def test_c5_setuptools_is_not_image_only() -> None:
    """The spec expects setuptools of C5 as image-only; it is also in poetry.lock and
    only LOW, so the severity filter drops it.
    """
    result = json.loads(load_case("c5")[0].read_text(encoding="utf-8"))
    records = [
        r for v in result["versions"] for r in v["vulns"] if r["pkg"] == "setuptools"
    ]
    assert records
    assert {r["severity"] for r in records} == {"LOW"}
    assert "poetry.lock" in records[0]["locations"]
