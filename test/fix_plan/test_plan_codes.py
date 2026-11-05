"""Reason codes and the schema 2 additions of the fix plan (N9.2, N10.1)."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import plan_codes
import pytest
from cases import CASES
from config import Config, parse_config
from helpers import DEV_SOURCE, development, plan, record, report, target, version
from plan import build_plan
from reports import merge_reports
from test_plan_cases import OPT_IN, run

# N9.2: the codes of the plan side, copied from the spec
N9_2_PLAN_CODES = {
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
}
# the codes of the ignored and skipped refs, N10.1
N10_1_REF_CODES = {"ref_not_semver", "same_ref_same_commit", "line_in_earlier_report"}

DEV_IMAGE = "image-app-development"


def release(*vulns: dict[str, Any], **fields: Any) -> dict[str, Any]:
    return version("1.2.3", vulns=list(vulns), **fields)


def only(result: dict[str, Any], pkg: str = "lib") -> dict[str, Any]:
    return {i["pkg"]: i for i in result["lines"][0]["items"]}[pkg]


def emitted(result: dict[str, Any]) -> set[str]:
    """Every reason code a plan carries, drop keys included."""
    codes: set[str] = set()
    for line in result["lines"]:
        codes |= {i["reason_code"] for i in line["items"]}
        codes |= {s["reason_code"] for s in line["skipped"]}
        codes |= {k for k, n in line["dropped"].items() if n}
    codes |= {r["reason_code"] for r in result.get("skipped_refs", [])}
    for source in result["reports"]:
        codes |= {r["reason_code"] for r in source.get("ignored_refs", [])}
    codes.discard(None)
    return codes


def os_release() -> dict[str, Any]:
    rec = record(
        "zlib",
        "1.3.2-r0",
        "1.3.2-r1",
        ecosystem="Alpine:v3.24",
        where=["image-app-1.2.3"],
        **{"class": "os"},
    )
    return release(
        rec, targets=[target("image-app-1.2.3", "image", "app", packages=50)]
    )


def os_dev() -> dict[str, Any]:
    return development(targets=[target(DEV_IMAGE, "image", "app")])


def test_n9_2_plan_table_is_in_the_spec_list() -> None:
    assert plan_codes.CODES == N9_2_PLAN_CODES | N10_1_REF_CODES


def test_n10_1_schema_version_is_2() -> None:
    assert plan(development(), release())["schema_version"] == 2


def test_n10_1_vulns_carry_sorted_aliases() -> None:
    rec = record("lib", "1.0.0", "1.0.5", aliases=["GHSA-b", "CVE-1", "GHSA-a"])
    bare = record("other", "1.0.0", "1.0.5")
    result = plan(development(), release(rec, bare))
    assert only(result)["vulns"][0]["aliases"] == ["CVE-1", "GHSA-a", "GHSA-b"]
    assert only(result, "other")["vulns"][0]["aliases"] == []


def test_n9_2_skips_carry_codes() -> None:
    accepted = record("a", "1.0.0", "1.0.5", accepted={"until": "2027-01-01"})
    present = record("b", "1.0.0", "1.0.5", id="CVE-b")
    still = record("b", "1.0.5", "", id="CVE-b")
    names = {s["pkg"]: s["reason_code"] for s in skips(plan(
        development(vulns=[still]), release(accepted, present)
    ))}
    assert names == {"a": "accepted", "b": "not_fixed_in_development"}
    gap = plan(
        development(targets=[target(DEV_SOURCE, packages=0)]),
        release(record("lib", "1.0.0", "1.0.5")),
    )
    assert skips(gap)[0]["reason_code"] == "development_data_incomplete"


def skips(result: dict[str, Any]) -> list[dict[str, Any]]:
    return result["lines"][0]["skipped"]


def test_n9_2_drops_are_counted_under_their_code() -> None:
    low = record("low", "1.0.0", "1.0.5", severity="LOW")
    unfixed = record("unfixed", "1.0.0", "")
    dev_only = record("devonly", "1.0.0", "1.0.5", dev=True)
    result = plan(
        development(),
        release(low, unfixed, dev_only),
        config=parse_config('{"include-dev": false}'),
    )
    assert result["lines"][0]["dropped"] == {"severity": 1, "unfixable": 1, "dev": 1}


@pytest.mark.parametrize(
    ("fixed", "installed", "code"),
    [
        ("", "1.0.0", "no_fixed_version"),
        ("2.0.0", "1.0.0", "needs_major"),
        ("1.0.5", "1.0-3ubuntu1", "version_unparsable"),
        ("1.0.5", [], "version_unparsable"),
    ],
)
def test_n9_2_target_failures(fixed: str, installed: Any, code: str) -> None:
    rec = record("lib", installed, fixed)
    result = plan(development(), release(rec), config=parse_config('{"fixable-only": false}'))
    item = only(result)
    assert (item["method"], item["reason_code"]) == ("manual", code)
    assert item["reason"]


def test_n9_2_method_failures() -> None:
    go = record("lib", "1.0.0", "1.0.5", ecosystem="Go")
    assert only(plan(development(), release(go)))["reason_code"] == "ecosystem_unsupported"
    off = parse_config('{"methods": ["docker-tag"]}')
    npm = record("lib", "1.0.0", "1.0.5")
    assert only(plan(development(), release(npm), config=off))["reason_code"] == (
        "method_disabled"
    )
    in_image = record("lib", "1.0.0", "1.0.5", where=["image-app-1.2.3"])
    rel = release(
        in_image,
        targets=[target("image-app-1.2.3", "image", "app"), target("source-1.2.3")],
    )
    assert only(plan(development(), rel))["reason_code"] == "only_in_image"
    assert only(plan(os_dev(), os_release()), "zlib")["reason_code"] == (
        "needs_image_rebuild"
    )


def test_n9_2_planned_item_has_no_code() -> None:
    item = only(plan(development(), release(record("lib", "1.0.0", "1.0.5"))))
    assert (item["method"], item["reason"], item["reason_code"]) == (
        "dependabot",
        None,
        None,
    )
    docker = parse_config('{"methods": ["docker-tag"]}')
    assert only(plan(os_dev(), os_release(), config=docker), "zlib")["reason_code"] is None


def test_n10_1_ref_codes() -> None:
    result = plan(development(), version("1.2.3"), version("nightly"))
    assert result["skipped_refs"][0]["reason_code"] == "ref_not_semver"


def test_n9_2_emitted_codes_are_in_the_spec_list(tmp_path: Path) -> None:
    results = [run(case, tmp_path / case, OPT_IN) for case in CASES]
    dev = development(targets=[target(DEV_SOURCE, commit_sha="d")])
    rel = release(targets=[target("source-1.2.3", commit_sha="r")])
    first = report(dev, rel, run_id="1")
    second = report(dev, version("1.2.9"), run_id="2")
    merged = merge_reports([first, second])
    results.append(build_plan(merged, Config()))
    results.append(plan(development(), version("1.2.3"), version("nightly")))
    results.append(plan(os_dev(), os_release()))
    seen = set().union(*(emitted(r) for r in results))
    assert seen
    assert seen <= N9_2_PLAN_CODES | N10_1_REF_CODES
    # the synthetic reports above reach the three ref codes
    assert N10_1_REF_CODES <= seen


def test_n9_2_codes_are_spelled_only_in_the_table() -> None:
    """No other module of the planner has a string literal that is a code (the
    words of the report schema that are also drop keys are not codes there).
    """
    shared = {"accepted", "severity", "dev", "unfixable"}
    for path in Path(plan_codes.__file__).parent.glob("*.py"):
        if path.name == "plan_codes.py":
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                assert node.value in shared or node.value not in plan_codes.CODES, (
                    path.name,
                    node.value,
                )
