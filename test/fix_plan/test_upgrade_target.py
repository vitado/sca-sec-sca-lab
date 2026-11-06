"""``upgrade_target``: the public wrapper of the planner's target rule."""

import json
from pathlib import Path

import pytest
import sca_fix_plan
from cases import CASES, load_case
from helpers import record
from sca_fix_plan import Config, build_plan, merge_reports, upgrade_target


def test_exported() -> None:
    assert "upgrade_target" in sca_fix_plan.__all__


def test_same_major_preferred() -> None:
    rec = record("lib", "1.0.0", "1.0.5, 2.0.0")
    assert upgrade_target("1.0.0", [rec]) == (
        "1.0.5",
        "lowest fixed version in the same major",
        None,
    )


def test_not_a_downgrade() -> None:
    # the first fixed version of one record is below the installed one
    rec = record("lib", "2.21.7", "2.18.11, 2.21.8")
    target, _, code = upgrade_target("2.21.7", [rec])
    assert (target, code) == ("2.21.8", None)


def test_highest_requirement_over_records() -> None:
    recs = [record("lib", "1.0.0", "1.0.5"), record("lib", "1.0.0", "1.1.2", id="B")]
    assert upgrade_target("1.0.0", recs)[0] == "1.1.2"


def test_development_evidence_preferred() -> None:
    rec = record("lib", "1.0.0", "1.0.5")
    assert upgrade_target("1.0.0", [rec], ["1.0.9"]) == (
        "1.0.9",
        "development runs 1.0.9",
        None,
    )
    assert upgrade_target("1.0.0", [rec], ["1.0.2"])[0] == "1.0.5"


def test_dev_version_of_another_major() -> None:
    rec = record("lib", "1.0.0", "1.0.5, 3.0.0")
    assert upgrade_target("1.0.0", [rec], ["3.0.0"])[0] == "1.0.5"
    assert upgrade_target("1.0.0", [rec], ["3.0.0"], "dev-proven")[0] == "3.0.0"


def test_needs_major() -> None:
    rec = record("lib", "1.0.0", "2.0.0")
    assert upgrade_target("1.0.0", [rec]) == (
        None,
        "fix needs another major (2.0.0), no development evidence",
        "needs_major",
    )


def test_no_fixed_version() -> None:
    assert upgrade_target("1.0.0", [record("lib", "1.0.0", "")]) == (
        None,
        "no fixed version above 1.0.0",
        "no_fixed_version",
    )
    assert upgrade_target("1.0.0", [record("lib", "1.0.0", "0.9.0")])[2] == (
        "no_fixed_version"
    )


def test_unparsable_is_returned_not_raised() -> None:
    rec = record("lib", "1.2-3ubuntu1", "1.2-4ubuntu1")
    target, text, code = upgrade_target("1.2-3ubuntu1", [rec])
    assert target is None
    assert code == "version_unparsable"
    assert text.startswith("cannot compare versions")


def test_unknown_allow_major() -> None:
    with pytest.raises(ValueError):
        upgrade_target("1.0.0", [], allow_major="any")


def test_result_is_json_serialisable() -> None:
    rec = record("lib", "1.0.0", "1.0.5")
    json.dumps(upgrade_target("1.0.0", [rec], ["1.0.9"]))


def compare_with_plan(case: str, allow_major: str) -> int:
    """Check every library target of the plan of a case against ``upgrade_target``
    and return how many were checked.
    """
    docs = [json.loads(Path(p).read_text(encoding="utf-8")) for p in load_case(case)]
    reports = merge_reports(docs)
    plan = build_plan(reports, Config(allow_major=allow_major))
    versions = {v.ref: v for v in reports.versions}
    dev = next(v for v in reports.versions if v.kind == "development")
    compared = 0
    for line in plan["lines"]:
        version = versions[line["ref"]]
        for item in line["items"]:
            if item["class"] == "os" or not item["targets"]:
                continue
            ids = {v["id"] for v in item["vulns"]}
            records = [
                r
                for r in version.vulns
                if r["pkg"] == item["pkg"]
                and r["class"] == item["class"]
                and r["id"] in ids
            ]
            dev_versions = [
                x
                for p in dev.packages
                if p["pkg"] == item["pkg"] and p["class"] == item["class"]
                for x in p["installed"]
            ]
            for entry in item["targets"]:
                target, text, _ = upgrade_target(
                    entry["installed"], records, dev_versions, allow_major
                )
                assert target == entry["target"], (case, item["pkg"])
                if target:
                    assert text == entry["evidence"], (case, item["pkg"])
                compared += 1
    return compared


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("allow_major", ["none", "dev-proven"])
def test_agrees_with_build_plan_on_real_fixtures(case: str, allow_major: str) -> None:
    compare_with_plan(case, allow_major)


def test_real_fixtures_give_targets_to_compare() -> None:
    assert sum(compare_with_plan(c, "dev-proven") for c in CASES) >= 10
