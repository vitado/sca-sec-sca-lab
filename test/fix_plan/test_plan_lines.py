"""Line selection (N4.1), the record filter order (N4.2), fixed in development per
package key (N4.3) and ``classify``.
"""

import json
from typing import Any

import pytest
from cases import CASES, load_case
from helpers import (
    DEV_SOURCE,
    development,
    inventory,
    items,
    plan,
    record,
    report,
    target,
    version,
)
from sca_fix_plan import (
    Config,
    ConfigError,
    build_plan,
    classify,
    merge_reports,
    parse_config,
)
from sca_fix_plan.development import norm


def lines_of(result: dict[str, Any]) -> list[tuple[str, str, str]]:
    return [(x["line"], x["ref"], x["kind"]) for x in result["lines"]]


def stable(ref: str, *vulns: dict[str, Any], **fields: Any) -> dict[str, Any]:
    return version(ref, vulns=list(vulns), **fields)


def candidate(ref: str, *vulns: dict[str, Any]) -> dict[str, Any]:
    return version(ref, "candidate", vulns=list(vulns))


def states(*versions: dict[str, Any]) -> dict[str, str]:
    """The state per record id of the classification of one report."""
    return {e["ids"][0]: e["state"] for e in classify([report(*versions)])}


def test_n4_1_candidate_does_not_displace_stable_line() -> None:
    versions = (
        development(),
        version("1.1.9"),
        version("1.2.5"),
        candidate("1.3.0-rc.1"),
    )
    assert lines_of(plan(*versions, config=parse_config('{"release-lines": 2}'))) == [
        ("1.3", "1.3.0-rc.1", "candidate"),
        ("1.2", "1.2.5", "release"),
        ("1.1", "1.1.9", "release"),
    ]
    off = plan(*versions, config=parse_config('{"include-candidate": false}'))
    assert lines_of(off) == [("1.2", "1.2.5", "release"), ("1.1", "1.1.9", "release")]


def test_n4_1_candidate_does_not_count_toward_release_lines() -> None:
    result = plan(
        development(),
        version("1.1.9"),
        version("1.2.5"),
        candidate("1.3.0-rc.1"),
        config=parse_config('{"release-lines": 1}'),
    )
    assert [x["line"] for x in result["lines"]] == ["1.3", "1.2"]


def test_n4_1_candidate_of_a_stable_line_is_not_planned() -> None:
    result = plan(
        development(),
        version("1.2.5"),
        candidate("1.2.6-rc.1"),
        candidate("1.1.0-rc.1"),
    )
    assert lines_of(result) == [("1.2", "1.2.5", "release")]


def test_n4_1_only_the_newest_candidate_line_is_planned() -> None:
    result = plan(
        development(),
        version("1.2.5"),
        candidate("1.3.0-rc.1"),
        candidate("1.3.0-rc.2"),
        candidate("1.4.0-rc.1"),
    )
    assert lines_of(result) == [
        ("1.4", "1.4.0-rc.1", "candidate"),
        ("1.2", "1.2.5", "release"),
    ]
    same_line = plan(development(), candidate("1.3.0-rc.1"), candidate("1.3.0-rc.2"))
    assert lines_of(same_line) == [("1.3", "1.3.0-rc.2", "candidate")]


def test_n4_1_lines_are_ordered_by_version_not_by_report_order() -> None:
    result = plan(development(), version("1.9.0"), version("1.10.0"), version("1.2.0"))
    assert [x["line"] for x in result["lines"]] == ["1.10", "1.9"]


@pytest.mark.parametrize(
    ("ref", "kind"),
    [
        ("1.2.3-rc.1", "release"),
        ("1.2.3", "candidate"),
        ("1.2", "release"),
        ("nightly", "candidate"),
    ],
)
def test_n4_1_ref_that_does_not_fit_its_kind_is_skipped(ref: str, kind: str) -> None:
    result = plan(development(), version("1.1.0"), version(ref, kind))
    assert result["skipped_refs"] == [
        {
            "ref": ref,
            "reason": "ref is not X.Y.Z or X.Y.Z-suffix",
            "reason_code": "ref_not_semver",
        }
    ]
    assert lines_of(result) == [("1.1", "1.1.0", "release")]


def test_n3_candidate_and_newest_line_use_severities_older_use_previous() -> None:
    low = record("lib", "1.0.0", "1.0.5", id="CVE-LOW", severity="LOW")
    config = parse_config('{"severities": ["LOW"], "severities-previous": ["HIGH"]}')
    result = plan(
        development(),
        stable("1.1.0", low),
        stable("1.2.0", low),
        candidate("1.3.0-rc.1", low),
        config=config,
    )
    assert {x["line"]: len(x["items"]) for x in result["lines"]} == {
        "1.3": 1,
        "1.2": 1,
        "1.1": 0,
    }
    older = plan(development(), stable("1.1.0", low), stable("1.2.0"), config=config)
    assert {x["line"]: len(x["items"]) for x in older["lines"]} == {"1.2": 0, "1.1": 0}
    assert older["lines"][1]["dropped"]["severity"] == 1


def test_n3_include_candidate_is_echoed_and_must_be_a_bool() -> None:
    config = Config(include_candidate=False)
    result = plan(development(), version("1.2.0"), config=config)
    assert result["config"]["include-candidate"] is False
    with pytest.raises(ConfigError, match="include-candidate"):
        parse_config('{"include-candidate": "yes"}')


def test_n4_1_partial_line_is_planned_and_marked() -> None:
    result = plan(development(), version("1.2.0", status="failed"))
    assert result["lines"][0]["partial"] is True


def test_n4_3_fixed_in_one_package_open_in_the_other() -> None:
    cve = {"id": "CVE-1", "names": ["CVE-1"]}
    fixed_pkg = record("lib-a", "1.0.0", "1.0.5", **cve)
    open_pkg = record("lib-b", "1.0.0", "1.0.5", **cve)
    dev = development(
        vulns=[record("lib-b", "1.0.0", "1.0.5", **cve)],
        packages=[inventory("lib-a", ["1.0.5"]), inventory("lib-b", ["1.0.0"])],
    )
    result = plan(dev, stable("1.2.0", fixed_pkg, open_pkg))
    assert list(items(result)) == ["lib-a"]
    assert [(s["pkg"], s["reason_code"]) for s in result["lines"][0]["skipped"]] == [
        ("lib-b", "not_fixed_in_development")
    ]


def test_n4_3_another_package_with_the_same_id_does_not_make_it_open() -> None:
    rec = record("lib", "1.0.0", "1.0.5", id="CVE-1")
    other = record("other", "2.0.0", "", id="CVE-1")
    dev = development(vulns=[other], packages=[inventory("lib", ["1.0.5"])])
    assert list(items(plan(dev, stable("1.2.0", rec)))) == ["lib"]


def test_n4_3_package_key_is_normalized() -> None:
    rec = record("My_Lib", "1.0.0", "1.0.5", id="CVE-1")
    still = record("my.lib", "1.0.0", "1.0.5", id="CVE-1")
    result = plan(development(vulns=[still]), stable("1.2.0", rec))
    assert items(result) == {}
    assert result["lines"][0]["skipped"][0]["reason_code"] == "not_fixed_in_development"


def test_n4_3_alias_only_match_is_open_in_development() -> None:
    plain = record("lib", "1.0.0", "1.0.5", id="GHSA-x", names=["GHSA-x"])
    aliased = record(
        "lib", "1.0.0", "1.0.5", id="CVE-9", names=["CVE-9"], aliases=["GHSA-x"]
    )
    for dev_rec, rel_rec in ((aliased, plain), (plain, aliased)):
        result = plan(development(vulns=[dev_rec]), stable("1.2.0", rel_rec))
        line = result["lines"][0]
        assert line["items"] == []
        assert line["skipped"][0]["reason_code"] == "not_fixed_in_development"


def test_n4_3_removed_in_development_is_planned() -> None:
    rec = record("lib", "1.0.0", "1.0.5", id="CVE-1")
    dev = development(packages=[inventory("other", ["1.0.0"])])
    result = plan(dev, stable("1.2.0", rec))
    assert items(result)["lib"]["targets"][0]["evidence"] == (
        "lowest fixed version in the same major"
    )


@pytest.mark.parametrize("status", ["failed", "partial"])
def test_n4_3_development_status_must_be_ok(status: str) -> None:
    dev = development()
    dev["status"] = status
    result = plan(dev, stable("1.2.0", record("lib", "1.0.0", "1.0.5")))
    skipped = result["lines"][0]["skipped"][0]
    assert skipped["reason_code"] == "development_data_incomplete"
    assert skipped["reason"] == (
        f"development data incomplete: development version status is {status}"
    )


def test_n4_2_completeness_comes_before_open_in_development() -> None:
    rec = record("lib", "1.0.0", "1.0.5", id="CVE-1")
    dev = development(vulns=[record("lib", "1.0.0", "1.0.5", id="CVE-1")])
    dev["status"] = "failed"
    result = plan(dev, stable("1.2.0", rec))
    assert [s["reason_code"] for s in result["lines"][0]["skipped"]] == [
        "development_data_incomplete"
    ]


def test_n4_2_filters_before_development_do_not_need_development_data() -> None:
    low = record("lib", "1.0.0", "1.0.5", severity="LOW")
    dev = development()
    dev["status"] = "failed"
    result = plan(dev, stable("1.2.0", low))
    assert result["lines"][0]["skipped"] == []
    assert result["lines"][0]["dropped"]["severity"] == 1


def test_n4_3_os_record_needs_the_development_image() -> None:
    img = "image-app-1.2.0"
    os_rec = record("libssl3", "3.0.1", "3.0.2", **{"class": "os", "where": [img]})
    rel = stable("1.2.0", os_rec, targets=[target(img, "image", "app")])
    no_image = plan(development(), rel)
    assert no_image["lines"][0]["skipped"][0]["reason_code"] == (
        "development_data_incomplete"
    )
    dev = development(targets=[target(DEV_SOURCE), target("image-dev", "image", "app")])
    assert list(items(plan(dev, rel))) == ["libssl3"]


def test_n4_3_classify_states() -> None:
    def rec(pkg: str, id: str, **fields: Any) -> dict[str, Any]:
        return record(pkg, "1.0.0", "1.0.5", id=id, **fields)

    dev = development(
        vulns=[rec("open-pkg", "CVE-O")],
        packages=[inventory("open-pkg", ["1.0.0"]), inventory("fixed-pkg", ["1.0.5"])],
    )
    release = stable(
        "1.2.0",
        rec("open-pkg", "CVE-O"),
        rec("fixed-pkg", "CVE-F"),
        rec("gone-pkg", "CVE-R"),
        rec("os-pkg", "CVE-I", **{"class": "os", "where": ["image-x"]}),
        rec("acc-pkg", "CVE-A", accepted={"until": "2099-01-01"}),
        targets=[target("source-1.2.0"), target("image-x", "image", "app")],
    )
    assert states(dev, release) == {
        "CVE-F": "fixed",
        "CVE-I": "incomplete",
        "CVE-O": "open",
        "CVE-R": "removed",
    }


def test_n4_3_classify_entries_and_order() -> None:
    a = record("zlib", "1.0.0", "1.0.5", id="CVE-2", aliases=["GHSA-2"])
    b = record("alib", "1.0.0", "1.0.5", id="CVE-1", severity="LOW")
    c = record("clib", "1.0.0", "1.0.5", id="CVE-3")
    result = classify(
        [report(development(), stable("1.2.0", a, b), candidate("1.3.0-rc.1", c))]
    )

    def entry(line: str, ref: str, kind: str, key: str, ids: list[str]) -> dict:
        return {
            "repo": "o/r",
            "line": line,
            "ref": ref,
            "kind": kind,
            "class": "lang",
            "key": key,
            "pkg": key,
            "ids": ids,
            "state": "removed",
        }

    assert result == [
        entry("1.3", "1.3.0-rc.1", "candidate", "clib", ["CVE-3"]),
        entry("1.2", "1.2.0", "release", "alib", ["CVE-1"]),
        entry("1.2", "1.2.0", "release", "zlib", ["CVE-2", "GHSA-2"]),
    ]


def test_n4_3_classify_uses_the_default_line_selection() -> None:
    old = record("lib", "1.0.0", "1.0.5", id="CVE-OLD")
    three = [stable("1.1.0", old), stable("1.2.0"), stable("1.3.0")]
    assert classify([report(development(), *three)]) == []
    two = [stable("1.1.0", old), stable("1.2.0")]
    assert [e["ids"] for e in classify([report(development(), *two)])] == [["CVE-OLD"]]


def test_n4_3_classify_takes_merged_reports_and_agrees_with_the_plan() -> None:
    dev = development(
        vulns=[record("open-pkg", "1.0.0", "1.0.5", id="CVE-O")],
        packages=[inventory("open-pkg", ["1.0.0"])],
    )
    release = stable(
        "1.2.0",
        record("open-pkg", "1.0.0", "1.0.5", id="CVE-O"),
        record("fixed-pkg", "1.0.0", "1.0.5", id="CVE-F"),
        record("gone-pkg", "1.0.0", "1.0.5", id="CVE-R"),
    )
    entries = classify(merge_reports([report(dev, release)]))
    assert entries == classify([report(dev, release)])
    result = plan(dev, release)
    planned = {v["id"] for x in result["lines"] for i in x["items"] for v in i["vulns"]}
    in_scope = {e["ids"][0] for e in entries if e["state"] in ("fixed", "removed")}
    assert planned == in_scope == {"CVE-F", "CVE-R"}
    assert {e["ids"][0] for e in entries if e["state"] == "open"} == {"CVE-O"}


@pytest.mark.parametrize("case", sorted(CASES))
def test_n4_3_classify_and_plan_agree_on_the_real_reports(case: str) -> None:
    """Every fixed or removed record in scope of a case is in some item."""
    raw = [json.loads(p.read_text(encoding="utf-8")) for p in load_case(case)]
    everything = Config(
        severities=("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"), fixable_only=False
    )
    result = build_plan(merge_reports(raw), everything)
    planned = {
        (
            x["line"],
            i["class"],
            norm(i["pkg"]),
            frozenset({v["id"], *v["names"], *v["aliases"]}),
        )
        for x in result["lines"]
        for i in x["items"]
        for v in i["vulns"]
    }
    entries = classify(raw)
    for entry in entries:
        key = (entry["line"], entry["class"], entry["key"], frozenset(entry["ids"]))
        assert (key in planned) == (entry["state"] in ("fixed", "removed")), entry
