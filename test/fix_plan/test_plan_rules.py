from typing import Any

import pytest
from helpers import (
    DEV_SOURCE,
    development,
    inventory,
    items,
    plan,
    record,
    target,
    version,
)
from sca_fix_plan import Config, ReportError, build_plan, merge_reports, parse_config

DEV_IMAGE = "image-app-development"


def single(result: dict[str, Any], pkg: str = "lib") -> dict[str, Any]:
    return items(result)[pkg]


def release(*vulns: dict[str, Any], **fields: Any) -> dict[str, Any]:
    return version("1.2.3", vulns=list(vulns), **fields)


def config(text: str) -> Config:
    return parse_config(text)


def test_plain_item() -> None:
    result = plan(development(), release(record("lib", "1.0.0", "1.0.5")))
    line = result["lines"][0]
    assert (line["line"], line["ref"], line["branch"]) == (
        "1.2",
        "1.2.3",
        "release-1.2",
    )
    item = single(result)
    assert item["targets"] == [
        {
            "installed": "1.0.0",
            "target": "1.0.5",
            "evidence": "lowest fixed version in the same major",
        }
    ]
    assert (item["method"], item["fallback"], item["reason"]) == (
        "dependabot",
        "npm-override",
        None,
    )
    assert item["locations"] == ["package-lock.json"]
    assert item["relationship"] == "direct"


def test_accepted_is_skipped() -> None:
    rec = record("lib", "1.0.0", "1.0.5", accepted={"until": "2027-01-01"})
    line = plan(development(), release(rec))["lines"][0]
    assert line["items"] == []
    assert line["skipped"][0]["reason"] == "accepted until 2027-01-01"


def test_severity_filter_and_previous_lines() -> None:
    low = record("lib", "1.0.0", "1.0.5", severity="LOW")
    medium = record("other", "1.0.0", "1.0.5", severity="MEDIUM")
    newer = version("1.3.0", vulns=[low, medium])
    older = version("1.2.0", vulns=[low, medium])
    result = plan(
        development(),
        newer,
        older,
        config=config(
            '{"severities": ["MEDIUM"], "severities-previous": ["LOW"]}',
        ),
    )
    assert [i["pkg"] for i in result["lines"][0]["items"]] == ["other"]
    assert [i["pkg"] for i in result["lines"][1]["items"]] == ["lib"]
    assert result["lines"][0]["dropped"]["severity"] == 1


def test_previous_severities_default_to_severities() -> None:
    low = record("lib", "1.0.0", "1.0.5", severity="LOW")
    result = plan(
        development(),
        version("1.3.0"),
        version("1.2.0", vulns=[low]),
        config=config('{"severities": ["LOW"]}'),
    )
    assert [i["pkg"] for i in result["lines"][1]["items"]] == ["lib"]


def test_fixable_only() -> None:
    unfixed = record("lib", "1.0.0", "")
    result = plan(development(), release(unfixed))
    assert result["lines"][0]["items"] == []
    assert result["lines"][0]["dropped"]["unfixable"] == 1
    kept = plan(
        development(), release(unfixed), config=config('{"fixable-only": false}')
    )
    assert single(kept)["method"] == "manual"
    assert single(kept)["reason"] == "no fixed version above 1.0.0"


def test_include_dev() -> None:
    dev_only = record("lib", "1.0.0", "1.0.5", dev=True)
    assert single(plan(development(), release(dev_only)))["method"] == "dependabot"
    result = plan(
        development(), release(dev_only), config=config('{"include-dev": false}')
    )
    assert result["lines"][0]["items"] == []
    assert result["lines"][0]["dropped"]["dev"] == 1


def test_n4_3_present_in_development_is_not_fixed_there() -> None:
    names = ["CVE-1", "GHSA-1"]
    rec = record("lib", "1.0.0", "1.0.5", id="CVE-1", names=names)
    still = record("lib", "1.0.5", "", id="GHSA-1", names=["GHSA-1"])
    result = plan(development(vulns=[still]), release(rec))
    line = result["lines"][0]
    assert line["items"] == []
    assert line["skipped"] == [
        {
            "pkg": "lib",
            "class": "lang",
            "ids": ["CVE-1"],
            "reason": "not fixed in development",
            "reason_code": "not_fixed_in_development",
        }
    ]


@pytest.mark.parametrize(
    "dev_targets",
    [
        [],
        [target(DEV_SOURCE, packages=0)],
        [target(DEV_SOURCE, status="failed")],
        [target(DEV_IMAGE, "image", "app")],
    ],
)
def test_development_data_must_cover_a_library(
    dev_targets: list[dict[str, Any]],
) -> None:
    result = plan(
        development(targets=dev_targets), release(record("lib", "1.0.0", "1.0.5"))
    )
    skipped = result["lines"][0]["skipped"][0]
    assert skipped["reason"] == (
        "development data incomplete: no ok source target with packages scanned"
    )


def os_record() -> dict[str, Any]:
    return record(
        "zlib",
        "1.3.2-r0",
        "1.3.2-r1",
        severity="HIGH",
        ecosystem="Alpine:v3.24",
        where=["image-app-1.2.3"],
        **{"class": "os"},
    )


def os_release() -> dict[str, Any]:
    return release(
        os_record(), targets=[target("image-app-1.2.3", "image", "app", packages=50)]
    )


def test_development_data_must_cover_the_image() -> None:
    other = target("image-other-development", "image", "other")
    result = plan(development(targets=[target(DEV_SOURCE), other]), os_release())
    assert result["lines"][0]["skipped"][0]["reason"] == (
        "development data incomplete: no ok image target for app"
    )
    empty = target(DEV_IMAGE, "image", "app", packages=0)
    assert plan(development(targets=[empty]), os_release())["lines"][0]["items"] == []
    ok = target(DEV_IMAGE, "image", "app")
    assert (
        single(plan(development(targets=[ok]), os_release(), config=DOCKER), "zlib")[
            "method"
        ]
        == "docker-tag"
    )


def test_development_version_is_the_target() -> None:
    dev = development(packages=[inventory("lib", ["1.0.9", "2.0.0"])])
    item = single(plan(dev, release(record("lib", "1.0.0", "1.0.5"))))
    assert item["targets"][0]["target"] == "1.0.9"
    assert item["targets"][0]["evidence"] == "development runs 1.0.9"


def test_development_version_below_the_fix_is_no_evidence() -> None:
    dev = development(packages=[inventory("lib", ["1.0.2"])])
    item = single(plan(dev, release(record("lib", "1.0.0", "1.0.5"))))
    assert item["targets"][0]["target"] == "1.0.5"
    assert item["targets"][0]["evidence"] == "lowest fixed version in the same major"


def test_development_in_another_major() -> None:
    dev = development(packages=[inventory("lib", ["3.0.0"])])
    rec = record("lib", "1.0.0", "1.0.5, 3.0.0")
    item = single(
        plan(dev, release(rec), config=config('{"allow-major": "dev-proven"}'))
    )
    assert item["targets"][0]["target"] == "3.0.0"
    strict = single(plan(dev, release(rec)))
    assert strict["targets"][0]["target"] == "1.0.5"


def test_another_major_needs_a_human() -> None:
    rec = record("lib", "1.0.0", "2.0.0")
    item = single(plan(development(), release(rec)))
    assert item["method"] == "manual"
    assert item["reason"] == "fix needs another major (2.0.0), no development evidence"
    dev = development(packages=[inventory("lib", ["2.0.0"])])
    strict = single(plan(dev, release(rec)))
    assert strict["reason"] == (
        "fix needs another major (2.0.0), development runs it, allow-major is none"
    )


def test_zero_major_is_two_components() -> None:
    item = single(plan(development(), release(record("lib", "0.3.1", "0.4.0"))))
    assert item["reason"].startswith("fix needs another major (0.4.0)")


def test_every_vuln_of_the_item_counts() -> None:
    first = record("lib", "1.0.0", "1.0.5, 2.0.0", id="CVE-A")
    second = record("lib", "1.0.0", "1.0.8", id="CVE-B")
    item = single(plan(development(), release(first, second)))
    assert [t["target"] for t in item["targets"]] == ["1.0.8"]
    assert [v["id"] for v in item["vulns"]] == ["CVE-A", "CVE-B"]


def test_one_target_per_installed_version() -> None:
    first = record("lib", ["1.0.0", "2.0.0"], "1.0.5, 2.0.4")
    item = single(plan(development(), release(first)))
    assert [(t["installed"], t["target"]) for t in item["targets"]] == [
        ("1.0.0", "1.0.5"),
        ("2.0.0", "2.0.4"),
    ]


def test_one_installed_version_without_a_target_makes_the_item_manual() -> None:
    first = record("lib", ["1.0.0", "2.0.0"], "1.0.5, 3.0.0")
    item = single(plan(development(), release(first)))
    assert item["method"] == "manual"
    assert "fix needs another major (3.0.0)" in item["reason"]


def test_packages_are_grouped_by_normalized_name() -> None:
    first = record("My_Lib", "1.0.0", "1.0.5", id="CVE-A")
    second = record("my.lib", "1.0.0", "1.0.5", id="CVE-B")
    result = plan(development(), release(first, second))
    assert len(result["lines"][0]["items"]) == 1


def test_unparseable_version_is_manual() -> None:
    item = single(plan(development(), release(record("lib", "1.0.0", "1.0-3ubuntu1"))))
    assert item["method"] == "manual"
    assert item["reason"] == "cannot compare versions 1.0-3ubuntu1"


@pytest.mark.parametrize(
    ("ecosystem", "method", "fallback"),
    [
        ("npm", "dependabot", "npm-override"),
        ("PyPI", "dependabot", "manual"),
        ("Maven", "dependabot", "manual"),
    ],
)
def test_method_by_ecosystem(ecosystem: str, method: str, fallback: str) -> None:
    item = single(
        plan(
            development(), release(record("lib", "1.0.0", "1.0.5", ecosystem=ecosystem))
        )
    )
    assert (item["method"], item["fallback"], item["reason"]) == (
        method,
        fallback,
        None,
    )


def test_unsupported_ecosystem() -> None:
    rec = record("lib", "1.0.0", "1.0.5", ecosystem="Go")
    item = single(plan(development(), release(rec)))
    assert (item["method"], item["reason"]) == ("manual", "ecosystem Go not supported")


def test_library_only_in_an_image() -> None:
    rec = record("lib", "1.0.0", "1.0.5", where=["image-app-1.2.3"])
    rel = release(
        rec, targets=[target("image-app-1.2.3", "image", "app"), target("source-1.2.3")]
    )
    item = single(plan(development(), rel))
    assert (item["method"], item["reason"]) == (
        "manual",
        "only in the image, not in a manifest",
    )


DOCKER = config('{"methods": ["docker-tag"]}')


def test_os_package_is_manual_by_default() -> None:
    dev = development(targets=[target(DEV_IMAGE, "image", "app")])
    item = single(plan(dev, os_release()), "zlib")
    assert (item["method"], item["fallback"]) == ("manual", None)
    assert item["reason"] == "rebuild the image to pick up the fixes"


def test_os_hint_names_the_newer_os_of_development() -> None:
    def image(id: str, name: str, family: str = "alpine") -> dict[str, Any]:
        return {
            **target(id, "image", "app", packages=50),
            "os": {"family": family, "name": name},
        }

    rel = release(os_record(), targets=[image("image-app-1.2.3", "3.24.2")])
    reason = single(
        plan(development(targets=[image(DEV_IMAGE, "3.24.5")]), rel), "zlib"
    )["reason"]
    assert reason.startswith("rebuild the image to pick up the fixes (development")
    assert "alpine 3.24.5" in reason
    for dev_image in (image(DEV_IMAGE, "3.24.2"), image(DEV_IMAGE, "3.25", "debian")):
        item = single(plan(development(targets=[dev_image]), rel), "zlib")
        assert item["reason"] == "rebuild the image to pick up the fixes"


def test_os_package_is_docker_tag() -> None:
    dev = development(targets=[target(DEV_IMAGE, "image", "app")])
    item = single(plan(dev, os_release(), config=DOCKER), "zlib")
    assert (item["method"], item["fallback"]) == ("docker-tag", "manual")
    assert item["targets"] == [
        {
            "installed": "1.3.2-r0",
            "target": None,
            "fixed": ["1.3.2-r1"],
            "evidence": "base image bump, verified by rescan",
        }
    ]


def test_os_versions_are_not_compared() -> None:
    rec = os_record()
    rec.update(installed=["1:2.3-1ubuntu1"], fixed="1:2.3-1ubuntu2")
    dev = development(targets=[target(DEV_IMAGE, "image", "app")])
    rel = release(rec, targets=[target("image-app-1.2.3", "image", "app")])
    item = single(plan(dev, rel, config=DOCKER), "zlib")
    assert (item["method"], item["reason"]) == ("docker-tag", None)
    assert item["targets"][0]["fixed"] == ["1:2.3-1ubuntu2"]


def test_methods_gate() -> None:
    rec = record("lib", "1.0.0", "1.0.5")
    off = single(
        plan(development(), release(rec), config=config('{"methods": ["docker-tag"]}'))
    )
    assert (off["method"], off["fallback"], off["reason"]) == (
        "manual",
        None,
        "method dependabot disabled",
    )
    no_override = config('{"methods": ["dependabot"]}')
    kept = single(plan(development(), release(rec), config=no_override))
    assert (kept["method"], kept["fallback"]) == ("dependabot", "manual")


def test_newest_lines_and_newest_ref_per_line() -> None:
    result = plan(
        development(),
        version("1.1.9"),
        version("1.2.0"),
        version("1.2.1-rc.1", "candidate"),
        version("1.2.1"),
        version("1.3.0-rc.1", "candidate"),
    )
    assert [(x["line"], x["ref"], x["kind"]) for x in result["lines"]] == [
        ("1.3", "1.3.0-rc.1", "candidate"),
        ("1.2", "1.2.1", "release"),
        ("1.1", "1.1.9", "release"),
    ]
    wide = plan(
        development(),
        version("1.1.9"),
        version("1.2.0"),
        config=config('{"release-lines": 1}'),
    )
    assert [x["line"] for x in wide["lines"]] == ["1.2"]


def test_release_branch_pattern() -> None:
    result = plan(
        development(),
        version("0.21.0-rc.0", "candidate"),
        config=config('{"release-branch": "rel/{major}-{minor}"}'),
    )
    assert result["lines"][0]["branch"] == "rel/0-21"


def test_partial_version_is_planned_from_its_ok_targets() -> None:
    rel = version("1.2.3", vulns=[record("lib", "1.0.0", "1.0.5")], status="failed")
    result = plan(development(), rel)
    assert result["lines"][0]["partial"] is True
    assert len(result["lines"][0]["items"]) == 1


def test_unparseable_ref_is_reported() -> None:
    result = plan(development(), version("1.2.3"), version("nightly"))
    assert result["skipped_refs"] == [
        {
            "ref": "nightly",
            "reason": "ref is not X.Y.Z or X.Y.Z-suffix",
            "reason_code": "ref_not_semver",
        }
    ]
    assert [x["ref"] for x in result["lines"]] == ["1.2.3"]


@pytest.mark.parametrize(
    "versions", [[version("1.2.3")], [development(), version("dev2", "development")]]
)
def test_exactly_one_development_version(versions: list[dict[str, Any]]) -> None:
    with pytest.raises(ReportError, match="exactly one development"):
        plan(*versions)


def test_plan_header() -> None:
    from helpers import report

    merged = merge_reports([report(development(), release(), run_id="7")])
    result = build_plan(merged, Config())
    assert result["schema_version"] == 2
    assert result["repo"] == "o/r"
    assert result["reports"] == [
        {
            "run_id": "7",
            "run_url": "https://example.test/1",
            "refs": ["development", "1.2.3"],
        }
    ]
    assert result["config"]["release-lines"] == 2


def test_n4_5_rule_1_fallback_not_in_methods_is_manual() -> None:
    rec = record("lib", "1.0.0", "1.0.5")
    only = config('{"methods": ["dependabot"]}')
    kept = single(plan(development(), release(rec), config=only))
    assert kept["fallback"] == "manual"


def test_n4_2_skips_are_grouped_per_package_and_code() -> None:
    first = record("lib", "1.0.0", "1.0.5", id="CVE-2", accepted={"until": "2027-01-01"})
    second = record("lib", "1.0.0", "1.0.6", id="CVE-1", accepted={"until": "2027-06-01"})
    skipped = plan(development(), release(first, second))["lines"][0]["skipped"]
    assert skipped == [
        {
            "pkg": "lib",
            "class": "lang",
            "ids": ["CVE-1", "CVE-2"],
            "reason": "accepted until 2027-01-01",
            "reason_code": "accepted",
        }
    ]
