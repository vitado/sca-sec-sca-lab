"""``version_kinds`` of targets.json: the caller names the kind of a version."""

import json
from pathlib import Path

import pytest
from golden_case import GOLDEN, as_before, merged
from test_merge_results import Run, target


def kinds(tmp_path: Path, version_kinds, tag="0.50.0-rc.1", field="kind", status="failed"):
    """``(ref, field)`` of the versions of a run of one image tagged ``tag`` (no result:
    a failed target); ``version_kinds`` None: the key is absent.
    """
    image = {**target("i", "trivy", "image", status, "x"), "tag": tag}
    header = None if version_kinds is None else {"version_kinds": version_kinds}
    run = Run(tmp_path, [image], header)
    _, report = run.merge()
    return [(v["ref"], v[field]) for v in report["versions"]]


def test_version_kinds_override_the_kind_derived_from_the_ref(tmp_path):
    assert kinds(tmp_path, {"0.50.0-rc.1": "release"}) == [("0.50.0-rc.1", "release")]


@pytest.mark.parametrize(
    ("version_kinds", "tag", "expected"),
    [
        (None, "0.50.0-rc.1", "candidate"),
        ({}, "0.50.0-rc.1", "candidate"),
        (None, "1.2.3", "release"),
        (None, "development", "development"),
    ],
)
def test_without_version_kinds_the_kind_is_derived_from_the_ref_as_before(
    tmp_path, version_kinds, tag, expected
):
    assert kinds(tmp_path, version_kinds, tag) == [(tag, expected)]


def test_a_ref_of_version_kinds_without_a_target_is_ignored(tmp_path):
    assert kinds(tmp_path, {"9.9.9": "development"}) == [("0.50.0-rc.1", "candidate")]


def test_an_unknown_version_kind_is_an_input_error(tmp_path):
    with pytest.raises(ValueError, match="unknown kind"):
        kinds(tmp_path, {"0.50.0-rc.1": "deployed"})


def test_the_map_is_read_with_the_ref_as_given_before_the_v_strip(tmp_path):
    assert kinds(tmp_path, {"v1.2.3-rc.1": "release"}, "v1.2.3-rc.1") == [
        ("1.2.3-rc.1", "release")
    ]
    (tmp_path / "b").mkdir()
    assert kinds(tmp_path / "b", {"1.2.3-rc.1": "release"}, "v1.2.3-rc.1") == [
        ("1.2.3-rc.1", "candidate")
    ]


def test_two_refs_of_one_version_mapped_to_different_kinds_are_an_input_error(tmp_path):
    # the git tag carries a v, the registry tag does not: one version, two raw refs
    source = {**target("s", "trivy"), "git_ref": "v1.2.3"}
    image = {**target("i", "trivy", "image"), "tag": "1.2.3"}
    run = Run(tmp_path, [source, image], {"version_kinds": {"v1.2.3": "release", "1.2.3": "candidate"}})
    with pytest.raises(ValueError, match=r"1\.2\.3 is candidate.*v1\.2\.3 is release|v1\.2\.3 is release.*1\.2\.3 is candidate"):
        run.merge()
    (tmp_path / "ok").mkdir()
    run = Run(tmp_path / "ok", [source, image], {"version_kinds": {"v1.2.3": "release", "1.2.3": "release"}})
    _, report = run.merge()
    assert [(v["ref"], v["kind"]) for v in report["versions"]] == [("1.2.3", "release")]


@pytest.mark.parametrize(
    ("version_kinds", "tag", "latest"),
    [
        ({"3.1-prod": "release"}, "3.1-prod", True),
        ({"3.1-prod": "candidate"}, "3.1-prod", False),
        ({"1.2.3": "candidate"}, "1.2.3", False),
        (None, "3.1-prod", False),
        (None, "1.2.3", True),
    ],
)
def test_latest_follows_the_kind_the_map_gave_else_the_spelling_of_the_ref(
    tmp_path, version_kinds, tag, latest
):
    got = kinds(tmp_path, version_kinds, tag, "latest", "not_applicable")
    assert got == [(tag, latest)]


def test_an_unmapped_version_keeps_the_latest_rule_next_to_a_mapped_one(tmp_path):
    images = [
        {**target("a", "trivy", "image", "not_applicable", "x"), "tag": "3.1-prod"},
        {**target("b", "trivy", "image", "not_applicable", "x"), "tag": "1.2.3"},
    ]
    _, report = Run(tmp_path, images, {"version_kinds": {"3.1-prod": "candidate"}}).merge()
    assert {v["ref"]: v["latest"] for v in report["versions"]} == {
        "3.1-prod": False,
        "1.2.3": True,
    }


def test_an_empty_map_leaves_the_report_byte_identical(tmp_path):
    out = merged(tmp_path, {"version_kinds": {}})
    assert as_before(out, tmp_path) == GOLDEN.read_bytes()
    assert json.loads(GOLDEN.read_bytes())["versions"][0]["kind"] == "development"
