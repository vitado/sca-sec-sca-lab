"""Acceptance rules of the caller (``acceptances`` of targets.json)."""

import json
from pathlib import Path

import ignores
import pytest
import vulns
from golden_case import GOLDEN, merged

SRC, REL, IMG = "source-development", "source-1.0.0", "image-dev"


def run(tmp_path: Path, rules: list | None) -> dict:
    header = None if rules is None else {"acceptances": rules}
    return json.loads(merged(tmp_path, header))


def rule(targets, package, ids=None, expires="2099-01-01", **extra):
    return {
        "scope": ["x"],
        "targets": targets,
        "package": package,
        "class": None,
        "ids": ids or [],
        "reason": "why",
        "expires": expires,
        "approved_by": "me",
        "ticket": None,
        **extra,
    }


def accepted(report):
    return {
        (f["target"], f["id"]): f["accepted"]
        for f in report["findings"]
        if "accepted" in f
    }


def records(report, ref="development"):
    version = next(v for v in report["versions"] if v["ref"] == ref)
    return {v["id"]: v["accepted"] for v in version["vulns"]}


def test_without_rules_the_report_is_byte_identical_to_before(tmp_path):
    out = merged(tmp_path)
    assert out == GOLDEN.read_bytes()
    assert "acceptances" not in json.loads(out)


def test_a_rule_with_ids_accepts_those_findings_of_the_package_in_its_targets_only(
    tmp_path,
):
    report = run(tmp_path, [rule([IMG], "libc6", ["CVE-2026-10"], reason="why now")])
    assert accepted(report) == {
        (IMG, "CVE-2026-10"): {"until": "2099-01-01", "reason": "why now", "rule": 0}
    }
    (entry,) = report["acceptances"]
    assert (entry["matched"], entry["expired"], entry["bad_expiry"]) == (1, False, False)
    assert len(report["findings"]) == len(json.loads(GOLDEN.read_bytes())["findings"])


def test_a_rule_without_ids_accepts_every_vulnerability_of_the_package(tmp_path):
    report = run(tmp_path, [rule([SRC, REL], "a")])
    assert set(accepted(report)) == {
        (SRC, "CVE-2026-1"),  # the Trivy and the OSV finding
        (REL, "CVE-2026-1"),
    }
    assert report["acceptances"][0]["matched"] == 3


def test_a_language_package_name_is_normalized_and_an_os_name_is_exact(tmp_path):
    report = run(tmp_path, [rule([SRC], "py-b"), rule([IMG], "LibC6")])
    assert set(accepted(report)) == {(SRC, "CVE-2026-2")}


def test_an_expired_rule_does_not_act_on_its_day(tmp_path):
    report = run(tmp_path, [rule([IMG], "libc6", expires="2026-10-14")])  # the report day
    assert not accepted(report) and records(report)["CVE-2026-10"] is None
    assert report["acceptances"][0]["expired"] and report["acceptances"][0]["matched"] == 0


@pytest.mark.parametrize("expires", [None, "soon", "2026-02-30"])
def test_a_rule_without_a_valid_date_does_not_act(tmp_path, expires):
    report = run(tmp_path, [rule([IMG], "libc6", expires=expires)])
    assert not accepted(report) and report["acceptances"][0]["bad_expiry"]
    assert records(report)["CVE-2026-10"] is None


def test_the_earliest_overlapping_rule_names_the_finding_and_each_counts_it(tmp_path):
    report = run(
        tmp_path,
        [
            rule([IMG], "nothing"),
            rule([IMG], "libc6", expires="2099-06-01"),
            rule([IMG], "libc6", ["CVE-2026-10"], expires="2098-01-01"),
        ],
    )
    assert accepted(report) == {
        (IMG, "CVE-2026-10"): {"until": "2098-01-01", "reason": "why", "rule": 2}
    }
    assert [a["matched"] for a in report["acceptances"]] == [0, 1, 1]


def test_extra_keys_of_a_rule_are_passed_through_and_empty_rules_stay_empty(tmp_path):
    (entry,) = run(tmp_path, [rule([IMG], "libc6", ticket="T-1", team="x")])["acceptances"]
    assert (entry["ticket"], entry["team"], entry["approved_by"]) == ("T-1", "x", "me")
    assert run(tmp_path / "e", []).get("acceptances") == []


def test_a_record_is_accepted_when_all_its_findings_are(tmp_path):
    report = run(tmp_path, [rule([IMG], "libc6", expires="2099-06-01")])
    assert records(report)["CVE-2026-10"] == {"until": "2099-06-01"}
    assert records(report)["CVE-2026-11"] is None


def test_the_rule_and_the_trivyignore_give_the_earliest_until(tmp_path):
    # the golden .trivyignore accepts CVE-2026-1 until 2099-01-01
    report = run(tmp_path, [rule([SRC], "a", expires="2098-01-01")])
    assert records(report)["CVE-2026-1"] == {"until": "2098-01-01"}
    report = run(tmp_path / "b", [rule([SRC], "a", expires="2099-09-01")])
    assert records(report)["CVE-2026-1"] == {"until": "2099-01-01"}


def test_the_counters_of_the_rules_and_the_trivyignore_are_independent(tmp_path):
    report = run(tmp_path, [rule([SRC], "a", ["CVE-2026-1"])])
    assert [e["matched"] for e in report["ignores"]] == [True]
    assert [a["matched"] for a in report["acceptances"]] == [2]  # trivy and osv finding


def found(pkg, names, cls="os", version="1", scanner="trivy"):
    return {
        "target": IMG,
        "pkg": pkg,
        "version": version,
        "names": names,
        "class": cls,
        "scanner": scanner,
    }


def accept(findings, rules):
    report = {"generated_utc": "2026-10-30T10:00:00Z", "findings": findings}
    ignores.add_acceptances(report, rules)
    return report


def test_ids_match_the_names_of_the_whole_merged_vulnerability():
    # the OSV twin knows the GHSA id of the vulnerability Trivy reports as CVE-1
    findings = [
        found("libx", ["CVE-1"]),
        found("libx", ["CVE-1", "GHSA-a"], scanner="osv"),
        found("libx", ["CVE-1"], version="2"),
        found("liby", ["CVE-1"]),
        found("libx", ["CVE-9"]),
    ]
    report = accept(findings, [rule([IMG], "libx", ["GHSA-a"])])
    assert ["accepted" in f for f in findings] == [True, True, False, False, False]
    assert report["acceptances"][0]["matched"] == 2


def test_an_os_package_is_matched_exactly_and_a_language_package_normalized():
    findings = [
        found("python3-12", ["CVE-1"]),
        found("python3.12", ["CVE-2"]),
        found("Py_Yaml", ["CVE-3"], "lang"),
        found("Six", ["CVE-4"]),
    ]
    accept(findings, [rule([IMG], "python3.12"), rule([IMG], "py-yaml"), rule([IMG], "six")])
    assert ["accepted" in f for f in findings] == [False, True, True, False]


def test_the_class_of_a_rule_restricts_it_to_os_or_language_packages():
    for cls, expected in (("os", [True, False]), ("lang", [False, True]), (None, [True, True])):
        findings = [found("six", ["CVE-1"]), found("six", ["CVE-2"], "lang")]
        accept(findings, [rule([IMG], "six", **{"class": cls})])
        assert ["accepted" in f for f in findings] == expected, cls


def test_a_record_is_accepted_only_when_every_finding_of_it_is():
    def twin(scanner, names):
        return {
            **found("libx", names, scanner=scanner),
            "id": names[0],
            "severity": "HIGH",
            "dev": False,
            "published": None,
            "modified": None,
            "cvss": None,
            "aliases": [],
            "ecosystem": None,
            "relationship": None,
            "locations": [],
            "fixed_version": "",
        }

    fs = [twin("trivy", ["CVE-1"]), twin("osv", ["GHSA-a", "CVE-1"])]
    accept(fs, [rule([IMG], "libx", ["GHSA-a"])])
    assert vulns.record_of(fs, set())["accepted"] == {"until": "2099-01-01"}
    del fs[1]["accepted"]
    assert vulns.record_of(fs, set())["accepted"] is None
