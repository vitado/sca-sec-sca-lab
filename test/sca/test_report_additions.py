"""``role``, ``pkg_key``, ``src_pkg`` and ``title`` of report.json versions."""

import json

import pytest
from golden_case import merged
from normalize import norm, normalize_osv, normalize_trivy
from test_normalize import osv_native, package, result, vuln
from test_summary import finding, report, target
from vulns import build_versions

# --- role ---


def roles(refs, kinds=None, default="development"):
    doc = report([target(f"s{i}", ref=r) for i, r in enumerate(refs)], [])
    doc["default_branch"] = default
    return {v["ref"]: v["role"] for v in build_versions(doc, {}, kinds)}


def test_every_development_is_dev_every_candidate_rc_and_two_release_lines_rel_and_rel_1():
    got = roles(["development", "3.0.0-rc.1", "2.1.3", "2.1.2", "2.0.5", "1.9.0"])
    assert got == {
        "development": "dev",
        "3.0.0-rc.1": "rc",
        "2.1.3": "rel",
        "2.1.2": None,  # not the newest of its line
        "2.0.5": "rel-1",
        "1.9.0": None,  # the third line
    }


def test_several_development_and_candidate_versions_all_get_their_role():
    got = roles(
        ["main", "next", "1.0.0-rc.1", "1.1.0-rc.1", "1.0.0"],
        {"next": "development"},
        default="main",
    )
    assert got == {
        "main": "dev",
        "next": "dev",
        "1.0.0-rc.1": "rc",
        "1.1.0-rc.1": "rc",
        "1.0.0": "rel",
    }


def test_one_release_line_has_no_rel_1_and_a_line_is_major_minor():
    assert roles(["1.4.1", "1.4.0"]) == {"1.4.1": "rel", "1.4.0": None}
    assert roles(["1.5.0", "1.4.9", "2.0.0"]) == {
        "2.0.0": "rel",
        "1.5.0": "rel-1",
        "1.4.9": None,
    }


def test_a_ref_that_is_not_a_release_line_has_no_role():
    assert roles(["2.0.0", "release-x", "7"]) == {
        "2.0.0": "rel",
        "release-x": None,
        "7": None,
    }


def test_the_role_comes_from_the_kind_the_caller_gave():
    assert roles(["3.1-prod", "2.0.0"], {"3.1-prod": "release"}) == {
        "3.1-prod": "rel",
        "2.0.0": "rel-1",
    }
    assert roles(["2.0.0"], {"2.0.0": "candidate"}) == {"2.0.0": "rc"}


# --- pkg_key ---


@pytest.mark.parametrize(
    "name", ["Py_Yaml", "a.b_c-d", "libc6", "python3.12", "A--B__C..D", "ABC", "x"]
)
def test_norm_is_idempotent(name):
    assert norm(norm(name)) == norm(name)


def test_pkg_key_is_the_normalized_name_on_records_and_packages():
    doc = report([target("s")], [finding("s", "CVE-1", "Py_Yaml")])
    (version,) = build_versions(doc, {"s": {("lang", "py-yaml", "1.0")}})
    (record,) = version["vulns"]
    (listed,) = version["packages"]
    assert (record["pkg"], record["pkg_key"]) == ("Py_Yaml", "py-yaml")
    assert (listed["pkg"], listed["pkg_key"]) == ("Py_Yaml", "py-yaml")


# --- src_pkg ---


def os_finding(vid="CVE-1", pkg="libc6", **extra):
    return finding("s", vid, pkg, cls="os", **extra)


def only(findings, sets=None):
    (version,) = build_versions(report([target("s")], findings), sets or {})
    return version


def test_src_pkg_is_the_first_trivy_source_package_of_the_record():
    plain = os_finding()
    named = os_finding(src_pkg="glibc")
    other = os_finding(src_pkg="other")
    other["version"] = "1.3"  # same vulnerability and package: one record
    assert only([plain, named, other])["vulns"][0]["src_pkg"] == "glibc"
    osv = os_finding(scanner="osv")
    assert only([osv])["vulns"][0]["src_pkg"] is None
    assert only([osv, named])["vulns"][0]["src_pkg"] == "glibc"


def test_a_language_record_has_no_src_pkg():
    assert only([finding("s", "CVE-1", "a")])["vulns"][0]["src_pkg"] is None


def test_a_package_has_the_source_of_its_records_in_any_version():
    doc = report(
        [target("s1", ref="1.0"), target("s2")],
        [{**os_finding(src_pkg="glibc"), "target": "s1"}],
    )
    sets = {"s2": {("os", "libc6", "1.3")}}
    versions = {v["ref"]: v for v in build_versions(doc, sets)}
    assert [p["src_pkg"] for p in versions["1.0"]["packages"]] == ["glibc"]
    assert [p["src_pkg"] for p in versions["development"]["packages"]] == ["glibc"]


def trivy_rows(native_result):
    findings = {}
    normalize_trivy("img", {"Results": [native_result]}, findings, {})
    return {f["pkg"]: f["src_pkg"] for f in findings.values()}


def test_trivy_gives_the_source_package_of_an_os_vulnerability_only():
    os_args = {"rtype": "ubuntu", "cls": "os-pkgs", "target": "ubuntu"}
    listed = {**package("libc6"), "Version": "2.39", "SrcName": "glibc"}
    got = trivy_rows(
        result(
            [listed],
            [vuln("libc6", version="2.39"), vuln("zlib1g", "CVE-2", SrcName="zlib")],
            **os_args,
        )
    )
    assert got == {"libc6": "glibc", "zlib1g": "zlib"}  # from Packages, from the vuln
    assert trivy_rows(result([package("libc6")], [vuln("libc6")], **os_args)) == {
        "libc6": None
    }
    lang = result([{**package("a"), "SrcName": "x"}], [vuln("a", SrcName="x")])
    assert trivy_rows(lang) == {"a": None}


# --- title ---


def test_the_title_is_trivy_title_else_osv_summary_whitespace_collapsed():
    trivy = finding("s", "CVE-1", "a", title="  A  flaw\n in\ta ")
    osv = finding("s", "CVE-1", "a", scanner="osv", summary="OSV summary", title="x")
    assert only([osv, trivy])["vulns"][0]["title"] == "A flaw in a"  # Trivy first
    assert only([osv])["vulns"][0]["title"] == "OSV summary"
    empty = finding("s", "CVE-1", "a", title=" \n ")
    assert only([empty, osv])["vulns"][0]["title"] == "OSV summary"  # first non-empty
    assert only([empty])["vulns"][0]["title"] is None


def osv_row(**changes):
    findings = {}
    native = osv_native()
    entry = native["results"][0]["packages"][0]["vulnerabilities"][0]
    entry.update(changes)
    for key in [k for k, v in changes.items() if v is None]:
        del entry[key]
    normalize_osv("s", native, findings, {})
    (row,) = findings.values()
    return row


def test_the_title_never_falls_back_to_the_osv_details():
    row = osv_row(summary=None, details="Details line\nmore")
    assert row["title"] == "Details line" and row["summary"] is None  # as before
    assert only([row])["vulns"][0]["title"] is None


def test_the_osv_summary_reaches_the_record():
    row = osv_row()
    assert row["summary"] == "A flaw"
    assert only([row])["vulns"][0]["title"] == "A flaw"


# --- the whole report ---


def test_the_merged_report_carries_the_new_fields_at_the_end_of_each_object(tmp_path):
    versions = {v["ref"]: v for v in json.loads(merged(tmp_path))["versions"]}
    dev = versions["development"]
    assert dev["role"] == "dev" and versions["1.0.0"]["role"] == "rel"
    assert list(dev)[-3:] == ["vulns", "packages", "role"]
    records = {v["id"]: v for v in dev["vulns"]}
    assert list(records["CVE-2026-1"])[-3:] == ["pkg_key", "src_pkg", "title"]
    assert records["CVE-2026-1"]["title"] == "A flaw in a"
    assert records["CVE-2026-2"]["pkg_key"] == "py-b"
    assert records["CVE-2026-2"]["title"] is None
    assert records["CVE-2026-10"]["src_pkg"] == "glibc"
    assert records["CVE-2026-10"]["title"] == "libc title"
    assert records["CVE-2026-11"]["src_pkg"] is None
    packages = {p["pkg"]: p for p in dev["packages"]}
    assert list(packages["libc6"])[-2:] == ["pkg_key", "src_pkg"]
    assert packages["libc6"]["src_pkg"] == "glibc" and packages["a"]["src_pkg"] is None
