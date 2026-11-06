"""Normalizers of the SCA merge: Trivy and OSV results into findings."""

import json

import pytest

from normalize import (
    apply_gradle_graph,
    borrow_source_chains,
    normalize_osv,
    normalize_trivy,
    pick_id,
    severity_of_score,
)


def package(name, version="1.0", depends_on=(), rel=None, dev=False, **extra):
    pkg = {"ID": f"{name}@{version}", "Name": name, "Version": version, **extra}
    pkg["DependsOn"] = [f"{d}@1.0" for d in depends_on]
    if rel:
        pkg["Relationship"] = rel
    if dev:
        pkg["Dev"] = True
    return pkg


def vuln(name, vid="CVE-2026-1", version="1.0", **extra):
    return {
        "VulnerabilityID": vid,
        "PkgName": name,
        "InstalledVersion": version,
        "Severity": "HIGH",
        "FixedVersion": "2.0",
        "PrimaryURL": f"https://example.test/{vid}",
        **extra,
    }


def result(
    packages, vulns=(), target="package-lock.json", rtype="npm", cls="lang-pkgs"
):
    return {
        "Target": target,
        "Type": rtype,
        "Class": cls,
        "Packages": packages,
        "Vulnerabilities": list(vulns),
    }


def trivy(*results, tid="source-development"):
    findings, inventory = {}, {}
    normalize_trivy(tid, {"Results": list(results)}, findings, inventory)
    return list(findings.values()), inventory


def test_a_null_title_is_an_empty_title():
    rows, _ = trivy(result([package("a")], [vuln("a", Title=None)]))
    assert rows[0]["title"] == ""


def test_pick_id_is_the_first_cve_else_the_first_id():
    assert pick_id(["GHSA-aaaa", "CVE-2026-2", "CVE-2026-1"]) == "CVE-2026-1"
    assert pick_id(["GHSA-aaaa", "PYSEC-1"]) == "GHSA-aaaa"


def test_trivy_id_is_its_own_vulnerability_id_with_names_and_published():
    rows, _ = trivy(
        result(
            [package("a")],
            [
                vuln(
                    "a",
                    "GHSA-aaaa",
                    VendorIDs=["CVE-2026-7"],
                    PublishedDate="2026-03-04T10:00:00Z",
                )
            ],
        )
    )
    row = rows[0]
    assert (row["id"], row["aliases"]) == ("GHSA-aaaa", ["CVE-2026-7"])
    assert (row["names"], row["published"]) == (["GHSA-aaaa"], "2026-03-04")
    rows, _ = trivy(result([package("a")], [vuln("a")]))
    assert rows[0]["published"] is None


def test_copies_in_several_lockfiles_become_one_row_with_locations():
    pkgs = [package("a")]
    rows, _ = trivy(
        result(
            pkgs,
            [vuln("a", PkgPath="x/package-lock.json")],
            target="x/package-lock.json",
        ),
        result(pkgs, [vuln("A")], target="y/package-lock.json"),
    )
    assert len(rows) == 1
    assert rows[0]["locations"] == ["x/package-lock.json", "y/package-lock.json"]
    assert rows[0]["severity"] == "HIGH" and rows[0]["fixed_version"] == "2.0"


def test_chain_is_the_shortest_path_from_the_nearest_direct_dependency():
    pkgs = [
        package("top", depends_on=["mid", "x"], rel="direct"),
        package("mid", depends_on=["leaf"], rel="indirect"),
        package("x", depends_on=["y"], rel="indirect"),
        package("y", depends_on=["leaf"], rel="indirect"),
        package("leaf", rel="indirect", dev=True),
        package("own", rel="direct"),
    ]
    rows, _ = trivy(result(pkgs, [vuln("leaf"), vuln("own", "CVE-2026-2")]))
    leaf, own = rows
    assert leaf["chain"] == ["top", "mid", "leaf"]
    assert (leaf["relationship"], leaf["dev"]) == ("indirect", True)
    assert own["chain"] == ["own"] and own["relationship"] == "direct"


def test_a_dependency_cycle_ends_and_gives_no_chain():
    pkgs = [
        package("a", depends_on=["b"], rel="indirect"),
        package("b", depends_on=["a"], rel="indirect"),
    ]
    rows, _ = trivy(result(pkgs, [vuln("b")]))
    assert rows[0]["chain"] == []


def test_no_graph_information_is_an_empty_chain_not_an_error():
    rows, _ = trivy(result([package("a")], [vuln("a")]))
    assert rows[0]["chain"] == [] and rows[0]["relationship"] is None


def test_os_findings_have_no_locations_and_no_chain():
    pkgs = [package("zlib", "1.3")]
    rows, inventory = trivy(
        result(pkgs, [vuln("zlib", version="1.3")], "alpine", "alpine", "os-pkgs")
    )
    assert (rows[0]["class"], rows[0]["locations"], rows[0]["chain"]) == ("os", [], [])
    assert inventory == {}


def write_graph(directory, project_dir, direct, modules):
    directory.mkdir(exist_ok=True)
    data = {
        "schema_version": 1,
        "project": ":" + project_dir,
        "project_dir": project_dir,
        "configurations": {"runtimeClasspath": {"direct": direct, "modules": modules}},
    }
    (directory / f"graph-{project_dir}.json").write_text(json.dumps(data))


def gradle_native(target="server/gradle.lockfile"):
    ids = ["g:app:1", "g:lib:1", "g:leaf:1"]
    pkgs = [{"ID": i, "Name": i.rsplit(":", 1)[0], "Version": "1"} for i in ids]
    vulns = [vuln("g:leaf", version="1", PkgID="g:leaf:1")]
    return {"Results": [result(pkgs, vulns, target, "gradle")]}


def test_gradle_chain_comes_from_the_graph_of_the_project(tmp_path):
    graph_dir = tmp_path / "graph"
    write_graph(
        graph_dir,
        "server",
        ["g:app:1"],
        {"g:app:1": ["g:lib:1"], "g:lib:1": ["g:leaf:1", "other:x:1"], "g:leaf:1": []},
    )
    native = gradle_native()
    apply_gradle_graph("source-development", native, graph_dir)
    findings = {}
    normalize_trivy("source-development", native, findings, {})
    row = next(iter(findings.values()))
    assert row["chain"] == ["g:app", "g:lib", "g:leaf"]
    assert row["relationship"] == "indirect"


def test_gradle_without_a_graph_for_the_project_has_no_chain(tmp_path, capsys):
    write_graph(tmp_path / "graph", "other", ["g:app:1"], {"g:app:1": []})
    native = gradle_native()
    apply_gradle_graph("source-development", native, tmp_path / "graph")
    findings = {}
    normalize_trivy("source-development", native, findings, {})
    assert next(iter(findings.values()))["chain"] == []
    assert "No Gradle dependency graph" in capsys.readouterr().out


def test_an_unreadable_graph_file_is_skipped_with_a_warning(tmp_path, capsys):
    (tmp_path / "graph").mkdir()
    (tmp_path / "graph" / "graph-x.json").write_text("{not json")
    apply_gradle_graph("source-development", gradle_native(), tmp_path / "graph")
    assert "Gradle dependency graph ignored" in capsys.readouterr().out


def test_an_image_package_borrows_the_chain_of_the_source_not_its_dev_flag():
    src_pkgs = [
        package("top", depends_on=["jar"], rel="direct"),
        package("jar", rel="indirect", dev=True),
    ]
    _, src_inventory = trivy(result(src_pkgs))
    image = result([package("Jar")], [vuln("Jar")], target="app/jar", rtype="jar")
    rows, _ = trivy(image, tid="app-development")
    findings = dict(enumerate(rows))
    borrow_source_chains(
        findings,
        {"source-development": src_inventory},
        [{"id": "source-development", "ref": "development"}],
        [{"id": "app-development", "ref": "development"}],
    )
    assert rows[0]["chain"] == ["top", "jar"] and rows[0]["relationship"] == "indirect"
    assert rows[0]["dev"] is False


def test_an_image_package_the_source_does_not_have_stays_without_a_chain():
    rows, _ = trivy(result([package("a")], [vuln("a")]), tid="app-development")
    borrow_source_chains(
        dict(enumerate(rows)),
        {"source-development": {}},
        [{"id": "source-development", "ref": "development"}],
        [{"id": "app-development", "ref": "development"}],
    )
    assert rows[0]["chain"] == []


def test_an_image_package_of_a_release_borrows_the_same_tag_source_first():
    _, dev_inventory = trivy(
        result([package("top", depends_on=["jar"], rel="direct"), package("jar", rel="indirect")])
    )
    _, rel_inventory = trivy(
        result([package("rel", depends_on=["jar"], rel="direct"), package("jar", rel="indirect")]),
        tid="source-0.21.4",
    )
    image = result([package("Jar")], [vuln("Jar")], target="app/jar", rtype="jar")
    rows, _ = trivy(image, tid="app-0.21.4")
    borrow_source_chains(
        dict(enumerate(rows)),
        {"source-development": dev_inventory, "source-0.21.4": rel_inventory},
        [
            {"id": "source-development", "ref": "development"},
            {"id": "source-0.21.4", "ref": "0.21.4"},
        ],
        [{"id": "app-0.21.4", "ref": "0.21.4"}],
    )
    # the release's own graph wins over development's
    assert rows[0]["chain"] == ["rel", "jar"]


@pytest.mark.parametrize(
    ("git_tag", "registry_tag"),
    [("1.0.0-rc.1", "1.0.0-rc.1"), ("v1.0.0-rc.1", "1.0.0-rc.1")],
)
def test_an_image_of_a_hyphenated_tag_borrows_from_its_own_release_source(
    git_tag, registry_tag
):
    _, dev_inventory = trivy(
        result([package("top", depends_on=["jar"], rel="direct"), package("jar", rel="indirect")])
    )
    _, rel_inventory = trivy(
        result([package("rel", depends_on=["jar"], rel="direct"), package("jar", rel="indirect")]),
        tid="source-rc",
    )
    image = result([package("Jar")], [vuln("Jar")], target="app/jar", rtype="jar")
    rows, _ = trivy(image, tid="app-rc")
    borrow_source_chains(
        dict(enumerate(rows)),
        {"source-development": dev_inventory, "source-rc": rel_inventory},
        [
            {"id": "source-development", "ref": "development"},
            {"id": "source-rc", "ref": git_tag},
        ],
        [{"id": "app-rc", "ref": registry_tag}],
    )
    assert rows[0]["chain"] == ["rel", "jar"]


def osv_native(
    group_ids=("GHSA-aaaa",),
    aliases=("CVE-2026-9",),
    severity=None,
    score="7.5",
    source_type="sbom",
    **package_extra,
):
    record = {
        "id": group_ids[0],
        "summary": "A flaw",
        "database_specific": {"severity": severity} if severity else {},
        "affected": [
            {
                "package": {"name": "a"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "1.5"}],
                    }
                ],
            }
        ],
    }
    group = {"ids": list(group_ids), "aliases": list(aliases), "max_severity": score}
    package_entry = {
        "package": {"name": "a", "version": "1.0", "ecosystem": "npm", **package_extra},
        "vulnerabilities": [record],
        "groups": [group],
    }
    return {
        "results": [
            {"source": {"path": "x.cdx.json", "type": source_type}, "packages": [package_entry]}
        ]
    }


def test_osv_finding_takes_chain_dev_and_locations_from_the_trivy_inventory():
    pkgs = [
        package("top", depends_on=["a"], rel="direct"),
        package("a", rel="indirect", dev=True),
    ]
    _, inventory = trivy(result(pkgs))
    findings = {}
    normalize_osv(
        "source-development", osv_native(severity="MODERATE"), findings, inventory
    )
    (row,) = findings.values()
    assert (row["id"], row["aliases"], row["scanner"]) == (
        "CVE-2026-9",
        ["GHSA-aaaa"],
        "osv",
    )
    assert (row["severity"], row["fixed_version"]) == ("MEDIUM", "1.5")
    assert row["chain"] == ["top", "a"] and row["dev"] is True
    assert row["locations"] == ["package-lock.json"]
    assert row["url"] == "https://osv.dev/vulnerability/GHSA-aaaa"


def test_osv_severity_falls_back_to_the_score_and_a_missing_inventory_is_fine():
    findings = {}
    normalize_osv("t", osv_native(score="9.8"), findings, {})
    (row,) = findings.values()
    assert (
        row["severity"] == "CRITICAL" and row["chain"] == [] and row["locations"] == []
    )
    assert [severity_of_score(s) for s in ("4.0", "0.1", "0", "", None)] == [
        "MEDIUM",
        "LOW",
        "UNKNOWN",
        "UNKNOWN",
        "UNKNOWN",
    ]


def test_trivy_and_osv_rows_of_one_vulnerability_share_the_key_fields():
    pkgs = [package("a")]
    trivy_rows, inventory = trivy(
        result(pkgs, [vuln("a", "CVE-2026-9", VendorIDs=["GHSA-aaaa"])])
    )
    findings = {}
    normalize_osv("source-development", osv_native(), findings, inventory)
    (osv_row,) = findings.values()
    key = ("id", "pkg", "version")
    assert [trivy_rows[0][k] for k in key] == [osv_row[k] for k in key]


def osv_fixed(*ranges):
    native = osv_native()
    affected = native["results"][0]["packages"][0]["vulnerabilities"][0]["affected"]
    affected[0]["ranges"] = [
        {"type": t, "events": [{"fixed": f} for f in fixed]} for t, *fixed in ranges
    ]
    findings = {}
    normalize_osv("t", native, findings, {})
    return next(iter(findings.values()))["fixed_version"]


def test_osv_fixed_version_skips_git_ranges():
    assert osv_fixed(("GIT", "0123abc"), ("SEMVER", "1.5")) == "1.5"
    assert osv_fixed(("GIT", "0123abc")) == ""


def test_osv_fixed_version_lists_every_branch_once():
    assert osv_fixed(("ECOSYSTEM", "1.5"), ("SEMVER", "2.1", "1.5")) == "1.5, 2.1"


# --- the image scan rows --------------------------------------------------------


def osv_image_native():
    """One osv result of an OS source (Alpine apk DB) and one of an artifact source,
    as ``osv-scanner scan image`` writes them."""
    os_entry = {
        "package": {
            "name": "expat",
            "os_package_name": "libexpat",
            "version": "2.8.5-r0",
            "ecosystem": "Alpine:v3.24",
        },
        "vulnerabilities": [
            {
                "id": "ALPINE-CVE-2026-1",
                "summary": "A flaw in expat",
                "affected": [
                    {
                        "package": {"name": "expat"},
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [{"introduced": "0"}, {"fixed": "2.8.6-r0"}],
                            }
                        ],
                    }
                ],
            }
        ],
        "groups": [
            {
                "ids": ["ALPINE-CVE-2026-1"],
                "aliases": ["CVE-2026-1"],
                "max_severity": "5.9",
            }
        ],
    }
    artifact_entry = {
        "package": {"name": "requests", "version": "2.0.0", "ecosystem": "PyPI"},
        "vulnerabilities": [
            {
                "id": "GHSA-aaaa",
                "summary": "A flaw in requests",
                "affected": [
                    {
                        "package": {"name": "requests"},
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [{"introduced": "0"}, {"fixed": "2.1.0"}],
                            }
                        ],
                    }
                ],
            }
        ],
        "groups": [{"ids": ["GHSA-aaaa"], "aliases": [], "max_severity": "7.5"}],
    }
    return {
        "results": [
            {
                "source": {"path": "/lib/apk/db/installed", "type": "os"},
                "packages": [os_entry],
            },
            {
                "source": {"path": "/usr/lib/python/metadata", "type": "artifact"},
                "packages": [artifact_entry],
            },
        ]
    }


def test_osv_image_class_and_pkg_come_from_the_result_and_os_package_name():
    findings: dict = {}
    normalize_osv("app-development", osv_image_native(), findings, {})
    os_row = next(r for r in findings.values() if r["id"] == "CVE-2026-1")
    assert (os_row["class"], os_row["pkg"]) == ("os", "libexpat")
    assert os_row["ecosystem"] == "Alpine:v3.24"  # as osv-scanner gives it
    lang_row = next(r for r in findings.values() if r["id"] == "GHSA-aaaa")
    assert (lang_row["class"], lang_row["pkg"]) == ("lang", "requests")


def test_an_os_row_without_a_trivy_twin_is_empty_but_true():
    findings: dict = {}
    normalize_osv("app-development", osv_image_native(), findings, {})
    os_row = next(r for r in findings.values() if r["id"] == "CVE-2026-1")
    assert (os_row["chain"], os_row["dev"], os_row["relationship"]) == ([], False, None)
    assert os_row["locations"] == []


def test_osv_image_fixed_version_is_filtered_on_the_source_name():
    findings: dict = {}
    normalize_osv("app-development", osv_image_native(), findings, {})
    os_row = next(r for r in findings.values() if r["id"] == "CVE-2026-1")
    # the record is keyed by the source name `expat`, not the installed `libexpat`
    assert os_row["fixed_version"] == "2.8.6-r0"


# --- findings rules of schema 4 ---------------------------------------------------


def osv_record(rid, aliases=(), priority=None, fixed="1.0", published=None):
    return {
        "id": rid,
        "summary": f"about {rid}",
        "aliases": list(aliases),
        "published": published,
        "severity": [{"type": "Ubuntu", "score": priority}] if priority else [],
        "affected": [
            {
                "package": {"name": "a"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": fixed}],
                    }
                ],
            }
        ],
    }


def osv_os(records, *groups):
    """The OS findings of one package: ``groups`` are (ids, aliases) pairs."""
    entry = {
        "package": {"name": "a", "version": "1.0", "ecosystem": "Ubuntu:24.04"},
        "vulnerabilities": records,
        "groups": [
            {"ids": list(i), "aliases": list(a), "max_severity": "9.8"}
            for i, a in groups
        ],
    }
    source = {"path": "dpkg", "type": "os"}
    findings: dict = {}
    normalize_osv(
        "image-x", {"results": [{"source": source, "packages": [entry]}]}, findings, {}
    )
    assert len({r["id"] for r in findings.values()}) == len(findings)  # one row per CVE
    return {r["id"]: r for r in findings.values()}


def test_osv_lang_names_are_the_advisory_names_without_distro_bulletins():
    native = osv_native(aliases=("CVE-2026-9", "DLA-1-1", "USN-1-1"))
    entry = native["results"][0]["packages"][0]
    entry["vulnerabilities"][0]["published"] = "2026-02-03T00:00:00Z"
    entry["vulnerabilities"].append({"id": "x", "published": "2025-12-31T00:00:00Z"})
    entry["groups"][0]["ids"].append("x")
    findings: dict = {}
    normalize_osv("t", native, findings, {})
    (row,) = findings.values()
    assert row["id"] == "CVE-2026-9"
    assert row["names"] == ["CVE-2026-9", "GHSA-aaaa"]
    assert row["published"] == "2025-12-31"


def test_osv_os_bundle_gives_one_finding_per_own_cve_from_its_member():
    cves = [f"CVE-2026-{n}" for n in range(1, 7)]
    priorities = ["negligible", "low", "medium", "high", "critical", "medium"]
    records = [
        osv_record(
            f"UBUNTU-{c}", priority=p, fixed=f"1.{n}", published=f"2026-01-0{n + 1}"
        )
        for n, (c, p) in enumerate(zip(cves, priorities, strict=True))
    ]
    rows = osv_os(
        records, (["USN-8702-1", *(f"UBUNTU-{c}" for c in cves)], ["CVE-2026-7", *cves])
    )
    assert sorted(rows) == cves  # none for CVE-2026-7
    severities = ["LOW", "LOW", "MEDIUM", "HIGH", "CRITICAL", "MEDIUM"]
    assert [rows[c]["severity"] for c in cves] == severities
    assert [rows[c]["fixed_version"] for c in cves] == [f"1.{n}" for n in range(6)]
    assert rows[cves[2]]["published"] == "2026-01-03"
    assert rows[cves[0]]["url"] == "https://osv.dev/vulnerability/UBUNTU-CVE-2026-1"
    assert rows[cves[0]]["aliases"] == ["UBUNTU-CVE-2026-1"]
    assert all(r["names"] == [c] for c, r in rows.items())


def test_osv_os_member_aliases_with_an_advisory_name_are_names():
    rec = osv_record("UBUNTU-CVE-2026-1", ["GHSA-aaaa", "USN-1-1", "CVE-2026-2"])
    row = osv_os([rec], (["UBUNTU-CVE-2026-1"], []))["CVE-2026-1"]
    assert row["names"] == ["CVE-2026-1", "CVE-2026-2", "GHSA-aaaa"]


def test_osv_os_member_lookup_and_own_cve_forms():
    records = [
        osv_record("CVE-2026-2", fixed="2.0"),
        osv_record("UBUNTU-CVE-2026-2", priority="high", fixed="2.1"),
        osv_record("UBUNTU-CVE-2026-3", priority="low", fixed="3.0"),
    ]
    rows = osv_os(
        records,
        (["CVE-2026-1"], []),  # plain id, no record at all
        (["CVE-2026-2", "UBUNTU-CVE-2026-2"], []),  # two ids, one CVE
        (["USN-1-1", "UBUNTU-CVE-2026-3"], []),
        (["UBUNTU-CVE-2026-3"], []),  # the same CVE from a second group
    )
    assert sorted(rows) == ["CVE-2026-1", "CVE-2026-2", "CVE-2026-3"]
    # the record with the Ubuntu priority wins over the plain CVE record
    assert (rows["CVE-2026-2"]["severity"], rows["CVE-2026-2"]["fixed_version"]) == (
        "HIGH",
        "2.1",
    )
    assert rows["CVE-2026-3"]["severity"] == "LOW"  # found, though not by group ids


def test_osv_os_cve_without_a_record_is_unknown_and_empty():
    row = osv_os([], (["USN-1-1", "UBUNTU-CVE-2026-1"], []))["CVE-2026-1"]
    assert (row["severity"], row["fixed_version"], row["published"]) == (
        "UNKNOWN",
        "",
        None,
    )
    assert row["url"].endswith("UBUNTU-CVE-2026-1")
    assert (row["aliases"], row["names"], row["title"]) == (
        ["UBUNTU-CVE-2026-1"],
        ["CVE-2026-1"],
        "",
    )


def test_osv_os_group_with_only_bulletins_is_one_unknown_finding():
    records = [
        osv_record("USN-2-1", published="2026-05-06"),
        osv_record("USN-1-1", published="2026-04-05"),
    ]
    rows = osv_os(records, (["USN-2-1", "USN-1-1"], ["CVE-2026-5"]))
    (row,) = rows.values()
    assert (row["id"], row["severity"]) == ("USN-1-1", "UNKNOWN")
    assert row["names"] == ["USN-1-1"]
    assert row["aliases"] == ["USN-2-1", "CVE-2026-5"]
    assert (row["fixed_version"], row["published"]) == ("1.0", "2026-04-05")


def test_osv_os_severity_is_the_ubuntu_priority_never_the_cvss_bucket():
    records = [
        osv_record("UBUNTU-CVE-2026-1", priority="negligible"),
        osv_record("DEBIAN-CVE-2026-2"),
    ]
    rows = osv_os(records, (["UBUNTU-CVE-2026-1"], []), (["DEBIAN-CVE-2026-2"], []))
    assert (rows["CVE-2026-1"]["severity"], rows["CVE-2026-2"]["severity"]) == (
        "LOW",
        "UNKNOWN",
    )


def test_normalize_trivy_returns_every_package_of_both_classes():
    os_result = {
        "Target": "ubuntu",
        "Type": "ubuntu",
        "Class": "os-pkgs",
        "Packages": [
            {"Name": "bsdutils", "Version": "2.39", "Release": "9u1", "Epoch": 1},
            {"Name": "musl", "Version": "1.2"},
        ],
    }
    lang = result([{"ID": "a@1", "Name": "A_b", "Version": "1"}])
    seen = normalize_trivy("t", {"Results": [lang, os_result]}, {}, {})
    assert seen == {
        ("lang", "a-b", "1"),
        ("os", "bsdutils", "1:2.39-9u1"),
        ("os", "musl", "1.2"),
    }


def cvss_of(cvss, **extra):
    rows, _ = trivy(result([package("lib")], [vuln("lib", CVSS=cvss, **extra)]))
    return rows[0]["cvss"]


def test_trivy_cvss_vendor_priority_and_v3_before_v4():
    v3 = {"V3Score": 7.5, "V3Vector": "CVSS:3.1/a"}
    v4 = {"V40Score": 8.1, "V40Vector": "CVSS:4.0/b"}
    got = cvss_of({"redhat": v3, "ghsa": v3, "nvd": v3, "zeta": v3})
    assert got == {"score": 7.5, "vector": "CVSS:3.1/a", "source": "nvd"}
    assert cvss_of({"redhat": v3, "zeta": v3})["source"] == "redhat"
    assert cvss_of({"zeta": v3, "alpha": v3})["source"] == "alpha"
    # a v3 of a lower-priority vendor beats the v4 of nvd
    assert cvss_of({"nvd": v4, "redhat": v3})["source"] == "redhat"
    assert cvss_of({"nvd": v4}) == {
        "score": 8.1,
        "vector": "CVSS:4.0/b",
        "source": "nvd",
    }
    assert cvss_of({"nvd": {"V2Score": 5.0, "V2Vector": "AV:N"}}) is None
    assert cvss_of({}) is None


def test_trivy_modified_is_the_date_of_last_modified():
    stamp = "2026-08-31T18:17:13.083Z"
    rows, _ = trivy(result([package("lib")], [vuln("lib", LastModifiedDate=stamp)]))
    assert rows[0]["modified"] == "2026-08-31"
    rows, _ = trivy(result([package("lib")], [vuln("lib")]))
    assert rows[0]["modified"] is None


def test_osv_cvss_is_a_vector_without_a_score_and_modified_is_the_latest():
    native = osv_native()
    entry = native["results"][0]["packages"][0]
    entry["vulnerabilities"][0] |= {
        "modified": "2026-05-01T00:00:00Z",
        "severity": [
            {"type": "CVSS_V4", "score": "CVSS:4.0/z"},
            {"type": "CVSS_V3", "score": "CVSS:3.1/y"},
        ],
    }
    findings = {}
    normalize_osv("t", native, findings, {})
    (row,) = findings.values()
    assert row["cvss"] == {"score": None, "vector": "CVSS:3.1/y", "source": "osv"}
    assert row["modified"] == "2026-05-01"
    v4 = [{"type": "CVSS_V4", "score": "CVSS:4.0/z"}]
    entry["vulnerabilities"][0]["severity"] = v4
    findings = {}
    normalize_osv("t", native, findings, {})
    assert next(iter(findings.values()))["cvss"]["vector"] == "CVSS:4.0/z"
    entry["vulnerabilities"][0].pop("severity")
    findings = {}
    normalize_osv("t", native, findings, {})
    assert next(iter(findings.values()))["cvss"] is None


def test_lang_cvss_comes_from_the_member_that_gives_the_rating():
    native = osv_native(group_ids=("GHSA-aaaa", "PYSEC-1"), severity="HIGH")
    entry = native["results"][0]["packages"][0]
    first, rated = entry["vulnerabilities"][0], {**entry["vulnerabilities"][0]}
    first["database_specific"] = {}
    first["severity"] = [{"type": "CVSS_V3", "score": "CVSS:3.1/plain"}]
    rated |= {"id": "PYSEC-1", "database_specific": {"severity": "HIGH"}}
    rated["severity"] = [{"type": "CVSS_V3", "score": "CVSS:3.1/rated"}]
    entry["vulnerabilities"] = [first, rated]
    findings = {}
    normalize_osv("t", native, findings, {})
    (row,) = findings.values()
    assert row["severity"] == "HIGH" and row["cvss"]["vector"] == "CVSS:3.1/rated"


def test_os_bundle_cves_take_the_vector_of_their_own_record():
    native = osv_image_native()
    entry = native["results"][0]["packages"][0]
    first = entry["vulnerabilities"][0]
    second = {**first, "id": "ALPINE-CVE-2026-2"}
    first["severity"] = [{"type": "CVSS_V3", "score": "CVSS:3.1/one"}]
    second["severity"] = [{"type": "CVSS_V3", "score": "CVSS:3.1/two"}]
    entry["vulnerabilities"].append(second)
    ids = ["ALPINE-CVE-2026-1", "ALPINE-CVE-2026-2"]
    entry["groups"] = [{"ids": ids, "aliases": []}]
    findings = {}
    normalize_osv("app-development", native, findings, {})
    rows = [r for r in findings.values() if r["class"] == "os"]
    vectors = {r["id"]: r["cvss"]["vector"] for r in rows}
    assert vectors == {"CVE-2026-1": "CVSS:3.1/one", "CVE-2026-2": "CVSS:3.1/two"}
