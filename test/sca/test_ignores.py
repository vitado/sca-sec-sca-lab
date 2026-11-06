"""Risk acceptance from .trivyignore: outcomes, grammar, expiry, matching."""

import json

from ignores import add_ignores, parse_line
from test_merge_results import Run, target, trivy_native

TODAY = "2026-10-14"
VULN = {
    "VulnerabilityID": "CVE-2026-1",
    "PkgName": "lodash",
    "InstalledVersion": "1.0",
    "Severity": "HIGH",
}
SRC = "source-development"
NONE = {"reason": None}


def merge(tmp_path, ignorefile="present", text=None, status="ok"):
    run = Run(tmp_path, [target(SRC, "trivy")])
    state = {"status": status}
    if status == "failed":
        state["reason"] = "boom"
    if ignorefile != "no key":
        state["ignorefile"] = ignorefile
    run.part("trivy", SRC, trivy_native([VULN]) if status == "ok" else None, state)
    if text is not None:
        (run.parts / "trivy" / f"{SRC}.trivyignore").write_text(text)
    _, report = run.merge()
    return run, report


def accepted(report):
    return report["versions"][0]["vulns"][0]["accepted"]


def src(tid=SRC, ref="development", kind="fs"):
    return {"id": tid, "scanner": "trivy", "kind": kind, "ref": ref}


def add(tmp_path, text, names=(["CVE-1"],), state="present", targets=None, **extra):
    """add_ignores on a synthetic report; ``text`` None writes no ignore file."""
    parts = tmp_path / "trivy"
    parts.mkdir(exist_ok=True)
    (parts / f"{SRC}.status.json").write_text(json.dumps({"ignorefile": state}))
    if text is not None:
        (parts / f"{SRC}.trivyignore").write_text(text, encoding="utf-8")
    report = {
        "default_branch": "development",
        "generated_utc": TODAY + "T00:00:00Z",
        "targets": targets or [src()],
        "versions": [{"vulns": [{"names": n, "accepted": None} for n in names]}],
        **extra,
    }
    add_ignores(report, tmp_path)
    return report


def accepted_of(report):
    return [v["accepted"] for v in report["versions"][0]["vulns"]]


# --- outcomes ---


def test_absent_is_an_empty_list(tmp_path):
    _, report = merge(tmp_path, "absent")
    assert report["ignores"] == [] and report["ignores_error"] is None
    assert accepted(report) is None


def test_null_means_checkout_failed(tmp_path):
    _, report = merge(tmp_path, None)
    assert (report["ignores"], report["ignores_error"]) == (None, "checkout failed")
    assert accepted(report) is None


def test_old_workflow_has_no_key(tmp_path):
    _, report = merge(tmp_path, "no key")
    assert report["ignores"] is None
    assert report["ignores_error"] == "the workflow does not pass the ignore file"


def versioned(tid, ref):
    return {**target(tid, "trivy"), "git_ref": ref}


def test_no_default_branch_target_and_several_sources(tmp_path):
    run = Run(tmp_path, [versioned("source-1.0", "1.0"), versioned("source-2.0", "2.0")])
    for tid in ("source-1.0", "source-2.0"):
        run.part("trivy", tid, trivy_native([VULN]), {"status": "ok", "ignorefile": "absent"})
    _, report = run.merge()
    assert report["ignores"] is None
    assert report["ignores_error"] == "no default-branch target in this run"


def test_the_only_source_of_a_run_is_read_whatever_its_ref(tmp_path):
    run = Run(tmp_path, [versioned("source-1.0", "1.0")])
    state = {"status": "ok", "ignorefile": "present"}
    run.part("trivy", "source-1.0", trivy_native([VULN]), state)
    (run.parts / "trivy" / "source-1.0.trivyignore").write_text("# why\nCVE-2026-1 exp:2099-01-01\n")
    _, report = run.merge()
    assert report["ignores_error"] is None
    assert [(e["id"], e["matched"], e["reason"]) for e in report["ignores"]] == [
        ("CVE-2026-1", True, "why")
    ]
    assert report["versions"][0]["vulns"][0]["accepted"] == {"until": "2099-01-01"}


def test_the_default_branch_source_wins_over_a_version_source(tmp_path):
    run = Run(tmp_path, [target(SRC, "trivy"), versioned("source-1.0", "1.0")])
    run.part("trivy", SRC, trivy_native([VULN]), {"status": "ok", "ignorefile": "present"})
    run.part("trivy", "source-1.0", trivy_native([VULN]), {"status": "ok", "ignorefile": "absent"})
    (run.parts / "trivy" / f"{SRC}.trivyignore").write_text("CVE-2026-1 exp:2099-01-01\n")
    _, report = run.merge()
    assert report["ignores_error"] is None and len(report["ignores"]) == 1


def test_a_run_without_a_source_target_has_no_error(tmp_path):
    image = {**target("image-1.0", "trivy", "image"), "tag": "1.0"}
    run = Run(tmp_path, [image])
    run.part("trivy", "image-1.0", trivy_native([VULN]), {"status": "ok"})
    _, report = run.merge()
    assert report["ignores"] is None and report["ignores_error"] is None


def test_present_but_file_missing(tmp_path):
    _, report = merge(tmp_path, "present")
    assert report["ignores"] is None
    assert SRC in report["ignores_error"] and "unreadable" in report["ignores_error"]


def test_a_failed_scan_with_a_checkout_still_reads_the_file(tmp_path):
    _, report = merge(tmp_path, "present", "CVE-2026-1 exp:2026-12-31\n", "failed")
    assert report["ignores_error"] is None
    assert [e["id"] for e in report["ignores"]] == ["CVE-2026-1"]


def test_present_file_is_parsed_accepted_and_copied(tmp_path):
    text = "CVE-2026-1 exp:2026-12-31\nCVE-9 exp:2027-01-01\n"
    run, report = merge(tmp_path, "present", text)
    flags = {"bad_expiry": False, "no_expiry": False, "expired": False}
    assert report["ignores"] == [
        {"id": "CVE-2026-1", "until": "2026-12-31", **flags, "matched": True} | NONE,
        {"id": "CVE-9", "until": "2027-01-01", **flags, "matched": False} | NONE,
    ]
    assert accepted(report) == {"until": "2026-12-31"}
    assert (run.out / "_native/trivy" / f"{SRC}.trivyignore").is_file()


def test_an_unexpected_ignorefile_value_is_an_error(tmp_path):
    report = add(tmp_path, None, state="maybe")
    assert report["ignores"] is None
    assert report["ignores_error"] == "unexpected ignorefile value: 'maybe'"


def test_an_unreadable_or_non_object_status_file_is_named(tmp_path):
    for body in ("{not json", "[1]", ""):
        report = add(tmp_path, None)
        (tmp_path / "trivy" / f"{SRC}.status.json").write_text(body)
        add_ignores(report, tmp_path)
        assert report["ignores"] is None
        assert report["ignores_error"] == f"no readable status file for {SRC}"
    (tmp_path / "trivy" / f"{SRC}.status.json").unlink()
    add_ignores(report, tmp_path)
    assert report["ignores_error"] == f"no readable status file for {SRC}"


def test_the_unreadable_file_reason_has_no_path(tmp_path):
    report = add(tmp_path, None)
    assert report["ignores"] is None
    assert str(tmp_path) not in report["ignores_error"]
    assert report["ignores_error"].startswith(f"the ignore file of {SRC} is unreadable")


def test_a_stray_bad_byte_does_not_drop_the_acceptances(tmp_path):
    report = add(tmp_path, "")
    ignorefile = tmp_path / "trivy" / f"{SRC}.trivyignore"
    ignorefile.write_bytes(b"# caf\xe9\nCVE-1 exp:2026-12-31\n")
    add_ignores(report, tmp_path)
    assert accepted_of(report) == [{"until": "2026-12-31"}]


def test_the_default_branch_is_taken_from_the_report_and_only_fs_counts(tmp_path):
    image = src("app-main", "main", "image")
    targets = [image, src(ref="main")]
    text = "CVE-1 exp:2026-12-31\n"
    report = add(tmp_path, text, targets=targets, default_branch="main")
    assert report["ignores_error"] is None and len(report["ignores"]) == 1
    # only an image target on the default branch: no source target, nothing to read
    report = add(tmp_path, text, targets=[image], default_branch="main")
    assert report["ignores"] is None and report["ignores_error"] is None


# --- grammar ---


def test_comments_and_blank_lines_are_skipped():
    assert parse_line("", TODAY) is None
    assert parse_line("   ", TODAY) is None
    assert parse_line("  # CVE-1 exp:2027-01-01", TODAY) is None


def test_extra_tokens_are_ignored():
    e = parse_line(
        "CVE-2025-59250 pkg:maven/com.microsoft.sqlserver/mssql-jdbc exp:2026-12-31",
        TODAY,
    )
    assert (e["id"], e["until"], e["bad_expiry"], e["no_expiry"]) == (
        "CVE-2025-59250",
        "2026-12-31",
        False,
        False,
    )


def test_bad_date_is_flagged_and_does_not_act(tmp_path):
    for bad in ("exp:2026-13-01", "exp:soon", "exp:", "exp:2026-1-1"):
        e = parse_line(f"CVE-1 {bad}", TODAY)
        assert e["bad_expiry"] and e["until"] is None and not e["no_expiry"]
        assert accepted_of(add(tmp_path, f"CVE-1 {bad}\n")) == [None]


def test_the_first_exp_field_counts():
    assert parse_line("CVE-1 exp:2026-01-01 exp:2027-12-31", TODAY)["expired"]
    e = parse_line("CVE-1 exp:bad exp:2027-12-31", TODAY)
    assert e["bad_expiry"] and e["until"] is None and not e["expired"]


def test_lines_split_on_newline_only(tmp_path):
    report = add(tmp_path, "CVE-1 exp:2026-12-31\r\nCVE-2\x0bCVE-3\n")
    assert [e["id"] for e in report["ignores"]] == ["CVE-1", "CVE-2"]


def test_no_expiry_is_not_an_acceptance_but_matches(tmp_path):
    report = add(tmp_path, "CVE-1\n")
    (e,) = report["ignores"]
    assert e["no_expiry"] and e["until"] is None and not e["bad_expiry"]
    assert accepted_of(report) == [None] and e["matched"]


# --- expiry, duplicates, names ---


def test_acts_the_day_before_not_on_the_exp_day(tmp_path):
    report = add(tmp_path, "CVE-1 exp:2026-10-15\n")
    assert accepted_of(report) == [{"until": "2026-10-15"}]
    assert not report["ignores"][0]["expired"]
    report = add(tmp_path, "CVE-1 exp:2026-10-14\n")
    assert accepted_of(report) == [None] and report["ignores"][0]["expired"]


def test_duplicates_give_the_earliest_acting_until(tmp_path):
    text = "CVE-1 exp:2027-05-01\nCVE-1 exp:2026-11-01\nCVE-1 exp:2026-01-01\n"
    assert accepted_of(add(tmp_path, text)) == [{"until": "2026-11-01"}]


def test_a_ghsa_line_accepts_a_record_through_names_and_matched_is_set(tmp_path):
    text = "GHSA-aaaa exp:2027-01-01\nCVE-404 exp:2027-01-01\n"
    names = (["CVE-1", "GHSA-aaaa"], ["CVE-2"])
    report = add(tmp_path, text, names)
    assert accepted_of(report) == [{"until": "2027-01-01"}, None]
    assert [e["matched"] for e in report["ignores"]] == [True, False]


def test_matched_counts_a_record_of_any_version(tmp_path):
    report = add(tmp_path, "CVE-2 exp:2027-01-01\n")
    report["versions"].append({"vulns": [{"names": ["CVE-2"], "accepted": None}]})
    add_ignores(report, tmp_path)
    assert report["ignores"][0]["matched"]
    assert report["versions"][1]["vulns"][0]["accepted"] == {"until": "2027-01-01"}


def reasons(tmp_path, text):
    return [(e["id"], e["reason"]) for e in add(tmp_path, text)["ignores"]]


def test_reason_is_the_comment_block_above_the_line(tmp_path):
    text = "# postponed: waiting\n  #  for the vendor \n#\n#### fix in Q4\n"
    assert reasons(tmp_path, text + "CVE-1 exp:2027-01-01\n") == [
        ("CVE-1", "postponed: waiting for the vendor fix in Q4")
    ]


def test_a_blank_line_or_an_ignore_line_ends_the_block(tmp_path):
    text = "# lost\n\nCVE-1\n# own\nCVE-2\nCVE-3\n# trailing\n"
    assert reasons(tmp_path, text) == [
        ("CVE-1", None),
        ("CVE-2", "own"),
        ("CVE-3", None),
    ]


def test_the_comment_above_a_bad_or_missing_expiry_is_its_reason(tmp_path):
    report = add(tmp_path, "# why\nCVE-1 exp:soon\n# also\nCVE-2\n")
    got = [(e["bad_expiry"], e["no_expiry"], e["reason"]) for e in report["ignores"]]
    assert got == [(True, False, "why"), (False, True, "also")]


def test_a_comment_never_acts(tmp_path):
    report = add(tmp_path, "# CVE-1 exp:2027-01-01\n")
    assert report["ignores"] == [] and accepted_of(report) == [None]


def test_crlf_lines_and_comments(tmp_path):
    report = add(tmp_path, "")
    ignorefile = tmp_path / "trivy" / f"{SRC}.trivyignore"
    ignorefile.write_bytes(b"# why\r\n#  more\r\nCVE-1 exp:2027-01-01\r\n")
    add_ignores(report, tmp_path)
    (entry,) = report["ignores"]
    assert (entry["id"], entry["until"], entry["reason"]) == (
        "CVE-1",
        "2027-01-01",
        "why more",
    )
