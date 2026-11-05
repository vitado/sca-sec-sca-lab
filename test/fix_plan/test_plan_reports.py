from typing import Any

import pytest
from helpers import development, report, target, version
from sca_fix_plan import ReportError, merge_reports


def test_merge_by_ref() -> None:
    merged = merge_reports(
        [report(version("1.2.3")), report(development(), version("1.1.0"))]
    )
    assert [v.ref for v in merged.versions] == ["1.2.3", "development", "1.1.0"]
    assert merged.repo == "o/r"
    assert merged.sources[1]["refs"] == ["development", "1.1.0"]
    assert merged.versions[0].targets["source-1.2.3"]["status"] == "ok"


def test_osv_twin_does_not_replace_trivy_target() -> None:
    raw = report(version("1.2.3"))
    twin = {**raw["targets"][0], "scanner": "osv", "status": "failed"}
    raw["targets"].insert(0, twin)
    assert merge_reports([raw]).versions[0].targets["source-1.2.3"]["status"] == "ok"


@pytest.mark.parametrize(
    ("reports", "message"),
    [
        ([], "no report"),
        ([report(version("1.2.3"), schema_version=3)], "schema_version 3"),
        (
            [report(version("1.2.3")), report(version("1.1.0"), repo="o/other")],
            "different repos",
        ),
        (
            [report(version("1.2.3")), report(version("1.2.3"))],
            "1.2.3 is in more than one",
        ),
    ],
)
def test_errors(reports: list[dict[str, Any]], message: str) -> None:
    with pytest.raises(ReportError, match=message):
        merge_reports(reports)


def at_commit(ref: str, commit: str, kind: str = "release") -> dict[str, Any]:
    return version(ref, kind, targets=[target(f"source-{ref}", commit_sha=commit)])


def test_same_ref_at_the_same_commit_is_taken_once() -> None:
    merged = merge_reports(
        [
            report(at_commit("1.1.19", "abc")),
            report(development(), at_commit("1.1.19", "abc")),
        ]
    )
    assert [v.ref for v in merged.versions] == ["1.1.19", "development"]
    assert merged.sources[0]["refs"] == ["1.1.19"]
    assert "ignored_refs" not in merged.sources[0]
    assert merged.sources[1]["ignored_refs"] == [
        {
            "ref": "1.1.19",
            "reason": "same ref and commit as an earlier report",
            "reason_code": "same_ref_same_commit",
        }
    ]


@pytest.mark.parametrize("second", ["def", None])
def test_same_ref_at_another_or_unknown_commit_is_an_error(
    second: str | None,
) -> None:
    other = at_commit("1.1.19", "def") if second else version("1.1.19")
    with pytest.raises(ReportError, match="not at the same source commit"):
        merge_reports([report(at_commit("1.1.19", "abc")), report(other)])


def test_earlier_report_keeps_its_line() -> None:
    merged = merge_reports(
        [
            report(at_commit("1.2.18", "abc")),
            report(
                development(), at_commit("1.2.22", "def"), at_commit("1.1.19", "ghi")
            ),
        ]
    )
    assert [v.ref for v in merged.versions] == ["1.2.18", "development", "1.1.19"]
    assert merged.sources[1]["ignored_refs"] == [
        {
            "ref": "1.2.22",
            "reason": "line 1.2 is given by an earlier report",
            "reason_code": "line_in_earlier_report",
        }
    ]
