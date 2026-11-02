from typing import Any

import pytest
from helpers import development, report, version
from reports import ReportError, merge_reports


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
