import json
from pathlib import Path

import pytest
from helpers import development, record, report, version
from sca_fix_plan import cli as fix_plan


def write_reports(tmp_path: Path) -> list[str]:
    rel = version("1.2.3", vulns=[record("lib|x", "1.0.0", "1.0.5")])
    paths = []
    for name, raw in (("a.json", report(rel)), ("b.json", report(development()))):
        (tmp_path / name).write_text(json.dumps(raw), encoding="utf-8")
        paths.append(str(tmp_path / name))
    return paths


def test_writes_json_and_markdown(tmp_path: Path) -> None:
    out = tmp_path / "out"
    code = fix_plan.main(
        ["--reports", *write_reports(tmp_path), "--output-dir", str(out)]
    )
    assert code == 0
    text = (out / "fix-plan.json").read_text(encoding="utf-8")
    assert text.endswith("}\n")
    assert text == json.dumps(json.loads(text), indent=1, sort_keys=True) + "\n"
    markdown = (out / "fix-plan.md").read_text(encoding="utf-8")
    assert "## Line 1.2 (1.2.3, release), branch `release-1.2`" in markdown
    assert "| lib\\|x | lang | 1.0.0 -> 1.0.5 | dependabot |" in markdown


def test_same_input_same_output(tmp_path: Path) -> None:
    paths = write_reports(tmp_path)
    for name in ("one", "two"):
        fix_plan.main(["--reports", *paths, "--output-dir", str(tmp_path / name)])
    for name in ("fix-plan.json", "fix-plan.md"):
        assert (tmp_path / "one" / name).read_bytes() == (
            tmp_path / "two" / name
        ).read_bytes()


def test_errors_exit_1(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    paths = write_reports(tmp_path)
    out = str(tmp_path / "out")
    assert (
        fix_plan.main(
            ["--reports", *paths, "--config", '{"x": 1}', "--output-dir", out]
        )
        == 1
    )
    assert "unknown key x" in capsys.readouterr().err
    assert fix_plan.main(["--reports", paths[0], "--output-dir", out]) == 1
    assert "development" in capsys.readouterr().err
    assert not (tmp_path / "out").exists()
