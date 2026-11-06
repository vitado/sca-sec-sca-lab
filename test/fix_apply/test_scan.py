"""The detector (recorded Trivy and osv-scanner outputs through the engine's code, N6.1)
and the gate on its records (N6.2, N6.3).
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from apply import process_line
from builders import file, finding, item, line, outcome, tools
from scan import (
    Finding,
    ScanError,
    detect,
    gate,
    new_serious,
    scan_image,
    scan_tree,
    tool_versions,
)
from test_apply import lockfile_tree


def trivy_doc(*vulns: tuple[str, str, str, str]) -> dict[str, Any]:
    """A ``trivy fs --format json`` result: (package, version, id, severity)."""
    return {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "package-lock.json",
                "Class": "lang-pkgs",
                "Type": "npm",
                "Packages": [
                    {"ID": f"{n}@{v}", "Name": n, "Version": v} for n, v, *_ in vulns
                ],
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": vid,
                        "PkgName": name,
                        "InstalledVersion": version,
                        "Severity": severity,
                    }
                    for name, version, vid, severity in vulns
                ],
            }
        ],
    }


def osv_doc(*groups: tuple[str, str, list[str], list[str], str]) -> dict[str, Any]:
    """An ``osv-scanner --format json`` result: (package, version, group ids, aliases,
    the severity the database gives).
    """
    return {
        "results": [
            {
                "source": {"path": "package-lock.json", "type": "lockfile"},
                "packages": [
                    {
                        "package": {"name": n, "version": v, "ecosystem": "npm"},
                        "vulnerabilities": [
                            {
                                "id": i,
                                "aliases": aliases,
                                "database_specific": {"severity": severity},
                            }
                            for i in ids
                        ],
                        "groups": [
                            {"ids": ids, "aliases": aliases, "max_severity": "7.5"}
                        ],
                    }
                    for n, v, ids, aliases, severity in groups
                ],
            }
        ]
    }


def fake_tools(osv: dict[str, Any], osv_exit: int = 1, convert_exit: int = 0) -> Any:
    """``trivy convert`` writes a BOM of the Trivy result's packages, osv-scanner the
    recorded result: no tool is started.
    """

    def run(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        if command[0] == "trivy":
            native = json.loads(Path(command[-1]).read_text(encoding="utf-8"))
            components = [
                {
                    "name": p["Name"],
                    "version": p["Version"],
                    "purl": f"pkg:npm/{p['Name']}@{p['Version']}",
                }
                for r in native["Results"]
                for p in r["Packages"]
            ]
            Path(command[command.index("--output") + 1]).write_text(
                json.dumps({"components": components}), encoding="utf-8"
            )
            return subprocess.CompletedProcess(command, convert_exit, "", "convert")
        Path(command[command.index("--output-file") + 1]).write_text(
            json.dumps(osv), encoding="utf-8"
        )
        return subprocess.CompletedProcess(command, osv_exit, "", "osv-scanner broke")

    return run


def detected(
    tmp_path: Path, trivy: dict[str, Any], osv: dict[str, Any], **exits: int
) -> set[Finding]:
    native = tmp_path / "trivy.json"
    native.write_text(json.dumps(trivy), encoding="utf-8")
    return detect(tmp_path, native, run=fake_tools(osv, **exits))


HONO = ("hono", "2.0.12", "CVE-hono", "HIGH")
OTHER = ("leftpad", "1.0.0", "CVE-other", "LOW")  # keeps leftpad in Trivy's packages
LEFTPAD_OSV = osv_doc(("leftpad", "1.0.0", ["GHSA-leftpad"], ["CVE-leftpad"], "HIGH"))
NOTHING = osv_doc()


def test_n6_1_records_come_from_trivy_and_osv_merged_by_the_engine(
    tmp_path: Path,
) -> None:
    both = osv_doc(("hono", "2.0.12", ["GHSA-hono"], ["CVE-hono"], "MODERATE"))
    assert detected(tmp_path, trivy_doc(HONO), both) == {
        Finding(
            "hono",
            "2.0.12",
            "CVE-hono",
            "HIGH",
            "lang",
            frozenset({"CVE-hono", "GHSA-hono"}),
        )
    }


def test_n6_1_osv_only_record_is_detected(tmp_path: Path) -> None:
    found = detected(tmp_path, trivy_doc(OTHER), LEFTPAD_OSV)
    assert {(f.pkg, f.id, f.severity) for f in found} == {
        ("leftpad", "CVE-leftpad", "HIGH"),
        ("leftpad", "CVE-other", "LOW"),
    }


@pytest.mark.parametrize("exits", [{"osv_exit": 2}, {"convert_exit": 1}])
def test_n6_1_scanner_failure_fails_the_detector(
    tmp_path: Path, exits: dict[str, int]
) -> None:
    with pytest.raises(ScanError, match="failed"):
        detected(tmp_path, trivy_doc(HONO), NOTHING, **exits)


def lockfile_command(
    monkeypatch: pytest.MonkeyPatch, exit_code: int, writes: bool = False
) -> None:
    """The lockfile command of the build ends with ``exit_code``; ``writes`` makes it
    leave a ``gradle.lockfile`` in its working directory (the tree copy).
    """

    def run(command: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if writes:
            (Path(kwargs["cwd"]) / "gradle.lockfile").write_text("", encoding="utf-8")
        return subprocess.CompletedProcess(command, exit_code, "", "no")

    monkeypatch.setattr("scan.subprocess.run", run)


def test_n6_1_gradle_build_without_a_lockfile_fails_the_detector(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lockfile_command(monkeypatch, 0)
    with pytest.raises(ScanError, match="no gradle.lockfile"):
        scan_tree(tmp_path, "./gradlew")


def test_n6_1_failed_lockfile_command_fails_the_detector(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lockfile_command(monkeypatch, 3, writes=True)
    with pytest.raises(ScanError, match="lockfile generation failed"):
        scan_tree(tmp_path, "./gradlew")


def test_n6_1_gradle_build_with_a_lockfile_goes_on_to_trivy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lockfile_command(monkeypatch, 0, writes=True)
    with pytest.raises(ScanError, match="trivy fs failed"):
        scan_tree(tmp_path, "./gradlew")


def leftpad(
    tmp_path: Path, baseline: set[Finding], after: set[Finding]
) -> dict[str, Any]:
    result = process_line(
        line(item("leftpad", fallback=None)),
        "o/r",
        lockfile_tree(tmp_path),
        tools(lambda job, manager: outcome(file("new")), [baseline, after]),
    )
    return result["items"][0]


def test_n6_3_osv_only_record_in_the_baseline_and_gone_after_is_applied(
    tmp_path: Path,
) -> None:
    baseline = detected(tmp_path, trivy_doc(OTHER), LEFTPAD_OSV)
    after = detected(tmp_path, trivy_doc(OTHER), NOTHING)
    assert leftpad(tmp_path, baseline, after)["status"] == "applied"


def test_n6_3_osv_only_record_not_in_the_baseline_is_already_fixed(
    tmp_path: Path,
) -> None:
    baseline = detected(tmp_path, trivy_doc(OTHER), NOTHING)
    record = leftpad(tmp_path, baseline, baseline)
    assert (record["status"], record["reason_code"]) == (
        "already_fixed",
        "not_in_baseline",
    )


def test_n6_2_osv_record_matches_by_the_alias_of_the_plan(tmp_path: Path) -> None:
    # the plan knows the vulnerability as ALIAS-leftpad, the detector as the group GHSA-leftpad
    osv = osv_doc(("leftpad", "1.0.0", ["GHSA-leftpad"], ["ALIAS-leftpad"], "HIGH"))
    found = detected(tmp_path, trivy_doc(OTHER), osv)
    assert "still present" in str(gate(item("leftpad"), found, found, found))
    assert gate(item("leftpad"), found, set(), found) is None


def test_n6_3_new_serious_osv_only_record_is_gate_new_serious(tmp_path: Path) -> None:
    baseline = detected(tmp_path, trivy_doc(OTHER), LEFTPAD_OSV)
    new = osv_doc(("newpkg", "1.0.0", ["GHSA-new"], ["CVE-new"], "CRITICAL"))
    after = detected(
        tmp_path, trivy_doc(OTHER, ("newpkg", "1.0.0", "CVE-low", "LOW")), new
    )
    record = leftpad(tmp_path, baseline, after)
    assert (record["status"], record["reason_code"]) == ("manual", "gate_new_serious")
    assert "newpkg CVE-new" in record["reason"]


def test_n6_3_osv_failure_after_the_change_is_rescan_failed(tmp_path: Path) -> None:
    scans = [
        lambda: detected(tmp_path, trivy_doc(HONO), NOTHING),
        lambda: detected(tmp_path, trivy_doc(HONO), NOTHING, osv_exit=2),
    ]
    fake = replace(
        tools(lambda job, manager: outcome(file("new")), []),
        scan_tree=lambda: scans.pop(0)(),
    )
    result = process_line(line(item()), "o/r", lockfile_tree(tmp_path), fake)
    record = result["items"][0]
    assert record["reason_code"] == "rescan_failed"
    assert "osv-scanner failed" in record["reason"]


def test_n6_1_osv_failure_of_the_baseline_fails_the_line(tmp_path: Path) -> None:
    fake = replace(
        tools(lambda job, manager: outcome(), []),
        scan_tree=lambda: detected(tmp_path, trivy_doc(HONO), NOTHING, osv_exit=2),
    )
    with pytest.raises(ScanError):
        process_line(line(item()), "o/r", lockfile_tree(tmp_path), fake)


def test_n6_3_gate_passes_when_the_vulnerability_is_gone() -> None:
    vuln = finding()
    assert gate(item(), {vuln}, set(), {vuln}) is None


def test_n6_2_gate_matches_by_alias_and_normalized_package_name() -> None:
    before = {finding("Hono", "GHSA-hono")}
    assert gate(item(), before, set(), before) is None
    aliased = {Finding("hono", "1", "CVE-x", "HIGH", "lang", frozenset({"ALIAS-hono"}))}
    assert gate(item(), aliased, set(), aliased) is None


def test_n6_2_versions_are_not_compared() -> None:
    old, new = finding(version="2.0.12"), finding(version="2.1.5")
    assert "still present" in str(gate(item(), {old}, {new}, {old}))


def test_n6_2_identifier_of_another_package_does_not_match() -> None:
    other = {finding("other", "CVE-hono")}
    assert "not in the baseline" in str(gate(item(), other, set(), other))


def test_n6_2_class_is_part_of_the_package_key() -> None:
    os_record = {Finding("hono", "1", "CVE-hono", "HIGH", "os")}
    assert "not in the baseline" in str(gate(item(), os_record, set(), os_record))


def test_n6_3_gate_fails_when_the_vulnerability_was_not_in_the_baseline() -> None:
    assert "not in the baseline" in str(gate(item(), set(), set(), set()))


def test_n6_3_gate_fails_when_still_present() -> None:
    vuln = finding()
    assert "still present" in str(gate(item(), {vuln}, {vuln}, {vuln}))


def test_n6_3_gate_fails_on_a_new_serious_vulnerability() -> None:
    vuln = finding()
    other = finding("other", "CVE-new", "CRITICAL")
    assert "CVE-new" in str(gate(item(), {vuln}, {other}, {vuln}))


def test_n6_3_new_serious_ignores_known_and_lower_severities() -> None:
    known = finding("a", "CVE-1")
    after = {known, finding("a", "CVE-2", "MEDIUM"), finding("a", "CVE-1", version="9")}
    assert new_serious(after, {known}) == []


def test_n6_3_new_serious_matches_by_identifier_not_by_id() -> None:
    known = Finding("a", "1", "CVE-1", "HIGH", "lang", frozenset({"GHSA-1"}))
    renamed = Finding("a", "1", "GHSA-1", "HIGH", "lang")
    assert new_serious({renamed}, {known}) == []


def test_n6_1_image_tag_has_a_tag_part_for_osv_scanner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commands: list[list[str]] = []

    def run(command: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        commands.append(list(command))
        return subprocess.CompletedProcess(
            command, 1 if command[0] == "docker" else 0, "", ""
        )

    monkeypatch.setattr("scan.subprocess.run", run)
    with pytest.raises(ScanError, match="docker build failed"):
        scan_image(tmp_path, "docker/Dockerfile.app")
    tag = commands[0][commands[0].index("-t") + 1]
    assert tag == "sca-fix-docker-dockerfile-app:scan"


def test_n10_2_tool_versions(monkeypatch: pytest.MonkeyPatch) -> None:
    trivy = {
        "Version": "0.75.0",
        "VulnerabilityDB": {"UpdatedAt": "2026-11-05T00:00:00Z"},
        "JavaDB": {"UpdatedAt": "2026-11-04T00:00:00Z"},
    }
    monkeypatch.setattr(
        "scan.subprocess.run",
        lambda command, **kw: subprocess.CompletedProcess(
            command, 0, json.dumps(trivy), ""
        ),
    )
    monkeypatch.setattr(
        "scan.run_command",
        lambda command: subprocess.CompletedProcess(
            command, 0, "osv-scanner version: 2.7.0\nosv-scalibr version: 0.5\n", ""
        ),
    )
    assert tool_versions() == {
        "trivy": "0.75.0",
        "osv_scanner": "2.7.0",
        "trivy_db": "2026-11-05T00:00:00Z",
        "trivy_java_db": "2026-11-04T00:00:00Z",
    }


def missing_binary(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    raise FileNotFoundError(command[0])


def no_output(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    """Every tool exits 0 and writes nothing."""
    return subprocess.CompletedProcess(command, 0, "", "")


def broken_output(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    """``trivy convert`` writes a BOM, osv-scanner an unreadable file."""
    if command[0] == "osv-scanner":
        Path(command[command.index("--output-file") + 1]).write_text("{", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")
    return fake_tools(NOTHING)(command)


BROKEN_DETECTORS = [missing_binary, no_output, broken_output]


def failing_detect(tmp_path: Path, run: Any) -> set[Finding]:
    work = tmp_path / "failing"
    work.mkdir(exist_ok=True)
    native = work / "trivy.json"
    native.write_text(json.dumps(trivy_doc(HONO)), encoding="utf-8")
    return detect(work, native, run=run)


@pytest.mark.parametrize("run", BROKEN_DETECTORS)
def test_n6_1_rule_6_every_detector_failure_is_a_scan_error(
    tmp_path: Path, run: Any
) -> None:
    with pytest.raises(ScanError):
        failing_detect(tmp_path, run)


def test_n6_1_rule_6_missing_trivy_binary_is_a_scan_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def run(command: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError(command[0])

    monkeypatch.setattr("scan.subprocess.run", run)
    with pytest.raises(ScanError, match="trivy fs failed"):
        scan_tree(tmp_path)
    with pytest.raises(ScanError, match="versions"):
        tool_versions()
    with pytest.raises(ScanError, match="docker build failed"):
        scan_image(tmp_path, "Dockerfile")


@pytest.mark.parametrize("run", BROKEN_DETECTORS)
def test_n6_3_rule_4_broken_detector_after_a_change_is_rescan_failed(
    tmp_path: Path, run: Any
) -> None:
    scans = [
        lambda: detected(tmp_path, trivy_doc(HONO), NOTHING),
        lambda: failing_detect(tmp_path, run),
    ]
    fake = replace(
        tools(lambda job, manager: outcome(file("new")), []),
        scan_tree=lambda: scans.pop(0)(),
    )
    tree = lockfile_tree(tmp_path)
    result = process_line(line(item()), "o/r", tree, fake)
    assert result["items"][0]["reason_code"] == "rescan_failed"
    assert result["items"][0]["reverted"] is True
    assert (tree / "package-lock.json").read_text(encoding="utf-8") == "old"
    assert result["files"] == []


@pytest.mark.parametrize("run", BROKEN_DETECTORS)
def test_n6_1_rule_6_broken_detector_of_the_baseline_fails_the_line(
    tmp_path: Path, run: Any
) -> None:
    calls: list[int] = []
    base = tools(lambda job, manager: calls.append(1) or outcome(file("new")), [])
    fake = replace(base, scan_tree=lambda: failing_detect(tmp_path, run))
    tree = lockfile_tree(tmp_path)
    with pytest.raises(ScanError):
        process_line(line(item()), "o/r", tree, fake)
    assert calls == []
    assert (tree / "package-lock.json").read_text(encoding="utf-8") == "old"
