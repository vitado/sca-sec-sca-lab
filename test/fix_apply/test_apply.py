import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from apply import Tools, process_line
from builders import file, finding, item, line, outcome, tools
from dependabot import TIMEOUT, Outcome
from scan import Finding, ScanError


def tree_with(tmp_path: Path, **files: str) -> Path:
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8", newline="")
    return tmp_path


def lockfile_tree(tmp_path: Path) -> Path:
    return tree_with(tmp_path, **{"package-lock.json": "old"})


def test_applied_item(tmp_path: Path) -> None:
    tree = lockfile_tree(tmp_path)
    seen: list[Mapping[str, Any]] = []

    def dependabot(job: Mapping[str, Any], manager: str) -> Outcome:
        seen.append(job)
        return outcome(file("new"))

    vuln = finding()
    result = process_line(line(item()), "o/r", tree, tools(dependabot, [{vuln}, set()]))
    record = result["items"][0]
    assert record["status"] == "applied"
    assert record["reason"] is None
    assert record["changes"][0]["to"] == "2.1.5"
    assert result["files"] == ["package-lock.json"]
    assert (tree / "package-lock.json").read_text(encoding="utf-8") == "new"
    assert seen[0]["source"]["directories"] == ["/"]
    assert result["baseline_findings"] == 1


def test_no_change_goes_on_to_the_override_step(tmp_path: Path) -> None:
    tree = lockfile_tree(tmp_path)
    result = process_line(
        line(item()),
        "o/r",
        tree,
        tools(lambda job, manager: outcome(), [{finding()}]),
    )
    record = result["items"][0]
    assert record["status"] == "manual"
    assert record["reason"] == "no package.json and package-lock.json at the root"
    assert record["dependabot_result"] == "dependabot produced no change"
    assert result["files"] == []


def not_needed(tmp_path: Path, baseline: set[Finding]) -> dict[str, Any]:
    return process_line(
        line(item()),
        "o/r",
        lockfile_tree(tmp_path),
        tools(
            lambda job, manager: outcome(error="security_update_not_needed"),
            [baseline],
        ),
    )["items"][0]


def test_n5_2_not_needed_is_already_fixed_when_the_detector_does_not_find_it(
    tmp_path: Path,
) -> None:
    record = not_needed(tmp_path, set())
    assert record["status"] == "already_fixed"
    assert record["reason_code"] == "not_in_baseline"
    assert record["dependabot_result"] == "security_update_not_needed"


def test_n5_2_not_needed_is_not_believed_when_the_detector_finds_it(
    tmp_path: Path,
) -> None:
    record = not_needed(tmp_path, {finding()})
    assert record["status"] == "manual"
    assert record["reason_code"] == "dependabot_refused"
    assert record["detail"] == "security_update_not_needed"


def test_gate_without_baseline_findings_is_already_fixed(tmp_path: Path) -> None:
    tree = lockfile_tree(tmp_path)
    result = process_line(
        line(item()),
        "o/r",
        tree,
        tools(lambda job, manager: outcome(file("new")), [set(), set()]),
    )
    record = result["items"][0]
    assert record["status"] == "already_fixed"
    assert record["reverted"] is True
    assert (tree / "package-lock.json").read_text(encoding="utf-8") == "old"


def test_dependabot_error_is_the_reason_without_a_fallback(tmp_path: Path) -> None:
    tree = tree_with(tmp_path, **{"poetry.lock": "old"})
    pip = item(
        "filelock", fallback="manual", ecosystem="PyPI", locations=("poetry.lock",)
    )
    result = process_line(
        line(pip),
        "o/r",
        tree,
        tools(
            lambda job, manager: outcome(error="security_update_not_possible"),
            [{finding("filelock")}],
        ),
    )
    assert result["items"][0]["reason"] == "security_update_not_possible"


def test_failed_gate_reverts_the_item(tmp_path: Path) -> None:
    tree = lockfile_tree(tmp_path)
    vuln = finding()
    result = process_line(
        line(item()),
        "o/r",
        tree,
        tools(lambda job, manager: outcome(file("new")), [{vuln}, {vuln}]),
    )
    record = result["items"][0]
    assert record["status"] == "manual"
    assert record["reverted"] is True
    assert "still present" in record["detail"]
    assert (tree / "package-lock.json").read_text(encoding="utf-8") == "old"
    assert result["files"] == []


def test_rescan_failure_reverts_the_item(tmp_path: Path) -> None:
    tree = lockfile_tree(tmp_path)
    scans = iter([{finding()}])

    def fail_second() -> set[Finding]:
        try:
            return next(scans)
        except StopIteration:
            raise ScanError("boom") from None

    fake = Tools(
        dependabot=lambda job, manager: outcome(file("new")),
        scan_tree=fail_second,
        scan_image=lambda t, p: set(),
        npm_install=lambda: None,
        npm_ls=lambda pkg: [],
        npm_version=lambda: "10",
        tool_versions=lambda: {},
    )
    result = process_line(line(item()), "o/r", tree, fake)
    assert "rescan failed: boom" in result["items"][0]["detail"]
    assert (tree / "package-lock.json").read_text(encoding="utf-8") == "old"


def test_items_run_in_turn_on_the_tree_the_previous_one_left(tmp_path: Path) -> None:
    tree = lockfile_tree(tmp_path)
    contents: list[str] = []

    def dependabot(job: Mapping[str, Any], manager: str) -> Outcome:
        contents.append((tree / "package-lock.json").read_text(encoding="utf-8"))
        return outcome(file(f"v{len(contents)}"))

    one, two = finding("a"), finding("b")
    result = process_line(
        line(item("a"), item("b")),
        "o/r",
        tree,
        tools(dependabot, [{one, two}, {two}, set()]),
    )
    assert contents == ["old", "v1"]
    assert [r["status"] for r in result["items"]] == ["applied", "applied"]


def test_manual_items_pass_through(tmp_path: Path) -> None:
    manual = item("x", method="manual", fallback=None, reason="why", target=None)
    result = process_line(
        line(manual), "o/r", tmp_path, tools(lambda j, m: outcome(), [])
    )
    assert result["items"][0]["status"] == "manual"
    assert result["items"][0]["reason"] == "why"


def os_item(pkg: str = "brotli-libs") -> dict[str, Any]:
    return item(
        pkg,
        method="docker-tag",
        fallback="manual",
        ecosystem="Alpine:v3.24",
        cls="os",
        target=None,
    )


def docker_tree(tmp_path: Path) -> Path:
    return tree_with(tmp_path, Dockerfile="FROM a:1\n")


def test_docker_step_applies_when_the_image_rescan_proves_it(tmp_path: Path) -> None:
    tree = docker_tree(tmp_path)
    vuln = finding("brotli-libs", cls="os")
    builds: list[str] = []

    def image(root: Path, path: str) -> set[Finding]:
        builds.append((root / path).read_text(encoding="utf-8"))
        return {vuln} if len(builds) == 1 else set()

    result = process_line(
        line(os_item()),
        "o/r",
        tree,
        tools(
            lambda job, manager: outcome(file("FROM a:2\n", "/", "Dockerfile")),
            [],
            image,
        ),
    )
    record = result["items"][0]
    assert record["status"] == "applied"
    assert builds == ["FROM a:1\n", "FROM a:2\n"]
    assert result["docker"]["status"] == "applied"
    assert result["files"] == ["Dockerfile"]
    assert (tree / "Dockerfile").read_text(encoding="utf-8") == "FROM a:2\n"


def test_docker_step_is_reverted_when_nothing_is_proven(tmp_path: Path) -> None:
    tree = docker_tree(tmp_path)
    vuln = finding("brotli-libs", cls="os")
    result = process_line(
        line(os_item()),
        "o/r",
        tree,
        tools(
            lambda job, manager: outcome(file("FROM a:2\n", "/", "Dockerfile")),
            [],
            lambda root, path: {vuln},
        ),
    )
    assert result["items"][0]["status"] == "manual"
    assert "image rescan gate" in result["items"][0]["reason"]
    assert result["docker"]["status"] == "reverted"
    assert result["files"] == []


def test_docker_build_failure_makes_items_manual(tmp_path: Path) -> None:
    tree = docker_tree(tmp_path)

    def image(root: Path, path: str) -> set[Finding]:
        if "a:2" in (root / path).read_text(encoding="utf-8"):
            raise ScanError("docker build failed: nope")
        return {finding("brotli-libs", cls="os")}

    result = process_line(
        line(os_item()),
        "o/r",
        tree,
        tools(
            lambda job, manager: outcome(file("FROM a:2\n", "/", "Dockerfile")),
            [],
            image,
        ),
    )
    reason = result["items"][0]["reason"]
    assert reason.startswith("image build failed: build after the bump of Dockerfile")
    assert result["docker"]["status"] == "reverted"
    assert (tree / "Dockerfile").read_text(encoding="utf-8") == "FROM a:1\n"


def test_docker_step_without_a_change(tmp_path: Path) -> None:
    tree = docker_tree(tmp_path)
    result = process_line(
        line(os_item()), "o/r", tree, tools(lambda job, manager: outcome(), [])
    )
    assert result["items"][0]["reason"] == "dependabot produced no change"
    assert result["docker"]["status"] == "none"


PACKAGE = '{\n  "name": "app",\n  "version": "1.0.0"\n}\n'
NODE = '{\n  "name": "app",\n  "engines": {\n    "node": ">=20"\n  }\n}\n'


def lock(version: str, **extra: str) -> str:
    packages: dict[str, Any] = {"": {"name": "app"}}
    packages["node_modules/hono"] = {"version": version}
    packages.update({f"node_modules/{n}": {"version": v} for n, v in extra.items()})
    return json.dumps({"lockfileVersion": 3, "packages": packages}, indent=2) + "\n"


def override_tree(tmp_path: Path, package: str = NODE) -> Path:
    return tree_with(
        tmp_path, **{"package.json": package, "package-lock.json": lock("2.0.12")}
    )


def run_override(
    tree: Path,
    scans: list[set[Finding]],
    install: Callable[[], str | None] | None = None,
    ls: Callable[[str], list[tuple[str, str]]] | None = None,
    relationship: str = "indirect",
) -> dict[str, Any]:
    def write_lock() -> str | None:
        text = lock("2.1.5", ms="1.0.1")
        (tree / "package-lock.json").write_text(text, encoding="utf-8")
        return None

    one = item()
    one["relationship"] = relationship
    return process_line(
        line(one),
        "o/r",
        tree,
        tools(
            lambda job, manager: outcome(error="security_update_not_possible"),
            scans,
            npm_install=install or write_lock,
            npm_ls=ls or (lambda pkg: [("hono", "2.1.5")]),
        ),
    )


def test_override_step_applies_and_proves(tmp_path: Path) -> None:
    tree = override_tree(tmp_path)
    result = run_override(tree, [{finding()}, set()])
    record = result["items"][0]
    assert record["status"] == "applied"
    assert record["method_used"] == "npm-override"
    assert record["override_keys"] == ["hono@^2.0.0"]
    assert (record["node_version"], record["node_source"]) == (
        "20",
        "package.json engines.node",
    )
    assert record["changed_other"] == ["ms 1.0.1 (new)"]
    assert record["dependabot_result"] == "security_update_not_possible"
    assert result["files"] == ["package-lock.json", "package.json"]
    written = (tree / "package.json").read_text(encoding="utf-8")
    assert '"hono@^2.0.0": "^2.1.5"' in written


def test_override_step_leaves_direct_dependencies_alone(tmp_path: Path) -> None:
    tree = override_tree(tmp_path)
    result = run_override(tree, [{finding()}], relationship="direct")
    assert result["items"][0]["reason"].startswith("direct dependency")
    assert result["files"] == []


def test_override_step_needs_a_node_version(tmp_path: Path) -> None:
    tree = override_tree(tmp_path, PACKAGE)
    result = run_override(tree, [{finding()}])
    assert result["items"][0]["reason"] == "node version of the branch not found"


def test_npm_failure_reverts(tmp_path: Path) -> None:
    tree = override_tree(tmp_path)

    def broken() -> str | None:
        (tree / "package-lock.json").write_text("{}", encoding="utf-8")
        return "npm error code ERESOLVE"

    result = run_override(tree, [{finding()}], install=broken)
    record = result["items"][0]
    assert record["reason"] == "npm error code ERESOLVE"
    assert record["reverted"] is True
    assert (tree / "package.json").read_text(encoding="utf-8") == NODE
    assert (tree / "package-lock.json").read_text(encoding="utf-8") == lock("2.0.12")
    assert result["files"] == []


def test_lockfile_format_change_reverts(tmp_path: Path) -> None:
    tree = override_tree(tmp_path)

    def rewrite() -> str | None:
        (tree / "package-lock.json").write_text(
            '{"lockfileVersion": 2}', encoding="utf-8"
        )
        return None

    record = run_override(tree, [{finding()}], install=rewrite)["items"][0]
    assert record["reason"] == "npm 10.9.2 would rewrite the lockfile format"
    assert (tree / "package-lock.json").read_text(encoding="utf-8") == lock("2.0.12")


def test_copy_below_the_target_reverts(tmp_path: Path) -> None:
    tree = override_tree(tmp_path)

    def copies(pkg: str) -> list[tuple[str, str]]:
        return [("a > hono", "2.1.5"), ("b > hono", "2.0.12")]

    result = run_override(tree, [{finding()}], ls=copies)
    assert result["items"][0]["reason"] == "override did not reach b > hono"
    assert result["files"] == []
    assert (tree / "package.json").read_text(encoding="utf-8") == NODE


def test_failed_gate_reverts_the_override(tmp_path: Path) -> None:
    tree = override_tree(tmp_path)
    vuln = finding()
    result = run_override(tree, [{vuln}, {vuln}])
    record = result["items"][0]
    assert record["reason"].startswith("rescan gate: still present")
    assert record["reverted"] is True
    assert result["files"] == []


def test_existing_nested_override_stays_manual(tmp_path: Path) -> None:
    package = (
        '{\n  "overrides": {\n    "a": {\n      "hono": {"x": "1"}\n    }\n  },\n'
        '  "engines": {"node": ">=20"}\n}\n'
    )
    tree = override_tree(tmp_path, package)
    result = run_override(tree, [{finding()}])
    reason = result["items"][0]["reason"]
    assert reason == "existing override for hono needs a manual change"
    assert (tree / "package.json").read_text(encoding="utf-8") == package


def test_timeout_goes_on_to_the_override_step(tmp_path: Path) -> None:
    tree = override_tree(tmp_path)
    result = process_line(
        line(item()),
        "o/r",
        tree,
        tools(
            lambda job, manager: outcome(error=TIMEOUT),
            [{finding()}, set()],
            npm_ls=lambda pkg: [("hono", "2.1.5")],
        ),
    )
    assert result["items"][0]["status"] == "applied"
    assert result["items"][0]["dependabot_result"] == TIMEOUT


def recorded_trivy(*vulns: tuple[str, str, str, str]) -> set[Finding]:
    return {
        Finding(name, version, vid, severity) for name, version, vid, severity in vulns
    }


def test_new_high_in_the_rescan_reverts_the_item_to_manual(tmp_path: Path) -> None:
    tree = lockfile_tree(tmp_path)
    hono = ("hono", "2.0.12", "CVE-hono", "HIGH")
    baseline = recorded_trivy(hono, ("next", "15.5.27", "CVE-next-old", "MEDIUM"))
    after = recorded_trivy(
        ("next", "15.5.27", "CVE-next-old", "MEDIUM"),
        ("tar-fs", "3.0.0", "CVE-new", "HIGH"),
    )
    result = process_line(
        line(item()),
        "o/r",
        tree,
        tools(lambda job, manager: outcome(file("new")), [baseline, after]),
    )
    record = result["items"][0]
    assert record["status"] == "manual"
    assert record["reverted"] is True
    assert record["detail"] == (
        "rescan gate: new HIGH or CRITICAL after the change: tar-fs CVE-new"
    )
    assert (tree / "package-lock.json").read_text(encoding="utf-8") == "old"
    assert result["files"] == []
