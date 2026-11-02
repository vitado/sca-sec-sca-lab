from collections.abc import Mapping
from pathlib import Path
from typing import Any

from apply import OVERRIDE_NOT_IMPLEMENTED, process_line
from builders import file, finding, item, line, outcome, tools
from dependabot import Outcome
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


def test_no_change_is_manual_with_the_override_fallback(tmp_path: Path) -> None:
    tree = lockfile_tree(tmp_path)
    result = process_line(
        line(item()),
        "o/r",
        tree,
        tools(lambda job, manager: outcome(), [{finding()}]),
    )
    record = result["items"][0]
    assert record["status"] == "manual"
    assert record["reason"] == OVERRIDE_NOT_IMPLEMENTED
    assert record["detail"] == "dependabot produced no change"
    assert result["files"] == []


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

    from apply import Tools

    fake = Tools(
        dependabot=lambda job, manager: outcome(file("new")),
        scan_tree=fail_second,
        scan_image=lambda t, p: set(),
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
    vuln = finding("brotli-libs")
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
    vuln = finding("brotli-libs")
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
        return {finding("brotli-libs")}

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
