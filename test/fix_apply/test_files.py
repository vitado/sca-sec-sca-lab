from pathlib import Path

from builders import file
from files import Journal, merge_text


def put(tree: Path, name: str, text: str) -> None:
    (tree / name).write_text(text, encoding="utf-8", newline="")


def test_merge_text_combines_separate_edits() -> None:
    merged, left_out = merge_text("a\nb\nc\nd\n", ["a\nB\nc\nd\n", "a\nb\nc\nD\n"])
    assert merged == "a\nB\nc\nD\n"
    assert left_out == 0


def test_merge_text_leaves_out_a_conflicting_version() -> None:
    merged, left_out = merge_text("a\nb\n", ["a\nX\n", "a\nY\n"])
    assert merged == "a\nX\n"
    assert left_out == 1


def test_merge_text_takes_identical_edits_once() -> None:
    merged, left_out = merge_text("a\nb\n", ["a\nX\n", "a\nX\n"])
    assert merged == "a\nX\n"
    assert left_out == 0


def test_apply_writes_and_reports_changed_files(tmp_path: Path) -> None:
    put(tmp_path, "package-lock.json", "old")
    journal = Journal(tmp_path)
    changed, _ = journal.apply([file("new"), file("fresh", "/sub", "other.json")])
    assert changed == ["package-lock.json", "sub/other.json"]
    assert (tmp_path / "package-lock.json").read_text(encoding="utf-8") == "new"
    assert journal.paths() == ["package-lock.json", "sub/other.json"]


def test_apply_merges_two_events_on_one_file(tmp_path: Path) -> None:
    put(tmp_path, "f", "a\nb\nc\nd\n")
    changed, left_out = Journal(tmp_path).apply(
        [file("a\nB\nc\nd\n", "/", "f"), file("a\nb\nc\nD\n", "/", "f")]
    )
    assert changed == ["f"]
    assert left_out == 0
    assert (tmp_path / "f").read_text(encoding="utf-8") == "a\nB\nc\nD\n"


def test_apply_ignores_identical_content(tmp_path: Path) -> None:
    put(tmp_path, "f", "same")
    changed, _ = Journal(tmp_path).apply([file("same", "/", "f")])
    assert changed == []


def test_restore_returns_to_the_checkpoint(tmp_path: Path) -> None:
    put(tmp_path, "a", "0")
    journal = Journal(tmp_path)
    journal.apply([file("1", "/", "a")])
    checkpoint = journal.checkpoint()
    journal.apply([file("2", "/", "a"), file("n", "/", "new")])
    journal.restore(checkpoint)
    assert (tmp_path / "a").read_text(encoding="utf-8") == "1"
    assert not (tmp_path / "new").exists()
    assert journal.paths() == ["a"]


def test_deleted_file(tmp_path: Path) -> None:
    put(tmp_path, "gone", "x")
    journal = Journal(tmp_path)
    changed, _ = journal.apply([{**file("", "/", "gone"), "deleted": True}])
    assert changed == ["gone"]
    assert not (tmp_path / "gone").exists()
