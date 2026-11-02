import pytest
from versions import VersionError, compare, major

OLDER_THAN = [
    ("1.2.16", "1.2.17"),
    ("1.9", "1.10"),
    ("1.2", "1.2.1"),
    ("3.5.7-r0", "3.5.8-r0"),
    ("3.5.8-r0", "3.5.8-r1"),
    ("3.5.8-r9", "3.5.9"),
    ("2.33.1-alpha", "2.33.1"),
    ("2.0.0-next.3", "2.0.0"),
    ("1.0.0-alpha", "1.0.0-beta"),
    ("1.0.0-rc.1", "1.0.0"),
    ("1.0.0rc1", "1.0.0"),
    ("1.0.0a1", "1.0.0b1"),
    ("1.0.0b1", "1.0.0rc1"),
    ("1.0.dev1", "1.0.0a1"),
    ("1.0.0", "1.0.0.post1"),
    ("1.0.0.post1", "1.0.1"),
    ("1.0-SNAPSHOT", "1.0-alpha-1"),
    ("1.0-alpha-1", "1.0-beta-1"),
    ("1.0-beta-1", "1.0-m1"),
    ("1.0-m1", "1.0-rc1"),
    ("1.0-cr1", "1.0"),
    ("4.2.16.Final", "4.2.17.Final"),
    ("4.2.16", "4.2.17.Final"),
]


@pytest.mark.parametrize(("older", "newer"), OLDER_THAN)
def test_order(older: str, newer: str) -> None:
    assert compare(older, newer) < 0
    assert compare(newer, older) > 0


@pytest.mark.parametrize(
    ("left", "right"),
    [
        ("1.2", "1.2.0"),
        ("4.2.16.Final", "4.2.16"),
        ("1.0-GA", "1.0"),
        ("3.5.8-r0", "3.5.8"),
        ("2.0.0+build5", "2.0.0"),
        ("v1.2.3", "1.2.3"),
    ],
)
def test_equal(left: str, right: str) -> None:
    assert compare(left, right) == 0


@pytest.mark.parametrize(
    "version",
    ["", "latest", "1.2-3ubuntu1", "1:2.3", "1.2.3_p1", "10.2.4.jre11", "1.0foo"],
)
def test_not_understood(version: str) -> None:
    with pytest.raises(VersionError):
        compare(version, "1.0")


def test_error_names_the_version() -> None:
    with pytest.raises(VersionError, match="1.2-3ubuntu1"):
        compare("1.0", "1.2-3ubuntu1")


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("14.0.3", (14,)),
        ("0.3.1", (0, 3)),
        ("0.4.0", (0, 4)),
        ("0", (0, 0)),
        ("3.5.8-r0", (3,)),
    ],
)
def test_major(version: str, expected: tuple[int, ...]) -> None:
    assert major(version) == expected
