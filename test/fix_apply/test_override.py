import json
from pathlib import Path
from typing import Any

import pytest
from dependabot import TIMEOUT, Settings, run_job
from override import (
    OverrideError,
    add_overrides,
    changed_other,
    detect_node,
    numbers,
    satisfies,
    selector,
)

PAIRS = [("1.16.1", "1.16.2")]


def written(text: str) -> dict[str, Any]:
    return dict(json.loads(text))


def test_new_overrides_object_keeps_the_rest_of_the_file() -> None:
    text = '{\n  "name": "a",\n  "files": ["dist"],\n  "scripts": {"x": "y"}\n}\n'
    new, keys = add_overrides(text, "follow-redirects", PAIRS)
    assert keys == ["follow-redirects@^1.0.0"]
    assert new == (
        '{\n  "name": "a",\n  "files": ["dist"],\n  "scripts": {"x": "y"},\n'
        '  "overrides": {\n    "follow-redirects@^1.0.0": "^1.16.2"\n  }\n}\n'
    )


def test_append_to_an_existing_overrides_object_with_four_spaces_and_crlf() -> None:
    text = '{\r\n    "overrides": {\r\n        "a": "1.0.0"\r\n    },\r\n    "z": 1\r\n}\r\n'
    new, _ = add_overrides(text, "b", [("2.3.0", "2.4.0")])
    assert new == (
        '{\r\n    "overrides": {\r\n        "a": "1.0.0",\r\n'
        '        "b@^2.0.0": "^2.4.0"\r\n    },\r\n    "z": 1\r\n}\r\n'
    )


def test_empty_overrides_object_is_filled() -> None:
    new, _ = add_overrides('{\n  "overrides": {}\n}', "b", [("2.3.0", "2.4.0")])
    assert new == '{\n  "overrides": {\n    "b@^2.0.0": "^2.4.0"\n  }\n}'


def test_one_key_per_installed_major_and_the_scoped_name() -> None:
    pairs = [("1.20.8", "1.20.9"), ("2.3.0", "2.4.0"), ("1.20.7", "1.20.9")]
    new, keys = add_overrides('{\n  "name": "a"\n}\n', "body-parser", pairs)
    assert keys == ["body-parser@^1.0.0", "body-parser@^2.0.0"]
    assert written(new)["overrides"] == {
        "body-parser@^1.0.0": "^1.20.9",
        "body-parser@^2.0.0": "^2.4.0",
    }
    new, keys = add_overrides(
        '{\n  "name": "a"\n}\n', "@vitest/mocker", [("4.1.11", "4.1.12")]
    )
    assert keys == ["@vitest/mocker@^4.0.0"]


def test_zero_major_selector_stops_at_the_minor() -> None:
    assert selector("0.8.2") == "~0.8.0"
    new, keys = add_overrides('{\n  "a": 1\n}\n', "fflate", [("0.8.2", "0.8.3")])
    assert keys == ["fflate@~0.8.0"]
    assert written(new)["overrides"] == {"fflate@~0.8.0": "^0.8.3"}


def test_existing_entry_is_raised_in_its_form() -> None:
    text = '{\n  "overrides": {\n    "x": "^1.0.0",\n    "glob@^10.0.0": "~10.4.1",\n    "y": {"glob": ">=10.5.0"}\n  }\n}\n'
    new, keys = add_overrides(text, "glob", [("10.4.1", "10.5.1")])
    assert keys == ["glob@^10.0.0", "y > glob"]
    assert new == text.replace("~10.4.1", "~10.5.1").replace(">=10.5.0", ">=10.5.1")


def test_existing_entry_that_cannot_be_raised_is_manual() -> None:
    for value in ('"$glob"', '{"a": "1.0.0"}', '"^11.0.0"', '"^10.9.0"', '"latest"'):
        text = f'{{\n  "overrides": {{\n    "glob": {value}\n  }}\n}}\n'
        with pytest.raises(OverrideError, match="needs a manual change"):
            add_overrides(text, "glob", [("10.4.1", "10.5.1")])


def test_overrides_that_is_not_an_object_is_manual() -> None:
    with pytest.raises(OverrideError, match="not an object"):
        add_overrides('{"overrides": 1}', "glob", PAIRS)


def test_numbers_and_ranges() -> None:
    assert numbers("1.16.2-rc.1") == (1, 16, 2)
    assert numbers("4") == (4, 0, 0)
    assert satisfies((20, 0, 0), ">=18")
    assert satisfies((22, 3, 0), "^20.10.0 || ^22.0.0")
    assert not satisfies((18, 0, 0), ">=20.0.0 <23")
    assert satisfies((22, 0, 0), ">=20 <23")
    assert not satisfies((24, 0, 0), "<24")


def write(tree: Path, name: str, text: str) -> None:
    (tree / name).parent.mkdir(parents=True, exist_ok=True)
    (tree / name).write_text(text, encoding="utf-8")


def test_node_version_sources_in_order(tmp_path: Path) -> None:
    write(
        tmp_path,
        "Dockerfile",
        "FROM node:20.11-alpine AS a\nFROM --platform=x node:22-slim\n",
    )
    write(tmp_path, "svc/Dockerfile.dev", "FROM node:18\n")
    docker = ["Dockerfile", "svc/Dockerfile.dev"]
    assert detect_node(tmp_path, docker) == ("22", "Dockerfile")
    write(tmp_path, "package.json", '{"engines": {"node": ">=19 <21"}}')
    assert detect_node(tmp_path, docker) == ("20", "package.json engines.node")
    write(
        tmp_path,
        "package.json",
        '{"engines": {"node": ">=19"}, "volta": {"node": "21.1.0"}}',
    )
    assert detect_node(tmp_path, docker) == ("21.1.0", "package.json volta.node")
    write(tmp_path, ".node-version", "v18.19.0\n")
    assert detect_node(tmp_path, docker) == ("18.19.0", ".node-version")
    write(tmp_path, ".nvmrc", "22\n")
    assert detect_node(tmp_path, docker) == ("22", ".nvmrc")


def test_node_version_not_found(tmp_path: Path) -> None:
    write(tmp_path, ".nvmrc", "lts/*\n")
    write(tmp_path, "package.json", '{"engines": {"node": "<10"}}')
    assert detect_node(tmp_path, []) is None


def test_changed_other_lists_moved_and_new_packages() -> None:
    def lock(**versions: str) -> str:
        packages = {f"node_modules/{n}": {"version": v} for n, v in versions.items()}
        return json.dumps({"packages": {"": {}, **packages}})

    before = lock(hono="1", ms="1.0.0", gone="1")
    after = lock(hono="2", ms="1.0.1", extra="3")
    assert changed_other(before, after, "hono") == [
        "extra 3 (new)",
        "ms 1.0.0 -> 1.0.1",
    ]


def test_dependabot_time_limit_is_the_timeout_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import subprocess

    calls: list[list[str]] = []

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if command[0] == "cli":
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])
        return subprocess.CompletedProcess(command, 0, "abc\n", "")

    monkeypatch.setattr(subprocess, "run", run)
    settings = Settings("cli", {"npm_and_yarn": "img"}, "proxy", "t", 480)
    outcome = run_job({}, tmp_path, settings, "npm_and_yarn")
    assert outcome.error == TIMEOUT
    assert ["docker", "rm", "-f", "abc"] in calls
