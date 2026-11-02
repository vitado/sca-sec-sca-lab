from pathlib import Path
from typing import Any

import pytest
from builders import item
from dependabot import (
    JobError,
    docker_job,
    job_directories,
    read_events,
    security_job,
)


def touch(tree: Path, *paths: str) -> None:
    for path in paths:
        target = tree / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("x", encoding="utf-8")


def test_npm_root_lockfile(tmp_path: Path) -> None:
    touch(tmp_path, "package-lock.json")
    assert job_directories(tmp_path, item()) == ("npm_and_yarn", ["/"])


def test_image_paths_and_node_modules_do_not_count(tmp_path: Path) -> None:
    touch(tmp_path, "package-lock.json", "app/node_modules/x/package.json")
    locations = (
        "app/node_modules/x/package.json",
        "package-lock.json",
        "app/lib/x.jar",
    )
    assert job_directories(tmp_path, item(locations=locations))[1] == ["/"]


def test_no_manifest_location_means_root(tmp_path: Path) -> None:
    assert job_directories(tmp_path, item(locations=("app/x.jar",)))[1] == ["/"]


def test_pypi_uses_pip_in_the_lockfile_directory(tmp_path: Path) -> None:
    touch(tmp_path, "svc/poetry.lock")
    found = job_directories(
        tmp_path, item(ecosystem="PyPI", locations=("svc/poetry.lock",))
    )
    assert found == ("pip", ["/svc"])


def test_gradle_lockfiles_map_to_build_files(tmp_path: Path) -> None:
    touch(tmp_path, "build.gradle", "secrets-utils/build.gradle", "docs/readme")
    locations = (
        "app/app.jar/BOOT-INF/lib/x.jar",
        "gradle.lockfile",
        "secrets-utils/gradle.lockfile",
        "docs/gradle.lockfile",
    )
    found = job_directories(tmp_path, item(ecosystem="Maven", locations=locations))
    assert found == ("gradle", ["/", "/secrets-utils"])


def test_maven_without_a_build_file_is_maven(tmp_path: Path) -> None:
    touch(tmp_path, "pom.xml")
    found = job_directories(tmp_path, item(ecosystem="Maven", locations=("pom.xml",)))
    assert found[0] == "maven"


def test_unsupported_ecosystem(tmp_path: Path) -> None:
    with pytest.raises(JobError, match="Go not supported"):
        job_directories(tmp_path, item(ecosystem="Go"))


def test_security_job_has_the_advisory_of_the_target() -> None:
    job = security_job(item(), "npm_and_yarn", "o/r", "release-1.2", ["/"])
    assert job["security-updates-only"] is True
    assert job["dependencies"] == ["hono"]
    assert job["source"]["branch"] == "release-1.2"
    assert job["security-advisories"] == [
        {
            "dependency-name": "hono",
            "affected-versions": ["< 2.1.5"],
            "patched-versions": [">= 2.1.5"],
        }
    ]


def test_docker_job_ignores_major_versions() -> None:
    job = docker_job("o/r", "b", ["/", "/app"])
    assert job["package-manager"] == "docker"
    assert "dependencies" not in job
    assert job["ignore-conditions"][0]["update-types"] == [
        "version-update:semver-major"
    ]


def test_read_events() -> None:
    document: dict[str, Any] = {
        "output": [
            {"type": "update_dependency_list", "expect": {"data": {}}},
            {
                "type": "create_pull_request",
                "expect": {
                    "data": {
                        "updated-dependency-files": [{"name": "a"}],
                        "dependencies": [{"name": "d"}],
                    }
                },
            },
            {
                "type": "record_update_job_error",
                "expect": {"data": {"error-type": "boom"}},
            },
        ]
    }
    result = read_events(document)
    assert result.files == [{"name": "a"}]
    assert result.dependencies == [{"name": "d"}]
    assert result.error == "boom"
    assert read_events({"output": None}).files == []
