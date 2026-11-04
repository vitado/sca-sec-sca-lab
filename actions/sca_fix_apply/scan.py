"""Rescans with Trivy and the gate that decides whether a change is proven."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, NamedTuple

# The scan profile of the scheduled scan (sca_scheduled.yml): exposure, not a gate,
# so nothing is ignored or filtered out and the repository's own settings cannot
# change what is compared
TRIVY_ENV = {
    "TRIVY_IGNOREFILE": "/dev/null",
    "TRIVY_IGNORE_UNFIXED": "false",
    "TRIVY_SEVERITY": "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
    "TRIVY_PKG_TYPES": "os,library",
    "TRIVY_SCANNERS": "vuln",
    "TRIVY_LIST_ALL_PKGS": "true",
    "TRIVY_INCLUDE_DEV_DEPS": "true",
    "TRIVY_EXIT_CODE": "0",
    "TRIVY_DISABLE_VEX_NOTICE": "true",
}
SERIOUS = ("HIGH", "CRITICAL")
NOT_IN_BASELINE = "the item's vulnerabilities are not in the baseline scan"


class ScanError(RuntimeError):
    """A scan or a build that could not be completed."""


class Finding(NamedTuple):
    pkg: str
    version: str
    id: str
    severity: str


def norm(pkg: str) -> str:
    """The package key of the report: lowercase, each run of ``-``, ``_``, ``.`` as
    one ``-``.
    """
    return re.sub(r"[-_.]+", "-", pkg.lower())


def parse_trivy(document: Mapping[str, Any]) -> set[Finding]:
    return {
        Finding(
            v["PkgName"], v["InstalledVersion"], v["VulnerabilityID"], v["Severity"]
        )
        for result in document.get("Results") or []
        for v in result.get("Vulnerabilities") or []
    }


def run_trivy(args: list[str], cwd: Path | None = None) -> set[Finding]:
    """Run ``trivy <args> --format json`` and read its findings."""
    with tempfile.TemporaryDirectory() as out:
        target = Path(out) / "trivy.json"
        done = subprocess.run(
            ["trivy", *args, "--format", "json", "--output", str(target)],
            cwd=cwd,
            env={**os.environ, **TRIVY_ENV},
            capture_output=True,
            check=False,
            text=True,
        )
        if done.returncode != 0 or not target.is_file():
            raise ScanError(f"trivy {args[0]} failed: {done.stderr.strip()[-500:]}")
        return parse_trivy(json.loads(target.read_text(encoding="utf-8")))


def scan_tree(tree: Path, lockfile_command: str = "") -> set[Finding]:
    """Scan a copy of ``tree``: the generated lockfiles of a Gradle build stay out of
    the working tree, so they can never reach a commit.
    """
    with tempfile.TemporaryDirectory() as parent:
        copy = Path(parent) / "tree"
        shutil.copytree(
            tree, copy, ignore=shutil.ignore_patterns(".git"), symlinks=True
        )
        if lockfile_command:
            done = subprocess.run(
                ["bash", "-ec", lockfile_command],
                cwd=copy,
                capture_output=True,
                check=False,
                text=True,
            )
            if done.returncode != 0:
                raise ScanError(
                    f"lockfile generation failed: {done.stderr.strip()[-500:]}"
                )
        return run_trivy(["fs", "."], cwd=copy)


def item_names(item: Mapping[str, Any]) -> set[str]:
    return {n for v in item["vulns"] for n in (v["id"], *v["names"])}


def present(item: Mapping[str, Any], findings: Iterable[Finding]) -> set[Finding]:
    """The findings of an item's package that are one of the item's vulnerabilities."""
    key, names = norm(item["pkg"]), item_names(item)
    return {f for f in findings if norm(f.pkg) == key and f.id in names}


def new_serious(after: Iterable[Finding], baseline: Iterable[Finding]) -> list[str]:
    """HIGH and CRITICAL vulnerabilities of ``after`` that the baseline did not have
    (by package and vulnerability, so a new copy of a known one does not count).
    """
    known = {(norm(f.pkg), f.id) for f in baseline}
    return sorted(
        {
            f"{f.pkg} {f.id}"
            for f in after
            if f.severity in SERIOUS and (norm(f.pkg), f.id) not in known
        }
    )


def gate(
    item: Mapping[str, Any],
    before: set[Finding],
    after: set[Finding],
    baseline: set[Finding],
) -> str | None:
    """Why an item is not proven, or None when it is.

    ``before`` is the scan of the state the change started from: an item whose
    vulnerabilities were not in it cannot be shown to be fixed. ``baseline`` is the
    scan of the untouched branch: the change must not bring a new serious one.
    """
    if not present(item, before):
        return NOT_IN_BASELINE
    left = present(item, after)
    if left:
        return "still present after the change: " + ", ".join(
            sorted({f"{f.pkg} {f.version} {f.id}" for f in left})
        )
    new = new_serious(after, baseline)
    if new:
        return "new HIGH or CRITICAL after the change: " + ", ".join(new)
    return None


def scan_image(
    tree: Path, dockerfile: str, build_args: Iterable[str] = ()
) -> set[Finding]:
    """Build ``dockerfile`` with the repository root as the context (as the build
    workflows of the repositories do) and scan the image; the image is removed.
    """
    tag = "sca-fix-" + re.sub(r"[^a-z0-9]+", "-", dockerfile.lower()).strip("-")
    secrets = [
        arg
        for name in ("GPR_USERNAME", "GPR_PASSWORD")
        if name in os.environ
        for arg in ("--secret", f"id={name},env={name}")
    ]
    command = ["docker", "build", "-f", dockerfile, "-t", tag, *secrets]
    for arg in build_args:
        command += ["--build-arg", arg]
    built = subprocess.run(
        [*command, "."],
        cwd=tree,
        capture_output=True,
        check=False,
        text=True,
        env={**os.environ, "DOCKER_BUILDKIT": "1"},
    )
    if built.returncode != 0:
        raise ScanError(
            f"docker build failed: {(built.stderr or built.stdout).strip()[-800:]}"
        )
    try:
        return run_trivy(["image", tag])
    finally:
        subprocess.run(
            ["docker", "rmi", "--force", tag],
            check=False,
            capture_output=True,
        )
