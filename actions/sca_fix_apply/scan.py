"""The detector of the fixer (Trivy and OSV, merged by the engine's code) and the gate
that decides whether a change is proven.
"""

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

import apply_codes as codes
from normalize import Findings, Inventory, normalize_osv, normalize_trivy
from query_osv import Runner, run_command, scan_target
from vulns import records_of

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
TARGET = "target"  # the id the detector gives its one target


class ScanError(RuntimeError):
    """A scan or a build that could not be completed."""


class Finding(NamedTuple):
    """A record of the engine as the gate reads it: the package key, the
    identifiers (``id`` and ``names``, which hold the aliases too) and the merged
    severity.
    """

    pkg: str
    version: str
    id: str
    severity: str
    cls: str = "lang"
    names: frozenset[str] = frozenset()

    @property
    def identifiers(self) -> frozenset[str]:
        return self.names | {self.id}


def norm(pkg: str) -> str:
    """The package key of the report: lowercase, each run of ``-``, ``_``, ``.`` as
    one ``-``.
    """
    return re.sub(r"[-_.]+", "-", pkg.lower())


def finding_of(record: Mapping[str, Any]) -> Finding:
    return Finding(
        record["pkg"],
        ", ".join(record["installed"]),
        record["id"],
        record["severity"],
        record["class"],
        frozenset((*record["names"], *record["aliases"])),
    )


def detect(
    work: Path,
    native: Path,
    ref: str | None = None,
    source: bool = True,
    run: Runner = run_command,
) -> set[Finding]:
    """The records of a Trivy result in ``native``: OSV is asked about its packages
    (``query_osv.scan_target``; for an image, ``ref`` also the image scan), both
    results are normalized and merged into records by the engine.
    """
    osv = work / "osv.json"
    status, reason = scan_target(native, work / "bom.json", osv, run, ref)
    if status != "ok":
        raise ScanError(f"osv-scanner failed: {reason}")
    findings: Findings = {}
    inventory: Inventory = {}
    try:
        trivy = json.loads(native.read_text(encoding="utf-8"))
        normalize_trivy(TARGET, trivy, findings, inventory)
        osv_result = json.loads(osv.read_text(encoding="utf-8"))
        normalize_osv(TARGET, osv_result, findings, inventory)
    except (KeyError, TypeError, AttributeError, IndexError, ValueError) as exc:
        raise ScanError(f"unexpected scan result: {exc!r}") from exc
    records = records_of(list(findings.values()), {TARGET} if source else set())
    return {finding_of(r) for r in records}


def run_trivy(args: list[str], native: Path, cwd: Path | None = None) -> None:
    """Run ``trivy <args> --format json`` and write the result to ``native``."""
    done = subprocess.run(
        ["trivy", *args, "--format", "json", "--output", str(native)],
        cwd=cwd,
        env={**os.environ, **TRIVY_ENV},
        capture_output=True,
        check=False,
        text=True,
    )
    if done.returncode != 0 or not native.is_file():
        raise ScanError(f"trivy {args[0]} failed: {done.stderr.strip()[-500:]}")


def scan_tree(tree: Path, lockfile_command: str = "") -> set[Finding]:
    """Scan a copy of ``tree``: the generated lockfiles of a Gradle build stay out of
    the working tree, so they can never reach a commit. A Gradle build whose command
    wrote no lockfile is a failed run, not a clean one.
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
            if next(copy.rglob("gradle.lockfile"), None) is None:
                raise ScanError("lockfile generation wrote no gradle.lockfile")
        work = Path(parent)
        run_trivy(["fs", "."], work / "trivy.json", copy)
        return detect(work, work / "trivy.json")


def tool_versions() -> dict[str, str | None]:
    """The tools of the detector for ``result.json``: the versions of Trivy and
    osv-scanner and the update times of the Trivy databases.
    """
    done = subprocess.run(
        ["trivy", "version", "--format", "json"],
        capture_output=True,
        check=False,
        text=True,
    )
    osv = run_command(["osv-scanner", "--version"])
    if done.returncode != 0 or osv.returncode != 0:
        raise ScanError("cannot read the versions of trivy and osv-scanner")
    info = json.loads(done.stdout)
    lines = osv.stdout.strip().splitlines()  # "osv-scanner version: 2.7.0"
    return {
        "trivy": info.get("Version"),
        "osv_scanner": lines[0].rpartition(":")[2].strip() if lines else None,
        "trivy_db": (info.get("VulnerabilityDB") or {}).get("UpdatedAt"),
        "trivy_java_db": (info.get("JavaDB") or {}).get("UpdatedAt"),
    }


def item_ids(item: Mapping[str, Any]) -> set[str]:
    return {n for v in item["vulns"] for n in (v["id"], *v["names"], *v["aliases"])}


def present(item: Mapping[str, Any], findings: Iterable[Finding]) -> set[Finding]:
    """The records of an item's package (class and normalized name) that share an
    identifier with one of the item's vulnerabilities; versions are not compared.
    """
    key, ids = (item["class"], norm(item["pkg"])), item_ids(item)
    return {f for f in findings if (f.cls, norm(f.pkg)) == key and f.identifiers & ids}


def new_serious(after: Iterable[Finding], baseline: Iterable[Finding]) -> list[str]:
    """HIGH and CRITICAL records of ``after`` that match nothing in the baseline (same
    package key and a shared identifier), so a new copy of a known one does not count.
    """
    known: dict[tuple[str, str], set[str]] = {}
    for f in baseline:
        known.setdefault((f.cls, norm(f.pkg)), set()).update(f.identifiers)
    return sorted(
        {
            f"{f.pkg} {f.id}"
            for f in after
            if f.severity in SERIOUS
            and not f.identifiers & known.get((f.cls, norm(f.pkg)), set())
        }
    )


def gate(
    item: Mapping[str, Any],
    before: set[Finding],
    after: set[Finding],
    baseline: set[Finding],
) -> tuple[str, str] | None:
    """Why an item is not proven as ``(reason_code, text)``, or None when it is.

    ``before`` is the scan of the state the change started from: an item whose
    vulnerabilities were not in it cannot be shown to be fixed. ``baseline`` is the
    scan of the untouched branch: the change must not bring a new serious one.
    """
    if not present(item, before):
        return codes.NOT_IN_BASELINE, NOT_IN_BASELINE
    left = present(item, after)
    if left:
        text = "still present after the change: " + ", ".join(
            sorted({f"{f.pkg} {f.version} {f.id}" for f in left})
        )
        return codes.GATE_STILL_PRESENT, text
    new = new_serious(after, baseline)
    if new:
        text = "new HIGH or CRITICAL after the change: " + ", ".join(new)
        return codes.GATE_NEW_SERIOUS, text
    return None


def scan_image(
    tree: Path, dockerfile: str, build_args: Iterable[str] = ()
) -> set[Finding]:
    """Build ``dockerfile`` with the repository root as the context (as the build
    workflows of the repositories do) and scan the image; the image is removed. The
    tag has a tag part: osv-scanner does not scan an image name without one.
    """
    slug = re.sub(r"[^a-z0-9]+", "-", dockerfile.lower()).strip("-")
    tag = f"sca-fix-{slug}:scan"
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
        with tempfile.TemporaryDirectory() as work:
            native = Path(work) / "trivy.json"
            run_trivy(["image", tag], native)
            return detect(Path(work), native, tag, source=False)
    finally:
        subprocess.run(
            ["docker", "rmi", "--force", tag],
            check=False,
            capture_output=True,
        )
