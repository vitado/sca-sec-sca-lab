#!/usr/bin/env python3
"""Check the packages found by Trivy against OSV with osv-scanner.

Used by the SCA scheduled scan. Every pending OSV target is the twin of a scanned
Trivy target (same id). The native Trivy JSON of the target is converted to a
CycloneDX BOM (``trivy convert``); OS packages (which OSV cannot be asked about
correctly through a BOM: no source package name) and components without a package URL
or a version (a local workspace package, which OSV cannot be asked about either) are
removed; ``osv-scanner scan source -L <id>.cdx.json --all-packages`` matches the rest
with OSV (online, api.osv.dev).

An image target also gets the direct ``osv-scanner scan image <ref> --all-packages``:
it reads the image's own package database (os-release, apk ``o:`` / dpkg ``Source:``)
and so can query OSV about the OS packages correctly. The BOM query runs either way,
so a package either detector sees keeps its OSV check; the two outputs are both
``{"results": [...]}`` and their ``results`` are concatenated into one ``osv/<id>.json``.
The image scan is skipped when the target carries ``image_scan_disabled`` (an image too
large for the runner disk): the target stays ``ok`` with a reason, so the exclusion is
stated, not silent. After each image scan ``docker image rm`` removes the pulled image
(their store must not fill the runner disk).

Reads targets.json and ``trivy/<id>.status.json`` of the parts directory. Writes, per
OSV target, ``osv/<id>.status.json`` (``{status, reason, queried_at,
scanner_version}``) and, if ``ok``, ``osv/<id>.json``, the osv-scanner output as is.

osv-scanner exits 0 (nothing found) or 1 (vulnerabilities found); any other exit code
is a failure, so a broken run never looks like a clean one - a failed image scan fails
its target even though the BOM query succeeded. A command has a timeout (a hung one is
exit code 124, a failed target with that reason). A target whose Trivy target was not
scanned is ``not_applicable``. The merge fails an output that is not a valid result.
The script exits 0: the workflow decides about failing the run.

With ``--offline-db-dir DIR`` osv-scanner makes no OSV or deps.dev network request (the image pull of an image scan still happens): ``DIR`` is the osv-scanner
database cache (``OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY``), filled by the caller beforehand
(``osv-scanner --download-offline-databases``; the engine never downloads). Both scans
run with ``--offline``, which switches off every network feature of osv-scanner, not only
the vulnerability lookup (no base-image lookup, no registry or Maven Central resolution).
An empty cache makes osv-scanner write a result without vulnerabilities, so there the
message "no offline version of the OSV database" on stderr fails the target even
if the exit code is 0 or 1.

A target may carry ``image_scan_disabled_reason`` next to ``image_scan_disabled``: the
reason that states the exclusion (instead of the default one) when the image scan is off.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import tempfile
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from _sca_lib import dump_json, format_time, read_json

# Components Trivy covers with its distribution feeds
OS_PURL_TYPES = frozenset({"deb", "apk", "rpm"})
# osv-scanner: 0 nothing found, 1 vulnerabilities found
EXIT_CODES_OK = (0, 1)
# osv-scanner offline without the database of an ecosystem: loud, but the output is empty
OFFLINE_MISSING = "no offline version of the OSV database"
CACHE_ENV = "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"
REASON_LIMIT = 400
# A command that hangs must not take the rest of the run with it (the job has one
# bound for all targets): the pull of an image takes the longest.
COMMAND_TIMEOUT_SECONDS = 600.0
IMAGE_SCAN_TIMEOUT_SECONDS = 1200.0
# An image target whose direct image scan is switched off for the repository
IMAGE_SCAN_DISABLED_REASON = (
    "osv image scan disabled for this repository (image too large for the runner "
    "disk): OS packages of the image are not checked by OSV"
)

Runner = Callable[[Sequence[str]], "subprocess.CompletedProcess[str]"]


def run_command(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    """Run a command; a program that cannot start is exit code 127 (as in a shell),
    one that outlives its timeout is exit code 124 (as in ``timeout``), so a hung
    target fails with a reason and the next target still runs."""
    timeout = (
        IMAGE_SCAN_TIMEOUT_SECONDS
        if list(command[1:3]) == ["scan", "image"]
        else COMMAND_TIMEOUT_SECONDS
    )
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(
            command, 124, "", f"timed out after {timeout:.0f}s"
        )
    except OSError as err:
        return subprocess.CompletedProcess(command, 127, "", str(err))


def scan_failed(scanned: subprocess.CompletedProcess[str], offline: bool) -> bool:
    """An osv-scanner run that must not count as a scan: an unexpected exit code, or
    (offline) a missing database, whose output looks like a clean result."""
    return scanned.returncode not in EXIT_CODES_OK or (
        offline and OFFLINE_MISSING in scanned.stderr
    )


def tail(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= REASON_LIMIT else "..." + text[-REASON_LIMIT:]


def filter_bom(bom: dict[str, Any]) -> dict[str, Any]:
    """The BOM of the language packages with a version, for osv-scanner.

    Only the components stay: osv-scanner has no use for the dependency graph and the
    Trivy findings. Trivy keeps the namespace of a package in ``group`` (a Maven
    group, an npm scope), but osv-scanner names the package it reports after ``name``
    alone, so the group is folded into the name as OSV writes it
    (``group:artifact``, ``@scope/name``).
    """
    kept = []
    for component in bom.get("components") or []:
        purl = component.get("purl") or ""
        ecosystem = purl.removeprefix("pkg:").split("/", 1)[0].lower()
        if (
            not purl.startswith("pkg:")
            or ecosystem in OS_PURL_TYPES
            or not component.get("version")
            or "@" not in re.split(r"[?#]", purl)[0]
        ):
            continue
        if group := component.get("group"):
            separator = ":" if ecosystem == "maven" else "/"
            component = {
                **{k: v for k, v in component.items() if k != "group"},
                "name": f"{group}{separator}{component.get('name')}",
            }
        kept.append(component)
    return {**bom, "components": kept, "dependencies": [], "vulnerabilities": []}


def scan_target(
    native: Path,
    bom_path: Path,
    output: Path,
    run: Runner,
    ref: str | None = None,
    offline: bool = False,
) -> tuple[str, str | None]:
    """Convert, filter and scan one target: ``(status, reason)``; the osv-scanner
    output is written to ``output``.

    An image target (``ref`` given) also scans the image itself, which queries OSV
    about its OS packages; its ``results`` are appended to the BOM output's. ``offline``
    queries local databases only (see the module docstring).
    """
    convert = ["trivy", "convert", "--format", "cyclonedx", "--output", str(bom_path)]
    converted = run([*convert, str(native)])
    if converted.returncode:
        code = converted.returncode
        return "failed", f"trivy convert failed (exit {code}): {tail(converted.stderr)}"
    try:
        bom = filter_bom(read_json(bom_path))
    except (OSError, ValueError, AttributeError) as err:
        return "failed", f"trivy convert wrote no valid BOM: {err}"
    dump_json(bom_path, bom)
    if bom["components"]:
        scan = ["scan", "source", "-L", str(bom_path), "--all-packages"]
        scan += ["--format", "json", "--output-file", str(output)]
        if offline:
            scan.append("--offline")
        scanned = run(["osv-scanner", *scan])
        if scan_failed(scanned, offline):
            code = scanned.returncode
            return "failed", f"osv-scanner failed (exit {code}): {tail(scanned.stderr)}"
    else:
        dump_json(output, {"results": []})
    if ref is None:
        return "ok", None
    try:
        # a separate file: the image scan must not overwrite the BOM output
        return scan_image(
            ref, output, bom_path.with_suffix(".image.json"), run, offline
        )
    finally:
        # cleanup, not a result: docker keeps every pulled image in its store
        run(["docker", "image", "rm", ref])


def scan_image(
    ref: str, output: Path, image_path: Path, run: Runner, offline: bool = False
) -> tuple[str, str | None]:
    """``osv-scanner scan image`` of one image reference: its ``results`` are
    concatenated onto the BOM query's ``results`` in ``output`` (the other top-level
    keys of the scan image output are dropped; the merge reads only ``results``).
    A failed scan is a failed target even though the BOM query succeeded: a target
    not scanned to the end never looks clean.
    """
    scan = ["scan", "image", ref, "--all-packages", "--format", "json"]
    scan += ["--output-file", str(image_path)]
    if offline:
        scan.append("--offline")
    scanned = run(["osv-scanner", *scan])
    if scan_failed(scanned, offline):
        code = scanned.returncode
        return (
            "failed",
            f"osv-scanner scan image failed (exit {code}): {tail(scanned.stderr)}",
        )
    try:
        results = [*read_json(output)["results"], *read_json(image_path)["results"]]
    except (OSError, ValueError, KeyError, TypeError) as err:
        # neutral wording: the BOM output of this target is read here too, so a
        # broken one would fail with the image scan blamed
        return "failed", f"no valid results to merge: {err}"
    dump_json(output, {"results": results})
    return "ok", None


def trivy_status(trivy_dir: Path, target_id: str) -> str:
    try:
        return str(read_json(trivy_dir / f"{target_id}.status.json")["status"])
    except (OSError, ValueError, KeyError, TypeError):
        return "failed"


def run_all(args: argparse.Namespace, run: Runner, now: datetime) -> None:
    offline = args.offline_db_dir is not None
    if offline:
        os.environ[CACHE_ENV] = str(args.offline_db_dir)
    # "osv-scanner version: 2.6.0"
    lines = run(["osv-scanner", "--version"]).stdout.strip().splitlines()
    version = lines[0].rpartition(":")[2].strip() if lines else None
    out_dir = args.output_dir / "osv"
    out_dir.mkdir(parents=True, exist_ok=True)
    trivy_dir = args.parts_dir / "trivy"
    with tempfile.TemporaryDirectory() as work:
        for target in read_json(args.targets_file)["targets"]:
            if target["scanner"] != "osv" or target["status"] != "pending":
                continue
            tid = target["id"]
            ref = target["ref"] if target["kind"] == "image" else None
            # osv-scanner takes the format of a BOM from its file name
            bom_path = Path(work) / f"{tid}.cdx.json"
            if (trivy := trivy_status(trivy_dir, tid)) != "ok":
                status, reason = "not_applicable", f"trivy target {trivy}"
            elif target.get("image_scan_disabled"):
                # the direct image scan is off for the repository; the BOM query runs
                # (ref=None), a failed one keeps its own reason, only a good one
                # states the exclusion
                status, reason = scan_target(
                    trivy_dir / f"{tid}.json",
                    bom_path,
                    out_dir / f"{tid}.json",
                    run,
                    offline=offline,
                )
                reason = (
                    reason
                    or target.get("image_scan_disabled_reason")
                    or IMAGE_SCAN_DISABLED_REASON
                )
            else:
                status, reason = scan_target(
                    trivy_dir / f"{tid}.json",
                    bom_path,
                    out_dir / f"{tid}.json",
                    run,
                    ref,
                    offline,
                )
            dump_json(
                out_dir / f"{tid}.status.json",
                {
                    "status": status,
                    "reason": reason,
                    "queried_at": format_time(now),
                    "scanner_version": version or None,
                },
            )
            print(f"{tid}: {status}" + (f" ({reason})" if reason else ""))


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--targets-file", required=True, type=Path)
    parser.add_argument("--parts-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument(
        "--offline-db-dir",
        type=Path,
        help="osv-scanner offline database cache; given: no query leaves the runner",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    run_all(parse_args(), run_command, datetime.now(UTC))
