"""One fixed run (source and image of the default branch, a release source, a
``.trivyignore``) merged into ``report.json``; its output is kept as a golden file
so a change of the engine shows what it did to a report that does not use it.
"""

import json
from pathlib import Path

from _sca_lib import dump_json
from merge_results import run_merge
from test_merge_results import DB, osv_native, target

NOW = "2026-10-14T00:00:00Z"
GOLDEN = Path(__file__).parent / "golden" / "report.json"

SRC_VULNS = [
    {
        "VulnerabilityID": "CVE-2026-1",
        "PkgName": "a",
        "PkgID": "a@1",
        "InstalledVersion": "1",
        "Severity": "HIGH",
        "FixedVersion": "2",
        "Title": "  A flaw\n in a  ",
    },
    {
        "VulnerabilityID": "CVE-2026-2",
        "PkgName": "Py_B",
        "PkgID": "Py_B@3",
        "InstalledVersion": "3",
        "Severity": "LOW",
    },
]
IMG_NATIVE = {
    "Trivy": {"Version": "0.75.0"},
    "Metadata": {"OS": {"Family": "ubuntu", "Name": "24.04"}},
    "Results": [
        {
            "Target": "ubuntu",
            "Type": "ubuntu",
            "Class": "os-pkgs",
            "Packages": [
                {"Name": "libc6", "Version": "2.39", "SrcName": "glibc"},
                {"Name": "linux-libc-dev", "Version": "6.8"},
            ],
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2026-10",
                    "PkgName": "libc6",
                    "InstalledVersion": "2.39",
                    "SrcName": "glibc",
                    "Severity": "MEDIUM",
                    "FixedVersion": "2.40",
                    "Title": "libc title",
                },
                {
                    "VulnerabilityID": "CVE-2026-11",
                    "PkgName": "linux-libc-dev",
                    "InstalledVersion": "6.8",
                    "Severity": "MEDIUM",
                },
            ],
        }
    ],
}


def source_native(vulns=SRC_VULNS):
    return {
        "Trivy": {"Version": "0.75.0"},
        "Metadata": {},
        "Results": [
            {
                "Target": "package-lock.json",
                "Type": "npm",
                "Class": "lang-pkgs",
                "Packages": [
                    {"ID": "a@1", "Name": "a", "Version": "1"},
                    {"ID": "Py_B@3", "Name": "Py_B", "Version": "3"},
                ],
                "Vulnerabilities": list(vulns),
            }
        ],
    }


def merged(tmp_path: Path, header: dict | None = None) -> bytes:
    """The ``report.json`` bytes of the run, ``header`` extra keys of ``targets.json``."""
    tmp_path.mkdir(exist_ok=True)
    release = {**target("source-1.0.0", "trivy"), "git_ref": "1.0.0"}
    image = {**target("image-dev", "trivy", "image"), "tag": "development"}
    targets = [
        target("source-development", "trivy"),
        target("source-development", "osv"),
        release,
        image,
    ]
    doc = {
        "repo": "o/app",
        "default_branch": "development",
        "commit_sha": "0123456789abcdef",
        "run_id": "1",
        "run_url": "https://example.test/run/1",
        "targets": targets,
        **(header or {}),
    }
    (tmp_path / "targets.json").write_text(json.dumps(doc))
    trivy = tmp_path / "parts" / "trivy"
    trivy.mkdir(parents=True)
    osv = tmp_path / "parts" / "osv"
    osv.mkdir()
    natives = {
        "source-development": source_native(),
        "source-1.0.0": source_native(SRC_VULNS[:1]),
        "image-dev": IMG_NATIVE,
    }
    for tid, native in natives.items():
        (trivy / f"{tid}.json").write_text(json.dumps(native))
        status = {"status": "ok"}
        if tid == "source-development":
            status["ignorefile"] = "present"
        (trivy / f"{tid}.status.json").write_text(json.dumps(status))
    (trivy / "source-development.trivyignore").write_text(
        "# reason\nCVE-2026-1 exp:2099-01-01\n"
    )
    (osv / "source-development.json").write_text(json.dumps(osv_native()))
    (osv / "source-development.status.json").write_text(json.dumps({"status": "ok"}))
    run_merge(tmp_path / "targets.json", tmp_path / "parts", tmp_path / "out", NOW, DB)
    return (tmp_path / "out" / "report.json").read_bytes()


if __name__ == "__main__":  # regenerate the golden file: python golden_case.py DIR
    import sys

    GOLDEN.parent.mkdir(exist_ok=True)
    GOLDEN.write_bytes(merged(Path(sys.argv[1])))


def as_before(raw: bytes, scratch: Path) -> bytes:
    """``report.json`` as the engine wrote it before the fields of the report
    additions: ``src_pkg`` and ``summary`` of the findings, ``role`` of a version,
    ``pkg_key`` and ``src_pkg`` of a vulnerability record and a package, ``title``
    of a record, removed. Same key order and format as the engine's own dump.
    """
    report = json.loads(raw)
    for finding in report["findings"]:
        del finding["src_pkg"], finding["summary"]
    for version in report["versions"]:
        del version["role"]
        for record in version["vulns"]:
            del record["pkg_key"], record["src_pkg"], record["title"]
        for package in version["packages"]:
            del package["pkg_key"], package["src_pkg"]
    dump_json(scratch / "before.json", report)
    return (scratch / "before.json").read_bytes()
