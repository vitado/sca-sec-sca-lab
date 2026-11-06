"""Normalizers of the SCA merge: Trivy and osv-scanner results into findings.

A finding is one row per (target, scanner, class, id, package, version); the copies
of a finding in several lockfiles of one target are one row with several
``locations``. The ``id`` is the scanner's own: Trivy's ``VulnerabilityID``, the CVE
(or the lowest id) of an OSV group; ``names`` are the other names of the same
vulnerability. Severity and fixed version are the scanner's own. The package of an
OSV finding is looked up in the Trivy inventory of the same target, which gives the
finding its chain, dev flag and locations.
"""

from __future__ import annotations

import posixpath
import re
from collections import deque
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from _sca_lib import escape_command_data, read_json

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
OSV_URL = "https://osv.dev/vulnerability/"
CVSS_VENDORS = {"nvd": 0, "ghsa": 1, "redhat": 2}

Finding = dict[str, Any]
# (target id, scanner, class, id, normalized package name, version) -> finding
Findings = dict[tuple[str, str, str, str, str, str], Finding]
# (normalized package name, version) -> {chain, relationship, dev, locations}
Inventory = dict[tuple[str, str], dict[str, Any]]
# (class, normalized package name, installed version) of every package of a target
PackageSet = set[tuple[str, str, str]]


def no_graph() -> dict[str, Any]:
    """What a package without a dependency graph (an OS package) has."""
    return {"chain": [], "relationship": None, "dev": False}


def norm(name: str) -> str:
    """The name a package is matched by (PEP 503 for every ecosystem)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def pick_id(ids: list[str]) -> str:
    """The first CVE (in string order) among the ids, else the first id."""
    cves = sorted(i for i in ids if i.startswith("CVE-"))
    return cves[0] if cves else ids[0]


def add_finding(findings: Findings, row: Finding) -> None:
    """Add a finding; a copy of a known one only adds its locations."""
    key = (
        row["target"],
        row["scanner"],
        row["class"],
        row["id"],
        norm(row["pkg"]),
        row["version"],
    )
    known = findings.setdefault(key, row)
    if known is not row:
        known["locations"] += [
            loc for loc in row["locations"] if loc not in known["locations"]
        ]


# ---------------------------------------------------------------- Gradle graph


def load_gradle_graphs(graph_dir: Path, tid: str) -> dict[str, tuple[set, dict]]:
    """The graph files written by lockfiles.init.gradle: project dir -> (direct
    modules, module -> modules it depends on), united over all configurations. A file
    that cannot be read is skipped with a warning.
    """
    graphs: dict[str, tuple[set[str], dict[str, set[str]]]] = {}
    for path in sorted(graph_dir.glob("*.json")):
        try:
            data = read_json(path)
            direct: set[str] = set()
            edges: dict[str, set[str]] = {}
            for config in data["configurations"].values():
                direct.update(config["direct"])
                for module, deps in config["modules"].items():
                    edges.setdefault(module, set()).update(deps)
            graphs[posixpath.normpath(data["project_dir"])] = (direct, edges)
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            print(
                "::warning title=Gradle dependency graph ignored::"
                + escape_command_data(f"{tid}: {path.name}: {e!r}")
            )
    return graphs


def apply_gradle_graph(tid: str, native: Mapping[str, Any], graph_dir: Path) -> None:
    """Fill ``Relationship`` and ``DependsOn`` of the packages of the gradle Results
    of an fs scan (a lockfile has no graph), in memory: ``_native/`` stays as is.
    """
    results = [r for r in native.get("Results") or [] if r.get("Type") == "gradle"]
    graphs = load_gradle_graphs(graph_dir, tid) if results else {}
    for result in results:
        graph = graphs.get(posixpath.normpath(posixpath.dirname(result["Target"])))
        if graph is None:
            print(
                "::warning title=No Gradle dependency graph::"
                + escape_command_data(
                    f"{tid}: {result['Target']} has no dependency graph, "
                    "so its findings have no chains"
                )
            )
            continue
        direct, edges = graph
        packages = result.get("Packages") or []
        ids = {p["ID"] for p in packages if p.get("ID")}
        for package in packages:
            module = package.get("ID")
            if module in direct or module in edges:
                package["Relationship"] = "direct" if module in direct else "indirect"
                package["DependsOn"] = sorted(
                    (edges.get(module, set()) & ids) - {module}
                )


# ---------------------------------------------------------------- Trivy


def shortest_chain(
    start: str, packages: Mapping[str, Any], parents: Mapping[str, list[str]]
) -> list[str]:
    """Names from the nearest direct dependency down to ``start``: a reverse
    breadth-first walk over ``DependsOn``; the visited set makes it cycle-safe.
    Empty if no direct dependency leads to it.
    """
    seen = {start}
    queue = deque([[start]])
    while queue:
        path = queue.popleft()
        if packages[path[-1]].get("Relationship") == "direct":
            return [packages[i]["Name"] for i in reversed(path)]
        for parent in parents.get(path[-1], []):
            if parent not in seen:
                seen.add(parent)
                queue.append([*path, parent])
    return []


def package_graph_info(
    pid: str, packages: Mapping[str, Any], parents: Mapping[str, list[str]]
) -> dict[str, Any]:
    package = packages.get(pid, {})
    relationship = package.get("Relationship")
    known = relationship in ("direct", "indirect")
    return {
        "chain": shortest_chain(pid, packages, parents) if known else [],
        "relationship": relationship,
        "dev": bool(package.get("Dev")),
    }


def normalize_trivy(
    tid: str, native: Mapping[str, Any], findings: Findings, inventory: Inventory
) -> PackageSet:
    """The vulnerabilities of a Trivy result as findings; every language package
    (vulnerable or not) goes into ``inventory`` for the OSV findings and the images.
    Returns every package of the result, language and OS, as ``(class, name,
    version)`` (the version as the findings spell it).
    """
    seen: PackageSet = set()
    for result in native.get("Results") or []:
        lang = result.get("Class") != "os-pkgs"
        packages = {
            p.get("ID") or f"{p['Name']}@{p.get('Version')}": p
            for p in result.get("Packages") or []
        }
        sources: dict[tuple[str, str], str] = {}  # (name, version) -> source package
        for package in packages.values():
            epoch, release = package.get("Epoch"), package.get("Release")
            version = f"{epoch}:" * bool(epoch) + (package.get("Version") or "")
            version += f"-{release}" * bool(release)
            seen.add(("lang" if lang else "os", norm(package["Name"]), version))
            if package.get("SrcName"):
                sources[package["Name"], version] = package["SrcName"]
        parents: dict[str, list[str]] = {}
        for pid, package in packages.items():
            for dep in package.get("DependsOn") or []:
                parents.setdefault(dep, []).append(pid)

        if lang:
            for pid, package in packages.items():
                entry = inventory.setdefault(
                    (norm(package["Name"]), package.get("Version")),
                    {**package_graph_info(pid, packages, parents), "locations": []},
                )
                location = package.get("FilePath") or result["Target"]
                if location not in entry["locations"]:
                    entry["locations"].append(location)
        for vuln in result.get("Vulnerabilities") or []:
            vid = vuln["VulnerabilityID"]
            name, version = vuln["PkgName"], vuln["InstalledVersion"]
            graph = no_graph()
            src_pkg = None
            if not lang:  # the source package of a distribution package
                src_pkg = vuln.get("SrcName") or sources.get((name, version))
            if lang:
                pid = vuln.get("PkgID") or f"{name}@{version}"
                graph = package_graph_info(pid, packages, parents)
            add_finding(
                findings,
                {
                    "target": tid,
                    "scanner": "trivy",
                    "id": vid,
                    "aliases": [i for i in vuln.get("VendorIDs") or [] if i != vid],
                    "names": [vid],
                    "published": (vuln.get("PublishedDate") or "")[:10] or None,
                    "modified": (vuln.get("LastModifiedDate") or "")[:10] or None,
                    "cvss": trivy_cvss(vuln.get("CVSS") or {}),
                    "pkg": name,
                    "version": version,
                    "ecosystem": result["Type"],
                    "class": "lang" if lang else "os",
                    "locations": [vuln.get("PkgPath") or result["Target"]]
                    if lang
                    else [],
                    "severity": vuln.get("Severity", "UNKNOWN"),
                    "fixed_version": vuln.get("FixedVersion", ""),
                    "dev": graph["dev"],
                    "relationship": graph["relationship"],
                    "chain": graph["chain"],
                    "title": vuln.get("Title") or "",
                    "url": vuln.get("PrimaryURL", ""),
                    "summary": None,
                    "src_pkg": src_pkg or None,
                },
            )
    return seen


# ---------------------------------------------------------------- OSV


def severity_of_score(score: Any) -> str:
    """The rating of a CVSS base score (osv-scanner's ``max_severity``)."""
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "UNKNOWN"
    for bound, name in ((9, "CRITICAL"), (7, "HIGH"), (4, "MEDIUM"), (0.1, "LOW")):
        if value >= bound:
            return name
    return "UNKNOWN"


NAME_PREFIXES = ("CVE-", "GHSA-", "PYSEC-", "GO-", "RUSTSEC-")
OWN_CVE = re.compile(r"(?:[A-Z]+-)?(CVE-\d+-\d+)")


def trivy_cvss(cvss: Mapping[str, Mapping[str, Any]]) -> dict[str, Any] | None:
    """The CVSS of a Trivy vulnerability: the first vendor (nvd, ghsa, redhat, then
    by name) with a v3 score or vector, else the first with v4. V2 is ignored."""
    vendors = sorted(cvss, key=lambda v: (CVSS_VENDORS.get(v, len(CVSS_VENDORS)), v))
    for version in ("V3", "V40"):
        for vendor in vendors:
            score = cvss[vendor].get(version + "Score")
            vector = cvss[vendor].get(version + "Vector")
            if score is not None or vector:
                return {"score": score, "vector": vector, "source": vendor}
    return None


def osv_cvss(records: Sequence[Mapping[str, Any]]) -> dict[str, Any] | None:
    """The first CVSS_V3 vector of the records (the member that gives the rating
    first), else the first CVSS_V4 (no score: the engine has no calculator)."""
    records = sorted(
        records, key=lambda v: not (v.get("database_specific") or {}).get("severity")
    )
    ratings = [r for v in records for r in v.get("severity") or []]
    for kind in ("CVSS_V3", "CVSS_V4"):
        if vector := next((r["score"] for r in ratings if r.get("type") == kind), None):
            return {"score": None, "vector": vector, "source": "osv"}
    return None


def names_of(vid: str, ids: Sequence[str]) -> list[str]:
    """The id first, then the other names of the vulnerability (the CVE, GHSA,
    PYSEC, GO and RUSTSEC ids among ``ids``) in string order."""
    return [vid, *sorted({i for i in ids if i.startswith(NAME_PREFIXES)} - {vid})]


def earliest(records: Sequence[Mapping[str, Any]]) -> str | None:
    """The first ``published`` date (``YYYY-MM-DD``) of the records, if any."""
    dates = [r["published"][:10] for r in records if r.get("published")]
    return min(dates, default=None)


def latest(records: Sequence[Mapping[str, Any]]) -> str | None:
    """The last ``modified`` date (``YYYY-MM-DD``) of the records, if any."""
    dates = [r["modified"][:10] for r in records if r.get("modified")]
    return max(dates, default=None)


def ubuntu_priority(record: Mapping[str, Any]) -> str:
    """The Ubuntu priority of an OSV record as a severity (negligible is LOW),
    ``UNKNOWN`` without one."""
    for rating in record.get("severity") or []:
        if rating.get("type") == "Ubuntu":
            score = str(rating.get("score")).upper().replace("NEGLIGIBLE", "LOW")
            return score if score in SEVERITIES else "UNKNOWN"
    return "UNKNOWN"


def fixed_of(records: Sequence[Mapping[str, Any]], name: str) -> str:
    """The fixes of every branch of the records for the package ``name``: ECOSYSTEM
    and SEMVER ranges (GIT ranges hold commits)."""
    return ", ".join(
        dict.fromkeys(
            event["fixed"]
            for v in records
            for affected in v.get("affected", [])
            if affected.get("package", {}).get("name") == name
            for rng in affected.get("ranges", [])
            if rng.get("type") in ("ECOSYSTEM", "SEMVER")
            for event in rng.get("events", [])
            if "fixed" in event
        )
    )


def normalize_osv(
    tid: str, native: Mapping[str, Any], findings: Findings, inventory: Inventory
) -> None:
    """Findings of the osv-scanner groups of a package. A group of ``lang`` is one
    finding: severity is the rating the database gives (GHSA), else the bucket of
    the group's CVSS score. A group of ``os`` is one finding per own CVE (an id
    ``CVE-Y-N`` or ``<PREFIX>-CVE-Y-N``) with the fields of that CVE's record only:
    the Ubuntu priority as severity (``UNKNOWN`` without one), never the bundle's
    CVSS or CVEs. A group of bulletins only (``USN-*``) is one ``UNKNOWN`` finding.

    The results of the BOM query and of a direct image scan are one list, so the
    class is derived per result entry: a result of an OS source holds OS packages.
    An OS package is reported under its installed name (``os_package_name``, what
    Trivy reports as ``Name`` too, so the rows line up) while OSV keys the record -
    and the ``fixed`` filter - by the source name.
    """
    for result in native["results"]:
        cls = "os" if result["source"]["type"] == "os" else "lang"
        for entry in result["packages"]:
            vulns = {v["id"]: v for v in entry.get("vulnerabilities", [])}
            package = entry["package"]
            name, version = package["name"], package["version"]
            pkg = package.get("os_package_name") or name
            own = inventory.get((norm(pkg), version), {**no_graph(), "locations": []})
            by_cve: dict[str, Mapping[str, Any]] = {}  # CVE -> its record
            for v in sorted(
                vulns.values() if cls == "os" else (),
                key=lambda v: (ubuntu_priority(v) == "UNKNOWN", v["id"]),
            ):
                if m := OWN_CVE.fullmatch(v["id"]):
                    by_cve.setdefault(m[1], v)
            for group in entry.get("groups", []):
                gids = group["ids"]
                members = [vulns[i] for i in gids if i in vulns]
                ids = list(dict.fromkeys(gids + group.get("aliases", [])))
                cves: dict[str, str] = {}  # own CVE -> the group id it comes from
                for i in gids if cls == "os" else []:
                    if m := OWN_CVE.fullmatch(i):
                        cves.setdefault(m[1], i)
                # (id, aliases, names, severity, records, id of the url)
                parts = []
                for cve, gid in sorted(cves.items()):
                    rec = by_cve.get(cve) or {"id": gid}
                    aliases = rec.get("aliases", [])
                    parts.append(
                        (
                            cve,
                            [rec["id"], *aliases],
                            names_of(cve, aliases),
                            ubuntu_priority(rec),
                            [rec],
                            rec["id"],
                        )
                    )
                if cls == "os" and not cves:
                    vid = min(gids)
                    parts.append((vid, ids, [vid], "UNKNOWN", members, gids[0]))
                elif cls == "lang":
                    vid = pick_id(ids)
                    rating = next(
                        (
                            v["database_specific"]["severity"]
                            for v in members
                            if (v.get("database_specific") or {}).get("severity")
                        ),
                        None,
                    )
                    rating = {"MODERATE": "MEDIUM"}.get(rating, rating)
                    if rating not in SEVERITIES:
                        rating = severity_of_score(group.get("max_severity"))
                    parts.append(
                        (vid, ids, names_of(vid, ids), rating, members, gids[0])
                    )
                for vid, aliases, names, severity, records, url_id in parts:
                    first = records[0] if records else {}
                    details = (first.get("details") or "").splitlines()
                    add_finding(
                        findings,
                        {
                            "target": tid,
                            "scanner": "osv",
                            "id": vid,
                            "aliases": [i for i in aliases if i != vid],
                            "names": names,
                            "published": earliest(records),
                            "modified": latest(records),
                            "cvss": osv_cvss(records),
                            "pkg": pkg,
                            "version": version,
                            "ecosystem": package["ecosystem"],
                            "class": cls,
                            "locations": list(own["locations"]),
                            "severity": severity,
                            "fixed_version": fixed_of(records, name),
                            "dev": own["dev"],
                            "relationship": own["relationship"],
                            "chain": own["chain"],
                            "title": first.get("summary") or next(iter(details), ""),
                            "url": OSV_URL + url_id,
                            "summary": first.get("summary") or None,
                            "src_pkg": None,
                        },
                    )


def borrow_source_chains(
    findings: Findings,
    inventories: Mapping[str, Inventory],
    source_targets: Sequence[Mapping[str, Any]],
    image_targets: Sequence[Mapping[str, Any]],
) -> None:
    """A language package of an image without a chain (an image has no graph) takes
    the chain of the same package and version from a source target of the repo: the
    source of its own release tag first, else the first source where the package
    and version match. The dev flag is not borrowed: what is in an image is shipped.
    The release of an image is the ``ref`` of its target (the registry tag, which may
    lack the ``v`` of the git tag the source's ``ref`` is).
    """
    sources = [(t["id"], t.get("ref") or "") for t in source_targets]
    source_ids = {sid for sid, _ in sources}
    image_refs = {t["id"]: t.get("ref") or "" for t in image_targets}

    def borrow(row, sid: str) -> bool:
        known = inventories.get(sid, {}).get((norm(row["pkg"]), row["version"]))
        if known and known["chain"]:
            row["chain"] = known["chain"]
            row["relationship"] = known["relationship"]
            return True
        return False

    for row in findings.values():
        if row["class"] != "lang" or row["chain"] or row["target"] in source_ids:
            continue
        release_tag = image_refs.get(row["target"], "")
        # the source of the release the image was built from, then the rest
        for sid, ref in sources:
            if borrow(row, sid) and ref.removeprefix("v") == release_tag:
                break
        else:
            for sid, _ in sources:
                if borrow(row, sid):
                    break
