# ai-dial-sec-sca

Composite GitHub Actions that run the software composition analysis (SCA) scan of AI DIAL repositories: [Trivy](https://trivy.dev/) finds known vulnerabilities in every target, [OSV](https://osv.dev/) then checks the language packages Trivy found plus, for image targets, the image itself (its OS packages included), and the results are merged into one report.

These actions are called by the `sca_scheduled.yml` workflow of [epam/ai-dial-ci](https://github.com/epam/ai-dial-ci). They are not meant to be used directly: repositories call that workflow, which orchestrates the scan and the actions below.

## Actions

- `actions/sca_resolve_targets`: builds the list of scan targets and resolves the releases: the default branch source, the source of each release of the release set, and, per image, `development` and the same release tags. The release set is the newest patch of each of the last `release-lines` (default 2) minor lines (`X.Y.Z` tags of non-prerelease, non-draft GitHub releases), plus at most one candidate. The candidate is the newest prerelease (by version, `X.Y.Z-pre`) whose base version is greater than the newest stable; a prerelease of an already published version is not scanned. A stable release whose tag is not `X.Y.Z` is left out of the set and counted in one notice. The release listing is read page by page (up to 1000 releases). Inputs: `scan-tag` focuses the run on one git tag (its source and the tag in every image, no `development`); `osv-image-scan` is the repository's own setting that switches the direct OSV image scan off; `force-image-scan` runs that scan anyway (a manual run) and marks the run with `forced_image_scan` in `targets.json` and `report.json`. Pass `osv-image-scan` as the repository sets it, not combined with the force flag: the action does the combining.
- `actions/sca_query_osv`: checks the language packages found by Trivy against OSV with osv-scanner; an image target also gets a direct `osv-scanner scan image`, which reads the image's own package database and so checks its OS packages against OSV correctly (a BOM cannot: OSV keys its records by the source package name). The BOM query runs either way, so a package either detector sees keeps its OSV check. Inputs: `targets-file`, `parts-dir`, `output-dir`, and `trivy-version` (a release tag, e.g. `v0.75.0`). The action installs Trivy from the aquasecurity/trivy GitHub release of that version: the archive is checked against the `checksums.txt` of the release and the install is cached by version, OS and architecture.
- `actions/sca_merge_results`: normalizes the Trivy and OSV reports, merges them into `report.json` and writes the `summary.md` job summary (see below).
- `actions/_install_trivy`: installs Trivy from the GitHub release of `version` (see `sca_query_osv`); `sca_query_osv` repeats its steps and shares its `install.sh`, because a composite action cannot use a sibling action by a relative path.
- `actions/generate_gradle_lockfiles`: generates Gradle lockfiles on the fly so Trivy can resolve Gradle dependencies (repository files are not modified).

The actions share the code in `actions/_sca_lib` (it is imported through `PYTHONPATH=${{ github.action_path }}/..`, so the `actions/` layout must stay as it is).

## Job summary

`summary.md` is organized by version (a branch or a release tag), because a fixer needs to know what to bump where. Only two tables and the version headings are visible; everything else is collapsed. The numbers come from `versions[]` of `report.json`, so the summary and the report agree.

- `Vulnerabilities`: one row per scanned version (`development` first, then releases from the newest) with the vulnerabilities by severity (`versions[].counts`) and how many have a fix (`Fixable`). A version whose scan failed shows what its `ok` targets found and is marked `(partial)`, as is `All (unique)` when any version failed. The last row, `All (unique)`, counts a vulnerability once however many versions have it, at its worst severity.
- `Packages to update`: the same rows with the vulnerable libraries by their worst severity, the vulnerable OS packages and how many packages have a fix. A package in several versions counts once in the last row.
- A section per version with its libraries and base image OS packages, each in a collapsed table. A package seen in the source and in the images of one version is one row, with `Seen in` naming where (`src` or the image name). Rows with a fix come first, development-only packages (marked `dev`) after the others, packages with no fix last, then by severity.
- `Ignore file`: the audit of the `.trivyignore` lines (expired, without expiry, with a bad date, matching nothing). When the file was not read, a line under the header says why (`Risk acceptance not applied: ...`); a run focused on one tag says nothing.
- `Scan details by target`: the status of every scan, including the failed and not applicable ones.
- Health warnings under the header: the Trivy DB is older than 48 hours at the time of the report, or an `ok` Trivy target scanned no packages.

Marks after a vulnerability id, in brackets:

- `new in DB`: the vulnerability was published at most 14 days before the run.
- `accepted until D`: a line of the default-branch `.trivyignore` accepts it until `D` (see Risk acceptance).
- `fixed in X`: on a release or a release candidate older than the newest release `X`: none of the names of the vulnerability is found in `X` (same class; the package name does not count, so a renamed package is not a fix). Shown only when both versions have the same targets, all their Trivy scans are `ok` and none scanned 0 packages.

A package is not fixable when none of its vulnerabilities has a fixed version. If only some have one, it counts as fixable and `Fixed` lists the versions that exist.

## Tests

```sh
python -m pip install pytest
python -m pytest test/sca
```

The tests need Python 3.12 and no network access. They run in GitHub Actions on every push and pull request to `main`.

## report.json

`sca_merge_results` writes `report.json` (`schema_version` 4):

- the header: `engine` (the ref of `sca_merge_results` as the runner resolved it: a tag, a branch or a commit SHA; `null` outside GitHub Actions), `repo`, `commit_sha`, `default_branch`, `run_id`, `run_attempt`, `run_url`, `generated_utc`, `event`, `actor`, and, when set, `scan_ref` and `forced_image_scan`;
- `tools`: the versions of Trivy and osv-scanner, the Trivy DBs and the OSV query time;
- `targets[]`: every target with its `status` (`ok`, `failed`, `not_applicable`) and `packages_scanned`; a Trivy image target also has `os` (`{family, name, eosl}` from the Trivy result, `eosl` true for an end-of-life distribution; `null` when the scan has no OS data: failed, `not_applicable`, source targets), the OSV entry does not; the Trivy and the OSV scan of a target are two entries with one id;
- `findings[]`: the raw layer, one finding per vulnerability in one package of one target from one scanner. Fields include `id`, `names`, `published`, `modified`, `cvss`, `severity`, `fixed_version`;
- `versions[]`: the vulnerability records per version;
- `ignores[]` and `ignores_error`: risk acceptance (see below).

### versions[]

A version is all targets of one ref. Its fields: `ref`, `kind` (`development`, `release`, `candidate`), `latest` (the newest `ok` release), `status`, `targets` (target ids), `counts`, `vulns[]` and `packages[]`.

- `status` is `failed` only when a scan of one of its targets failed (Trivy, or OSV `failed`). `ok` does not mean every target was scanned: a `not_applicable` target (for example an image not published for the tag yet) does not fail the version; read the statuses in `targets[]` for the coverage. A `failed` version keeps the records and counts of its `ok` targets, so they are partial.
- `counts`: `c`, `h`, `m`, `l`, `unknown` (severities), `all` and `fixable`, computed from the `vulns[]` of the version. The unit is one vulnerability in one package.
- `vulns[]`, sorted by the key `(class, norm(pkg), id)`, where `norm(pkg)` is the package name in lowercase with each run of `-`, `_` and `.` turned into one `-`; the package version and the ref are not part of it. A record: `id`, `names`, `pkg`, `class` (`lang` for an application dependency, `os` for an image OS package), `severity`, `fixed`, `dev`, `installed`, `where` (target ids), `sources` (`trivy`, `osv`), `published` (the earliest date among the findings, or `null`), `modified` (the latest date among the findings, or `null`), `cvss` (`{score, vector, source}` of the first finding that has a score, else of the first with a vector, else `null`; scores come from Trivy only (v3 before v4, vendor order nvd, ghsa, redhat, then by name), an OSV-only record has a vector and a `null` score), `aliases` (the other ids the scanners list for it that are not in `names`, display only: never used for merging or acceptance), `ecosystem` (the OSV ecosystem name to query OSV with: the one of an OSV finding, else mapped from the Trivy type of a `lang` record, else `null`), `relationship` (`direct` over `indirect`, else the first known value, or `null`), `locations` (manifest or file paths) and `accepted` (`{"until": "YYYY-MM-DD"}` or `null`). Title and url are not on the record: the findings of a record are those of the version's targets with the same `class`, `norm(pkg)` and an `id` that is in the record `names` (exact: every finding id is its own first name, and findings merge into a record when their names intersect).
- `packages[]`, sorted by `(class, norm(pkg))`: for every package that has a record in any version of the run, one entry per version with `pkg`, `class`, `installed` (the versions present in the targets of this version) and `where` (the target ids). The package is listed whether or not it is vulnerable in this version, so a package that is clean in one version and vulnerable in another shows what each runs. `installed` is sorted as strings, not by version. `[]` in both fields means the package is in none of the `ok` targets of the version; a `failed` or `not_applicable` target is not evidence of absence (read the statuses in `targets[]`). The source is the Trivy package lists of the `ok` targets (language and OS) plus the version's own records; a `failed` or `not_applicable` target adds nothing. Packages without any record are not listed.

How the records are made. The findings of a version for one package merge into one record when their `names` intersect; `names` are the id and the real aliases of one vulnerability.

- Trivy: the id is `VulnerabilityID`; `names` is the id alone.
- OSV library advisories (`lang`): the id is the smallest CVE among the ids and aliases of the advisory, so a GHSA and its CVE are one record from the first day; without a CVE, the first id. `names` are the ids and aliases (CVE, GHSA, PYSEC, GO, RUSTSEC).
- OSV OS groups (`os`): one record per own CVE of the group (`UBUNTU-CVE-Y-N` reads as `CVE-Y-N`), with the fields of the member record of that CVE (a record with an Ubuntu priority is preferred). The CVEs that are only aliases of the group are not records: they are the list of a bulletin, not names of this package's vulnerabilities. A group of bulletins alone (`USN-...`) gives one record with the bulletin id and severity `UNKNOWN`.
- Severity: the worst Trivy rating among the record's findings, else the worst OSV rating. An OSV-only `os` record takes the Ubuntu priority of its member (`negligible` as `LOW`); other distributions give no priority, so `UNKNOWN`.
- `fixed` joins the fixed versions of the findings (Trivy first); `dev` is true only when every finding is for a development-only package.

## Risk acceptance

The engine reads the `.trivyignore` of the default branch and marks the records of every version; no finding is removed, and the scheduled scan itself does not apply ignores. The workflow passes the file and states `ignorefile` (`present`, `absent`, or `null` when the checkout failed) in the `status.json` of the source target of the default branch.

- The grammar is the plain Trivy one: the first field of a line is the id, the first `exp:YYYY-MM-DD` counts, a line with a bad date does not act (the file as a whole is still read), a comment is a whole line starting with `#`, blank lines are skipped.
- `reason`: the text of the comment lines directly above a line (leading `#` and spaces dropped, joined by a space), `null` when there is none. A blank line or another ignore line ends the block. It is information for readers and never acts.
- A line accepts a record only with an acting `exp:` (the date is after the day of the run; on the day itself it no longer acts), and only when its id equals the `id` or one of the `names` of the record. It matches in every version of the run. The matching is by id and names only, so it can be wider than the Trivy gate itself: purl and path scoping on a line is not applied.
- Intended differences from Trivy: a line without `exp:` is not an acceptance here (Trivy ignores such a vulnerability forever); when several lines name one vulnerability, the earliest acting date wins (Trivy takes the first match).
- `ignores[]`: per line `id`, `until`, `expired`, `bad_expiry`, `no_expiry`, `matched` (the line matched a record of any version) and `reason`.
- `ignores_error` is `null`, or the reason `ignores` is `null` (no record is `accepted` then): `the workflow does not pass the ignore file`, `no readable status file for <id>` (the `status.json` of the default-branch source target is missing, unreadable or not a JSON object), `unexpected ignorefile value: ...`, `checkout failed`, `no default-branch target in this run` (a run focused on one tag), or the file could not be read.
- `.trivyignore.yaml` is not read.

## Versioning

Releases are git tags `vX.Y.Z`. Schema 4 of `report.json` is a breaking change: the `counts` block is gone (the numbers are in `versions[].counts`), and `findings[]` changed too: a Trivy finding's id is `VulnerabilityID` (no longer the lowest CVE among `VulnerabilityID` and `VendorIDs`); an OSV `os` group gives one finding per own CVE with that member's Ubuntu priority, fixes and date (was one finding per group with the group's CVSS bucket); a bulletin-only group gives one `UNKNOWN` finding with the smallest bulletin id. Consumers therefore branch on `schema_version`. Consumers pin a tag, for example:

```yml
- uses: epam/ai-dial-sec-sca/actions/sca_merge_results@v0.7.0
```

The third-party actions are pinned by commit SHA and osv-scanner by the sha256 of its binary (in `actions/sca_query_osv/action.yml`). Trivy is pinned by version only: the install checks the download against the checksums published with the same release, not against a value pinned here.

## License

Apache-2.0, see [LICENSE](LICENSE).
