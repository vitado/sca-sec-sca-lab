Security fixes for `release-1.2` (1.2.3).

Each change was rescanned with Trivy and OSV: the targeted vulnerabilities are gone and no new High or Critical appeared.

| Package | Installed -> new | Method | Status | Vulnerabilities | Note |
|---|---|---|---|---|---|
| fixed-by-other | - | dependabot | fixed | CVE-fixed-by-other | fixed with pyyaml |
| follow-redirects | 1.0.0 -> 1.0.1 | npm-override | fixed | CVE-follow-redirects |  |
| pyyaml | 1.0.0 -> 1.0.2 | dependabot | fixed | CVE-pyyaml |  |

### Side effects

- follow-redirects: also changed by npm resolution: ms 1.0.0 -> 1.0.1; debug 2.0.0 -> 2.0.1
- pyyaml: 2 version(s) of a file change left out, their edits overlap with an earlier one
- poetry.lock: written by Poetry 2.1.0, was 1.8.3
- package-lock.json: updated with npm 10.9.2, lockfile format unchanged

Baseline CI (informational): latest completed run on the branch before this change: failure (commit status: ci/build). The baseline is red: failures that were there before this change are not caused by it and the rescan gate does not look at them.
