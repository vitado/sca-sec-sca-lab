Security fixes for `release-1.2` (1.2.3).

Scan: https://github.com/o/r/actions/runs/11, https://github.com/o/r/actions/runs/12

Each change was rescanned with Trivy and OSV: the targeted vulnerabilities are gone and no new High or Critical appeared.

| Package | Installed -> new | Method | Status | Vulnerabilities | Note |
|---|---|---|---|---|---|
| axios | - | dependabot | fixed | CVE-axios | fixed with hono |
| hono | 1.0.0 -> 1.0.2 | dependabot | fixed | CVE-hono |  |
| debug | - | dependabot | already fixed | CVE-debug |  |
| glob | - | manual | open | CVE-glob | why glob |

Baseline CI (informational): latest completed run on the branch before this change: success.

<details><summary>Skipped by the planner</summary>

- glob (lang): not fixed in development

</details>
