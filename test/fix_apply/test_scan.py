from builders import finding, item
from scan import gate, new_serious, parse_trivy


def test_parse_trivy() -> None:
    vuln = {
        "PkgName": "a",
        "InstalledVersion": "1",
        "VulnerabilityID": "CVE-1",
        "Severity": "HIGH",
    }
    document = {"Results": [{"Vulnerabilities": [vuln]}, {"Target": "no findings"}]}
    assert parse_trivy(document) == {finding("a", "CVE-1", "HIGH", "1")}
    assert parse_trivy({}) == set()


def test_gate_passes_when_the_vulnerability_is_gone() -> None:
    vuln = finding()
    assert gate(item(), {vuln}, set(), {vuln}) is None


def test_gate_matches_by_alias_and_normalized_package_name() -> None:
    before = {finding("Hono", "GHSA-hono")}
    assert gate(item(), before, set(), before) is None


def test_gate_fails_when_the_vulnerability_was_not_in_the_baseline() -> None:
    assert "not in the baseline" in str(gate(item(), set(), set(), set()))


def test_gate_fails_when_still_present() -> None:
    vuln = finding()
    assert "still present" in str(gate(item(), {vuln}, {vuln}, {vuln}))


def test_gate_fails_on_a_new_serious_vulnerability() -> None:
    vuln = finding()
    other = finding("other", "CVE-new", "CRITICAL")
    assert "CVE-new" in str(gate(item(), {vuln}, {other}, {vuln}))


def test_new_serious_ignores_known_and_lower_severities() -> None:
    known = finding("a", "CVE-1")
    after = {known, finding("a", "CVE-2", "MEDIUM"), finding("a", "CVE-1", version="9")}
    assert new_serious(after, {known}) == []
