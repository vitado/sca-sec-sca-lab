import pytest
from config import Config, ConfigError, parse_config


def test_defaults() -> None:
    assert parse_config("{}").effective() == {
        "severities": ["CRITICAL", "HIGH", "MEDIUM"],
        "severities-previous": ["CRITICAL", "HIGH", "MEDIUM"],
        "fixable-only": True,
        "include-dev": True,
        "release-branch": "release-{major}.{minor}",
        "release-lines": 2,
        "methods": ["dependabot", "npm-override"],
        "allow-major": "none",
    }
    assert parse_config("") == Config()


def test_every_key() -> None:
    config = parse_config(
        """{"severities": ["CRITICAL"], "severities-previous": ["HIGH"],
        "fixable-only": false, "include-dev": false,
        "release-branch": "rel/{major}.{minor}", "release-lines": 3,
        "methods": ["dependabot"], "allow-major": "none"}"""
    )
    assert config.severities == ("CRITICAL",)
    assert config.previous_severities() == ("HIGH",)
    assert not config.fixable_only
    assert not config.include_dev
    assert config.branch(1, 2) == "rel/1.2"
    assert config.release_lines == 3
    assert config.methods == ("dependabot",)
    assert config.allow_major == "none"


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ('{"nope": 1}', "unknown key nope"),
        ("[]", "JSON object"),
        ("{", "not valid JSON"),
        ('{"release-branch": "release-{major}"}', "release-branch"),
        ('{"release-branch": "release-{minor}"}', "release-branch"),
        ('{"release-branch": 3}', "release-branch"),
        ('{"severities": ["SEVERE"]}', "severities"),
        ('{"severities": "HIGH"}', "severities"),
        ('{"methods": ["magic"]}', "methods"),
        ('{"allow-major": "always"}', "allow-major"),
        ('{"release-lines": 0}', "release-lines"),
        ('{"release-lines": true}', "release-lines"),
        ('{"fixable-only": "yes"}', "fixable-only"),
        ('{"include-dev": 1}', "include-dev"),
    ],
)
def test_errors(text: str, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        parse_config(text)
