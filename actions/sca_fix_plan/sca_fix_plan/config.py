"""The configuration of the fix planner: a JSON object, every key optional."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
METHODS = ("dependabot", "docker-tag", "npm-override")
ALLOW_MAJOR = ("none", "dev-proven")


class ConfigError(ValueError):
    """The configuration is not valid."""


@dataclass(frozen=True)
class Config:
    severities: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM")
    severities_previous: tuple[str, ...] | None = None
    fixable_only: bool = True
    include_dev: bool = True
    release_branch: str = "release-{major}.{minor}"
    release_lines: int = 2
    include_candidate: bool = True
    methods: tuple[str, ...] = ("dependabot", "npm-override")
    allow_major: str = "none"

    def previous_severities(self) -> tuple[str, ...]:
        if self.severities_previous is None:
            return self.severities
        return self.severities_previous

    def branch(self, major: int, minor: int) -> str:
        return self.release_branch.replace("{major}", str(major)).replace(
            "{minor}", str(minor)
        )

    def effective(self) -> dict[str, Any]:
        """The configuration with every default filled in, as the plan records it."""
        return {
            "severities": list(self.severities),
            "severities-previous": list(self.previous_severities()),
            "fixable-only": self.fixable_only,
            "include-dev": self.include_dev,
            "release-branch": self.release_branch,
            "release-lines": self.release_lines,
            "include-candidate": self.include_candidate,
            "methods": list(self.methods),
            "allow-major": self.allow_major,
        }


def _choices(key: str, value: Any, allowed: tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"config {key}: a list of strings is expected")
    unknown = [v for v in value if v not in allowed]
    if unknown:
        raise ConfigError(
            f"config {key}: unknown {', '.join(unknown)} (allowed: {', '.join(allowed)})"
        )
    return tuple(value)


def _flag(key: str, value: Any) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"config {key}: true or false is expected")
    return value


def parse_config(text: str) -> Config:
    """Parse the JSON text; an unknown key or a bad value is an error."""
    try:
        raw = json.loads(text or "{}")
    except json.JSONDecodeError as exc:
        raise ConfigError(f"config is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError("config must be a JSON object")
    values: dict[str, Any] = {}
    for key, value in raw.items():
        if key == "severities":
            values["severities"] = _choices(key, value, SEVERITIES)
        elif key == "severities-previous":
            values["severities_previous"] = _choices(key, value, SEVERITIES)
        elif key == "fixable-only":
            values["fixable_only"] = _flag(key, value)
        elif key == "include-dev":
            values["include_dev"] = _flag(key, value)
        elif key == "release-branch":
            if (
                not isinstance(value, str)
                or "{major}" not in value
                or "{minor}" not in value
            ):
                raise ConfigError(
                    "config release-branch: a pattern with {major} and {minor} is expected"
                )
            values["release_branch"] = value
        elif key == "release-lines":
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ConfigError("config release-lines: an integer of 1 or more")
            values["release_lines"] = value
        elif key == "include-candidate":
            values["include_candidate"] = _flag(key, value)
        elif key == "methods":
            values["methods"] = _choices(key, value, METHODS)
        elif key == "allow-major":
            if value not in ALLOW_MAJOR:
                raise ConfigError(
                    f"config allow-major: one of {', '.join(ALLOW_MAJOR)} is expected"
                )
            values["allow_major"] = value
        else:
            raise ConfigError(f"config: unknown key {key}")
    return Config(**values)
