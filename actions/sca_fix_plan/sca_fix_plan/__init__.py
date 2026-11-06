"""Plan the fixes of the vulnerable packages of the newest release lines.

The public API: ``build_plan`` (the fix plan), ``classify`` (the state of every record
in the planned lines: fixed, removed or open in development, or incomplete data),
``upgrade_target`` (the target version the plan rule gives for one installed version
of a package), the configuration and the report loader they take. The plan is a pure
function of the schema 4 reports and the configuration. Standard library only; no
side effects on import.
"""

from .config import Config, ConfigError, parse_config
from .development import classify
from .plan import SCHEMA_VERSION, build_plan, upgrade_target
from .reports import ReportError, Reports, merge_reports

__version__ = "1.0.0"

__all__ = [
    "SCHEMA_VERSION",
    "Config",
    "ConfigError",
    "ReportError",
    "Reports",
    "build_plan",
    "classify",
    "merge_reports",
    "parse_config",
    "upgrade_target",
]
