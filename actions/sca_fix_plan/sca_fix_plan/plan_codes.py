"""The reason codes the planner writes (the plan side of the fixer's code table).

A code says why a record was skipped, dropped or left to a human; consumers rely on
the code, never on the text next to it. This module is the only place the codes are
spelled.
"""

from __future__ import annotations

ACCEPTED = "accepted"
NOT_FIXED_IN_DEVELOPMENT = "not_fixed_in_development"
DEVELOPMENT_DATA_INCOMPLETE = "development_data_incomplete"
SEVERITY = "severity"
UNFIXABLE = "unfixable"
DEV = "dev"
NO_FIXED_VERSION = "no_fixed_version"
NEEDS_MAJOR = "needs_major"
VERSION_UNPARSABLE = "version_unparsable"
NEEDS_IMAGE_REBUILD = "needs_image_rebuild"
ONLY_IN_IMAGE = "only_in_image"
ECOSYSTEM_UNSUPPORTED = "ecosystem_unsupported"
METHOD_DISABLED = "method_disabled"
REF_NOT_SEMVER = "ref_not_semver"
SAME_REF_SAME_COMMIT = "same_ref_same_commit"
LINE_IN_EARLIER_REPORT = "line_in_earlier_report"

CODES = frozenset(
    value
    for name, value in tuple(globals().items())
    if name.isupper() and isinstance(value, str)
)
