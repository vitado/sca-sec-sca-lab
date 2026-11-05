"""The reason codes the applier writes (the apply side of the fixer's code table).

A code says why an item is not applied; consumers rely on the code, never on the
text next to it. This module is the only place the codes are spelled; ``detail`` of
an item record keeps the machine text a code was derived from.
"""

from __future__ import annotations

DEPENDABOT_REFUSED = "dependabot_refused"
DEPENDABOT_NO_CHANGE = "dependabot_no_change"
DEPENDABOT_TIMEOUT = "dependabot_timeout"
DEPENDABOT_FAILED = "dependabot_failed"
ECOSYSTEM_UNSUPPORTED = "ecosystem_unsupported"
OVERRIDE_DIRECT = "override_direct"
OVERRIDE_RELATIONSHIP_UNKNOWN = "override_relationship_unknown"
OVERRIDE_NO_ROOT_LOCKFILE = "override_no_root_lockfile"
OVERRIDE_NO_NODE = "override_no_node"
OVERRIDE_NEEDS_MANUAL = "override_needs_manual"
OVERRIDE_LOCKFILE_FORMAT = "override_lockfile_format"
OVERRIDE_NOT_REACHED = "override_not_reached"
OVERRIDE_NPM_FAILED = "override_npm_failed"
IMAGE_BUILD_FAILED = "image_build_failed"
NO_DOCKERFILE = "no_dockerfile"
NO_DOCKERFILE_CHANGED = "no_dockerfile_changed"
RESCAN_FAILED = "rescan_failed"
GATE_STILL_PRESENT = "gate_still_present"
GATE_NEW_SERIOUS = "gate_new_serious"
NOT_IN_BASELINE = "not_in_baseline"
DRY_RUN = "dry_run"
NOTHING_APPLIED = "nothing_applied"
PR_FAILED = "pr_failed"

CODES = frozenset(
    value
    for name, value in tuple(globals().items())
    if name.isupper() and isinstance(value, str)
)
