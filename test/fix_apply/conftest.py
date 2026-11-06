"""pytest configuration of the fix applier tests."""

import sys
from pathlib import Path

ACTIONS = Path(__file__).resolve().parents[2] / "actions"

# the scan engine the detector reuses, on the path as the action's PYTHONPATH has it
for path in (
    ACTIONS,
    ACTIONS / "sca_merge_results",
    ACTIONS / "sca_query_osv",
    ACTIONS / "sca_fix_apply",
):
    sys.path.insert(0, str(path))
