"""pytest configuration of the fix applier tests."""

import sys
from pathlib import Path

sys.path.insert(
    0, str(Path(__file__).resolve().parents[2] / "actions" / "sca_fix_apply")
)
