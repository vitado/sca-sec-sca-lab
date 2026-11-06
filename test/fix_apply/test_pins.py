"""N8.5: the osv-scanner of the fixer workflow is the one the scheduled scan installs."""

import os
import re
from pathlib import Path

import pytest

LAB = Path(__file__).resolve().parents[2]
ENGINE_ACTION = LAB / "actions" / "sca_query_osv" / "action.yml"
PINS = ("OSV_SCANNER_VERSION", "SHA256_AMD64", "SHA256_ARM64")


def pins(text: str) -> dict[str, str]:
    found = {}
    for name in PINS:
        values = set(re.findall(rf"^\s*{name}:\s*(\S+)\s*$", text, re.MULTILINE))
        assert len(values) == 1, f"{name}: expected one value, found {values}"
        found[name] = values.pop()
    return found


def workflow_path() -> Path | None:
    """The fixer workflow: SCA_FIX_WORKFLOW, else the sibling checkout of the CI repository."""
    given = os.environ.get("SCA_FIX_WORKFLOW")
    path = (
        Path(given)
        if given
        else LAB.parent / "ai-dial-ci" / ".github" / "workflows" / "sca_fix.yml"
    )
    return path if path.is_file() else None


def test_n8_5_the_engine_pins_osv_scanner_by_version_and_checksum() -> None:
    found = pins(ENGINE_ACTION.read_text(encoding="utf-8"))
    assert re.fullmatch(r"v\d+\.\d+\.\d+", found["OSV_SCANNER_VERSION"])
    assert all(re.fullmatch(r"[0-9a-f]{64}", found[k]) for k in PINS[1:])


def test_n8_5_the_fixer_workflow_uses_the_osv_scanner_pin_of_the_engine() -> None:
    path = workflow_path()
    if path is None:
        pytest.skip("sca_fix.yml not found: set SCA_FIX_WORKFLOW")
    assert pins(path.read_text(encoding="utf-8")) == pins(
        ENGINE_ACTION.read_text(encoding="utf-8")
    )
