import copy
from pathlib import Path

import pytest
import yaml

from scripts.zap_scope import validate_plan

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("suffix", ["passive", "active"])
def test_plans_are_allowlisted_and_bounded(suffix):
    plan = yaml.safe_load((ROOT / f"infrastructure/zap/hardened-{suffix}.yaml").read_text())
    assert validate_plan(plan, suffix == "active") == []
    changed = copy.deepcopy(plan)
    changed["env"]["contexts"][0]["urls"] = ["https://example.com"]
    assert validate_plan(changed, suffix == "active")


def test_active_requires_selection():
    plan = yaml.safe_load((ROOT / "infrastructure/zap/hardened-active.yaml").read_text())
    assert validate_plan(plan, False)
    for job in plan["jobs"]:
        if job["type"] == "activeScan":
            job["parameters"]["maxScanDurationInMins"] = 0
    assert validate_plan(plan, True)


def test_active_start_urls_must_exist_in_seeded_site_tree():
    plan = yaml.safe_load((ROOT / "infrastructure/zap/hardened-active.yaml").read_text())
    for job in plan["jobs"]:
        if job["type"] == "requestor":
            job["requests"] = [
                r for r in job["requests"] if r["url"] != "http://hardened:8080/api/tickets"
            ]
    assert validate_plan(plan, True)
