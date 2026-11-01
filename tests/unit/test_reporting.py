import hashlib
import json
from pathlib import Path

import pytest

from apps.lab_control.reporting import findings, markdown
from scripts.report import from_evidence


def test_no_evidence_never_becomes_verified():
    data = findings({"results": {}, "progress": {}})
    assert len(data["findings"]) == 12
    assert not any(f["hardened_verification"] for f in data["findings"])
    report = markdown(data)
    assert "0/12" in report
    assert "|\n\n|" not in report
    assert {
        "finding_id",
        "lab_id",
        "name",
        "cwe",
        "owasp_top10_2025",
        "asvs_5_0_0",
        "wstg_4_2",
        "affected_component",
        "preconditions",
        "severity",
        "severity_rationale",
        "reproduction_steps",
        "observed_behavior",
        "evidence",
        "business_impact",
        "root_cause",
        "recommended_remediation",
        "implemented_remediation",
        "hardened_verification",
        "residual_risk",
        "references",
    } <= data["findings"][0].keys()


def test_retained_evidence_provenance_matches_exact_bytes():
    root = Path(__file__).resolve().parents[2] / "reports/examples"
    report = json.loads((root / "assessment.json").read_text(encoding="utf-8"))
    assert (
        hashlib.sha256((root / "local-test-evidence.json").read_bytes()).hexdigest()
        == report["provenance"][0]["sha256"]
    )
    redaction = json.loads(
        (root / "zap/hardened-passive.redaction.json").read_text(encoding="utf-8")
    )
    for item in redaction["files"]:
        assert (
            hashlib.sha256((root / "zap" / item["file"]).read_bytes()).hexdigest()
            == item["redacted_sha256"]
        )


def test_failed_execution_is_not_promoted_to_report(tmp_path):
    # Contract fixture, deliberately not vulnerability evidence.
    from scripts.report import ROOT

    output = ROOT / "artifacts/tests/failed-contract-fixture.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({"schema_version": 1, "exit_status": 1, "observations": []}))
    with pytest.raises(ValueError, match="successful"):
        from_evidence([output])
