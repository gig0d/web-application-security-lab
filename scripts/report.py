"""Build reports from actual successful pytest observations, never expected catalog text alone."""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from apps.lab_control.catalog import LABS, ROOT
from apps.lab_control.reporting import findings, markdown


def from_evidence(paths: list[Path]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    provenance = []
    for path in paths:
        resolved = path.resolve()
        if not resolved.is_relative_to(ROOT) or resolved.stat().st_size > 2_000_000:
            raise ValueError("Evidence must be a bounded local repository artifact")
        raw = resolved.read_bytes()
        document = json.loads(raw)
        if document.get("schema_version") != 1 or document.get("exit_status") != 0:
            raise ValueError("Only a completed successful version-1 test execution is reportable")
        rows.extend(document["observations"])
        provenance.append(
            {
                "path": resolved.relative_to(ROOT).as_posix(),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "generated_at": document["generated_at"],
            }
        )
    results = {}
    for lab in LABS:
        observations = [
            row for row in rows if row.get("lab_id") == lab.id and row.get("test_passed") is True
        ]
        if lab.id in {"lab05", "lab06"}:
            eligible = [
                row
                for row in observations
                if row["observations"].get("browser_execution_verified") is True
            ]
        elif lab.id == "lab07":
            eligible = [
                row for row in observations if row["observations"].get("browser_verified") is True
            ]
        else:
            eligible = observations
        variants = {row["variant"] for row in eligible}
        results[lab.id] = {
            "status": "passed" if {"vulnerable", "hardened"} <= variants else "not-verified",
            "vulnerable_demonstrated": "vulnerable" in variants,
            "hardened_verified": "hardened" in variants,
            "checks": observations,
            "limitations": [
                "Local test evidence; database/transport/browser details are recorded per observation. This does not establish Docker networking or ZAP outcomes."
            ],
        }
    report = findings({"results": results, "progress": {}})
    report["provenance"] = provenance
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", action="append", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/report")
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / "artifacts"):
        raise SystemExit("Generated report output must stay under ignored artifacts/")
    report = from_evidence(args.evidence)
    output.mkdir(parents=True, exist_ok=True)
    (output / "assessment.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (output / "assessment.md").write_text(markdown(report), encoding="utf-8")
    print(f"Report generated from {len(args.evidence)} successful evidence files: {output}")


if __name__ == "__main__":
    main()
