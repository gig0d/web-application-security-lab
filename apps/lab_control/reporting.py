import json
from datetime import UTC, datetime
from typing import Any

from apps.lab_control.catalog import LABS


def findings(state: dict[str, Any]) -> dict[str, Any]:
    items = []
    for lab in LABS:
        result = state["results"].get(lab.id)
        items.append(
            {
                "finding_id": f"AEGIS-{lab.number}",
                "lab_id": lab.id,
                "name": lab.name,
                "cwe": lab.cwe,
                "owasp_top10_2025": lab.owasp,
                "asvs_5_0_0": lab.asvs,
                "wstg_4_2": lab.wstg,
                "affected_component": lab.component,
                "preconditions": "Synthetic local account; isolated repository-created services only.",
                "severity": lab.severity,
                "severity_rationale": "Qualitative fictional business impact; no CVSS score is claimed.",
                "reproduction_steps": lab.steps,
                "expected_behavior": lab.expected,
                "observed_behavior": result["checks"] if result else [],
                "evidence": result or {"status": "not-executed"},
                "business_impact": lab.scenario,
                "root_cause": lab.root_cause,
                "recommended_remediation": lab.remediation,
                "implemented_remediation": lab.remediation,
                "hardened_verification": result.get("hardened_verified", False)
                if result
                else False,
                "residual_risk": lab.residual,
                "references": [
                    "https://top10.owasp.org/2025/",
                    "https://github.com/OWASP/ASVS/tree/v5.0.0",
                    "https://owasp.org/www-project-web-security-testing-guide/v42/",
                ],
            }
        )
    return {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "scope": "Aegis local isolated HarborDesk only",
        "findings": items,
    }


def markdown(data: dict[str, Any]) -> str:
    verified = sum(bool(f["hardened_verification"]) for f in data["findings"])
    parts = [
        "# Aegis — HarborDesk security assessment",
        f"Generated: {data['generated_at']}",
        "## Executive summary",
        f"Twelve intentional training weaknesses are cataloged. {verified} have a recorded hardened verification in this evidence store. Unexecuted scenarios are not confirmed findings.",
        "## Scope and authorization",
        "Only repository-created local HarborDesk services and synthetic accounts are in scope. No public systems were authorized.",
        "## Methodology",
        "Paired behavioral checks follow selected WSTG 4.2 scenarios and reference ASVS 5.0.0 and OWASP Top 10:2025. Browser execution and ZAP outputs are separate evidence sources; mappings are not compliance claims.",
        "## Tested components",
        "Ticket API and HTML routes, document downloads, administrative assignment, search, rendering, profile updates, login, session logout, uploads, internal previews and error handling.",
        "## Findings by severity",
        "| ID | Finding | Severity | Recorded hardened verification |",
        "| --- | --- | --- | --- |",
    ]
    for finding in data["findings"]:
        parts.append(
            f"| {finding['finding_id']} | {finding['name']} | {finding['severity']} | {'Verified' if finding['hardened_verification'] else 'Not verified'} |"
        )
    for finding in data["findings"]:
        parts.extend(
            [
                f"## {finding['finding_id']} — {finding['name']}",
                f"{finding['cwe']} · {finding['owasp_top10_2025']}",
                f"ASVS: {', '.join(finding['asvs_5_0_0'])}. WSTG: {finding['wstg_4_2']}.",
                f"**Component:** {finding['affected_component']}",
                f"**Preconditions:** {finding['preconditions']}",
                f"**Impact and context:** {finding['business_impact']}",
                f"**Severity rationale:** {finding['severity_rationale']}",
                "### Reproduction",
                *[f"{i}. {s}" for i, s in enumerate(finding["reproduction_steps"], 1)],
                f"**Expected comparison:** {finding['expected_behavior']}",
                "### Technical evidence",
                "```json",
                json.dumps(finding["evidence"], indent=2),
                "```",
                f"**Root cause:** {finding['root_cause']}",
                f"**Remediation comparison:** {finding['implemented_remediation']}",
                f"**Hardened verification:** {'Recorded prevention verified' if finding['hardened_verification'] else 'Not verified in this evidence store'}",
                f"**Residual risk:** {finding['residual_risk']}",
                "References: " + ", ".join(finding["references"]),
            ]
        )
    parts.extend(
        [
            "## Verification outcomes",
            f"{verified}/12 labs have prevention evidence in this export. Consult each observation for the actual status codes and checks.",
            "## Limitations",
            "This is an educational assessment of deliberately bounded scenarios, not a complete security assessment, ASVS certification, measured timing guarantee, or CVSS assessment. Missing evidence is explicitly unverified. ZAP reports are not exploitation proof. Local HTTP does not establish transport security.",
            "## Conclusion",
            "The paired implementations make selected failures and remediations observable. Acceptance depends on executed evidence, including real browser and PostgreSQL/network verification.",
        ]
    )
    # Keep table rows contiguous; prose blocks and numbered list items stay separated.
    output = "\n\n".join(parts) + "\n"
    return output.replace(" |\n\n|", " |\n|")
