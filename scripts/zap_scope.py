"""Validate exact scan plans; never turns arbitrary targets into authorized scope."""

from pathlib import Path
from typing import Any

import yaml

APPROVED = "http://hardened:8080"
ROOT = Path(__file__).resolve().parents[1]


def validate_plan(plan: dict[str, Any], active: bool) -> list[str]:
    errors = []
    contexts = plan.get("env", {}).get("contexts", [])
    if len(contexts) != 1 or contexts[0].get("urls") != [APPROVED]:
        errors.append("Only the exact hardened Compose target is approved")
    for context in contexts:
        if context.get("includePaths") != [APPROVED + "/.*"]:
            errors.append("Scan scope regex is not the approved exact host")
        auth = context.get("authentication", {}).get("parameters", {})
        if auth.get("loginRequestUrl") != APPROVED + "/api/login":
            errors.append("Authentication target rejected")
    seen_active = False
    active_minutes = 0
    for job in plan.get("jobs", []):
        kind = job.get("type")
        if kind not in {
            "passiveScan-config",
            "requestor",
            "spider",
            "activeScan",
            "passiveScan-wait",
            "report",
            "exitStatus",
        }:
            errors.append("Unapproved ZAP job type")
        parameters = job.get("parameters", {})
        if kind == "requestor":
            for request in job.get("requests", []):
                if (
                    not request.get("url", "").startswith(APPROVED + "/")
                    or request.get("method") != "GET"
                ):
                    errors.append("Requestor may only fetch approved local GET routes")
        if kind == "spider" and not 0 < parameters.get("maxDuration", 0) <= 1:
            errors.append("Spider must be bounded to one minute")
        if kind == "activeScan":
            seen_active = True
            if parameters.get("url") not in {APPROVED + "/search", APPROVED + "/api/tickets"}:
                errors.append("Active scan is limited to the two implemented search sinks")
            active_minutes += parameters.get("maxScanDurationInMins", 0)
            if (
                not 0 < parameters.get("maxScanDurationInMins", 0) <= 3
                or parameters.get("threadPerHost") != 1
            ):
                errors.append("Active execution bounds rejected")
        if kind == "report" and parameters.get("reportDir") != "/zap/wrk":
            errors.append("Report path rejected")
    if seen_active != active:
        errors.append("Active job requires separate explicit selection")
    if active_minutes > 3:
        errors.append("Combined active scanning exceeds three minutes")
    return errors


def main() -> None:
    for suffix in ("passive", "active"):
        plan = yaml.safe_load((ROOT / f"infrastructure/zap/hardened-{suffix}.yaml").read_text())
        errors = validate_plan(plan, suffix == "active")
        if errors:
            raise SystemExit("; ".join(errors))
    print("ZAP scope and execution-bound checks passed; this is not a scan result")


if __name__ == "__main__":
    main()
