"""Safe fixed-project lifecycle; no arbitrary Docker or scan arguments."""

import argparse
import json
import secrets

import yaml

from scripts.isolation import ROOT, compose, docker, effective_runtime, validate
from scripts.zap_scope import validate_plan


def check_local_docker() -> None:
    contexts = json.loads(docker(["context", "inspect"]))
    endpoint = contexts[0]["Endpoints"]["docker"]["Host"]
    if not endpoint.startswith(("npipe://", "unix://")):
        raise SystemExit("Only a local Docker Desktop/Engine context is authorized")


def check_config() -> None:
    errors = validate(yaml.safe_load((ROOT / "compose.yml").read_text()))
    errors += validate(json.loads(compose(["--profile", "scan", "config", "--format", "json"])))
    if errors:
        raise SystemExit("Isolation rejected: " + "; ".join(errors))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["init", "up", "inspect", "reset", "down", "scan"])
    parser.add_argument("--target", choices=["hardened"])
    parser.add_argument("--active", action="store_true")
    args = parser.parse_args()
    if args.operation == "init":
        env = ROOT / ".env"
        if env.exists():
            print("Existing .env preserved")
        else:
            values = [
                f"{name}={secrets.token_hex(32)}"
                for name in (
                    "VULN_DB_OWNER_PASSWORD",
                    "VULN_DB_PASSWORD",
                    "HARD_DB_OWNER_PASSWORD",
                    "HARD_DB_PASSWORD",
                )
            ]
            env.write_text("\n".join(values) + "\n", encoding="utf-8")
            print("Created local-only generated database credentials in ignored .env")
        (ROOT / "artifacts/zap").mkdir(parents=True, exist_ok=True)
        return
    check_local_docker()
    check_config()
    if args.operation == "up":
        print("WARNING: intentionally vulnerable HarborDesk is starting on loopback only.")
        compose(["up", "-d", "--build", "--wait", "--wait-timeout", "180"])
        errors = effective_runtime()
        if errors:
            compose(["stop"])
            raise SystemExit("Runtime isolation rejected; services stopped: " + "; ".join(errors))
        print("Healthy local lab: vulnerable :18080, hardened :18081, Aegis :18082")
    elif args.operation == "inspect":
        errors = effective_runtime()
        if errors:
            raise SystemExit("; ".join(errors))
        print("Effective loopback bindings and internal networks verified")
    elif args.operation == "reset":
        services = [
            "vulnerable",
            "hardened",
            "vulnerable-init",
            "hardened-init",
            "vulnerable-db",
            "hardened-db",
        ]
        compose(["rm", "--stop", "--force", *services])
        # Exact project-owned names only; unrelated volumes and progress remain untouched.
        docker(["volume", "rm", "aegis_vulnerable-data", "aegis_hardened-data"])
        compose(["up", "-d", "--wait", "--wait-timeout", "180"])
        if effective_runtime():
            raise SystemExit("Reset finished but runtime verification failed")
        print("Synthetic business data restored; learning progress preserved")
    elif args.operation == "down":
        compose(["down", "--remove-orphans"])
        print("Aegis containers/networks removed; named data volumes preserved")
    elif args.operation == "scan":
        if args.target != "hardened":
            raise SystemExit("Select --target hardened explicitly before any scan")
        errors = effective_runtime({"hardened", "hardened-db", "simulator"})
        if errors:
            raise SystemExit("Scan rejected: " + "; ".join(errors))
        (ROOT / "artifacts/zap").mkdir(parents=True, exist_ok=True)
        plan = "hardened-active.yaml" if args.active else "hardened-passive.yaml"
        plan_path = ROOT / "infrastructure/zap" / plan
        plan_errors = validate_plan(yaml.safe_load(plan_path.read_text()), args.active)
        if plan_errors:
            raise SystemExit("Scan plan rejected: " + "; ".join(plan_errors))
        expected_report = ROOT / "artifacts/zap" / plan.replace(".yaml", ".json")
        previous_mtime = expected_report.stat().st_mtime_ns if expected_report.exists() else 0
        compose(
            [
                "--profile",
                "scan",
                "run",
                "--rm",
                "zap-hardened",
                "zap.sh",
                "-cmd",
                "-autorun",
                f"/zap/plans/{plan}",
            ]
        )
        if not expected_report.exists() or expected_report.stat().st_mtime_ns <= previous_mtime:
            raise SystemExit("Scanner exited without the expected JSON report")
        print("Actual scan artifacts are in artifacts/zap; inspect findings and limitations")


if __name__ == "__main__":
    main()
