"""Fail-closed source, resolved Compose, and effective Docker isolation validation."""

import argparse
import json
import shutil
import subprocess  # nosec B404
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
SERVICES = {
    "vulnerable-db",
    "hardened-db",
    "vulnerable-init",
    "hardened-init",
    "vulnerable",
    "hardened",
    "simulator",
    "control",
    "zap-hardened",
}
NETWORKS = {
    "vulnerable-db": {"vulnerable-net"},
    "vulnerable-init": {"vulnerable-net"},
    "vulnerable": {"vulnerable-net"},
    "hardened-db": {"hardened-net"},
    "hardened-init": {"hardened-net"},
    "hardened": {"hardened-net"},
    "simulator": {"vulnerable-net", "hardened-net"},
    "control": {"control-net", "vulnerable-net", "hardened-net"},
    "zap-hardened": {"hardened-net"},
}
PORTS = {"vulnerable": 18080, "hardened": 18081, "control": 18082}


def validate(config: dict[str, Any]) -> list[str]:
    errors = []
    services = config.get("services", {})
    if set(services) != SERVICES:
        errors.append("The exact approved service inventory is required")
    networks = config.get("networks", {})
    if set(networks) != {"vulnerable-net", "hardened-net", "control-net"}:
        errors.append("Unexpected network inventory")
    for name, network in networks.items():
        if not network.get("internal") or network.get("external"):
            errors.append(f"{name}: network must be internal and project-owned")
        if network.get("name", f"aegis_{name}") != f"aegis_{name}":
            errors.append(f"{name}: network name must belong to Aegis")
    volumes = config.get("volumes", {})
    if set(volumes) != {"vulnerable-data", "hardened-data", "progress-data"}:
        errors.append("Unexpected data volume inventory")
    for name, definition in volumes.items():
        definition = definition or {}
        if (
            definition.get("external")
            or definition.get("driver_opts")
            or definition.get("name", f"aegis_{name}") != f"aegis_{name}"
        ):
            errors.append(f"{name}: data volume must be project-owned")
    for name, service in services.items():
        if service.get("network_mode") or service.get("privileged"):
            errors.append(f"{name}: host/privileged mode forbidden")
        if service.get("devices") or service.get("cap_add") or service.get("extra_hosts"):
            errors.append(f"{name}: additional host access forbidden")
        if any(
            service.get(key)
            for key in ("configs", "secrets", "env_file", "extends", "links", "volumes_from")
        ):
            errors.append(f"{name}: unapproved external configuration or mounts")
        if service.get("pid") or service.get("ipc") == "host":
            errors.append(f"{name}: host namespace forbidden")
        if service.get("user") not in {"10001:10001", "999:999", "1000:1000"}:
            errors.append(f"{name}: explicit non-root user required")
        if "ALL" not in service.get("cap_drop", []):
            errors.append(f"{name}: all capabilities must be dropped")
        options = [str(v).replace("=", ":") for v in service.get("security_opt", [])]
        if "no-new-privileges:true" not in options:
            errors.append(f"{name}: no-new-privileges required")
        if not name.endswith("-db") and not service.get("read_only"):
            errors.append(f"{name}: read-only root filesystem required")
        if not service.get("pids_limit") or not service.get("mem_limit") or not service.get("cpus"):
            errors.append(f"{name}: execution limits required")
        if set(service.get("networks", [])) != NETWORKS.get(name, set()):
            errors.append(f"{name}: network membership rejected")
        ports = service.get("ports", [])
        if len(ports) != (1 if name in PORTS else 0):
            errors.append(f"{name}: unexpected published ports")
        for port in ports:
            if isinstance(port, str):
                good = port == f"127.0.0.1:{PORTS.get(name)}:8080"
            else:
                good = (
                    port.get("host_ip") == "127.0.0.1"
                    and str(port.get("published")) == str(PORTS.get(name))
                    and port.get("target") == 8080
                    and port.get("protocol", "tcp") == "tcp"
                )
            if not good:
                errors.append(f"{name}: only exact loopback publication is allowed")
        for volume in service.get("volumes", []):
            if isinstance(volume, str):
                parts = volume.split(":")
                source, target = parts[0], parts[1]
                readonly = len(parts) > 2 and parts[2] == "ro"
                bind = source.startswith(".") or source.startswith("/")
            else:
                source, target = volume.get("source", ""), volume.get("target", "")
                readonly, bind = volume.get("read_only", False), volume.get("type") == "bind"
            if "docker.sock" in source or "docker.sock" in target:
                errors.append(f"{name}: Docker socket forbidden")
            if bind:
                expected = {
                    "/docker-entrypoint-initdb.d/01-app.sh": (
                        "infrastructure/database/init.sh",
                        True,
                    ),
                    "/zap/plans": ("infrastructure/zap", True),
                    "/zap/wrk": ("artifacts/zap", False),
                }.get(target)
                resolved = (ROOT / source).resolve()
                if (
                    not expected
                    or resolved != (ROOT / expected[0]).resolve()
                    or readonly != expected[1]
                ):
                    errors.append(f"{name}: unapproved host mount")
            elif (name, source, target) not in {
                ("vulnerable-db", "vulnerable-data", "/var/lib/postgresql"),
                ("hardened-db", "hardened-data", "/var/lib/postgresql"),
                ("control", "progress-data", "/data"),
            }:
                errors.append(f"{name}: unapproved data volume")
    return errors


def docker(arguments: list[str]) -> str:
    # CLI callers construct fixed argument lists; no shell or user-supplied command.
    executable = shutil.which("docker")
    if not executable:
        raise RuntimeError("Docker CLI unavailable; install and start local Docker Desktop/Engine")
    result = subprocess.run(  # nosec B603
        [executable, *arguments],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    if result.returncode:
        # Docker output may include interpolated credentials: deliberately suppress it.
        raise RuntimeError(
            "Docker command failed; inspect Docker Desktop and named Aegis resources"
        )
    return result.stdout


def compose(arguments: list[str]) -> str:
    return docker(["compose", "-p", "aegis", "-f", str(ROOT / "compose.yml"), *arguments])


def effective_runtime() -> list[str]:
    errors = []
    ids = compose(["ps", "-aq"]).split()
    if not ids:
        return ["No Aegis containers to inspect"]
    objects = json.loads(docker(["inspect", *ids]))
    running = set()
    for container in objects:
        name = container["Config"]["Labels"].get("com.docker.compose.service")
        if name not in SERVICES:
            errors.append("Unexpected project container")
            continue
        if container["State"]["Running"]:
            running.add(name)
        host = container["HostConfig"]
        if host.get("Privileged") or host.get("NetworkMode") == "host":
            errors.append(f"{name}: unsafe runtime privilege/network")
        if container["Config"].get("User") not in {"10001:10001", "999:999", "1000:1000"}:
            errors.append(f"{name}: unexpected runtime user")
        if "ALL" not in host.get("CapDrop", []) or host.get("CapAdd"):
            errors.append(f"{name}: unsafe runtime capabilities")
        bindings = host.get("PortBindings") or {}
        expected_ports = {"8080/tcp"} if name in PORTS else set()
        if set(bindings) != expected_ports:
            errors.append(f"{name}: unexpected effective port inventory")
        for entries in bindings.values():
            for entry in entries or []:
                if entry["HostIp"] != "127.0.0.1" or entry["HostPort"] != str(PORTS.get(name)):
                    errors.append(f"{name}: unsafe effective host binding")
        actual = set(container["NetworkSettings"]["Networks"])
        if actual != {f"aegis_{n}" for n in NETWORKS[name]}:
            errors.append(f"{name}: unexpected effective network membership")
    if (
        not {"vulnerable", "hardened", "control", "simulator", "vulnerable-db", "hardened-db"}
        <= running
    ):
        errors.append("Required Aegis services are not running")
    for network in json.loads(
        docker(
            [
                "network",
                "inspect",
                *[f"aegis_{n}" for n in ("vulnerable-net", "hardened-net", "control-net")],
            ]
        )
    ):
        if not network["Internal"]:
            errors.append("Effective network allows external egress")
    return errors


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--resolved", action="store_true")
    parser.add_argument("--runtime", action="store_true")
    args = parser.parse_args()
    config = (
        json.loads(compose(["config", "--format", "json"]))
        if args.resolved
        else yaml.safe_load((ROOT / "compose.yml").read_text())
    )
    errors = validate(config)
    if args.runtime:
        errors.extend(effective_runtime())
    if errors:
        raise SystemExit("Isolation rejected:\n" + "\n".join(errors))
    print(
        "Isolation checks passed" + (" (effective runtime)" if args.runtime else " (configuration)")
    )


if __name__ == "__main__":
    main()
