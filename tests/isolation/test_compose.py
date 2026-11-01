import copy
from pathlib import Path

import pytest
import yaml

from scripts.isolation import validate

ROOT = Path(__file__).resolve().parents[2]


def config():
    return yaml.safe_load((ROOT / "compose.yml").read_text())


def test_approved_configuration():
    assert validate(config()) == []


@pytest.mark.parametrize(
    "key,value",
    [
        ("ports", ["0.0.0.0:18080:8080"]),
        ("ports", ["18080:8080"]),
        ("privileged", True),
        ("network_mode", "host"),
        ("user", "0:0"),
        ("cap_add", ["NET_ADMIN"]),
        ("read_only", False),
        ("pids_limit", 0),
        ("volumes", ["/var/run/docker.sock:/var/run/docker.sock"]),
        ("volumes", ["C:/Users:/host:ro"]),
        ("networks", ["hardened-net"]),
        ("extra_hosts", ["host.docker.internal:host-gateway"]),
    ],
)
def test_unsafe_container_changes_rejected(key, value):
    data = copy.deepcopy(config())
    data["services"]["vulnerable"][key] = value
    assert validate(data)


def test_external_network_rejected():
    data = copy.deepcopy(config())
    data["networks"]["vulnerable-net"]["internal"] = False
    assert validate(data)


def test_unquoted_tmpfs_options_are_rejected():
    data = copy.deepcopy(config())
    data["services"]["hardened"]["tmpfs"] = ["/tmp:size=32m", "mode=1777"]  # noqa: S108
    assert validate(data)


def test_relay_cannot_publish_non_loopback_or_forward_packets():
    data = copy.deepcopy(config())
    data["services"]["ingress"]["ports"][0] = "0.0.0.0:18080:8080"
    assert validate(data)
    data = copy.deepcopy(config())
    data["services"]["ingress"]["sysctls"]["net.ipv4.ip_forward"] = "1"
    assert validate(data)
    data = copy.deepcopy(config())
    data["services"]["vulnerable"]["networks"].append("ingress-net")
    assert validate(data)


def test_database_ports_and_extra_services_rejected():
    data = copy.deepcopy(config())
    data["services"]["vulnerable-db"]["ports"] = ["127.0.0.1:5432:5432"]
    assert validate(data)
    data = config()
    data["services"]["unapproved"] = {}
    assert validate(data)


def test_hardened_image_cannot_import_training_policy():
    dockerfile = (ROOT / "infrastructure/docker/HarborDesk.Dockerfile").read_text()
    hardened = dockerfile.split("FROM business AS hardened")[1].split(
        "FROM business AS vulnerable"
    )[0]
    business = dockerfile.split("FROM dependencies AS business")[1].split(
        "FROM business AS hardened"
    )[0]
    assert "apps/vulnerable" not in hardened + business
    assert "apps/hardened" in hardened
    assert "apps.vulnerable" not in (ROOT / "apps/hardened/main.py").read_text()
