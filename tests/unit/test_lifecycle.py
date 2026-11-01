import json

import pytest
import yaml

from scripts import isolation, lab


def test_resolved_validation_enables_profile_without_starting_it(monkeypatch):
    source = yaml.safe_load((isolation.ROOT / "compose.yml").read_text())
    calls = []

    def compose(arguments):
        calls.append(arguments)
        assert arguments == ["--profile", "scan", "config", "--format", "json"]
        return json.dumps(source)

    monkeypatch.setattr(lab, "compose", compose)
    lab.check_config()
    assert len(calls) == 1


@pytest.mark.parametrize(
    "endpoint,version,allowed",
    [
        ("unix:///var/run/docker.sock", "28.0.0", True),
        ("npipe:////./pipe/dockerDesktopLinuxEngine", "29.0.0", True),
        ("unix:///var/run/docker.sock", "27.5.0", False),
        ("tcp://192.0.2.1:2375", "29.0.0", False),
    ],
)
def test_local_supported_engine_is_required(monkeypatch, endpoint, version, allowed):
    def docker(arguments):
        if arguments == ["context", "inspect"]:
            return json.dumps([{"Endpoints": {"docker": {"Host": endpoint}}}])
        assert arguments == ["version", "--format", "{{.Server.Version}}"]
        return version

    monkeypatch.setattr(lab, "docker", docker)
    if allowed:
        lab.check_local_docker()
    else:
        with pytest.raises(SystemExit):
            lab.check_local_docker()
