import json

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
