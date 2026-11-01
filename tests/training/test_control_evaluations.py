import httpx
import pytest
from fastapi.testclient import TestClient

from apps.core.config import Settings
from apps.lab_control.main import create_control
from apps.simulator.main import app as simulator

pytestmark = pytest.mark.training


@pytest.mark.parametrize("lab_id", [f"lab{n:02}" for n in range(1, 13) if n not in {5, 6}])
def test_control_center_runs_real_paired_requests(
    lab_id, tmp_path, app_factory, monkeypatch, evidence
):
    control = create_control(Settings(progress_path=tmp_path / "progress.db"))
    applications = {variant: app_factory(variant).app for variant in ("hardened", "vulnerable")}
    original = httpx.AsyncClient

    def local_client(**kwargs):
        base = kwargs.get("base_url", "")
        variant = {"http://ingress:8080": "vulnerable", "http://ingress:8081": "hardened"}.get(base)
        application = applications[variant] if variant else simulator
        return original(transport=httpx.ASGITransport(app=application), **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", local_client)
    with TestClient(control) as client:
        client.get("/")
        headers = {"X-Aegis-Token": client.cookies.get("aegis_control_csrf")}
        response = client.post(
            "/api/evaluate/" + lab_id, headers=headers, json={"selection": "isolated-pair"}
        )
        assert response.status_code == 200 and response.json()["status"] == "passed", response.text
        result = response.json()
        assert result["vulnerable_demonstrated"] and result["hardened_verified"]
        assert (
            client.get("/exports/findings.json").json()["findings"][int(lab_id[-2:]) - 1][
                "hardened_verification"
            ]
            is True
        )
        if lab_id == "lab01":
            assert (
                client.post(
                    "/api/progress/lab01",
                    json={"notes": "Reset persistence check", "reviewed": True},
                    headers=headers,
                ).status_code
                == 200
            )
            restored = client.post(
                "/api/reset-data",
                json={"selection": "isolated-pair", "confirmation": "RESET SYNTHETIC HARBORDESK"},
                headers=headers,
            )
            assert restored.status_code == 200
            assert restored.json()["outcomes"] == {"vulnerable": "reset", "hardened": "reset"}
            assert (
                client.get("/api/state").json()["progress"]["lab01"]["notes"]
                == "Reset persistence check"
            )
        for observation in result["checks"]:
            evidence(
                lab_id,
                observation["variant"],
                control_evaluation=observation,
                transport="in-process ASGI, including synthetic simulator; not Docker network evidence",
            )
