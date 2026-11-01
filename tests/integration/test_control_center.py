import httpx
from fastapi.testclient import TestClient

from apps.core.config import Settings
from apps.lab_control.main import create_control


def test_notebook_evidence_and_exports_are_separate(tmp_path, app_factory, monkeypatch):
    app = create_control(Settings(progress_path=tmp_path / "progress.db"))
    apps = {variant: app_factory(variant).app for variant in ("hardened", "vulnerable")}
    original = httpx.AsyncClient

    def local_client(**kwargs):
        variant = "hardened" if "hardened" in kwargs["base_url"] else "vulnerable"
        return original(transport=httpx.ASGITransport(app=apps[variant]), **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", local_client)
    with TestClient(app) as client:
        assert client.get("/").status_code == 200
        token = client.cookies.get("aegis_control_csrf")
        headers = {"X-Aegis-Token": token}
        assert (
            client.post(
                "/api/progress/lab01", json={"notes": "local observation", "reviewed": True}
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/api/progress/lab01",
                headers=headers,
                json={"notes": "local observation", "reviewed": True},
            ).status_code
            == 200
        )
        data = client.get("/exports/findings.json").json()
        assert data["findings"][0]["hardened_verification"] is False
        assert (
            client.post(
                "/api/evaluate/lab01", headers=headers, json={"selection": "https://example.com"}
            ).status_code
            == 422
        )
        result = client.post(
            "/api/evaluate/lab01", headers=headers, json={"selection": "isolated-pair"}
        )
        assert result.status_code == 200 and result.json()["status"] == "passed", result.text
        assert result.json()["checks"][0]["observation"]["foreign_api_status"] == 200
        assert result.json()["checks"][1]["observation"]["foreign_api_status"] == 404
        assert (
            client.get("/exports/findings.json").json()["findings"][0]["hardened_verification"]
            is True
        )
        report = client.get("/exports/report.md")
        assert report.status_code == 200 and "Executive summary" in report.text
        assert "1/12" in report.text
        assert (
            client.post(
                "/api/evaluate/lab05", headers=headers, json={"selection": "isolated-pair"}
            ).json()["status"]
            == "requires-browser"
        )
        assert client.delete("/api/progress/lab01", headers=headers).status_code == 200
        assert "lab01" not in client.get("/api/state").json()["results"]
        assert client.get("/labs/unknown").status_code == 404
